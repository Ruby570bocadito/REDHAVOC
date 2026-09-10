# -*- coding: utf-8 -*-
"""
core.framework
==============
Consola interactiva de REDHAVOC (REPL estilo Metasploit).

Comandos soportados en el prompt raíz:
    help | ?                Ayuda de comandos
    search <término>        Buscar módulos (filtros: cat:web · riesgo:alto)
    use <modulo>            Cargar un módulo (cambia el prompt)
    info [modulo]           Metadatos y opciones de un módulo
    show modules|options    Listado de módulos / opciones activas
    set OPT VAL             Fijar una opción (global o del módulo)
    setg OPT VAL            Fijar una opción GLOBAL (aunque haya módulo cargado)
    unset OPT               Restaurar el valor por defecto de una opción
    run [-j]                Ejecutar el módulo (-j: como job en segundo plano)
    jobs [-k ID|-k all|-c]  Tareas en segundo plano lanzadas con run -j
    RHOSTS (opción)         Barrido multi-host estilo NetExec: CIDR, rango,
                            @fichero o comas → una línea de resultado por host
    sessions [-i N|-k N|-k all|-x N cmd]  Gestionar sesiones del handler
    hosts | creds | vulns | services   Base de datos del workspace (-c limpia)
    notes [add|-c]          Cuaderno libre del operador
    export json|csv|md      Exportar el workspace a output/
    audit [N]               Traza de auditoría ética (workspace/audit.log)
    report                  Ruta del último informe generado
    banner                  Volver a mostrar el banner
    history [-c]            Historial persistente de comandos
    clear                   Limpiar pantalla
    exit | quit             Salir
"""

import json
import re
import shlex
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

try:
    import readline          # autocompletado TAB (POSIX)
except ImportError:          # pragma: no cover — Windows sin pyreadline
    readline = None

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from core import __version__
from core.base_module import BaseModulo, ModuloError
from core.colors import console, PROMPT_RAIZ, prompt_modulo, trabajo
from core.engagement import Engagement, NOMBRES_OBJETIVO
from core.ethics import EthicsGate
from core.module_manager import ModuleManager, ModuloNoEncontrado
from core.option_store import OptionStore
from core.plugins import GestorPlugins as Plugins, PluginError
from core.advice import consejos_de_resultado
from core.render import (mostrar_consejos, mostrar_consejos_lista, mostrar_plan,
                         mostrar_resultado)
from core.reporter import Reporter
from core.workspace_db import NOMBRE_DEFECTO, WorkspaceDB, ruta_de_workspace
from core.targets import ObjetivoError, expandir_objetivos

# Nombres válidos de workspace: a-z 0-9 _ - (1-24 caracteres)
_NOMBRE_WS_VALIDO = re.compile(r"^[a-z0-9_-]{1,24}$")


class Ctx:
    """Contexto que se inyecta en cada módulo durante la ejecución.

    Permite a los módulos acceder a las opciones globales, al reporter y —
    en el caso de handlers interactivos — al registro de sesiones.
    """

    def __init__(self, opciones_globales: OptionStore, reporter: Reporter,
                 sesiones: Dict, workspace) -> None:
        self.globales = opciones_globales
        self.reporter = reporter
        self.sesiones = sesiones          # {id: {"conn": socket, "addr": tuple, "abierta": tiempo}}
        self.workspace = workspace


class RedHavocFramework:
    """Framework principal: registra módulos y ejecuta el REPL."""

    COMANDOS = (
        "help", "?", "search", "use", "info", "show", "set", "unset",
        "setg", "unsetg", "run", "exploit", "back", "sessions", "hosts",
        "creds", "vulns", "services", "notes", "export", "audit",
        "consejos", "report", "engagement", "attack", "resource",
        "workspace", "plugin", "jobs", "banner", "history", "clear",
        "exit", "quit",
    )

    def __init__(self, raiz) -> None:
        self.raiz = raiz
        self.module_manager = ModuleManager()
        self.ethics = EthicsGate(raiz / "workspace")
        self.reporter = Reporter(raiz / "output")
        self.engagement = Engagement(raiz / "workspace")

        # Workspaces múltiples: se restaura el último activo (estilo msf)
        self.nombre_workspace = self._leer_workspace_actual()
        self.workspace_db = WorkspaceDB(raiz / "workspace", self.nombre_workspace)

        # Opciones globales del framework (disponibles para todos los módulos)
        self.globales = OptionStore()
        self.globales.declarar("AUTHORIZED", "", False, "Autorización explícita para módulos de riesgo alto (true/1)")
        self.globales.declarar("REPORT", "true", False, "Guardar informe JSON+MD tras cada ejecución")
        self.globales.declarar("THREADS", "10", False, "Hilos por defecto para módulos concurrentes")
        self.globales.declarar("TIMEOUT", "5", False, "Timeout de red por defecto (segundos)")
        self.globales.declarar("USER_AGENT", "REDHAVOC/" + __version__, False, "User-Agent HTTP por defecto")
        self.globales.declarar("PROXY", "", False, "Proxy HTTP(S) tipo http://127.0.0.1:8080")
        self.globales.declarar("VERBOSE", "false", False, "Mostrar trazas de depuración")

        # Estado de la sesión de consola
        self.modulo_actual: Optional[BaseModulo] = None
        self.sesiones: Dict = {}
        self._siguiente_id_sesion = 1
        self.historial: List[str] = []
        self._inicio_sesion = time.time()
        self._informes_sesion = 0          # informes generados en esta sesión
        self._ultima_busqueda: List = []   # resultados de search (use/info <n>)

        # Jobs en segundo plano (run -j): {id: {...estado, hilo...}}
        self.jobs: Dict[int, Dict] = {}
        self._siguiente_id_job = 1
        self._lock_reporte = threading.Lock()   # serializa informes de jobs
        self.ctx = Ctx(self.globales, self.reporter, self.sesiones, self.workspace_db)
        self.plugins = Plugins(self.raiz, self.ethics)
        self._cargar_historial()

        # Persistencia de opciones entre sesiones (roadmap v2.0)
        self._restaurar_opciones_guardadas()

        # Autocompletado con TAB (solo POSIX)
        self._activar_readline()

    # ==================================================================
    # Historial persistente entre sesiones (estilo bash)
    # ==================================================================
    @property
    def _ruta_historial(self) -> Path:
        return self.raiz / "workspace" / "historial.txt"

    def _cargar_historial(self, max_lineas: int = 500) -> None:
        """Restaura el historial de sesiones anteriores (si existe)."""
        try:
            lineas = self._ruta_historial.read_text(encoding="utf-8").splitlines()
            self.historial = [l for l in lineas[-max_lineas:] if l.strip()]
        except OSError:
            self.historial = []

    def _guardar_historial(self) -> None:
        """Persiste el historial de la sesión al salir."""
        try:
            previas = []
            if self._ruta_historial.exists():
                previas = self._ruta_historial.read_text(encoding="utf-8").splitlines()
            todo = [l for l in (previas + self.historial) if l.strip()]
            self._ruta_historial.write_text("\n".join(todo[-500:]) + "\n", encoding="utf-8")
        except OSError:
            pass  # nunca romper la salida por un fallo de disco

    # ==================================================================
    # Workspaces múltiples (estilo msf: workspace list/new/use/del)
    # ==================================================================
    @property
    def _ruta_workspace_actual(self) -> Path:
        return self.raiz / "workspace" / "actual.txt"

    def _leer_workspace_actual(self) -> str:
        """Nombre del workspace activo de la sesión anterior (o principal)."""
        try:
            nombre = self._ruta_workspace_actual.read_text(encoding="utf-8").strip()
            if nombre and _NOMBRE_WS_VALIDO.fullmatch(nombre):
                return nombre
        except OSError:
            pass
        return NOMBRE_DEFECTO

    def _fijar_workspace(self, nombre: str) -> None:
        """Cambia al workspace indicado (creándolo si no existe)."""
        nombre = (nombre or "").strip().lower()
        if not _NOMBRE_WS_VALIDO.fullmatch(nombre):
            console.print("[error][✗][/error] Nombre de workspace inválido: usa "
                          "1-24 caracteres de [bold]a-z 0-9 _ -[/bold]")
            return
        self.workspace_db = WorkspaceDB(self.raiz / "workspace", nombre)
        self.ctx.workspace = self.workspace_db
        self.nombre_workspace = nombre
        try:
            self._ruta_workspace_actual.write_text(nombre, encoding="utf-8")
        except OSError:
            pass  # el cambio funciona igualmente en esta sesión
        console.print(f"[ok][✓][/ok] Workspace activo: [modulo]{nombre}[/modulo] "
                      f"[dim]({self.workspace_db.resumen()})[/dim]")

    def cmd_workspace(self, args) -> None:
        """workspace | new <n> | use <n> | del <n> — workspaces múltiples."""
        sub = args[0].lower() if args else ""
        if sub in ("new", "use"):
            if len(args) < 2:
                console.print(f"[aviso][!][/aviso] Uso: [bold]workspace {sub} "
                              f"<nombre>[/bold]")
                return
            self._fijar_workspace(args[1])
            return
        if sub == "del":
            if len(args) < 2:
                console.print("[aviso][!][/aviso] Uso: [bold]workspace del <nombre>[/bold]")
                return
            nombre = args[1].strip().lower()
            if nombre == NOMBRE_DEFECTO:
                console.print("[error][✗][/error] El workspace 'principal' no se puede "
                              "borrar (usa hosts -c / creds -c / vulns -c / notes -c).")
                return
            ruta = ruta_de_workspace(self.raiz / "workspace", nombre)
            if not ruta.exists():
                console.print(f"[error][✗][/error] No existe el workspace: {escape(nombre)}")
                return
            if nombre == self.nombre_workspace:
                console.print("[error][✗][/error] Es el workspace activo: cambia antes a "
                              "otro (workspace use principal).")
                return
            try:
                ruta.unlink()
            except OSError as err:
                console.print(f"[error][✗][/error] No se pudo borrar: {escape(str(err))}")
                return
            console.print(f"[ok][✓][/ok] Workspace borrado: [modulo]{escape(nombre)}[/modulo]")
            return
        if sub:
            console.print("[aviso][!][/aviso] Uso: workspace | [bold]new <n>[/bold] | "
                          "[bold]use <n>[/bold] | [bold]del <n>[/bold]")
            return
        todos = WorkspaceDB.listar(self.raiz / "workspace")
        tabla = Table(title="Workspaces", border_style="dim")
        tabla.add_column("", justify="center", no_wrap=True)
        tabla.add_column("Nombre", style="modulo", no_wrap=True)
        tabla.add_column("Contenido", style="white", overflow="fold")
        for ws in todos:
            actual = "[accent]●[/accent]" if ws.nombre == self.nombre_workspace else ""
            tabla.add_row(actual, ws.nombre, ws.resumen())
        console.print(tabla)
        console.print("[dim]Crea con: workspace new <nombre> · cambia con: "
                      "workspace use <nombre> · borra: workspace del <nombre>[/dim]")

    # ==================================================================
    # Persistencia de opciones entre sesiones (workspace/opciones.json)
    # ==================================================================
    @property
    def _ruta_opciones(self) -> Path:
        return self.raiz / "workspace" / "opciones.json"

    def _cargar_opciones_guardadas(self) -> Dict:
        """Lee {"global": {OPT: val}, "modulos": {name: {OPT: val}}}."""
        try:
            datos = json.loads(self._ruta_opciones.read_text(encoding="utf-8"))
            if isinstance(datos, dict):
                datos.setdefault("global", {})
                datos.setdefault("modulos", {})
                return datos
        except (json.JSONDecodeError, OSError):
            pass
        return {"global": {}, "modulos": {}}

    def _guardar_opciones_guardadas(self) -> None:
        try:
            self._ruta_opciones.write_text(
                json.dumps(self._opciones_guardadas, indent=2, ensure_ascii=False),
                encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _opcion_persistible(nombre_opt: str) -> bool:
        """AUTHORIZED nunca se persiste (la autorización es por sesión)."""
        return nombre_opt.upper() != "AUTHORIZED"

    def _persistir_opcion(self, destino: str, opt: str, valor: Optional[str]) -> None:
        """Registra/elimina una opción del almacén persistente.

        destino: 'global' o NAME del módulo. valor=None elimina la entrada.
        """
        if not self._opcion_persistible(opt):
            return
        almacen = self._opciones_guardadas
        seccion = almacen["global"] if destino == "global" \
            else almacen["modulos"].setdefault(destino, {})
        if valor is None:
            seccion.pop(opt, None)
            if destino != "global" and not seccion:
                almacen["modulos"].pop(destino, None)
        else:
            seccion[opt] = valor
        self._guardar_opciones_guardadas()

    def _restaurar_opciones_guardadas(self) -> None:
        """Aplica las opciones persistidas (globales al arrancar)."""
        self._opciones_guardadas = self._cargar_opciones_guardadas()
        for opt, valor in self._opciones_guardadas["global"].items():
            self.globales.set(opt, valor)   # ignora silenciosamente si ya no existe

    def _restaurar_opciones_modulo(self, modulo: BaseModulo) -> None:
        """Restaura las opciones guardadas del módulo recién cargado."""
        for opt, valor in self._opciones_guardadas["modulos"].get(modulo.NAME, {}).items():
            modulo.opciones.set(opt, valor)

    # ==================================================================
    # REPL
    # ==================================================================
    def repl(self) -> None:
        """Bucle principal de la consola interactiva."""
        while True:
            try:
                prompt = PROMPT_RAIZ if self.modulo_actual is None else prompt_modulo(self.modulo_actual.NAME)
                linea = console.input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                if self.modulo_actual is not None:
                    self.cmd_back()
                    continue
                break
            if not linea:
                continue
            self.historial.append(linea)
            try:
                salir = self._procesar(linea)
            except SystemExit:
                break  # salida limpia solicitada (comando exit/quit)
            except Exception as err:  # noqa: BLE001
                if self.globales.get_bool("VERBOSE"):
                    console.print_exception()
                else:
                    # escape(): el mensaje puede contener corchetes que Rich interpretaría como markup
                    console.print(f"[error][✗][/error] Error interno: {escape(str(err))}")
                salir = False
            if salir:
                break

    # ------------------------------------------------------------------
    def _procesar(self, linea: str) -> bool:
        """Procesa una línea de comando. Devuelve True para salir."""
        try:
            partes = shlex.split(linea)
        except ValueError:
            partes = linea.split()
        if not partes:
            return False
        cmd, args = partes[0].lower(), partes[1:]

        # `set`/`unset`/`setg`/`unsetg` conservan el valor tal cual (URLs con & , =, etc.)
        if cmd in ("set", "unset", "setg", "unsetg"):
            self.cmd_set(args, deshacer=cmd in ("unset", "unsetg"),
                         solo_global=cmd in ("setg", "unsetg"))
            return False

        despachador = {
            "help": self.cmd_help, "?": self.cmd_help,
            "search": self.cmd_search,
            "use": self.cmd_use,
            "info": self.cmd_info,
            "show": self.cmd_show,
            "run": self.cmd_run, "exploit": self.cmd_run,
            "back": self.cmd_back,
            "sessions": self.cmd_sessions,
            "hosts": self.cmd_hosts,
            "creds": self.cmd_creds,
            "vulns": self.cmd_vulns,
            "services": self.cmd_services,
            "jobs": self.cmd_jobs,
            "notes": self.cmd_notes,
            "export": self.cmd_export,
            "audit": self.cmd_audit,
            "consejos": self.cmd_consejos,
            "engagement": self.cmd_engagement,
            "attack": self.cmd_attack,
            "resource": self.cmd_resource,
            "workspace": self.cmd_workspace,
            "plugin": self.cmd_plugin,
            "report": self.cmd_report,
            "banner": self.cmd_banner,
            "history": self.cmd_history,
            "clear": self.cmd_clear,
            "exit": self.cmd_exit, "quit": self.cmd_exit,
        }
        funcion = despachador.get(cmd)
        if funcion is None:
            console.print(f"[error][✗][/error] Comando desconocido: [bold]{escape(partes[0])}[/bold]. "
                          "Escribe [bold]help[/bold].")
            return False
        funcion(args)
        return False

    # ==================================================================
    # Comandos
    # ==================================================================
    def cmd_help(self, args=None) -> None:
        """Tabla de comandos disponibles."""
        tabla = Table(title="Comandos de REDHAVOC", border_style="dim", title_style="bold white")
        tabla.add_column("Comando", style="bold cyan", no_wrap=True)
        tabla.add_column("Descripción", style="white")
        filas = [
            ("search <término>", "Buscar módulos por nombre o descripción"),
            ("use <módulo>", "Cargar un módulo (p. ej. use recon/ip_info)"),
            ("info [módulo]", "Metadatos y opciones del módulo"),
            ("show modules / options", "Listar módulos / opciones activas"),
            ("set <OPT> <valor>", "Fijar una opción (o AUTHORIZED true en raíz)"),
            ("setg <OPT> <valor>", "Fijar una opción GLOBAL aunque haya módulo cargado"),
            ("unset · unsetg <OPT>", "Restaurar el valor por defecto (módulo · global)"),
            ("run · exploit [-j]", "Ejecutar el módulo cargado (-j: job en segundo plano)"),
            ("jobs [-k ID | -k all | -c]", "Tareas en segundo plano lanzadas con run -j"),
            ("back", "Descargar el módulo actual (o Ctrl+C)"),
            ("sessions [-i N | -x N cmd | -k N]", "Listar / interactuar / comando único / cerrar sesiones"),
            ("hosts [-c]", "Ver la base de datos de hosts del workspace (-c limpia)"),
            ("creds [-c]", "Ver credenciales válidas descubiertas (-c limpia)"),
            ("vulns [-c]", "Hallazgos/vulnerabilidades confirmados (-c limpia)"),
            ("services", "Servicios/puertos descubiertos (vista plana de hosts)"),
            ("notes [add <texto> | -c]", "Notas libres del operador (persistidas en el workspace)"),
            ("workspace [new|use|del <n>]", "Workspaces múltiples estilo msf (cada uno con su DB)"),
            ("export json | csv | md", "Exportar el workspace (hosts/creds/vulns/notas) a output/"),
            ("audit [N]", "Últimos N eventos de la traza de auditoría (por defecto 20)"),
            ("consejos", "Plan de batalla: siguientes pasos según el workspace"),
            ("engagement [load|clear]", "Alcance autorizado y kill-date de la operación"),
            ("attack [técnica]", "Mapa módulos ↔ técnicas MITRE ATT&CK"),
            ("resource <fichero>", "Ejecutar un guion de comandos .rc (estilo msf)"),
            ("plugin install|list|del <pack>", "Plugins desde Git/ruta (con revisión previa)"),
            ("report", "Rutas del último informe (JSON·MD·HTML·PDF)"),
            ("banner · history · clear", "Utilidades de consola"),
            ("exit · quit", "Cerrar la sesión"),
        ]
        for a, b in filas:
            tabla.add_row(a, b)
        console.print(tabla)

    def cmd_search(self, args) -> None:
        """Busca módulos por término. Soporta filtros cat:<categoria> y
        riesgo:<nivel> combinables con texto (p. ej. search ad riesgo:medio)."""
        termino, filtros = self._parse_filtros(args)
        resultados = self.module_manager.buscar(termino)
        if "cat" in filtros:
            resultados = [c for c in resultados if c.CATEGORIA.lower() == filtros["cat"]]
        if "riesgo" in filtros:
            resultados = [c for c in resultados if c.RIESGO.lower() == filtros["riesgo"]]
        self._ultima_busqueda = list(resultados)
        if not resultados:
            console.print(f"[aviso][!][/aviso] Sin resultados para [bold]{escape(termino or '*')}[/bold].")
            console.print("[dim]Filtros disponibles: [white]cat:<categoría>[/white] · "
                          "[white]riesgo:<bajo|medio|alto>[/white][/dim]")
            return
        partes_titulo = [escape(termino or "*")]
        if "cat" in filtros:
            partes_titulo.append(f"cat={escape(filtros['cat'])}")
        if "riesgo" in filtros:
            partes_titulo.append(f"riesgo={escape(filtros['riesgo'])}")
        tabla = Table(title=f"Módulos que coinciden con [bold]{' · '.join(partes_titulo)}[/bold] "
                            f"[dim]({len(resultados)})[/dim]", border_style="dim")
        tabla.add_column("#", style="dim", justify="right")
        tabla.add_column("Módulo", style="modulo", no_wrap=True)
        tabla.add_column("Riesgo", justify="center")
        tabla.add_column("Descripción", style="white", overflow="fold")
        color_riesgo = {"bajo": "green", "medio": "yellow", "alto": "red"}
        for i, cls in enumerate(resultados, 1):
            r = color_riesgo.get(cls.RIESGO, "white")
            tabla.add_row(str(i), cls.NAME, f"[{r}]{cls.RIESGO}[/{r}]", cls.DESCRIPCION)
        console.print(tabla)
        console.print("[dim]Carga uno con: use <módulo> · o por número: use <#> "
                      "(p. ej. use 3) · filtros: cat:web · riesgo:alto[/dim]")

    @staticmethod
    def _parse_filtros(args) -> tuple:
        """Separa tokens 'clave:valor' (cat:, riesgo:) del texto libre."""
        texto: List[str] = []
        filtros: Dict[str, str] = {}
        for token in args:
            if ":" in token:
                clave, valor = token.split(":", 1)
                if clave.lower() in ("cat", "categoria", "riesgo") and valor.strip():
                    clave = "cat" if clave.lower() != "riesgo" else "riesgo"
                    filtros[clave] = valor.strip().lower()
                    continue
            texto.append(token)
        return " ".join(texto).strip(), filtros

    # ------------------------------------------------------------------
    def _resolver_modulo(self, texto: str):
        """Resuelve 'categoría/módulo' o un índice de la última búsqueda.

        `use 3` carga el tercer resultado del último `search` (paridad msf).
        Devuelve la clase o None (tras imprimir el error).
        """
        texto = (texto or "").strip()
        if texto.isdigit():
            if not self._ultima_busqueda:
                console.print("[aviso][!][/aviso] No hay búsqueda previa. Haz [bold]search "
                              "<término>[/bold] y luego usa [bold]use <número>[/bold].")
                return None
            idx = int(texto)
            if not 1 <= idx <= len(self._ultima_busqueda):
                console.print(f"[error][✗][/error] Índice fuera de rango: la última "
                              f"búsqueda devolvió {len(self._ultima_busqueda)} módulos.")
                return None
            return self._ultima_busqueda[idx - 1]
        try:
            return self.module_manager.obtener(texto)
        except ModuloNoEncontrado as err:
            console.print(f"[error][✗][/error] {escape(str(err))}")
            return None

    def cmd_use(self, args) -> None:
        """Carga un módulo y cambia el prompt."""
        if not args:
            console.print("[aviso][!][/aviso] Uso: [bold]use <categoria/modulo>[/bold] "
                          "· o [bold]use <#>[/bold] tras una búsqueda")
            return
        cls = self._resolver_modulo(" ".join(args))
        if cls is None:
            return
        self.modulo_actual = cls()
        self.modulo_actual.ctx = self.ctx
        self._restaurar_opciones_modulo(self.modulo_actual)   # persistencia v2.0
        riesgo_color = {"bajo": "green", "medio": "yellow", "alto": "red"}.get(cls.RIESGO, "white")
        attack_line = ", ".join(cls.ATTCK) if cls.ATTCK else "—"
        console.print(Panel(
            f"[modulo]{cls.NAME}[/modulo]  ·  riesgo [bold {riesgo_color}]{cls.RIESGO}[/bold {riesgo_color}]"
            f"  ·  ATT&CK [dim]{escape(attack_line)}[/dim]\n"
            f"[dim]{escape(cls.DESCRIPCION)}[/dim]\n\n"
            f"Configura con [white]set <OPT> <valor>[/white] · lanza con [white]run[/white]",
            title="[bold white]módulo cargado[/bold white]", border_style="dim", expand=False))

    def cmd_info(self, args) -> None:
        """Muestra metadatos del módulo (cargado o indicado)."""
        cls = None
        if args:
            cls = self._resolver_modulo(" ".join(args))
            if cls is None:
                return
        elif self.modulo_actual is not None:
            cls = type(self.modulo_actual)
        if cls is None:
            console.print("[aviso][!][/aviso] No hay módulo cargado. Uso: [bold]info <modulo>[/bold]")
            return

        color_riesgo = {"bajo": "green", "medio": "yellow", "alto": "red"}[cls.RIESGO]
        attack_line = ", ".join(cls.ATTCK) if cls.ATTCK else "—"
        cve_line = ", ".join(getattr(cls, "CVE", ()) or ()) or "—"
        meta = (
            f"[bold white]Nombre    [/bold white]: [modulo]{cls.NAME}[/modulo]\n"
            f"[bold white]Categoría [/bold white]: {cls.CATEGORIA}\n"
            f"[bold white]Riesgo    [/bold white]: [{color_riesgo}]{cls.RIESGO}[/{color_riesgo}]\n"
            f"[bold white]Autor     [/bold white]: {cls.AUTOR}\n"
            f"[bold white]ATT&CK    [/bold white]: {escape(attack_line)}\n"
            f"[bold white]Referencia[/bold white]: {escape(cls.REFERENCIA or '—')}\n"
            f"[bold white]CVE       [/bold white]: {escape(cve_line)}\n\n"
            f"[bold white]Descripción[/bold white]\n{escape(cls.DESCRIPCION)}"
        )
        console.print(Panel(meta, title="info", border_style="dim"))

        instancia = cls() if cls is not (type(self.modulo_actual) if self.modulo_actual else None) else self.modulo_actual
        self._tabla_opciones(instancia.opciones, titulo=f"Opciones de {cls.NAME}")

    def cmd_show(self, args) -> None:
        """show modules | show options"""
        sub = args[0].lower() if args else ""
        if sub == "modules":
            self._mostrar_arbol_modulos()
        elif sub == "options":
            if self.modulo_actual is not None:
                self._tabla_opciones(self.modulo_actual.opciones, titulo=f"Opciones de {self.modulo_actual.NAME}")
            self._tabla_opciones(self.globales, titulo="Opciones globales")
        else:
            console.print("[aviso][!][/aviso] Uso: [bold]show modules[/bold] o [bold]show options[/bold]")

    def cmd_set(self, args, deshacer: bool = False, solo_global: bool = False) -> None:
        """set/unset OPT VAL — global si no hay módulo cargado.

        setg/unsetg (solo_global=True) afectan SIEMPRE a las opciones
        globales, aunque haya un módulo cargado (paridad msf).
        """
        if not args:
            console.print("[aviso][!][/aviso] Uso: [bold]set <OPT> <valor>[/bold] "
                          "· global: [bold]setg <OPT> <valor>[/bold]")
            return
        opt = args[0].upper()
        valor = " ".join(args[1:]) if len(args) > 1 and not deshacer else ""

        # Validación amable de opciones numéricas (evita fallos tardíos en el run)
        if not deshacer and valor and opt in ("THREADS", "TIMEOUT", "PUERTOS_HILOS"):
            if not valor.isdigit() or int(valor) <= 0:
                console.print(f"[error][✗][/error] {escape(opt)} espera un entero positivo, "
                              f"no [bold]{escape(valor)}[/bold] (p. ej. set {opt} 20)")
                return
        if solo_global:
            destino, ambito = self.globales, "global"
        else:
            destino = self.modulo_actual.opciones if self.modulo_actual is not None else self.globales
            ambito = self.modulo_actual.NAME if self.modulo_actual is not None else "global"

        if deshacer:
            if destino.unset(opt):
                self._persistir_opcion(ambito, opt, None)
                console.print(f"[ok][✓][/ok] {escape(opt)} restaurada ([dim]{ambito}[/dim]).")
            else:
                console.print(f"[error][✗][/error] Opción desconocida: {escape(opt)}")
        else:
            if valor == "":
                console.print("[aviso][!][/aviso] Uso: [bold]set <OPT> <valor>[/bold]")
                return
            if destino.set(opt, valor):
                self._persistir_opcion(ambito, opt, valor)
                console.print(f"[ok][✓][/ok] {escape(opt)} => [valor]{escape(valor)}[/valor] ([dim]{ambito}[/dim])")
            else:
                disponibles = ", ".join(o.nombre for o in destino) or "—"
                console.print(f"[error][✗][/error] Opción desconocida: {escape(opt)}. "
                              f"Disponibles: {escape(disponibles)}")

    def cmd_run(self, args=None) -> None:
        """Ejecuta el módulo cargado con validación, ética y reporte.

        run -j: lanza la ejecución como job en segundo plano (ver `jobs`).
        Si el módulo declara la opción RHOSTS y tiene valor, se hace un
        barrido multi-host (estilo NetExec): el framework expande los
        objetivos y ejecuta el módulo contra cada uno con THREADS hilos,
        pintando una línea de resultado por host.
        """
        args = list(args or [])
        en_fondo = "-j" in args
        if en_fondo:
            args.remove("-j")
        if self.modulo_actual is None:
            console.print("[error][✗][/error] No hay módulo cargado. Usa [bold]use <modulo>[/bold].")
            return
        modulo = self.modulo_actual

        # --- RHOSTS: objetivos multi-host (estilo NetExec) ----------------
        texto_rhosts = ""
        excluir: tuple = ()
        if "RHOSTS" in modulo.opciones:
            texto_rhosts = modulo.opciones.get("RHOSTS").strip()
            if texto_rhosts:
                excluir = ("RHOST", "TARGET")
        error = modulo.opciones.validar_o_error(excluir)
        if error:
            console.print(f"[error][✗][/error] {escape(str(error))}")
            console.print("[dim]Pista: set <OPT> <valor> · show options[/dim]")
            return
        objetivos: List[str] = []
        if texto_rhosts:
            try:
                objetivos = expandir_objetivos(texto_rhosts)
            except ObjetivoError as err:
                console.print(f"[error][✗][/error] {escape(str(err))}")
                return
            if not objetivos:
                console.print("[error][✗][/error] RHOSTS no produjo ningún objetivo.")
                return

        # --- Engagement: scope y kill-date -------------------------------
        if self.engagement.activo():
            if objetivos:
                objetivos = self._filtrar_por_scope(modulo, objetivos)
                if not objetivos:
                    return
            else:
                valores = {o.nombre: o.valor for o in modulo.opciones if o.valor}
                fuera_permitido = False
                for nombre in NOMBRES_OBJETIVO:
                    permitido, motivo = self.engagement.verifica(valores.get(nombre, ""))
                    if not permitido:
                        console.print(Panel(
                            f"[bold red]BLOQUEADO por el engagement[/bold red]\n{escape(motivo)}\n\n"
                            "Actualiza el alcance (engagement load) o trabaja solo con "
                            "objetivos dentro del alcance autorizado.",
                            border_style="red", title="engagement"))
                        self.ethics.auditar("BLOQUEO_ENGAGEMENT", f"{modulo.NAME}: {motivo}")
                        return
                    if "fuera del alcance" in motivo:
                        fuera_permitido = True
                if fuera_permitido:
                    self.ethics.auditar("OBJETIVO_FUERA_ALCANCE_PERMITIDO", modulo.NAME)

        # --- Puerta ética para módulos de riesgo alto -------------------
        if str(modulo.RIESGO).lower() == "alto":
            autorizado = (self.globales.get_bool("AUTHORIZED")
                          or EthicsGate.autorizado())
            if not autorizado:
                console.print(Panel(
                    "[bold yellow]Módulo de RIESGO ALTO[/bold yellow]\n"
                    "Solo para entornos con AUTORIZACIÓN EXPRESA del propietario.\n\n"
                    "Fija [bold]set AUTHORIZED true[/bold] (o exporta [bold]REDHAVOC_AUTHORIZED=1[/bold]) "
                    "declarando bajo tu responsabilidad que cuentas con ese permiso.",
                    border_style="yellow", title="ética"))
                self.ethics.auditar("BLOQUEO_RIESGO_ALTO", modulo.NAME)
                return

        # --- Ejecución ---------------------------------------------------
        opciones_usadas = {o.nombre: o.valor for o in modulo.opciones if o.valor}
        objetivo = texto_rhosts or (modulo.opt("TARGET") or modulo.opt("URL")
                                    or modulo.opt("DOMAIN") or modulo.opt("LHOST")
                                    or modulo.opt("HOST") or "—")

        if en_fondo:
            self._lanzar_job(modulo, objetivos, str(objetivo), opciones_usadas)
            return

        console.print(f"[info][*][/info] Ejecutando [modulo]{modulo.NAME}[/modulo] "
                      f"contra [bold]{escape(str(objetivo))}[/bold] ...")
        inicio = time.time()
        if objetivos:
            resultados, tipo_error = self._ejecutar_multihost(modulo, objetivos)
        else:
            resultados, tipo_error = self._ejecutar_solo(modulo)
        duracion = time.time() - inicio
        if resultados is None:
            if tipo_error == "controlado":
                self.ethics.auditar("FALLO_MODULO", modulo.NAME)
            return

        modulo.resultado = resultados
        console.print(f"[ok][+][/ok] Módulo completado en [bold]{duracion:.1f}s[/bold].")

        # --- Resultados EN la terminal (paneles/tablas/columnas) ---------
        if objetivos:
            # En multi-host el detalle ya se pintó línea a línea; los
            # siguientes pasos se deduplican de TODOS los resultados.
            self._consejos_multihost(modulo.NAME, resultados)
        elif isinstance(resultados, dict) and resultados:
            mostrar_resultado(modulo.NAME, resultados, console)
            # --- Siguientes pasos accionables (playbook) -----------------
            mostrar_consejos(modulo.NAME, resultados, console)

        # --- Reporte -----------------------------------------------------
        if self.globales.get_bool("REPORT", True):
            ruta = self.reporter.guardar(modulo.NAME, objetivo, modulo.resultado, opciones_usadas)
            self._informes_sesion += 1
            console.print(f"[info][*][/info] Informe: [dim]{ruta}[/dim] (+ .md)")
        self.ethics.auditar("RUN", f"{modulo.NAME} -> {objetivo} ({duracion:.1f}s)")

    # ------------------------------------------------------------------
    # Ejecución: single-host, multi-host (NetExec-like) y jobs
    # ------------------------------------------------------------------
    def _filtrar_por_scope(self, modulo, objetivos: List[str]) -> List[str]:
        """Engagement activo + barrido multi-host: verifica cada objetivo.

        Devuelve la lista depurada (solo los permitidos). Si TODOS están
        bloqueados muestra el panel y devuelve [].
        """
        bloqueados: List[tuple] = []
        permitidos: List[str] = []
        for obj in objetivos:
            permitido, motivo = self.engagement.verifica(obj)
            if permitido:
                permitidos.append(obj)
                if "fuera del alcance" in motivo:
                    self.ethics.auditar("OBJETIVO_FUERA_ALCANCE_PERMITIDO",
                                        f"{modulo.NAME}: {obj}")
            else:
                bloqueados.append((obj, motivo))
                self.ethics.auditar("BLOQUEO_ENGAGEMENT", f"{modulo.NAME}: {motivo}")
        for obj, motivo in bloqueados:
            console.print(f"[error][✗][/error] {escape(obj)}: {escape(motivo)}")
        if bloqueados and not permitidos:
            console.print(Panel(
                "[bold red]BLOQUEADO por el engagement[/bold red]\n"
                "Ningún objetivo del barrido está dentro del alcance autorizado.\n\n"
                "Actualiza el alcance (engagement load) o revisa RHOSTS.",
                border_style="red", title="engagement"))
            return []
        if bloqueados:
            console.print(f"[aviso][!][/aviso] {len(bloqueados)} objetivo(s) excluidos "
                          "del barrido por el engagement.")
        return permitidos

    def _ejecutar_solo(self, modulo, silencioso: bool = False):
        """Ejecución single-host. Devuelve (resultados, None) o (None, tipo)."""
        try:
            if silencioso or getattr(modulo, "INTERACTIVO", False):
                # Jobs y handlers interactivos: sin spinner (salida en vivo).
                resultados = modulo.ejecutar()
            else:
                # Spinner propio con cronómetro en vivo; las impresiones del
                # módulo se apilan encima del spinner en tiempo real.
                with trabajo(modulo.NAME):
                    resultados = modulo.ejecutar()
        except ModuloError as err:
            console.print(f"[error][✗][/error] {escape(str(err))}")
            return None, "controlado"
        except KeyboardInterrupt:
            console.print("\n[aviso][!][/aviso] Módulo interrumpido por el operador.")
            return None, "interrumpido"
        except Exception as err:  # noqa: BLE001
            console.print(f"[error][✗][/error] Fallo inesperado: {escape(str(err))}")
            if self.globales.get_bool("VERBOSE"):
                console.print_exception()
            return None, "inesperado"
        return resultados or {}, None

    @staticmethod
    def _opcion_host_de(modulo) -> Optional[str]:
        """Nombre de la opción que fija el host en el módulo dado."""
        for nombre in ("RHOST", "TARGET"):
            if nombre in modulo.opciones:
                return nombre
        return None

    def _clonar_modulo(self, modulo, opcion_host: str, host: str):
        """Instancia limpia del módulo con las opciones actuales y el host dado.

        Cada hilo del barrido trabaja sobre SU instancia: sin condiciones
        de carrera sobre las opciones compartidas.
        """
        instancia = type(modulo)()
        instancia.ctx = self.ctx
        for o in modulo.opciones:
            instancia.opciones.set(o.nombre, o.valor)
        instancia.opciones.set(opcion_host, host)
        return instancia

    def _ejecutar_multihost(self, modulo, objetivos: List[str],
                            silencioso: bool = False, job: Optional[Dict] = None):
        """Barrido multi-host: clona el módulo por objetivo y ejecuta.

        THREADS hilos, una línea de resultado por host (estilo NetExec) y
        agregado consolidado para el informe. Devuelve (agregado, None)
        o (None, tipo_error).
        """
        opcion_host = self._opcion_host_de(modulo)
        if opcion_host is None:
            console.print("[error][✗][/error] El módulo no declara RHOST ni TARGET: "
                          "no puede ejecutarse en modo multi-host.")
            return None, "controlado"
        hilos = self.globales.get_int("THREADS", 10) or 10
        hilos = max(1, min(hilos, len(objetivos)))
        inicio = time.time()
        agregado: Dict = {"modo": "multi-host", "objetivos": len(objetivos),
                          "resultados": {}}
        contadores = {"ok": 0, "fallos": 0, "hecho": 0}

        def _uno(host: str):
            if job is not None and job["cancelar"].is_set():
                return host, None, "cancelado"
            try:
                instancia = self._clonar_modulo(modulo, opcion_host, host)
                return host, instancia.ejecutar(), None
            except ModuloError as err:
                return host, None, str(err)
            except Exception as err:  # noqa: BLE001
                return host, None, f"fallo inesperado: {err}"

        def _recibir(host: str, res, fallo) -> None:
            if not silencioso:
                self._linea_host(host, res, fallo)
            if fallo is None:
                contadores["ok"] += 1
                agregado["resultados"][host] = res if isinstance(res, dict) \
                    else {"resumen": str(res)}
            else:
                contadores["fallos"] += 1
                agregado["resultados"][host] = {"error": fallo}
            contadores["hecho"] += 1
            if job is not None:
                job["hecho"] = contadores["hecho"]

        if silencioso:
            if hilos <= 1:
                for host in objetivos:
                    h, res, fallo = _uno(host)
                    _recibir(h, res, fallo)
            else:
                with ThreadPoolExecutor(max_workers=hilos) as pool:
                    futuros = [pool.submit(_uno, host) for host in objetivos]
                    for futuro in as_completed(futuros):
                        h, res, fallo = futuro.result()
                        _recibir(h, res, fallo)
        else:
            with trabajo(f"{modulo.NAME} · {len(objetivos)} objetivos"):
                if hilos <= 1:
                    for host in objetivos:
                        h, res, fallo = _uno(host)
                        _recibir(h, res, fallo)
                else:
                    with ThreadPoolExecutor(max_workers=hilos) as pool:
                        futuros = [pool.submit(_uno, host) for host in objetivos]
                        for futuro in as_completed(futuros):
                            h, res, fallo = futuro.result()
                            _recibir(h, res, fallo)

        duracion = time.time() - inicio
        agregado["ok"] = contadores["ok"]
        agregado["fallos"] = contadores["fallos"]
        agregado["duracion"] = round(duracion, 1)
        if not silencioso:
            console.print(f"[info][*][/info] Barrido completado: [bold]{contadores['ok']}"
                          f"[/bold] OK · [bold]{contadores['fallos']}[/bold] fallos · "
                          f"[bold]{duracion:.1f}s[/bold] ({hilos} hilos).")
        return agregado, None

    @staticmethod
    def _linea_host(host: str, resultado, fallo) -> None:
        """Una línea de resultado por host (el sello NetExec)."""
        host_txt = f"[bold cyan]{escape(host)}[/bold cyan]"
        if fallo == "cancelado":
            console.print(f"[aviso][!][/aviso] {host_txt} · cancelado")
        elif fallo:
            console.print(f"[error][−][/error] {host_txt} · {escape(fallo)}")
        else:
            linea = ""
            if isinstance(resultado, dict):
                linea = str(resultado.get("resumen") or resultado.get("nota") or "")
            console.print(f"[ok][+][/ok] {host_txt} · {escape(linea or 'completado')}")

    def _consejos_multihost(self, nombre: str, agregado: Dict) -> None:
        """Siguientes pasos deduplicados a partir de TODOS los resultados."""
        try:
            vistos = set()
            unicos = []
            for res in (agregado.get("resultados") or {}).values():
                if not isinstance(res, dict) or res.get("error"):
                    continue
                for consejo in consejos_de_resultado(nombre, res):
                    clave = (consejo.texto, consejo.comando)
                    if clave not in vistos:
                        vistos.add(clave)
                        unicos.append(consejo)
            if unicos:
                mostrar_consejos_lista(unicos[:4], console)
        except Exception:  # noqa: BLE001 — los consejos jamás rompen un run
            pass

    # ------------------------------------------------------------------
    # Jobs en segundo plano (run -j)
    # ------------------------------------------------------------------
    def _lanzar_job(self, modulo, objetivos: List[str], objetivo_txt: str,
                    opciones_usadas: Dict) -> None:
        job_id = self._siguiente_id_job
        self._siguiente_id_job += 1
        job: Dict = {
            "id": job_id, "modulo": modulo.NAME, "objetivo": objetivo_txt,
            "estado": "ejecutando", "inicio": time.time(), "fin": None,
            "resumen": "", "ruta_informe": None, "hecho": 0,
            "total": len(objetivos) or 1, "cancelar": threading.Event(),
        }
        self.jobs[job_id] = job
        hilo = threading.Thread(
            target=self._trabajador_job,
            args=(job, modulo, objetivos, opciones_usadas, objetivo_txt),
            name=f"redhavoc-job-{job_id}", daemon=True)
        hilo.start()
        modo = f"{len(objetivos)} objetivos" if objetivos else "ejecución única"
        console.print(f"[ok][✓][/ok] Job [bold cyan]#{job_id}[/bold cyan] en segundo plano "
                      f"· [modulo]{modulo.NAME}[/modulo] → {escape(objetivo_txt)} "
                      f"[dim]({modo})[/dim] · consulta con [bold]jobs[/bold]")

    def _trabajador_job(self, job: Dict, modulo, objetivos: List[str],
                        opciones_usadas: Dict, objetivo_txt: str) -> None:
        """Cuerpo del job: ejecuta, guarda informe y actualiza el estado."""
        try:
            if objetivos:
                resultados, tipo_error = self._ejecutar_multihost(
                    modulo, objetivos, silencioso=True, job=job)
            else:
                resultados, tipo_error = self._ejecutar_solo(modulo, silencioso=True)
            job["fin"] = time.time()
            if resultados is None:
                job["estado"] = "cancelado" if tipo_error == "cancelado" else "error"
                job["resumen"] = {
                    "controlado": "el módulo terminó con error (ver el detalle al reejecutar)",
                    "interrumpido": "interrumpido",
                    "cancelado": "orden de parada recibida",
                }.get(tipo_error or "", "error durante la ejecución")
                self.ethics.auditar("JOB_FIN", f"#{job['id']} {modulo.NAME} ({job['estado']})")
                return
            if job["cancelar"].is_set():
                # Parada recibida a mitad de barrido: los hosts restantes
                # quedaron como "cancelado" en el agregado.
                job["estado"] = "cancelado"
                job["resumen"] = (f"parado tras {resultados.get('ok', 0)} OK de "
                                  f"{resultados.get('objetivos', 0)} objetivos")
                self.ethics.auditar("JOB_FIN", f"#{job['id']} {modulo.NAME} cancelado")
                return
            job["estado"] = "completado"
            job["resumen"] = self._resumen_resultado(resultados)
            if self.globales.get_bool("REPORT", True):
                with self._lock_reporte:
                    ruta = self.reporter.guardar(modulo.NAME, objetivo_txt,
                                                 resultados, opciones_usadas)
                job["ruta_informe"] = str(ruta)
            self.ethics.auditar("JOB_FIN", f"#{job['id']} {modulo.NAME} completado")
        except Exception as err:  # noqa: BLE001 — un job jamás tumba la consola
            job["fin"] = time.time()
            job["estado"] = "error"
            job["resumen"] = f"fallo inesperado: {err}"

    @staticmethod
    def _resumen_resultado(resultados) -> str:
        """Resumen corto del resultado de un job para el listado."""
        if isinstance(resultados, dict):
            if resultados.get("modo") == "multi-host":
                return (f"{resultados.get('ok', 0)} OK · {resultados.get('fallos', 0)} "
                        f"fallos de {resultados.get('objetivos', 0)} objetivos")
            resumen = resultados.get("resumen")
            if resumen:
                return str(resumen)
        return "completado"

    def cmd_jobs(self, args) -> None:
        """jobs | jobs -k <ID> | jobs -k all | jobs -c — tareas en segundo plano."""
        if args and args[0] == "-k":
            if len(args) > 1 and args[1].lower() == "all":
                vivos = 0
                for job in list(self.jobs.values()):
                    if job["estado"] == "ejecutando":
                        job["cancelar"].set()
                        vivos += 1
                    self.jobs.pop(job["id"], None)
                console.print(f"[ok][✓][/ok] Jobs cerrados ({vivos} en marcha recibieron "
                              "la orden de parada; se detendrán entre objetivos).")
                return
            if len(args) < 2:
                console.print("[aviso][!][/aviso] Uso: jobs -k <ID> | jobs -k all | jobs -c")
                return
            try:
                jid = int(args[1])
            except ValueError:
                console.print("[error][✗][/error] ID de job inválido.")
                return
            job = self.jobs.get(jid)
            if job is None:
                console.print(f"[error][✗][/error] El job {jid} no existe.")
                return
            if job["estado"] == "ejecutando":
                job["cancelar"].set()
                console.print(f"[ok][✓][/ok] Job #{jid}: orden de parada enviada "
                              "(se detiene entre objetivos o al terminar la operación "
                              "de red en curso).")
            else:
                self.jobs.pop(jid, None)
                console.print(f"[ok][✓][/ok] Job #{jid} eliminado del listado.")
            return
        if args and args[0] == "-c":
            activos = {j["id"]: j for j in self.jobs.values()
                       if j["estado"] == "ejecutando"}
            total = len(self.jobs) - len(activos)
            self.jobs = activos
            console.print(f"[ok][✓][/ok] Listado limpiado ({total} job(s) terminados "
                          "eliminados; los activos se conservan).")
            return
        if args:
            console.print("[aviso][!][/aviso] Uso: jobs | jobs -k <ID> | jobs -k all | jobs -c")
            return
        if not self.jobs:
            console.print("[dim]No hay jobs. Lanza un módulo en segundo plano con: "
                          "[white]run -j[/white] · luego consulta con jobs[/dim]")
            return
        tabla = Table(title="Jobs en segundo plano", border_style="dim")
        tabla.add_column("ID", justify="right", style="bold cyan")
        tabla.add_column("Módulo", style="modulo", no_wrap=True)
        tabla.add_column("Objetivo", style="white", overflow="fold")
        tabla.add_column("Estado", justify="center", no_wrap=True)
        tabla.add_column("Dur.", justify="right", style="dim")
        tabla.add_column("Detalle", style="white", overflow="fold")
        for job in sorted(self.jobs.values(), key=lambda j: j["id"]):
            estado = job["estado"]
            color = {"ejecutando": "yellow", "completado": "green",
                     "cancelado": "yellow"}.get(estado, "red")
            if estado == "ejecutando" and job.get("total", 1) > 1:
                detalle = f"{job.get('hecho', 0)}/{job['total']} objetivos"
            else:
                detalle = job.get("resumen") or ""
            fin = job["fin"] or time.time()
            tabla.add_row(str(job["id"]), job["modulo"], str(job["objetivo"]),
                          f"[{color}]{estado}[/{color}]", f"{fin - job['inicio']:.0f}s",
                          escape(detalle))
        console.print(tabla)
        console.print("[dim]Para un job: jobs -k <ID> · todos: jobs -k all · "
                      "limpia terminados: jobs -c · los informes quedan en output/[/dim]")

    # ------------------------------------------------------------------
    def cmd_services(self, args) -> None:
        """Tabla de servicios/puertos descubiertos (vista plana de hosts)."""
        filas: List[tuple] = []
        for h in self.workspace_db.hosts():
            for entrada in h.get("servicios", []):
                texto = str(entrada)
                puerto, _, srv = texto.partition("/")
                filas.append((h["ip"], puerto or texto, srv or "?",
                              h.get("hostname") or ""))
        if not filas:
            console.print("[dim]Sin servicios registrados todavía: los escáneres "
                          "los añaden (recon/port_scanner, ad/smb_check, "
                          "recon/ping_sweep...).[/dim]")
            return
        tabla = Table(title=f"Servicios descubiertos [dim]({len(filas)})[/dim]",
                      border_style="dim")
        tabla.add_column("IP", style="bold cyan", no_wrap=True)
        tabla.add_column("Puerto", justify="right", style="white", no_wrap=True)
        tabla.add_column("Servicio", style="valor", no_wrap=True)
        tabla.add_column("Hostname", style="dim", overflow="fold")
        for ip, puerto, srv, hostname in filas:
            tabla.add_row(ip, puerto, srv, hostname or "—")
        console.print(tabla)
        console.print("[dim]Los servicios viven en la tabla de hosts: se limpian "
                      "con hosts -c[/dim]")

    def cmd_back(self, args=None) -> None:
        """Descarga el módulo actual."""
        if self.modulo_actual is None:
            console.print("[dim]Ya estás en el prompt raíz.[/dim]")
            return
        console.print(f"[dim][*] Módulo descargado: {self.modulo_actual.NAME}[/dim]")
        self.modulo_actual = None

    def cmd_sessions(self, args) -> None:
        """Gestión de sesiones del multi_handler."""
        if not self.sesiones:
            console.print("[dim]No hay sesiones activas. Lanza post/multi_handler para crearlas.[/dim]")
            return
        # sessions            → listar
        if not args:
            tabla = Table(title="Sesiones activas", border_style="dim")
            tabla.add_column("ID", justify="right", style="bold cyan")
            tabla.add_column("Origen", style="white")
            tabla.add_column("Abierta", style="dim")
            for sid, ses in sorted(self.sesiones.items()):
                tabla.add_row(str(sid), f"{ses['addr'][0]}:{ses['addr'][1]}",
                              time.strftime("%H:%M:%S", time.localtime(ses["abierta"])))
            console.print(tabla)
            console.print("[dim]Interactúa: sessions -i <ID> · comando único: sessions -x <ID> <cmd> "
                          "· cierra: sessions -k <ID> · todas: sessions -k all[/dim]")
            return
        if args[0] == "-i" and len(args) > 1:
            self._interactuar_sesion(args[1])
        elif args[0] == "-x" and len(args) >= 3:
            self._comando_en_sesion(args[1], " ".join(args[2:]))
        elif args[0] == "-k" and len(args) > 1:
            if args[1].lower() == "all":
                total = len(self.sesiones)
                for sid, ses in list(self.sesiones.items()):
                    try:
                        ses["conn"].close()
                    except OSError:
                        pass
                    self.sesiones.pop(sid, None)
                console.print(f"[ok][✓][/ok] {total} sesiones cerradas.")
            else:
                self._cerrar_sesion(args[1])
        else:
            console.print("[aviso][!][/aviso] Uso: sessions | sessions -i <ID> | "
                          "sessions -x <ID> <comando> | sessions -k <ID> | sessions -k all")

    def _comando_en_sesion(self, sid_txt: str, comando: str) -> None:
        """Ejecuta un comando en una sesión SIN entrar en modo interactivo
        (equivalente a sessions -i + comando + background, en un paso)."""
        try:
            sid = int(sid_txt)
        except ValueError:
            console.print("[error][✗][/error] ID de sesión inválido.")
            return
        ses = self.sesiones.get(sid)
        if ses is None:
            console.print(f"[error][✗][/error] La sesión {sid} no existe.")
            return
        conn = ses["conn"]
        console.print(f"[bold cyan]sesión {sid}[/bold cyan] > {escape(comando)}")
        try:
            conn.sendall((comando + "\n").encode())
            conn.settimeout(2.0)
            salida = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                except Exception:  # timeout ⇒ fin de la respuesta
                    break
                if not chunk:
                    break
                salida += chunk
            texto = salida.decode(errors="replace")
            console.print(texto or "[dim](sin salida)[/dim]")
        except OSError as err:
            console.print(f"[error][✗][/error] Conexión perdida: {err}")
            self.sesiones.pop(sid, None)

    def _interactuar_sesion(self, sid_txt: str) -> None:
        """Bucle interactivo con una sesión (shell reversa simplificada)."""
        try:
            sid = int(sid_txt)
        except ValueError:
            console.print("[error][✗][/error] ID de sesión inválido.")
            return
        ses = self.sesiones.get(sid)
        if ses is None:
            console.print(f"[error][✗][/error] La sesión {sid} no existe.")
            return
        conn = ses["conn"]
        console.print(f"[ok][✓][/ok] Interactuando con sesión [bold cyan]{sid}[/bold cyan] "
                      f"({ses['addr'][0]}). Escribe [bold]background[/bold] para volver.")
        while True:
            try:
                cmd = console.input("[bold cyan]shell[/bold cyan] [white]>[/white] ")
            except (EOFError, KeyboardInterrupt):
                break
            if cmd.strip().lower() in ("background", "bg", "exit"):
                break
            if not cmd.strip():
                continue
            try:
                conn.sendall((cmd + "\n").encode())
                conn.settimeout(2.0)
                salida = b""
                while True:
                    try:
                        chunk = conn.recv(4096)
                    except Exception:  # timeout ⇒ fin de la respuesta
                        break
                    if not chunk:
                        break
                    salida += chunk
                console.print(salida.decode(errors="replace") or "[dim](sin salida)[/dim]")
            except OSError as err:
                console.print(f"[error][✗][/error] Conexión perdida: {err}")
                self.sesiones.pop(sid, None)
                break

    def _cerrar_sesion(self, sid_txt: str) -> None:
        """Cierra una sesión por ID."""
        try:
            sid = int(sid_txt)
        except ValueError:
            console.print("[error][✗][/error] ID de sesión inválido.")
            return
        ses = self.sesiones.pop(sid, None)
        if ses:
            try:
                ses["conn"].close()
            except OSError:
                pass
            console.print(f"[ok][✓][/ok] Sesión {sid} cerrada.")
        else:
            console.print(f"[error][✗][/error] La sesión {sid} no existe.")

    def cmd_hosts(self, args) -> None:
        """Base de datos de hosts del workspace (autorellenada por los módulos)."""
        if args and args[0] == "-c":
            self.workspace_db.limpiar_hosts()
            console.print("[ok][✓][/ok] Tabla de hosts vaciada (creds y hallazgos se conservan).")
            return
        hosts = self.workspace_db.hosts()
        if not hosts:
            console.print("[dim]No hay hosts en el workspace. Los módulos de recon los "
                          "añaden automáticamente (p. ej. recon/port_scanner).[/dim]")
            return
        tabla = Table(title=f"Hosts del workspace [dim]({len(hosts)})[/dim]",
                      border_style="dim")
        tabla.add_column("IP", style="bold cyan", no_wrap=True)
        tabla.add_column("Hostname", style="white")
        tabla.add_column("Servicios", style="valor", overflow="fold")
        tabla.add_column("Visto", style="dim")
        for h in hosts:
            tabla.add_row(h["ip"], h.get("hostname") or "—",
                          ", ".join(h.get("servicios", [])) or "—", h.get("visto", ""))
        console.print(tabla)
        console.print("[dim]Limpia con: hosts -c[/dim]")

    def cmd_creds(self, args) -> None:
        """Credenciales válidas descubiertas durante la operación."""
        if args and args[0] == "-c":
            self.workspace_db.limpiar_creds()
            console.print("[ok][✓][/ok] Credenciales borradas (hosts y hallazgos se conservan).")
            return
        creds = self.workspace_db.creds()
        if not creds:
            console.print("[dim]No hay credenciales registradas. Los módulos de brute "
                          "guardan aquí las válidas (con AUTHORIZED).[/dim]")
            return
        tabla = Table(title=f"Credenciales válidas [dim]({len(creds)})[/dim]",
                      border_style="dim")
        tabla.add_column("IP", style="bold cyan", no_wrap=True)
        tabla.add_column("Usuario", style="white")
        tabla.add_column("Secreto", style="valor")
        tabla.add_column("Servicio", style="white")
        tabla.add_column("Hora", style="dim")
        for c in creds:
            tabla.add_row(c.get("ip", ""), c.get("usuario", ""),
                          c.get("secreto", ""), c.get("servicio", ""),
                          c.get("hora", ""))
        console.print(tabla)
        console.print("[dim]Limpia con: creds -c[/dim]")

    def cmd_vulns(self, args) -> None:
        """Hallazgos/vulnerabilidades confirmados acumulados en el workspace."""
        if args and args[0] == "-c":
            self.workspace_db.limpiar_vulns()
            console.print("[ok][✓][/ok] Hallazgos borrados (hosts y creds se conservan).")
            return
        hallazgos = self.workspace_db.vulns()
        if not hallazgos:
            console.print("[dim]No hay hallazgos registrados. Módulos como "
                          "smb_check, jwt_analyzer, cookie_audit o ssti_scanner "
                          "los añaden automáticamente.[/dim]")
            return
        colores = {"info": "dim", "bajo": "green", "medio": "yellow",
                   "alto": "red", "critico": "bold red"}
        tabla = Table(title=f"Hallazgos del workspace [dim]({len(hallazgos)})[/dim]",
                      border_style="dim")
        tabla.add_column("Sev", justify="center", no_wrap=True)
        tabla.add_column("Host", style="bold cyan", no_wrap=True)
        tabla.add_column("Hallazgo", style="white", overflow="fold")
        tabla.add_column("Módulo", style="dim", no_wrap=True)
        for v in hallazgos:
            color = colores.get(v.get("severidad"), "white")
            tabla.add_row(f"[{color}]{v['severidad']}[/{color}]",
                          v.get("host") or "—", v.get("titulo", ""),
                          v.get("modulo", ""))
        console.print(tabla)
        console.print("[dim]Los informes JSON/MD/HTML incluyen el detalle completo "
                      "· limpia con: vulns -c[/dim]")

    def cmd_notes(self, args) -> None:
        """notes | notes add <texto> | notes -c — cuaderno del operador."""
        if args and args[0] == "-c":
            self.workspace_db.limpiar_notas()
            console.print("[ok][✓][/ok] Notas borradas (hosts, creds y hallazgos se conservan).")
            return
        if args and args[0].lower() == "add":
            texto = " ".join(args[1:]).strip()
            if not texto:
                console.print("[aviso][!][/aviso] Uso: [bold]notes add <texto>[/bold]")
                return
            entrada = self.workspace_db.add_nota(texto)
            console.print(f"[ok][✓][/ok] Nota guardada [dim]({entrada.get('hora', '')})[/dim].")
            return
        if args:
            console.print("[aviso][!][/aviso] Uso: notes | [bold]notes add <texto>[/bold] | notes -c")
            return
        notas = self.workspace_db.notas()
        if not notas:
            console.print("[dim]Sin notas. Añade con: notes add <texto> "
                          "(p. ej. notes add 'DMZ con red plana, revisar segmentación')[/dim]")
            return
        tabla = Table(title=f"Notas del operador [dim]({len(notas)})[/dim]",
                      border_style="dim")
        tabla.add_column("#", style="dim", justify="right", no_wrap=True)
        tabla.add_column("Hora", style="dim", no_wrap=True)
        tabla.add_column("Nota", style="white", overflow="fold")
        for i, n in enumerate(notas, 1):
            tabla.add_row(str(i), n.get("hora", ""), n.get("texto", ""))
        console.print(tabla)
        console.print("[dim]Añade con: notes add <texto> · limpia con: notes -c[/dim]")

    def cmd_export(self, args) -> None:
        """export json | csv | md | pdf — vuelca el workspace a output/."""
        formato = (args[0].lower() if args else "json")
        if formato not in ("json", "csv", "md", "markdown", "pdf"):
            console.print("[aviso][!][/aviso] Uso: [bold]export json[/bold] | "
                          "[bold]export csv[/bold] | [bold]export md[/bold] | "
                          "[bold]export pdf[/bold]")
            return
        formato = "md" if formato == "markdown" else formato
        datos = {
            "hosts": self.workspace_db.hosts(),
            "creds": self.workspace_db.creds(),
            "vulns": self.workspace_db.vulns(),
            "notas": self.workspace_db.notas(),
        }
        if not any(datos.values()):
            console.print("[dim]El workspace está vacío: nada que exportar "
                          "(ejecuta un módulo de recon primero).[/dim]")
            return
        marca = time.strftime("%Y-%m-%d_%H-%M-%S")
        carpeta = self.reporter.carpeta
        escritos: List[str] = []
        try:
            if formato == "json":
                ruta = carpeta / f"export_{marca}.json"
                ruta.write_text(json.dumps(
                    {"framework": "REDHAVOC", "fecha": time.strftime("%Y-%m-%d %H:%M:%S"),
                     **datos}, indent=2, ensure_ascii=False), encoding="utf-8")
                escritos.append(str(ruta))
            elif formato == "pdf":
                from core.pdf_min import DocumentoPDF
                doc = DocumentoPDF("REDHAVOC - export del workspace")
                doc.titulo_doc("REDHAVOC - Export del workspace")
                doc.meta("Fecha", time.strftime("%Y-%m-%d %H:%M:%S"))
                secciones = (
                    ("hosts", "Hosts"), ("creds", "Credenciales válidas"),
                    ("vulns", "Hallazgos"), ("notas", "Notas del operador"),
                )
                for clave, titulo in secciones:
                    doc.seccion(f"{titulo} ({len(datos[clave])})")
                    if datos[clave]:
                        doc.tabla(datos[clave])
                    else:
                        doc.parrafo("(vacío)")
                ruta = carpeta / f"export_{marca}.pdf"
                doc.guardar(ruta)
                escritos.append(str(ruta))
            elif formato == "csv":
                for tabla, filas in datos.items():
                    if not filas:
                        continue
                    ruta = carpeta / f"export_{tabla}_{marca}.csv"
                    columnas = self._columnas_csv(filas)
                    lineas = [",".join(columnas)]
                    for fila in filas:
                        lineas.append(",".join(
                            self._celda_csv(fila.get(c, "")) for c in columnas))
                    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
                    escritos.append(str(ruta))
            else:
                ruta = carpeta / f"export_{marca}.md"
                ruta.write_text(self._export_markdown(datos), encoding="utf-8")
                escritos.append(str(ruta))
        except OSError as err:
            console.print(f"[error][✗][/error] No se pudo exportar: {escape(str(err))}")
            return
        console.print(f"[ok][✓][/ok] Exportado ({formato.upper()}):")
        for ruta in escritos:
            console.print(f"    [dim]{escape(ruta)}[/dim]")

    @staticmethod
    def _columnas_csv(filas: List[Dict]) -> List[str]:
        """Unión ordenada de claves de las filas (hosts usan ip primero)."""
        columnas: List[str] = []
        for fila in filas:
            for clave in fila:
                if clave not in columnas:
                    columnas.append(clave)
        # los listados (servicios) se serializan con join en _celda_csv
        return columnas

    @staticmethod
    def _celda_csv(valor) -> str:
        """Serializa una celda CSV con escape de comillas y comas."""
        if isinstance(valor, (list, dict)):
            valor = "; ".join(str(x) for x in valor) if isinstance(valor, list) \
                else json.dumps(valor, ensure_ascii=False)
        texto = str(valor if valor is not None else "")
        if any(ch in texto for ch in (",", '"', "\n")):
            texto = '"' + texto.replace('"', '""') + '"'
        return texto

    @staticmethod
    def _export_markdown(datos: Dict) -> str:
        """Export consolidado del workspace en Markdown listo para el informe."""
        lineas = [
            "# REDHAVOC — Export del workspace",
            "",
            f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        secciones = (
            ("hosts", "Hosts", ("ip", "hostname", "servicios", "visto")),
            ("creds", "Credenciales válidas", ("ip", "usuario", "secreto", "servicio", "hora")),
            ("vulns", "Hallazgos", ("severidad", "host", "titulo", "detalle", "modulo")),
            ("notas", "Notas del operador", ("hora", "texto")),
        )
        for clave, titulo, _ in secciones:
            filas = datos.get(clave, [])
            lineas.append(f"## {titulo} ({len(filas)})")
            lineas.append("")
            if not filas:
                lineas.append("_(vacío)_")
                lineas.append("")
                continue
            columnas = list(filas[0].keys())
            lineas.append("| " + " | ".join(columnas) + " |")
            lineas.append("|" + "---|" * len(columnas))
            for fila in filas:
                celdas = []
                for c in columnas:
                    v = fila.get(c, "")
                    v = "; ".join(str(x) for x in v) if isinstance(v, list) else str(v)
                    celdas.append(v.replace("|", "\\|").replace("\n", " "))
                lineas.append("| " + " | ".join(celdas) + " |")
            lineas.append("")
        lineas += ["---", "*Export generado por REDHAVOC — solo para pruebas autorizadas.*"]
        return "\n".join(lineas) + "\n"

    def cmd_audit(self, args) -> None:
        """audit [N] — últimos N eventos de la traza de auditoría ética."""
        try:
            n = max(1, min(200, int(args[0]))) if args else 20
        except ValueError:
            console.print("[aviso][!][/aviso] Uso: [bold]audit[/bold] | [bold]audit <N>[/bold]")
            return
        ruta = self.ethics.fichero_auditoria
        if not ruta.exists():
            console.print("[dim]Sin eventos de auditoría todavía "
                          "(cada run y bloqueo ético se registra aquí).[/dim]")
            return
        try:
            lineas = ruta.read_text(encoding="utf-8").splitlines()
        except OSError as err:
            console.print(f"[error][✗][/error] No se pudo leer la auditoría: {escape(str(err))}")
            return
        visibles = lineas[-n:]
        tabla = Table(title=f"Traza de auditoría [dim]({len(lineas)} eventos, "
                            f"mostrando {len(visibles)})[/dim]", border_style="dim")
        tabla.add_column("Evento", style="bold cyan", no_wrap=False,
                         overflow="fold", max_width=34)
        tabla.add_column("Detalle", style="white", overflow="fold")
        for linea in visibles:
            cuerpo = linea.strip("[]")
            marca, _, resto = cuerpo.partition("] ")
            if " | " in resto:
                evento, detalle = resto.split(" | ", 1)
            else:
                evento, detalle = resto, ""
            tabla.add_row(f"[dim]{marca}[/dim] {escape(evento)}", escape(detalle))
        console.print(tabla)
        console.print(f"[dim]Log completo: {ruta}[/dim]")

    def cmd_consejos(self, args=None) -> None:
        """Plan de batalla leído de la base de datos del workspace."""
        mostrar_plan(console, self.workspace_db)
        console.print("[dim]Cada módulo muestra sus 'siguientes pasos' al terminar; "
                      "este plan resume la operación completa.[/dim]")

    def cmd_resource(self, args) -> None:
        """Ejecuta un guion de comandos .rc (uno por línea, # comentarios)."""
        if not args:
            console.print("[aviso][!][/aviso] Uso: [bold]resource <fichero.rc>[/bold]")
            return
        ruta = Path(" ".join(args).strip()).expanduser()
        if not ruta.is_file():
            console.print(f"[error][✗][/error] El guion no existe: {escape(str(ruta))}")
            return
        console.print(f"[info][*][/info] Ejecutando guion: [dim]{escape(str(ruta))}[/dim]")
        for numero, linea in enumerate(
                ruta.read_text(encoding="utf-8").splitlines(), 1):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            console.print(f"[dim]rc:{numero:03d}[/dim] [white]{escape(linea)}[/white]")
            if self._procesar(linea):
                break   # el guion pidió salir (exit)
        console.print("[ok][✓][/ok] Guion completado.")

    def cmd_plugin(self, args) -> None:
        """plugin install <pack> | plugin list | plugin del <categoria>.

        Los packs remotos exigen AUTHORIZED + confirmación explícita:
        instalar código de terceros es una acción de máxima confianza.
        """
        sub = args[0].lower() if args else ""
        if sub == "list":
            plugins = self.plugins.listar()
            if not plugins:
                console.print("[dim]Sin plugins instalados. Instala uno con: "
                              "[white]plugin install <ruta-o-URL.git>[/white][/dim]")
                return
            tabla = Table(title="Plugins instalados", border_style="dim")
            tabla.add_column("Categoría", style="modulo", no_wrap=True)
            tabla.add_column("Ficheros", style="white", overflow="fold")
            for p in plugins:
                tabla.add_row(p["categoria"], ", ".join(p["ficheros"]))
            console.print(tabla)
            return
        if sub == "install":
            if len(args) < 2:
                console.print("[aviso][!][/aviso] Uso: [bold]plugin install "
                              "<ruta-local | https://…/repo.git>[/bold]")
                return
            fuente = " ".join(args[1:]).strip()
            remoto = fuente.startswith(("http://", "https://", "git@"))
            if remoto:
                autorizado = (self.globales.get_bool("AUTHORIZED")
                              or self.ethics.autorizado())
                if not autorizado:
                    console.print(Panel(
                        "[bold yellow]Instalación de código de terceros[/bold yellow]\n"
                        "Los plugins remotos requieren AUTHORIZED: ejecutar código "
                        "externo con privilegios del framework es una acción de "
                        "máxima confianza.",
                        border_style="yellow", title="ética"))
                    self.ethics.auditar("BLOQUEO_PLUGIN_SIN_AUTH", fuente[:120])
                    return
                console.print(
                    "[aviso][!][/aviso] REVISIÓN PREVIA: descarga y audita el código "
                    "antes de confirmar. Se clonará y se copiarán los .py a "
                    "[dim]plugins/[/dim] (ver "
                    "[dim]docs/DEVELOPMENT.md[/dim]).")
                try:
                    respuesta = console.input(
                        "[bold]Escribe[/bold] [accent]REVISADO[/accent] [bold]para "
                        "confirmar la instalación:[/bold] ")
                except (EOFError, KeyboardInterrupt):
                    respuesta = ""
                if respuesta.strip().upper() != "REVISADO":
                    console.print("[dim]Instalación cancelada (respuesta distinta "
                                  "de REVISADO).[/dim]")
                    self.ethics.auditar("PLUGIN_CANCELADO", fuente[:120])
                    return
            try:
                registrados, avisos = self.plugins.instalar(
                    fuente, self.module_manager._registro,
                    autorizado=not remoto)
            except PluginError as err:
                console.print(f"[error][✗][/error] {escape(str(err))}")
                return
            if registrados:
                console.print(f"[ok][✓][/ok] {len(registrados)} módulo(s) "
                              "disponible(s) al instante:")
                for nombre in registrados:
                    console.print(f"    [modulo]{escape(nombre)}[/modulo]")
                console.print("[dim]Búscalos con search o cárgalos con "
                              "use <categoria/modulo>[/dim]")
            for aviso in avisos:
                console.print(f"[aviso][!][/aviso] {escape(aviso)}")
            return
        if sub in ("del", "uninstall"):
            if len(args) < 2:
                console.print("[aviso][!][/aviso] Uso: [bold]plugin del <categoria>[/bold] "
                              "(lista las categorías con plugin list)")
                return
            try:
                ficheros = self.plugins.desinstalar(args[1])
                console.print(f"[ok][✓][/ok] Plugin eliminado: {len(ficheros)} "
                              "fichero(s). Reinicia la consola para que los "
                              "módulos desaparezcan del arsenal.")
            except PluginError as err:
                console.print(f"[error][✗][/error] {escape(str(err))}")
            return
        console.print("[aviso][!][/aviso] Uso: plugin | "
                      "[bold]plugin install <pack>[/bold] | "
                      "[bold]plugin list[/bold] | [bold]plugin del <categoria>[/bold]")

    def cmd_engagement(self, args) -> None:
        """engagement | engagement load <fichero> | engagement clear"""
        sub = args[0].lower() if args else ""
        if sub == "clear":
            self.engagement.limpiar()
            console.print("[ok][✓][/ok] Engagement descartado.")
            return
        if sub == "load":
            fichero = " ".join(args[1:]).strip()
            if not fichero:
                console.print("[aviso][!][/aviso] Uso: [bold]engagement load <fichero.json>[/bold]")
                return
            ok, avisos = self.engagement.cargar(fichero)
            if ok:
                console.print(f"[ok][✓][/ok] Engagement cargado: "
                              f"[bold]{escape(str(self.engagement.datos['nombre']))}[/bold]")
                for aviso in avisos:
                    console.print(f"[aviso][!][/aviso] {escape(aviso)}")
            else:
                for aviso in avisos:
                    console.print(f"[error][✗][/error] {escape(aviso)}")
            return
        if sub:
            console.print("[aviso][!][/aviso] Uso: engagement | engagement load <fichero> "
                          "| engagement clear")
            return
        if not self.engagement.activo():
            console.print("[dim]Sin engagement cargado. Usa [white]engagement load "
                          "<fichero.json>[/white] (plantilla: templates/engagement_ejemplo.json).[/dim]")
            return
        datos = self.engagement.datos
        vigente, motivo = self.engagement.vigente()
        estado = "[ok]VIGENTE[/ok]" if vigente else f"[error]VENCIDO[/error] ({escape(motivo)})"
        alcance = "\n".join(f"  · {escape(str(x))}" for x in datos.get("alcance", [])) \
            or "  · (vacío: sin control de scope)"
        excluidos = "\n".join(f"  · {escape(str(x))}" for x in datos.get("excluidos", [])) \
            or "  · —"
        cuerpo = (
            f"[bold white]Nombre[/bold white]  : {escape(str(datos.get('nombre', '')))}\n"
            f"[bold white]Cliente[/bold white]: {escape(str(datos.get('cliente', '') or '—'))}\n"
            f"[bold white]Estado[/bold white] : {estado}\n"
            f"[bold white]Kill-date[/bold white]: {escape(str(datos.get('kill_date', '') or '—'))}\n\n"
            f"[bold white]Alcance autorizado[/bold white]\n{alcance}\n\n"
            f"[bold white]Excluidos[/bold white]\n{excluidos}\n\n"
            f"[bold white]permitir_fuera_alcance[/bold white]: "
            f"{'sí (auditado)' if datos.get('permitir_fuera_alcance') else 'no'}"
        )
        console.print(Panel(cuerpo, title="engagement", border_style="dim"))
        console.print("[dim]El framework bloquea las ejecuciones fuera del alcance "
                      "y con kill-date vencido.[/dim]")

    def cmd_attack(self, args) -> None:
        """Mapa módulos ↔ técnicas MITRE ATT&CK (o filtra una técnica)."""
        tecnica = (args[0].upper() if args else "").strip()
        mapa: Dict[str, List[str]] = {}
        for cls in self.module_manager.listar():
            for t in getattr(cls, "ATTCK", ()) or ():
                mapa.setdefault(t, []).append(cls.NAME)
        if not mapa:
            console.print("[dim]Ningún módulo declara técnicas ATT&CK.[/dim]")
            return
        titulo = "Módulos por técnica MITRE ATT&CK" + (f" — {escape(tecnica)}" if tecnica else "")
        tabla = Table(title=titulo, border_style="dim")
        tabla.add_column("Técnica", style="bold cyan", no_wrap=True)
        tabla.add_column("Módulos", style="white", overflow="fold")
        filas = 0
        for t in sorted(mapa):
            if tecnica and not t.startswith(tecnica):
                continue
            tabla.add_row(t, ", ".join(mapa[t]))
            filas += 1
        if filas:
            console.print(tabla)
        else:
            console.print(f"[aviso][!][/aviso] Ningún módulo mapea a {escape(tecnica)}.")

    def cmd_report(self, args=None) -> None:
        """Muestra la ruta del último informe."""
        if self.reporter.ultimo_reporte and self.reporter.ultimo_reporte.exists():
            base = str(self.reporter.ultimo_reporte)[:-5]
            console.print(f"[info][*][/info] Último informe: [dim]{self.reporter.ultimo_reporte}[/dim]")
            console.print(f"[info][*][/info] Markdown   : [dim]{base}.md[/dim]")
            console.print(f"[info][*][/info] HTML       : [dim]{base}.html[/dim]")
            ruta_pdf = Path(base + ".pdf")
            if ruta_pdf.exists():
                console.print(f"[info][*][/info] PDF        : [dim]{ruta_pdf}[/dim]")
        else:
            console.print("[dim]Todavía no se ha generado ningún informe (ejecuta un módulo).[/dim]")

    def cmd_banner(self, args=None) -> None:
        """Reimprime el banner."""
        from core.banner import Banner
        Banner.mostrar(console, self.module_manager.total_modulos())

    def cmd_history(self, args=None) -> None:
        """Muestra el historial de comandos (persiste entre sesiones)."""
        if args and args[0] == "-c":
            self.historial = []
            try:
                self._ruta_historial.write_text("", encoding="utf-8")
            except OSError:
                pass
            console.print("[ok][✓][/ok] Historial vaciado (esta sesión y el fichero persistido).")
            return
        if not self.historial:
            console.print("[dim]Historial vacío.[/dim]")
            return
        for i, linea in enumerate(self.historial[-30:], start=max(1, len(self.historial) - 29)):
            console.print(f"  [dim]{i:3}[/dim]  {escape(linea)}")
        console.print("[dim]El historial persiste entre sesiones · límpialo con: history -c[/dim]")

    def cmd_clear(self, args=None) -> None:
        """Limpia la pantalla."""
        console.clear()

    def cmd_exit(self, args=None) -> None:
        """Sale del REPL cerrando sesiones, guardando el historial y
        mostrando un resumen de la operación (SystemExit capturado más abajo)."""
        self._guardar_historial()
        for sid, ses in list(self.sesiones.items()):
            try:
                ses["conn"].close()
            except OSError:
                pass
            self.sesiones.pop(sid, None)
        self._resumen_salida()
        raise SystemExit(0)

    def _resumen_salida(self) -> None:
        """Resumen profesional de la operación al cerrar la consola."""
        duracion = max(0, int(time.time() - self._inicio_sesion))
        horas, resto = divmod(duracion, 3600)
        minutos, segundos = divmod(resto, 60)
        dur_txt = f"{horas}h {minutos:02d}m" if horas else f"{minutos}m {segundos:02d}s"
        filas = (
            ("Workspace activo", self.nombre_workspace),
            ("Duración de la sesión", dur_txt),
            ("Hosts en workspace", str(self.workspace_db.total_hosts())),
            ("Credenciales", str(self.workspace_db.total_creds())),
            ("Hallazgos", str(self.workspace_db.total_vulns())),
            ("Notas del operador", str(self.workspace_db.total_notas())),
            ("Informes generados", str(self._informes_sesion)),
            ("Jobs lanzados", f"{len(self.jobs)} "
             f"({sum(1 for j in self.jobs.values() if j['estado'] == 'ejecutando')} activos)"),
        )
        cuerpo = "\n".join(
            f"[bold white]{etiqueta.ljust(21)}[/bold white]: [valor]{valor}[/valor]"
            for etiqueta, valor in filas
        )
        console.print(Panel(cuerpo, title="resumen de la operación",
                            border_style="dim", expand=False, padding=(0, 1)))
        console.print("[dim]Recuerda: entrega el informe al cliente y borra los datos "
                      "sensibles del workspace cuando cierre el engagement.[/dim]")

    # ==================================================================
    # Presentación auxiliar
    # ==================================================================
    def _tabla_opciones(self, opciones: OptionStore, titulo: str) -> None:
        """Tabla homogénea de opciones."""
        tabla = Table(title=titulo, border_style="dim")
        tabla.add_column("Opción", style="opcion", no_wrap=True)
        tabla.add_column("Valor", style="valor")
        tabla.add_column("Req", justify="center", style="requerido")
        tabla.add_column("Descripción", style="white", overflow="fold")
        for o in opciones:
            valor = o.valor if o.valor else "[dim](vacío)[/dim]"
            req = "[magenta]sí[/magenta]" if o.requerido else "no"
            tabla.add_row(o.nombre, valor, req, o.descripcion)
        console.print(tabla)

    def _mostrar_arbol_modulos(self) -> None:
        """Árbol de módulos agrupado por categoría (estilo explorador)."""
        arbol = self.module_manager.categorias()
        icono_cat = {
            "recon": "🔎", "web": "🌐", "phishing": "🎣",
            "payloads": "💣", "post": "🧩", "opsec": "🥷",
            "osint": "🕵️", "iot": "📡", "brute": "🔨", "dos": "🌊",
            "ad": "🏛️", "cloud": "☁️", "generico": "🧪",
        }
        guia = Tree(
            f"[bold white]REDHAVOC[/bold white] [bold white]arsenal[/bold white] "
            f"[dim]({self.module_manager.total_modulos()} módulos · "
            f"{len(arbol)} categorías)[/dim]"
        )
        for categoria in sorted(arbol):
            nombres = arbol[categoria]
            rama = guia.add(
                f"{icono_cat.get(categoria, '•')} [bold white]{categoria}[/bold white] "
                f"[dim]({len(nombres)})[/dim]"
            )
            for nombre in nombres:
                rama.add(f"[modulo]{nombre}[/modulo]")
        console.print(guia)
        console.print("[dim]Carga uno con: use <categoria/modulo> · detalle con: info <modulo>[/dim]")

    # ==================================================================
    # Autocompletado TAB
    # ==================================================================
    def _activar_readline(self) -> None:
        """Configura el autocompletado con la librería readline (POSIX)."""
        if readline is None:
            return
        import atexit
        readline.set_completer(self._completer)
        readline.set_completer_delims(" \t\n")
        if "libedit" in (getattr(readline, "__doc__", "") or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        atexit.register(lambda: readline.set_completer(None))

    def _candidatos_para(self, texto: str, buffer: str) -> List[str]:
        """Candidatos de autocompletado para el texto y buffer dados.

        Separado del completer para poder testearlo sin TTY.
        """
        partes = buffer.split()
        if len(partes) <= 1 and not buffer.endswith(" "):
            return [c for c in self.COMANDOS if c.startswith(texto)]
        cmd = partes[0] if partes else ""
        if cmd in ("use", "info"):
            return [n for n in self.module_manager.nombres() if n.startswith(texto)]
        if cmd in ("set", "unset"):
            if self.modulo_actual is not None:
                return [o.nombre for o in self.modulo_actual.opciones
                        if o.nombre.lower().startswith(texto.lower())]
            return [o.nombre for o in self.globales
                    if o.nombre.lower().startswith(texto.lower())]
        if cmd in ("setg", "unsetg"):
            return [o.nombre for o in self.globales
                    if o.nombre.lower().startswith(texto.lower())]
        if cmd == "show":
            return [s for s in ("modules", "options") if s.startswith(texto)]
        if cmd == "engagement":
            return [s for s in ("load", "clear") if s.startswith(texto)]
        if cmd == "workspace":
            return [s for s in ("new", "use", "del") if s.startswith(texto)]
        if cmd == "sessions":
            return [s for s in ("-i", "-x", "-k") if s.startswith(texto)]
        if cmd == "jobs":
            return [s for s in ("-k", "-c") if s.startswith(texto)]
        if cmd in ("hosts", "creds", "vulns"):
            return [s for s in ("-c",) if s.startswith(texto)]
        if cmd == "notes":
            return [s for s in ("add", "-c") if s.startswith(texto)]
        if cmd == "history":
            return [s for s in ("-c",) if s.startswith(texto)]
        if cmd == "resource":
            return [s for s in ("templates/",) if s.startswith(texto)]
        if cmd == "plugin":
            return [s for s in ("install", "list", "del") if s.startswith(texto)]
        return []

    def _completer(self, texto: str, estado: int):
        """Autocompletado de comandos, módulos y opciones."""
        if readline is None:
            return None
        buffer = readline.get_line_buffer()
        candidatos = self._candidatos_para(texto, buffer)
        try:
            return candidatos[estado]
        except IndexError:
            return None
