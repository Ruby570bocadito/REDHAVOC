# -*- coding: utf-8 -*-
"""
core.workspace_db
=================
Base de datos ligera del workspace (estilo `hosts`/`services`/`creds` de
Metasploit), persistida en workspace/db.json (o workspace/ws_<nombre>.json
con los workspaces múltiples).

Los módulos la rellenan automáticamente cuando pueden (p. ej. port_scanner
registra hosts y servicios abiertos; los módulos de brute guardan las
credenciales válidas) y el operador la consulta con los comandos:

    hosts      Listar hosts y sus servicios descubiertos
    creds      Listar credenciales válidas registradas
    vulns      Listar hallazgos/vulnerabilidades confirmados
    hosts -c   Vaciar la base de datos del workspace
"""

import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional


NOMBRE_DEFECTO = "principal"


def ruta_de_workspace(carpeta_workspace: Path, nombre: str) -> Path:
    """Ruta del fichero JSON de un workspace por nombre (helper puro).

    El workspace por defecto es 'principal' (db.json, retrocompatible);
    los demás viven como ws_<nombre>.json junto a él.
    """
    nombre = (nombre or NOMBRE_DEFECTO).strip() or NOMBRE_DEFECTO
    if nombre == NOMBRE_DEFECTO:
        return Path(carpeta_workspace) / "db.json"
    return Path(carpeta_workspace) / f"ws_{nombre}.json"


class WorkspaceDB:
    """Almacén JSON de hosts, servicios y credenciales de la operación."""

    def __init__(self, carpeta_workspace: Path, nombre: str = NOMBRE_DEFECTO) -> None:
        self.carpeta = Path(carpeta_workspace)
        self.carpeta.mkdir(parents=True, exist_ok=True)
        self.nombre = (nombre or NOMBRE_DEFECTO).strip() or NOMBRE_DEFECTO
        self.ruta = ruta_de_workspace(self.carpeta, self.nombre)
        self._lock = threading.Lock()
        self._datos: Dict = {"hosts": {}, "creds": [], "vulns": [], "notas": []}
        self._cargar()

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def _cargar(self) -> None:
        if self.ruta.exists():
            try:
                datos = json.loads(self.ruta.read_text(encoding="utf-8"))
                if isinstance(datos, dict) and "hosts" in datos:
                    self._datos = {"hosts": datos.get("hosts", {}),
                                   "creds": datos.get("creds", []),
                                   "vulns": datos.get("vulns", []),
                                   "notas": datos.get("notas", [])}
            except (json.JSONDecodeError, OSError):
                pass  # DB corrupta → se arranca de cero

    def _guardar(self) -> None:
        try:
            self.ruta.write_text(
                json.dumps(self._datos, indent=2, ensure_ascii=False),
                encoding="utf-8")
        except OSError:
            pass  # la consola nunca debe morir por un fallo de disco

    # ------------------------------------------------------------------
    # Hosts y servicios
    # ------------------------------------------------------------------
    def add_host(self, ip: str, hostname: str = "", notas: str = "") -> None:
        """Registra (o actualiza) un host descubierto."""
        self._add_host(ip, hostname, notas, guardar=True)

    def _add_host(self, ip: str, hostname: str, notas: str, guardar: bool) -> Dict:
        ip = (ip or "").strip()
        if not ip:
            return {}
        host = self._datos["hosts"].setdefault(ip, {
            "hostname": "", "servicios": [], "visto": "", "notas": ""})
        if hostname:
            host["hostname"] = hostname
        if notas:
            host["notas"] = notas
        host["visto"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if guardar:
            self._guardar()
        return host

    def add_service(self, ip: str, puerto, servicio: str = "?") -> None:
        """Añade un puerto/servicio a un host (sin duplicados)."""
        with self._lock:
            host = self._add_host(ip, "", "", guardar=False)
            if not host:
                return
            entrada = f"{puerto}/{servicio}"
            if entrada not in host.get("servicios", []):
                host.setdefault("servicios", []).append(entrada)
            self._guardar()

    def hosts(self) -> List[Dict]:
        """Lista de {ip, ...datos} ordenada por IP."""
        with self._lock:
            return [{"ip": ip, **datos} for ip, datos in sorted(self._datos["hosts"].items())]

    def total_hosts(self) -> int:
        with self._lock:
            return len(self._datos["hosts"])

    # ------------------------------------------------------------------
    # Credenciales
    # ------------------------------------------------------------------
    def add_cred(self, ip: str, usuario: str, secreto: str = "", servicio: str = "?") -> None:
        """Registra una credencial válida descubierta."""
        usuario = (usuario or "").strip()
        if not usuario:
            return
        with self._lock:
            entrada = {"ip": ip, "usuario": usuario, "secreto": secreto,
                       "servicio": servicio, "hora": time.strftime("%Y-%m-%d %H:%M:%S")}
            if entrada not in self._datos["creds"]:
                self._datos["creds"].append(entrada)
            self._guardar()

    def creds(self) -> List[Dict]:
        with self._lock:
            return list(self._datos["creds"])

    def total_creds(self) -> int:
        with self._lock:
            return len(self._datos["creds"])

    # ------------------------------------------------------------------
    # Hallazgos (vulnerabilidades confirmadas)
    # ------------------------------------------------------------------
    SEVERIDADES = ("info", "bajo", "medio", "alto", "critico")

    def add_vuln(self, host: str, titulo: str, severidad: str = "medio",
                 detalle: str = "", modulo: str = "") -> None:
        """Registra un hallazgo confirmado (sin duplicados por host+titulo)."""
        titulo = (titulo or "").strip()
        if not titulo:
            return
        severidad = severidad if severidad in self.SEVERIDADES else "medio"
        with self._lock:
            entrada = {"host": (host or "").strip(), "titulo": titulo,
                       "severidad": severidad, "detalle": detalle,
                       "modulo": modulo, "hora": time.strftime("%Y-%m-%d %H:%M:%S")}
            ya = any(v["host"] == entrada["host"] and v["titulo"] == titulo
                     for v in self._datos["vulns"])
            if not ya:
                self._datos["vulns"].append(entrada)
            self._guardar()

    def vulns(self) -> List[Dict]:
        """Hallazgos ordenados por gravedad (critico primero)."""
        with self._lock:
            orden = {s: i for i, s in enumerate(reversed(self.SEVERIDADES))}
            return sorted(self._datos["vulns"],
                          key=lambda v: (orden.get(v.get("severidad"), 1),
                                         v.get("hora", "")))

    def total_vulns(self) -> int:
        with self._lock:
            return len(self._datos["vulns"])

    # ------------------------------------------------------------------
    # Notas del operador
    # ------------------------------------------------------------------
    def add_nota(self, texto: str, autor: str = "operador") -> Dict:
        """Registra una nota libre del operador con marca temporal."""
        texto = (texto or "").strip()
        if not texto:
            return {}
        with self._lock:
            entrada = {"texto": texto, "autor": autor,
                       "hora": time.strftime("%Y-%m-%d %H:%M:%S")}
            self._datos.setdefault("notas", []).append(entrada)
            self._guardar()
            return entrada

    def notas(self) -> List[Dict]:
        """Notas del operador en orden de inserción."""
        with self._lock:
            return list(self._datos.get("notas", []))

    def total_notas(self) -> int:
        with self._lock:
            return len(self._datos.get("notas", []))

    def limpiar_notas(self) -> None:
        """Vacía SOLO las notas del operador."""
        with self._lock:
            self._datos["notas"] = []
            self._guardar()

    # ------------------------------------------------------------------
    # Mantenimiento
    # ------------------------------------------------------------------
    def limpiar(self) -> None:
        """Vacía la base de datos del workspace (hosts + creds + vulns + notas)."""
        with self._lock:
            self._datos = {"hosts": {}, "creds": [], "vulns": [], "notas": []}
            self._guardar()

    def limpiar_hosts(self) -> None:
        """Vacía SOLO la tabla de hosts (creds y vulns se conservan)."""
        with self._lock:
            self._datos["hosts"] = {}
            self._guardar()

    def limpiar_creds(self) -> None:
        """Vacía SOLO las credenciales registradas."""
        with self._lock:
            self._datos["creds"] = []
            self._guardar()

    def limpiar_vulns(self) -> None:
        """Vacía SOLO los hallazgos confirmados."""
        with self._lock:
            self._datos["vulns"] = []
            self._guardar()

    def resumen(self) -> str:
        """Cadena corta 'N hosts · M credenciales' para el banner/estado."""
        return (f"{self.total_hosts()} hosts · {self.total_creds()} creds · "
                f"{self.total_vulns()} hallazgos · {self.total_notas()} notas")

    @staticmethod
    def listar(carpeta_workspace: Path) -> List["WorkspaceDB"]:
        """Todos los workspaces existentes (principal primero, luego A-Z)."""
        carpeta = Path(carpeta_workspace)
        nombres = [NOMBRE_DEFECTO]
        if carpeta.is_dir():
            for fichero in sorted(carpeta.glob("ws_*.json")):
                nombres.append(fichero.stem[3:])
        return [WorkspaceDB(carpeta, n) for n in dict.fromkeys(nombres)]

    # Compatibilidad: algunos módulos esperaban que workspace fuera una ruta
    def __fspath__(self) -> str:
        return str(self.carpeta)
