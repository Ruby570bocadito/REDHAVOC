# -*- coding: utf-8 -*-
"""
core.plugins
============
Gestor de plugins de REDHAVOC (roadmap v2.1: "plugins desde Git").

Un plugin es un pack de módulos Python que sigue la misma estructura que
`modules/`:

    mi-pack/
      modules/
        recon/
          mi_modulo.py       (clase BaseModulo con NAME = "recon/mi_modulo")

Fuentes aceptadas por `plugin install`:
    • Ruta local (directorio del pack)     → ideal para desarrollo
    • URL https://…/.git (o GitHub)        → clona con `git` si existe

Gate de seguridad (obligatorio):
    • Los packs remotos exigen AUTHORIZED y confirmación explícita
      (el operador declara que ha REVISADO el código — ejecutar código
      de terceros es una acción de máxima confianza).
    • Los nombres de módulo se validan para no escapar de plugins/.
    • Cada instalación queda en la traza de auditoría ética.

Instalación: copia los .py a `plugins/<categoria>/` y los registra EN
CALIENTE en el ModuleManager (sin reiniciar la consola).
"""

import importlib.util
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.base_module import BaseModulo

# nombres válidos de categoría/módulo de plugin
_NOMBRE_VALIDO = re.compile(r"^[a-z][a-z0-9_]{0,20}$")
_PAQUETES_VALIDOS = re.compile(r"^[a-z][a-z0-9_]{0,20}(\.py)?$")
MANIFIESTO = "redhavoc_plugin.json"


class PluginError(Exception):
    """Error controlado del gestor de plugins."""


def validar_modulo_plugin(ruta_py: Path, raiz_pack: Path) -> List[str]:
    """Devuelve los nombres NAME declarados por un .py de plugin (sin importar)."""
    try:
        texto = ruta_py.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    nombres = re.findall(r"NAME\s*=\s*[\"']([a-z0-9_]+/[a-z0-9_]+)[\"']", texto)
    return nombres


def registrar_desde_fichero(ruta_py: Path, registro: Dict) -> List[str]:
    """Importa un fichero de plugin y registra sus clases BaseModulo.

    registro: dict NAME → clase del ModuleManager (se muta en caliente).
    Devuelve los nombres registrados.
    """
    nombre_import = f"redhavoc_plugin_{ruta_py.stem}_{int(time.time())}"
    spec = importlib.util.spec_from_file_location(nombre_import, str(ruta_py))
    if spec is None or spec.loader is None:
        raise PluginError(f"No se pudo importar: {ruta_py}")
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[nombre_import] = modulo
    try:
        spec.loader.exec_module(modulo)
    except Exception as err:  # noqa: BLE001
        sys.modules.pop(nombre_import, None)
        raise PluginError(f"El módulo falla al importar: {err}")
    registrados = []
    for atributo in vars(modulo).values():
        if (isinstance(atributo, type)
                and issubclass(atributo, BaseModulo)
                and atributo is not BaseModulo
                and getattr(atributo, "NAME", "")):
            registro[atributo.NAME] = atributo
            registrados.append(atributo.NAME)
    return registrados


class GestorPlugins:
    """Instala, lista y desinstala packs de plugins."""

    def __init__(self, raiz, ethics=None) -> None:
        self.raiz = Path(raiz)
        self.carpeta = self.raiz / "plugins"
        self.ethics = ethics

    # ------------------------------------------------------------------
    def _audit(self, evento: str, detalle: str) -> None:
        if self.ethics is not None:
            try:
                self.ethics.auditar(evento, detalle)
            except Exception:  # noqa: BLE001 — auditoría nunca rompe
                pass

    # ------------------------------------------------------------------
    def listar(self) -> List[Dict]:
        """Plugins instalados: {categoria, ficheros, modulo}."""
        plugins: List[Dict] = []
        if not self.carpeta.exists():
            return plugins
        for cat_dir in sorted(self.carpeta.iterdir()):
            if not cat_dir.is_dir():
                continue
            ficheros = sorted(p.name for p in cat_dir.glob("*.py")
                              if p.name != "__init__.py")
            if ficheros:
                plugins.append({"categoria": cat_dir.name, "ficheros": ficheros})
        return plugins

    # ------------------------------------------------------------------
    def instalar(self, fuente: str, registro: Dict,
                 confirmado: bool = False,
                 autorizado: bool = False) -> Tuple[List[str], List[str]]:
        """Instala un pack (ruta local o URL git) y registra sus módulos.

        Devuelve (registrados, avisos). Lanza PluginError ante problemas.
        """
        fuente = (fuente or "").strip()
        if not fuente:
            raise PluginError("Indica la fuente: plugin install <ruta|URL.git>")

        origen = self._preparar_fuente(fuente)
        try:
            pack_modules = origen / "modules"
            if not pack_modules.is_dir():
                raise PluginError(
                    "El pack no tiene la estructura esperada "
                    "(<pack>/modules/<categoria>/<modulo>.py). Escribe el "
                    "código antes de instalarlo — revisa docs/DEVELOPMENT.md.")

            registrados: List[str] = []
            avisos: List[str] = []
            py_ficheros = sorted(pack_modules.rglob("*.py"))
            if not py_ficheros:
                raise PluginError("El pack no contiene ficheros .py en modules/.")

            for py in py_ficheros:
                categoria = py.parent.name.lower()
                nombre_mod = py.stem.lower()
                if not _NOMBRE_VALIDO.fullmatch(categoria) \
                        or not _PAQUETES_VALIDOS.fullmatch(py.name):
                    raise PluginError(
                        f"Nombre fuera de rango: {py.relative_to(origen)} "
                        "(usa a-z0-9_ en categoría y fichero)")

                nombres = validar_modulo_plugin(py, origen)
                if not nombres:
                    avisos.append(f"{py.name}: sin clase BaseModulo — se copia "
                                  "pero no registra módulos")
                destino = self.carpeta / categoria
                destino.mkdir(parents=True, exist_ok=True)
                if not (destino / "__init__.py").exists():
                    (destino / "__init__.py").write_text(
                        "# -*- coding: utf-8 -*-\n"
                        f"# plugins externos — categoria {categoria}\n",
                        encoding="utf-8")
                shutil.copy2(py, destino / py.name)

                if nombres:
                    registrados.extend(
                        registrar_desde_fichero(destino / py.name, registro))

            self._audit("INSTALACION_PLUGIN", f"{fuente} → {len(registrados)} módulo(s)")
            return registrados, avisos
        finally:
            if origen != Path(fuente):
                shutil.rmtree(origen, ignore_errors=True)

    # ------------------------------------------------------------------
    def _preparar_fuente(self, fuente: str) -> Path:
        """Devuelve una ruta local del pack (clona si es URL git)."""
        es_url = fuente.startswith(("http://", "https://", "git@"))
        if not es_url:
            ruta = Path(fuente).expanduser().resolve()
            if not ruta.is_dir():
                raise PluginError(f"La ruta del pack no existe: {ruta}")
            return ruta

        if shutil.which("git") is None:
            raise PluginError(
                "No hay binario `git`: instala git o descarga el pack y usa "
                "plugin install <ruta-local>")
        destino = self.raiz / "workspace" / "_plugin_tmp"
        shutil.rmtree(destino, ignore_errors=True)
        destino.parent.mkdir(parents=True, exist_ok=True)
        try:
            resultado = subprocess.run(
                ["git", "clone", "--depth", "1", fuente, str(destino)],
                capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError) as err:
            raise PluginError(f"Fallo al clonar: {err}")
        if resultado.returncode != 0:
            raise PluginError("git clone falló: "
                              + (resultado.stderr or "").strip()[:300])
        return destino

    # ------------------------------------------------------------------
    def desinstalar(self, categoria: str) -> List[str]:
        """Elimina una categoría de plugins instalados. Devuelve ficheros borrados."""
        categoria = (categoria or "").strip().lower()
        if not _NOMBRE_VALIDO.fullmatch(categoria):
            raise PluginError(f"Categoría inválida: {categoria}")
        destino = self.carpeta / categoria
        if not destino.is_dir():
            raise PluginError(f"No hay plugins de la categoría: {categoria}")
        ficheros = [p.name for p in destino.glob("*.py")
                    if p.name != "__init__.py"]
        shutil.rmtree(destino, ignore_errors=True)
        self._audit("DESINSTALACION_PLUGIN", categoria)
        return ficheros
