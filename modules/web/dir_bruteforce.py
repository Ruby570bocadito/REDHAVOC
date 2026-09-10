# -*- coding: utf-8 -*-
"""
Módulo web/dir_bruteforce
=========================
Descubrimiento de rutas/directorios web por fuerza bruta con wordlist.
Filtra por códigos de estado y longitud de respuesta (anti 404-blanking).

Riesgo: MEDIO (genera múltiples peticiones al objetivo).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from core.base_module import BaseModulo, ModuloError
from core.colors import console

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORDLIST = Path(__file__).resolve().parent.parent.parent / "templates" / "wordlists" / "dirs.txt"

CODIGOS_INTERES = {200, 201, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}


class DirBruteforce(BaseModulo):
    """Fuerza bruta de rutas web con wordlist integrada o personalizada."""

    NAME = "web/dir_bruteforce"
    CATEGORIA = "web"
    DESCRIPCION = ("Descubre rutas ocultas en un servidor web probando una "
                   "wordlist (dirbuster simplificado) con filtro de estado.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "dirsearch · gobuster"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL base (p. ej. https://example.com)")
        self.opciones.declarar("WORDLIST", "", False, "Wordlist personalizada; por defecto la integrada")
        self.opciones.declarar("EXTENSIONES", "", False, "Extensiones extra separadas por coma (p. ej. php,html)")

    def _cargar_wordlist(self) -> list:
        ruta = self.opt("WORDLIST")
        fichero = Path(ruta) if ruta else WORDLIST
        if not fichero.exists():
            raise ModuloError(f"Wordlist no encontrada: {fichero}")
        return [l.strip().lstrip("/") for l in fichero.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]

    def _probar(self, sesion: requests.Session, url: str, ruta: str, timeout: int):
        """Prueba una ruta y devuelve un hallazgo si responde de forma interesante."""
        try:
            resp = sesion.get(url + "/" + ruta, timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code in CODIGOS_INTERES:
                return {"ruta": "/" + ruta, "estado": resp.status_code,
                        "longitud": len(resp.content), "ubicacion": resp.headers.get("Location", "")}
        except requests.RequestException:
            return None
        return None

    def ejecutar(self) -> dict:
        base = self.opt("URL").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        timeout = self.opt_int("TIMEOUT", 5) or 5
        hilos = min(self.opt_int("THREADS", 10) or 10, 50)

        rutas = self._cargar_wordlist()
        extensiones = [e.strip().lstrip(".") for e in self.opt("EXTENSIONES").split(",") if e.strip()]
        if extensiones:
            rutas = rutas + [f"{r}.{e}" for r in rutas for e in extensiones]

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        # Referencia anti-404 falso: longitud de una ruta inexistente aleatoria
        try:
            resp_ref = sesion.get(base + "/redhavoc-noexiste-0xdeadbeef", timeout=timeout, verify=False)
            longitud_404 = len(resp_ref.content)
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        hallazgos = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = [pool.submit(self._probar, sesion, base, r, timeout) for r in rutas]
            for i, futuro in enumerate(as_completed(futuros), 1):
                resultado = futuro.result()
                if resultado and resultado["longitud"] != longitud_404:
                    hallazgos.append(resultado)
                    console.print(f"  [ok][+][/ok] /{resultado['ruta'].lstrip('/')} "
                                  f"[bold cyan]({resultado['estado']})[/bold cyan] "
                                  f"[dim]{resultado['longitud']} bytes[/dim]")

        hallazgos.sort(key=lambda x: x["ruta"])
        resumen = f"{base}: {len(hallazgos)} rutas encontradas de {len(rutas)} probadas"
        return {
            "resumen": resumen,
            "url_base": base,
            "probadas": len(rutas),
            "hallazgos": hallazgos,
        }
