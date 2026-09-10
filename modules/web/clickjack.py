# -*- coding: utf-8 -*-
"""
Módulo web/clickjack
====================
Audita la protección anti-clickjacking (UI redressing) de una URL:

    • Cabecera X-Frame-Options: DENY | SAMEORIGIN | ALLOW-FROM uri
      (ALLOW-FROM está obsoleto: los navegadores modernos lo ignoran)
    • CSP frame-ancestors 'none' | 'self' | lista (la forma moderna)
    • Detección de iframes embebidos de terceros en la respuesta

Un endpoint sensible sin ninguna de las dos protecciones puede incrustarse
en una página señuelo y capturar clics del usuario (T1185, OWASP A05).

Riesgo: BAJO (una GET normal).
ATT&CK: T1185 (Browser Session Hijacking, contexto) · CWE-1021.
"""

import re
from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patrones CSP frame-ancestors: directiva seguida de fuentes hasta ';'
_RE_FRAME_ANCESTORS = re.compile(
    r"frame-ancestors\s+([^;]+)", re.IGNORECASE)
_RE_IFRAME_SRC = re.compile(
    r"<iframe[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


def evaluar_proteccion(xfo: str, csp: str) -> Dict:
    """Evalúa XFO + CSP y devuelve la ficha (función pura).

    Devuelve {nivel: 'protegido'|'parcial'|'vulnerable', motivos: [...]}
    """
    xfo = (xfo or "").strip()
    csp = (csp or "").strip()
    motivos: List[str] = []
    ancestros = _RE_FRAME_ANCESTORS.search(csp)
    fuentes_ancestros = ancestros.group(1).strip() if ancestros else ""

    xfo_ok = xfo.upper() in ("DENY", "SAMEORIGIN")
    xfo_deprecado = xfo.upper().startswith("ALLOW-FROM")
    csp_ok = bool(fuentes_ancestros) and (
        "'none'" in fuentes_ancestros.lower()
        or "'self'" in fuentes_ancestros.lower()
        or "http" in fuentes_ancestros.lower()      # lista explícita de orígenes
        or "https" in fuentes_ancestros.lower())

    if xfo_ok or csp_ok:
        nivel = "protegido"
        if xfo_ok:
            motivos.append(f"X-Frame-Options: {xfo}")
        if csp_ok:
            motivos.append(f"CSP frame-ancestors: {fuentes_ancestros}")
        if xfo_deprecado:
            motivos.append("XFO ALLOW-FROM está obsoleto: añade frame-ancestors")
        elif xfo_ok and not csp_ok:
            motivos.append("XFO cubre el caso; frame-ancestors lo refuerza")
    elif xfo_deprecado:
        nivel = "vulnerable"
        motivos.append("Solo XFO ALLOW-FROM: los navegadores modernos lo IGNORAN")
        motivos.append("Añade CSP frame-ancestors 'self'")
    elif not xfo and not fuentes_ancestros:
        nivel = "vulnerable"
        motivos.append("Sin X-Frame-Options ni CSP frame-ancestors")
    else:
        nivel = "parcial"
        if fuentes_ancestros:
            motivos.append(f"frame-ancestors sin fuentes claras: {fuentes_ancestros}")

    return {"nivel": nivel, "motivos": motivos,
            "xfo": xfo or "(ausente)",
            "frame_ancestors": fuentes_ancestros or "(ausente)"}


class ClickjackAudit(BaseModulo):
    """Audita la protección anti-clickjacking de la URL objetivo."""

    NAME = "web/clickjack"
    CATEGORIA = "web"
    DESCRIPCION = ("Audita la defensa anti-clickjacking: X-Frame-Options y "
                   "CSP frame-ancestors + iframes de terceros embebidos")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP Clickjacking Defense Cheat Sheet · CWE-1021"
    ATTCK = ("T1185",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo")
        self.opciones.declarar("BUSCAR_IFRAMES", "true", False,
                               "Detectar iframes embebidos en el HTML")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        timeout = self.opt_int("TIMEOUT", 5) or 5
        try:
            resp = requests.get(
                url, timeout=timeout, verify=False, allow_redirects=True,
                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        ficha = evaluar_proteccion(xfo, csp)

        iframes: List[str] = []
        if self.opt_bool("BUSCAR_IFRAMES", True) and "html" in \
                resp.headers.get("Content-Type", "").lower():
            for src in _RE_IFRAME_SRC.findall(resp.text[:500_000]):
                iframes.append(src[:120])

        host = url.split("//")[-1].split("/")[0]
        if ficha["nivel"] == "vulnerable" and self.workspace is not None:
            self.workspace.add_vuln(
                host, "Endpoint sin protección anti-clickjacking", "medio",
                "; ".join(ficha["motivos"]), self.NAME)

        return {
            "resumen": f"{url}: {ficha['nivel']} ({len(ficha['motivos'])} detalle(s))",
            "url": url,
            "nivel": ficha["nivel"],
            "motivos": ficha["motivos"],
            "x_frame_options": ficha["xfo"],
            "frame_ancestors": ficha["frame_ancestors"],
            "iframes_embebidos": iframes,
        }
