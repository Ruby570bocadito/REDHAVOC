# -*- coding: utf-8 -*-
"""
Módulo web/open_redirect
========================
Detecta redirecciones abiertas (open redirect) de forma INERT:

    1. Añade a la URL un parámetro candidato (PARAMS: url, next, redirect,
       return, goto, target...) con un valor sonda //redhavoc.lab/x
    2. NO sigue la redirección (allow_redirects=False): examina solo la
       cabecera Location y los meta refresh.
    3. Es redirigida si Location apunta a la sonda sin validación.

Una redirección abierta sirve para phishing convincente
(https://banco.com/login?url=//phisher.x) y para saltar filtros de URL.

Riesgo: BAJO (peticiones GET, sin seguir la redirección).
ATT&CK: T1566.002 (Spearphishing Link, contexto) · CWE-601.
"""

import re
from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_RE_META_REFRESH = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*[\"']refresh[\"'][^>]+"
    r"url\s*=\s*([^\"'>]+)", re.IGNORECASE)

_DEFECTO_PARAMS = "url,next,redirect,return,returnTo,goto,target,dest,continue,u,r"


def es_redireccion_abierta(location: str, cuerpo: str, sonda: str) -> Dict:
    """Clasifica una respuesta con sonda de redirect (función pura).

    La sonda es //redhavoc.lab/x: una URL relativa-protocolo de dominio
    del auditor. Es VULNERABLE si Location o meta-refresh apuntan a la
    sonda tal cual (sin dominio propio, sin encode raro).
    """
    sonda = sonda.lower().replace("https://", "").replace("http://", "")
    destino = (location or "").strip()
    fuente = ""
    if destino and sonda in destino.lower():
        fuente = "Location"
    else:
        m = _RE_META_REFRESH.search(cuerpo or "")
        if m and sonda in m.group(1).lower():
            fuente = "meta-refresh"
    if not fuente:
        return {"vulnerable": False, "fuente": "", "destino": destino or "—"}
    # Diferenciamos reflexión simple (param devuelto en un enlace) vs redirección
    return {"vulnerable": True, "fuente": fuente, "destino": destino}


class OpenRedirectScan(BaseModulo):
    """Detecta open redirects con sonda inerte (no sigue la redirección)."""

    NAME = "web/open_redirect"
    CATEGORIA = "web"
    DESCRIPCION = ("Redirecciones abiertas con sonda inerte: Location y "
                   "meta-refresh por parámetro (url/next/redirect...) sin "
                   "seguir la redirección")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP Unvalidated Redirects · CWE-601"
    ATTCK = ("T1566.002",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo (puede incluir ?param=)")
        self.opciones.declarar(
            "PARAMS", _DEFECTO_PARAMS, False,
            "Parámetros candidatos separados por coma")
        self.opciones.declarar(
            "SONDA", "//redhavoc.lab/rx", False,
            "Valor sonda (dominio relativo-protocolo del auditor)")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        params = [p.strip() for p in self.opt("PARAMS", _DEFECTO_PARAMS).split(",")
                  if p.strip()]
        sonda = self.opt("SONDA", "//redhavoc.lab/rx").strip()
        timeout = self.opt_int("TIMEOUT", 6) or 6
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        pruebas: List[Dict] = []
        confirmados: List[Dict] = []

        for param in params[:12]:
            sep = "&" if "?" in url else "?"
            url_prueba = f"{url}{sep}{param}={sonda}"
            try:
                resp = requests.get(url_prueba, timeout=timeout, verify=False,
                                    headers=ua, allow_redirects=False)
            except requests.RequestException as err:
                raise ModuloError(f"El objetivo no responde ({param}): {err}")

            resultado = es_redireccion_abierta(
                resp.headers.get("Location", ""), resp.text[:100_000], sonda)
            fila = {
                "parametro": param,
                "codigo": resp.status_code,
                "vulnerable": "sí" if resultado["vulnerable"] else "no",
                "fuente": resultado["fuente"] or "—",
                "destino": resultado["destino"][:90],
            }
            pruebas.append(fila)
            if resultado["vulnerable"]:
                confirmados.append({**fila,
                                    "url": url_prueba.replace(sonda, sonda)})

        nivel = "vulnerable" if confirmados else "ok"
        if confirmados and self.workspace is not None:
            host = url.split("//")[-1].split("/")[0]
            self.workspace.add_vuln(
                host, "Redirección abierta", "medio",
                f"Parámetros: {', '.join(c['parametro'] for c in confirmados)}",
                self.NAME)

        return {
            "resumen": (f"{url}: {len(confirmados)}/{len(pruebas)} parámetros "
                        f"redirigen a la sonda"),
            "url": url,
            "sonda": sonda,
            "nivel": nivel,
            "confirmados": confirmados or "(ninguno)",
            "pruebas": pruebas,
            "nota": "Sonda inerte: la redirección NO se sigue. Impacto: phishing "
                    "con dominio legítimo y bypass de filtros de URL.",
        }
