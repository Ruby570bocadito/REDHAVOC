# -*- coding: utf-8 -*-
"""
Módulo web/xss_reflected
========================
Detector EDUCATIVO de XSS reflejado por marcador INERTE (no explota):

    1. Inyecta un marcador único y sin actividad (p. ej. <rhv7x3kz>) en cada
       parámetro GET de la URL objetivo.
    2. Comprueba si la respuesta lo refleja y en qué contexto:
         • texto HTML      → reflexión simple (informativa)
         • atributo        → reflexión en value="…" (medio)
         • <script>/string → reflexión dentro de JS (alto)
         • sin filtrar < > → el navegador interpretaría etiquetas (alto)
    3. Nunca inyecta javascript:, onerror=, onload= ni payloads activos:
       la clasificación es suficiente para el informe y no ejecuta nada.

Riesgo: MEDIO (peticiones GET con cadenas inofensivas).
ATT&CK: T1059.007 (JavaScript/JScript — solo detección de superficie).
"""

import re
import secrets
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_MARCADOR = "rhv{}zz"
_ETIQUETA = re.compile(_MARCADOR.format(r"\w+"))

# contextos donde puede caer el marcador reflejado
_RE_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_RE_ATRIBUTO = re.compile(r"<[^>]*=[\"'][^\"']*" + _MARCADOR.format(r"\w+") + r"[^\"']*[\"']", re.IGNORECASE)
_RE_TAG_CRUDO = re.compile(r"<" + _MARCADOR.format(r"\w+") + r"[/]?>", re.IGNORECASE)
_RE_COMENTARIO = re.compile(r"<!--.*?-->", re.DOTALL)


def generar_marcador() -> Tuple[str, str]:
    """Genera (marcador_plano, marcador_etiqueta) únicos (función pura)."""
    token = secrets.token_hex(3)
    return _MARCADOR.format(token), f"<{_MARCADOR.format(token)}>"


def clasificar_contexto(html: str, marcador: str) -> List[str]:
    """Clasifica dónde cae el marcador reflejado (función pura).

    Devuelve contextos únicos: 'html', 'atributo', 'script', 'comentario'.
    """
    contextos: List[str] = []
    cuerpo_sin_script = _RE_SCRIPT.sub("", html)
    if marcador in cuerpo_sin_script:
        contextos.append("html")
    if _RE_ATRIBUTO.search(html):
        contextos.append("atributo")
    for cuerpo_js in _RE_SCRIPT.findall(html):
        if marcador in cuerpo_js:
            contextos.append("script")
            break
    for comentario in _RE_COMENTARIO.findall(html):
        if marcador in comentario:
            contextos.append("comentario")
            break
    if _RE_TAG_CRUDO.search(html):
        # la etiqueta llegó SIN codificar: el navegador la interpretaría
        if "html" not in contextos:
            contextos.append("html")
        contextos.append("sin_filtrar")
    return contextos


def riesgos_de(contextos: List[str]) -> str:
    """Nivel de riesgo según los contextos reflejados (función pura)."""
    if "sin_filtrar" in contextos or "script" in contextos:
        return "alto"
    if "atributo" in contextos:
        return "medio"
    if contextos:
        return "bajo"
    return "ok"


def construir_url(url: str, param: str, valor: str) -> str:
    """Sustituye (o añade) un parámetro GET con el valor dado (función pura)."""
    partes = urlparse(url)
    pares = parse_qsl(partes.query, keep_blank_values=True)
    if any(k == param for k, _ in pares):
        pares = [(k, valor if k == param else v) for k, v in pares]
    else:
        pares.append((param, valor))
    return urlunparse(partes._replace(query=urlencode(pares)))


class XssReflected(BaseModulo):
    """Detecta reflexión inerte de parámetros GET y clasifica el contexto."""

    NAME = "web/xss_reflected"
    CATEGORIA = "web"
    DESCRIPCION = ("Detector EDUCATIVO de XSS reflejado con marcador inerte: "
                   "reflexión y contexto (HTML/atributo/script), sin payloads")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP WSTG-INPV-02 · dalfox (detección, no explotación)"
    ATTCK = ("T1059.007",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True,
                               "URL con parámetros GET (…?q=x&page=1)")
        self.opciones.declarar("PARAMS", "", False,
                               "Solo estos parámetros (coma). Vacío = todos")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if "?" not in url:
            raise ModuloError("La URL no tiene parámetros GET: el sondeo de "
                              "reflexión necesita ?param=valor")
        solo = [p.strip() for p in self.opt("PARAMS").split(",") if p.strip()]
        timeout = self.opt_int("TIMEOUT", 5) or 5

        pares = parse_qsl(urlparse(url).query, keep_blank_values=True)
        if solo:
            pares = [(k, v) for k, v in pares if k in solo]
        if not pares:
            raise ModuloError("No hay parámetros que sondear.")

        try:
            base = requests.get(url, timeout=timeout, verify=False,
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        hallazgos: List[Dict] = []
        for param, _ in pares:
            marcador, etiqueta = generar_marcador()
            try:
                resp = requests.get(construir_url(url, param, etiqueta),
                                    timeout=timeout, verify=False,
                                    headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
            except requests.RequestException:
                continue
            if marcador not in resp.text:
                continue
            contextos = clasificar_contexto(resp.text, marcador)
            hallazgos.append({
                "parametro": param,
                "contextos": contextos,
                "riesgo": riesgos_de(contextos),
                "marcador": etiqueta,
            })

        host = url.split("//")[-1].split("/")[0]
        if self.workspace is not None:
            for h in hallazgos:
                if h["riesgo"] == "alto":
                    self.workspace.add_vuln(
                        host, f"Reflexión sin filtrar en ?{h['parametro']} (XSS posible)",
                        "medio", f"contextos: {', '.join(h['contextos'])}", self.NAME)

        nivel_max = ("alto" if any(h["riesgo"] == "alto" for h in hallazgos)
                     else "medio" if any(h["riesgo"] == "medio" for h in hallazgos)
                     else "bajo" if hallazgos else "ok")
        return {
            "resumen": f"{url}: {len(hallazgos)}/{len(pares)} parámetro(s) reflejan "
                       f"el marcador · nivel máximo {nivel_max}",
            "url": url,
            "parametros_sondeados": [k for k, _ in pares],
            "reflejos": hallazgos,
            "nivel_maximo": nivel_max,
            "nota": "Detección por reflexión inerte: valida el contexto manualmente "
                    "antes de reportar XSS explotable.",
        }
