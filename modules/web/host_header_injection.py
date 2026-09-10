# -*- coding: utf-8 -*-
"""
Módulo web/host_header_injection
================================
Detecta inyección/caché envenenable vía cabecera Host (inerte):

    1. Pide la URL con Host manipulado a un dominio sonda
       (SONDA, por defecto redhavoc-probe.example) y con la cabecera
       X-Forwarded-Host igual a la sonda.
    2. Analiza si la respuesta REFLEJA la sonda en:
       • Location / cabeceras de redirección (poisoning de caché)
       • enlaces absolutos del HTML (generación de URLs con el Host)
       • cookies de dominio (cookies emitidas para el host sonda)
    3. Clasifica el contexto y sugiere el impacto real
       (password reset poisoning, envenenamiento de caché web).

La sonda es un dominio INEXISTENTE controlado por el auditor: no hay
exfiltración ni contactos a terceros.

Riesgo: BAJO (dos peticiones GET normales).
ATT&CK: T1557 (Adversary-in-the-Middle, contexto) · CWE-444.
"""

import re
from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_RE_ABSOLUTAS = re.compile(
    r"(?:href|src|action)\s*=\s*[\"']https?://([^\"'/]+)", re.IGNORECASE)
_RE_COOKIE_DOM = re.compile(r"domain\s*=\s*([^;]+)", re.IGNORECASE)


def reflejo_sonda(cuerpo: str, cabeceras: Dict[str, str], sonda: str) -> Dict:
    """Analiza dónde se refleja la sonda (función pura)."""
    sonda = sonda.lower()
    ctx: List[str] = []

    location = cabeceras.get("Location", "") or cabeceras.get("location", "")
    if location and sonda in location.lower():
        ctx.append("redireccion")
    if sonda in (cuerpo or "").lower():
        if _RE_ABSOLUTAS.search(cuerpo or "") and \
                any(sonda in m.lower() for m in _RE_ABSOLUTAS.findall(cuerpo or "")):
            ctx.append("enlaces_absolutos")
        else:
            ctx.append("cuerpo")
    for v in cabeceras.get("Set-Cookie", "") if isinstance(cabeceras.get("Set-Cookie"), str) \
            else _junta(cabeceras.get("Set-Cookie", [])):
        if _RE_COOKIE_DOM.search(v or "") and sonda in _RE_COOKIE_DOM.search(v).group(1):
            ctx.append("cookie_de_dominio")
    return {"contextos": ctx, "reflejada": bool(ctx)}


def _junta(valor) -> List[str]:
    """Normaliza Set-Cookie (str o lista) a lista de strings."""
    if isinstance(valor, list):
        return [str(x) for x in valor]
    return [str(valor)] if valor else []


class HostHeaderInjection(BaseModulo):
    """Detecta reflexión de la cabecera Host / X-Forwarded-Host (inerte)."""

    NAME = "web/host_header_injection"
    CATEGORIA = "web"
    DESCRIPCION = ("Inyección de cabecera Host: reflexión de la sonda en "
                   "Location, enlaces absolutos y cookies (inerte) — "
                   "password reset poisoning y cache poisoning")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP Host Header Injection · CWE-444"
    ATTCK = ("T1557",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo")
        self.opciones.declarar(
            "SONDA", "redhavoc-probe.example", False,
            "Dominio sonda (inexistente) para detectar la reflexión")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        sonda = self.opt("SONDA", "redhavoc-probe.example").strip()
        timeout = self.opt_int("TIMEOUT", 6) or 6
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}
        host_objetivo = url.split("//")[-1].split("/")[0]

        hallazgos: List[str] = []
        pruebas: List[Dict] = []

        # Prueba 1: Host manipulado (sin TLS SNI roto: usamos cabecera HTTP)
        try:
            r1 = requests.get(url, timeout=timeout, verify=False,
                              headers={**ua, "Host": sonda}, allow_redirects=False)
            analisis1 = reflejo_sonda(r1.text[:200_000], dict(r1.headers), sonda)
            pruebas.append({"prueba": "Host: <sonda>", "codigo": r1.status_code,
                            "reflejada": analisis1["reflejada"],
                            "contextos": ", ".join(analisis1["contextos"]) or "—"})
            if analisis1["reflejada"]:
                hallazgos.append(
                    f"El servidor refleja el Host manipulado en "
                    f"{', '.join(analisis1['contextos'])}: si hay formularios de "
                    "restablecimiento de contraseña, el enlace enviado usará el "
                    "dominio del atacante (password reset poisoning)")
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        # Prueba 2: X-Forwarded-Host (el Host original se conserva)
        try:
            r2 = requests.get(url, timeout=timeout, verify=False,
                              headers={**ua, "X-Forwarded-Host": sonda},
                              allow_redirects=False)
            analisis2 = reflejo_sonda(r2.text[:200_000], dict(r2.headers), sonda)
            pruebas.append({"prueba": "X-Forwarded-Host: <sonda>",
                            "codigo": r2.status_code,
                            "reflejada": analisis2["reflejada"],
                            "contextos": ", ".join(analisis2["contextos"]) or "—"})
            if analisis2["reflejada"]:
                hallazgos.append(
                    "El proxy/app confía en X-Forwarded-Host: envenenamiento de "
                    "caché web posible si hay CDN/proxy delante "
                    "(we cache what the first user saw)")
        except requests.RequestException:
            pruebas.append({"prueba": "X-Forwarded-Host: <sonda>",
                            "codigo": 0, "reflejada": False, "contextos": "sin respuesta"})

        nivel = "vulnerable" if hallazgos else "protegido"
        if hallazgos and self.workspace is not None:
            self.workspace.add_vuln(
                host_objetivo, "Reflexión de cabecera Host", "medio",
                " | ".join(hallazgos[:2]), self.NAME)

        return {
            "resumen": f"{host_objetivo}: {nivel} "
                       f"({len(hallazgos)} prueba(s) con reflexión)",
            "url": url,
            "sonda": sonda,
            "nivel": nivel,
            "pruebas": pruebas,
            "hallazgos": hallazgos,
            "nota": "Sonda inerte (dominio inexistente): sin exfiltración. "
                    "Confirma el impacto generando un reset real SOLO en lab.",
        }
