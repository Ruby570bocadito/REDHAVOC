# -*- coding: utf-8 -*-
"""
Módulo web/crlf_scan
====================
Sondea inyección CRLF (HTTP Response Splitting) en la URL objetivo:

    • Inserta %0d%0a + cabecera canaria en el PATH y en cada parámetro
    • Comprueba si la respuesta del servidor refleja la cabecera inyectada
    • También detecta la variante "crlf → redirect" (Location controlado)

Un CRLF en la respuesta permite dividir la respuesta HTTP, inyectar
cabeceras (Set-Cookie de sesión falsa, CORS laxo) o forzar redirects.
Hoy en día pocos frameworks lo permiten, pero proxies/ALBs mal ajustados
aún caen.

Riesgo: MEDIO (petición activa con payload marcador, sin explotación).
ATT&CK: T1190 (Exploit Public-Facing Application) · CWE-93.
"""

from typing import Dict, List
from urllib.parse import urlsplit

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CANARIO = "xrhvcmarcador"
# Payloads: %0d%0a crudo y variantes con dobles codificaciones
PAYLOADS = (
    ("%0d%0a" + CANARIO + ": inyectada", "clásico"),
    ("%25%30d%25%30a" + CANARIO + ": inyectada", "doble-codificado"),
    ("%0d%0a%0d%0a<script>//</script>", "reflejado-en-cuerpo"),
)


def _partes(url: str) -> Dict[str, object]:
    """Separa base (sin query) y query en pares clave=valor (función pura)."""
    trozos = urlsplit(url)
    base = f"{trozos.scheme}://{trozos.netloc}{trozos.path}" if trozos.scheme \
        else url.split("?")[0]
    pares: List[str] = [p for p in (trozos.query or url.split("?")[1] if "?" in url else "").split("&") if p]
    return {"base": base, "pares": pares}


def respuesta_refleja_crlf(codigo: int, cabeceras: Dict[str, str], cuerpo: str,
                           variante: str) -> str:
    """Clasifica si la respuesta confirma la inyección (función pura).

    Devuelve: "INYECTADA" | "REFLEJADA" | ""
    """
    claves = {k.lower() for k in cabeceras or {}}
    if CANARIO in claves:
        return "INYECTADA"
    cuerpo_bajo = (cuerpo or "")[:200_000].lower()
    if variante == "reflejado-en-cuerpo" and CANARIO in cuerpo_bajo:
        return "INYECTADA"
    # Variante clásica en un body con las cabeceras volcadas (depuración)
    if variante == "clásico" and f"{CANARIO}: inyectada" in cuerpo_bajo \
            and "<html" not in cuerpo_bajo[:200].lower():
        return "INYECTADA"
    if CANARIO in (cuerpo_bajo or ""):
        return "REFLEJADA"
    return ""


class CrlfScan(BaseModulo):
    """Sondea CRLF injection en path y parámetros de la URL objetivo."""

    NAME = "web/crlf_scan"
    CATEGORIA = "web"
    DESCRIPCION = ("Inyección CRLF / Response Splitting en path y parámetros "
                   "(3 variantes de codificación, cabecera canaria)")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "CWE-93 (CRLF Injection) · OWASP"
    ATTCK = ("T1190",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "URL", "", True, "URL a sondear, con query si se quiere "
            "(p. ej. https://sitio.com/buscar?q=1)")
        self.opciones.declarar(
            "TIMEOUT", "8", False, "Timeout por petición en segundos")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url:
            raise ModuloError("Indica el objetivo: set URL https://sitio.com/ruta?q=1")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        timeout = self.opt_int("TIMEOUT", 8) or 8
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        partes = _partes(url)
        base: str = partes["base"]                       # type: ignore[assignment]
        pares: List[str] = partes["pares"]               # type: ignore[assignment]

        pruebas: List[str] = [base]                      # path puro
        for par in pares:
            clave = par.split("=")[0]
            pruebas.append(f"{base}?{clave}=MARCA")

        confirmadas: List[Dict] = []
        reflejadas: List[str] = []
        total = 0
        for plantilla in pruebas:
            for payload, variante in PAYLOADS:
                objetivo = plantilla.replace("MARCA", payload) \
                    if "MARCA" in plantilla else f"{plantilla}?{payload}"
                total += 1
                try:
                    resp = requests.get(objetivo, timeout=timeout, verify=False,
                                        headers=ua, allow_redirects=False)
                except requests.RequestException:
                    continue
                veredicto = respuesta_refleja_crlf(
                    resp.status_code, dict(resp.headers), resp.text, variante)
                if veredicto == "INYECTADA":
                    confirmadas.append({"url": objetivo, "variante": variante})
                elif veredicto == "REFLEJADA":
                    reflejadas.append(objetivo)

        host = self._objetivo_host(url)
        if confirmadas and self.workspace is not None:
            self.workspace.add_vuln(
                host, "CRLF injection confirmada", "alto",
                f"{len(confirmadas)} punto(s) permiten dividir la respuesta HTTP",
                self.NAME)

        resultado = {
            "pruebas": total,
            "inyectadas": confirmadas,
            "reflejadas_sin_confirmar": len(reflejadas),
        }
        resumen = (f"CRLF: {total} pruebas → {len(confirmadas)} inyección(es) "
                   f"confirmada(s), {len(reflejadas)} reflejo(s) sin confirmar")
        if not confirmadas and not reflejadas:
            resumen += " — el objetivo normaliza correctamente"
        return {
            "resumen": resumen,
            "resultados": [resultado],
            "nota": "Un CRLF confirmado permite cachear respuestas envenenadas, "
                    "fijar cookies de sesión y saltar filtros: reporta y "
                    "normaliza %0d/%0a en el proxy o framework.",
        }
