# -*- coding: utf-8 -*-
"""
Módulo web/http_methods
=======================
Audita los métodos HTTP que el servidor acepta:

    • OPTIONS /  → cabecera Allow (métodos declarados)
    • TRACE      → Cross-Site Tracing real (eco del cuerpo): robo de cookies
                   con HttpOnly vía JS en navegadores antiguos
    • Métodos peligrosos declarados: PUT, DELETE, MOVE, COPY, CONNECT,
      PATCH, PROPFIND (WebDAV)

El módulo NO sube ficheros (no prueba PUT escribiendo): verifica lo que el
servidor DECLARA y el eco TRACE, que es una petición inofensiva de lectura.

Riesgo: BAJO-MEDIO (OPTIONS/TRACE son peticiones de lectura).
ATT&CK: T1210 (Exploitation of Remote Services, contexto) · CWE-650.
"""

import re
from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PELIGROSOS = {"PUT", "DELETE", "TRACE", "CONNECT", "MOVE", "COPY", "PROPFIND",
               "PROPPATCH", "MKCOL", "LOCK", "UNLOCK", "PATCH"}

_RE_TRACE_ECO = re.compile(r"REDHAVOC-XST-PROBE", re.IGNORECASE)


def evaluar_allow(allow: str) -> Dict:
    """Clasifica la cabecera Allow/OPTIONS (función pura).

    Devuelve {metodos: [...], peligrosos: [...], nivel: 'ok'|'aviso'|'peligro'}
    """
    metodos = [m.strip().upper() for m in re.split(r"[, ]+", allow or "") if m.strip()]
    peligrosos = [m for m in metodos if m in _PELIGROSOS]
    if "PUT" in peligrosos or "MOVE" in peligrosos or "COPY" in peligrosos:
        nivel = "peligro"
    elif peligrosos:
        nivel = "aviso"
    else:
        nivel = "ok"
    return {"metodos": metodos, "peligrosos": peligrosos, "nivel": nivel}


class HttpMethodsAudit(BaseModulo):
    """Audita métodos HTTP peligrosos (OPTIONS + TRACE)."""

    NAME = "web/http_methods"
    CATEGORIA = "web"
    DESCRIPCION = ("Métodos HTTP aceptados: Allow de OPTIONS, eco TRACE (XST) y "
                   "métodos peligrosos declarados (PUT/DELETE/WebDAV)")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP HTTP Request Testing · CWE-650"
    ATTCK = ("T1210",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo")
        self.opciones.declarar(
            "PROBAR_TRACE", "true", False,
            "Enviar TRACE con marcador inerte para detectar eco (XST)")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        timeout = self.opt_int("TIMEOUT", 6) or 6
        cabeceras = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        hallazgos: List[str] = []

        # 1) OPTIONS sobre la raíz
        allow = ""
        try:
            resp = requests.options(url, timeout=timeout, verify=False,
                                    headers=cabeceras, allow_redirects=True)
            allow = resp.headers.get("Allow", "") or resp.headers.get(
                "Public", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        ficha = evaluar_allow(allow)

        # 2) TRACE con marcador inerte
        trace_eco = False
        if self.opt_bool("PROBAR_TRACE", True):
            try:
                resp_t = requests.request(
                    "TRACE", url, timeout=timeout, verify=False,
                    headers={**cabeceras, "X-REDHAVOC-XST": "REDHAVOC-XST-PROBE"},
                    allow_redirects=False)
                cuerpo = resp_t.text[:20_000]
                trace_eco = (resp_t.status_code == 200
                             and bool(_RE_TRACE_ECO.search(cuerpo)))
            except requests.RequestException:
                trace_eco = False

        # 3) Interpretación
        if trace_eco:
            hallazgos.append("TRACE devuelve el eco de la petición: Cross-Site "
                             "Tracing viable (robo de cookies HttpOnly en "
                             "navegadores antiguos) — desactiva TraceEnable")
            nivel_global = "peligro"
        elif ficha["nivel"] == "peligro":
            hallazgos.append(f"El servidor DECLARA métodos de escritura: "
                             f"{', '.join(ficha['peligrosos'])} — verifica que "
                             "requieren autenticación real antes de aceptarlos")
            nivel_global = "peligro"
        elif ficha["nivel"] == "aviso":
            hallazgos.append(f"Métodos a revisar declarados: "
                             f"{', '.join(ficha['peligrosos'])}")
            nivel_global = "aviso"
        else:
            nivel_global = "ok"
            hallazgos.append("Sin métodos peligrosos declarados en Allow")

        if not allow:
            hallazgos.append("OPTIONS no revela Allow (servidor silencioso): "
                             "prueba peticiones a mano si el cliente lo permite")

        host = url.split("//")[-1].split("/")[0]
        if nivel_global == "peligro" and self.workspace is not None:
            self.workspace.add_vuln(
                host, "Métodos HTTP peligrosos", "medio",
                "; ".join(hallazgos[:2]), self.NAME)

        return {
            "resumen": f"{url}: nivel {nivel_global}"
                       + (" (TRACE con eco)" if trace_eco else ""),
            "url": url,
            "allow": allow or "(no revelado)",
            "metodos": ficha["metodos"],
            "peligrosos": ficha["peligrosos"],
            "trace_eco": trace_eco,
            "nivel": nivel_global,
            "hallazgos": hallazgos,
        }
