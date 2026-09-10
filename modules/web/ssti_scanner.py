# -*- coding: utf-8 -*-
"""
Módulo web/ssti_scanner
=======================
Detecta inyección de plantillas del servidor (SSTI, T1221/CWE-1336)
enviando sondas MATEMÁTICAS INOCUAS (7*7=49) a un parámetro de la URL.
Solo motores comunes y sin payloads destructivos:

    {{7*7}}      → Jinja2, Twig
    ${7*7}       → FreeMarker, Velocity, Thymeleaf
    #{7*7}       → Ruby ERB, Thymeleaf
    <%= 7*7 %>   → ERB, EJS
    {7*7}        → Smarty
    **{{7*7}}**  → doble render (mutación Jinja2)

Si la respuesta contiene 49 donde enviamos la sonda, hay render de
plantillas. NUNCA se usan payloads de ejecución de comandos.

Riesgo: MEDIO (sondas pasivas; un SSTI confirmado es hallazgo grave).
ATT&CK: T1221 (Template Injection).
"""

import requests
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sonda → motor probable. La sonda se envía con un prefijo único
# ("rvh{{7*7}}"); si el servidor RENDERIZA, la respuesta contiene "rvh49";
# si solo la repite, contiene el eco literal. Nunca se evalúa nada peligroso.
SONDAS = (
    ("{{7*7}}", "Jinja2/Twig"),
    ("${7*7}", "FreeMarker/Thymeleaf"),
    ("#{7*7}", "ERB/Thymeleaf (expresión)"),
    ("<%= 7*7 %>", "ERB/EJS"),
    ("{7*7}", "Smarty"),
)

MARCA = "rvh"
RESULTADO = "rvh49"     # 7*7 renderizado tras la marca


class SstiScanner(BaseModulo):
    """Prueba sondas SSTI inocuas en los parámetros de una URL."""

    NAME = "web/ssti_scanner"
    CATEGORIA = "web"
    DESCRIPCION = ("Detecta SSTI con sondas matemáticas inocuas (7*7=49) sobre "
                   "los parámetros de la URL: Jinja2, Twig, FreeMarker, ERB, "
                   "Smarty. Sin payloads destructivos.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "portswigger/ssti-planner · tplmap (idea) · MITRE T1221"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True,
                               "URL con parámetros (p. ej. /hola?nombre=x)")
        self.opciones.declarar("POST", "false", False,
                               "Enviar sondas en el cuerpo POST en vez de la query")

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        usar_post = self.opt_bool("POST", False)
        timeout = self.opt_int("TIMEOUT", 5) or 5

        partes = urlsplit(url)
        params = parse_qsl(partes.query, keep_blank_values=True)
        if not params and not usar_post:
            raise ModuloError("La URL no tiene parámetros para inyectar "
                              "(usa /ruta?param=valor)")

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        try:
            base = sesion.get(url, timeout=timeout, verify=False)
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")
        if base.status_code >= 500:
            raise ModuloError(f"El objetivo devuelve HTTP {base.status_code} en la base")

        hallazgos, pruebas = [], []
        for nombre, _ in params:
            for sonda, motor in SONDAS:
                resultado = self._probar(sesion, url, nombre, sonda,
                                         motor, usar_post, timeout)
                pruebas.append(resultado)
                if resultado["reflejado"]:
                    hallazgos.append(resultado)
                    break   # primer motor confirmado para este parámetro

        # SSTI confirmado → workspace.vulns (hallazgo de nivel alto)
        for h in hallazgos:
            self.ctx.workspace.add_vuln(
                partes.netloc.split(":")[0],
                f"SSTI confirmado en parámetro {h['parametro']} ({h['motor']})",
                "alto",
                "El servidor renderiza plantillas con input del usuario; "
                "según el motor puede llegar a RCE. NO explotar en producción.",
                self.NAME)

        resumen = (f"{url}: SSTI CONFIRMADO en {len(hallazgos)} parámetro(s)"
                   if hallazgos else
                   f"{url}: sin render de plantillas evidente "
                   f"({len(pruebas)} pruebas)")
        return {
            "resumen": resumen,
            "url": url,
            "confirmados": hallazgos,
            "pruebas": pruebas,
            "impacto": ("SSTI permite ejecución de código del lado del servidor "
                        "según el motor (Jinja2 → RCE con sandbox escape). "
                        "REMITIR AL EQUIPO DE DESARROLLO, no explotar.")
            if hallazgos else "",
        }

    # ------------------------------------------------------------------
    def _probar(self, sesion, url: str, nombre: str, sonda: str,
                motor: str, usar_post: bool, timeout: int) -> dict:
        """Inyecta la sonda con marca única y analiza el eco de la respuesta."""
        valor = f"{MARCA}{sonda}"
        if usar_post:
            resp = sesion.post(url, data={nombre: valor}, timeout=timeout, verify=False)
            donde = "POST"
        else:
            partes = urlsplit(url)
            params = [(n, valor if n == nombre else v)
                      for n, v in parse_qsl(partes.query, keep_blank_values=True)]
            resp = sesion.get(urlunsplit(partes._replace(query=urlencode(params))),
                              timeout=timeout, verify=False)
            donde = "query"

        cuerpo = resp.text
        reflejado = RESULTADO in cuerpo                # rvh49 → render real
        eco_literal = f"{MARCA}{sonda}" in cuerpo      # repite la plantilla tal cual
        return {
            "parametro": nombre,
            "sonda": sonda,
            "motor": motor,
            "metodo": donde,
            "http": resp.status_code,
            "reflejado": reflejado,
            "eco_literal": eco_literal,
            "nota": ("La sonda solo evalúa 7*7: inocua. El render confirma SSTI."
                     if reflejado else ""),
        }
