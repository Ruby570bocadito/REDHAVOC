# -*- coding: utf-8 -*-
"""
Módulo web/sqli_scanner
=======================
Detector EDUCATIVO de SQLi basada en error para parámetros GET.

    • Inyecta cargas inocuas (' " ' OR '1'='1 -- ) en cada parámetro.
    • Compara la respuesta con firmas de errores SQL conocidos
      (MySQL, PostgreSQL, SQLite, MSSQL, Oracle, ODBC).
    • NO explota nada: solo marca parámetros candidatos para revisión manual.

Riesgo: ALTO (envía payloads al objetivo → exige AUTHORIZED).
"""

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CARGAS = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "1' -- ", "1\" -- "]

FIRMAS = {
    "MySQL":      ["you have an error in your sql syntax", "warning: mysql", "mysqli_query"],
    "PostgreSQL": ["pg_query", "unterminated quoted string", "postgresql"],
    "SQLite":     ["sqlite_query", "sqlite3.OperationalError", "unrecognized token"],
    "MSSQL":      ["microsoft sql server", "odbc sql server driver", "sqlsyntaxerrorexception"],
    "Oracle":     ["ora-00933", "ora-01756", "oracle error"],
    "Genérico":   ["sql syntax", "syntax error at or near", "unclosed quotation mark"],
}


class SqliScanner(BaseModulo):
    """Marca parámetros GET con indicios de SQLi basada en error (educativo)."""

    NAME = "web/sqli_scanner"
    CATEGORIA = "web"
    DESCRIPCION = ("Detector educativo de SQLi por error en parámetros GET: "
                   "inyecta cargas inocuas y busca firmas de error SQL. "
                   "No explota ni extrae datos.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RED_HAWK (error based SQLi) · sqlmap (firmas)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL CON parámetros (p. ej. https://x.com/item.php?id=1&cat=2)")

    def _probar_parametro(self, sesion, base_url: str, nombre_param: str, valor: str,
                          carga: str, timeout: int):
        """Devuelve el cuerpo de la respuesta sustituyendo el valor del parámetro."""
        params = dict(parse_qsl(base_url.split("?", 1)[1], keep_blank_values=True))
        params[nombre_param] = valor + carga
        url_prueba = urlunparse(urlparse(base_url)._replace(query=urlencode(params)))
        resp = sesion.get(url_prueba, timeout=timeout, verify=False, allow_redirects=True)
        return resp.text[:200_000].lower()

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if "?" not in url or "=" not in url:
            raise ModuloError("La URL debe incluir parámetros GET, p. ej. https://x.com/item.php?id=1")
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        # Respuesta de referencia (sin carga) para descartar falsos positivos previos
        try:
            resp_base = sesion.get(url, timeout=timeout, verify=False).text[:200_000].lower()
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        candidatos = []
        for nombre_param, valor in parse_qsl(url.split("?", 1)[1], keep_blank_values=True):
            hallazgos_param = []
            for carga in CARGAS:
                try:
                    cuerpo = self._probar_parametro(sesion, url, nombre_param, valor, carga, timeout)
                except requests.RequestException:
                    continue
                for motor, firmas in FIRMAS.items():
                    for firma in firmas:
                        if firma in cuerpo and firma not in resp_base:
                            hallazgos_param.append({"carga": carga, "motor": motor, "firma": firma})
            if hallazgos_param:
                candidatos.append({"parametro": nombre_param, "evidencias": hallazgos_param})

        resumen = (f"{url.split('?')[0]}: {len(candidatos)} parámetro(s) con indicios de SQLi"
                   if candidatos else f"{url.split('?')[0]}: sin indicios de SQLi por error")
        return {
            "resumen": resumen,
            "url": url,
            "aviso": "Resultados indicativos únicamente. Confirmar manualmente; no es explotación.",
            "candidatos": candidatos,
        }
