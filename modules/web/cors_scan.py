# -*- coding: utf-8 -*-
"""
Módulo web/cors_scan
====================
Escáner de configuraciones CORS inseguras (idea "CORS Misconfiguration
Scanner" de Argus):

    1. Reflejo de Origin arbitrario (https://evil.com) + credenciales.
    2. Origin "null" aceptado.
    3. Prefijos/subdominios confiados (atacksyndicate.com dentro de
       trusted-domain.com, etc.).
    4. Preflight OPTIONS con Access-Control-Request-Method.

Clasificación: VULNERABLE (reflejo con credenciales), DUDOSO, OK.

Riesgo: BAJO-MEDIO (peticiones GET/OPTIONS con cabeceras de prueba).
"""

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CorsScan(BaseModulo):
    """Detecta misconfiguraciones CORS reflejando Origins de prueba."""

    NAME = "web/cors_scan"
    CATEGORIA = "web"
    DESCRIPCION = ("Escanea configuraciones CORS: reflejo de Origin, origin "
                   "null, prefijos de dominio confiado y preflight OPTIONS.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (CORS Misconfiguration Scanner)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo (endpoint que devuelve datos)")
        self.opciones.declarar("ORIGIN_ATACANTE", "https://atacante.evil", False, "Origin de prueba")

    def _cabeceras_cors(self, cabeceras) -> dict:
        return {
            "acao": cabeceras.get("Access-Control-Allow-Origin", ""),
            "acac": cabeceras.get("Access-Control-Allow-Credentials", ""),
            "vary": cabeceras.get("Vary", ""),
            "acah": cabeceras.get("Access-Control-Allow-Headers", ""),
            "acam": cabeceras.get("Access-Control-Allow-Methods", ""),
        }

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        origen_malo = self.opt("ORIGIN_ATACANTE", "https://atacante.evil")
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        # Referencia sin Origin
        try:
            base = sesion.get(url, timeout=timeout, verify=False)
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")
        if base.status_code >= 400:
            raise ModuloError(f"El endpoint devuelve HTTP {base.status_code}")

        pruebas = []

        def evalua(nombre: str, origin: str, extra: dict | None = None):
            cab = {"Origin": origin}
            if extra:
                cab.update(extra)
            resp = sesion.get(url, headers=cab, timeout=timeout, verify=False)
            c = self._cabeceras_cors(resp.headers)
            vulnerable = False
            if c["acao"] == origin and c["acac"].lower() == "true":
                vulnerable = True
            elif c["acao"] == origin and c["acac"] == "":
                vulnerable = False  # refleja pero sin credenciales: riesgo bajo
            pruebas.append({
                "prueba": nombre, "origin_enviado": origin,
                "acao_reflejado": c["acao"], "credentials": c["acac"],
                "vulnerable": vulnerable,
            })
            return c

        # 1) Origin arbitrario
        evalua("Origin arbitrario reflejado", origen_malo)
        # 2) Origin null
        evalua("Origin null", "null")
        # 3) Subdominio del objetivo (política de prefijo)
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        dominio = parsed.netloc.split(":")[0]
        evalua("Prefijo de dominio confiado", f"{dominio}.evil.com")
        # 4) Preflight
        try:
            resp = sesion.options(url, headers={
                "Origin": origen_malo,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            }, timeout=timeout, verify=False)
            c = self._cabeceras_cors(resp.headers)
            pruebas.append({
                "prueba": "Preflight OPTIONS", "origin_enviado": origen_malo,
                "acao_reflejado": c["acao"], "credentials": c["acac"],
                "vulnerable": (c["acao"] == origen_malo and c["acac"].lower() == "true"),
            })
        except requests.RequestException:
            pass

        criticos = [p for p in pruebas if p["vulnerable"]]
        resumen = (f"{url}: CORS VULNERABLE en {len(criticos)} prueba(s)"
                   if criticos else f"{url}: sin misconfiguración CORS evidente")
        return {
            "resumen": resumen,
            "url": url,
            "pruebas": pruebas,
            "impacto": ("Un atacante puede leer respuestas autenticadas de las víctimas "
                        "desde su dominio si ACAO refleja origin + credenciales." if criticos else ""),
        }
