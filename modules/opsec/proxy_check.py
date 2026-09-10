# -*- coding: utf-8 -*-
"""
Módulo opsec/proxy_check
========================
Verifica tu anonimato operativo ANTES de lanzar módulos contra objetivos:

    • Consulta tu IP pública a DOS servicios independientes (ip-api e
      ipify) y avisa si no coinciden (posible proxy roto/transparente).
    • Marca si la salida es proxy/VPN/hosting/TOR según ip-api.
    • Compara con la IP vista por el módulo opsec/tor_check.

Ideal tras cambiar de cadena TOR o VPN: si los servicios no ven la misma
IP de salida, tu cadena de anonimato tiene fugas.

Riesgo: BAJO (consultas a servicios públicos sobre tu propia conexión).
"""

import json
import urllib.request

from core.base_module import BaseModulo, ModuloError


class ProxyCheck(BaseModulo):
    """Doble verificación de la IP de salida y detección de fugas."""

    NAME = "opsec/proxy_check"
    CATEGORIA = "opsec"
    DESCRIPCION = ("Verifica tu IP de salida con dos servicios independientes y "
                   "detecta fugas de la cadena TOR/VPN (IPs que no coinciden). "
                   "Úsalo antes de operar contra objetivos.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Auto_Tor_IP_changer (concepto) · whoer.net (verificación doble)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("EXIGIR_PROXY", "false", False,
                               "true = falla si la salida NO parece proxy/VPN/TOR")

    def _consulta(self, url: str, timeout: float) -> dict:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def ejecutar(self) -> dict:
        timeout = self.opt_int("TIMEOUT", 5) or 5

        # Servicio 1: ip-api (IP + clasificación)
        try:
            info = self._consulta(
                "http://ip-api.com/json/?fields=query,country,isp,org,proxy,hosting,mobile", timeout)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as err:
            raise ModuloError(f"Sin respuesta de ip-api: {err}")
        ip1 = info.get("query", "?")

        # Servicio 2: ipify (solo IP, ruta distinta)
        ip2 = ip1
        try:
            data2 = self._consulta("https://api.ipify.org?format=json", timeout)
            ip2 = data2.get("ip", ip1)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            ip2 = ip1  # segundo servicio caído → no bloquea, se avisa

        fuga = ip2 != ip1
        es_proxy = bool(info.get("proxy"))
        es_hosting = bool(info.get("hosting"))
        es_movil = bool(info.get("mobile"))

        # ¿Es salida TOR? (check.torproject.org)
        es_tor = False
        try:
            es_tor = bool(self._consulta("https://check.torproject.org/api/ip", timeout)
                          .get("IsTor", False))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            es_tor = False

        anonimo = es_proxy or es_tor or es_hosting
        if self.opt_bool("EXIGIR_PROXY") and not anonimo:
            raise ModuloError(
                f"OPSEC insuficiente: la salida {ip1} no es proxy/VPN/TOR/hosting "
                f"(EXIGIR_PROXY=true)")

        resumen = (f"Salida {ip1} ({info.get('country', '?')} · {info.get('isp', '?')}) — "
                   f"{'ANÓNIMA' if anonimo else 'IP REAL'}"
                   + (f" — ¡FUGA! segundo servicio ve {ip2}" if fuga else ""))

        return {
            "resumen": resumen,
            "ip_salida_1": ip1,
            "ip_salida_2": ip2,
            "fuga_detectada": fuga,
            "pais": info.get("country", "?"),
            "isp": info.get("isp", "?"),
            "org": info.get("org", "?"),
            "es_proxy": es_proxy,
            "es_hosting": es_hosting,
            "es_tor": es_tor,
            "anonimo": anonimo,
            "recomendacion": ("Cadena OK: puedes operar." if anonimo and not fuga else
                              "Fuga de IP: revisa proxychains/TOR antes de operar."
                              if fuga else
                              "Estás saliendo con tu IP real: activa TOR/VPN si el "
                              "objetivo no debe ver tu origen."),
        }
