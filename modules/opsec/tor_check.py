# -*- coding: utf-8 -*-
"""
Módulo opsec/tor_check
======================
Comprueba tu OPSEC previa a la operación:

    • IP de salida actual (vía ip-api).
    • Si esa IP es una salida de TOR (vía check.torproject.org).
    • Advertencias si sales con tu IP real.

Riesgo: BAJO (consultas a servicios públicos sobre tu propia conexión).
"""

import json
import urllib.request

from core.base_module import BaseModulo, ModuloError


class TorCheck(BaseModulo):
    """Verifica si tu IP de salida es una salida TOR y avisa si no lo es."""

    NAME = "opsec/tor_check"
    CATEGORIA = "opsec"
    DESCRIPCION = ("Comprueba tu IP de salida y si es nodo de salida TOR. "
                   "Avisa si estás operando con tu IP real.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "FDX100/Auto_Tor_IP_changer (concepto)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("EXIGIR_TOR", "false", False, "true = falla si no sales por TOR")

    def ejecutar(self) -> dict:
        timeout = self.opt_int("TIMEOUT", 5) or 5

        # 1) IP de salida
        try:
            with urllib.request.urlopen("http://ip-api.com/json/?fields=query,country,isp,proxy,hosting", timeout=timeout) as resp:
                info = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            raise ModuloError(f"No se pudo consultar la IP de salida: {err}")

        ip_salida = info.get("query", "?")

        # 2) ¿Es salida TOR?
        es_tor = False
        try:
            with urllib.request.urlopen("https://check.torproject.org/api/ip", timeout=timeout) as resp:
                tor_info = json.loads(resp.read().decode())
                es_tor = bool(tor_info.get("IsTor", False))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            es_tor = False  # sin confirmación se asume no

        exigir = self.opt_bool("EXIGIR_TOR", False)
        if exigir and not es_tor:
            raise ModuloError(f"OPSEC insuficiente: {ip_salida} NO es salida TOR (EXIGIR_TOR=true)")

        resumen = (f"IP de salida {ip_salida} — TOR: {'SÍ' if es_tor else 'NO'} "
                   f"(ISP: {info.get('isp', '?')})")
        return {
            "resumen": resumen,
            "ip_salida": ip_salida,
            "es_salida_tor": es_tor,
            "pais": info.get("country"),
            "isp": info.get("isp"),
            "advertencia": ("" if es_tor else
                            "Estás operando con tu IP real. Usa TOR/proxychain en operaciones sensibles."),
        }
