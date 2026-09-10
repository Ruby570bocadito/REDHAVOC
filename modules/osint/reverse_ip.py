# -*- coding: utf-8 -*-
"""
Módulo osint/reverse_ip
=======================
Búsqueda inversa: qué dominios comparten la IP del objetivo
("Reverse IP Lookup" de Argus / RED_HAWK). Usa la API gratuita de
Hackertarget (best-effort, sin clave).

Riesgo: BAJO (consulta pública).
"""

import requests

from core.base_module import BaseModulo, ModuloError

API = "https://api.hackertarget.com/reverseiplookup/?q={q}"


class ReverseIp(BaseModulo):
    """Lista dominios alojados en la misma IP (hosting compartido)."""

    NAME = "osint/reverse_ip"
    CATEGORIA = "osint"
    DESCRIPCION = ("Reverse IP lookup: dominios alojados en la misma IP que el "
                   "objetivo (API gratuita Hackertarget, best-effort).")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (Reverse IP Lookup) · RED_HAWK"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "IP o dominio objetivo")

    def ejecutar(self) -> dict:
        objetivo = self._objetivo_host(self.opt("TARGET"))
        timeout = self.opt_int("TIMEOUT", 10) or 10

        try:
            resp = requests.get(API.format(q=objetivo), timeout=timeout,
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"Consulta Hackertarget falló: {err}")

        texto = resp.text.strip()
        if "error check your search" in texto.lower() or resp.status_code >= 400:
            raise ModuloError(f"Hackertarget respondió: {texto[:120]}")

        dominios = [d for d in texto.splitlines() if d.strip() and "@" not in d]
        dominios = sorted(set(dominios))

        resumen = f"{objetivo}: {len(dominios)} dominios en la misma IP"
        return {
            "resumen": resumen,
            "objetivo": objetivo,
            "dominios": dominios,
            "nota": "El objetivo comparte hosting: comprometer un vecino expone al objetivo (principio de defensa).",
        }
