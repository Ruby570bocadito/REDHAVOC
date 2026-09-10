# -*- coding: utf-8 -*-
"""
Módulo osint/typosquat
======================
Genera variantes typosquatting de un dominio y comprueba cuáles están
registradas (DNS) — versión simplificada de dnstwist, idea "Typosquat
Domain Checker" de Argus.

Algoritmos: omisión, duplicación, intercambio adyacente, bitsquatting,
sustitución de vocales y variantes de TLD.

Utilidad: detectar dominios de suplantación contra tu marca (fase de
threat intel y monitorización defensiva).

Riesgo: BAJO (solo resoluciones DNS de dominios públicos).
"""

import socket
import string

from core.base_module import BaseModulo, ModuloError

TLD_ALTERNATIVOS = [".com", ".net", ".org", ".es", ".io", ".co", ".info", ".biz", ".xyz", ".top"]
VOCALES = "aeiou"


def _variantes(dominio: str) -> set:
    """Genera typosquats del SLD (sin TLD)."""
    if "." not in dominio:
        raise ModuloError("El dominio debe incluir TLD, p. ej. acme.com")
    sld, tld = dominio.rsplit(".", 1)
    resultado = set()

    for i in range(len(sld)):                       # omisión de carácter
        if len(sld) > 1:
            resultado.add(sld[:i] + sld[i + 1:])
        resultado.add(sld[:i] + sld[i] + sld[i:] if sld[i] else sld)   # duplicación
        if i < len(sld) - 1:                        # intercambio adyacente
            resultado.add(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:])
        if sld[i] in VOCALES:                       # sustitución de vocal
            for v in VOCALES:
                if v != sld[i]:
                    resultado.add(sld[:i] + v + sld[i + 1:])
        for bit in (1, 2, 4):                       # bitsquatting
            c = chr(ord(sld[i]) ^ bit)
            if c in string.ascii_lowercase or c.isdigit():
                resultado.add(sld[:i] + c + sld[i + 1:])
    return {v + "." + tld for v in resultado if v} | {sld + t for t in TLD_ALTERNATIVOS if t != "." + tld}


class Typosquat(BaseModulo):
    """Genera y comprueba dominios typosquat de la marca objetivo."""

    NAME = "osint/typosquat"
    CATEGORIA = "osint"
    DESCRIPCION = ("Genera variantes typosquatting del dominio (omisión, swap, "
                   "bitsquat, TLD) y comprueba cuáles están registradas.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "elceef/dnstwist · jasonxtn/argus (Typosquat Domain Checker)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio legítimo de la marca (p. ej. acme.com)")
        self.opciones.declarar("MAX_VARIANTES", "80", False, "Límite de variantes a comprobar (DNS)")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN")).lower()
        maximo = min(max(self.opt_int("MAX_VARIANTES", 80), 10), 300)

        candidatas = sorted(_variantes(dominio))
        candidatas = [c for c in candidatas if c != dominio][:maximo]
        if not candidatas:
            raise ModuloError("No se generaron variantes")

        registradas, libres = [], []
        for variante in candidatas:
            try:
                socket.getaddrinfo(variante, None, socket.AF_INET)
                registradas.append(variante)
            except (socket.gaierror, OSError):
                libres.append(variante)

        resumen = (f"{len(candidatas)} variantes: {len(registradas)} registradas "
                   f"(revisar posibles suplantaciones)")
        return {
            "resumen": resumen,
            "dominio_original": dominio,
            "generadas": len(candidatas),
            "registradas": registradas,
            "libres": libres[:50],
            "nota": "Registradas != suplantación: verifica WHOIS/contenido antes de concluir.",
        }
