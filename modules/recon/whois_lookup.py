# -*- coding: utf-8 -*-
"""
Módulo recon/whois_lookup
=========================
Consulta WHOIS pura por socket (puerto 43) siguiendo las referencias de
la IANA al registrar correspondiente. Sin dependencias externas.

Riesgo: BAJO (consulta pública de metadatos de dominio).
"""

import socket

from core.base_module import BaseModulo, ModuloError

SERVIDOR_RAIZ = "whois.iana.org"


def _whois_query(servidor: str, consulta: str, timeout: int) -> str:
    """Ejecuta una consulta WHOIS cruda y devuelve la respuesta completa."""
    with socket.create_connection((servidor, 43), timeout=timeout) as sock:
        sock.sendall((consulta + "\r\n").encode())
        respuesta = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            respuesta += chunk
    return respuesta.decode(errors="replace")


class WhoisLookup(BaseModulo):
    """Registro WHOIS de un dominio: registrante, fechas y nameservers."""

    NAME = "recon/whois_lookup"
    CATEGORIA = "recon"
    DESCRIPCION = ("Consulta WHOIS (puerto 43) de un dominio: registrador, "
                   "fechas de registro/expiración y nameservers.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RED_HAWK (whois)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio objetivo (p. ej. example.com)")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN"))
        timeout = self.opt_int("TIMEOUT", 5) or 5

        # 1) Consulta a la IANA para descubrir el whois del TLD
        try:
            respuesta = _whois_query(SERVIDOR_RAIZ, dominio, timeout)
        except (OSError, socket.timeout) as err:
            raise ModuloError(f"Sin conexión a {SERVIDOR_RAIZ}: {err}")

        referido = None
        for linea in respuesta.splitlines():
            if linea.lower().startswith("refer:"):
                referido = linea.split(":", 1)[1].strip()
                break

        # 2) Consulta al registrador específico (si existe)
        if referido:
            try:
                respuesta = _whois_query(referido, dominio, timeout)
            except (OSError, socket.timeout):
                pass  # se conserva la respuesta de la IANA

        # 3) Extracción de campos clave
        campos = {}
        claves = ("registrar:", "creation date:", "created:", "registered:",
                  "expiry date:", "expiration date:", "updated date:",
                  "registrant name:", "registrant organization:",
                  "registrant country:", "abuse contact email:")
        for linea in respuesta.lower().splitlines():
            for clave in claves:
                if linea.startswith(clave) and clave[:-1].title() not in campos:
                    campos[clave[:-1].title()] = linea.split(":", 1)[1].strip()

        nameservers = sorted({
            l.split(":", 1)[1].strip().lower()
            for l in respuesta.lower().splitlines()
            if l.startswith("name server:") and ":" in l
        })

        resumen = f"WHOIS de {dominio} vía {referido or SERVIDOR_RAIZ}"
        return {
            "resumen": resumen,
            "dominio": dominio,
            "servidor_whois": referido or SERVIDOR_RAIZ,
            "campos": campos,
            "nameservers": nameservers,
            "respuesta_cruda": respuesta[:4000],  # recortada para el informe
        }
