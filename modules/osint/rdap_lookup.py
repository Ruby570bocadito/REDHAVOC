# -*- coding: utf-8 -*-
"""
Módulo osint/rdap_lookup
========================
Ficha de registro vía RDAP (rdap.org, sustituto moderno de whois):
para dominios — registrador, fechas de registro/expiración, nameservers
y contacto de abuso; para IPs — ASN, organización, país y rango.

Ideas de: reconmap (módulo rdap) · theHarvester.
Riesgo: BAJO (consulta pública).
ATT&CK: T1596.001 (WHOIS) / T1590.001 (Domain Properties).
"""

import ipaddress

import requests

from core.base_module import BaseModulo, ModuloError

RDAP = "https://rdap.org/{tipo}/{valor}"


class RdapLookup(BaseModulo):
    """Consulta RDAP de dominio o IP (registrar, ASN, abuse…)."""

    NAME = "osint/rdap_lookup"
    CATEGORIA = "osint"
    DESCRIPCION = ("Ficha de registro RDAP (dominio: registrar/fechas/abuso · "
                   "IP: ASN/organización/país/rango). Sustituto moderno de whois.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (módulo rdap) · MITRE ATT&CK T1596.001"
    ATTCK = ("T1596.001", "T1590.001")

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Dominio o IP objetivo")

    def ejecutar(self) -> dict:
        objetivo = self._objetivo_host(self.opt("TARGET"))
        timeout = self.opt_int("TIMEOUT", 15) or 15
        cabeceras = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC",
                     "Accept": "application/rdap+json, application/json"}

        try:
            ipaddress.ip_address(objetivo)
            tipo = "ip"
        except ValueError:
            tipo = "domain"

        try:
            resp = requests.get(RDAP.format(tipo=tipo, valor=objetivo),
                                timeout=timeout, headers=cabeceras)
        except requests.RequestException as err:
            raise ModuloError(f"Consulta RDAP falló: {err}")
        if resp.status_code == 404:
            raise ModuloError(f"RDAP no tiene datos para {objetivo}")
        if resp.status_code != 200:
            raise ModuloError(f"RDAP respondió HTTP {resp.status_code}")
        try:
            datos = resp.json()
        except ValueError as err:
            raise ModuloError(f"RDAP devolvió JSON inválido: {err}")

        ficha = {"objetivo": objetivo, "tipo": tipo}
        if tipo == "domain":
            ficha["registrar"] = ""
            for entidad in datos.get("entities", []) or []:
                if "registrar" in (entidad.get("roles") or []):
                    vcard = entidad.get("vcardArray") or []
                    if len(vcard) > 1:
                        for campo in vcard[1]:
                            if campo[0] == "fn":
                                ficha["registrar"] = campo[3] if isinstance(campo[3], str) else ""
                                break
            fechas = {}
            for evento in datos.get("events", []) or []:
                fechas[evento.get("eventAction", "?")] = evento.get("eventDate", "")
            ficha["fechas"] = fechas
            ficha["nameservers"] = [n.get("ldhName", "") for n in datos.get("nameservers", []) or []]
            ficha["estados"] = datos.get("status", [])[:10]
            # contacto de abuso (vcard del registrar)
            for entidad in datos.get("entities", []) or []:
                if "registrar" in (entidad.get("roles") or []):
                    vcard = entidad.get("vcardArray") or []
                    if len(vcard) > 1:
                        for campo in vcard[1]:
                            if campo[0] == "email":
                                ficha["abuse"] = campo[3]
                                break
        else:
            ficha["asn"] = ""
            ficha["organizacion"] = ""
            for entidad in datos.get("entities", []) or []:
                manejador = str(entidad.get("handle", ""))
                if manejador.upper().startswith("AS") and manejador[2:].isdigit():
                    ficha["asn"] = manejador
                vcard = entidad.get("vcardArray") or []
                if len(vcard) > 1 and not ficha["organizacion"]:
                    for campo in vcard[1]:
                        if campo[0] == "fn":
                            ficha["organizacion"] = campo[3] if isinstance(campo[3], str) else ""
                            break
            ficha["pais"] = (datos.get("country") or "").upper()
            ficha["rango"] = f"{datos.get('startAddress', '')} – {datos.get('endAddress', '')}"
            ficha["tipo_red"] = datos.get("type", "")
            # algunos RDAP exponen el ASN como handle del objeto de red
            if not ficha["asn"]:
                raiz = str(datos.get("handle", ""))
                if raiz.upper().startswith("AS") and raiz[2:].isdigit():
                    ficha["asn"] = raiz

        partes = [f"RDAP {objetivo} ({tipo})"]
        if tipo == "domain" and ficha.get("registrar"):
            partes.append(f"registrar={ficha['registrar']}")
        if tipo == "ip" and ficha.get("asn"):
            partes.append(f"{ficha['asn']} ({ficha.get('organizacion', '?')})")

        return {"resumen": " · ".join(str(p) for p in partes), **ficha}
