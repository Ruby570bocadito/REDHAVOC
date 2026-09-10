# -*- coding: utf-8 -*-
"""
Módulo osint/cert_transparency
==============================
Subdominios desde los logs de Transparencia de Certificados (CT logs):
crt.sh (con fallback a CertSpotter). Es la fuente pasiva de subdominios
más fiable: cualquier certificado emitido para el dominio queda registrado.

Ideas de: reconmap (módulo cert) · Osmedeus.
Riesgo: BAJO (consulta pública).
ATT&CK: T1596.003 (Search Open Technical Databases: Digital Certificates).
"""

import requests

from core.base_module import BaseModulo, ModuloError

CRTSH = "https://crt.sh/?q=%25.{d}&output=json"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"


class CertTransparency(BaseModulo):
    """Recoge subdominios históricos y actuales de los CT logs."""

    NAME = "osint/cert_transparency"
    CATEGORIA = "osint"
    DESCRIPCION = ("Subdominios vía CT logs (crt.sh + CertSpotter): certificados "
                   "históricos y actuales del dominio objetivo. Pasivo, sin API key.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (módulo cert) · MITRE ATT&CK T1596.003"
    ATTCK = ("T1596.003",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Dominio objetivo (p. ej. empresa.com)")
        self.opciones.declarar("LIMITE", "800", False, "Máximo de subdominios a devolver")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("TARGET")).lower()
        limite = self.opt_int("LIMITE", 800) or 800
        timeout = self.opt_int("TIMEOUT", 15) or 15
        cabeceras = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        nombres = set()
        fuentes_ok, fuentes_ko = [], []

        # --- crt.sh -------------------------------------------------------
        try:
            resp = requests.get(CRTSH.format(d=dominio), timeout=timeout,
                                headers=cabeceras)
            if resp.status_code == 200 and resp.text.strip().startswith("["):
                for fila in resp.json():
                    for nombre in (fila.get("name_value") or "").split("\n"):
                        nombres.add(nombre.strip().lower())
                fuentes_ok.append("crt.sh")
            else:
                fuentes_ko.append(f"crt.sh (HTTP {resp.status_code})")
        except (requests.RequestException, ValueError) as err:
            fuentes_ko.append(f"crt.sh ({err})")

        # --- CertSpotter (fallback/complemento) ---------------------------
        try:
            resp = requests.get(CERTSPOTTER.format(d=dominio), timeout=timeout,
                                headers=cabeceras)
            if resp.status_code == 200 and resp.text.strip().startswith("["):
                for fila in resp.json():
                    for nombre in fila.get("dns_names") or []:
                        nombres.add(nombre.strip().lower())
                fuentes_ok.append("certspotter")
            else:
                fuentes_ko.append(f"certspotter (HTTP {resp.status_code})")
        except (requests.RequestException, ValueError) as err:
            fuentes_ko.append(f"certspotter ({err})")

        if not fuentes_ok:
            raise ModuloError("Ninguna fuente CT respondió: " + "; ".join(fuentes_ko))

        subdominios = sorted(
            n for n in nombres
            if n.endswith("." + dominio) or n == dominio
            if "*" not in n
        )[:limite]
        salvajes = sorted(n for n in nombres if "*" in n and dominio in n)

        return {
            "resumen": (f"CT logs {dominio}: {len(subdominios)} subdominios "
                        f"({' + '.join(fuentes_ok)})"),
            "dominio": dominio,
            "fuentes": fuentes_ok,
            "fuentes_ko": fuentes_ko,
            "subdominios": subdominios,
            "wildcards": salvajes,
        }
