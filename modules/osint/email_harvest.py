# -*- coding: utf-8 -*-
"""
Módulo osint/email_harvest
==========================
Recolección de direcciones de correo publicadas en el sitio objetivo
(inspirado en "Email Harvesting" de Argus y en theHarvester).

Extrae correos de:
    • Enlaces mailto:
    • Texto plano con regex + obfuscaciones habituales (nombre[arroba]dom)
    • Páginas de contacto habituales (/contacto, /contact, /about, /team)

Riesgo: BAJO (peticiones GET normales).
"""

import re
from urllib.parse import urljoin, urlparse

import requests

from core.base_module import BaseModulo, ModuloError

PAGINAS_HABITUALES = ["", "contacto", "contact", "about", "equipo", "team",
                      "impressum", "aviso-legal", "legal", "privacy"]

REGEX_CORREO = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)
# Filtra falsos positivos típicos
REGEX_FALSO = re.compile(r"\.(png|jpe?g|gif|svg|webp|css|js|ico)$", re.I)
OBFUSCACIONES = [("[arroba]", "@"), ("[at]", "@"), ("[a]", "@"), (" at ", "@"),
                 ("(arroba)", "@"), ("(at)", "@"), ("&#64;", "@"), ("%40", "@")]


class EmailHarvest(BaseModulo):
    """Extrae correos publicados en un sitio web objetivo."""

    NAME = "osint/email_harvest"
    CATEGORIA = "osint"
    DESCRIPCION = ("Recolección de correos expuestos en el sitio objetivo "
                   "(mailto, texto y páginas de contacto habituales).")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (Email Harvesting) · laramies/theHarvester"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL del sitio objetivo")
        self.opciones.declarar("MAX_PAGINAS", "5", False, "Máximo de páginas a descargar (1-20)")
        self.opciones.declarar("DOMINIO", "", False, "Filtrar solo correos de este dominio")

    def _extrae_de_texto(self, texto: str) -> set:
        """Aplica regex y desobfuscaciones sobre un HTML/texto."""
        hallados = set()
        for marcador, arroba in OBFUSCACIONES:
            if marcador in texto.lower():
                hallados.update(REGEX_CORREO.findall(texto.lower().replace(marcador, arroba)))
        hallados.update(REGEX_CORREO.findall(texto))
        limpios = set()
        for correo in hallados:
            correo = correo.strip(".-_").lower()
            if REGEX_FALSO.search(correo):
                continue
            dominio_filtro = self.opt("DOMINIO").lower()
            if dominio_filtro and not correo.endswith("@" + dominio_filtro.lstrip("@")):
                continue
            limpios.add(correo)
        return limpios

    def ejecutar(self) -> dict:
        base = self.opt("URL").strip()
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        max_paginas = min(max(self.opt_int("MAX_PAGINAS", 5), 1), 20)
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        correos = set()
        paginas_visitadas = []
        # 1) Página principal + rutas habituales de contacto
        rutas = PAGINAS_HABITUALES[:max_paginas]
        for ruta in rutas:
            url = urljoin(base + "/", ruta)
            try:
                resp = sesion.get(url, timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            if resp.status_code >= 400:
                continue
            paginas_visitadas.append(url)
            correos |= self._extrae_de_texto(resp.text[:300_000])
            # 2) Enlaces mailto: explícitos
            for mailto in re.findall(r'mailto:([^"\'?>\s]+)', resp.text[:300_000], re.I):
                c = mailto.lower().strip()
                if not REGEX_FALSO.search(c):
                    correos.add(c)

        ordenados = sorted(correos)
        resumen = f"{base}: {len(ordenados)} correos en {len(paginas_visitadas)} páginas"
        return {
            "resumen": resumen,
            "url_base": base,
            "paginas_visitadas": paginas_visitadas,
            "correos": ordenados,
        }
