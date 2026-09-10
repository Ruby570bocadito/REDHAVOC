# -*- coding: utf-8 -*-
"""
Módulo web/cms_detect
=====================
Detección de CMS (WordPress, Joomla, Drupal, Shopify, Moodle...) mediante
rutas y ficheros característicos. Inspirado en BadMod / RED_HAWK.

Riesgo: BAJO-MEDIO (pocas peticiones GET a rutas públicas conocidas).
"""

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CMS → lista de (ruta, huella esperada en el cuerpo o "") 
FINGERPRINTS = {
    "WordPress": [
        ("/wp-login.php", "wp-submit"),
        ("/wp-includes/js/wp-emoji.js", "wp-emoji"),
        ("/readme.html", "WordPress"),
    ],
    "Joomla": [
        ("/administrator/", "Joomla"),
        ("/language/en-GB/en-GB.ini", "Joomla"),
    ],
    "Drupal": [
        ("/misc/drupal.js", "Drupal"),
        ("/core/CHANGELOG.txt", "Drupal"),
    ],
    "Shopify": [
        ("/cart.js", "shopify"),
    ],
    "Moodle": [
        ("/login/index.php", "moodle"),
    ],
    "PrestaShop": [
        ("/modules/ps_shoppingcart/", "prestashop"),
    ],
}


class CmsDetect(BaseModulo):
    """Identifica el CMS del objetivo comprobando rutas características."""

    NAME = "web/cms_detect"
    CATEGORIA = "web"
    DESCRIPCION = ("Detección de CMS (WordPress, Joomla, Drupal, Shopify...) "
                   "comprobando rutas y ficheros característicos.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "MrSqar-Ye/BadMod · RED_HAWK (CMS detection)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo (p. ej. https://example.com)")

    def _comprueba(self, sesion, base: str, ruta: str, huella: str, timeout: int):
        """GET a la ruta; True si responde 2xx/3xx y la huella aparece."""
        try:
            resp = sesion.get(base + ruta, timeout=timeout, verify=False, allow_redirects=True)
        except requests.RequestException:
            return False
        if resp.status_code >= 400:
            return False
        if huella and huella.lower() not in resp.text[:200_000].lower():
            return False
        return True

    def ejecutar(self) -> dict:
        base = self.opt("URL").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        detecciones = []
        for cms, pruebas in FINGERPRINTS.items():
            aciertos = sum(1 for ruta, huella in pruebas
                           if self._comprueba(sesion, base, ruta, huella, timeout))
            if aciertos > 0:
                detecciones.append({"cms": cms, "confianza": f"{aciertos}/{len(pruebas)}"})

        if not detecciones:
            resumen = f"{base}: CMS no identificado"
        else:
            resumen = f"{base}: " + ", ".join(f"{d['cms']} ({d['confianza']})" for d in detecciones)

        return {
            "resumen": resumen,
            "url_base": base,
            "cms_detectados": detecciones,
            "cms_principal": detecciones[0]["cms"] if detecciones else "",
        }
