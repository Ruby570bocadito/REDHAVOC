# -*- coding: utf-8 -*-
"""
Módulo web/tech_detect
======================
Fingerprinting de tecnologías web: servidor, frameworks, lenguajes y
CMS inferidos de cabeceras, cookies y marcadores en el HTML.

Riesgo: BAJO (peticiones GET normales).
"""

import requests

from core.base_module import BaseModulo, ModuloError

# Huellas: (evidencia, tipo, ubicación) → tecnología
HUELLAS_CABECERAS = {
    "X-Powered-By": {
        "PHP": "PHP", "ASP.NET": "ASP.NET", "Express": "Express.js",
        "Next.js": "Next.js", "Phusion Passenger": "Ruby/Rails",
    },
    "Server": {
        "nginx": "Nginx", "Apache": "Apache", "IIS": "Microsoft IIS",
        "cloudflare": "Cloudflare", "LiteSpeed": "LiteSpeed", "gunicorn": "Gunicorn",
    },
}
HUELLAS_COOKIE = {
    "PHPSESSID": "PHP", "JSESSIONID": "Java", "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel", "csrftoken": "Django", "sessionid": "Django",
    "connect.sid": "Express.js", "_rails_session": "Ruby/Rails",
}
HUELLAS_HTML = {
    'wp-content': "WordPress", 'wp-json': "WordPress",
    '/administrator/': "Joomla", 'Joomla!': "Joomla",
    'Drupal.settings': "Drupal", 'drupal.js': "Drupal",
    'cdn.shopify.com': "Shopify", 'Shopify.theme': "Shopify",
    'generator" content="Wix': "Wix", 'react': "React",
    'ng-version': "Angular", '__NEXT_DATA__': "Next.js",
    'nuxt': "Nuxt.js", 'vue': "Vue.js", 'jquery': "jQuery",
}


class TechDetect(BaseModulo):
    """Identifica tecnologías de una aplicación web pasivamente."""

    NAME = "web/tech_detect"
    CATEGORIA = "web"
    DESCRIPCION = ("Fingerprinting pasivo de tecnologías web: servidor, "
                   "lenguaje, framework y CMS vía cabeceras, cookies y HTML.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Wappalyzer (heurísticas simplificadas)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo (p. ej. https://example.com)")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        timeout = self.opt_int("TIMEOUT", 5) or 5

        try:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"},
                                verify=False)
        except requests.RequestException as err:
            raise ModuloError(f"Petición fallida: {err}")

        tecnologias = set()

        # 1) Cabeceras
        for cabecera, mapa in HUELLAS_CABECERAS.items():
            valor = resp.headers.get(cabecera, "")
            for huella, nombre in mapa.items():
                if huella.lower() in valor.lower():
                    tecnologias.add(nombre)

        # 2) Cookies
        for cookie in resp.cookies:
            if cookie.name in HUELLAS_COOKIE:
                tecnologias.add(HUELLAS_COOKIE[cookie.name])

        # 3) HTML
        cuerpo = resp.text[:100_000].lower()
        for huella, nombre in HUELLAS_HTML.items():
            if huella.lower() in cuerpo:
                tecnologias.add(nombre)

        lista = sorted(tecnologias)
        resumen = f"{resp.url}: {len(lista)} tecnologías detectadas"
        return {
            "resumen": resumen,
            "url_final": resp.url,
            "codigo_estado": resp.status_code,
            "servidor": resp.headers.get("Server", "(no revelada)"),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "tecnologias": lista,
        }
