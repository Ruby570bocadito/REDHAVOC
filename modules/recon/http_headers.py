# -*- coding: utf-8 -*-
"""
Módulo recon/http_headers
=========================
Auditoría de cabeceras HTTP: muestra las recibidas y evalúa las cabeceras
de seguridad ausentes (CSP, HSTS, X-Frame-Options, etc.) con puntuación.

Riesgo: BAJO (una petición GET normal).
"""

import requests

from core.base_module import BaseModulo, ModuloError

# Cabeceras de seguridad esperadas y su explicación
CABECERAS_SEGURIDAD = {
    "Content-Security-Policy": "Mitiga XSS e inyección de contenido",
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS)",
    "X-Frame-Options": "Previene clickjacking",
    "X-Content-Type-Options": "Evita MIME-sniffing",
    "Referrer-Policy": "Controla filtración del referrer",
    "Permissions-Policy": "Restringe APIs del navegador",
}


class HttpHeaders(BaseModulo):
    """Audita las cabeceras HTTP de una URL y su postura de seguridad."""

    NAME = "recon/http_headers"
    CATEGORIA = "recon"
    DESCRIPCION = ("Auditoría de cabeceras HTTP de una URL: valores recibidos "
                   "y cabeceras de seguridad ausentes con puntuación.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RED_HAWK (basic scan)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo (p. ej. https://example.com)")
        self.opciones.declarar("FOLLOW", "true", False, "Seguir redirecciones (true/false)")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        try:
            resp = sesion.get(url, timeout=timeout, allow_redirects=self.opt_bool("FOLLOW", True))
        except requests.RequestException as err:
            raise ModuloError(f"Petición fallida a {url}: {err}")

        cabeceras = {k: v for k, v in resp.headers.items()}
        ausentes = [
            {"cabecera": h, "motivo": motivo}
            for h, motivo in CABECERAS_SEGURIDAD.items() if h not in cabeceras
        ]
        presentes = [h for h in CABECERAS_SEGURIDAD if h in cabeceras]
        puntuacion = round(100 * len(presentes) / len(CABECERAS_SEGURIDAD))

        # Nota: el servidor puede ocultar la cabecera Server por configuración.
        servidor = cabeceras.get("Server", "(no revelada)")
        resumen = f"{url} → HTTP {resp.status_code}, postura de seguridad {puntuacion}/100"

        return {
            "resumen": resumen,
            "url_final": resp.url,
            "codigo_estado": resp.status_code,
            "servidor": servidor,
            "cabeceras": cabeceras,
            "seguridad_presentes": presentes,
            "seguridad_ausentes": ausentes,
            "puntuacion_seguridad": puntuacion,
        }
