# -*- coding: utf-8 -*-
"""
Módulo phishing/template_gen
============================
Genera páginas de phishing EDUCATIVAS a partir de plantillas del repo,
sustituyendo marcadores {{ORG}}, {{TARGET_URL}}, {{LOGO}}.

Las plantillas incluidas son genéricas (portal corporativo / cambio de
contraseña) y sirven para simulaciones de concienciación autorizadas,
como las que hacen las plataformas comerciales (GoPhish et al.).

Riesgo: BAJO (genera ficheros localmente; no contacta con el objetivo).
"""

import shutil
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

PLANTILLAS = Path(__file__).resolve().parent.parent.parent / "templates" / "phishing"
SALIDA = Path(__file__).resolve().parent.parent.parent / "output" / "phishing"


class TemplateGen(BaseModulo):
    """Genera una página de simulación de phishing desde una plantilla."""

    NAME = "phishing/template_gen"
    CATEGORIA = "phishing"
    DESCRIPCION = ("Genera páginas de simulación de phishing (concienciación) "
                   "desde plantillas del repo, personalizando organización y logo.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "htr-tech/zphisher (concepto) · GoPhish (simulaciones)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("PLANTILLA", "portal_corporativo", True,
                               "Nombre de plantilla en templates/phishing/ (sin .html)")
        self.opciones.declarar("ORG", "Mi Empresa S.L.", False, "Nombre de la organización para la simulación")
        self.opciones.declarar("TARGET_URL", "https://intranet.local", False, "URL legítima a la que redirigir tras la 'captura'")
        self.opciones.declarar("NOMBRE_SALIDA", "campana", False, "Nombre del fichero HTML generado")

    def ejecutar(self) -> dict:
        nombre = self.opt("PLANTILLA").strip().replace(".html", "")
        origen = PLANTILLAS / f"{nombre}.html"
        if not origen.exists():
            disponibles = ", ".join(p.stem for p in PLANTILLAS.glob("*.html")) or "—"
            raise ModuloError(f"Plantilla '{nombre}' no encontrada. Disponibles: {disponibles}")

        html = origen.read_text(encoding="utf-8")
        sustituciones = {
            "{{ORG}}": self.opt("ORG", "Mi Empresa"),
            "{{TARGET_URL}}": self.opt("TARGET_URL", "https://intranet.local"),
            "{{FECHA}}": __import__("time").strftime("%d/%m/%Y"),
        }
        for marcador, valor in sustituciones.items():
            html = html.replace(marcador, valor)

        SALIDA.mkdir(parents=True, exist_ok=True)
        destino = SALIDA / f"{self.opt('NOMBRE_SALIDA', 'campana')}.html"
        destino.write_text(html, encoding="utf-8")

        # Copia también el script de captura adjunto a la plantilla si existe
        capturador = PLANTILLAS / "capture.js"
        copiado = ""
        if capturador.exists():
            shutil.copy(capturador, SALIDA / capturador.name)
            copiado = str(SALIDA / capturador.name)

        resumen = f"Página generada: {destino}"
        return {
            "resumen": resumen,
            "plantilla": nombre,
            "fichero_html": str(destino),
            "capturador_copiado": copiado,
            "marcadores_sustituidos": list(sustituciones.keys()),
        }
