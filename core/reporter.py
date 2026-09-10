# -*- coding: utf-8 -*-
"""
core.reporter
=============
Reportes de ejecución en JSON, Markdown, HTML y PDF.

Cada ejecución de módulo genera cuatro ficheros en ./output:

    output/2026-09-10_12-00-01_recon-ip_info.json
    output/2026-09-10_12-00-01_recon-ip_info.md
    output/2026-09-10_12-00-01_recon-ip_info.html
    output/2026-09-10_12-00-01_recon-ip_info.pdf

El JSON es processable por otras herramientas; el Markdown es el informe
legible que puede entregarse al cliente; el HTML es presentable y el PDF
(generador puro en core.pdf_min) es el entregable ejecutivo.
"""

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


class Reporter:
    """Genera y persiste informes de ejecución de módulos."""

    def __init__(self, carpeta_salida: Path):
        self.carpeta = Path(carpeta_salida)
        self.carpeta.mkdir(parents=True, exist_ok=True)
        self.ultimo_reporte: Optional[Path] = None

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def guardar(self, modulo_nombre: str, objetivo: str, resultados: Dict[str, Any],
                opciones_usadas: Dict[str, str] | None = None) -> Path:
        """Guarda el reporte JSON+MD de una ejecución. Devuelve ruta del JSON."""
        marca = time.strftime("%Y-%m-%d_%H-%M-%S")
        slug = modulo_nombre.replace("/", "-")
        base = self.carpeta / f"{marca}_{slug}"

        envoltura = {
            "framework": "REDHAVOC",
            "modulo": modulo_nombre,
            "objetivo": objetivo,
            "fecha": time.strftime("%Y-%m-%d %H:%M:%S"),
            "opciones": opciones_usadas or {},
            "resultados": resultados,
        }

        ruta_json = Path(str(base) + ".json")
        ruta_md = Path(str(base) + ".md")
        ruta_html = Path(str(base) + ".html")
        ruta_pdf = Path(str(base) + ".pdf")

        ruta_json.write_text(
            json.dumps(envoltura, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        ruta_md.write_text(self._a_markdown(envoltura), encoding="utf-8")
        ruta_html.write_text(self._a_html(envoltura), encoding="utf-8")
        # PDF puro (roadmap v2.1) — un fallo del PDF nunca rompe el informe
        try:
            from core.pdf_min import informe_a_pdf
            informe_a_pdf(ruta_pdf, envoltura)
        except Exception:  # noqa: BLE001
            pass

        self.ultimo_reporte = ruta_json
        return ruta_json

    # ------------------------------------------------------------------
    # Render HTML
    # ------------------------------------------------------------------
    @staticmethod
    def _a_html(datos: Dict[str, Any]) -> str:
        """Convierte la envoltura de resultados en un informe HTML autocontenido."""
        e = html.escape

        def filas_opciones(opciones: Dict[str, str]) -> str:
            if not opciones:
                return "<em>(sin opciones)</em>"
            celdas = "".join(
                f"<tr><td><code>{e(k)}</code></td><td><code>{e(str(v))}</code></td></tr>"
                for k, v in opciones.items())
            return ("<table><tr><th>Opción</th><th>Valor</th></tr>"
                    f"{celdas}</table>")

        def render(valor: Any, nivel: int = 0) -> str:
            sangria = "margin-left:%dpx" % (14 * nivel)
            if isinstance(valor, dict):
                if not valor:
                    return "<em>(vacío)</em>"
                filas = "".join(
                    f"<div style='{sangria}'><strong>{e(str(clave))}</strong>: "
                    f"{render(sub, nivel + 1) if isinstance(sub, (dict, list)) else '<code>' + e(str(sub)) + '</code>'}"
                    f"</div>" for clave, sub in valor.items())
                return f"<div class='bloque'>{filas}</div>"
            if isinstance(valor, list):
                if not valor:
                    return "<em>(vacía)</em>"
                items = "".join(
                    f"<li>{render(item, nivel + 1) if isinstance(item, (dict, list)) else '<code>' + e(str(item)) + '</code>'}</li>"
                    for item in valor)
                return f"<ul style='{sangria}'>{items}</ul>"
            return f"<code>{e(str(valor))}</code>"

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>REDHAVOC · {e(datos['modulo'])}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #10141d; color: #dde3ee; margin: 0; }}
  .cont {{ max-width: 900px; margin: 0 auto; padding: 32px 20px 60px; }}
  h1 {{ color: #ff4757; font-size: 22px; letter-spacing: 1px; }}
  h2 {{ color: #7dd3fc; font-size: 15px; margin-top: 28px; text-transform: uppercase; letter-spacing: 2px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
  th, td {{ border: 1px solid #2a3245; padding: 7px 10px; font-size: 13px; text-align: left; }}
  th {{ background: #1a2130; color: #9fb3d1; }}
  code {{ background: #1a2130; padding: 2px 6px; border-radius: 4px; font-size: 12.5px; color: #a5e075; word-break: break-all; }}
  .cab {{ background: linear-gradient(135deg, #141926, #1c2438); border: 1px solid #2a3245; border-radius: 10px; padding: 18px 22px; }}
  .cab code {{ color: #ffd166; }}
  .meta {{ font-size: 13px; color: #9fb3d1; }}
  .pie {{ margin-top: 40px; font-size: 11.5px; color: #6b7a94; border-top: 1px solid #2a3245; padding-top: 14px; }}
  .bloque {{ margin: 6px 0; }}
  ul {{ padding-left: 18px; }}
  li {{ margin: 3px 0; font-size: 13px; }}
</style>
</head>
<body><div class="cont">
  <h1>■ REDHAVOC — Informe de módulo</h1>
  <div class="cab">
    <p class="meta">Módulo&nbsp;&nbsp;<code>{e(datos['modulo'])}</code></p>
    <p class="meta">Objetivo&nbsp;<code>{e(datos['objetivo'])}</code></p>
    <p class="meta">Fecha&nbsp;&nbsp;&nbsp;&nbsp;{e(datos['fecha'])}</p>
  </div>
  <h2>Opciones utilizadas</h2>
  {filas_opciones(datos['opciones'])}
  <h2>Resultados</h2>
  {render(datos['resultados'])}
  <p class="pie">Generado por REDHAVOC — Uso exclusivo en pruebas de seguridad AUTORIZADAS.</p>
</div></body>
</html>"""

    # ------------------------------------------------------------------
    # Render Markdown
    # ------------------------------------------------------------------
    @staticmethod
    def _a_markdown(datos: Dict[str, Any]) -> str:
        """Convierte la envoltura de resultados en un informe Markdown."""
        lineas = [
            f"# REDHAVOC — Informe de módulo",
            "",
            f"| Campo | Valor |",
            f"|---|---|",
            f"| Módulo | `{datos['modulo']}` |",
            f"| Objetivo | `{datos['objetivo']}` |",
            f"| Fecha | {datos['fecha']} |",
            "",
            "## Opciones utilizadas",
            "",
        ]
        if datos["opciones"]:
            lineas += [f"- **{k}**: `{v}`" for k, v in datos["opciones"].items()]
        else:
            lineas += ["_(sin opciones)_"]

        lineas += ["", "## Resultados", ""]
        lineas += Reporter._render_valor(datos["resultados"], nivel=0)
        lineas += ["", "---", "*Generado por REDHAVOC — solo para pruebas autorizadas.*"]
        return "\n".join(lineas) + "\n"

    @staticmethod
    def _render_valor(valor: Any, nivel: int) -> list:
        """Render recursivo de estructuras arbitrarias a Markdown legible."""
        sangria = "  " * nivel
        lineas: list = []
        if isinstance(valor, dict):
            for clave, sub in valor.items():
                if isinstance(sub, (dict, list)):
                    lineas.append(f"{sangria}- **{clave}**:")
                    lineas += Reporter._render_valor(sub, nivel + 1)
                else:
                    lineas.append(f"{sangria}- **{clave}**: `{sub}`")
        elif isinstance(valor, list):
            for item in valor:
                if isinstance(item, (dict, list)):
                    lineas += Reporter._render_valor(item, nivel + 1)
                else:
                    lineas.append(f"{sangria}- `{item}`")
        else:
            lineas.append(f"{sangria}- `{valor}`")
        return lineas
