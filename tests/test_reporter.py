# -*- coding: utf-8 -*-
"""Tests del reporter (core.reporter)."""

import json
from pathlib import Path

from core.reporter import Reporter


def test_guardar_genera_json_y_md(tmp_path):
    reporter = Reporter(tmp_path)
    ruta = reporter.guardar(
        "recon/ip_info", "8.8.8.8",
        {"resumen": "ok", "pais": "EE. UU.", "lista": [1, 2], "anidado": {"a": True}},
        opciones_usadas={"TARGET": "8.8.8.8"},
    )
    assert ruta.exists() and ruta.suffix == ".json"
    md = Path(str(ruta)[:-5] + ".md")
    assert md.exists()

    datos = json.loads(ruta.read_text(encoding="utf-8"))
    assert datos["modulo"] == "recon/ip_info"
    assert datos["objetivo"] == "8.8.8.8"
    assert datos["resultados"]["pais"] == "EE. UU."
    assert datos["opciones"]["TARGET"] == "8.8.8.8"

    contenido_md = md.read_text(encoding="utf-8")
    assert "REDHAVOC" in contenido_md
    assert "recon/ip_info" in contenido_md
    assert "EE. UU." in contenido_md


def test_reporter_ultimo_reporte(tmp_path):
    reporter = Reporter(tmp_path)
    ruta = reporter.guardar("web/cms_detect", "x.com", {"resumen": "nada"})
    assert reporter.ultimo_reporte == ruta


def test_estructuras_complejas(tmp_path):
    from pathlib import Path
    reporter = Reporter(tmp_path)
    ruta = reporter.guardar("t/x", "t", {"d": [{"n": 1}, {"n": 2}]})
    datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
    assert datos["resultados"]["d"][0]["n"] == 1
