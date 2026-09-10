# -*- coding: utf-8 -*-
"""Smoke E2E de la consola v1.2: comandos nuevos + módulos nuevos (sin red real)."""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_consola_v12_end_to_end(tmp_path, monkeypatch):
    import builtins

    from core import ethics
    from core.framework import RedHavocFramework

    # Sin interacción humana: disclaimer ya aceptado + riesgo alto autorizado
    monkeypatch.setattr(ethics.EthicsGate, "autorizado", staticmethod(lambda: True))
    monkeypatch.setenv("REDHAVOC_AUTHORIZED", "1")

    fw = RedHavocFramework(tmp_path)

    entradas = iter([
        "search tunnel",
        "use phishing/tunnel",
        "show options",
        "back",
        "use recon/ping_sweep",
        "set TARGET 127.0.0.1/32",
        "back",
        "use brute/http_basic",
        "set URL http://127.0.0.1:1/admin",
        "back",
        "hosts",
        "creds",
        "help",
        "exit",
    ])

    def input_falso(prompt=""):
        try:
            return next(entradas)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr("core.colors.console.input", input_falso)
    fw.repl()

    # El framework sigue vivo tras el REPL y las DB están vacías
    assert fw.modulo_actual is None


def test_ejecucion_bloque_sin_authorized(tmp_path, monkeypatch):
    """dos/stress_http (alto) sin AUTHORIZED → bloqueado, sin ejecutar."""
    from core import ethics
    from core.framework import RedHavocFramework

    monkeypatch.setattr(ethics.EthicsGate, "autorizado", staticmethod(lambda: False))
    monkeypatch.delenv("REDHAVOC_AUTHORIZED", raising=False)

    fw = RedHavocFramework(tmp_path)
    fw._procesar("use dos/stress_http")
    fw._procesar("set URL http://127.0.0.1:1/")
    fw._procesar("run")
    # no debe haber informes generados porque se bloqueó
    assert not list((tmp_path / "output").glob("*.json"))


def test_reporte_html_json_md(tmp_path, monkeypatch):
    """Ejecución de un módulo bajo → genera JSON+MD+HTML y report lo lista."""
    from core import ethics
    from core.framework import RedHavocFramework

    monkeypatch.setattr(ethics.EthicsGate, "autorizado", staticmethod(lambda: True))

    fw = RedHavocFramework(tmp_path)
    fw._procesar("use osint/typosquat")
    fw._procesar("set DOMAIN acme.com")
    fw._procesar("run")
    jsons = list((tmp_path / "output").glob("*.json"))
    htmls = list((tmp_path / "output").glob("*.html"))
    mds = list((tmp_path / "output").glob("*.md"))
    assert jsons and mds and htmls
    contenido = htmls[0].read_text(encoding="utf-8")
    assert "REDHAVOC" in contenido
    fw._procesar("report")
