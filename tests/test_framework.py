# -*- coding: utf-8 -*-
"""Tests del framework (consola REPL) con módulos simulados."""

import pytest

from core.framework import RedHavocFramework


@pytest.fixture()
def fw(tmp_path):
    """Framework apuntando a un workspace temporal."""
    return RedHavocFramework(raiz=tmp_path)


def _ejecuta(fw, linea):
    """Procesa una línea sin salir del REPL (captura SystemExit)."""
    try:
        fw._procesar(linea)
    except SystemExit:
        pass


def test_inicializacion(fw):
    assert fw.module_manager.total_modulos() == 79
    assert "AUTHORIZED" in fw.globales
    assert "REPORT" in fw.globales


def test_use_y_back(fw):
    _ejecuta(fw, "use recon/ip_info")
    assert fw.modulo_actual is not None
    assert fw.modulo_actual.NAME == "recon/ip_info"
    _ejecuta(fw, "back")
    assert fw.modulo_actual is None


def test_use_inexistente_no_rompe(fw):
    _ejecuta(fw, "use no/existe")
    assert fw.modulo_actual is None


def test_set_unset_en_modulo(fw):
    _ejecuta(fw, "use recon/ip_info")
    _ejecuta(fw, "set TARGET 8.8.8.8")
    assert fw.modulo_actual.opt("TARGET") == "8.8.8.8"
    _ejecuta(fw, "unset TARGET")
    assert fw.modulo_actual.opt("TARGET") == ""


def test_set_global_sin_modulo(fw):
    _ejecuta(fw, "set THREADS 25")
    assert fw.globales.get("THREADS") == "25"


def test_set_con_url_con_iguales(fw):
    """El valor debe conservarse íntegro aunque contenga '=' o '&'."""
    _ejecuta(fw, "use web/sqli_scanner")
    _ejecuta(fw, "set URL https://x.com/a.php?id=1&b=2")
    assert fw.modulo_actual.opt("URL") == "https://x.com/a.php?id=1&b=2"


def test_run_sin_modulo_da_error(fw, capsys):
    _ejecuta(fw, "run")
    salida = capsys.readouterr().out
    assert "No hay módulo cargado" in salida


def test_run_falta_opcion_obligatoria(fw, capsys):
    _ejecuta(fw, "use recon/ip_info")
    _ejecuta(fw, "run")
    salida = capsys.readouterr().out
    assert "Faltan opciones" in salida


def test_run_modulo_generador(fw, capsys):
    """payloads/macro_gen es offline y de riesgo alto → con AUTHORIZED corre."""
    _ejecuta(fw, "set AUTHORIZED true")
    _ejecuta(fw, "use payloads/macro_gen")
    _ejecuta(fw, "run")
    salida = capsys.readouterr().out
    assert "Módulo completado" in salida
    assert "Informe" in salida  # REPORT=true por defecto


def test_run_riesgo_alto_bloqueado_sin_autorizacion(fw, capsys):
    _ejecuta(fw, "use payloads/macro_gen")
    _ejecuta(fw, "run")
    salida = capsys.readouterr().out
    assert "RIESGO ALTO" in salida or "AUTHORIZED" in salida


def test_search_muestra_tabla(fw, capsys):
    _ejecuta(fw, "search subdominios")
    salida = capsys.readouterr().out
    assert "recon/subdomain_scan" in salida


def test_show_modules(fw, capsys):
    _ejecuta(fw, "show modules")
    salida = capsys.readouterr().out
    assert "recon" in salida and "payloads" in salida


def test_comando_desconocido(fw, capsys):
    _ejecuta(fw, "frobnicate")
    salida = capsys.readouterr().out
    assert "desconocido" in salida


def test_informe_generado(tmp_path, fw, capsys):
    _ejecuta(fw, "set AUTHORIZED true")
    _ejecuta(fw, "use payloads/loader_gen")
    _ejecuta(fw, "run")
    _ejecuta(fw, "report")
    salida = capsys.readouterr().out
    assert "Último informe" in salida
    # hay JSON en output/
    informes = list((tmp_path / "output").glob("*.json"))
    assert informes
