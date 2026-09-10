# -*- coding: utf-8 -*-
"""Tests de la puerta ética (core.ethics)."""

import json

from core.ethics import EthicsGate


def test_aceptacion_flujo_completo(tmp_path):
    gate = EthicsGate(tmp_path)
    assert gate.ya_aceptado() is False
    gate.registrar_aceptacion("tester")
    assert gate.ya_aceptado() is True
    datos = json.loads((tmp_path / "aceptacion.json").read_text(encoding="utf-8"))
    assert datos["aceptado"] is True
    assert datos["operador"] == "tester"


def test_auditoria_escribe_lineas(tmp_path):
    gate = EthicsGate(tmp_path)
    gate.auditar("RUN", "recon/ip_info -> 8.8.8.8")
    gate.auditar("BLOQUEO_RIESGO_ALTO", "web/sqli_scanner")
    lineas = (tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(lineas) == 2
    assert "RUN" in lineas[0] and "recon/ip_info" in lineas[0]
    assert lineas[1].startswith("[")  # marca temporal


def test_autorizado_por_entorno(monkeypatch):
    monkeypatch.setenv("REDHAVOC_AUTHORIZED", "1")
    assert EthicsGate.autorizado() is True
    monkeypatch.setenv("REDHAVOC_AUTHORIZED", "true")
    assert EthicsGate.autorizado() is True
    monkeypatch.setenv("REDHAVOC_AUTHORIZED", "")
    assert EthicsGate.autorizado() is False
    monkeypatch.delenv("REDHAVOC_AUTHORIZED", raising=False)
    assert EthicsGate.autorizado() is False
