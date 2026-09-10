# -*- coding: utf-8 -*-
"""Tests del gestor de módulos (core.module_manager)."""

import pytest

from core.module_manager import ModuleManager, ModuloNoEncontrado


def test_total_modulos_esperado(manager):
    # 79 módulos: recon 10 + web 19 + phishing 5 + payloads 3 + post 2 + opsec 3
    #             + osint 13 + iot 3 + brute 4 + dos 1 + ad 12 + cloud 4
    assert manager.total_modulos() == 79


def test_obtener_por_ruta_completa(manager):
    cls = manager.obtener("recon/ip_info")
    assert cls.NAME == "recon/ip_info"
    assert cls.CATEGORIA == "recon"


def test_obtener_por_sufijo_unico(manager):
    cls = manager.obtener("whois_lookup")
    assert cls.NAME == "recon/whois_lookup"


def test_obtener_inexistente_lanza(manager):
    with pytest.raises(ModuloNoEncontrado):
        manager.obtener("no/existe")


def test_buscar_por_termino(manager):
    resultados = manager.buscar("phishing")
    assert resultados
    assert all("phishing" in c.NAME or "phishing" in c.DESCRIPCION.lower() for c in resultados)


def test_buscar_vacio_devuelve_todos(manager):
    assert len(manager.buscar("")) == 79


def test_categorias_completas(manager):
    arbol = manager.categorias()
    assert set(arbol) == {"recon", "web", "phishing", "payloads", "post", "opsec",
                          "osint", "iot", "brute", "dos", "ad", "cloud"}
    assert len(arbol["recon"]) == 10
    assert len(arbol["web"]) == 19
    assert len(arbol["phishing"]) == 5
    assert len(arbol["payloads"]) == 3
    assert len(arbol["post"]) == 2
    assert len(arbol["opsec"]) == 3
    assert len(arbol["osint"]) == 13
    assert len(arbol["iot"]) == 3
    assert len(arbol["brute"]) == 4
    assert len(arbol["dos"]) == 1
    assert len(arbol["ad"]) == 12
    assert len(arbol["cloud"]) == 4


def test_todos_heredan_de_base_modulo(manager):
    from core.base_module import BaseModulo
    for cls in manager.listar():
        assert issubclass(cls, BaseModulo)
        assert cls.RIESGO in ("bajo", "medio", "alto"), cls.NAME
        assert cls.DESCRIPCION, cls.NAME


def test_instanciacion_todos(manager):
    """Cada módulo debe instanciarse y declarar opciones sin errores."""
    for cls in manager.listar():
        instancia = cls()
        assert instancia.opciones is not None
        assert len(instancia.opciones) >= 0
