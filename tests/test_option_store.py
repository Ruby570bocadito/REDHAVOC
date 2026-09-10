# -*- coding: utf-8 -*-
"""Tests del sistema de opciones (core.option_store)."""

import pytest

from core.option_store import OptionStore


@pytest.fixture()
def store() -> OptionStore:
    s = OptionStore()
    s.declarar("TARGET", "", True, "objetivo")
    s.declarar("PORT", "8080", False, "puerto")
    s.declarar("FLAG", "true", False, "booleana")
    return s


def test_declarar_defaults(store):
    assert store.get("PORT") == "8080"
    assert store.get("NO_EXISTE", "respaldo") == "respaldo"
    assert len(store) == 3


def test_set_y_unset(store):
    assert store.set("PORT", "9090") is True
    assert store.get("PORT") == "9090"
    assert store.unset("PORT") is True
    assert store.get("PORT") == "8080"  # vuelve al por_defecto


def test_set_inexistente(store):
    assert store.set("INVENTADA", "1") is False


def test_validacion_requeridos(store):
    assert store.validar_o_error() is not None  # TARGET vacío
    store.set("TARGET", "10.0.0.1")
    assert store.validar_o_error() is None


def test_faltantes(store):
    assert store.faltantes() == ["TARGET"]
    store.set("TARGET", "x")
    assert store.faltantes() == []


def test_booleanos_y_enteros(store):
    assert store.get_bool("FLAG") is True
    store.set("FLAG", "no")
    assert store.get_bool("FLAG") is False
    assert store.get_int("PORT") == 8080
    store.set("PORT", "no-numero")
    assert store.get_int("PORT") == 0


def test_contains_e_iteracion(store):
    assert "TARGET" in store
    nombres = {o.nombre for o in store}
    assert {"TARGET", "PORT", "FLAG"} == nombres


def test_redeclarar_conserva_valor(store):
    store.set("PORT", "1234")
    store.declarar("PORT", "8080", False, "nueva descripcion")
    assert store.get("PORT") == "1234"  # el valor fijado por el operador persiste
