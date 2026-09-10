# -*- coding: utf-8 -*-
"""Fixtures compartidas de los tests de REDHAVOC."""

import sys
from pathlib import Path

import pytest

# Añade la raíz del proyecto al path (tests/ → raíz)
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from core.module_manager import ModuleManager  # noqa: E402


@pytest.fixture(scope="session")
def raiz() -> Path:
    """Ruta raíz del proyecto."""
    return RAIZ


@pytest.fixture(scope="session")
def manager() -> ModuleManager:
    """Gestor de módulos con todos los módulos reales cargados."""
    return ModuleManager()


@pytest.fixture()
def modulo_ip_info(manager):
    """Instancia fresca del módulo recon/ip_info."""
    cls = manager.obtener("recon/ip_info")
    return cls()
