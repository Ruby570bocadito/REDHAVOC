# -*- coding: utf-8 -*-
"""
core.base_module
================
Clase base de la que heredan TODOS los módulos de REDHAVOC.

Un módulo de REDHAVOC es una clase Python que:
  • Declara metadatos (NAME, CATEGORIA, DESCRIPCION, RIESGO, AUTOR).
  • Declara sus opciones en `definir_opciones()`.
  • Implementa `ejecutar()` que devuelve un diccionario de resultados.

El framework se encarga de: validar opciones, pedir autorización si el
riesgo es alto, mostrar el spinner, guardar el reporte (JSON/MD) y auditar.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

from core.option_store import OptionStore

# Niveles de riesgo (ordenados de menor a mayor gravedad operacional)
RIESGOS = ("bajo", "medio", "alto")


class BaseModulo(ABC):
    """Base común para todos los módulos del framework."""

    # --- Metadatos (sobrescribir en cada módulo) -----------------------
    NAME: str = "generico/sin_nombre"       # ruta tipo categoria/nombre
    CATEGORIA: str = "generico"
    DESCRIPCION: str = "Módulo sin descripción."
    RIESGO: str = "bajo"                    # bajo | medio | alto
    AUTOR: str = "REDHAVOC"
    REFERENCIA: str = ""                    # proyecto de inspiración, si aplica
    ATTCK: tuple = ()                       # técnicas MITRE ATT&CK asociadas
    CVE: tuple = ()                         # CVEs/advisories relacionados (info)

    def __init__(self) -> None:
        self.opciones = OptionStore()
        self.resultado: Dict[str, Any] = {}
        self.definir_opciones()

    # ------------------------------------------------------------------
    # API que deben implementar los módulos
    # ------------------------------------------------------------------
    def definir_opciones(self) -> None:
        """Declara las opciones del módulo vía self.opciones.declarar(...)."""

    @abstractmethod
    def ejecutar(self) -> Dict[str, Any]:
        """Ejecuta la acción del módulo y devuelve un dict de resultados.

        Debe lanzar ModuloError en caso de fallo controlado (el framework
        lo mostrará como error limpio sin traceback).
        """

    # ------------------------------------------------------------------
    # Helpers de conveniencia para los módulos
    # ------------------------------------------------------------------
    @property
    def workspace(self):
        """Workspace del framework (o None si el módulo corre sin contexto).

        Los módulos que autorellenan la base de datos deben tolerar un
        `None`: fuera de la consola (tests, import directo) no hay ctx.
        """
        ctx = getattr(self, "ctx", None)
        return getattr(ctx, "workspace", None) if ctx is not None else None

    def opt(self, nombre: str, por_defecto: str = "") -> str:
        """Atajo para leer una opción como texto."""
        return self.opciones.get(nombre, por_defecto)

    def opt_bool(self, nombre: str, por_defecto: bool = False) -> bool:
        """Atajo para leer una opción como booleano."""
        return self.opciones.get_bool(nombre, por_defecto)

    def opt_int(self, nombre: str, por_defecto: int = 0) -> int:
        """Atajo para leer una opción como entero."""
        return self.opciones.get_int(nombre, por_defecto)

    @staticmethod
    def _objetivo_host(url_o_host: str) -> str:
        """Extrae el host de una URL o lo devuelve tal cual si ya es host."""
        valor = (url_o_host or "").strip()
        for prefijo in ("https://", "http://"):
            if valor.startswith(prefijo):
                valor = valor[len(prefijo):]
        return valor.split("/")[0].split(":")[0]


class ModuloError(Exception):
    """Error controlado de un módulo: se muestra limpio en la consola."""


class ModuloCancelado(Exception):
    """El operador canceló la ejecución del módulo (Ctrl+C)."""
