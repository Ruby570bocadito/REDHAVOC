# -*- coding: utf-8 -*-
"""
core.module_manager
===================
Descubrimiento, carga y búsqueda de módulos.

Escanea recursivamente el paquete `modules/`, importa los ficheros Python
y registra las clases que heredan de BaseModulo. Soporta:

    manager.total_modulos()
    manager.buscar("recon")          → lista de clases
    manager.obtener("recon/ip_info") → clase del módulo
    manager.nombres()                → todas las rutas de módulos
    manager.arbol()                  → dict {categoria: [nombres]}
"""

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Type

from rich.markup import escape

from core.base_module import BaseModulo


class ModuloNoEncontrado(Exception):
    """Se pidió un módulo que no existe en el registro."""


class ModuleManager:
    """Registro central de módulos del framework."""

    def __init__(self, paquete: str = "modules"):
        self.paquete = paquete
        self._registro: Dict[str, Type[BaseModulo]] = {}
        self._cargar_todo()

    # ------------------------------------------------------------------
    # Carga
    # ------------------------------------------------------------------
    def _cargar_todo(self) -> None:
        """Importa todos los submódulos del paquete y registra sus clases."""
        paquete = importlib.import_module(self.paquete)
        for info in pkgutil.walk_packages(paquete.__path__, prefix=f"{self.paquete}."):
            try:
                modulo = importlib.import_module(info.name)
            except Exception as err:  # noqa: BLE001
                # Un módulo roto no debe tumbar el framework; se avisa en el arranque.
                from core.colors import console
                console.print(f"[aviso][!][/aviso] Módulo no cargable [dim]{info.name}[/dim]: "
                              f"{escape(str(err))}")
                continue
            for atributo in vars(modulo).values():
                if (isinstance(atributo, type)
                        and issubclass(atributo, BaseModulo)
                        and atributo is not BaseModulo
                        and getattr(atributo, "NAME", "")):
                    self._registro[atributo.NAME] = atributo

    # ------------------------------------------------------------------
    # Consulta
    # ------------------------------------------------------------------
    def obtener(self, nombre: str) -> Type[BaseModulo]:
        """Devuelve la clase del módulo por su ruta completa (categoria/nombre)."""
        nombre = (nombre or "").strip().strip("/")
        if not nombre:
            raise ModuloNoEncontrado("Nombre de módulo vacío")
        if nombre in self._registro:
            return self._registro[nombre]
        # Tolerancia: si el operador no escribió la categoría, busca por sufijo único.
        coincidencias = [c for r, c in self._registro.items() if r.endswith("/" + nombre)]
        if len(coincidencias) == 1:
            return coincidencias[0]
        raise ModuloNoEncontrado(f"Módulo '{nombre}' no encontrado. Escribe search para "
                                 "ver el arsenal.")

    def buscar(self, termino: str) -> List[Type[BaseModulo]]:
        """Busca módulos cuyo NAME o DESCRIPCION contenga el término."""
        termino = (termino or "").strip().lower()
        if not termino:
            return self.listar()
        return sorted(
            (cls for ruta, cls in self._registro.items()
             if termino in ruta.lower() or termino in cls.DESCRIPCION.lower()),
            key=lambda c: c.NAME,
        )

    def listar(self) -> List[Type[BaseModulo]]:
        """Todos los módulos ordenados por ruta."""
        return sorted(self._registro.values(), key=lambda c: c.NAME)

    def nombres(self) -> List[str]:
        """Rutas completas de todos los módulos registrados."""
        return sorted(self._registro.keys())

    def categorias(self) -> Dict[str, List[str]]:
        """Diccionario {categoria: [nombres de módulos]} para show modules."""
        arbol: Dict[str, List[str]] = {}
        for ruta in self.nombres():
            categoria, nombre = ruta.split("/", 1)
            arbol.setdefault(categoria, []).append(ruta)
        return arbol

    def total_modulos(self) -> int:
        """Número total de módulos registrados."""
        return len(self._registro)
