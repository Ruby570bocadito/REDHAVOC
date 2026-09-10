# -*- coding: utf-8 -*-
"""
core.option_store
=================
Sistema de opciones estilo Metasploit.

Cada módulo declara sus opciones (nombre, valor por defecto, obligatoriedad,
descripción) y el operador las modifica con `set` / `unset`. El framework
valida las obligatorias antes de ejecutar.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional

# Valores que se consideran "verdadero" en opciones booleanas
_VERDADEROS = {"true", "1", "yes", "si", "sí", "on"}


@dataclass
class Opcion:
    """Una opción configurable de un módulo."""
    nombre: str
    valor: str = ""
    requerido: bool = False
    descripcion: str = ""
    por_defecto: str = ""

    def como_bool(self) -> bool:
        """Interpreta el valor como booleano (true/1/si/on...)."""
        return self.valor.strip().lower() in _VERDADEROS

    def como_int(self, por_defecto: int = 0) -> int:
        """Interpreta el valor como entero, con valor de respaldo."""
        try:
            return int(self.valor)
        except (TypeError, ValueError):
            return por_defecto


class OptionStore:
    """Contenedor de opciones de un módulo o del framework global."""

    def __init__(self) -> None:
        self._opciones: Dict[str, Opcion] = {}

    # ------------------------------------------------------------------
    # Declaración
    # ------------------------------------------------------------------
    def declarar(self, nombre: str, valor: str = "", requerido: bool = False,
                 descripcion: str = "") -> Opcion:
        """Declara (o redeclara conservando valor) una opción."""
        nombre = nombre.upper()
        if nombre in self._opciones:                      # conserva el valor fijado por el operador
            self._opciones[nombre].descripcion = descripcion
            self._opciones[nombre].requerido = requerido
            return self._opciones[nombre]
        opcion = Opcion(nombre=nombre, valor=valor, requerido=requerido,
                        descripcion=descripcion, por_defecto=valor)
        self._opciones[nombre] = opcion
        return opcion

    # ------------------------------------------------------------------
    # Acceso
    # ------------------------------------------------------------------
    def set(self, nombre: str, valor: str) -> bool:
        """Fija el valor de una opción. False si la opción no existe."""
        nombre = nombre.upper()
        if nombre not in self._opciones:
            return False
        self._opciones[nombre].valor = valor
        return True

    def unset(self, nombre: str) -> bool:
        """Restaura el valor por defecto de una opción."""
        nombre = nombre.upper()
        if nombre not in self._opciones:
            return False
        self._opciones[nombre].valor = self._opciones[nombre].por_defecto
        return True

    def get(self, nombre: str, por_defecto: str = "") -> str:
        """Devuelve el valor de una opción (o por_defecto si no existe)."""
        opcion = self._opciones.get(nombre.upper())
        return opcion.valor if opcion else por_defecto

    def get_bool(self, nombre: str, por_defecto: bool = False) -> bool:
        """Devuelve el valor interpretado como booleano."""
        opcion = self._opciones.get(nombre.upper())
        if opcion is None or opcion.valor == "":
            return por_defecto
        return opcion.como_bool()

    def get_int(self, nombre: str, por_defecto: int = 0) -> int:
        """Devuelve el valor interpretado como entero."""
        opcion = self._opciones.get(nombre.upper())
        if opcion is None or opcion.valor == "":
            return por_defecto
        return opcion.como_int(por_defecto)

    def opcion(self, nombre: str) -> Optional[Opcion]:
        """Devuelve el objeto Opcion o None."""
        return self._opciones.get(nombre.upper())

    def __contains__(self, nombre: str) -> bool:
        return nombre.upper() in self._opciones

    def __iter__(self) -> Iterator[Opcion]:
        return iter(self._opciones.values())

    def __len__(self) -> int:
        return len(self._opciones)

    # ------------------------------------------------------------------
    # Validación
    # ------------------------------------------------------------------
    def faltantes(self, excluir: tuple = ()) -> list:
        """Lista de nombres de opciones requeridas sin valor.

        `excluir` permite ignorar opciones concretas: el framework la usa
        para no exigir RHOST/TARGET cuando RHOSTS ya define los objetivos.
        """
        excluir = {n.upper() for n in excluir}
        return [o.nombre for o in self._opciones.values()
                if o.requerido and o.nombre not in excluir and not o.valor.strip()]

    def validar_o_error(self, excluir: tuple = ()) -> Optional[str]:
        """Devuelve un mensaje de error si faltan opciones requeridas."""
        faltan = self.faltantes(excluir)
        if not faltan:
            return None
        return "Faltan opciones obligatorias: " + ", ".join(faltan)
