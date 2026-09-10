#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REDHAVOC — Red Team Havoc Framework
====================================
Punto de entrada del framework.

Uso:
    python3 redhavoc.py                # inicia la consola interactiva
    python3 redhavoc.py --version      # muestra la versión
    python3 redhavoc.py --no-banner    # inicia sin mostrar el banner

REDHAVOC es una herramienta de ciberseguridad ofensiva diseñada EXCLUSIVAMENTE
para pruebas de penetración autorizadas, laboratorios propios y formación en
seguridad. El uso no autorizado es ilegal. Ver DISCLAIMER.md.

Autor   : Proyecto REDHAVOC
Licencia: MIT (ver LICENSE)
"""

import sys
import signal
from pathlib import Path

from rich.markup import escape

# Añade la raíz del proyecto al path para importar el paquete core
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from core.banner import Banner
from core.colors import console
from core.ethics import EthicsGate
from core.framework import RedHavocFramework
from core import __version__


def _preparar_signals() -> None:
    """Configura el manejo de señales para una salida limpia (Ctrl+C)."""
    def _handler(sig, frame):
        console.print("\n[yellow][!][/yellow] Interrupción recibida (Ctrl+C). Escribe [bold]exit[/bold] para salir.")
        # Eleva KeyboardInterrupt de forma controlada; el REPL lo captura.
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _handler)


def main() -> int:
    """Punto de entrada principal del framework."""
    args = [a for a in sys.argv[1:] if a.startswith("--")]

    if "--version" in args:
        print(f"REDHAVOC v{__version__}")
        return 0

    _preparar_signals()

    try:
        framework = RedHavocFramework(raiz=ROOT_DIR)
    except Exception as err:  # noqa: BLE001
        console.print(f"[bold red][FATAL][/bold red] No se pudo inicializar el framework: "
                      f"{escape(str(err))}")
        return 1

    # --- Puerta ética: bloquea el arranque sin aceptación del disclaimer ---
    if not EthicsGate.verificar_arranque(console):
        console.print("[red]Sesión no autorizada. Saliendo.[/red]")
        return 2

    # --- Arranque del REPL ---
    if "--no-banner" not in args:
        from core.boot import Boot
        Boot.animar(console, framework.module_manager)
        Banner.mostrar(console, framework.module_manager.total_modulos())

    framework.repl()
    Banner.despedida(console)
    return 0


if __name__ == "__main__":
    sys.exit(main())
