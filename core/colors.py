# -*- coding: utf-8 -*-
"""
core.colors
===========
Tema visual compartido de REDHAVOC sobre Rich.

Diseño "herramienta profesional moderna": cromo neutro (blancos/grises),
un único acento frío para elementos interactivos y el rojo reservado para
errores y severidades altas. Nada de degradados agresivos ni estética de
terminal "de película".

Define la consola única del framework, el estilo del prompt y pequeñas
funciones de ayuda para imprimir tablas y paneles de forma homogénea.
"""

import threading
import time
from contextlib import contextmanager

from rich.console import Console
from rich.markup import escape
from rich.spinner import SPINNERS
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Paleta del framework
# ---------------------------------------------------------------------------
ACENTO = "#6ea8fe"          # acento frío: módulos, comandos sugeridos, focos

TEMA = Theme({
    # Marca (neutra y limpia, sin rojo saturado)
    "marca":        "bold white",
    "marca2":       f"bold {ACENTO}",
    "modulo":       f"bold {ACENTO}",
    "accent":       f"bold {ACENTO}",

    # Estados (semántica clásica, moderada)
    "ok":           "bold green",
    "info":         "cyan",
    "aviso":        "bold yellow",
    "error":        "bold red",
    "debug":        "dim white",

    # Estructura de tablas
    "columna":      "bold white",
    "valor":        "white",
    "requerido":    "bold magenta",
    "opcion":       "bold cyan",
})

# Consola global del framework (única instancia compartida por todos los módulos)
console = Console(theme=TEMA)

# Spinner propio del framework: puntos clásicos a ritmo suave (discreto)
SPINNERS.setdefault("redhavoc", {"interval": 80,
                                 "frames": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"})

# Prompt estilo Metasploit moderno:  redhavoc >   /   redhavoc (modulo) >
PROMPT_RAIZ = "[bold white]redhavoc[/bold white] [dim]>[/dim] "


def prompt_modulo(nombre: str) -> str:
    """Devuelve el markup del prompt cuando hay un módulo cargado."""
    return (f"[bold white]redhavoc[/bold white] [dim]([/dim]"
            f"[bold {ACENTO}]{nombre}[/bold {ACENTO}][dim])[/dim] [dim]>[/dim] ")


def linea(color: str = "dim", char: str = "─", ancho: int = 64) -> None:
    """Imprime una línea separadora horizontal."""
    console.print(f"[{color}]{char * ancho}[/{color}]")


def titulo_seccion(texto: str) -> None:
    """Imprime un título de sección con línea superior e inferior."""
    linea()
    console.print(f" [bold white]{texto}[/bold white]")
    linea()


@contextmanager
def trabajo(nombre: str):
    """Contexto de ejecución: spinner animado con cronómetro en vivo.

    En TTY muestra 'nombre · 1.4s' con un spinner discreto; las impresiones
    que haga el módulo durante la ejecución se apilan ENCIMA del spinner
    (gracias al Live de Rich), así los resultados aparecen en la terminal
    en tiempo real. Hace yield del objeto Status (o None si no hay TTY)
    para poder actualizar el texto desde fuera.
    """
    inicio = time.time()
    if not console.is_terminal:
        yield None
        return
    with console.status(
        f"[bold white]{escape(nombre)}[/bold white] [dim]· 0.0s[/dim]",
        spinner="redhavoc", refresh_per_second=10,
    ) as estado:
        # Rich 14: Status crea internamente su Live con transient=True,
        # la línea del spinner desaparece sola al terminar.
        paro = threading.Event()

        def _reloj() -> None:
            """Actualiza el cronómetro del estado 10 veces por segundo."""
            while not paro.wait(0.1):
                estado.update(
                    f"[bold white]{escape(nombre)}[/bold white] "
                    f"[dim]· {time.time() - inicio:.1f}s[/dim]"
                )

        hilo = threading.Thread(target=_reloj, daemon=True)
        hilo.start()
        try:
            yield estado
        finally:
            paro.set()
