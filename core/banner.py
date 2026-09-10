# -*- coding: utf-8 -*-
"""
core.banner
===========
Banner ASCII y pantalla de despedida de REDHAVOC.

Estética profesional: el arte se pinta con un degradado flat muy sutil
entre dos tonos pizarra (sin rojos "de fuego") y la información de la
operación va en una línea limpia debajo.
"""

from rich.text import Text

from core import __version__, __nombre__, __eslogan__, __autor__

ARTE = r"""
██████╗  ███████╗██████╗  ██╗  ██╗  █████╗  ██╗   ██╗  ██████╗   ██████╗
██╔══██╗ ██╔════╝ ██╔══██╗ ██║  ██║ ██╔══██╗ ██║   ██║ ██╔═══██╗ ██╔════╝
██████╔╝ █████╗   ██║  ██║ ███████║███████║ ██║   ██║ ██║   ██║ ██║
██╔══██╗ ██╔══╝   ██║  ██║ ██╔══██║██╔══██║ ╚██╗ ██╔╝ ██║   ██║ ██║
██║  ██║ ███████╗██████╔╝ ██║  ██║ ██║  ██║  ╚████╔╝  ╚██████╔╝ ╚██████╔╝
╚═╝  ╚═╝ ╚══════╝ ╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝   ╚═══╝    ╚═════╝   ╚═════╝
"""

# Extremos del degradado: pizarra oscura → pizarra clara (flat, sobrio)
_INICIO_RGB = (100, 116, 139)     # #64748b
_FIN_RGB = (148, 163, 184)        # #94a3b8


def _gradiente_hex(pasos: int) -> list:
    """Devuelve `pasos` colores hex interpolados entre los extremos."""
    if pasos <= 1:
        return [f"#{_INICIO_RGB[0]:02x}{_INICIO_RGB[1]:02x}{_INICIO_RGB[2]:02x}"]
    colores = []
    for i in range(pasos):
        t = i / (pasos - 1)
        rgb = tuple(round(a + (b - a) * t) for a, b in zip(_INICIO_RGB, _FIN_RGB))
        colores.append(f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}")
    return colores


class Banner:
    """Renderizado del banner principal y de la despedida."""

    @staticmethod
    def mostrar(console, total_modulos: int) -> None:
        """Imprime el banner con degradado sutil, versión y módulos cargados."""
        lineas = ARTE.strip("\n").splitlines()
        arte = Text()
        for linea_txt, color in zip(lineas, _gradiente_hex(len(lineas))):
            arte.append(linea_txt + "\n", style=color)
        console.print(arte)

        console.print(
            f"  [bold white]{__eslogan__}[/bold white]   "
            f"[dim]|   v{__version__}   |   {total_modulos} módulos cargados[/dim]"
        )
        console.print(
            "  [dim]Uso exclusivo en entornos AUTORIZADOS · audita tus acciones · "
            "comandos: [white]help[/white], [white]search[/white], "
            "[white]use[/white], [white]consejos[/white][/dim]"
        )
        console.print()

    @staticmethod
    def despedida(console) -> None:
        """Mensaje de salida."""
        console.print("[dim][*] Sesión cerrada. Hasta la próxima incursión.[/dim]")
