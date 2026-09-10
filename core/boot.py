# -*- coding: utf-8 -*-
"""
core.boot
=========
Animación de arranque de la consola REDHAVOC.

Una barra de progreso discreta recorre las categorías del arsenal mientras
el framework "se arma". Animación SUTIL: corta, colores neutros con el
acento frío del tema, y al terminar la barra se desvanece (transient)
quedando una única línea de estado limpia.

En consolas no interactivas (tests, tuberías) se degrada a una única
línea de confirmación para no ensuciar la salida.
"""

import time

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from core.colors import ACENTO


class Boot:
    """Animación de carga del arsenal."""

    @staticmethod
    def animar(console, manager, segundos: float = 0.8) -> None:
        """Recorre las categorías del gestor con una barra de progreso.

        Args:
            console: consola Rich compartida del framework.
            manager: ModuleManager ya cargado (necesita .categorias()).
            segundos: duración aproximada de la animación en TTY.
        """
        if not console.is_terminal:
            console.print(f"[ok][✓][/ok] {manager.total_modulos()} módulos cargados.")
            return

        categorias = manager.categorias()
        orden = sorted(categorias)
        if not orden:
            return

        with Progress(
            SpinnerColumn(spinner_name="redhavoc", style="bold white"),
            TextColumn("[progress.description][bold white]{task.description}[/bold white]"),
            BarColumn(bar_width=24, style="dim", complete_style=ACENTO,
                      finished_style="bold green"),
            TextColumn("[dim]{task.fields[detalle]}[/dim]"),
            console=console,
            transient=True,
        ) as barra:
            tarea = barra.add_task("Cargando el arsenal...", total=len(orden), detalle="")
            pausa = max(segundos / len(orden), 0.02)
            for categoria in orden:
                barra.update(
                    tarea,
                    description=f"[bold white]{categoria}[/bold white]",
                    detalle=f"{len(categorias[categoria])} módulos",
                    advance=1,
                )
                time.sleep(pausa)

        console.print(
            f"[ok][✓][/ok] Arsenal listo: [bold]{manager.total_modulos()}[/bold] módulos "
            f"en [bold]{len(orden)}[/bold] categorías · escribe [bold]help[/bold] para empezar."
        )
