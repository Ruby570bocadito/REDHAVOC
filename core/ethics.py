# -*- coding: utf-8 -*-
"""
core.ethics
===========
Puerta ética de REDHAVOC.

REDHAVOC es una herramienta dual-use pensada para pentesting autorizado,
laboratorios y formación. Este módulo garantiza que:

  1. En el primer arranque el operador LEA y ACEPTE el disclaimer (se guarda
     el consentimiento en workspace/aceptacion.json).
  2. Los módulos de riesgo alto exijan la autorización explícita mediante
     la variable de entorno REDHAVOC_AUTHORIZED=1 o la opción global
     AUTHORIZED=true dentro de la sesión.
  3. Toda ejecución de módulo quede registrada en workspace/audit.log
     (trazabilidad de operador).

Nada de esto sustituye a la ley: usar REDHAVOC contra sistemas sin permiso
escrito del propietario es ilegal en la mayoría de jurisdicciones.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

TEXTO_DISCLAIMER = (
    "[bold red]AVISO LEGAL Y ÉTICO[/bold red]\n\n"
    "REDHAVOC es un framework de ciberseguridad ofensiva destinado ÚNICAMENTE a:\n"
    "  [green]•[/green] Pruebas de penetración con AUTORIZACIÓN EXPRESA y POR ESCRITO del propietario del sistema.\n"
    "  [green]•[/green] Laboratorios propios, entornos aislados y máquinas virtuales de práctica.\n"
    "  [green]•[/green] Formación, investigación y divulgación de seguridad.\n\n"
    "El uso contra sistemas de terceros sin autorización es [bold red]ILEGAL[/bold red]\n"
    "(p. ej. arts. 197 y ss. del Código Penal español; CFAA en EE. UU.; equivalentes locales).\n\n"
    "Los autores de este proyecto no se hacen responsables del mal uso de la herramienta.\n"
    "Tus ejecuciones quedan registradas en [dim]workspace/audit.log[/dim] con fines de trazabilidad."
)


class EthicsGate:
    """Control de aceptación del disclaimer y de autorización operacional."""

    def __init__(self, carpeta_workspace: Path):
        self.carpeta_workspace = Path(carpeta_workspace)
        self.carpeta_workspace.mkdir(parents=True, exist_ok=True)
        self.fichero_aceptacion = self.carpeta_workspace / "aceptacion.json"
        self.fichero_auditoria = self.carpeta_workspace / "audit.log"

    # ------------------------------------------------------------------
    # Aceptación del disclaimer (persistente)
    # ------------------------------------------------------------------
    def ya_aceptado(self) -> bool:
        """True si existe registro previo de aceptación del disclaimer."""
        if not self.fichero_aceptacion.exists():
            return False
        try:
            datos = json.loads(self.fichero_aceptacion.read_text(encoding="utf-8"))
            return bool(datos.get("aceptado", False))
        except (json.JSONDecodeError, OSError):
            return False

    def registrar_aceptacion(self, operador: str = "anon") -> None:
        """Guarda el consentimiento con marca temporal."""
        datos = {
            "aceptado": True,
            "operador": operador,
            "fecha": time.strftime("%Y-%m-%d %H:%M:%S"),
            "version_disclaimer": "1.0",
        }
        self.fichero_aceptacion.write_text(
            json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @staticmethod
    def verificar_arranque(console) -> bool:
        """Flujo de aceptación al arrancar la consola. False ⇒ no se arranca."""
        gate = EthicsGate(Path(__file__).resolve().parent.parent / "workspace")
        if gate.ya_aceptado():
            # Comprueba la autorización operacional en cada arranque.
            return gate.autorizado() or True  # la autorización se pide al ejecutar módulos de riesgo alto
        return gate.solicitar_aceptacion(console)

    def solicitar_aceptacion(self, console) -> bool:
        """Muestra el disclaimer y exige escribir ACEPTO (mayúsculas)."""
        from rich.panel import Panel

        console.print(Panel(TEXTO_DISCLAIMER, border_style="red", title="[bold red]REDHAVOC[/bold red]"))
        try:
            respuesta = console.input("[bold yellow]Escribe [red]ACEPTO[/red] para continuar (o nada para salir): [/bold yellow]")
        except (EOFError, KeyboardInterrupt):
            return False
        if respuesta.strip() == "ACEPTO":
            self.registrar_aceptacion()
            console.print("[ok][✓][/ok] Aceptación registrada. Recuerda: [bold]solo con autorización[/bold].")
            return True
        return False

    # ------------------------------------------------------------------
    # Autorización operacional (por entorno o por sesión)
    # ------------------------------------------------------------------
    @staticmethod
    def autorizado() -> bool:
        """True si REDHAVOC_AUTHORIZED=1 está presente en el entorno."""
        return os.environ.get("REDHAVOC_AUTHORIZED", "").strip() in ("1", "true", "TRUE", "yes", "si")

    # ------------------------------------------------------------------
    # Auditoría
    # ------------------------------------------------------------------
    def auditar(self, evento: str, detalle: str = "") -> None:
        """Añade una línea al log de auditoría (workspace/audit.log)."""
        marca = time.strftime("%Y-%m-%d %H:%M:%S")
        linea = f"[{marca}] {evento}" + (f" | {detalle}" if detalle else "")
        try:
            with open(self.fichero_auditoria, "a", encoding="utf-8") as fh:
                fh.write(linea + "\n")
        except OSError:
            pass  # la auditoría nunca debe romper la ejecución
