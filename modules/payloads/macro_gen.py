# -*- coding: utf-8 -*-
"""
Módulo payloads/macro_gen
=========================
Genera una PLANTILLA de macro VBA educativa (T1204.002 — User Execution:
Malicious File / T1566.001 Spearphishing Attachment) para entrenar:

    • Por qué las macros son un vector de entrada persistente.
    • Cómo se estructura una macro de prueba en un documento autorizado.
    • Cómo detectarla/micultarla (AMSI, políticas GPO, marca MTM).

La macro generada es inocua: SOLO escribe en un log local y lanza
`calc.exe` como demostración clásica de laboratorio. Los TODO marcan
dónde colocaría el payload TU prueba autorizada.

Riesgo: ALTO → exige AUTHORIZED.
"""

import shutil
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

SALIDA_RAIZ = Path(__file__).resolve().parent.parent.parent / "output" / "payloads"

MACRO_VBA = r"""' macro_lab.vba — Plantilla educativa de macro (REDHAVOC)
' Técnica: User Execution T1204.002 / Spearphishing Attachment T1566.001
' USO SOLO EN LABORATORIO O CON AUTORIZACIÓN ESCRITA.
Option Explicit

' ─── AutoOpen / DocumentOpen: gatillos habituales ──────────────────────
Sub AutoOpen()
    Demostracion
End Sub

Sub Document_Open()
    Demostracion
End Sub

' ─── Demostración inocua ────────────────────────────────────────────────
Private Sub Demostracion()
    ' 1) Evidencia de ejecución (log local del laboratorio)
    Dim rutaLog As String
    rutaLog = Environ("TEMP") & "\redhavoc_lab.log"
    Dim num As Integer
    num = FreeFile
    Open rutaLog For Append As #num
    Print #num, "Macro ejecutada: " & Now & " en " & Environ("COMPUTERNAME")
    Close #num

    ' 2) Demostración clásica: abrir la calculadora
    Shell "calc.exe", vbNormalFocus

    ' TODO(lab): sustituye la demo por el gesto de TU prueba autorizada,
    ' p. ej. descargar un agente del lab o disparar un beacon de simulación.
    ' TODO(lab): prueba ofuscación básica (Split/Chr) y observa AMSI.
End Sub
"""

README = """# Macro VBA educativa (REDHAVOC)

## Técnica
Las macros de Office siguen siendo un vector de entrada clave
(MITRE ATT&CK T1204.002, T1566.001). Esta plantilla muestra la estructura
mínima de una macro de laboratorio: gatillos `AutoOpen`/`Document_Open`,
evidencia de ejecución y payload de demostración inocuo (`calc.exe`).

## Cómo usarla en el lab
1. Abre Word → crea un documento → `Alt+F11` (editor VBA).
2. Pega `macro_lab.vba` en `ThisDocument`.
3. Guarda como **.docm** (habilitado para macros).
4. Al abrir el documento: escribe log en `%TEMP%\\redhavoc_lab.log` y abre calc.

## Defensas a evaluar (para el informe)
- Políticas GPO: deshabilitar macros de Internet (marca MOTW).
- AMSI: Office lo integra desde 2019 → las ofuscaciones básicas se detectan.
- Regla EDR: `winword.exe` hijo de `calc.exe`/`powershell.exe` → alarma.

## Aviso legal
Uso exclusivo en laboratorio o con autorización escrita. El uso no
autorizado es delito.
"""


class MacroGen(BaseModulo):
    """Genera la plantilla de macro VBA educativa + guía."""

    NAME = "payloads/macro_gen"
    CATEGORIA = "payloads"
    DESCRIPCION = ("Genera una plantilla VBA educativa (AutoOpen + demo inocua "
                   "calc.exe) con guía de laboratorio y controles defensivos. "
                   "Uso autorizado.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "MITRE ATT&CK T1204.002 · T1566.001"

    def definir_opciones(self) -> None:
        self.opciones.declarar("NOMBRE", "macro_lab", False, "Nombre base de los ficheros generados")

    def ejecutar(self) -> dict:
        nombre = self.opt("NOMBRE", "macro_lab").strip().replace(" ", "_") or "macro_lab"
        carpeta = SALIDA_RAIZ / f"macro_{nombre}"
        if carpeta.exists():
            shutil.rmtree(carpeta)
        carpeta.mkdir(parents=True)

        (carpeta / f"{nombre}.vba").write_text(MACRO_VBA, encoding="utf-8")
        (carpeta / "README.md").write_text(README, encoding="utf-8")

        ficheros = sorted(str(p) for p in carpeta.iterdir())
        return {
            "resumen": f"Plantilla de macro generada en {carpeta}",
            "carpeta": str(carpeta),
            "ficheros": ficheros,
            "tecnica": "MITRE ATT&CK T1204.002 · T1566.001",
        }
