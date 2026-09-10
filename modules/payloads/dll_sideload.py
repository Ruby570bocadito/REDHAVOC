# -*- coding: utf-8 -*-
"""
Módulo payloads/dll_sideload
============================
Genera un PROYECTO DE PLANTILLA de DLL proxy para demostrar y testear
técnica de DLL sideloading en entornos AUTORIZADOS (lab o pentest con
permiso escrito).

Qué genera (en output/payloads/dll_sideload_<nombre>/):
    main.cpp        → esqueleto DllMain + funciones exportadas proxy
    exports.def     → definición de exportaciones
    CMakeLists.txt  → build multiplataforma (MinGW/MSVC)
    README.md       → explicación de la técnica, cómo compilar y cómo
                      detectarla/mitigarla (bloqueo de carga, firma, etc.)

NO compila binarios ni incluye código malicioso real: es material de
formación sobre la técnica y sus defensas (MITRE ATT&CK T1574.002).

Riesgo: ALTO → exige AUTHORIZED.
"""

import shutil
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

SALIDA_RAIZ = Path(__file__).resolve().parent.parent.parent / "output" / "payloads"

PLANTILLA_MAIN = r"""// main.cpp — Plantilla educativa de DLL proxy (REDHAVOC)
// Técnica: DLL Sideloading / Proxy Execution (MITRE ATT&CK T1574.002)
// USO RESTRINGIDO A LABORATORIOS Y PENTESTS AUTORIZADOS.
#include <windows.h>

// ─── DllMain: punto de entrada ─────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // TODO(lab): registrar carga (OutputDebugString / Event Log)
            // TODO(lab): aquí demostrarías la acción de tu prueba autorizada
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// ─── Exportaciones proxy ────────────────────────────────────────────────
// Sustituye estas firmas por las de la DLL legítima del objetivo para
// practicar el encadenamiento (reenviar llamadas a la DLL real).
extern "C" __declspec(dllexport) void FuncionEjemplo(void) {
    // TODO(lab): forward a la DLL legítima via LoadLibrary + GetProcAddress
}

extern "C" __declspec(dllexport) int VersionEjemplo(void) {
    return 1; // TODO(lab)
}
"""

PLANTILLA_DEF = r"""; exports.def — Exportaciones de la DLL proxy (REDHAVOC)
LIBRARY "proxy_demo"
EXPORTS
    FuncionEjemplo
    VersionEjemplo
"""

PLANTILLA_CMAKE = r"""# CMakeLists.txt — DLL proxy demo (REDHAVOC)
cmake_minimum_required(VERSION 3.15)
project(proxy_demo CXX)

add_library(proxy_demo SHARED main.cpp)

# Aplica el fichero de definiciones de exportaciones
if (WIN32)
    target_sources(proxy_demo PRIVATE exports.def)
    set_target_properties(proxy_demo PROPERTIES OUTPUT_NAME "proxy_demo")
endif()
"""

PLANTILLA_README = """# DLL Sideloading — Plantilla educativa (REDHAVOC)

## Qué es la técnica
El *DLL sideloading* (MITRE ATT&CK [T1574.002](https://attack.mitre.org/techniques/T1574/002/))
explota el orden de búsqueda de DLLs de Windows: si una aplicación firmada
carga una DLL por nombre sin ruta absoluta ni firma válida, un atacante con
acceso de escritura en el directorio de la app puede colocar una DLL maliciosa
con el mismo nombre y la app la cargará ejecutando código en su contexto.

## Qué contiene este proyecto
| Fichero | Propósito |
|---|---|
| `main.cpp` | Esqueleto de `DllMain` + exportaciones proxy |
| `exports.def` | Definición de exportaciones que debe replicar |
| `CMakeLists.txt` | Build con MinGW o MSVC |

## Compilación (solo laboratorio)
```bash
# Con MinGW-w64:
x86_64-w64-mingw32-g++ -shared -o proxy_demo.dll main.cpp exports.def
# O con CMake + MSVC:
cmake -B build && cmake --build build --config Release
```

## Ejercicio de laboratorio sugerido
1. Crea una app de prueba que llame a `LoadLibrary("proxy_demo.dll")`.
2. Compila esta DLL y colócala junto a la app.
3. Observa el orden de búsqueda con **Process Monitor** (filtro: Path ends with .dll).
4. Añade las exportaciones reales de una DLL del sistema y practica el proxy.

## Detección y mitigación (para el informe del pentest)
- Firmar y verificar DLLs cargadas (WinVerifyTrust).
- Directorios de aplicación con ACLs estrictas (no escribible por usuarios).
- `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` en el código.
- Monitorizar creaciones de DLL no firmadas junto a binarios firmados (EDR).
- Regla YARA/Sigma: DLL no firmada en carpeta de binario firmado.

## Aviso legal
Uso exclusivo en laboratorio o con autorización escrita. El uso no
autorizado es delito.
"""


class DllSideload(BaseModulo):
    """Genera el proyecto de plantilla de DLL proxy para laboratorio."""

    NAME = "payloads/dll_sideload"
    CATEGORIA = "payloads"
    DESCRIPCION = ("Genera un proyecto C++ educativo de DLL proxy/sideloading "
                   "(T1574.002) con esqueleto de código, build y guía de "
                   "detección. Para laboratorios autorizados.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "MITRE ATT&CK T1574.002"

    def definir_opciones(self) -> None:
        self.opciones.declarar("NOMBRE", "proxy_demo", True, "Nombre del proyecto generado")

    def ejecutar(self) -> dict:
        nombre = self.opt("NOMBRE").strip().replace(" ", "_") or "proxy_demo"
        carpeta = SALIDA_RAIZ / f"dll_sideload_{nombre}"
        if carpeta.exists():
            shutil.rmtree(carpeta)
        carpeta.mkdir(parents=True)

        (carpeta / "main.cpp").write_text(PLANTILLA_MAIN, encoding="utf-8")
        (carpeta / "exports.def").write_text(PLANTILLA_DEF, encoding="utf-8")
        (carpeta / "CMakeLists.txt").write_text(PLANTILLA_CMAKE, encoding="utf-8")
        (carpeta / "README.md").write_text(PLANTILLA_README, encoding="utf-8")

        ficheros = sorted(str(p) for p in carpeta.iterdir())
        resumen = f"Proyecto DLL proxy generado en {carpeta} ({len(ficheros)} ficheros)"
        return {
            "resumen": resumen,
            "carpeta": str(carpeta),
            "ficheros": ficheros,
            "tecnica": "MITRE ATT&CK T1574.002 — DLL Side-Loading",
        }
