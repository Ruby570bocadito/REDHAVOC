# -*- coding: utf-8 -*-
"""
Paquete brute — módulos de fuerza bruta de credenciales.

SOLO para auditar entornos propios o con autorización expresa del
propietario. Todos los módulos de esta categoría son de RIESGO ALTO y
el framework exige AUTHORIZED=true antes de ejecutarlos.

Las credenciales válidas descubiertas se registran automáticamente en
la base de datos del workspace (comando `creds`).
"""

from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent.parent


def usuarios_desde_listas(lista_usuarios: str, limite: int = 50) -> list:
    """Resuelve la lista de usuarios: wordlist incluida, ruta o lista CSV.

    Devuelve como máximo `limite` entradas para mantener el uso ético
    (auditoría de contraseñas débiles, no un ataque masivo).
    """
    candidatos = [Path(lista_usuarios), RAIZ / "templates" / "wordlists" / lista_usuarios]
    for ruta in candidatos:
        if ruta.is_file():
            entradas = [ln.strip() for ln in ruta.read_text(encoding="utf-8").splitlines()
                        if ln.strip() and not ln.startswith("#")]
            return entradas[:limite]
    # No hay fichero: se interpreta como lista separada por comas
    return [u.strip() for u in lista_usuarios.split(",") if u.strip()][:limite]


def claves_desde_listas(lista_claves: str, limite: int = 50) -> list:
    """Igual que usuarios_desde_listas pero para contraseñas."""
    return usuarios_desde_listas(lista_claves, limite)
