# -*- coding: utf-8 -*-
"""
core.targets
============
Expansión de objetivos multi-host (estilo NetExec) para la opción RHOSTS.

Formatos aceptados (combinables con comas):

    10.0.0.5                 host único (IP o nombre DNS)
    10.0.0.0/24              red CIDR (todas las IPs útiles)
    10.0.0.1-20              rango del último octeto
    10.0.0.1-10.0.0.5        rango completo (mismo /24)
    dc01.corp.local          nombre DNS (se deja tal cual)
    @objetivos.txt           fichero con un objetivo por línea (# comentarios)

Devuelve una lista sin duplicados (conservando el orden) y acotada a
MAX_OBJETIVOS para evitar expansiones accidentales gigantes.
"""

import ipaddress
from pathlib import Path
from typing import List

# Tope duro de objetivos por ejecución (protección ante /8 escritos por error)
MAX_OBJETIVOS = 1024


class ObjetivoError(ValueError):
    """Expresión de objetivos inválida: se muestra limpia en la consola."""


def _es_red(texto: str) -> bool:
    try:
        ipaddress.ip_network(texto, strict=False)
        return True
    except ValueError:
        return False


def _expandir_rango(trozo: str) -> List[str]:
    """Expande 10.0.0.1-20 o 10.0.0.1-10.0.0.5 (mismo prefijo /24).

    Lanza ObjetivoError si el rango está invertido o fuera de rango.
    Si no tiene forma de rango, devuelve [] para que el llamador lo trate
    como host único.
    """
    base, _, fin = trozo.partition("-")
    if not fin or "." not in base:
        return []
    prefijo, _, ultimo_txt = base.rpartition(".")
    if not prefijo or not ultimo_txt.isdigit():
        return []

    # Caso 1: 10.0.0.1-20 (fin = último octeto)
    if fin.isdigit():
        ini, fin_n = int(ultimo_txt), int(fin)
    # Caso 2: 10.0.0.1-10.0.0.5 (fin = IP del mismo prefijo)
    elif fin.count(".") == 3 and fin.rpartition(".")[0] == prefijo \
            and fin.rpartition(".")[2].isdigit():
        ini, fin_n = int(ultimo_txt), int(fin.rpartition(".")[2])
    else:
        return []

    if ini > fin_n or fin_n > 255:
        raise ObjetivoError(
            f"Rango inválido: {trozo} (usa 10.0.0.1-20 o 10.0.0.1-10.0.0.20)")
    return [f"{prefijo}.{n}" for n in range(ini, fin_n + 1)]


def _leer_fichero(texto: str) -> str:
    """Reemplaza '@fichero' por su contenido (un objetivo por línea)."""
    ruta = Path(texto[1:]).expanduser()
    if not ruta.is_file():
        raise ObjetivoError(f"El fichero de objetivos no existe: {ruta}")
    try:
        lineas = ruta.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise ObjetivoError(f"No se pudo leer {ruta}: {err}") from err
    limpias = [l.strip() for l in lineas if l.strip() and not l.strip().startswith("#")]
    if not limpias:
        raise ObjetivoError(f"El fichero de objetivos está vacío: {ruta}")
    return ",".join(limpias)


def expandir_objetivos(texto: str) -> List[str]:
    """Convierte la expresión RHOSTS en la lista concreta de objetivos.

    Nunca devuelve IPs duplicadas y respeta el orden de aparición.
    Lanza ObjetivoError con un mensaje accionable ante entrada inválida.
    """
    texto = (texto or "").strip()
    if not texto:
        return []
    if texto.startswith("@"):
        texto = _leer_fichero(texto)

    objetivos: List[str] = []
    for trozo in texto.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if "/" in trozo and _es_red(trozo):
            red = ipaddress.ip_network(trozo, strict=False)
            # Tope ANTES de materializar (un /8 tendría 16M de direcciones)
            if red.num_addresses > MAX_OBJETIVOS:
                raise ObjetivoError(
                    f"{trozo} expandiría {red.num_addresses} direcciones: el tope "
                    f"es {MAX_OBJETIVOS}. Parte la ejecución en bloques.")
            objetivos.extend(str(h) for h in red.hosts())
            continue
        expandido = _expandir_rango(trozo)
        if expandido:
            objetivos.extend(expandido)
            continue
        if "-" in trozo and not trozo.startswith("@"):
            # Parecía un rango pero no es válido (p. ej. 10.0.0.1-mal)
            raise ObjetivoError(
                f"Objetivo no reconocido: {trozo} (formatos: IP, CIDR, "
                "rango 10.0.0.1-20, @fichero)")
        objetivos.append(trozo)

    unicos = list(dict.fromkeys(objetivos))
    if len(unicos) > MAX_OBJETIVOS:
        raise ObjetivoError(
            f"Demasiados objetivos ({len(unicos)}): el tope es {MAX_OBJETIVOS}. "
            "Parte la ejecución en bloques.")
    return unicos
