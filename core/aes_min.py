# -*- coding: utf-8 -*-
"""
core.aes_min
============
Implementación PURA de AES (Rijndael, FIPS-197) para REDHAVOC: cifrado y
descifrado en modo ECB y CBC para claves de 128/192/256 bits.

¿Por qué a mano? El framework se orgullecen de funcionar sin dependencias
criptográficas externas (igual que krb5.py implementa MD4/RC4 y smb_min
implementa NTLMv2). AES puro permite, por ejemplo, descifrar los
`cpassword` de Group Policy Preferences (MS-GPPREF) en un módulo sin
instalar nada.

Es una implementación EDUCATIVA y no hardened: sin protección de canal
lateral, sin constant-time. Para criptografía de producción usa `cryptography`.
"""

from typing import List

# ---------------------------------------------------------------------------
# Tablas generadas por código (sin tablas fijas gigantes en el fuente)
# ---------------------------------------------------------------------------

def _build() -> tuple:
    """Genera SBOX, INV_SBOX, RCON y las tablas de Galois (GF(2^8))."""
    # S-box estándar FIPS-197 generada vía inverso multiplicativo + afín
    log = [0] * 256
    alog = [0] * 256
    x = 1
    for i in range(255):
        alog[i] = x
        log[x] = i
        # x = x * 3 en GF(2^8) (multiplicar por el generador 0x03)
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
        x &= 0xFF

    def _inv(a: int) -> int:
        return 0 if a == 0 else alog[(255 - log[a]) % 255]

    sbox = [0] * 256
    for i in range(256):
        b = _inv(i)
        # transformación afín: b ^= rot(b,1) ^ rot(b,2) ^ rot(b,3) ^ rot(b,4) ^ 0x63
        r = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            r ^= b
        sbox[i] = r ^ 0x63

    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i

    rcon = [0x01]
    for _ in range(13):
        rcon.append((rcon[-1] << 1) ^ (0x11B if rcon[-1] & 0x80 else 0))
        rcon[-1] &= 0xFF

    return sbox, inv_sbox, rcon


SBOX, INV_SBOX, RCON = _build()


def _xt(a: int) -> int:
    """Multiplica por 2 en GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiplicación en GF(2^8) (algoritmo ruso de campesinos)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


# ---------------------------------------------------------------------------
# Estado: bloque de 16 bytes como 4 palabras de columna (orden FIPS-197)
# ---------------------------------------------------------------------------

def _bytes_a_estado(bloque: bytes) -> List[List[int]]:
    """16 bytes → matriz 4x4 por COLUMNAS (como define FIPS-197)."""
    return [[bloque[f + 4 * c] for c in range(4)] for f in range(4)]


def _estado_a_bytes(estado: List[List[int]]) -> bytes:
    return bytes(estado[f][c] for c in range(4) for f in range(4))


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------

def _expandir_clave(clave: bytes) -> List[List[List[int]]]:
    """Key schedule: devuelve lista de round keys (matrices 4x4 por columnas)."""
    nk = len(clave) // 4            # 4 | 6 | 8
    rounds = nk + 6                 # 10 | 12 | 14
    palabras: List[List[int]] = [list(clave[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        t = list(palabras[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [SBOX[b] for b in t]                # SubWord
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        palabras.append([palabras[i - nk][j] ^ t[j] for j in range(4)])
    # agrupar de 4 en 4 palabras → round keys
    return [ [ [palabras[rk * 4 + c][f] for c in range(4)] for f in range(4) ]
             for rk in range(rounds + 1) ]


# ---------------------------------------------------------------------------
# Transformaciones
# ---------------------------------------------------------------------------

def _add_round_key(e: List[List[int]], k: List[List[int]]) -> None:
    for c in range(4):
        for f in range(4):
            e[f][c] ^= k[f][c]


def _sub_bytes(e: List[List[int]], caja) -> None:
    for fila in e:
        for c in range(4):
            fila[c] = caja[fila[c]]


def _shift_rows(e: List[List[int]]) -> None:
    for f in range(1, 4):
        e[f] = e[f][f:] + e[f][:f]


def _inv_shift_rows(e: List[List[int]]) -> None:
    for f in range(1, 4):
        e[f] = e[f][-f:] + e[f][:-f]


def _mix_columns(e: List[List[int]]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = (e[f][c] for f in range(4))
        e[0][c] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        e[1][c] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        e[2][c] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        e[3][c] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def _inv_mix_columns(e: List[List[int]]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = (e[f][c] for f in range(4))
        e[0][c] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        e[1][c] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        e[2][c] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        e[3][c] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)


# ---------------------------------------------------------------------------
# API pública: cifrar/descifrar bloques y modos ECB/CBC
# ---------------------------------------------------------------------------

def cifrar_bloque(bloque: bytes, clave: bytes) -> bytes:
    """Cifra UN bloque de 16 bytes en modo ECB (FIPS-197)."""
    if len(bloque) != 16 or len(clave) not in (16, 24, 32):
        raise ValueError("bloque de 16 bytes y clave de 16/24/32 bytes")
    rounds = len(clave) // 4 + 6
    claves = _expandir_clave(clave)
    e = _bytes_a_estado(bloque)
    _add_round_key(e, claves[0])
    for r in range(1, rounds):
        _sub_bytes(e, SBOX)
        _shift_rows(e)
        _mix_columns(e)
        _add_round_key(e, claves[r])
    _sub_bytes(e, SBOX)
    _shift_rows(e)
    _add_round_key(e, claves[rounds])
    return _estado_a_bytes(e)


def descifrar_bloque(bloque: bytes, clave: bytes) -> bytes:
    """Descifra UN bloque de 16 bytes en modo ECB (FIPS-197)."""
    if len(bloque) != 16 or len(clave) not in (16, 24, 32):
        raise ValueError("bloque de 16 bytes y clave de 16/24/32 bytes")
    rounds = len(clave) // 4 + 6
    claves = _expandir_clave(clave)
    e = _bytes_a_estado(bloque)
    _add_round_key(e, claves[rounds])
    for r in range(rounds - 1, 0, -1):
        _inv_shift_rows(e)
        _sub_bytes(e, INV_SBOX)
        _add_round_key(e, claves[r])
        _inv_mix_columns(e)
    _inv_shift_rows(e)
    _sub_bytes(e, INV_SBOX)
    _add_round_key(e, claves[0])
    return _estado_a_bytes(e)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cifrar_cbc(datos: bytes, clave: bytes, iv: bytes) -> bytes:
    """Cifrado CBC con relleno PKCS#7 (datos de cualquier longitud)."""
    if len(iv) != 16:
        raise ValueError("IV de 16 bytes")
    relleno = 16 - (len(datos) % 16)
    datos = datos + bytes([relleno]) * relleno
    anterior = iv
    salida = bytearray()
    for i in range(0, len(datos), 16):
        anterior = cifrar_bloque(_xor(datos[i:i + 16], anterior), clave)
        salida += anterior
    return bytes(salida)


def descifrar_cbc(datos: bytes, clave: bytes, iv: bytes) -> bytes:
    """Descifrado CBC con validación de relleno PKCS#7."""
    if len(iv) != 16:
        raise ValueError("IV de 16 bytes")
    if not datos or len(datos) % 16:
        raise ValueError("datos CBC deben ser múltiplo de 16 bytes")
    anterior = iv
    salida = bytearray()
    for i in range(0, len(datos), 16):
        bloque = datos[i:i + 16]
        salida += _xor(descifrar_bloque(bloque, clave), anterior)
        anterior = bloque
    relleno = salida[-1]
    if not 1 <= relleno <= 16 or salida[-relleno:] != bytes([relleno]) * relleno:
        raise ValueError("relleno PKCS#7 inválido")
    return bytes(salida[:-relleno])
