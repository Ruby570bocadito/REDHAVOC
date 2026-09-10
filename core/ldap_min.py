# -*- coding: utf-8 -*-
"""
core.ldap_min
=============
Cliente LDAP mínimo (RFC 4511) sobre TCP, escrito a mano y sin dependencias.
Soporta justo lo que necesitan los módulos ad/ldap_enum y ad/spn_enum:

    • bind simple (anónimo o con usuario/clave)
    • search request con filtros =, *, & | ! (mini-parser de filtros)
    • lectura de SearchResultEntry y SearchResultDone

No implementa STARTTLS, paging ni controles extendidos.
"""

import socket
from typing import Dict, List, Optional, Tuple

# Códigos de resultado LDAP más habituales
CODIGOS = {
    0: "éxito",
    1: "error de operación",
    10: "referencia",
    11: "límite administrativo superado",
    14: "SASL en curso",
    32: "objeto no existe (base DN incorrecto)",
    49: "credenciales inválidas",
    50: "permisos insuficientes",
    53: "servicio no disponible (anónimo deshabilitado?)",
    64: "convención de nombres violada",
}


# ===========================================================================
# BER básico
# ===========================================================================
def _longitud(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    cuerpo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(cuerpo)]) + cuerpo


def tlv(etiqueta: int, cuerpo: bytes) -> bytes:
    return bytes([etiqueta]) + _longitud(len(cuerpo)) + cuerpo


def ber_entero(valor: int) -> bytes:
    if valor == 0:
        return tlv(0x02, b"\x00")
    return tlv(0x02, valor.to_bytes((valor.bit_length() + 8) // 8, "big"))


def ber_enumerado(valor: int) -> bytes:
    return tlv(0x0A, valor.to_bytes(max((valor.bit_length() + 7) // 8, 1), "big", signed=True))


def ber_octetos(datos: bytes) -> bytes:
    return tlv(0x04, datos)


def ber_bool(valor: bool) -> bytes:
    return tlv(0x01, b"\xff" if valor else b"\x00")


def ber_secuencia(*partes: bytes) -> bytes:
    return tlv(0x30, b"".join(partes))


def leer_tlv(datos: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    etiqueta = datos[offset]
    offset += 1
    largo = datos[offset]
    offset += 1
    if largo & 0x80:
        n = largo & 0x7F
        largo = int.from_bytes(datos[offset:offset + n], "big")
        offset += n
    return etiqueta, datos[offset:offset + largo], offset + largo


def hijos(cuerpo: bytes) -> List[Tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(cuerpo):
        etiqueta, contenido, pos = leer_tlv(cuerpo, pos)
        out.append((etiqueta, contenido))
    return out


# ===========================================================================
# Mini-parser de filtros LDAP: (a=b), (a=*), (&…), (|…), (!…)
# ===========================================================================
def codificar_filtro(texto: str) -> bytes:
    """Codifica un filtro LDAP textual a su forma BER."""
    texto = texto.strip()
    cuerpo, pos = _filtro(texto, 0)
    if pos < len(texto):
        raise ValueError(f"Filtro LDAP: caracteres sobrantes desde la posición {pos}")
    return cuerpo


def _filtro(texto: str, pos: int) -> Tuple[bytes, int]:
    if pos >= len(texto) or texto[pos] != "(":
        raise ValueError("Filtro LDAP: se esperaba '('")
    op = texto[pos + 1]
    if op == "&":
        subf, pos = _varios(texto, pos + 2, 0xA0)
        return subf, pos
    if op == "|":
        subf, pos = _varios(texto, pos + 2, 0xA1)
        return subf, pos
    if op == "!":
        subf, pos = _filtro(texto, pos + 2)
        if pos >= len(texto) or texto[pos] != ")":
            raise ValueError("Filtro LDAP: se esperaba ')'")
        return tlv(0xA2, subf), pos + 1
    cierre = texto.find(")", pos)
    if cierre == -1:
        raise ValueError("Filtro LDAP: falta ')'")
    cuerpo = texto[pos + 1:cierre]
    if "=" not in cuerpo:
        raise ValueError(f"Filtro LDAP sin '=': ({cuerpo})")
    atributo, valor = cuerpo.split("=", 1)
    atributo, valor = atributo.strip(), valor.strip()
    if valor == "*":
        return tlv(0x87, atributo.encode()), cierre + 1
    if atributo.endswith(">=") or atributo.endswith("<="):
        raise ValueError("Filtros >=/<= no soportados (usa =)")
    eq = tlv(0xA3, ber_octetos(atributo.encode()) + ber_octetos(valor.encode()))
    return eq, cierre + 1


def _varios(texto: str, pos: int, tag: int) -> Tuple[bytes, int]:
    subs = []
    while pos < len(texto) and texto[pos] == "(":
        subf, pos = _filtro(texto, pos)
        subs.append(subf)
    if pos >= len(texto) or texto[pos] != ")":
        raise ValueError("Filtro LDAP: se esperaba ')'")
    if not subs:
        raise ValueError("Filtro LDAP: operador sin operandos")
    return tlv(tag, b"".join(subs)), pos + 1


# ===========================================================================
# Mensajes LDAP
# ===========================================================================
def _mensaje(id_msg: int, operacion: bytes) -> bytes:
    """Envuelve operación en LdapMessage: SEQUENCE { id, op }."""
    return ber_secuencia(ber_entero(id_msg), operacion)


def peticion_bind(id_msg: int, usuario: str = "", clave: str = "") -> bytes:
    """BindRequest (APPLICATION 0 = 0x60) con autenticación simple."""
    op = tlv(0x60, ber_entero(3)
             + ber_octetos(usuario.encode("utf-8"))
             + tlv(0x80, clave.encode("utf-8")))
    return _mensaje(id_msg, op)


def peticion_busqueda(id_msg: int, base_dn: str, filtro: bytes, atributos: List[str],
                      alcance: int = 2, limite: int = 0) -> bytes:
    """SearchRequest (APPLICATION 3 = 0x63); alcance 0 base, 1 nivel, 2 subárbol."""
    op = tlv(0x63, ber_octetos(base_dn.encode())
             + ber_enumerado(alcance)
             + ber_enumerado(0)          # derefAliases: nunca
             + ber_entero(limite)
             + ber_entero(10)            # timeLimit
             + ber_bool(False)           # typesOnly
             + filtro
             + ber_secuencia(*[ber_octetos(a.encode()) for a in atributos]))
    return _mensaje(id_msg, op)


def peticion_unbind() -> bytes:
    return tlv(0x42, b"")


def _recibir(sock, n: int) -> bytes:
    trozos = bytearray()
    while len(trozos) < n:
        trozo = sock.recv(n - len(trozos))
        if not trozo:
            raise ConnectionError("LDAP: conexión cerrada")
        trozos.extend(trozo)
    return bytes(trozos)


def _leer_mensaje(sock) -> Tuple[int, bytes]:
    """Lee un mensaje LDAP completo. Devuelve (tag_del_mensaje, contenido)."""
    cabecera = _recibir(sock, 1)
    tag = cabecera[0]
    largo_b = _recibir(sock, 1)
    largo = largo_b[0]
    if largo & 0x80:
        n = largo & 0x7F
        largo = int.from_bytes(_recibir(sock, n), "big")
    if tag != 0x30:
        raise ConnectionError("LDAP: mensaje sin envoltorio SEQUENCE")
    return tag, _recibir(sock, largo)


def _texto(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _resultado(children) -> Tuple[int, str]:
    """Extrae (resultCode, detalle) de una BindResponse/SearchResultDone."""
    codigo, detalle = 1, ""
    for tag, contenido in children:
        if tag == 0x0A and contenido:
            codigo = int.from_bytes(contenido, "big", signed=True)
        elif tag == 0x04 and contenido:
            detalle = _texto(contenido)
    return codigo, detalle


def _parsear_entrada(contenido: bytes) -> Dict:
    """SearchResultEntry (0x64) → {dn, atributos: {tipo: [valores]}}."""
    partes = hijos(contenido)
    dn = _texto(partes[0][1]) if partes else ""
    atributos: Dict[str, List[str]] = {}
    if len(partes) > 1 and partes[1][0] == 0x30:
        for _, parcial in hijos(partes[1][1]):
            partes_parcial = hijos(parcial)
            if len(partes_parcial) < 2:
                continue
            tipo = _texto(partes_parcial[0][1])
            if partes_parcial[1][0] == 0x30:
                valores = [_texto(v) for _, v in hijos(partes_parcial[1][1])]
                atributos.setdefault(tipo, []).extend(valores)
    return {"dn": dn, "atributos": atributos}


def _op_de_mensaje(contenido: bytes) -> Tuple[int, bytes]:
    """Extrae (tag_op, cuerpo) del protocolOp dentro del LdapMessage
    (el primer hijo es el messageID, se salta)."""
    for tag, cuerpo in hijos(contenido):
        if tag != 0x02:                      # messageID
            return tag, cuerpo
    raise ConnectionError("LDAP: mensaje sin operación")


def _resp_bind_ok(contenido: bytes) -> None:
    tag_b, cuerpo_b = _op_de_mensaje(contenido)
    if tag_b != 0x61:
        raise ConnectionError("LDAP: la primera respuesta no es un BindResponse")
    codigo, detalle = _resultado(hijos(cuerpo_b))
    if codigo != 0:
        raise PermissionError(
            f"Bind LDAP falló ({codigo}): {CODIGOS.get(codigo, detalle or 'error')}")


def buscar(host: str, base_dn: str, filtro: str, atributos: List[str],
           usuario: str = "", clave: str = "", puerto: int = 389,
           timeout: int = 5, limite: int = 0) -> Tuple[List[Dict], str]:
    """Ejecuta bind + search. Devuelve (entradas, aviso); aviso vacío si todo OK."""
    filtro_ber = codificar_filtro(filtro)
    sock = socket.create_connection((host, puerto), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(peticion_bind(1, usuario, clave))
        _, mensaje = _leer_mensaje(sock)
        _resp_bind_ok(mensaje)

        sock.sendall(peticion_busqueda(2, base_dn, filtro_ber, atributos, limite=limite))
        entradas: List[Dict] = []
        aviso = ""
        while True:
            _, contenido = _leer_mensaje(sock)
            tag_op, cuerpo_op = _op_de_mensaje(contenido)
            if tag_op == 0x64:                    # SearchResultEntry
                entradas.append(_parsear_entrada(cuerpo_op))
                if limite and len(entradas) >= limite:
                    aviso = f"límite de {limite} objetos alcanzado"
                    break
            elif tag_op == 0x65:                  # SearchResultDone
                codigo, _det = _resultado(hijos(cuerpo_op))
                if codigo == 4:
                    aviso = "el servidor tiene más resultados (sizeLimit del servidor)"
                elif codigo != 0:
                    aviso = CODIGOS.get(codigo, f"código LDAP {codigo}")
                break
            # SearchResultReference (0x73) y otros se ignoran
        return entradas, aviso
    finally:
        try:
            sock.sendall(peticion_unbind())
        except OSError:
            pass
        sock.close()
