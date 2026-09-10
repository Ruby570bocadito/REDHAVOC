# -*- coding: utf-8 -*-
"""
Módulo recon/snmp_enum
======================
Enumera dispositivos con SNMP v1/v2c abierto probando comunidades típicas
(public, private, ...) contra sysDescr / sysName / sysUpTime / sysLocation.

El paquete SNMP se codifica a mano (ASN.1 BER, sin dependencias) y se envía
por UDP 161. Una comunidad válida en redes internas es oro para el operador:
revela modelo del equipo, versión de firmware, ubicación física y hostname,
y abre la puerta a IF-MIB/BRIDGE-MIB (mapeo de red) y, en impresoras/routers,
a escritura si la comunidad es "private" (NO lo ejerce este módulo).

Riesgo: MEDIO (sondeo UDP de lectura).
ATT&CK: T1046 (Network Service Discovery) · CWE-200.
"""

import socket
from typing import Dict, List, Tuple

from core.base_module import BaseModulo, ModuloError

PUERTO_DEFECTO = 161

# OIDs estándar del grupo System (MIB-II)
OIDS = (
    ("1.3.6.1.2.1.1.1.0", "sysDescr"),
    ("1.3.6.1.2.1.1.5.0", "sysName"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation"),
)

COMUNIDADES_DEFECTO = "public,private,community,public@es,manager,admin"


# ----------------------------------------------------------------------
# ASN.1 BER (codificación mínima para SNMP v2c)
# ----------------------------------------------------------------------
def _tlv(tag: int, cuerpo: bytes) -> bytes:
    """Codifica TLV con longitud DER (función pura)."""
    if len(cuerpo) < 0x80:
        return bytes([tag, len(cuerpo)]) + cuerpo
    longitudes = b""
    n = len(cuerpo)
    while n:
        longitudes = bytes([n & 0xFF]) + longitudes
        n >>= 8
    return bytes([tag, 0x80 | len(longitudes)]) + longitudes + cuerpo


def _entero(valor: int) -> bytes:
    """Entero DER sin signo de tamaño mínimo (función pura)."""
    if valor == 0:
        return _tlv(0x02, b"\x00")
    bruto = valor.to_bytes((valor.bit_length() + 8) // 8, "big")
    return _tlv(0x02, bruto)


def _cadena(texto: str) -> bytes:
    return _tlv(0x04, texto.encode("utf-8", "replace"))


def _oid_a_bytes(oid: str) -> bytes:
    """Convierte '1.3.6.1.2.1.1.1.0' a los octetos BER del OID (función pura)."""
    arcos = [int(p) for p in oid.strip(".").split(".") if p != ""]
    if len(arcos) < 2:
        return b"\x2b"          # 1.3 por defecto
    primero = arcos[0] * 40 + min(arcos[1], 0x3F)
    octetos = bytearray([primero])
    for arco in arcos[2:]:
        pila = bytearray([arco & 0x7F])
        arco >>= 7
        while arco:
            pila.insert(0, 0x80 | (arco & 0x7F))
            arco >>= 7
        octetos.extend(pila)
    return bytes(octetos)


def peticion_get(comunidad: str, oid: str, id_peticion: int = 1) -> bytes:
    """Construye un SNMP v2c GET (función pura)."""
    varbind = _tlv(0x30, _tlv(0x06, _oid_a_bytes(oid)) + _tlv(0x05, b""))
    lista = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _entero(id_peticion) + _entero(0) + _entero(0) + lista)
    mensaje = _tlv(0x30, _entero(1) + _cadena(comunidad) + pdu)
    return mensaje


# ----------------------------------------------------------------------
# Decodificación mínima de la respuesta
# ----------------------------------------------------------------------
def _leer_tlv(datos: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Devuelve (tag, cuerpo, siguiente_pos) (función pura)."""
    if pos >= len(datos):
        return 0, b"", pos
    tag = datos[pos]
    pos += 1
    longitud = datos[pos]
    pos += 1
    if longitud & 0x80:
        n = longitud & 0x7F
        longitud = int.from_bytes(datos[pos:pos + n], "big")
        pos += n
    return tag, datos[pos:pos + longitud], pos + longitud


def _valores_varbinds(cuerpo_pdu: bytes) -> List[str]:
    """Extrae los valores de la lista de varbinds (función pura)."""
    valores: List[str] = []
    pos = 0
    for _ in range(3):                    # request-id, error-status, error-index
        _tag, _x, pos = _leer_tlv(cuerpo_pdu, pos)
    _tag, cuerpo_lista, _fin = _leer_tlv(cuerpo_pdu, pos)
    while cuerpo_lista:
        _tag, varbind, siguiente = _leer_tlv(cuerpo_lista, 0)
        p = 0
        _tag_oid, _oid, p = _leer_tlv(varbind, p)
        tag_val, valor, _p = _leer_tlv(varbind, p)
        if tag_val == 0x04:
            valores.append(valor.decode("utf-8", "replace"))
        elif tag_val in (0x02, 0x43):     # Integer / TimeTicks
            valores.append(str(int.from_bytes(valor, "big") if valor else 0))
        elif tag_val == 0x05:
            valores.append("")
        else:
            valores.append(valor.hex()[:64])
        cuerpo_lista = cuerpo_lista[siguiente:] if siguiente else b""
    return valores


def decodificar_respuesta(paquete: bytes) -> Dict[str, str]:
    """Devuelve {oid: valor} de un paquete GET-RESPONSE (función pura)."""
    salida: Dict[str, str] = {}
    tag, cuerpo, _p = _leer_tlv(paquete, 0)
    if tag != 0x30:
        return salida
    # version | community | PDU
    _tag, _ver, pos = _leer_tlv(cuerpo, 0)
    _tag, _com, pos = _leer_tlv(cuerpo, pos)
    tag_pdu, cuerpo_pdu, _fin = _leer_tlv(cuerpo, pos)
    if tag_pdu != 0xA2:                   # solo GET-RESPONSE
        return salida
    pos2 = 0
    for _ in range(3):                    # request-id, error-status, error-index
        _tag, _x, pos2 = _leer_tlv(cuerpo_pdu, pos2)
    _tag, cuerpo_lista, _f = _leer_tlv(cuerpo_pdu, pos2)
    while cuerpo_lista:
        _tag, varbind, siguiente = _leer_tlv(cuerpo_lista, 0)
        p = 0
        _t, oid_crudo, p = _leer_tlv(varbind, p)
        oid = ".".join(str(x) for x in _expander_oid(oid_crudo))
        _tv, valor, _pp = _leer_tlv(varbind, p)
        if _tv == 0x04:
            texto = valor.decode("utf-8", "replace")
        elif _tv in (0x02, 0x43):
            texto = str(int.from_bytes(valor, "big") if valor else 0)
        elif _tv == 0x05:
            texto = ""
        else:
            texto = valor.hex()[:64]
        salida[oid] = texto
        cuerpo_lista = cuerpo_lista[siguiente:] if siguiente else b""
    return salida


def _expander_oid(octetos: bytes) -> List[int]:
    """Convierte los octetos internos de un OID a su lista de arcos (pura)."""
    if not octetos:
        return []
    arcos = [octetos[0] // 40, octetos[0] % 40]
    valor = 0
    for byte in octetos[1:]:
        valor = (valor << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcos.append(valor)
            valor = 0
    return arcos


class SnmpEnum(BaseModulo):
    """Enumera dispositivos SNMP con comunidades por defecto (solo lectura)."""

    NAME = "recon/snmp_enum"
    CATEGORIA = "recon"
    DESCRIPCION = ("SNMP v2c con comunidades típicas (public/private/…): "
                   "sysDescr, sysName, sysUpTime y sysLocation — BER propio")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RFC 3418 · CWE-200 (exposición de información)"
    ATTCK = ("T1046",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "RHOST", "", True, "Host objetivo (IP o nombre)")
        self.opciones.declarar(
            "PUERTO", str(PUERTO_DEFECTO), False, "Puerto SNMP (UDP)")
        self.opciones.declarar(
            "COMUNIDADES", COMUNIDADES_DEFECTO, False,
            "Comunidades a probar, separadas por coma")
        self.opciones.declarar(
            "TIMEOUT", "4", False, "Timeout por consulta en segundos")

    def ejecutar(self) -> dict:
        host = self.opt("RHOST").strip()
        if not host:
            raise ModuloError("Indica el objetivo: set RHOST <host>")
        try:
            puerto = int(self.opt("PUERTO", str(PUERTO_DEFECTO)))
        except ValueError:
            puerto = PUERTO_DEFECTO
        timeout = self.opt_int("TIMEOUT", 4) or 4
        comunidades = [c.strip() for c in
                       self.opt("COMUNIDADES", COMUNIDADES_DEFECTO).split(",")
                       if c.strip()]

        acierto: Tuple[str, Dict[str, str]] | None = None
        comunidad_valida = ""
        probadas: List[str] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            for comunidad in comunidades:
                probadas.append(comunidad)
                paquete = peticion_get(comunidad, OIDS[0][0])
                try:
                    sock.sendto(paquete, (host, puerto))
                    datos, _peer = sock.recvfrom(65535)
                except (OSError, socket.timeout):
                    continue
                respuesta = decodificar_respuesta(datos)
                if respuesta:
                    comunidad_valida = comunidad
                    # Consulta el resto de OIDs con la comunidad válida
                    try:
                        for oid_extra, _nombre in OIDS[1:]:
                            sock.sendto(peticion_get(comunidad, oid_extra), (host, puerto))
                            datos2, _p2 = sock.recvfrom(65535)
                            respuesta.update(decodificar_respuesta(datos2))
                    except (OSError, socket.timeout):
                        pass
                    acierto = (comunidad, respuesta)
                    break
        finally:
            sock.close()

        if acierto is None:
            return {
                "resumen": (f"SNMP {host}:{puerto} sin comunidad válida "
                            f"({len(probadas)} probadas) o sin respuesta"),
                "resultados": [{"comunidades_probadas": probadas}],
                "nota": "Sin acierto: el agente puede filtrar por ACL, usar v3, "
                        "o simplemente no ser SNMP. Prueba otro puerto o host.",
            }

        comunidad, valores = acierto
        filas = []
        for oid, nombre in OIDS:
            valor = valores.get(oid)
            if valor is not None:
                filas.append({"campo": nombre, "valor": valor})

        sensible = any(v.get("campo") == "sysDescr" and v.get("valor")
                       for v in filas)
        if sensible and self.workspace is not None:
            self.workspace.add_vuln(
                host, "SNMP con comunidad por defecto", "medio",
                f"comunidad '{comunidad}' expone sysDescr/sysName (UDP {puerto})",
                self.NAME)

        return {
            "resumen": (f"SNMP {host}:{puerto} responde a la comunidad "
                        f"'{comunidad}' ({len(filas)} campos leídos)"),
            "resultados": filas,
            "comunidad": comunidad,
            "nota": "Solo lectura (grupo System). Cambia las comunidades, "
                    "pasa a SNMPv3 con auth/priv y filtra por ACL.",
        }
