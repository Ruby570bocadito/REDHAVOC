# -*- coding: utf-8 -*-
"""
Módulo recon/dns_enum
=====================
Cliente DNS mínimo implementado a mano sobre UDP/53 (RFC 1035):
construye la consulta y parsea la respuesta sin dependencias externas.

Soporta registros A, AAAA, MX, NS, TXT, SOA y CNAME.

Riesgo: BAJO (consultas DNS normales contra el resolver del sistema).
"""

import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from core.base_module import BaseModulo, ModuloError

TIPOS = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
IN = 1  # clase INET


# ---------------------------------------------------------------------------
# Construcción del paquete de consulta
# ---------------------------------------------------------------------------
def _pregunta(nombre: str, tipo: int) -> bytes:
    """Construye una consulta DNS en binario."""
    identificador = random.randint(0, 65535)
    cabecera = struct.pack(">HHHHHH", identificador, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b"".join(bytes([len(p)]) + p.encode() for p in nombre.split(".")) + b"\x00"
    return cabecera + qname + struct.pack(">HH", tipo, IN)


def _nombre_comprimido(datos: bytes, offset: int):
    """Lee un nombre DNS resolviendo punteros de compresión (0xC0)."""
    etiquetas, saltado = [], None
    while True:
        longitud = datos[offset]
        if longitud & 0xC0 == 0xC0:  # puntero
            puntero = struct.unpack(">H", datos[offset:offset + 2])[0] & 0x3FFF
            if saltado is None:
                saltado = offset + 2
            offset = puntero
            continue
        offset += 1
        if longitud == 0:
            break  # offset ya apunta al byte siguiente del terminador
        etiquetas.append(datos[offset:offset + longitud].decode(errors="replace"))
        offset += longitud
    return ".".join(etiquetas), (saltado if saltado is not None else offset)


def _consultar(resolver: str, nombre: str, tipo: int, timeout: int) -> bytes:
    """Envía la consulta UDP y devuelve el paquete de respuesta."""
    consulta = _pregunta(nombre, tipo)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(consulta, (resolver, 53))
        respuesta, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if respuesta[:2] != consulta[:2]:
        raise ModuloError("El identificador DNS no coincide (respuesta fuera de sesión)")
    return respuesta


def _parsear_respuesta(datos: bytes, tipo: int):
    """Extrae la sección ANSWER del paquete según el tipo consultado."""
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", datos[:12])
    if not (flags & 0x8000):
        raise ModuloError("Respuesta DNS no es una respuesta válida")
    rcode = flags & 0x000F
    if rcode != 0:
        return {"rcode": rcode, "respuestas": []}

    offset = 12
    for _ in range(qd):  # saltar la sección QUESTION
        _, offset = _nombre_comprimido(datos, offset)
        offset += 4
    respuestas = []
    for _ in range(an):
        _, offset = _nombre_comprimido(datos, offset)
        tipo_r, _, ttl, rdlargo = struct.unpack(">HHIH", datos[offset:offset + 10])
        offset += 10
        rdata = datos[offset:offset + rdlargo]
        offset += rdlargo
        if tipo_r == 1 and len(rdata) == 4:                 # A
            respuestas.append(socket.inet_ntoa(rdata))
        elif tipo_r == 28 and len(rdata) == 16:             # AAAA
            respuestas.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif tipo_r in (2, 5, 12):                          # NS / CNAME / PTR
            nombre, _ = _nombre_comprimido(datos, offset - rdlargo)
            respuestas.append(nombre)
        elif tipo_r == 15:                                  # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            host, _ = _nombre_comprimido(datos, offset - rdlargo + 2)
            respuestas.append(f"{pref} {host}")
        elif tipo_r == 16:                                  # TXT
            texto, pos = "", 0
            while pos < len(rdata):
                l = rdata[pos]
                texto += rdata[pos + 1:pos + 1 + l].decode(errors="replace")
                pos += 1 + l
            respuestas.append(texto)
        elif tipo_r == 6:                                   # SOA
            mname, o1 = _nombre_comprimido(datos, offset - rdlargo)
            rname, o2 = _nombre_comprimido(datos, o1)
            respuestas.append(f"{mname} {rname}")
    return {"rcode": rcode, "respuestas": respuestas}


class DnsEnum(BaseModulo):
    """Enumeración de registros DNS de un dominio sin dependencias externas."""

    NAME = "recon/dns_enum"
    CATEGORIA = "recon"
    DESCRIPCION = ("Enumera registros DNS (A, AAAA, MX, NS, TXT, SOA, CNAME) "
                   "con un cliente DNS propio sobre UDP/53.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RED_HAWK (dns lookup)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio objetivo (p. ej. example.com)")
        self.opciones.declarar("RESOLVER", "", False, "Servidor DNS a consultar (por defecto: el del sistema)")
        self.opciones.declarar("TIPOS", "A,AAAA,MX,NS,TXT,SOA", False, "Tipos de registro separados por coma")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN"))
        timeout = self.opt_int("TIMEOUT", 5) or 5

        resolver = self.opt("RESOLVER")
        if not resolver:
            # Descubre el resolver del sistema (Linux) o usa el conocido 1.1.1.1
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as fh:
                    for linea in fh:
                        if linea.startswith("nameserver"):
                            resolver = linea.split()[1]
                            break
            except OSError:
                pass
            resolver = resolver or "1.1.1.1"

        tipos_solicitados = [t.strip().upper() for t in self.opt("TIPOS").split(",") if t.strip()]
        tipos_desconocidos = [t for t in tipos_solicitados if t not in TIPOS]
        if tipos_desconocidos:
            raise ModuloError(f"Tipos DNS no soportados: {', '.join(tipos_desconocidos)}")

        # Consultas en paralelo: el peor caso (resolver sordo) tarda 1 timeout
        # en vez de 7 en serie.
        resultados: dict = {}
        with ThreadPoolExecutor(max_workers=min(8, len(tipos_solicitados))) as pool:
            futuros = {
                tipo: pool.submit(self._consultar_tipo, resolver, dominio,
                                  tipo, timeout)
                for tipo in tipos_solicitados
            }
            for tipo, futuro in futuros.items():
                resultados[tipo] = futuro.result()

        encontrados = {t: v for t, v in resultados.items() if v and not str(v[0]).startswith("(")}
        resumen = f"{dominio}: " + " · ".join(f"{t}={len(v)}" for t, v in encontrados.items())
        return {
            "resumen": resumen,
            "dominio": dominio,
            "resolver": resolver,
            "registros": resultados,
        }

    @staticmethod
    def _consultar_tipo(resolver: str, dominio: str, tipo: str, timeout: int) -> list:
        """Consulta un tipo de registro y degrada los fallos a texto."""
        try:
            paquete = _consultar(resolver, dominio, TIPOS[tipo], timeout)
            return _parsear_respuesta(paquete, TIPOS[tipo])["respuestas"]
        except socket.timeout:
            return ["(timeout)"]
        except (OSError, ModuloError) as err:
            return [f"(error: {err})"]
