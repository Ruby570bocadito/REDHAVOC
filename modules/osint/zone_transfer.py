# -*- coding: utf-8 -*-
"""
Módulo osint/zone_transfer
==========================
Intento de transferencia de zona DNS (AXFR) contra los nameservers del
dominio objetivo — técnica clásica de reconocimiento (idea "Zone Transfer"
de Argus y RED_HAWK).

Un AXFR bien configurado debe ser rechazado. Si un NS lo permite, el
dominio expone TODO su mapa DNS interno (subdominios, hosts, etc.).

Implementación: cliente DNS propio extendido a TCP/53 (AXFR es TCP,
respuesta fragmentada con prefijo de 2 bytes).

Riesgo: MEDIO (contacto directo con los DNS autoritativos del objetivo).
"""

import socket
import struct

from core.base_module import BaseModulo, ModuloError
from modules.recon.dns_enum import (_consultar, _parsear_respuesta,
                                    _nombre_comprimido, TIPOS, IN)
from modules.recon.dns_enum import _pregunta as _pregunta_udp

QTYPE_AXFR = 252


def _pregunta_axfr(nombre: str) -> bytes:
    """Consulta AXFR (qtype 252) sobre TCP. Sin recursión."""
    identificador = 0x4141
    cabecera = struct.pack(">HHHHHH", identificador, 0x0000, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in nombre.split(".")) + b"\x00"
    return cabecera + qname + struct.pack(">HH", QTYPE_AXFR, IN)


def _axfr(servidor_ns: str, dominio: str, timeout: int):
    """Ejecuta AXFR contra un NS. Devuelve (permitido, registros, detalle)."""
    try:
        with socket.create_connection((servidor_ns, 53), timeout=timeout) as sock:
            sock.settimeout(timeout)
            consulta = _pregunta_axfr(dominio)
            sock.sendall(struct.pack(">H", len(consulta)) + consulta)

            registros = []
            paquetes = 0
            while paquetes < 50:  # límite de seguridad
                prefijo = sock.recv(2)
                if len(prefijo) < 2:
                    break
                (longitud,) = struct.unpack(">H", prefijo)
                datos = b""
                while len(datos) < longitud:
                    trozo = sock.recv(longitud - len(datos))
                    if not trozo:
                        break
                    datos += trozo
                if not datos:
                    break
                paquetes += 1
                try:
                    parsed = _parsear_respuesta(datos, TIPOS["A"])
                    registros.extend(parsed["respuestas"])
                    # Extrae también los nombres de la sección answer (hosts)
                    offset = 12
                    (qd, an) = struct.unpack(">HH", datos[4:8])
                    for _ in range(qd):
                        _, offset = _nombre_comprimido(datos, offset)
                        offset += 4
                    for _ in range(an):
                        nombre, offset = _nombre_comprimido(datos, offset)
                        if nombre and nombre not in registros:
                            registros.append(nombre)
                        tipo_r, _, ttl, rdlargo = struct.unpack(">HHIH", datos[offset:offset + 10])
                        offset += 10 + rdlargo
                except (IndexError, struct.error):
                    break
            if registros:
                return True, registros, f"{paquetes} mensaje(s) de transferencia recibidos"
            return False, [], "El NS cerró la conexión sin datos (correcto)"
    except (OSError, socket.timeout) as err:
        return False, [], f"Sin AXFR ({type(err).__name__}: {err})"


class ZoneTransfer(BaseModulo):
    """Prueba transferencias de zona (AXFR) contra los NS del dominio."""

    NAME = "osint/zone_transfer"
    CATEGORIA = "osint"
    DESCRIPCION = ("Intenta AXFR contra los nameservers del dominio. Un NS "
                   "mal configurado expone todo el mapa DNS interno.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (Zone Transfer) · RED_HAWK"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio objetivo")
        self.opciones.declarar("RESOLVER", "", False, "Resolver para descubrir los NS (por defecto: sistema)")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN"))
        timeout = self.opt_int("TIMEOUT", 5) or 5

        resolver = self.opt("RESOLVER") or "1.1.1.1"
        try:
            paquete = _consultar(resolver, dominio, TIPOS["NS"], timeout)
            ns_resp = _parsear_respuesta(paquete, TIPOS["NS"])
        except (OSError, ModuloError) as err:
            raise ModuloError(f"No se pudieron resolver los NS de {dominio}: {err}")
        nameservers = [ns for ns in ns_resp["respuestas"] if ns and not ns.startswith("(")]
        if not nameservers:
            raise ModuloError(f"{dominio} no tiene NS públicos resolubles")

        resultados = []
        for ns in nameservers:
            permitido, registros, detalle = _axfr(ns, dominio, timeout)
            resultados.append({"ns": ns, "axfr_permitido": permitido,
                               "registros": registros[:200], "detalle": detalle})

        vulnerables = [r["ns"] for r in resultados if r["axfr_permitido"]]
        if vulnerables:
            resumen = f"VULNERABLE: AXFR permitido por {', '.join(vulnerables)}"
        else:
            resumen = f"{dominio}: {len(nameservers)} NS probados, ninguno permite AXFR (correcto)"

        return {
            "resumen": resumen,
            "dominio": dominio,
            "nameservers": nameservers,
            "resultados": resultados,
            "vulnerable": bool(vulnerables),
        }
