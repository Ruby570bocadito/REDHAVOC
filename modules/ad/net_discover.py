# -*- coding: utf-8 -*-
"""
Módulo ad/net_discover
======================
Descubrimiento PASIVO de nombres de host en la red local escuchando
consultas LLMNR (UDP/5355), NBT-NS (UDP/137) y mDNS (UDP/5353).

Es la fase de reconocimiento previa al envenenamiento de Responder
(T1557.001): saber qué nombres se resuelven en el segmento indica dónde
hay sistemas Windows legacy, impresoras, NAS y services mal configurados.

Este módulo SOLO escucha y registra; NO responde a las consultas
(no envenena). Escuchar puertos < 1024 requiere root.

Ideas de: Responder (análisis pasivo) · suite propia (sirena, fase previa).
Riesgo: MEDIO (escucha pasiva de tráfico de red).
ATT&CK: T1557.001 (fase de reconocimiento del envenenamiento).
"""

import socket
import struct
import threading
import time

from core.base_module import BaseModulo, ModuloError

PROTOS = {
    "llmnr": 5355,
    "nbtns": 137,
    "mdns": 5353,
}


# ---------------------------------------------------------------------------
# Parseadores de paquetes (expuestos para tests)
# ---------------------------------------------------------------------------
def parsear_etiquetas_dns(datos: bytes, offset: int):
    """Lee un nombre DNS (etiquetas length-prefixed). Devuelve (nombre, sig_offset)."""
    etiquetas = []
    while offset < len(datos):
        longitud = datos[offset]
        offset += 1
        if longitud == 0:
            break
        etiquetas.append(datos[offset:offset + longitud].decode(errors="replace"))
        offset += longitud
    return ".".join(etiquetas), offset


def parsear_llmnr(datos: bytes):
    """Consulta LLMNR (formato DNS): devuelve el nombre preguntado o None."""
    if len(datos) < 12:
        return None
    _, flags, preguntas, _, _, _ = struct.unpack(">HHHHHH", datos[:12])
    if not preguntas:
        return None
    if (flags & 0x8000):                      # es respuesta, no consulta
        return None
    nombre, _ = parsear_etiquetas_dns(datos, 12)
    return nombre or None


def decodificar_nombre_netbios(bloque: str) -> str:
    """Decodifica un nombre NetBIOS de primer nivel (codificación 'CB')."""
    limpio = "".join(c for c in bloque if c != ".")
    if len(limpio) % 2 or not all(c.isalpha() and c.isupper() for c in limpio):
        return ""
    pares = [(ord(limpio[i]) - ord("A"), ord(limpio[i + 1]) - ord("A"))
             for i in range(0, len(limpio), 2)]
    crudo = bytes((hi << 4) | lo for hi, lo in pares)
    nombre = crudo.decode("cp437", errors="replace").rstrip()
    return nombre.split()[0] if nombre else ""


def parsear_nbtns(datos: bytes):
    """Consulta/registro NBT-NS: devuelve (nombre, opcode) o None."""
    if len(datos) < 12:
        return None
    _, flags, preguntas, _, _, _ = struct.unpack(">HHHHHH", datos[:12])
    if not preguntas:
        return None
    opcode = (flags >> 11) & 0xF
    if opcode not in (0, 5, 7, 8):            # query, registration, refresh...
        return None
    nombre, offset = parsear_etiquetas_dns(datos, 12)
    # tras el nombre codificado van: null byte + tipo (2) + clase (2)
    if offset + 4 > len(datos):
        return None
    decodificado = decodificar_nombre_netbios(nombre)
    return (decodificado, opcode) if decodificado else None


def parsear_mdns(datos: bytes):
    """Consulta mDNS (formato DNS sobre UDP/5353): devuelve el nombre o None."""
    if len(datos) < 12:
        return None
    _, flags, preguntas, _, _, _ = struct.unpack(">HHHHHH", datos[:12])
    if flags & 0x8000 or not preguntas:       # solo consultas
        return None
    nombre, _ = parsear_etiquetas_dns(datos, 12)
    return nombre or None


class NetDiscover(BaseModulo):
    """Escucha pasiva de consultas de nombres (LLMNR/NBT-NS/mDNS)."""

    NAME = "ad/net_discover"
    CATEGORIA = "ad"
    DESCRIPCION = ("Descubrimiento PASIVO de nombres en la LAN: escucha consultas "
                   "LLMNR/NBT-NS/mDNS (fase previa al envenenamiento de Responder). "
                   "Solo escucha, nunca responde. Puertos <1024 requieren root.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Responder (modo pasivo) · MITRE ATT&CK T1557.001 (recon)"
    ATTCK = ("T1557.001",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("DURACION", "15", False, "Segundos a escuchar (1–120)")
        self.opciones.declarar("PROTOCOLOS", "llmnr,nbtns,mdns", False,
                               "Protocolos a escuchar, separados por coma")

    def ejecutar(self) -> dict:
        duracion = min(max(self.opt_int("DURACION", 15) or 15, 1), 120)
        pedidos = [p.strip().lower() for p in self.opt("PROTOCOLOS").split(",") if p.strip()]
        protocolos = [p for p in pedidos if p in PROTOS]
        if not protocolos:
            raise ModuloError("Ningún protocolo válido en PROTOCOLOS "
                              "(opciones: llmnr, nbtns, mdns)")

        observaciones: list = []
        nombres: dict = {}
        fallos: list = []
        zocalos: dict = {}
        lock = threading.Lock()

        def abrir(p):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", PROTOS[p]))
            sock.settimeout(0.5)
            return sock

        for p in protocolos:
            try:
                zocalos[p] = abrir(p)
            except (PermissionError, OSError) as err:
                fallos.append({"protocolo": p,
                               "error": f"sin permiso para el puerto {PROTOS[p]} (¿root?)"
                                        if isinstance(err, PermissionError) else str(err)})

        if not zocalos:
            raise ModuloError("No se pudo abrir ningún socket de escucha: "
                              + "; ".join(f"{f['protocolo']}: {f['error']}" for f in fallos))

        def escuchar(nombre_proto, sock):
            fin = time.time() + duracion
            while time.time() < fin:
                try:
                    datos, origen = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                with lock:
                    self._registrar(nombre_proto, datos, origen, observaciones, nombres)

        hilos = [threading.Thread(target=escuchar, args=(p, s), daemon=True)
                 for p, s in zocalos.items()]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        for s in zocalos.values():
            s.close()

        if not observaciones and not fallos:
            raise ModuloError(f"Sin consultas de nombres en {duracion}s "
                              "(¿red muy quieta? prueba DURACION mayor)")

        resumen = (f"{len(observaciones)} consultas · {len(nombres)} nombres únicos en "
                   f"{duracion}s ({', '.join(zocalos)})")
        return {
            "resumen": resumen,
            "duracion": duracion,
            "protocolos": sorted(zocalos),
            "observaciones": observaciones,
            "nombres_unicos": sorted(nombres),
            "fallos": fallos,
            "nota": "Solo escucha: el envenenamiento/respuesta NO está implementado "
                    "en REDHAVOC (escenario de lab con autorización).",
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _registrar(proto, datos, origen, observaciones, nombres):
        """Clasifica un datagrama y lo añade a las listas (bajo lock del caller)."""
        origen_ip = origen[0] if isinstance(origen, tuple) else "?"
        if proto == "llmnr":
            nombre = parsear_llmnr(datos)
        elif proto == "nbtns":
            par = parsear_nbtns(datos)
            nombre = par[0] if par else None
        elif proto == "mdns":
            nombre = parsear_mdns(datos)
        else:
            nombre = None
        if not nombre:
            return
        observaciones.append({"protocolo": proto, "nombre": nombre, "origen": origen_ip})
        nombres.setdefault(nombre, {"veces": 0, "protocolos": set()})
        nombres[nombre]["veces"] += 1
        nombres[nombre]["protocolos"].add(proto)
