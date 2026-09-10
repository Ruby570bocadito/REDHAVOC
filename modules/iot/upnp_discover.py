# -*- coding: utf-8 -*-
"""
Módulo iot/upnp_discover
========================
Descubrimiento de dispositivos UPnP/SSDP en la red local mediante M-SEARCH
(multicast 239.255.255.250:1900) — técnica estándar de inventario de
dispositivos (routers, cámaras, NAS, smart TV) usada por herramientas de
auditoría IoT.

Muestra Server, ST y Location (XML de descripción) de cada dispositivo que
responda. Útil para mapear la superficie de ataque del LABORATORIO.

Riesgo: MEDIO (broadcast en la LAN; usar solo en red propia de laboratorio).
"""

import socket
import time

from core.base_module import BaseModulo, ModuloError

DIRECCION_SSDP = ("239.255.255.250", 1900)
M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


class UpnpDiscover(BaseModulo):
    """Descubre dispositivos UPnP/SSDP en la LAN del laboratorio."""

    NAME = "iot/upnp_discover"
    CATEGORIA = "iot"
    DESCRIPCION = ("Descubre dispositivos UPnP/SSDP en la LAN (M-SEARCH) y "
                   "extrae Server/Location para inventario de laboratorio.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RouterSploit/Nettacker (descubrimiento) · Scanners-Box (IoT)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("ESPERA", "3", False, "Segundos de escucha de respuestas (1-10)")

    def ejecutar(self) -> dict:
        espera = min(max(self.opt_int("ESPERA", 3), 1), 10)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        sock.settimeout(0.5)

        try:
            sock.sendto(M_SEARCH.encode(), DIRECCION_SSDP)
        except OSError as err:
            raise ModuloError(f"No se pudo enviar M-SEARCH: {err}")

        # Reenvía a mitad del periodo para no perder respuestas
        inicio = time.time()
        respuestas = {}
        while time.time() - inicio < espera:
            if abs((time.time() - inicio) - espera / 2) < 0.4:
                try:
                    sock.sendto(M_SEARCH.encode(), DIRECCION_SSDP)
                except OSError:
                    pass
            try:
                datos, origen = sock.recvfrom(4096)
            except socket.timeout:
                continue
            texto = datos.decode(errors="replace")
            cabeceras = {}
            for linea in texto.splitlines()[1:]:
                if ":" in linea:
                    k, v = linea.split(":", 1)
                    cabeceras[k.strip().upper()] = v.strip()
            clave = origen[0]
            if clave not in respuestas:  # deduplica por IP
                respuestas[clave] = {
                    "ip": clave,
                    "server": cabeceras.get("SERVER", "")[:160],
                    "st": cabeceras.get("ST", ""),
                    "location": cabeceras.get("LOCATION", ""),
                }
        sock.close()

        dispositivos = sorted(respuestas.values(), key=lambda d: d["ip"])
        resumen = f"UPnP: {len(dispositivos)} dispositivo(s) en la LAN"
        return {
            "resumen": resumen,
            "dispositivos": dispositivos,
            "nota": "Revisa el XML de Location: expone servicios y acciones UPnP del dispositivo.",
        }
