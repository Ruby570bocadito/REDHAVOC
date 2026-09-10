# -*- coding: utf-8 -*-
"""
Módulo iot/device_scan
======================
Huella de dispositivos IoT/OT en el objetivo: sondea puertos típicos de
routers, cámaras IP, PLCs y sistema de construcción, captura banners y
clasifica el tipo de dispositivo (idea de RouterSploit/IoTSeeker y la
sección IoT de Scanners-Box).

Puertos sondeados (TCP): 21 FTP, 22 SSH, 23 Telnet, 80/443/8080 HTTP(S),
554 RTSP (cámaras), 1883 MQTT, 502 Modbus, 102 S7 (Siemens), 20000 DNP3,
47808 BACnet, 9100 HP JetDirect.

Riesgo: MEDIO (conexiones TCP al objetivo).
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModulo, ModuloError

# puerto → (protocolo, sonda, tipo de dispositivo típico)
PUERTOS_IOT = {
    21:    ("FTP", None, "NAS / cámara / router"),
    22:    ("SSH", None, "servidor / dispositivo embebido"),
    23:    ("Telnet", None, "router / switch / cámara (legacy)"),
    80:    ("HTTP", "GET / HTTP/1.0\r\n\r\n", "panel web IoT"),
    443:   ("HTTPS", None, "panel web IoT"),
    554:   ("RTSP", "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", "cámara IP / NVR"),
    1883:  ("MQTT", None, "broker IoT"),
    102:   ("S7", None, "PLC Siemens"),
    502:   ("Modbus", None, "PLC / RTU industrial"),
    20000: ("DNP3", None, "SCADA / RTU"),
    47808: ("BACnet", None, "HVAC / edificio inteligente"),
    9100:  ("JetDirect", None, "impresora de red"),
    8080:  ("HTTP-alt", "GET / HTTP/1.0\r\n\r\n", "panel web IoT"),
}

PALABRAS_CLAVE = {
    "router": "router", "gateway": "router", "openwrt": "router",
    "camera": "cámara IP", "hikvision": "cámara IP", "dahua": "cámara IP",
    "axis": "cámara IP", "rtsp": "cámara IP",
    "siemens": "PLC Siemens", "modicon": "PLC Modicon", "schneider": "PLC",
    "printer": "impresora", "hp jetdirect": "impresora",
    "mosquitto": "broker MQTT", "emqx": "broker MQTT",
    "nginx": "servidor web", "apache": "servidor web", "boa": "web embebida",
    "lighttpd": "web embebida", "mini_httpd": "web embebida", "goahead": "web embebida",
}


def _sondea(ip: str, puerto: int, timeout: float):
    """Conecta a un puerto IoT y devuelve banner clasificado."""
    protocolo, sonda, tipo = PUERTOS_IOT[puerto]
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            if sonda:
                try:
                    sock.sendall(sonda.encode())
                except OSError:
                    pass
            try:
                banner = sock.recv(256).decode(errors="replace").strip()
            except (OSError, socket.timeout):
                banner = ""
            return puerto, protocolo, tipo, banner
    except OSError:
        return None


class DeviceScan(BaseModulo):
    """Fingerprinting de dispositivos IoT/OT por puertos y banners."""

    NAME = "iot/device_scan"
    CATEGORIA = "iot"
    DESCRIPCION = ("Sondea puertos típicos IoT/OT (Telnet, RTSP, MQTT, Modbus, "
                   "S7, BACnet...) y clasifica el dispositivo por banner.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "threat9/routersploit · Scanners-Box (IoT Hardware Audit)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "IP del dispositivo/lab objetivo")
        self.opciones.declarar("PUERTOS", "", False, "Subconjunto de puertos IoT (por defecto: todos)")

    def ejecutar(self) -> dict:
        ip = self._objetivo_host(self.opt("TARGET"))
        timeout = self.opt_int("TIMEOUT", 3) or 3
        hilos = min(self.opt_int("THREADS", 10) or 10, len(PUERTOS_IOT))

        puertos = sorted(PUERTOS_IOT.keys())
        filtro = self.opt("PUERTOS").strip()
        if filtro:
            elegidos = {int(p) for p in filtro.split(",") if p.strip().isdigit()}
            puertos = [p for p in puertos if p in elegidos]

        dispositivos = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = [pool.submit(_sondea, ip, p, timeout) for p in puertos]
            for futuro in as_completed(futuros):
                r = futuro.result()
                if r is None:
                    continue
                puerto, protocolo, tipo, banner = r
                clasificacion = tipo
                for clave, etiqueta in PALABRAS_CLAVE.items():
                    if clave in banner.lower():
                        clasificacion = etiqueta
                        break
                dispositivos.append({
                    "puerto": puerto, "protocolo": protocolo,
                    "tipo_probable": clasificacion,
                    "banner": banner[:160],
                })

        dispositivos.sort(key=lambda d: d["puerto"])
        tipos = sorted({d["tipo_probable"] for d in dispositivos})
        resumen = f"{ip}: {len(dispositivos)} servicios IoT/OT — {', '.join(tipos) if tipos else 'sin huella'}"
        return {
            "resumen": resumen,
            "ip": ip,
            "dispositivo_probable": tipos,
            "servicios": dispositivos,
        }
