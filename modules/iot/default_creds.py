# -*- coding: utf-8 -*-
"""
Módulo iot/default_creds
========================
Verificación EDUCATIVA de credenciales por defecto en dispositivos del
LABORATORIO (inspirada en rapid7/IoTSeeker, scu-igroup/telnet-scanner y
RouterHunterBR de Scanners-Box).

Comprueba dos vías, solo contra el objetivo que declares (tu lab):
    • Telnet (23): negocia login/password con un diccionario de pares
      de fábrica y detecta prompt de shell.
    • HTTP Basic Auth (80/8080/443): probatura de pares en / y /admin/.

El diccionario es MUY limitado (8 pares de fábrica conocidos) por diseño:
el objetivo es demostrar el riesgo de las credenciales por defecto, no
hacer fuerza bruta. Requiere AUTHORIZED.

Riesgo: ALTO (autenticación activa contra el objetivo).
"""

import socket
import time

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Pares de fábrica universalmente documentados (no diccionario de ataque)
CREDENCIALES_DEFECTO = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("root", "root"), ("root", "toor"),
    ("user", "user"), ("cisco", "cisco"),
]

PROMPT_SHELL = (b"#", b"$", b">", b"~")


def _telnet_prueba(ip: str, puerto: int, usuario: str, clave: str, timeout: int):
    """Intenta un login Telnet manual (RFC 854 mínimo)."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as sock:
            sock.settimeout(timeout)
            buffer = b""

            def leer_hasta(marcadores, segundos=2.0):
                nonlocal buffer
                fin = time.time() + segundos
                while time.time() < fin:
                    for m in marcadores:
                        if m in buffer.lower():
                            return True
                    try:
                        datos = sock.recv(1024)
                    except (socket.timeout, OSError):
                        return False
                    if not datos:
                        return False
                    buffer += datos
                return False

            # Descarta negociación IAC (0xFF...) inicial
            leer_hasta([b"login:", b"username:", b"denied"], 2.0)
            if b"login:" not in buffer.lower() and b"username:" not in buffer.lower():
                return None  # el puerto no expone login telnet
            sock.sendall(usuario.encode() + b"\n")
            if not leer_hasta([b"password:"], 2.0):
                return False
            sock.sendall(clave.encode() + b"\n")
            if leer_hasta([b"denied", b"incorrect", b"failed", b"invalid"], 2.5):
                return False
            if leer_hasta(PROMPT_SHELL, 2.5):
                return True
            return False
    except OSError:
        return None


def _http_prueba(sesion, base: str, usuario: str, clave: str, timeout: int):
    """Prueba credenciales HTTP Basic en / y /admin/."""
    for ruta in ("/", "/admin/"):
        try:
            resp = sesion.get(base + ruta, auth=(usuario, clave), timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and ruta == "/admin/":
            return True
        if resp.status_code in (200, 302) and ruta == "/":
            # 200 en / con credenciales puede ser público: solo cuenta si antes fue 401
            return "posible"
    return False


class DefaultCreds(BaseModulo):
    """Verifica credenciales de fábrica en dispositivos del laboratorio."""

    NAME = "iot/default_creds"
    CATEGORIA = "iot"
    DESCRIPCION = ("Comprueba credenciales de FÁBRICA (telnet + HTTP basic) en un "
                   "dispositivo de tu LABORATORIO. Diccionario mínimo educativo.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "rapid7/IoTSeeker · scu-igroup/telnet-scanner · RouterHunterBR"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "IP del dispositivo del lab")
        self.opciones.declarar("PUERTOS", "23,80,8080", False, "Puertos a comprobar (telnet/http)")
        self.opciones.declarar("ADMIN_PATH", "/admin/", False, "Ruta de administración HTTP")

    def ejecutar(self) -> dict:
        ip = self._objetivo_host(self.opt("TARGET"))
        puertos = {int(p) for p in self.opt("PUERTOS").split(",") if p.strip().isdigit()}
        timeout = self.opt_int("TIMEOUT", 4) or 4

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        hallazgos = []
        # --- Telnet ------------------------------------------------------
        if 23 in puertos:
            for usuario, clave in CREDENCIALES_DEFECTO:
                resultado = _telnet_prueba(ip, 23, usuario, clave, timeout)
                if resultado is True:
                    hallazgos.append({"via": f"telnet://23", "credencial": f"{usuario}:{clave or '(vacía)'}",
                                      "estado": "ACEPTADA"})
                    break  # con uno basta para el hallazgo
                if resultado is None:
                    hallazgos.append({"via": "telnet://23", "credencial": "—",
                                      "estado": "puerto sin login telnet"})
                    break

        # --- HTTP Basic ---------------------------------------------------
        for puerto in (80, 8080, 443) if 80 not in puertos else (80,):
            esquema = "https" if puerto == 443 else "http"
            base = f"{esquema}://{ip}:{puerto}"
            try:
                sin_auth = sesion.get(base + "/", timeout=timeout, verify=False)
            except requests.RequestException:
                continue
            if sin_auth.status_code != 401:
                continue  # / no está protegido; nada que verificar por basic
            for usuario, clave in CREDENCIALES_DEFECTO:
                resp = sesion.get(base + "/", auth=(usuario, clave), timeout=timeout, verify=False)
                if resp.status_code == 200:
                    hallazgos.append({"via": f"{base} (basic)", "credencial": f"{usuario}:{clave or '(vacía)'}",
                                      "estado": "ACEPTADA"})
                    break

        resumen = (f"{ip}: {len([h for h in hallazgos if h['estado'] == 'ACEPTADA'])} credencial(es) "
                   f"de fábrica ACEPTADAS") if hallazgos else f"{ip}: sin hallazgos de credenciales por defecto"
        return {
            "resumen": resumen,
            "ip": ip,
            "hallazgos": hallazgos,
            "recomendacion": "Cambia credenciales de fábrica, deshabilita Telnet y aísla el dispositivo.",
        }
