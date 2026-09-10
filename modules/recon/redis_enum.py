# -*- coding: utf-8 -*-
"""
Módulo recon/redis_enum
=======================
Enumera servidores Redis accesibles mediante el protocolo RESP (propio,
sobre socket TCP) SIN credenciales:

    • SIN_AUTH     → PING/INFO responden: la instancia no pide contraseña
    • PROTEGIDA    → exige autenticación (NOAUTH / -ERR operation not permitted)
    • NO_EXISTE    → puerto cerrado o respuesta no-Redis

Una Redis SIN_AUTH permite leer claves (sesiones, tokens, cachés de
contraseñas) y, en despliegues antiguos, escribir ficheros vía CONFIG SET
(que este módulo NUNCA ejecuta: solo lectura con PING/INFO/DBSIZE).

Riesgo: MEDIO (conexión de servicio; toda consulta es de lectura).
ATT&CK: T1046 (Network Service Discovery) · CWE-306.
"""

import socket
from typing import Dict, List

from core.base_module import BaseModulo, ModuloError

PUERTO_DEFECTO = 6379


# ----------------------------------------------------------------------
# Protocolo RESP (solo lo necesario para consultas de lectura)
# ----------------------------------------------------------------------
def comando_resp(*palabras: str) -> bytes:
    """Codifica un comando Redis como array RESP (función pura)."""
    salida = [f"*{len(palabras)}\r\n".encode()]
    for palabra in palabras:
        bruto = palabra.encode()
        salida.append(f"${len(bruto)}\r\n".encode() + bruto + b"\r\n")
    return b"".join(salida)


def _linea(sock) -> str:
    """Lee una línea CRLF del socket (sin introducir EOF infinitos)."""
    trozos: List[bytes] = []
    while True:
        byte = sock.recv(1)
        if not byte:
            break
        trozos.append(byte)
        if byte == b"\n":
            break
    return b"".join(trozos).decode("utf-8", "replace").strip()


def _texto_simple(sock) -> str:
    """Consume una respuesta RESP simple (+string/-err/:num/$bulk) y la aplana."""
    linea = _linea(sock)
    if not linea:
        return ""
    prefijo, resto = linea[:1], linea[1:]
    if prefijo == "$":                        # bulk string: lee len+2 bytes
        try:
            n = int(resto)
        except ValueError:
            return resto
        if n <= 0:
            return ""
        datos = b""
        while len(datos) < n + 2:
            datos += sock.recv(n + 2 - len(datos))
        return datos[:n].decode("utf-8", "replace")
    if prefijo == "*":                        # array: consume n elementos
        try:
            n = int(resto)
        except ValueError:
            return resto
        partes = []
        for _ in range(max(0, n)):
            partes.append(_texto_simple(sock))
        return " | ".join(p for p in partes if p)
    return resto                              # +simple, -error, :entero


def clasificar_respuesta(respuestas: Dict[str, str]) -> str:
    """Clasifica la instancia según sus respuestas (función pura).

    Estados: SIN_AUTH | PROTEGIDA | NO_REDIS
    """
    ping = (respuestas.get("PING") or "").lower()
    info = (respuestas.get("INFO") or "").lower()
    if ping.startswith("pong"):
        return "SIN_AUTH"
    if "noauth" in ping or "authentication required" in info or \
       "denied" in ping or "operation not permitted" in info:
        return "PROTEGIDA"
    if ping or info:
        # Responde algo pero no es PONG ni error clásico: probablemente no-Redis
        return "NO_REDIS"
    return "NO_REDIS"


def parsear_info(info: str) -> Dict[str, str]:
    """Extrae los campos útiles de la salida INFO (función pura)."""
    campos: Dict[str, str] = {}
    for linea in (info or "").splitlines():
        if ":" in linea and not linea.startswith("#"):
            clave, _, valor = linea.partition(":")
            if clave in ("redis_version", "redis_mode", "os", "tcp_port",
                         "connected_clients", "db0", "run_id", "uptime_in_days"):
                campos[clave] = valor
    return campos


class RedisEnum(BaseModulo):
    """Enumera instancias Redis sin autenticación (solo lectura)."""

    NAME = "recon/redis_enum"
    CATEGORIA = "recon"
    DESCRIPCION = ("Redis sin contraseña (RESP propio: PING/INFO/DBSIZE de "
                   "lectura): SIN_AUTH / PROTEGIDA / NO_REDIS")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Redis security guide · CWE-306"
    ATTCK = ("T1046",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "RHOST", "", True, "Host objetivo (IP o nombre)")
        self.opciones.declarar(
            "PUERTO", str(PUERTO_DEFECTO), False, "Puerto Redis (TCP)")
        self.opciones.declarar(
            "TIMEOUT", "6", False, "Timeout por conexión en segundos")

    def ejecutar(self) -> dict:
        host = self.opt("RHOST").strip()
        if not host:
            raise ModuloError("Indica el objetivo: set RHOST <host>")
        try:
            puerto = int(self.opt("PUERTO", str(PUERTO_DEFECTO)))
        except ValueError:
            puerto = PUERTO_DEFECTO
        timeout = self.opt_int("TIMEOUT", 6) or 6

        respuestas: Dict[str, str] = {}
        try:
            with socket.create_connection((host, puerto), timeout=timeout) as sock:
                sock.settimeout(timeout)
                for comando in ("PING", "INFO", "DBSIZE"):
                    sock.sendall(comando_resp(comando))
                    respuestas[comando] = _texto_simple(sock)
        except OSError as exc:
            raise ModuloError(f"Sin conexión Redis en {host}:{puerto} ({exc})")

        estado = clasificar_respuesta(respuestas)
        info = parsear_info(respuestas.get("INFO") or "") if estado == "SIN_AUTH" else {}
        dbsize = respuestas.get("DBSIZE", "")

        if estado == "SIN_AUTH":
            if self.workspace is not None:
                self.workspace.add_vuln(
                    host, "Redis sin autenticación", "alto",
                    f"versión {info.get('redis_version', '?')} · "
                    f"{dbsize or '?'} claves legibles sin credenciales",
                    self.NAME)

        resultado = {
            "host": f"{host}:{puerto}",
            "estado": estado,
            "info": info,
            "claves": dbsize if estado == "SIN_AUTH" else "",
        }
        return {
            "resumen": (f"Redis {host}:{puerto} → {estado}"
                        + (f" (v{info.get('redis_version', '?')}, {dbsize} claves)"
                           if estado == "SIN_AUTH" else "")),
            "resultados": [resultado],
            "nota": "Solo lectura: PING/INFO/DBSIZE. Una Redis SIN_AUTH expone "
                    "sesiones y tokens: exige requirepass y TLS, y aísla el puerto.",
        }
