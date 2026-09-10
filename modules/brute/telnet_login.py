# -*- coding: utf-8 -*-
"""
Módulo brute/telnet_login
=========================
Auditoría de credenciales débiles sobre Telnet (RFC 854) con socket puro:
espera los prompts de login/password, envía el par y VERIFICA con un
comando eco (default `echo RHV_OK`) en lugar de adivinar por el banner —
evita falsos positivos típicos de Telnet.

Acotado por diseño: MAX_INTENTOS (tope duro 200) y parada al primer acierto.
Para routers/switches de TU laboratorio o infraestructura autorizada.

Riesgo: ALTO → exige AUTHORIZED (acceso no autorizado = delito).
Las credenciales válidas se guardan en el workspace (comando `creds`).
"""

import socket
import time
from typing import Optional, Tuple

from core.base_module import BaseModulo, ModuloError
from modules.brute import claves_desde_listas, usuarios_desde_listas

# Sentencias que delatan el fallo de autenticación en la mayoría de TTYS
FRASES_FALLO = ("incorrect", "invalid", "failed", "denied", "wrong",
                "authentication", "login:", "username:", "password:")


def interpreta_sesion(transcripcion: str, marca: str) -> bool:
    """Decide si el par fue válido a partir de la transcripción (función pura).

    Válido ⇔ la marca de eco aparece y no hay re-prompt de login ni frases
    de fallo después del último intento.
    """
    bajo = transcripcion.lower()
    if marca.lower() not in bajo:
        return False
    tras_marca = bajo[bajo.rindex(marca.lower()):]
    return not any(f in tras_marca for f in FRASES_FALLO)


def siguiente_prompt(buffer: str) -> Optional[str]:
    """Devuelve el prompt detectado en el buffer (función pura).

    'login' | 'password' | 'shell' | None.
    """
    bajo = buffer.lower()
    if bajo.endswith(("assword:", "assword: ")):
        return "password"
    for marca in ("login:", "username:"):
        if marca in bajo:
            return "login"
    if bajo.rstrip().endswith(("#", "$", ">")):
        return "shell"
    return None


class TelnetLogin(BaseModulo):
    """Prueba pares usuario/clave contra un servicio Telnet (socket puro)."""

    NAME = "brute/telnet_login"
    CATEGORIA = "brute"
    DESCRIPCION = ("Auditoría de credenciales en Telnet (socket puro, verificación "
                   "por eco). Para routers/hosts de tu lab. Guarda los aciertos.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "hydra (telnet, acotado) · routersploit default creds"
    ATTCK = ("T1110.001", "T1110.004")

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Host Telnet objetivo")
        self.opciones.declarar(
            "RHOSTS", "", False,
            "Multi-host estilo NetExec: 10.0.0.0/24, 10.0.0.1-20, n1,n2 o @fichero")
        self.opciones.declarar("PORT", "23", False, "Puerto Telnet")
        self.opciones.declarar("USERS", "usuarios_lab.txt", False,
                               "Wordlist de usuarios incluida, ruta o lista por comas")
        self.opciones.declarar("PASS", "claves_lab.txt", False,
                               "Wordlist de claves incluida, ruta o lista por comas")
        self.opciones.declarar("MAX_INTENTOS", "30", False,
                               "Máximo de pares a probar (tope ético)")

    # ------------------------------------------------------------------
    def _sesion_telnet(self, host: str, puerto: int, usuario: str, clave: str,
                       timeout: float, marca: str) -> Tuple[bool, str]:
        """Ejecuta una sesión Telnet completa y devuelve (válida, transcripción)."""
        transcripcion = ""
        try:
            with socket.create_connection((host, puerto), timeout=timeout) as s:
                s.settimeout(timeout)
                # IAC: el servidor puede enviar negociación telnet; la aceptamos
                # a lo bruto respondiendo WONT/DONT (bytes 255 = IAC).
                def _leer(hasta_seg: float) -> str:
                    datos = b""
                    fin = time.time() + hasta_seg
                    while time.time() < fin:
                        try:
                            trozo = s.recv(4096)
                        except socket.timeout:
                            break
                        if not trozo:
                            break
                        datos += trozo
                        texto = datos.decode(errors="replace")
                        # responde a las negociaciones IAC para no bloquear
                        if 255 in trozo:
                            s.sendall(b"\xff\xfc\x01\xff\xfc\x18")  # WONT ECHO/WONT TTYPE
                        if siguiente_prompt(texto):
                            return texto
                    return datos.decode(errors="replace")

                transcripcion += _leer(timeout)
                s.sendall((usuario + "\r\n").encode())
                transcripcion += _leer(timeout)
                s.sendall((clave + "\r\n").encode())
                transcripcion += _leer(max(2.0, timeout))
                # verificación por eco: si entramos, el shell ejecuta el echo
                s.sendall(f"echo {marca}\r\n".encode())
                transcripcion += _leer(max(2.0, timeout))
                s.sendall(b"exit\r\n")
        except OSError as err:
            raise ModuloError(f"Error de conexión Telnet: {err}")
        return interpreta_sesion(transcripcion, marca), transcripcion

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("TARGET"))
        puerto = self.opt_int("PORT", 23) or 23
        timeout = self.opt_int("TIMEOUT", 5) or 5
        max_intentos = max(1, min(self.opt_int("MAX_INTENTOS", 30), 200))

        usuarios = usuarios_desde_listas(self.opt("USERS"), max_intentos)
        claves = claves_desde_listas(self.opt("PASS"), max_intentos)
        if not usuarios or not claves:
            raise ModuloError("No se han resuelto usuarios o claves de las listas")

        probados, validos, muestra_fallo = 0, [], ""
        for usuario in usuarios:
            for clave in claves:
                if probados >= max_intentos:
                    break
                probados += 1
                marca = f"RHV_OK_{probados:02d}"
                ok, transcripcion = self._sesion_telnet(
                    host, puerto, usuario, clave, timeout, marca)
                if ok:
                    validos.append({"usuario": usuario, "clave": clave})
                    self._registrar_credencial(host, usuario, clave)
                    break
                if not muestra_fallo and transcripcion:
                    muestra_fallo = " ".join(transcripcion.split())[:120]
            else:
                continue
            break

        return {
            "resumen": (f"Telnet {host}:{puerto} — {probados} pares probados, "
                        f"{len(validos)} válidos"),
            "host": host,
            "puerto": puerto,
            "pares_probados": probados,
            "credenciales_validas": validos,
            "muestra_transcripcion": muestra_fallo,
        }

    def _registrar_credencial(self, host: str, usuario: str, clave: str) -> None:
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)
        if db is not None:
            try:
                db.add_cred(host, usuario, clave, servicio="telnet")
            except Exception:  # noqa: BLE001
                pass
