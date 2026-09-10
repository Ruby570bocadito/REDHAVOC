# -*- coding: utf-8 -*-
"""
Módulo brute/ftp_login
======================
Auditoría de credenciales débiles sobre FTP (RFC 959) con la librería
estándar (ftplib). Prueba el par usuario/clave contra el servidor
objetivo y detiene la prueba en cuanto encuentra una válida.

Diseñado para verificar contraseñas por defecto en LABORATORIOS o
servidores propios tras un pentest autorizado. El límite de intentos
(MAX_INTENTOS) mantiene la prueba acotada y evita bloqueos de cuenta.

Riesgo: ALTO → exige AUTHORIZED (acceso no autorizado = delito).
Las credenciales válidas se guardan en el workspace (comando `creds`).
"""

import ftplib

from core.base_module import BaseModulo, ModuloError
from modules.brute import claves_desde_listas, usuarios_desde_listas


class FtpLogin(BaseModulo):
    """Prueba pares usuario/clave contra un servicio FTP."""

    NAME = "brute/ftp_login"
    CATEGORIA = "brute"
    DESCRIPCION = ("Auditoría de credenciales débiles/default en FTP (ftplib, "
                   "sin dependencias). Para servidores propios o autorizados. "
                   "Guarda los aciertos en el workspace.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "hydra (FTP module, acotado) · routersploit default creds"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Host FTP objetivo (IP o dominio)")
        self.opciones.declarar(
            "RHOSTS", "", False,
            "Multi-host estilo NetExec: 10.0.0.0/24, 10.0.0.1-20, n1,n2 o @fichero")
        self.opciones.declarar("PORT", "21", False, "Puerto FTP")
        self.opciones.declarar("USERS", "usuarios_lab.txt", False,
                               "Wordlist de usuarios incluida, ruta o lista separada por comas")
        self.opciones.declarar("PASS", "claves_lab.txt", False,
                               "Wordlist de claves incluida, ruta o lista separada por comas")
        self.opciones.declarar("MAX_INTENTOS", "50", False,
                               "Máximo de pares a probar (tope ético)")

    def _probar_par(self, host: str, puerto: int, usuario: str, clave: str,
                    timeout: float) -> bool:
        """Devuelve True si el par usuario/clave es válido."""
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(host, puerto, timeout=timeout)
                ftp.login(usuario, clave)
                return True
        except ftplib.error_perm:
            return False           # credenciales rechazadas
        except (OSError, ftplib.all_errors) as err:  # noqa: B014
            # error_perm es subclase de all_errors; OSError = red
            if isinstance(err, ftplib.error_perm):
                return False
            raise ModuloError(f"Error de conexión FTP: {err}")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("TARGET"))
        puerto = self.opt_int("PORT", 21)
        timeout = self.opt_int("TIMEOUT", 5) or 5
        max_intentos = max(1, min(self.opt_int("MAX_INTENTOS", 50), 200))

        usuarios = usuarios_desde_listas(self.opt("USERS"), max_intentos)
        claves = claves_desde_listas(self.opt("PASS"), max_intentos)
        if not usuarios or not claves:
            raise ModuloError("No se han resuelto usuarios o claves de las listas")

        # Banner inicial del servidor (útil para el informe)
        banner = ""
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(host, puerto, timeout=timeout)
                banner = ftp.getwelcome()[:120]
        except ftplib.error_perm as err:
            banner = str(err)[:120]
        except OSError as err:
            raise ModuloError(f"No se puede conectar a {host}:{puerto} — {err}")

        probados = 0
        validos = []
        parar = False
        for usuario in usuarios:
            if parar:
                break
            for clave in claves:
                if probados >= max_intentos:
                    parar = True
                    break
                probados += 1
                if self._probar_par(host, puerto, usuario, clave, timeout):
                    validos.append({"usuario": usuario, "clave": clave})
                    self._registrar_credencial(host, usuario, clave)
                    parar = True  # un acierto basta para la auditoría
                    break

        return {
            "resumen": (f"FTP {host}:{puerto} — {probados} pares probados, "
                        f"{len(validos)} válidos"),
            "host": host,
            "puerto": puerto,
            "banner": banner,
            "pares_probados": probados,
            "credenciales_validas": validos,
        }

    def _registrar_credencial(self, host: str, usuario: str, clave: str) -> None:
        """Guarda el acierto en la DB del workspace (si hay contexto)."""
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)
        if db is not None:
            try:
                db.add_cred(host, usuario, clave, servicio="ftp")
            except Exception:  # noqa: BLE001
                pass
