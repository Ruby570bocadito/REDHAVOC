# -*- coding: utf-8 -*-
"""
Módulo osint/email_verify
=========================
Verificación de existencia de buzones por SMTP (RCPT TO sin enviar
mensaje): resuelve el MX del dominio con el cliente DNS propio de
recon/dns_enum, abre sesión y pregunta por cada correo.

Muchos servidores responden «unknown» (greylisting): el módulo clasifica
confirmado / inexistente / desconocido y NUNCA envía cuerpo de mensaje.
Idea de: reconmap (verificación SMTP) · mailrecon.

Riesgo: MEDIO (el sondeo RCPT puede considerarse abuso; usar solo con
autorización y con pausa). ATT&CK: T1589.002 (Email Addresses).
"""

import random
import smtplib
import socket
import time
from typing import Dict, List, Tuple

from core.base_module import BaseModulo, ModuloError
from modules.recon.dns_enum import TIPOS, _consultar, _parsear_respuesta
from modules.ad.kerberos_userenum import cargar_lista

PUERTO = 25


def resolver_mx(dominio: str, timeout: int = 5) -> List[Tuple[int, str]]:
    """Resuelve los MX del dominio con el cliente DNS propio (UDP/53)."""
    resolver = ""
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for linea in fh:
                if linea.startswith("nameserver"):
                    resolver = linea.split()[1]
                    break
    except OSError:
        pass
    resolver = resolver or "1.1.1.1"
    paquete = _consultar(resolver, dominio, TIPOS["MX"], timeout)
    parsed = _parsear_respuesta(paquete, TIPOS["MX"])
    registros = []
    for fila in parsed["respuestas"]:
        partes = fila.split()
        if len(partes) == 2 and partes[0].isdigit():
            registros.append((int(partes[0]), partes[1]))
    return sorted(registros)


class EmailVerify(BaseModulo):
    """Verifica buzones por RCPT TO contra el MX del dominio."""

    NAME = "osint/email_verify"
    CATEGORIA = "osint"
    DESCRIPCION = ("Verificación SMTP de buzones (RCPT TO, sin enviar correo): "
                   "confirma si un correo existe. Requiere puerto 25 saliente; "
                   "degrada con elegancia si está bloqueado.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (SMTP probe) · MITRE ATT&CK T1589.002"
    ATTCK = ("T1589.002",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("CORREOS", "", True,
                               "Correos separados por comas o fichero @ruta")
        self.opciones.declarar("HELO", "redhavoc.lab", False, "Nombre HELO a presentar")
        self.opciones.declarar("PUERTO", "25", False, "Puerto SMTP del MX")
        self.opciones.declarar("PAUSA_MS", "400", False, "Pausa entre RCPT (ms)")

    def ejecutar(self) -> dict:
        correos = cargar_lista(self.opt("CORREOS"))
        if not correos:
            raise ModuloError("Sin correos que verificar")
        helo = self.opt("HELO").strip() or "redhavoc.lab"
        puerto = self.opt_int("PUERTO", 25) or 25
        pausa = (self.opt_int("PAUSA_MS", 400) or 400) / 1000.0
        timeout = self.opt_int("TIMEOUT", 10) or 10

        # cache de MX por dominio
        mx_por_dominio: Dict[str, str] = {}
        resultados = []
        confirmados, inexistentes, desconocidos = [], [], []

        for correo in correos:
            if "@" not in correo:
                resultados.append({"correo": correo, "estado": "invalido"})
                continue
            dominio = correo.split("@", 1)[1].lower()
            if dominio not in mx_por_dominio:
                try:
                    registros = resolver_mx(dominio, timeout=timeout)
                    mx_por_dominio[dominio] = registros[0][1] if registros else ""
                except (socket.timeout, TimeoutError, OSError):
                    mx_por_dominio[dominio] = ""
            mx = mx_por_dominio.get(dominio, "")
            if not mx:
                estado = "sin_mx"
            else:
                estado = self._rcpt(mx, puerto, helo, correo, timeout)
                if pausa:
                    time.sleep(pausa)

            resultados.append({"correo": correo, "estado": estado, "mx": mx})
            if estado == "confirmado":
                confirmados.append(correo)
            elif estado == "inexistente":
                inexistentes.append(correo)
            elif estado not in ("invalido",):
                desconocidos.append(correo)

        if all(r["estado"] == "sin_mx" for r in resultados):
            raise ModuloError("No se pudo resolver el MX de ningún dominio "
                              "(¿el puerto 53/25 está bloqueado en esta red?)")

        return {
            "resumen": (f"Verificación SMTP: {len(confirmados)} confirmados, "
                        f"{len(inexistentes)} inexistentes, {len(desconocidos)} desconocidos"),
            "resultados": resultados,
            "confirmados": confirmados,
            "inexistentes": inexistentes,
            "desconocidos": desconocidos,
            "nota": "RCPT TO no envía mensaje. Greylisting frecuente = 'desconocido'.",
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _rcpt(mx: str, puerto: int, helo: str, correo: str, timeout: int) -> str:
        """Hace MAIL FROM + RCPT TO y clasifica la respuesta."""
        try:
            con = smtplib.SMTP(mx, puerto, timeout=timeout)
        except (OSError, smtplib.SMTPException):
            return "mx_inaccesible"
        try:
            con.helo(helo)
            estado_mail = con.docmd("MAIL", f"FROM:<sondeo@{helo}>")
            if estado_mail[0] != 250:
                return "mail_rechazado"
            estado_rcpt = con.docmd("RCPT", f"TO:<{correo}>")
            con.docmd("RSET")
            if estado_rcpt[0] == 250:
                return "confirmado"
            if estado_rcpt[0] in (550, 551, 553):
                return "inexistente"
            return "desconocido"
        except (OSError, smtplib.SMTPException):
            return "desconocido"
        finally:
            try:
                con.quit()
            except Exception:  # noqa: BLE001
                con.close()
