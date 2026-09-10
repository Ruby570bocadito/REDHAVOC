# -*- coding: utf-8 -*-
"""
Módulo recon/smtp_enum
======================
Enumeración de usuarios contra un servidor SMTP autorizado usando los
comandos VRFY y EXPN (RFC 821) y comprobación RCPT TO opcional:

    VRFY juan   → 250 2.1.9 <juan@dominio>     (el buzón existe)
    VRFY nadie  → 550 2.1.9 …                  (no existe)
    EXPN lista  → miembros de una lista de distribución

Los servidores bien configurados responden 252/502 (no divultan); la
enumeración exitosa indica una configuración laxa útil para el informe.

Cliente SMTP a mano sobre socket (sin smtplib: control fino de códigos).

Riesgo: MEDIO (peticiones legítimas al servicio, ruido bajo).
ATT&CK: T1018 (Remote System Discovery) · T1087 (Account Discovery).
"""

import socket
import time
from pathlib import Path
from typing import Dict, List, Optional

from core.base_module import BaseModulo, ModuloError


def clasificar_respuesta(codigo: int, texto: str) -> str:
    """Clasifica la respuesta SMTP a VRFY/EXPN/RCPT (función pura).

    Devuelve 'existe' | 'no_existe' | 'no_divulga' | 'error'.
    """
    codigo = int(codigo)
    if codigo in (250, 251, 252) and any(
            marca in texto.lower() for marca in ("@", "<", "accepted", "ok")):
        # 252 con "cannot VRFY" es NO divulga; con buzón es existe
        if codigo == 252 and "cannot" in texto.lower():
            return "no_divulga"
        return "existe" if codigo in (250, 251) else "no_divulga"
    if codigo in (550, 551, 553):
        return "no_existe"
    if codigo in (252,):
        return "no_divulga"
    if codigo in (502, 500, 503):
        return "no_divulga"
    if 400 <= codigo < 500:
        return "error"          # 4xx temporal (greylisting, rate limit)
    return "error"


def parsear_saludo(banner: str) -> Dict[str, str]:
    """Extrae datos útiles del 220 inicial (ESMTP, ETRN, STARTTLS…)."""
    limpio = banner.replace("\r", " ").replace("\n", " ").strip()
    datos = {"banner": limpio}
    baja = limpio.lower()
    if "postfix" in baja:
        datos["mta"] = "Postfix"
    elif "exchange" in baja or "microsoft esmtp" in baja:
        datos["mta"] = "Microsoft Exchange"
    elif "sendmail" in baja:
        datos["mta"] = "Sendmail"
    elif "exim" in baja:
        datos["mta"] = "Exim"
    elif "smtpd" in baja or "esmtp" in baja:
        datos["mta"] = "ESMTP genérico"
    else:
        datos["mta"] = "?"
    return datos


class SmtpEnum(BaseModulo):
    """Enumera buzones válidos en un SMTP con VRFY/EXPN/RCPT."""

    NAME = "recon/smtp_enum"
    CATEGORIA = "recon"
    DESCRIPCION = ("Enumeración de buzones SMTP con VRFY/EXPN y RCPT TO "
                   "(cliente propio sobre socket, estilo smtp-user-enum)")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "smtp-user-enum · RFC 821 VRFY/EXPN"
    ATTCK = ("T1087", "T1018")

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "Host SMTP objetivo")
        self.opciones.declarar("PUERTO", "25", False, "Puerto SMTP (25/465/587)")
        self.opciones.declarar("USUARIOS", "", True,
                               "Lista de buzones a verificar (fichero @ruta o coma)")
        self.opciones.declarar("METODO", "VRFY", False, "VRFY | EXPN | RCPT")
        self.opciones.declarar("HELO", "redhavoc.lab", False, "Nombre HELO/EHLO")

    # ------------------------------------------------------------------
    def _conectar(self, timeout: float) -> socket.socket:
        try:
            s = socket.create_connection(
                (self.opt("RHOST").strip(), self.opt_int("PUERTO", 25) or 25),
                timeout=timeout)
        except OSError as err:
            raise ModuloError(f"No se pudo conectar al SMTP: {err}")
        s.settimeout(timeout)
        return s

    @staticmethod
    def _leer(s: socket.socket) -> str:
        """Lee una respuesta SMTP multilínea (termina en 'NNN ')."""
        buf = b""
        fin = time.time() + 8
        while time.time() < fin:
            try:
                trozo = s.recv(4096)
            except socket.timeout:
                break
            if not trozo:
                break
            buf += trozo
            texto = buf.decode(errors="replace")
            lineas = [l for l in texto.splitlines() if l.strip()]
            if lineas and len(lineas[-1]) >= 4 and lineas[-1][3] == " ":
                break
        return buf.decode(errors="replace")

    def _verificar(self, s: socket.socket, comando: str, buzón: str,
                   metodo: str) -> Dict[str, str]:
        if metodo == "RCPT":
            secuencia = (f"MAIL FROM:<sondeo@redhavoc.lab>\r\n"
                         f"RCPT TO:<{buzón}>\r\n")
            s.sendall(secuencia.encode())
            respuesta = self._leer(s) + self._leer(s)
            # RCPT 250 = buzón aceptado; 550 = rechazado
            codigo = 0
            for linea in respuesta.splitlines():
                if linea[:3].isdigit():
                    codigo = int(linea[:3])
            # cierra el MAIL para no ensuciar la siguiente prueba
            s.sendall(b"RSET\r\n")
            self._leer(s)
            clas = ("existe" if codigo == 250 else
                    "no_existe" if codigo in (550, 551, 553) else "no_divulga")
            return {"usuario": buzón, "codigo": codigo,
                    "respuesta": respuesta.replace("\r\n", " | ").strip(),
                    "estado": clas}
        s.sendall(f"{metodo} {buzón}\r\n".encode())
        respuesta = self._leer(s)
        linea = next((l for l in respuesta.splitlines() if l[:3].isdigit()), "000")
        codigo = int(linea[:3]) if linea[:3].isdigit() else 0
        return {"usuario": buzón, "codigo": codigo,
                "respuesta": respuesta.replace("\r\n", " | ").strip(),
                "estado": clasificar_respuesta(codigo, respuesta)}

    def ejecutar(self) -> dict:
        rhost = self.opt("RHOST").strip()
        puerto = self.opt_int("PUERTO", 25) or 25
        metodo = self.opt("METODO").upper().strip()
        if metodo not in ("VRFY", "EXPN", "RCPT"):
            raise ModuloError("METODO debe ser VRFY, EXPN o RCPT")
        usuarios = self._cargar_usuarios(self.opt("USUARIOS"))
        if not usuarios:
            raise ModuloError("USUARIOS vacío: pásalo como lista coma o fichero "
                              "(set USUARIOS @templates/wordlists/ad_usuarios.txt)")
        timeout = self.opt_int("TIMEOUT", 5) or 5

        with self._conectar(timeout) as s:
            banner = self._leer(s)
            saludo = parsear_saludo(banner)
            if not banner.startswith("220"):
                raise ModuloError(f"No es un SMTP válido: {saludo['banner'][:80]}")
            s.sendall(f"HELO {self.opt('HELO') or 'redhavoc.lab'}\r\n".encode())
            self._leer(s)

            resultados: List[Dict] = []
            for buzón in usuarios:
                buzón = buzón.strip()
                if not buzón or buzón.startswith("#"):
                    continue
                try:
                    resultados.append(self._verificar(s, None, buzón, metodo))
                except (OSError, socket.timeout):
                    resultados.append({"usuario": buzón, "codigo": 0,
                                       "respuesta": "sin respuesta", "estado": "error"})

            s.sendall(b"QUIT\r\n")

        existe = [r for r in resultados if r["estado"] == "existe"]
        no_divulga = all(r["estado"] == "no_divulga" for r in resultados
                         if r["estado"] != "error")

        if self.workspace is not None and existe:
            for r in existe:
                self.workspace.add_host(rhost, notas=f"SMTP {puerto}")
            self.workspace.add_vuln(
                rhost, "Enumeración de usuarios SMTP posible", "medio",
                f"{metodo} devuelve buzones válidos ({len(existe)}/{len(resultados)})",
                self.NAME)

        return {
            "resumen": (f"{rhost}:{puerto} · {metodo}: {len(existe)}/{len(resultados)} "
                        f"buzones confirmados"
                        + ("" if existe else " (el servidor no divulga)" if no_divulga else "")),
            "host": f"{rhost}:{puerto}",
            "mta": saludo.get("mta", "?"),
            "banner": saludo.get("banner", "")[:120],
            "metodo": metodo,
            "usuarios": resultados,
            "validos": [r["usuario"] for r in existe],
        }

    @staticmethod
    def _cargar_usuarios(especificacion: str) -> List[str]:
        """Carga usuarios desde 'a,b,c' o '@fichero' (función pura de ruta)."""
        texto = (especificacion or "").strip()
        if not texto:
            return []
        if texto.startswith("@"):
            try:
                contenido = Path(texto[1:]).read_text(encoding="utf-8")
                return [l.strip() for l in contenido.splitlines()
                        if l.strip() and not l.lstrip().startswith("#")]
            except OSError:
                return []
        return [u.strip() for u in texto.split(",") if u.strip()]
