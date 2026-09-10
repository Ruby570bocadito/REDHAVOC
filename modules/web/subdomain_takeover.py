# -*- coding: utf-8 -*-
"""
Módulo web/subdomain_takeover
=============================
Detecta subdominios candidatos a takeover (secuestro de subdominio):

    1. Resuelve el CNAME del subdominio con un cliente DNS propio (UDP/53).
    2. Pide HTTP(S) al subdominio SIN seguir redirecciones.
    3. Compara el código + cuerpo con las FIRMAS de servicios colgados
       (dangling): GitHub Pages, S3, Azure, CloudFront, Heroku, Shopify,
       Surge, Zendesk, Fastly, Bitbucket, Pantheon...

Un CNAME apuntando a un recurso liberado permite al atacante reclamar el
contenido del subdominio (phishing con el dominio legítimo + cookies de
dominio padre si hay wildcard).

Riesgo: BAJO-MEDIO (DNS + GET de lectura).
ATT&CK: T1584.006 (Compromise Infrastructure: Domain Properties) · CWE-350.
"""

import socket
import struct
from typing import Dict, List, Optional, Tuple

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# (clave de firma, servicio, frases del cuerpo que delatan recurso colgado)
_FIRMAS = (
    ("github", "GitHub Pages",
     ("there isn't a github pages site here", "404 there isn't")),
    ("s3", "AWS S3",
     ("nosuchbucket", "the specified bucket does not exist")),
    ("azure", "Azure (websites/cloudapp)",
     ("404 web site not found", "let's get you back on track")),
    ("cloudfront", "AWS CloudFront",
     ("bad request", "error: the request could not be satisfied")),
    ("heroku", "Heroku",
     ("no such app", "there's nothing here, yet")),
    ("shopify", "Shopify",
     ("sorry, this shop is currently unavailable",
      "only one step left!")),
    ("surge", "Surge.sh",
     ("project not found", "surge")),
    ("zendesk", "Zendesk",
     ("help center closed", "this help center no longer exists")),
    ("fastly", "Fastly",
     ("fastly error: unknown domain", "please check that this domain")),
    ("bitbucket", "Bitbucket Cloud",
     ("repository not found")),
    ("pantheon", "Pantheon",
     ("the gods are wise", "does not exist on pantheon")),
    ("unbounce", "Unbounce",
     ("the requested url was not found on this server", "unbounce")),
    ("helpjuice", "HelpJuice",
     ("we could not find what you're looking for")),
    ("tumblr", "Tumblr",
     ("there's nothing here.", "whatever you were looking for")),
    ("cargocollective", "Cargo Collective",
     ("404 not found")),
)


def fingerprint_tomaover(codigo: int, cuerpo: str) -> Tuple[str, str, bool]:
    """Clasifica la respuesta HTTP contra las firmas (función pura).

    Devuelve (servicio, evidencia, tomable). tomable exige 404/410 y una
    firma clara del recurso liberado.
    """
    bajo = (cuerpo or "").lower()[:50_000]
    if codigo in (404, 410):
        for clave, servicio, frases in _FIRMAS:
            for frase in frases:
                if frase in bajo:
                    return servicio, frase, True
        # 404 sin firma: probablemente la web real devuelve 404 propio
        return "desconocido", "", False
    if codigo == 200 and bajo:
        for clave, servicio, frases in _FIRMAS:
            for frase in frases:
                if frase in bajo and "surge" != clave:
                    return servicio, frase, False     # plataforma viva: no colgada
    return "desconocido", "", False


def cname_de(nombre: str, servidor: str, timeout: float = 4.0) -> Optional[str]:
    """Resuelve el CNAME con un cliente DNS UDP mínimo (sin dependencias).

    Devuelve el CNAME canónico o None si es A/AAAA directo o no responde.
    """
    partes = nombre.rstrip(".").split(".")
    if len(partes) < 2:
        return None
    try:
        qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in partes) + b"\x00"
    except Exception:  # noqa: BLE001 — dominio no codificable
        return None
    # Pregunta IN A con RD=1
    paquete = struct.pack(">HHHHHH", 0x5147, 0x0100, 1, 0, 0, 0) + qname + \
        struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(1.0, timeout))
    try:
        sock.sendto(paquete, (servidor, 53))
        datos, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    if len(datos) < 12:
        return None
    qd, an = struct.unpack(">H", datos[4:6])[0], struct.unpack(">H", datos[6:8])[0]
    pos = 12
    for _ in range(qd):                      # salta la pregunta
        while pos < len(datos) and datos[pos]:
            pos += datos[pos] + 1
        pos += 5
    for _ in range(an):                      # lee respuestas
        saltos = 0
        while True:                          # nombre (con compresión)
            if pos >= len(datos):
                return None
            largo = datos[pos]
            if largo == 0:
                pos += 1
                break
            if largo & 0xC0 == 0xC0:
                pos += 2
                break
            pos += largo + 1
            saltos += 1
            if saltos > 20:
                return None
        if pos + 10 > len(datos):
            return None
        tipo, _, _, _, rdlongitud = struct.unpack(">HHIH", datos[pos:pos + 10])
        pos += 10
        rdatos = datos[pos:pos + rdlongitud]
        pos += rdlongitud
        if tipo == 5 and rdatos:             # CNAME
            return _leer_nombre(rdatos, datos)
    return None


def _leer_nombre(rdatos: bytes, mensaje: bytes) -> str:
    """Lee un nombre DNS (con punteros de compresión)."""
    etiquetas: List[str] = []
    pos, saltado = 0, False
    while True:
        if pos >= len(rdatos):
            break
        largo = rdatos[pos]
        if largo == 0:
            break
        if largo & 0xC0 == 0xC0:
            if not saltado:
                saltado = True
                indice = ((largo & 0x3F) << 8) | rdatos[pos + 1]
                rdatos = mensaje
                pos = indice
            else:
                break
            continue
        etiquetas.append(rdatos[pos + 1:pos + 1 + largo].decode(
            "latin-1", errors="replace"))
        pos += largo + 1
    return ".".join(etiquetas) + "." if etiquetas else ""


class SubdomainTakeover(BaseModulo):
    """Detecta subdominios con CNAME colgado (takeover)."""

    NAME = "web/subdomain_takeover"
    CATEGORIA = "web"
    DESCRIPCION = ("Candidatos a takeover: CNAME a servicios liberados "
                   "(GitHub Pages, S3, Azure, Heroku, Shopify...) con firma "
                   "de recurso colgado")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "can-i-take-over-xyz · CWE-350"
    ATTCK = ("T1584.006",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "SUBDOMINIOS", "", True,
            "Subdominios a verificar, separados por coma")
        self.opciones.declarar(
            "DNS", "", False, "Servidor DNS recursivo (por defecto: del sistema)")

    def ejecutar(self) -> dict:
        bruto = self.opt("SUBDOMINIOS")
        subdominios = [s.strip().lower() for s in bruto.replace(";", ",").split(",")
                       if s.strip()]
        if not subdominios:
            raise ModuloError("Indica subdominios: set SUBDOMINIOS a.acme.com,b.acme.com")
        dns = self.opt("DNS").strip() or "1.1.1.1"
        timeout = self.opt_int("TIMEOUT", 6) or 6
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        filas: List[Dict] = []
        tomables: List[Dict] = []

        for sub in subdominios:
            cname = cname_de(sub, dns, timeout)
            fila: Dict = {"subdominio": sub, "cname": cname or "(sin CNAME)",
                          "servicio": "—", "estado": "no evaluado", "tomable": "no"}
            if cname:
                for esquema in ("https", "http"):
                    try:
                        resp = requests.get(
                            f"{esquema}://{sub}", timeout=timeout, verify=False,
                            headers=ua, allow_redirects=False)
                        break
                    except requests.RequestException:
                        resp = None
                if resp is None:
                    fila["estado"] = "sin respuesta HTTP"
                else:
                    servicio, evidencia, tomable = fingerprint_tomaover(
                        resp.status_code, resp.text)
                    fila["servicio"] = servicio
                    fila["estado"] = (f"HTTP {resp.status_code}"
                                      + (f" · firma: {evidencia}" if evidencia else ""))
                    fila["tomable"] = "sí" if tomable else "no"
                    if tomable:
                        tomables.append(fila)
            filas.append(fila)

            if fila["tomable"] == "sí" and self.workspace is not None:
                self.workspace.add_vuln(
                    sub, "Subdominio candidato a takeover", "alto",
                    f"CNAME {cname} → {fila['servicio']} colgado", self.NAME)

        nivel = "vulnerable" if tomables else "ok"
        return {
            "resumen": (f"{len(subdominios)} subdominios verificados: "
                        f"{len(tomables)} candidato(s) a takeover"),
            "nivel": nivel,
            "candidatos": tomables or "(ninguno)",
            "resultados": filas,
            "nota": "Verifica la propiedad del recurso liberado creando el "
                    "contenido de prueba SOLO si el proveedor lo permite y "
                    "el dominio es del cliente.",
        }
