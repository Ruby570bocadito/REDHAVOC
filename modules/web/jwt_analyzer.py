# -*- coding: utf-8 -*-
"""
Módulo web/jwt_analyzer
=======================
Analiza tokens JWT (JSON Web Token, RFC 7519) de una URL o de la opción
TOKEN, sin librerías externas:

    1. Decodifica header/payload y muestra claims (sub, exp, role…).
    2. alg=none / algoritmo débil → hallazgo crítico (T1552/OWASP A02).
    3. secret débil HS256: prueba la wordlist con HMAC-SHA256 puro.
    4. exp/nbf caducados o inexistentes.
    5. Firma inválida (contra el secreto crackeado, si se encontró).
    6. kid con caracteres raros (posible inyección SQL en el header).

Riesgo: BAJO (peticiones GET normales; crackeo offline de la firma).
ATT&CK: T1552.001 (Credentials In Files) · OWASP API Security A2.
"""

import base64
import hashlib
import hmac
import json
import time

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECRETOS_DEBILES = ("secret", "password", "clave", "jwt_secret", "changeme",
                    "secreto", "123456", "supersecret", "clave_secreta",
                    "your-256-bit-secret", "test", "admin", "dev", "key")


# ---------------------------------------------------------------------------
# Utilidades JWT puras (sin dependencias)
# ---------------------------------------------------------------------------
def _b64url_decodificar(datos: bytes) -> bytes:
    """Base64url sin padding (RFC 7515)."""
    return base64.urlsafe_b64decode(datos + b"=" * (-len(datos) % 4))


def _b64url_codificar(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def dividir_token(token: str) -> dict:
    """Divide y decodifica un JWT. Lanza ModuloError si no es un JWT."""
    partes = token.strip().split(".")
    if len(partes) not in (2, 3):
        raise ModuloError("El token no es un JWT (se esperan 3 segmentos)")
    try:
        cabecera = json.loads(_b64url_decodificar(partes[0].encode()))
        payload = json.loads(_b64url_decodificar(partes[1].encode()))
    except (ValueError, json.JSONDecodeError) as err:
        raise ModuloError(f"JWT ilegible: {err}")
    firma = _b64url_decodificar(partes[2].encode()) if len(partes) == 3 else b""
    return {"header": cabecera, "payload": payload, "firma": firma,
            "partes": partes}


def verificar_firma_hs256(partes, secreto: str) -> bool:
    """Recalcula HMAC-SHA256(header.payload) y compara con la firma."""
    esperada = hmac.new(secreto.encode(),
                        f"{partes[0]}.{partes[1]}".encode(),
                        hashlib.sha256).digest()
    return hmac.compare_digest(esperada, _b64url_decodificar(partes[2].encode()))


def probar_secretos_debiles(partes, candidatos=SECRETOS_DEBILES) -> list:
    """Devuelve los secretos de la lista que verifican la firma HS256."""
    encontrados = []
    if len(partes) < 3:
        return encontrados
    for secreto in candidatos:
        if verificar_firma_hs256(partes, secreto):
            encontrados.append(secreto)
    return encontrados


class JwtAnalyzer(BaseModulo):
    """Audita JWTs: alg=none, secretos débiles, expiración y kid sospechoso."""

    NAME = "web/jwt_analyzer"
    CATEGORIA = "web"
    DESCRIPCION = ("Analiza JWT de una URL o token directo: alg=none, firma "
                   "HS256 con secretos débiles, exp/nbf caducados y kid "
                   "sospechoso (inyección). Decodificación y crack puro Python.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP JWT Cheat Sheet · jwt-analyzer de PortSwigger"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", False,
                               "URL que devuelve un JSON con token (claves "
                               "token/access_token/jwt) — o deja TOKEN")
        self.opciones.declarar("TOKEN", "", False, "JWT en crudo (si no hay URL)")
        self.opciones.declarar("CRACK", "true", False,
                               "Probar secretos débiles si el alg es HS256")

    def ejecutar(self) -> dict:
        token = self.opt("TOKEN").strip()
        if not token:
            token = self._token_de_url()
        if not token:
            raise ModuloError("Sin TOKEN ni URL que lo devuelva")

        token = token.replace("Bearer ", "").strip()
        decodificado = dividir_token(token)
        cabecera, payload, partes = (decodificado["header"],
                                     decodificado["payload"],
                                     decodificado["partes"])
        algoritmo = str(cabecera.get("alg", "?"))
        hallazgos = []

        # 1) alg=none / sin firma
        if algoritmo.lower() == "none" or len(partes) == 2:
            hallazgos.append({
                "severidad": "critico", "titulo": "alg=none o token sin firma",
                "detalle": "El token se acepta sin verificación de firma: "
                           "cualquiera puede forjar claims (role=admin).",
            })

        # 2) algoritmos asimétricos confundidos con simétricos
        if algoritmo.startswith("RS") or algoritmo.startswith("ES"):
            hallazgos.append({
                "severidad": "info",
                "titulo": f"algoritmo asimétrico {algoritmo}",
                "detalle": "Probar confusión de algoritmos (RS256→HS256) solo "
                           "si la librería del servidor confía en el header.",
            })

        # 3) secreto débil HS256
        secreto_roto = ""
        if self.opt_bool("CRACK", True) and algoritmo.upper() == "HS256":
            debiles = probar_secretos_debiles(partes)
            if debiles:
                secreto_roto = debiles[0]
                hallazgos.append({
                    "severidad": "critico", "titulo": "secreto HS256 débil",
                    "detalle": f"La firma verifica con el secreto {debiles[0]!r}: "
                               "se pueden firmar tokens arbitrarios.",
                })

        # 4) expiración
        ahora = time.time()
        exp = payload.get("exp")
        if exp is None:
            hallazgos.append({"severidad": "medio",
                              "titulo": "sin claim exp",
                              "detalle": "El token no caduca nunca."})
        elif float(exp) < ahora:
            hallazgos.append({"severidad": "bajo", "titulo": "token caducado",
                              "detalle": f"exp era {time.strftime('%Y-%m-%d %H:%M', time.gmtime(float(exp)))} UTC."})
        nbf = payload.get("nbf")
        if nbf is not None and float(nbf) > ahora:
            hallazgos.append({"severidad": "info", "titulo": "nbf en el futuro",
                              "detalle": "El token aún no es válido (nbf futuro)."})

        # 5) kid sospechoso (inyección SQL / path traversal)
        kid = str(cabecera.get("kid", ""))
        if any(m in kid.lower() for m in ("'", "\"", "..", "/", "union", "--")):
            hallazgos.append({
                "severidad": "alto", "titulo": "kid sospechoso",
                "detalle": "El kid contiene caracteres de inyección: la librería "
                           "podría interpolarse en SQL o en rutas de fichero.",
            })

        gravedad = ("critico" if any(h["severidad"] == "critico" for h in hallazgos)
                    else "alto" if any(h["severidad"] == "alto" for h in hallazgos)
                    else "medio" if any(h["severidad"] == "medio" for h in hallazgos)
                    else "ok")
        # Hallazgos graves → workspace.vulns
        for h in hallazgos:
            if h["severidad"] in ("alto", "critico"):
                self.ctx.workspace.add_vuln(
                    self._objetivo_host(self.opt("URL")) or "(token)",
                    f"JWT: {h['titulo']}", h["severidad"], h["detalle"], self.NAME)
        resumen = f"JWT analizado ({algoritmo}): {len(hallazgos)} hallazgo(s) — {gravedad}"
        return {
            "resumen": resumen,
            "algoritmo": algoritmo,
            "header": cabecera,
            "payload": payload,
            "firma_hex": decodificado["firma"].hex() if decodificado["firma"] else "",
            "hallazgos": hallazgos,
            "secreto_roto": secreto_roto,
            "gravedad": gravedad,
        }

    # ------------------------------------------------------------------
    def _token_de_url(self) -> str:
        """Descarga la URL y extrae el token del JSON de respuesta."""
        url = self.opt("URL").strip()
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            resp = requests.get(url, timeout=self.opt_int("TIMEOUT", 5) or 5,
                                verify=False,
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")
        if resp.status_code >= 400:
            raise ModuloError(f"El endpoint devuelve HTTP {resp.status_code}")
        try:
            datos = resp.json()
        except ValueError:
            raise ModuloError("La respuesta no es JSON (¿endpoint equivocado?)")
        if isinstance(datos, dict):
            for clave in ("token", "access_token", "jwt", "id_token"):
                if clave in datos and isinstance(datos[clave], str):
                    return datos[clave]
        raise ModuloError("No se encontró token en el JSON "
                          "(claves buscadas: token/access_token/jwt/id_token)")
