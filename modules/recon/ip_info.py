# -*- coding: utf-8 -*-
"""
Módulo recon/ip_info
====================
Enumeración de información de una dirección IP o dominio: geolocalización,
ISP, ASN y resolución DNS inversa. Inspirado en track-ip / info-site de
ALHacking, reescrito en Python puro con la API pública gratuita ip-api.com.

Riesgo: BAJO (consulta APIs públicas sobre datos abiertos).
"""

import json
import socket
import urllib.request

from core.base_module import BaseModulo, ModuloError

API = "http://ip-api.com/json/{q}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query,reverse"


class IpInfo(BaseModulo):
    """Información geográfica y de red de una IP o dominio."""

    NAME = "recon/ip_info"
    CATEGORIA = "recon"
    DESCRIPCION = ("Geolocalización, ISP, ASN y DNS inverso de una IP o dominio "
                   "vía ip-api.com (sin API key).")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "htr-tech/track-ip · king-hacking/info-site"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "IP o dominio objetivo (p. ej. 8.8.8.8 o example.com)")

    def ejecutar(self) -> dict:
        objetivo = self._objetivo_host(self.opt("TARGET"))

        # Si es un dominio, resuélvelo a IP primero
        ip = objetivo
        try:
            socket.gethostbyname(objetivo)
        except socket.gaierror:
            raise ModuloError(f"No se puede resolver '{objetivo}'")

        try:
            with urllib.request.urlopen(API.format(q=ip), timeout=self.opt_int("TIMEOUT", 5) or 5) as resp:
                datos = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            raise ModuloError(f"Consulta a ip-api falló: {err}")

        if datos.get("status") != "success":
            raise ModuloError(f"ip-api respondió: {datos.get('message', 'error desconocido')}")

        # DNS inverso (best-effort)
        try:
            inverso = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            inverso = "(sin registro PTR)"

        resumen = (
            f"{datos.get('query')} → {datos.get('city', '?')} "
            f"({datos.get('country', '?')}), ISP: {datos.get('isp', '?')}"
        )
        return {
            "resumen": resumen,
            "ip": datos.get("query"),
            "objetivo_original": objetivo,
            "pais": datos.get("country"),
            "region": datos.get("regionName"),
            "ciudad": datos.get("city"),
            "codigo_postal": datos.get("zip"),
            "latitud": datos.get("lat"),
            "longitud": datos.get("lon"),
            "zona_horaria": datos.get("timezone"),
            "isp": datos.get("isp"),
            "organizacion": datos.get("org"),
            "as": datos.get("as"),
            "dns_inverso": inverso,
            "mobile": bool(datos.get("mobile")),
            "proxy": bool(datos.get("proxy")),
            "hosting": bool(datos.get("hosting")),
        }
