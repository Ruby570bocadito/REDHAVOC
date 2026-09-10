# -*- coding: utf-8 -*-
"""
Módulo recon/subdomain_scan
===========================
Descubrimiento de subdominios por resolución DNS masiva de una wordlist.
Wordlist integrada de ~120 entradas habituales.

Riesgo: BAJO-MEDIO (solo consultas DNS; no toca los servidores web).
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

WORDLIST = Path(__file__).resolve().parent.parent.parent / "templates" / "wordlists" / "subdomains.txt"


def _resuelve(nombre: str):
    """Devuelve (nombre, [ips]) si el subdominio resuelve, si no None."""
    try:
        infos = socket.getaddrinfo(nombre, None, socket.AF_INET)
        ips = sorted({i[4][0] for i in infos})
        return nombre, ips
    except (socket.gaierror, OSError):
        return None


class SubdomainScan(BaseModulo):
    """Enumera subdominios resolviendo una wordlist contra el dominio."""

    NAME = "recon/subdomain_scan"
    CATEGORIA = "recon"
    DESCRIPCION = ("Descubrimiento de subdominios mediante resolución DNS "
                   "masiva de wordlist integrada o personalizada.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "zidansec/subscan · Amass (simplificado)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio raíz (p. ej. example.com)")
        self.opciones.declarar("WORDLIST", "", False, "Wordlist personalizada (ruta); por defecto usa la integrada")

    def _cargar_wordlist(self) -> list:
        """Carga la wordlist de subdominios (personalizada o integrada)."""
        ruta = self.opt("WORDLIST")
        fichero = Path(ruta) if ruta else WORDLIST
        if not fichero.exists():
            raise ModuloError(f"Wordlist no encontrada: {fichero}")
        return [l.strip().lower() for l in fichero.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN")).lstrip(".")
        hilos = min(self.opt_int("THREADS", 10) or 10, 50)
        candidatos = self._cargar_wordlist()

        dominios = [f"{sub}.{dominio}" for sub in candidatos]
        encontrados = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = {pool.submit(_resuelve, d): d for d in dominios}
            for futuro in as_completed(futuros):
                resultado = futuro.result()
                if resultado:
                    encontrados.append({"subdominio": resultado[0], "ips": resultado[1]})

        encontrados.sort(key=lambda x: x["subdominio"])
        resumen = f"{dominio}: {len(encontrados)} subdominios resueltos de {len(dominios)} probados"
        return {
            "resumen": resumen,
            "dominio": dominio,
            "probados": len(dominios),
            "encontrados": encontrados,
        }
