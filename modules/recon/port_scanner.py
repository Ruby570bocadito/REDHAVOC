# -*- coding: utf-8 -*-
"""
Módulo recon/port_scanner
=========================
Escáner TCP connect multihilo con captura de banner de servicio.
Incluye detección básica de servicios por puerto conocido.

Riesgo: MEDIO (contacto directo con los puertos del objetivo).
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModulo, ModuloError

# Servicios habituales para etiquetar puertos
SERVICIOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def _escanear_puerto(host: str, puerto: int, timeout: float, capturar_banner: bool):
    """Intenta conectar TCP; devuelve (puerto, abierto, servicio, banner)."""
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            banner = ""
            if capturar_banner:
                try:
                    # Los banners reales (SSH/FTP/SMTP) llegan en milisegundos.
                    # Esperar el timeout completo penalizaría a los servicios
                    # que no envían nada al conectar (HTTP espera la petición).
                    sock.settimeout(min(timeout, 1.0))
                    banner = sock.recv(128).decode(errors="replace").strip()
                except (OSError, socket.timeout):
                    banner = ""
            return puerto, True, SERVICIOS.get(puerto, "?"), banner
    except OSError:
        return puerto, False, None, ""


class PortScanner(BaseModulo):
    """Escáner de puertos TCP con banner grabbing."""

    NAME = "recon/port_scanner"
    CATEGORIA = "recon"
    DESCRIPCION = ("Escáner TCP connect multihilo con banner grabbing y "
                   "etiquetado de servicios habituales.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "nmap (simplificado) · RED_HAWK (port scan)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Host objetivo (IP o dominio)")
        self.opciones.declarar("PORTS", "21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017", False,
                               "Puertos: lista separada por comas o rango 1-1000")
        self.opciones.declarar("BANNER", "true", False, "Capturar banner de servicio (true/false)")

    def _parsear_puertos(self, especificacion: str) -> list:
        """Convierte '80,443,8000-8100' en una lista de enteros."""
        puertos = set()
        for trozo in especificacion.split(","):
            trozo = trozo.strip()
            if "-" in trozo:
                inicio, fin = trozo.split("-", 1)
                if not (inicio.isdigit() and fin.isdigit()):
                    raise ModuloError(f"Rango inválido: '{trozo}'")
                if int(fin) - int(inicio) > 10000:
                    raise ModuloError("Rango demasiado grande (máx. 10000 puertos)")
                puertos.update(range(int(inicio), int(fin) + 1))
            elif trozo.isdigit():
                puertos.add(int(trozo))
            elif trozo:
                raise ModuloError(f"Puerto inválido: '{trozo}'")
        if not puertos:
            raise ModuloError("No hay puertos que escanear")
        return sorted(puertos)

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("TARGET"))
        puertos = self._parsear_puertos(self.opt("PORTS"))
        timeout = self.opt_int("TIMEOUT", 5) or 5
        hilos = min(self.opt_int("THREADS", 10) or 10, 100)
        capturar = self.opt_bool("BANNER", True)

        # Resolución previa: falla pronto si el host no existe
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            raise ModuloError(f"Host no resoluble: '{host}'")

        abiertos = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = {pool.submit(_escanear_puerto, ip, p, timeout, capturar): p
                       for p in puertos}
            for futuro in as_completed(futuros):
                puerto, abierto, servicio, banner = futuro.result()
                if abierto:
                    abiertos.append({"puerto": puerto, "servicio": servicio, "banner": banner})

        abiertos.sort(key=lambda x: x["puerto"])
        resumen = f"{host} ({ip}): {len(abiertos)}/{len(puertos)} puertos abiertos"

        # --- Autorelleno del workspace (hosts + servicios) ----------------
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)
        if abiertos and db is not None:
            try:
                db.add_host(ip, hostname=host if host != ip else "", notas="recon/port_scanner")
                for item in abiertos:
                    db.add_service(ip, item["puerto"], item["servicio"])
            except Exception:  # noqa: BLE001 — el escaneo no debe fallar por la DB
                pass

        return {
            "resumen": resumen,
            "host": host,
            "ip_resuelta": ip,
            "puertos_escaneados": len(puertos),
            "abiertos": abiertos,
        }
