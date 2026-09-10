# -*- coding: utf-8 -*-
"""
Módulo recon/ping_sweep
=======================
Descubrimiento de hosts vivos en una red local (CIDR), combinando:

    • TCP-ping a puertos habituales (80/443/22/445/3389) — no requiere root.
    • Opcionalmente ICMP del sistema (`ping`) si ICMP=true.

No usa raw sockets ni ARP: funciona en contenedores y sin privilegios.
Los hosts vivos se registran automáticamente en el workspace (comando
`hosts`) con los servicios TCP que respondieron.

Riesgo: MEDIO (contacto directo con la red; solo en redes propias/autorizadas).
"""

import ipaddress
import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModulo, ModuloError

PUERTOS_TCP = [80, 443, 22, 445, 3389, 8080]


def _red_desde(target: str):
    """Convierte '192.168.1.0/24', '192.168.1.5/24' o '192.168.1.5' en red."""
    try:
        if "/" in target:
            return ipaddress.ip_network(target, strict=False)
        return ipaddress.ip_network(f"{target}/32", strict=False)
    except ValueError as err:
        raise ModuloError(f"Rango inválido '{target}': {err}")


def _tcp_vivo(ip: str, timeout: float) -> list:
    """Puertos TCP que responden en el host (indica host vivo)."""
    abiertos = []
    for puerto in PUERTOS_TCP:
        try:
            with socket.create_connection((ip, puerto), timeout=timeout):
                abiertos.append(puerto)
        except OSError:
            continue
    return abiertos


def _icmp_vivo(ip: str, timeout: float) -> bool:
    """ICMP del sistema (requiere que `ping` esté permitido)."""
    ruta = shutil.which("ping")
    if not ruta:
        return False
    bandera = "-n" if hasattr(subprocess, "STARTUPINFO") else "-c"
    espera = "-w" if hasattr(subprocess, "STARTUPINFO") else "-W"
    try:
        res = subprocess.run(
            [ruta, bandera, "1", espera, str(int(timeout)), ip],
            capture_output=True, timeout=timeout + 2)
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


class PingSweep(BaseModulo):
    """Descubre hosts vivos en una red local y los registra en el workspace."""

    NAME = "recon/ping_sweep"
    CATEGORIA = "recon"
    DESCRIPCION = ("Descubre hosts vivos en una red CIDR (TCP-ping a puertos "
                   "habituales + ICMP opcional, sin root). Registra los vivos "
                   "en el workspace. Solo redes propias/autorizadas.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "nmap -sn · netdiscover (concepto, sin raw sockets)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "127.0.0.1/32", True,
                               "Rango CIDR a explorar (p. ej. 192.168.1.0/24)")
        self.opciones.declarar("ICMP", "true", False, "Usar además ICMP del sistema (true/false)")
        self.opciones.declarar("MAX_HOSTS", "256", False,
                               "Máximo de direcciones a explorar (tope ético)")

    def ejecutar(self) -> dict:
        red = _red_desde(self.opt("TARGET"))
        timeout = min(self.opt_int("TIMEOUT", 5) or 5, 10)
        hilos = max(1, min(self.opt_int("THREADS", 10), 100))
        max_hosts = max(1, min(self.opt_int("MAX_HOSTS", 256), 1024))

        direcciones = [str(ip) for ip in red.hosts()][:max_hosts]
        if not direcciones:
            raise ModuloError(f"La red {red} no tiene direcciones de host")
        if len(list(red.hosts())) > max_hosts:
            from core.colors import console
            console.print(f"[aviso][!][/aviso] La red tiene {red.num_addresses - 2} hosts; "
                          f"se exploran solo los primeros {max_hosts} (MAX_HOSTS).")

        usar_icmp = self.opt_bool("ICMP", True)
        vivos = []
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)

        def explorar(ip: str) -> None:
            puertos = _tcp_vivo(ip, timeout)
            vivo = bool(puertos) or (usar_icmp and _icmp_vivo(ip, timeout))
            if vivo:
                vivos.append({"ip": ip, "puertos_tcp": puertos})
                if db is not None:
                    try:
                        db.add_host(ip, notas="recon/ping_sweep")
                        for p in puertos:
                            db.add_service(ip, p, "tcp")
                    except Exception:  # noqa: BLE001
                        pass

        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = {pool.submit(explorar, ip): ip for ip in direcciones}
            for futuro in as_completed(futuros):
                futuro.exception()  # propaga errores inesperados si los hay

        vivos.sort(key=lambda x: tuple(int(o) for o in x["ip"].split(".")))
        resumen = f"{red}: {len(vivos)}/{len(direcciones)} hosts vivos"
        return {
            "resumen": resumen,
            "red": str(red),
            "explorados": len(direcciones),
            "vivos": vivos,
        }
