# -*- coding: utf-8 -*-
"""
Módulo opsec/mac_changer
========================
Cambia (o aleatoriza) la dirección MAC de una interfaz de red LOCAL para
evitar asociaciones previas del equipo en auditorías de red inalámbrica
WiFi/LAN autorizadas (p. ej. ejercicio red team con acceso físico).

Implementación: comandos `ip link` de Linux (iproute2). Requiere root:
    sudo python redhavoc.py
En otros sistemas operativos devuelve un error limpio.

Riesgo: MEDIO (solo modifica TU propia máquina; puede cortar tu conexión
unos segundos y redes con NAC pueden bloquear MACs nuevas).
"""

import random
import re
import shutil
import subprocess
import time

from core.base_module import BaseModulo, ModuloError

PREFIJOS_OUI = [  # OUIs reales habituales (evita MACs obviamente falsas)
    "00:1A:2B", "3C:5A:B4", "D8:BB:C1", "F0:9F:C2",
    "B8:27:EB", "DC:A6:32", "00:0C:29", "08:00:27",
]


def _mac_aleatoria() -> str:
    """Genera una MAC local-administrada con OUI realista."""
    oui = random.choice(PREFIJOS_OUI)
    resto = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{oui}:{resto}"


class MacChanger(BaseModulo):
    """Aleatoriza la MAC de una interfaz local (Linux, requiere root)."""

    NAME = "opsec/mac_changer"
    CATEGORIA = "opsec"
    DESCRIPCION = ("Cambia la MAC de una interfaz local (Linux + root) para "
                   "operaciones inalámbricas autorizadas. Genera MACs con OUI "
                   "realista; conserva la original en el informe.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Auto_Tor_IP_changer (MAC) · macchanger (GNU)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("IFACE", "eth0", False, "Interfaz de red (eth0/wlan0/...)")
        self.opciones.declarar("MAC", "", False, "MAC destino (vacío = aleatoria)")
        self.opciones.declarar("RESTAURAR", "false", False,
                               "true = restaurar la MAC original guardada en workspace")

    # ------------------------------------------------------------------
    def _ip(self, *args: str) -> str:
        ruta_ip = shutil.which("ip")
        if not ruta_ip:
            raise ModuloError("No se encuentra el comando 'ip' (iproute2). Solo Linux.")
        res = subprocess.run([ruta_ip, *args], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            raise ModuloError(f"ip {' '.join(args)} falló: {res.stderr.strip()[:120]}")
        return res.stdout

    def _mac_actual(self, iface: str) -> str:
        salida = self._ip("link", "show", iface)
        m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", salida)
        if not m:
            raise ModuloError(f"No se pudo leer la MAC de '{iface}'. ¿Existe la interfaz?")
        return m.group(1).lower()

    def _es_root(self) -> bool:
        import os
        return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        if not self._es_root():
            raise ModuloError("Se necesitan permisos de root: sudo python redhavoc.py")

        iface = self.opt("IFACE", "eth0").strip()
        original = self._mac_actual(iface)
        marca = time.strftime("%Y-%m-%d %H:%M:%S")

        # Restaurar la MAC guardada en un cambio anterior
        if self.opt_bool("RESTAURAR"):
            guardada = self._leer_original_guardada()
            if not guardada:
                raise ModuloError("No hay MAC original guardada en el workspace.")
            destino = guardada["mac_original"]
            nota = "restauración"
        else:
            destino = self.opt("MAC", "").strip().lower() or _mac_aleatoria()
            if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", destino):
                raise ModuloError(f"MAC inválida: '{destino}' (formato aa:bb:cc:dd:ee:ff)")
            self._guardar_original(iface, original, marca)
            nota = "cambio"

        # Bajar → cambiar MAC → subir
        self._ip("link", "set", "dev", iface, "down")
        try:
            self._ip("link", "set", "dev", iface, "address", destino)
            time.sleep(0.3)
        finally:
            self._ip("link", "set", "dev", iface, "up")
            time.sleep(0.5)

        nueva = self._mac_actual(iface)
        if nueva != destino:
            raise ModuloError(f"El kernel no aplicó la MAC pedida ({destino}); "
                              f"quedó {nueva}. Puede que el driver no lo permita.")

        return {
            "resumen": f"MAC de {iface}: {nota} {original} → {nueva}",
            "iface": iface,
            "mac_original": original,
            "mac_nueva": nueva,
            "operacion": nota,
            "aviso": "Las redes con NAC/802.1X pueden bloquear la MAC nueva; "
                     "RESTAURAR=true devuelve la original.",
        }

    # --- Persistencia de la MAC original -------------------------------
    def _fichero(self):
        from pathlib import Path
        ws = getattr(getattr(self, "ctx", None), "workspace", None)
        carpeta = Path(ws.carpeta if hasattr(ws, "carpeta") else ws) if ws else Path("workspace")
        carpeta.mkdir(parents=True, exist_ok=True)
        return carpeta / "mac_original.json"

    def _guardar_original(self, iface: str, mac: str, marca: str) -> None:
        import json
        datos = {}
        if self._fichero().exists():
            try:
                datos = json.loads(self._fichero().read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                datos = {}
        datos.setdefault(iface, {"mac_original": mac, "fecha": marca})
        self._fichero().write_text(json.dumps(datos, indent=2), encoding="utf-8")

    def _leer_original_guardada(self) -> dict | None:
        import json
        if not self._fichero().exists():
            return None
        try:
            datos = json.loads(self._fichero().read_text(encoding="utf-8"))
            iface = self.opt("IFACE", "eth0").strip()
            return datos.get(iface)
        except (json.JSONDecodeError, OSError):
            return None
