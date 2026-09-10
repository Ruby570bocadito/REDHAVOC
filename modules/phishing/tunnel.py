# -*- coding: utf-8 -*-
"""
Módulo phishing/tunnel
======================
Expone el servidor de campaña LOCAL (phishing/campaign_server) a través de
un túnel SSH inverso, al estilo de los túneles de zphisher, para que el
equipo de concienciación pueda abrir la página de simulación desde fuera
de la red del laboratorio.

Proveedores soportados (no requieren registro):
    • serveo        → ssh -R 80:localhost:PORT serveo.net
    • localhost.run → ssh -R 80:localhost:PORT nokey@localhost.run

IMPORTANTE: el módulo solo CREA el túnel. El uso legítimo es servir la
página de SIMULACIÓN de REDHAVOC en campañas de concienciación AUTORIZADAS.
Exponer infraestructura de phishing contra terceros es ilegal.

Riesgo: MEDIO (publica un puerto local; el contenido servido es tu
responsabilidad y debe ser una simulación autorizada).
Detener con Ctrl+C.
"""

import re
import shutil
import subprocess
import threading
import time

from core.base_module import BaseModulo, ModuloError

PROVEEDORES = {
    "serveo": ["-o", "StrictHostKeyChecking=no",
               "-o", "ServerAliveInterval=30",
               "-R", "80:localhost:{puerto}", "serveo.net"],
    "localhost.run": ["-o", "StrictHostKeyChecking=no",
                      "-o", "ServerAliveInterval=30",
                      "-R", "80:localhost:{puerto}", "nokey@localhost.run"],
}

_RE_URL = re.compile(r"(https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)")


class Tunnel(BaseModulo):
    """Túnel SSH inverso (serveo/localhost.run) para la campaña local."""

    NAME = "phishing/tunnel"
    CATEGORIA = "phishing"
    DESCRIPCION = ("Publica el servidor de campaña local en internet vía túnel "
                   "SSH inverso (serveo/localhost.run), estilo zphisher. SOLO "
                   "para simulaciones de concienciación autorizadas. Ctrl+C para "
                   "detener.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "htr-tech/zphisher (túneles) · serveo.net · localhost.run"

    def definir_opciones(self) -> None:
        self.opciones.declarar("PORT", "8080", True,
                               "Puerto local del campaign_server a exponer")
        self.opciones.declarar("PROVEEDOR", "serveo", False,
                               "serveo | localhost.run")
        self.opciones.declarar("DURACION", "0", False,
                               "Segundos antes de cerrar (0 = hasta Ctrl+C)")

    # ------------------------------------------------------------------
    def _comando_ssh(self, proveedor: str, puerto: int) -> list:
        plantilla = PROVEEDORES.get(proveedor)
        if plantilla is None:
            raise ModuloError(f"Proveedor desconocido '{proveedor}'. "
                              f"Disponibles: {', '.join(PROVEEDORES)}")
        ruta_ssh = shutil.which("ssh")
        if not ruta_ssh:
            raise ModuloError("No se encuentra el cliente 'ssh' en el sistema.")
        return [ruta_ssh, *[a.format(puerto=puerto) for a in plantilla]]

    def _leer_url(self, salida_acumulada: str) -> str | None:
        """Extrae la primera URL pública que el proveedor asigna."""
        urls = _RE_URL.findall(salida_acumulada)
        for url in urls:
            # descarta URLs de localhost o del propio sshd
            if "localhost" not in url and "127.0.0.1" not in url:
                return url
        return None

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        puerto = self.opt_int("PORT", 8080)
        proveedor = self.opt("PROVEEDOR", "serveo").strip().lower()
        duracion = self.opt_int("DURACION", 0)
        comando = self._comando_ssh(proveedor, puerto)

        from core.colors import console
        console.print(f"[info][*][/info] Abriendo túnel {proveedor} hacia 127.0.0.1:{puerto} ...")

        # Comprueba que algo escucha en el puerto local (aviso, no bloqueo)
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex(("127.0.0.1", puerto)) != 0:
                console.print(f"[aviso][!][/aviso] Nada escucha en el puerto {puerto}. "
                              f"Lanza antes phishing/campaign_server.")

        try:
            proceso = subprocess.Popen(
                comando, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True)
        except OSError as err:
            raise ModuloError(f"No se pudo ejecutar ssh: {err}")

        url_publica = None
        salida_total = []

        def _lector():
            nonlocal url_publica
            for linea in proceso.stdout:  # type: ignore[union-attr]
                salida_total.append(linea.rstrip())
                url_publica = self._leer_url("\n".join(salida_total))

        hilo = threading.Thread(target=_lector, daemon=True)
        hilo.start()

        # Espera activa hasta que el proveedor asigne URL (máx. 15 s)
        inicio = time.time()
        while url_publica is None and time.time() - inicio < 15:
            if proceso.poll() is not None:
                break
            time.sleep(0.3)

        if proceso.poll() is not None and url_publica is None:
            detalle = "\n".join(salida_total)[-300:] or "(sin salida)"
            raise ModuloError(
                f"ssh terminó inmediatamente (código {proceso.returncode}). "
                f"Salida: {detalle}")

        if url_publica is None:
            console.print("[aviso][!][/aviso] El proveedor no ha asignado URL en 15 s "
                          "(¿sin internet? ¿censura del puerto 22?). Pulsa Ctrl+C para salir.")
        else:
            console.print(f"[ok][✓][/ok] Túnel activo: [bold cyan]{url_publica}[/bold cyan]")
            console.print("[dim]   Todo lo que llegue a esa URL se redirige a tu "
                          "campaign_server local.[/dim]")
            console.print("   Detén con Ctrl+C.")

        try:
            if duracion > 0:
                time.sleep(duracion)
            else:
                while proceso.poll() is None:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            proceso.terminate()
            try:
                proceso.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proceso.kill()

        return {
            "resumen": (f"Túnel {proveedor}: {url_publica or 'sin URL asignada'} "
                        f"→ 127.0.0.1:{puerto}"),
            "proveedor": proveedor,
            "puerto_local": puerto,
            "url_publica": url_publica,
            "duracion_s": duracion if duracion > 0 else "hasta Ctrl+C",
            "salida_ssh": "\n".join(salida_total)[-400:],
        }
