# -*- coding: utf-8 -*-
"""
Módulo phishing/campaign_server
===============================
Servidor HTTP LOCAL para simulaciones de concienciación de phishing
(autorizadas), al estilo de GoPhish:

    • Sirve la página generada (templates/phishing/ o output/phishing/).
    • Registra CADA visita (píxel de seguimiento /track.gif).
    • Registra los envíos del formulario (POST /captura) con los campos
      remitidos y guarda todo en workspace/capturas/<campana>.json.
    • Tras la captura redirige a la URL legítima indicada.

NO envía nada a internet: solo escucha en localhost/LAN del laboratorio.
Pulsa Ctrl+C para detener; las sesiones y capturas persisten.

Riesgo: ALTO → exige AUTHORIZED (hosting de página de captura de credenciales).
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

WORKSPACE = Path(__file__).resolve().parent.parent.parent / "workspace"


class _Handler(BaseHTTPRequestHandler):
    """Handler HTTP con captura de visitas y envíos del formulario."""

    modulo = None  # lo inyecta la clase al arrancar el servidor

    def log_message(self, formato, *args):  # silencia el logging por defecto
        pass

    def _ruta_pagina(self) -> Path:
        # El handler delega en el módulo (única fuente de verdad)
        return self.modulo._ruta_pagina()

    def do_GET(self):  # noqa: N802 (API de http.server)
        ruta = self.path.split("?")[0]
        if ruta == "/track.gif":
            # Píxel 1x1: registra la visita (email abierto la simulación)
            self.modulo._registrar_visita(self.client_address[0], self.headers.get("Referer", ""))
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.end_headers()
            self.wfile.write(b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;")
            return
        pagina = self._ruta_pagina()
        if ruta == "/" and pagina.exists():
            cuerpo = pagina.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(cuerpo)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<h1>404</h1>")

    def do_POST(self):  # noqa: N802
        if self.path.split("?")[0] != "/captura":
            self.send_response(404)
            self.end_headers()
            return
        longitud = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(longitud).decode(errors="replace")
        campos = dict(par.split("=", 1) for par in cuerpo.split("&") if "=" in par)
        self.modulo._registrar_captura(self.client_address[0], campos)

        # Redirige a la URL legítima (efecto educativo de "era una simulación")
        destino = self.modulo.opt("REDIRECT_URL", "https://example.com")
        self.send_response(302)
        self.send_header("Location", destino)
        self.end_headers()


class CampaignServer(BaseModulo):
    """Servidor HTTP de simulación de phishing con tracking y captura."""

    NAME = "phishing/campaign_server"
    CATEGORIA = "phishing"
    DESCRIPCION = ("Servidor HTTP local para SIMULACIONES autorizadas de phishing: "
                   "sirve la página, registra visitas y envíos, y redirige a la "
                   "URL legítima. Detener con Ctrl+C.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "GoPhish · htr-tech/zphisher"
    INTERACTIVO = True

    def definir_opciones(self) -> None:
        self.opciones.declarar("PORT", "8080", True, "Puerto local de escucha")
        self.opciones.declarar("BIND", "0.0.0.0", False, "IP de escucha (0.0.0.0 = todas)")
        self.opciones.declarar("PAGINA", "campana", False, "Nombre de página en output/phishing/")
        self.opciones.declarar("CAMPANA", "simulacion1", False, "Nombre de campaña para las capturas")
        self.opciones.declarar("REDIRECT_URL", "https://example.com", False, "URL legítima tras la captura")
        self.opciones.declarar("DURACION", "0", False, "Segundos antes de detenerse (0 = hasta Ctrl+C)")

    # --- Registro de eventos -------------------------------------------
    def _ruta_pagina(self) -> Path:
        """Ruta de la página HTML servida (output/phishing/<PAGINA>.html)."""
        raiz = Path(__file__).resolve().parent.parent.parent
        return raiz / "output" / "phishing" / f"{self.opt('PAGINA', 'campana')}.html"

    def _fichero_campana(self) -> Path:
        carpeta = WORKSPACE / "capturas"
        carpeta.mkdir(parents=True, exist_ok=True)
        return carpeta / f"{self.opt('CAMPANA', 'simulacion1')}.json"

    def _volcar(self) -> None:
        self._fichero_campana().write_text(
            json.dumps(self.resultado, indent=2, ensure_ascii=False), encoding="utf-8")

    def _registrar_visita(self, ip: str, referer: str) -> None:
        self.resultado["visitas"].append({"ip": ip, "referer": referer, "hora": time.strftime("%H:%M:%S")})
        self._volcar()

    def _registrar_captura(self, ip: str, campos: dict) -> None:
        self.resultado["capturas"].append({"ip": ip, "campos": campos, "hora": time.strftime("%H:%M:%S")})
        self._volcar()

    # --- Ejecución -------------------------------------------------------
    def ejecutar(self) -> dict:
        puerto = self.opt_int("PORT", 8080)
        bind = self.opt("BIND", "0.0.0.0")
        duracion = self.opt_int("DURACION", 0)

        if not self._ruta_pagina().exists():
            raise ModuloError(f"No existe output/phishing/{self.opt('PAGINA', 'campana')}.html. "
                              f"Genera una antes con phishing/template_gen.")

        self.resultado = {"visitas": [], "capturas": []}

        _Handler.modulo = self
        try:
            servidor = ThreadingHTTPServer((bind, puerto), _Handler)
        except OSError as err:
            raise ModuloError(f"No se puede escuchar en {bind}:{puerto} — {err}")

        from rich.markup import escape

        from core.colors import console
        console.print(f"[ok][✓][/ok] Servidor de campaña activo en "
                      f"[bold]http://{bind}:{puerto}/[/bold]")
        console.print(f"[dim]   Visitas  → /track.gif · Capturas → POST /captura\n"
                      f"   Capturas en: {escape(str(self._fichero_campana()))}\n"
                      f"   Detén con Ctrl+C (las capturas persisten).[/dim]")

        hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
        hilo.start()

        try:
            if duracion > 0:
                time.sleep(duracion)
            else:
                while True:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            servidor.shutdown()
            console.print("[aviso][!][/aviso] Servidor detenido.")

        return {
            "resumen": (f"Campaña '{self.opt('CAMPANA', 'simulacion1')}': "
                        f"{len(self.resultado['visitas'])} visitas, "
                        f"{len(self.resultado['capturas'])} capturas"),
            "campana": self.opt("CAMPANA", "simulacion1"),
            "puerto": puerto,
            "visitas": self.resultado["visitas"],
            "capturas": self.resultado["capturas"],
        }
