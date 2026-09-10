# -*- coding: utf-8 -*-
"""
Módulo post/multi_handler
=========================
Listener de shells reversas estilo Metasploit multi/handler, versión de
laboratorio:

    • Escucha TCP (LHOST:LPORT) y acepta N conexiones.
    • Cada conexión queda registrada como SESIÓN del framework.
    • TLS=true envuelve CADA conexión en un túnel TLS (certificado del lab).
    • Salir del módulo con Ctrl+C MANTIENE las sesiones vivas; gestionalas
      con `sessions`, `sessions -i <ID>` y `sessions -k <ID>`.

El "agente" correspondiente está en templates/payloads/agent_shell.py
(ejecútalo en el host del lab: python3 agent_shell.py LHOST LPORT [--tls]).

Certificados de laboratorio: genera un par autofirmado una sola vez con
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -subj "/CN=redhavoc-lab" -keyout lab.key -out lab.pem
y apunta CERTFILE/KEYFILE a ellos.

Riesgo: ALTO → exige AUTHORIZED (recepción de conexiones reversas).
"""

import os
import socket
import ssl
import threading
import time

from core.base_module import BaseModulo, ModuloError


class MultiHandler(BaseModulo):
    """Listener multi-sesión de shells reversas para el laboratorio."""

    NAME = "post/multi_handler"
    CATEGORIA = "post"
    DESCRIPCION = ("Listener TCP de shells reversas estilo multi/handler: "
                   "registra sesiones del lab y las gestiona con 'sessions'. "
                   "Soporta TLS con certificado del lab (TLS=true). "
                   "Detén el listener con Ctrl+C; las sesiones persisten.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Metasploit multi/handler · t3l3machus/Villain"
    INTERACTIVO = True

    def definir_opciones(self) -> None:
        self.opciones.declarar("LHOST", "0.0.0.0", True, "IP de escucha (0.0.0.0 = todas)")
        self.opciones.declarar("LPORT", "4444", True, "Puerto de escucha")
        self.opciones.declarar("DURACION", "0", False, "Segundos antes de cerrar el listener (0 = hasta Ctrl+C)")
        self.opciones.declarar("TLS", "false", False, "Envolver cada conexión en TLS (true/false)")
        self.opciones.declarar("CERTFILE", "", False, "Ruta del certificado PEM (requerido si TLS=true)")
        self.opciones.declarar("KEYFILE", "", False, "Ruta de la clave PEM (requerido si TLS=true)")

    # ------------------------------------------------------------------
    def _contexto_tls(self) -> ssl.SSLContext:
        """Construye el contexto TLS servidor con el certificado del lab."""
        cert = self.opt("CERTFILE")
        clave = self.opt("KEYFILE")
        if not cert or not clave:
            raise ModuloError(
                "TLS=true requiere CERTFILE y KEYFILE. Genera un par del lab:\n"
                "  openssl req -x509 -newkey rsa:2048 -nodes -days 365 "
                "-subj '/CN=redhavoc-lab' -keyout lab.key -out lab.pem"
            )
        if not (os.path.isfile(cert) and os.path.isfile(clave)):
            raise ModuloError(f"No se encuentran los ficheros de certificado: {cert} / {clave}")
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            contexto.load_cert_chain(certfile=cert, keyfile=clave)
        except (ssl.SSLError, OSError) as err:
            raise ModuloError(f"Certificados TLS inválidos — {err}")
        return contexto

    def _envolver(self, conn: socket.socket, contexto_tls) -> socket.socket:
        """Aplica el handshake TLS servidor; devuelve None si falla."""
        if contexto_tls is None:
            return conn
        try:
            return contexto_tls.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            # Handshake fallido (escáner, cliente plano, Sondeo TLS antiguo…)
            try:
                conn.close()
            except OSError:
                pass
            return None

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        lhost = self.opt("LHOST", "0.0.0.0")
        lport = self.opt_int("LPORT", 4444)
        contexto_tls = self._contexto_tls() if self.opt_bool("TLS") else None

        try:
            servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            servidor.bind((lhost, lport))
            servidor.listen(5)
        except OSError as err:
            raise ModuloError(f"No se puede escuchar en {lhost}:{lport} — {err}")

        from core.colors import console
        etiqueta = "TLS" if contexto_tls else "TCP"
        console.print(f"[ok][✓][/ok] Handler activo en [bold]{lhost}:{lport}[/bold] "
                      f"[bold cyan]({etiqueta})[/bold cyan]")
        banderas = " --tls" if contexto_tls else ""
        console.print(f"[dim]   Lanza el agente del lab: python3 templates/payloads/agent_shell.py <LHOST> <LPORT>{banderas}\n"
                      f"   Las conexiones se registran como sesiones (comando: sessions)\n"
                      f"   Detén el listener con Ctrl+C (las sesiones persisten).[/dim]")

        servidor.settimeout(1.0)
        aceptadas = 0
        limite = None
        if self.opt_int("DURACION", 0) > 0:
            limite = time.time() + self.opt_int("DURACION", 0)
        try:
            while limite is None or time.time() < limite:
                try:
                    conn, addr = servidor.accept()
                except socket.timeout:
                    continue
                conn = self._envolver(conn, contexto_tls)
                if conn is None:
                    continue          # handshake TLS fallido: no contamina sesiones
                sid = self._registrar(conn, addr)
                aceptadas += 1
                console.print(f"[ok][+][/ok] Sesión [bold cyan]{sid}[/bold cyan] abierta desde "
                              f"[bold]{addr[0]}:{addr[1]}[/bold]{(' (TLS)' if contexto_tls else '')}")
        except KeyboardInterrupt:
            pass
        finally:
            servidor.close()
            vivas = len(self._ctx_seguro()[0])
            console.print("[aviso][!][/aviso] Listener detenido. "
                          f"[bold]{vivas}[/bold] sesión(es) activa(s) → comando [bold]sessions[/bold]")

        return {
            "resumen": f"Handler {lhost}:{lport} ({etiqueta}) cerrado. "
                       f"Conexiones aceptadas: {aceptadas}. "
                       f"Sesiones vivas: {len(self._ctx_seguro()[0])}",
            "lhost": lhost,
            "lport": lport,
            "tls": bool(contexto_tls),
            "conexiones_aceptadas": aceptadas,
        }

    def _ctx_seguro(self):
        """(sesiones, globales) con fallback si el módulo corre sin framework.

        Desde la consola el ctx siempre existe; fuera de ella (tests, uso
        como librería) el handler funciona igual pero las sesiones viven
        solo en el módulo.
        """
        ctx = getattr(self, "ctx", None)
        if ctx is not None:
            return ctx.sesiones, ctx.globales
        if getattr(self, "_sesiones_locales", None) is None:
            self._sesiones_locales: dict = {}
        return self._sesiones_locales, None

    def _registrar(self, conn: socket.socket, addr) -> int:
        """Registra la conexión como sesión en el framework y devuelve su ID."""
        sesiones, globales = self._ctx_seguro()
        if globales is not None:
            sid = globales.get_int("__SID__", 0) + 1   # contador compartido
            globales.set("__SID__", str(sid))
        else:
            sid = max(sesiones.keys(), default=0) + 1
        conn.settimeout(None)
        sesiones[sid] = {"conn": conn, "addr": addr, "abierta": time.time()}
        return sid
