# -*- coding: utf-8 -*-
"""
Tests v1.5.0 — Consola pulida
=============================
Cubre:
  • core/render: resultados de módulos pintados en terminal (tablas, paneles,
    columnas, truncado, severidad coloreada, escape de markup).
  • core/colors.trabajo: spinner con cronómetro (TTY y no-TTY).
  • core/boot: animación de arranque (TTY y no-TTY).
  • Banner con degradado.
  • framework: panel en use, árbol en show modules, resultados tras run.
  • post/multi_handler con TLS (certificado de lab en tests/assets).
"""

import io
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from rich.console import Console
from rich.spinner import SPINNERS

from core.banner import Banner, _gradiente_hex
from core.base_module import ModuloError
from core.boot import Boot
from core.colors import console, trabajo
from core.framework import Ctx, RedHavocFramework
from core.option_store import OptionStore
from core.render import MAX_FILAS, mostrar_resultado

ASSETS = Path(__file__).resolve().parent / "assets"
CERT = str(ASSETS / "lab.pem")
KEY = str(ASSETS / "lab.key")


# ----------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------
def _consola_cap() -> Console:
    """Consola Rich no interactiva con captura de texto plano."""
    return Console(file=io.StringIO(), width=100, theme=None)


def _consola_tty() -> Console:
    """Consola Rich FORZADA a terminal (para probar animaciones)."""
    return Console(file=io.StringIO(), width=100, force_terminal=True,
                   color_system="truecolor")


def _puerto_libre() -> int:
    """Reserva un puerto efímero y lo libera."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    puerto = s.getsockname()[1]
    s.close()
    return puerto


# ----------------------------------------------------------------------
# core/render
# ----------------------------------------------------------------------
def test_render_resumen_y_totales():
    c = _consola_cap()
    mostrar_resultado("demo/mod", {
        "resumen": "Escaneo terminado",
        "abiertos": [{"puerto": 22, "servicio": "ssh"},
                     {"puerto": 80, "servicio": "http"}],
    }, c)
    texto = c.file.getvalue()
    assert "resultado · demo/mod" in texto
    assert "Escaneo terminado" in texto
    assert "Puertos abiertos" in texto
    assert "Puertos abiertos: 2" in texto          # línea de totales
    assert "22" in texto and "ssh" in texto


def test_render_tabla_severidad_coloreada():
    c = _consola_cap()
    mostrar_resultado("web/jwt", {
        "resumen": "ok",
        "hallazgos": [{"severidad": "critico", "titulo": "alg=none aceptado"},
                      {"severidad": "bajo", "titulo": "exp a 30 días"}],
    }, c)
    texto = c.file.getvalue()
    assert "critico" in texto and "bajo" in texto   # celdas presentes, sin MarkupError


def test_render_truncado_listas_largas():
    c = _consola_cap()
    sobra = 70 - 60                                   # MAX_COLUMNAS = 60
    mostrar_resultado("recon/x", {"subdominios": [f"sub{i}.lab" for i in range(70)]}, c)
    texto = c.file.getvalue()
    assert f"+{sobra} más" in texto


def test_render_truncado_lista_linea_a_linea():
    """Textos largos → vista numerada; se trunca a MAX_FILAS."""
    c = _consola_cap()
    urls = [f"https://dominio-muy-largo-de-prueba-{i}.lab/ruta" for i in range(40)]
    mostrar_resultado("recon/x", {"probados": urls}, c)
    texto = c.file.getvalue()
    sobra = 40 - MAX_FILAS
    assert f"+{sobra} más" in texto
    assert "dominio-muy-largo-de-prueba-0" in texto


def test_render_escape_de_markup():
    """Un valor con corchetes se muestra literal y no rompe Rich."""
    c = _consola_cap()
    mostrar_resultado("demo/x", {"resumen": "eco", "probados": ["[bold rojo]inyectado[/bold rojo]"]}, c)
    texto = c.file.getvalue()
    assert "[bold rojo]inyectado" in texto          # aparece como TEXTO
    assert "inyectado[/bold rojo]" in texto


def test_render_columnas_listas_cortas():
    c = _consola_cap()
    mostrar_resultado("osint/x", {"subdominios": ["a.lab", "b.lab", "c.lab", "d.lab"]}, c)
    texto = c.file.getvalue()
    assert "a.lab" in texto and "d.lab" in texto


def test_render_dict_y_escalar_genericos():
    c = _consola_cap()
    mostrar_resultado("demo/d", {"resumen": "r", "pais": "España", "tecnica": {"nombre": "X", "id": 1}}, c)
    texto = c.file.getvalue()
    assert "pais" in texto.lower() and "España" in texto
    assert "X" in texto


def test_render_formas_raras_no_rompen():
    c = _consola_cap()
    mostrar_resultado("demo/r", None, c)            # None → silencio
    mostrar_resultado("demo/r", {}, c)              # dict vacío → silencio
    assert c.file.getvalue() == ""


def test_render_errores_seccion():
    c = _consola_cap()
    mostrar_resultado("demo/e", {"resumen": "r", "errores": ["timeout host A", "refused B"]}, c)
    texto = c.file.getvalue()
    assert "Errores" in texto and "timeout host A" in texto


# ----------------------------------------------------------------------
# core/colors.trabajo (spinner con cronómetro)
# ----------------------------------------------------------------------
def test_spinners_redhavoc_registrado():
    assert "redhavoc" in SPINNERS
    assert len(SPINNERS["redhavoc"]["frames"]) >= 4


def test_trabajo_sin_tty_silencioso_y_ejecuta():
    """Consola global (no TTY en tests): el cuerpo corre y no ensucia salida."""
    ejecutado = []
    with trabajo("recon/port_scanner"):
        ejecutado.append(1)
    assert ejecutado == [1]


def test_trabajo_con_tty_muestra_animacion():
    """En TTY: Live activo, texto con módulo y cronómetro, y restaurado al salir."""
    c = _consola_tty()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("core.colors.console", c)
        with trabajo("web/dir_bruteforce") as estado:
            time.sleep(0.25)                       # deja latir al cronómetro
            texto = estado.status
            vivo = estado._live._started           # el Live interno está en marcha
        assert vivo, "No arrancó el estado animado en TTY"
        assert "web/dir_bruteforce" in texto
        assert "·" in texto                        # el cronómetro está pintado
        assert not estado._live._started, "El Live no se restauró al salir"


# ----------------------------------------------------------------------
# core/boot (animación de arranque)
# ----------------------------------------------------------------------
def test_boot_sin_tty_mensaje(capsys, manager):
    Boot.animar(console, manager)
    assert f"{manager.total_modulos()} módulos cargados" in capsys.readouterr().out


def test_boot_con_tty_arsenal_listo(manager):
    c = _consola_tty()
    Boot.animar(c, manager, segundos=0.05)
    texto = c.file.getvalue()
    assert "Arsenal listo" in texto
    assert f"{manager.total_modulos()}" in texto


# ----------------------------------------------------------------------
# Banner con degradado
# ----------------------------------------------------------------------
def test_gradiente_hex_extremos():
    colores = _gradiente_hex(6)
    assert len(colores) == 6
    assert colores[0] == "#64748b"     # pizarra oscura (tema profesional)
    assert colores[-1] == "#94a3b8"    # pizarra clara


def test_banner_mostrar_sin_explotar():
    c = _consola_cap()
    Banner.mostrar(c, 58)
    texto = c.file.getvalue()
    assert "módulos cargados" in texto
    assert "REDHAVOC" in texto or "████" in texto     # el arte está pintado


def test_banner_despedida():
    c = _consola_cap()
    Banner.despedida(c)
    assert "Sesión cerrada" in c.file.getvalue()


# ----------------------------------------------------------------------
# framework: presentación nueva
# ----------------------------------------------------------------------
@pytest.fixture()
def fw(tmp_path):
    return RedHavocFramework(raiz=tmp_path)


def _ejecuta(fw, linea):
    try:
        fw._procesar(linea)
    except SystemExit:
        pass


def test_use_muestra_panel(fw, capsys):
    _ejecuta(fw, "use recon/ip_info")
    salida = capsys.readouterr().out
    assert "módulo cargado" in salida
    assert "recon/ip_info" in salida


def test_show_modules_arbol(fw, capsys):
    _ejecuta(fw, "show modules")
    salida = capsys.readouterr().out
    assert "arsenal" in salida
    assert "recon" in salida and "payloads" in salida
    assert "recon/ip_info" in salida


def test_run_renderiza_resultados_record(tmp_path):
    fw = RedHavocFramework(raiz=tmp_path)
    fw.globales.set("AUTHORIZED", "true")
    fw.globales.set("REPORT", "false")
    _ejecuta(fw, "use payloads/macro_gen")
    _ejecuta(fw, "run")
    # La consola global escribe en stdout: verificamos por el estado del módulo
    # y el panel vía salida capturada por capsys del test anterior; aquí
    # comprobamos el efecto: resultado recogido y renderizable sin excepción.
    from core.render import mostrar_resultado as mr
    c = _consola_cap()
    mr(fw.modulo_actual.NAME, fw.modulo_actual.resultado, c)
    assert "resultado · payloads/macro_gen" in c.file.getvalue()


# ----------------------------------------------------------------------
# post/multi_handler con TLS
# ----------------------------------------------------------------------
def _ctx_falso():
    """Ctx mínimo para el handler fuera del REPL."""
    globales = OptionStore()
    return Ctx(globales, reporter=None, sesiones={}, workspace=None)


def _lanza_handler(modulo, resultado, error):
    def corredor():
        try:
            resultado.append(modulo.ejecutar())
        except Exception as exc:  # noqa: BLE001
            error.append(exc)
    hilo = threading.Thread(target=corredor, daemon=True)
    hilo.start()
    return hilo


def test_tls_sin_certificados_lanza_modulo_error():
    from importlib import import_module
    cls = import_module("modules.post.multi_handler").MultiHandler
    m = cls()
    m.opciones.set("TLS", "true")
    with pytest.raises(ModuloError):
        m.ejecutar()


def test_tls_certificado_inexistente_lanza_modulo_error():
    from importlib import import_module
    cls = import_module("modules.post.multi_handler").MultiHandler
    m = cls()
    m.opciones.set("TLS", "true")
    m.opciones.set("CERTFILE", "/no/existe/lab.pem")
    m.opciones.set("KEYFILE", "/no/existe/lab.key")
    with pytest.raises(ModuloError):
        m.ejecutar()


def _modulo_handler_tls(puerto, duracion=2.0):
    from importlib import import_module
    cls = import_module("modules.post.multi_handler").MultiHandler
    m = cls()
    m.ctx = _ctx_falso()
    m.opciones.set("LHOST", "127.0.0.1")
    m.opciones.set("LPORT", str(puerto))
    m.opciones.set("DURACION", str(duracion))
    m.opciones.set("TLS", "true")
    m.opciones.set("CERTFILE", CERT)
    m.opciones.set("KEYFILE", KEY)
    return m


def test_tls_handshake_y_sesion_registrada():
    puerto = _puerto_libre()
    m = _modulo_handler_tls(puerto, duracion=3)
    resultado, error = [], []
    hilo = _lanza_handler(m, resultado, error)

    cliente = None
    fin = time.time() + 4
    while time.time() < fin:                       # reintento hasta que escuche
        try:
            bruto = socket.create_connection(("127.0.0.1", puerto), timeout=2)
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("El handler TLS nunca abrió el puerto")
    contexto = ssl._create_unverified_context()
    cliente = contexto.wrap_socket(bruto, server_hostname="127.0.0.1")
    assert cliente.version() is not None           # canal cifrado vivo
    time.sleep(0.3)
    assert len(m.ctx.sesiones) == 1                # registrada como sesión
    cliente.close()
    hilo.join(timeout=8)
    assert not error, f"El handler falló: {error}"
    assert resultado and resultado[0]["conexiones_aceptadas"] == 1
    assert resultado[0]["tls"] is True
    assert "TLS" in resultado[0]["resumen"]


def test_handshake_plano_no_rompe_el_handler():
    """Un cliente TCP plano (sin TLS) no crashea el listener ni crea sesión."""
    puerto = _puerto_libre()
    m = _modulo_handler_tls(puerto, duracion=2)
    resultado, error = [], []
    hilo = _lanza_handler(m, resultado, error)
    time.sleep(0.4)
    try:
        bruto = socket.create_connection(("127.0.0.1", puerto), timeout=2)
        bruto.sendall(b"GET / HTTP/1.0\r\n\r\n")   # basura para el handshake
        time.sleep(0.3)
        bruto.close()
    except OSError:
        pass
    hilo.join(timeout=6)
    assert not error, f"El handler falló: {error}"
    assert resultado and resultado[0]["conexiones_aceptadas"] == 0
