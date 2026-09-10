# -*- coding: utf-8 -*-
"""Tests OFFLINE de los módulos (sin red o con mocks)."""

import json
from unittest import mock

import pytest

from core.base_module import ModuloError


# =====================================================================
# Utilidades offline
# =====================================================================
class TestGeneradoresOffline:
    """payloads/* y phishing/template_gen: generan ficheros sin red."""

    def test_macro_gen_crea_ficheros(self, manager, tmp_path):
        cls = manager.obtener("payloads/macro_gen")
        m = cls()
        m.opt("NOMBRE", "t1")  # noop, garantiza API
        m.opciones.set("NOMBRE", "t1")
        m.opciones.set("AUTHORIZED", "true")
        res = m.ejecutar()
        carpeta = res["carpeta"]
        assert (f"{carpeta}/macro_t1.vba")
        assert (f"{carpeta}/README.md")
        assert "T1204" in res["tecnica"]

    def test_dll_sideload_crea_proyecto(self, manager):
        cls = manager.obtener("payloads/dll_sideload")
        m = cls()
        m.opciones.set("NOMBRE", "prueba_x")
        res = m.ejecutar()
        assert res["carpeta"].endswith("dll_sideload_prueba_x")
        assert any(f.endswith("main.cpp") for f in res["ficheros"])
        assert any(f.endswith("exports.def") for f in res["ficheros"])

    def test_loader_gen_crea_runners(self, manager):
        cls = manager.obtener("payloads/loader_gen")
        m = cls()
        m.opciones.set("NOMBRE", "lab2")
        res = m.ejecutar()
        assert any("runner_windows.c" in f for f in res["ficheros"])
        assert any("runner_linux.c" in f for f in res["ficheros"])

    def test_template_gen_plantilla_inexistente(self, manager):
        cls = manager.obtener("phishing/template_gen")
        m = cls()
        m.opciones.set("PLANTILLA", "no_existe_xxx")
        with pytest.raises(ModuloError):
            m.ejecutar()

    def test_template_gen_ok(self, manager):
        cls = manager.obtener("phishing/template_gen")
        m = cls()
        m.opciones.set("PLANTILLA", "portal_corporativo")
        m.opciones.set("ORG", "ACME Corp")
        m.opciones.set("NOMBRE_SALIDA", "test_campana")
        res = m.ejecutar()
        html = open(res["fichero_html"], encoding="utf-8").read()
        assert "ACME Corp" in html
        assert "{{ORG}}" not in html  # marcadores sustituidos


# =====================================================================
# port_scanner contra localhost (offline real)
# =====================================================================
class TestPortScanner:
    def test_parseo_puertos(self, manager):
        cls = manager.obtener("recon/port_scanner")
        m = cls()
        assert m._parsear_puertos("80,443,8000-8005") == [80, 443, 8000, 8001, 8002, 8003, 8004, 8005]

    def test_parseo_invalido(self, manager):
        cls = manager.obtener("recon/port_scanner")
        m = cls()
        with pytest.raises(ModuloError):
            m._parsear_puertos("abc")
        with pytest.raises(ModuloError):
            m._parsear_puertos("1-999999")

    def test_escaneo_localhost_con_puerto_abierto(self, manager):
        import socket as sk
        import threading

        # Servidor local efímero
        srv = sk.socket()
        srv.bind(("127.0.0.1", 0))
        puerto = srv.getsockname()[1]
        srv.listen(5)

        def aceptar():
            try:
                srv.accept()
            except OSError:
                pass

        hilo = threading.Thread(target=aceptar, daemon=True)
        hilo.start()

        cls = manager.obtener("recon/port_scanner")
        m = cls()
        m.opciones.set("TARGET", "127.0.0.1")
        m.opciones.set("PORTS", str(puerto))
        res = m.ejecutar()
        assert any(p["puerto"] == puerto for p in res["abiertos"])
        srv.close()


# =====================================================================
# dns_enum contra 1.1.1.1 requiere red → test unitario del parser con mock
# =====================================================================
class TestDnsEnumParser:
    def test_parsear_respuesta_a(self, manager):
        from modules.recon.dns_enum import _parsear_respuesta, _pregunta
        import struct

        # Construye una respuesta DNS mínima sintética: 1 question + 1 answer A=93.184.216.34
        nombre = b"\x07example\x03com\x00"
        pregunta = nombre + struct.pack(">HH", 1, 1)
        cabecera = struct.pack(">HHHHHH", 1234, 0x8180, 1, 1, 0, 0)
        respuesta_r = nombre + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
        paquete = cabecera + pregunta + respuesta_r
        parsed = _parsear_respuesta(paquete, 1)
        assert parsed["respuestas"] == ["93.184.216.34"]
        assert _pregunta("example.com", 1)  # no lanza


# =====================================================================
# http_headers / tech_detect con requests simulado
# =====================================================================
class _RespuestaFalsa:
    def __init__(self, headers, texto="", status=200, url="https://x.com/"):
        self.headers = headers
        self.text = texto
        self.status_code = status
        self.url = url
        self.content = texto.encode()
        self.cookies = []


class TestHttpHeaders:
    def test_auditoria_con_mock(self, manager):
        cls = manager.obtener("recon/http_headers")
        m = cls()
        m.opciones.set("URL", "https://example.com")
        resp = _RespuestaFalsa({"Server": "nginx", "Content-Security-Policy": "default-src 'self'"})
        with mock.patch("requests.Session.get", return_value=resp):
            res = m.ejecutar()
        assert res["puntuacion_seguridad"] < 100
        ausentes = {a["cabecera"] for a in res["seguridad_ausentes"]}
        assert "Strict-Transport-Security" in ausentes
        assert "Content-Security-Policy" not in ausentes


class TestTechDetect:
    def test_deteccion_wordpress(self, manager):
        cls = manager.obtener("web/tech_detect")
        m = cls()
        m.opciones.set("URL", "https://blog.local")
        resp = _RespuestaFalsa(
            {"Server": "Apache", "X-Powered-By": "PHP/8.1"},
            texto="<div id='wp-content'>hola<script src='/wp-json'></script>",
        )
        with mock.patch("requests.get", return_value=resp):
            res = m.ejecutar()
        assert "WordPress" in res["tecnologias"]
        assert "Apache" in res["tecnologias"]
        assert "PHP" in res["tecnologias"]


# =====================================================================
# mailer en modo DRY_RUN (sin red)
# =====================================================================
class TestMailer:
    def test_dry_run_no_envia(self, manager, capsys):
        cls = manager.obtener("phishing/mailer")
        m = cls()
        m.opciones.set("SMTP_HOST", "smtp.local")
        m.opciones.set("TO", "a@lab.local, b@lab.local")
        res = m.ejecutar()
        assert res["modo"] == "dry_run"
        assert len(res["destinatarios"]) == 2

    def test_max_destinatarios(self, manager):
        cls = manager.obtener("phishing/mailer")
        m = cls()
        m.opciones.set("SMTP_HOST", "smtp.local")
        m.opciones.set("TO", ",".join(f"u{i}@lab.local" for i in range(250)))
        with pytest.raises(ModuloError):
            m.ejecutar()


# =====================================================================
# ip_info con mock de la API
# =====================================================================
class TestIpInfo:
    def test_ip_info_mock(self, manager):
        cls = manager.obtener("recon/ip_info")
        m = cls()
        m.opciones.set("TARGET", "example.com")

        respuesta_api = json.dumps({
            "status": "success", "country": "United States", "city": "Mountain View",
            "isp": "Google LLC", "query": "8.8.8.8", "lat": 37.4, "lon": -122.08,
            "mobile": False, "proxy": False, "hosting": True,
        }).encode()

        falsa = mock.Mock()
        falsa.read.return_value = respuesta_api
        falsa.__enter__ = mock.Mock(return_value=falsa)
        falsa.__exit__ = mock.Mock(return_value=False)

        with mock.patch("socket.gethostbyname", return_value="8.8.8.8"):
            with mock.patch("urllib.request.urlopen", return_value=falsa):
                res = m.ejecutar()
        assert res["isp"] == "Google LLC"
        assert res["hosting"] is True
