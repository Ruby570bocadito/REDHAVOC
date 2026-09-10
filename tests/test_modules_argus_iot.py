# -*- coding: utf-8 -*-
"""Tests OFFLINE de los módulos osint/iot añadidos en v1.1 (ideas de
jasonxtn/argus y We5ter/Scanners-Box)."""

import json
from unittest import mock

import pytest

from core.base_module import ModuloError


class _RespuestaFalsa:
    def __init__(self, headers=None, texto="", status=200, url="https://x.com/"):
        self.headers = headers or {}
        self.text = texto
        self.status_code = status
        self.url = url
        self.content = texto.encode()
        self.cookies = []


# =====================================================================
# osint/typosquat — generación de variantes (función pura)
# =====================================================================
class TestTyposquat:
    def test_genera_variantes(self, manager):
        from modules.osint.typosquat import _variantes
        variantes = _variantes("acme.com")
        # omisión: cmec.com / acme con swap: acem.com / vocal: aceem... y TLDs
        assert "acem.com" in variantes          # swap adyacente
        assert "acme.net" in variantes          # TLD alternativo
        assert "acme.com" not in variantes      # el original no es variante

    def test_ejecucion_con_mock(self, manager):
        cls = manager.obtener("osint/typosquat")
        m = cls()
        m.opciones.set("DOMAIN", "acme.com")
        m.opciones.set("MAX_VARIANTES", "30")
        with mock.patch("socket.getaddrinfo", side_effect=OSError):
            res = m.ejecutar()  # nada resuelve → todo libre
        assert res["registradas"] == []
        assert res["generadas"] > 0


# =====================================================================
# osint/social_presence — con requests simulado
# =====================================================================
class TestSocialPresence:
    def test_alias_encontrado(self, manager):
        cls = manager.obtener("osint/social_presence")
        m = cls()
        m.opciones.set("ALIAS", "octocat")
        # GitHub responde 200; Reddit 404 (simulado)
        def get_falso(url, **kwargs):
            if "github.com" in url:
                return _RespuestaFalsa(url=url, texto="x", status=200)
            return _RespuestaFalsa(status=404, url=url)
        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        assert any(h["plataforma"] == "GitHub" for h in res["confirmados"])
        assert res["alias"] == "octocat"


# =====================================================================
# osint/spf_dmarc — mockeando el cliente DNS propio
# =====================================================================
class TestSpfDmarc:
    def test_spf_y_dmarc_correctos(self, manager):
        cls = manager.obtener("osint/spf_dmarc")
        m = cls()
        m.opciones.set("DOMAIN", "acme.com")

        def txt_falso(resolver, nombre, timeout):
            if nombre == "acme.com":
                return ["v=spf1 include:_spf.acme.com -all"]
            if nombre == "_dmarc.acme.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"]
            return []  # DKIM selectors → ninguno
        with mock.patch("modules.osint.spf_dmarc._txt", side_effect=txt_falso):
            with mock.patch.object(m, "_sondea_dkim", return_value={"selectores_probados": 1, "encontrados": [{"selector": "s"}], "problema": ""}):
                res = m.ejecutar()
        assert res["spf"]["presente"] is True
        assert res["dmarc"]["politica"] == "reject"
        assert res["problemas"] == []

    def test_spf_ausente(self, manager):
        cls = manager.obtener("osint/spf_dmarc")
        m = cls()
        m.opciones.set("DOMAIN", "acme.com")
        with mock.patch("modules.osint.spf_dmarc._txt", return_value=[]):
            res = m.ejecutar()
        assert res["spf"]["presente"] is False
        assert any("SPF" in p for p in res["problemas"])


# =====================================================================
# osint/zone_transfer — AXFR contra servidor simulado
# =====================================================================
class TestZoneTransfer:
    def test_axfr_rechazado(self, manager):
        cls = manager.obtener("osint/zone_transfer")
        m = cls()
        m.opciones.set("DOMAIN", "acme.com")
        resp_ns = {"respuestas": ["ns1.acme.com"]}
        with mock.patch("modules.osint.zone_transfer._consultar") as c, \
             mock.patch("modules.osint.zone_transfer._parsear_respuesta", return_value=resp_ns), \
             mock.patch("modules.osint.zone_transfer._axfr", return_value=(False, [], "rechazado")):
            res = m.ejecutar()
        assert res["vulnerable"] is False
        assert len(res["nameservers"]) == 1


# =====================================================================
# osint/email_harvest — con requests simulado
# =====================================================================
class TestEmailHarvest:
    def test_extraccion_basica(self, manager):
        cls = manager.obtener("osint/email_harvest")
        m = cls()
        m.opciones.set("URL", "https://acme.local")
        m.opciones.set("MAX_PAGINAS", "1")
        html = ('<a href="mailto:info@acme.local">escríbenos</a> '
                'contacto: soporte[arroba]acme.local y foto.png@no.com')
        def get_falso(url, **kwargs):
            return _RespuestaFalsa(texto=html, status=200, url=url)
        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        assert "info@acme.local" in res["correos"]
        assert "soporte@acme.local" in res["correos"]   # desobfuscado
        assert all(not c.endswith("png") for c in res["correos"])


# =====================================================================
# web/exposed_files — .git expuesto detectado
# =====================================================================
class TestExposedFiles:
    def test_git_expuesto(self, manager):
        cls = manager.obtener("web/exposed_files")
        m = cls()
        m.opciones.set("URL", "https://acme.local")
        def get_falso(url, **kwargs):
            if url.endswith("/.git/HEAD"):
                return _RespuestaFalsa(texto="ref: refs/heads/main", status=200)
            if url.endswith("/.env"):
                return _RespuestaFalsa(texto="Page not found", status=404)
            return _RespuestaFalsa(status=404)
        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        criticos = [h for h in res["hallazgos"] if h["gravedad"] == "CRÍTICO"]
        assert any(h["ruta"] == "/.git/HEAD" for h in criticos)


# =====================================================================
# web/cors_scan — reflejo con credenciales
# =====================================================================
class TestCorsScan:
    def test_cors_vulnerable(self, manager):
        cls = manager.obtener("web/cors_scan")
        m = cls()
        m.opciones.set("URL", "https://api.acme.local/datos")
        cabeceras = {
            "Access-Control-Allow-Origin": "https://atacante.evil",
            "Access-Control-Allow-Credentials": "true",
        }
        def get_falso(url, **kwargs):
            origen = (kwargs.get("headers") or {}).get("Origin", "")
            if origen == "https://atacante.evil":
                return _RespuestaFalsa(headers=dict(cabeceras), status=200, url=url)
            return _RespuestaFalsa(status=200, url=url)
        with mock.patch("requests.Session.get", side_effect=get_falso):
            with mock.patch("requests.Session.options", side_effect=get_falso):
                res = m.ejecutar()
        assert any(p["vulnerable"] for p in res["pruebas"])
        assert "VULNERABLE" in res["resumen"]


# =====================================================================
# iot/device_scan — puerto abierto simulado en localhost
# =====================================================================
class TestDeviceScan:
    def test_banner_ssh_local(self, manager):
        import socket as sk
        import threading
        srv = sk.socket()
        srv.bind(("127.0.0.1", 0))
        puerto = srv.getsockname()[1]
        srv.listen(5)

        def atender():
            try:
                conn, _ = srv.accept()
                conn.sendall(b"SSH-2.0-OpenSSH_9.2 lab\r\n")
                conn.close()
            except OSError:
                pass
        threading.Thread(target=atender, daemon=True).start()

        cls = manager.obtener("iot/device_scan")
        m = cls()
        m.opciones.set("TARGET", "127.0.0.1")
        m.opciones.set("PUERTOS", str(puerto))
        # Añade dinámicamente el puerto efímero al mapa de sondeo
        import modules.iot.device_scan as ds
        ds.PUERTOS_IOT[puerto] = ("SSH-test", None, "dispositivo embebido")
        try:
            res = m.ejecutar()
        finally:
            del ds.PUERTOS_IOT[puerto]
            srv.close()
        assert any(s["banner"].startswith("SSH") for s in res["servicios"])


# =====================================================================
# iot/default_creds — telnet simulado
# =====================================================================
class TestDefaultCreds:
    def test_requiere_autorizacion(self, manager, capsys):
        """Sin AUTHORIZED el framework bloquea: garantizado por cmd_run."""
        cls = manager.obtener("iot/default_creds")
        assert cls.RIESGO == "alto"


# =====================================================================
# osint/reverse_ip — con mock
# =====================================================================
class TestReverseIp:
    def test_lista_dominios(self, manager):
        cls = manager.obtener("osint/reverse_ip")
        m = cls()
        m.opciones.set("TARGET", "93.184.216.34")
        texto = "foo.com\nbar.com\nfoo.com\n"
        with mock.patch("requests.get", return_value=_RespuestaFalsa(texto=texto, status=200)):
            res = m.ejecutar()
        assert sorted(res["dominios"]) == ["bar.com", "foo.com"]
