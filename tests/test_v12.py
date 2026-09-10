# -*- coding: utf-8 -*-
"""Tests OFFLINE de las novedades v1.2: workspace DB, reporte HTML,
categorías brute/dos, opsec (proxy/mac), phishing/tunnel, ping_sweep y waf_detect."""

import json
from unittest import mock

import pytest

from core.base_module import ModuloError
from core.reporter import Reporter
from core.workspace_db import WorkspaceDB


class _RespuestaFalsa:
    def __init__(self, headers=None, texto="", status=200, url="https://x.com/"):
        self.headers = headers or {}
        self.text = texto
        self.status_code = status
        self.url = url
        self.content = texto.encode()
        self.cookies = []


class _UrlopenFalsa:
    """Reemplazo de urllib.request.urlopen que devuelve JSON por URL."""
    def __init__(self, por_url):
        self.por_url = por_url

    def __call__(self, url, timeout=None):
        import io
        clave = next((k for k in self.por_url if k in url), None)
        cuerpo = json.dumps(self.por_url.get(clave, {})).encode()
        return io.BytesIO(cuerpo)


# =====================================================================
# core/workspace_db
# =====================================================================
class TestWorkspaceDB:
    def test_add_host_y_servicio(self, tmp_path):
        db = WorkspaceDB(tmp_path)
        db.add_host("10.0.0.5", hostname="srv.lab", notas="prueba")
        db.add_service("10.0.0.5", 22, "SSH")
        db.add_service("10.0.0.5", 22, "SSH")  # duplicado → no crece
        hosts = db.hosts()
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "srv.lab"
        assert hosts[0]["servicios"] == ["22/SSH"]

    def test_add_service_crea_host(self, tmp_path):
        db = WorkspaceDB(tmp_path)
        db.add_service("10.0.0.9", 80, "HTTP")
        assert db.total_hosts() == 1

    def test_creds_sin_duplicados(self, tmp_path):
        db = WorkspaceDB(tmp_path)
        db.add_cred("10.0.0.5", "admin", "123456", servicio="ftp")
        db.add_cred("10.0.0.5", "admin", "123456", servicio="ftp")
        assert db.total_creds() == 1
        assert db.creds()[0]["usuario"] == "admin"

    def test_persistencia_entre_instancias(self, tmp_path):
        db1 = WorkspaceDB(tmp_path)
        db1.add_host("10.1.1.1")
        db2 = WorkspaceDB(tmp_path)
        assert db2.total_hosts() == 1

    def test_db_corrupta_no_explota(self, tmp_path):
        (tmp_path / "db.json").write_text("{no-es-json", encoding="utf-8")
        db = WorkspaceDB(tmp_path)
        assert db.total_hosts() == 0

    def test_limpiar(self, tmp_path):
        db = WorkspaceDB(tmp_path)
        db.add_host("10.0.0.1")
        db.limpiar()
        assert db.total_hosts() == 0 and db.total_creds() == 0

    def test_resumen(self, tmp_path):
        db = WorkspaceDB(tmp_path)
        db.add_host("10.0.0.1")
        db.add_cred("10.0.0.1", "a", "b")
        assert "1 hosts" in db.resumen() and "1 creds" in db.resumen()


# =====================================================================
# reporter — HTML
# =====================================================================
class TestReporterHTML:
    def test_genera_json_md_html(self, tmp_path):
        rep = Reporter(tmp_path)
        ruta = rep.guardar("web/waf_detect", "http://lab", {"waf": "Cloudflare"},
                           {"URL": "http://lab"})
        base = str(ruta)[:-5]
        assert ruta.exists()
        html = open(base + ".html", encoding="utf-8").read()
        assert "REDHAVOC" in html
        assert "Cloudflare" in html
        assert "waf_detect" in html
        # el HTML escapa el markup peligroso
        rep2 = Reporter(tmp_path)
        rep2.guardar("m", "<script>alert(1)</script>", {"x": "<b>"}, {})
        html2 = open(str(rep2.ultimo_reporte)[:-5] + ".html", encoding="utf-8").read()
        assert "<script>alert" not in html2
        assert "&lt;script&gt;" in html2


# =====================================================================
# framework — comandos hosts/creds
# =====================================================================
class TestComandosWorkspace:
    @pytest.fixture()
    def fw(self, tmp_path, raiz):
        from core.framework import RedHavocFramework
        marco = RedHavocFramework(tmp_path)
        return marco

    def _ejecuta(self, fw, linea):
        fw._procesar(linea)

    def test_hosts_vacio_y_relleno(self, fw, capsys):
        self._ejecuta(fw, "hosts")
        fw.workspace_db.add_host("10.0.0.3", hostname="pc1")
        self._ejecuta(fw, "hosts")
        salida = capsys.readouterr().out
        assert "10.0.0.3" in salida and "pc1" in salida

    def test_creds_relleno_y_limpiar(self, fw, capsys):
        fw.workspace_db.add_cred("10.0.0.3", "admin", "123456", servicio="ssh")
        self._ejecuta(fw, "creds")
        salida = capsys.readouterr().out
        assert "admin" in salida and "123456" in salida
        self._ejecuta(fw, "creds -c")
        assert fw.workspace_db.total_creds() == 0

    def test_port_scanner_rellena_workspace(self, fw):
        cls = fw.module_manager.obtener("recon/port_scanner")
        m = cls()
        m.opciones.set("TARGET", "127.0.0.1")
        m.opciones.set("PORTS", "9999")
        m.ctx = fw.ctx
        with mock.patch("socket.gethostbyname", return_value="127.0.0.1"), \
             mock.patch("modules.recon.port_scanner._escanear_puerto",
                        return_value=(9999, True, "?", "banner")):
            m.ejecutar()
        hosts = fw.workspace_db.hosts()
        assert hosts and hosts[0]["ip"] == "127.0.0.1"
        assert "9999/?" in hosts[0]["servicios"]


# =====================================================================
# brute — listas y módulos
# =====================================================================
class TestListasBrute:
    def test_wordlist_incluida(self):
        from modules.brute import usuarios_desde_listas
        usuarios = usuarios_desde_listas("usuarios_lab.txt")
        assert "admin" in usuarios and "root" in usuarios

    def test_lista_csv(self):
        from modules.brute import claves_desde_listas
        assert claves_desde_listas("a, b, c") == ["a", "b", "c"]

    def test_limite(self):
        from modules.brute import usuarios_desde_listas
        assert len(usuarios_desde_listas("a,b,c,d,e", limite=2)) == 2


class TestBruteFtp:
    def test_login_valido_para_y_para(self, manager):
        cls = manager.obtener("brute/ftp_login")
        m = cls()
        m.opciones.set("TARGET", "10.0.0.5")
        m.opciones.set("USERS", "admin,usuario")
        m.opciones.set("PASS", "123456,password")
        with mock.patch("modules.brute.ftp_login.ftplib.FTP") as ftp_cls:
            ftp = ftp_cls.return_value.__enter__.return_value
            ftp.getwelcome.return_value = "220 Bienvenido"
            # login OK solo con admin/123456
            ftp.login.side_effect = lambda u, p: None if (u, p) == ("admin", "123456") \
                else (_ for _ in ()).throw(__import__("ftplib").error_perm("530"))
            res = m.ejecutar()
        assert res["credenciales_validas"] == [{"usuario": "admin", "clave": "123456"}]
        assert res["pares_probados"] == 1

    def test_conexion_rechazada(self, manager):
        cls = manager.obtener("brute/ftp_login")
        m = cls()
        m.opciones.set("TARGET", "10.0.0.5")
        with mock.patch("modules.brute.ftp_login.ftplib.FTP") as ftp_cls:
            ftp_cls.return_value.__enter__.side_effect = OSError("conexión rehusada")
            with pytest.raises(ModuloError):
                m.ejecutar()


class TestBruteHttpBasic:
    def test_requiere_basic_auth(self, manager):
        cls = manager.obtener("brute/http_basic")
        m = cls()
        m.opciones.set("URL", "http://lab/admin")
        # el servidor responde 200 sin WWW-Authenticate → error limpio
        with mock.patch("requests.Session.get",
                        return_value=_RespuestaFalsa(status=200)):
            with pytest.raises(ModuloError):
                m.ejecutar()

    def test_credencial_valida(self, manager):
        cls = manager.obtener("brute/http_basic")
        m = cls()
        m.opciones.set("URL", "http://lab/admin")
        m.opciones.set("USERS", "admin")
        m.opciones.set("PASS", "123456,otra")

        def get_falso(url, **kwargs):
            auth = kwargs.get("headers", {}).get("Authorization", "")
            if not auth:
                return _RespuestaFalsa(status=401,
                                       headers={"WWW-Authenticate": 'Basic realm="lab"'})
            import base64
            token = auth.replace("Basic ", "")
            if base64.b64decode(token).decode() == "admin:123456":
                return _RespuestaFalsa(status=200)
            return _RespuestaFalsa(status=401)

        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        assert res["credenciales_validas"] == [{"usuario": "admin", "clave": "123456"}]
        assert res["realm"] == "lab"


class TestBruteSsh:
    def test_paramiko_ausente_error_limpio(self, manager):
        cls = manager.obtener("brute/ssh_login")
        m = cls()
        m.opciones.set("TARGET", "10.0.0.5")
        import modules.brute.ssh_login as mod
        with mock.patch.object(mod, "PARAMIKO_OK", False):
            with pytest.raises(ModuloError, match="paramiko"):
                m.ejecutar()

    def test_banner_no_ssh(self, manager):
        cls = manager.obtener("brute/ssh_login")
        m = cls()
        m.opciones.set("TARGET", "10.0.0.5")
        import modules.brute.ssh_login as mod
        if not mod.PARAMIKO_OK:
            pytest.skip("paramiko no instalado")
        ctx = mock.mock_open(read_data=b"HTTP/1.1 200 OK\r\n")
        with mock.patch("socket.create_connection") as conn, \
             mock.patch.object(mock.Mock, "recv", return_value=b"HTTP/1.1 200 OK"):
            conn.return_value.__enter__.return_value.recv.return_value = b"HTTP/1.1 200"
            with pytest.raises(ModuloError, match="SSH"):
                m.ejecutar()


# =====================================================================
# dos/stress_http
# =====================================================================
class TestStressHttp:
    def test_tope_duracion_y_hilos(self):
        from modules.dos.stress_http import DURACION_MAX, HILOS_MAX, RPS_MAX, StressHttp
        duracion, hilos, rps = StressHttp.acotar(9999, 9999, 9999)
        assert duracion == DURACION_MAX
        assert hilos == HILOS_MAX
        assert rps * hilos <= RPS_MAX

    def test_tope_minimo(self):
        from modules.dos.stress_http import StressHttp
        duracion, hilos, rps = StressHttp.acotar(0, 0, 0)
        assert duracion >= 1 and hilos >= 1 and rps >= 1

    def test_objetivo_caido(self, manager):
        cls = manager.obtener("dos/stress_http")
        m = cls()
        m.opciones.set("URL", "http://lab/")
        import requests as rq
        with mock.patch("requests.get", side_effect=rq.ConnectionError("down")):
            with pytest.raises(ModuloError):
                m.ejecutar()

    def test_metricas(self, manager):
        cls = manager.obtener("dos/stress_http")
        m = cls()
        m.opciones.set("URL", "http://lab/")
        m.opciones.set("DURACION", "1")
        m.opciones.set("RPS", "50")
        with mock.patch("requests.get", return_value=_RespuestaFalsa(status=200)), \
             mock.patch("requests.Session.get", return_value=_RespuestaFalsa(status=200)):
            res = m.ejecutar()
        assert res["peticiones_enviadas"] > 0
        assert res["codigos_http"].get(200, 0) > 0


# =====================================================================
# opsec/proxy_check + opsec/mac_changer
# =====================================================================
class TestProxyCheck:
    def test_sin_fuga_con_tor(self, manager):
        cls = manager.obtener("opsec/proxy_check")
        m = cls()
        datos = {
            "ip-api.com": {"query": "1.2.3.4", "country": "ES", "isp": "Tor Exit",
                           "proxy": True, "hosting": False, "mobile": False, "org": "tor"},
            "ipify": {"ip": "1.2.3.4"},
            "torproject": {"IsTor": True},
        }
        with mock.patch("urllib.request.urlopen", side_effect=_UrlopenFalsa(datos)):
            res = m.ejecutar()
        assert res["fuga_detectada"] is False
        assert res["anonimo"] is True
        assert res["es_tor"] is True

    def test_fuga_detectada(self, manager):
        cls = manager.obtener("opsec/proxy_check")
        m = cls()
        datos = {
            "ip-api.com": {"query": "9.9.9.9", "country": "ES", "isp": "Movistar",
                           "proxy": False, "hosting": False, "mobile": False},
            "ipify": {"ip": "8.8.8.8"},
        }
        with mock.patch("urllib.request.urlopen", side_effect=_UrlopenFalsa(datos)):
            res = m.ejecutar()
        assert res["fuga_detectada"] is True
        assert res["anonimo"] is False

    def test_exigir_proxy_falla(self, manager):
        cls = manager.obtener("opsec/proxy_check")
        m = cls()
        m.opciones.set("EXIGIR_PROXY", "true")
        datos = {"ip-api.com": {"query": "9.9.9.9", "proxy": False, "hosting": False}}
        with mock.patch("urllib.request.urlopen", side_effect=_UrlopenFalsa(datos)):
            with pytest.raises(ModuloError, match="OPSEC"):
                m.ejecutar()


class TestMacChanger:
    def test_mac_aleatoria_valida(self):
        from modules.opsec.mac_changer import _mac_aleatoria
        import re
        for _ in range(20):
            assert re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", _mac_aleatoria())

    def test_sin_root_error_limpio(self, manager):
        cls = manager.obtener("opsec/mac_changer")
        m = cls()
        m.opciones.set("IFACE", "eth0")
        with mock.patch.object(m, "_es_root", return_value=False):
            with pytest.raises(ModuloError, match="root"):
                m.ejecutar()

    def test_mac_invalida(self, manager):
        cls = manager.obtener("opsec/mac_changer")
        m = cls()
        m.opciones.set("IFACE", "eth0")
        m.opciones.set("MAC", "zz:zz")
        with mock.patch.object(m, "_es_root", return_value=True):
            with pytest.raises(ModuloError, match="MAC inválida"):
                m.ejecutar()


# =====================================================================
# phishing/tunnel
# =====================================================================
class TestTunnel:
    @pytest.fixture()
    def ssh_falso(self):
        with mock.patch("shutil.which", return_value="/usr/bin/ssh"):
            yield

    def test_comando_serveo(self, manager, ssh_falso):
        cls = manager.obtener("phishing/tunnel")
        m = cls()
        m.opciones.set("PORT", "8080")
        m.opciones.set("PROVEEDOR", "serveo")
        cmd = m._comando_ssh("serveo", 8080)
        assert cmd[0] == "/usr/bin/ssh"
        assert "-R" in cmd and "80:localhost:8080" in cmd
        assert "serveo.net" in cmd

    def test_comando_localhost_run(self, manager, ssh_falso):
        cls = manager.obtener("phishing/tunnel")
        m = cls()
        cmd = m._comando_ssh("localhost.run", 8081)
        assert "nokey@localhost.run" in cmd

    def test_proveedor_desconocido(self, manager, ssh_falso):
        cls = manager.obtener("phishing/tunnel")
        m = cls()
        with pytest.raises(ModuloError):
            m._comando_ssh("maloso", 80)

    def test_ssh_ausente(self, manager):
        cls = manager.obtener("phishing/tunnel")
        m = cls()
        with mock.patch("shutil.which", return_value=None):
            with pytest.raises(ModuloError, match="ssh"):
                m._comando_ssh("serveo", 8080)

    def test_leer_url(self, manager):
        cls = manager.obtener("phishing/tunnel")
        m = cls()
        assert m._leer_url("Forwarding HTTP traffic to https://abcdef.serveo.net") == \
            "https://abcdef.serveo.net"
        assert m._leer_url("nada por aquí localhost:8080") is None


# =====================================================================
# recon/ping_sweep
# =====================================================================
class TestPingSweep:
    def test_redes_validas(self, manager):
        from modules.recon.ping_sweep import _red_desde
        assert str(_red_desde("192.168.1.0/24")) == "192.168.1.0/24"
        assert str(_red_desde("192.168.1.77/24")) == "192.168.1.0/24"  # strict=False
        assert str(_red_desde("10.0.0.5")) == "10.0.0.5/32"

    def test_red_invalida(self, manager):
        from modules.recon.ping_sweep import _red_desde
        with pytest.raises(ModuloError):
            _red_desde("no-es-una-red")

    def test_sweep_con_mock(self, manager):
        cls = manager.obtener("recon/ping_sweep")
        m = cls()
        m.opciones.set("TARGET", "127.0.0.1/32")
        m.opciones.set("ICMP", "false")
        with mock.patch("modules.recon.ping_sweep._tcp_vivo", return_value=[80]):
            res = m.ejecutar()
        assert res["vivos"] == [{"ip": "127.0.0.1", "puertos_tcp": [80]}]
        assert res["explorados"] == 1

    def test_sweep_sin_vivos(self, manager):
        cls = manager.obtener("recon/ping_sweep")
        m = cls()
        m.opciones.set("TARGET", "127.0.0.1/32")
        m.opciones.set("ICMP", "false")
        with mock.patch("modules.recon.ping_sweep._tcp_vivo", return_value=[]):
            res = m.ejecutar()
        assert res["vivos"] == []
        assert res["explorados"] == 1


# =====================================================================
# web/waf_detect
# =====================================================================
class TestWafDetect:
    def test_cloudflare_por_cabecera(self, manager):
        cls = manager.obtener("web/waf_detect")
        m = cls()
        m.opciones.set("URL", "http://lab/")
        cf = {"cf-ray": "abc123", "Server": "cloudflare", "Set-Cookie": "__cf_bm=x"}
        with mock.patch("requests.Session.get",
                        return_value=_RespuestaFalsa(headers=cf, status=200)):
            res = m.ejecutar()
        assert res["waf"] == "Cloudflare"
        assert "Cloudflare" in res["firmas"]

    def test_bloqueo_generico_sin_firma(self, manager):
        cls = manager.obtener("web/waf_detect")
        m = cls()
        m.opciones.set("URL", "http://lab/")

        def get_falso(url, **kwargs):
            if "id=" in url:
                return _RespuestaFalsa(status=403, texto="Request blocked by security policy")
            return _RespuestaFalsa(status=200, texto="normal")

        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        assert res["sonda_bloqueada"] is True
        assert res["waf"] == "WAF desconocido (bloqueo genérico)"

    def test_sin_waf(self, manager):
        cls = manager.obtener("web/waf_detect")
        m = cls()
        m.opciones.set("URL", "http://lab/")

        def get_falso(url, **kwargs):
            if "id=" in url:
                return _RespuestaFalsa(status=200, texto="pagina normal")
            return _RespuestaFalsa(status=200, texto="normal", headers={"Server": "nginx"})

        with mock.patch("requests.Session.get", side_effect=get_falso):
            res = m.ejecutar()
        assert res["waf"] == "sin WAF conocido"

    def test_objetivo_inaccesible(self, manager):
        cls = manager.obtener("web/waf_detect")
        m = cls()
        m.opciones.set("URL", "http://lab/")
        import requests as rq
        with mock.patch("requests.Session.get", side_effect=rq.ConnectionError("down")):
            with pytest.raises(ModuloError):
                m.ejecutar()
