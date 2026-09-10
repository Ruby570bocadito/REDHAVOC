# -*- coding: utf-8 -*-
"""Tests v1.3 (parte 2): post/host_audit, osint extendido con mocks y
comandos del framework (attack, engagement + enforcement en run)."""

import json
from unittest import mock

import pytest

from core.base_module import ModuloError

from tests.test_v13 import TestLdapMin  # noqa: F401  (fixture helper reutilizado)


class _RespuestaFalsa:
    def __init__(self, headers=None, texto="", status=200):
        self.headers = headers or {}
        self.text = texto
        self.status_code = status
        self.content = texto.encode()
        self.cookies = []

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return json.loads(self.text)


@pytest.fixture()
def fw(tmp_path):
    from core.framework import RedHavocFramework
    return RedHavocFramework(tmp_path)


# =====================================================================
# post/host_audit
# =====================================================================
class TestHostAudit:
    def test_genera_ps1(self, fw, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.post.host_audit.SALIDA_RAIZ", tmp_path)
        cls = fw.module_manager.obtener("post/host_audit")
        mod = cls()
        mod.opciones.set("NOMBRE", "lab1")
        r = mod.ejecutar()
        ps1 = tmp_path / "audit_lab1" / "lab1.ps1"
        assert ps1.exists()
        contenido = ps1.read_text(encoding="utf-8")
        for funcion in ("Get-AuditSystem", "Get-AuditNetwork", "Get-AuditDefense",
                        "Get-AuditUsers", "Get-AuditProcesses", "Get-AuditServices",
                        "Get-AuditScheduledTasks", "Get-AuditRecentFiles",
                        "Get-AuditInstalledApps", "Get-AuditBrowserData",
                        "Get-AuditCredentialFiles", "Invoke-AuditHost"):
            assert funcion in contenido, funcion
        # Por diseño: SIN técnicas evasivas
        assert "AmsiScanBuffer" not in contenido
        assert "Invoke-AMSIBypass" not in contenido
        assert "ninguna" in r["evasion_incluida"]

    def test_sin_wifi_por_defecto(self, fw, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.post.host_audit.SALIDA_RAIZ", tmp_path)
        cls = fw.module_manager.obtener("post/host_audit")
        mod = cls()
        mod.opciones.set("NOMBRE", "sinwifi")
        r = mod.ejecutar()
        contenido = (tmp_path / "audit_sinwifi" / "sinwifi.ps1").read_text(encoding="utf-8")
        assert "WiFiPasswords = Get-AuditWiFiPasswords" not in contenido
        assert "BrowserData = Get-AuditBrowserData" in contenido
        assert "WiFiPasswords" not in r["modulos_colecta"]

    def test_con_wifi(self, fw, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.post.host_audit.SALIDA_RAIZ", tmp_path)
        cls = fw.module_manager.obtener("post/host_audit")
        mod = cls()
        mod.opciones.set("INCLUIR_WIFI", "true")
        r = mod.ejecutar()
        assert "WiFiPasswords" in r["modulos_colecta"]

    def test_riesgo_alto_requiere_authorized(self, fw):
        fw._procesar("use post/host_audit")
        fw._procesar("run")           # sin AUTHORIZED → bloqueado por ética
        # el módulo no produjo informe
        assert fw.reporter.ultimo_reporte is None


# =====================================================================
# osint extendido (requests mockeado)
# =====================================================================
class TestCertTransparency:
    def test_combina_fuentes(self, fw, monkeypatch):
        monkeypatch.setattr("requests.get", lambda *a, **k: _RespuestaFalsa(
            texto=json.dumps([{"name_value": "www.acme.com\nmail.acme.com"},
                              {"name_value": "*.acme.com"}])))
        cls = fw.module_manager.obtener("osint/cert_transparency")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        r = mod.ejecutar()
        assert "crt.sh" in r["fuentes"]
        assert r["subdominios"] == ["mail.acme.com", "www.acme.com"]
        assert r["wildcards"] == ["*.acme.com"]

    def test_todas_ko_lanza(self, fw, monkeypatch):
        import requests as rq
        def explota(*a, **k):
            raise rq.RequestException("sin red")
        monkeypatch.setattr("requests.get", explota)
        cls = fw.module_manager.obtener("osint/cert_transparency")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        with pytest.raises(ModuloError):
            mod.ejecutar()


class TestWaybackUrls:
    def test_clasifica(self, fw, monkeypatch):
        filas = [["original", "mimetype", "statuscode"],
                 ["https://www.acme.com/informes/q1.pdf", "application/pdf", "200"],
                 ["https://api.acme.com/v1/users?id=3", "application/json", "200"],
                 ["https://old.acme.com/home", "text/html", "404"]]
        monkeypatch.setattr("requests.get",
                            lambda *a, **k: _RespuestaFalsa(texto=json.dumps(filas)))
        cls = fw.module_manager.obtener("osint/wayback_urls")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        r = mod.ejecutar()
        assert r["documentos"] == ["https://www.acme.com/informes/q1.pdf"]
        assert r["con_parametros"] == ["https://api.acme.com/v1/users?id=3"]
        assert "old.acme.com" in r["subdominios"]

    def test_vacio(self, fw, monkeypatch):
        monkeypatch.setattr("requests.get",
                            lambda *a, **k: _RespuestaFalsa(texto=json.dumps([])))
        cls = fw.module_manager.obtener("osint/wayback_urls")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        r = mod.ejecutar()
        assert r["endpoints"] == [] and "sin URLs" in r["resumen"]


class TestRdapLookup:
    def test_dominio(self, fw, monkeypatch):
        datos = {"entities": [{"roles": ["registrar"],
                               "vcardArray": ["vcard", [["fn", {}, "text", "Registrar X"],
                                                        ["email", {}, "text", "abuse@regx.com"]]]}],
                 "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
                 "nameservers": [{"ldhName": "NS1.ACME.COM"}],
                 "status": ["client transfer prohibited"]}
        monkeypatch.setattr("requests.get", lambda *a, **k: _RespuestaFalsa(texto=json.dumps(datos)))
        cls = fw.module_manager.obtener("osint/rdap_lookup")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        r = mod.ejecutar()
        assert r["tipo"] == "domain" and r["registrar"] == "Registrar X"
        assert r["abuse"] == "abuse@regx.com"
        assert r["nameservers"] == ["NS1.ACME.COM"]

    def test_ip_asn(self, fw, monkeypatch):
        datos = {"handle": "AS64512", "country": "ES",
                 "startAddress": "10.20.0.0", "endAddress": "10.20.255.255",
                 "type": "DIRECT ALLOCATION",
                 "entities": [{"roles": ["administrative"],
                               "vcardArray": ["vcard", [["fn", {}, "text", "ACME NET"]]]}]}
        captura = {}

        def falso_get(url, *a, **k):
            captura["url"] = url
            return _RespuestaFalsa(texto=json.dumps(datos))

        monkeypatch.setattr("requests.get", falso_get)
        cls = fw.module_manager.obtener("osint/rdap_lookup")
        mod = cls()
        mod.opciones.set("TARGET", "10.20.1.2")
        r = mod.ejecutar()
        assert "/ip/" in captura["url"]
        assert r["tipo"] == "ip" and r["asn"] == "AS64512" and r["pais"] == "ES"


class TestDocMetadata:
    def test_ooxml_y_correos(self, fw, tmp_path, monkeypatch):
        import io
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr("docProps/core.xml",
                       '<?xml version="1.0"?><cp:coreProperties '
                       'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                       'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">'
                       '<dc:creator>María García</dc:creator>'
                       '<cp:lastModifiedBy>maria.garcia@acme.com</cp:lastModifiedBy>'
                       '</cp:coreProperties>')
            z.writestr("docProps/app.xml",
                       '<Properties><Application>Microsoft Office Word</Application>'
                       '<Company>ACME SL</Company></Properties>')
        respuesta = _RespuestaFalsa(texto="no importa")
        respuesta.content = buffer.getvalue()
        monkeypatch.setattr("requests.get", lambda *a, **k: respuesta)
        cls = fw.module_manager.obtener("osint/doc_metadata")
        mod = cls()
        mod.opciones.set("URLS", "https://acme.com/plan.docx")
        r = mod.ejecutar()
        assert r["documentos"][0]["tipo"] == "ooxml"
        assert r["documentos"][0]["application"].lower() == "microsoft office word"
        assert "maria.garcia@acme.com" in r["correos"]
        assert "María García" in r["personas"]

    def test_pdf_sin_pypdf_fallback(self, fw, monkeypatch):
        cuerpo = b"%PDF-1.4\n/Author (Sr. Test)\n/Producer (Word)\n"
        respuesta = _RespuestaFalsa(texto="x")
        respuesta.content = cuerpo
        monkeypatch.setattr("requests.get", lambda *a, **k: respuesta)
        cls = fw.module_manager.obtener("osint/doc_metadata")
        mod = cls()
        mod.opciones.set("URLS", "https://acme.com/doc.pdf")
        r = mod.ejecutar()
        assert r["documentos"][0]["tipo"] == "pdf"
        assert r["documentos"][0]["author"] == "Sr. Test"


class TestPasteSearch:
    def test_busca_y_filtra(self, fw, monkeypatch):
        def falso_get(url, *a, **k):
            if "/api/search/" in url:
                return _RespuestaFalsa(texto=json.dumps({"count": 2, "data": ["abc123", "def456"]}))
            if "abc123" in url:
                return _RespuestaFalsa(texto=json.dumps(
                    {"text": "vendo accessos de acme.com admin:admin"}))
            return _RespuestaFalsa(texto=json.dumps({"text": "sin nada útil"}))

        monkeypatch.setattr("requests.get", falso_get)
        cls = fw.module_manager.obtener("osint/paste_search")
        mod = cls()
        mod.opciones.set("TARGET", "acme.com")
        r = mod.ejecutar()
        assert r["total_indexado"] == 2
        assert len(r["pastes"][0]["coincidencias"]) == 1


class TestEmailVerify:
    def test_sin_mx(self, fw, monkeypatch):
        monkeypatch.setattr("modules.osint.email_verify.resolver_mx", lambda d, timeout=5: [])
        cls = fw.module_manager.obtener("osint/email_verify")
        mod = cls()
        mod.opciones.set("CORREOS", "a@desconocido.local")
        with pytest.raises(ModuloError):
            mod.ejecutar()

    def test_clasificacion(self, fw, monkeypatch):
        monkeypatch.setattr("modules.osint.email_verify.resolver_mx",
                            lambda d, timeout=5: [(10, "mx.acme.com")])
        estados = {"si@acme.com": 250, "no@acme.com": 550, "quizas@acme.com": 451}

        class FalsoSMTP:
            def __init__(self, mx, puerto, timeout=None):
                self.correo = None

            def helo(self, nombre):
                pass

            def docmd(self, cmd, arg=""):
                if cmd == "RCPT":
                    correo = arg[4:-1]
                    return (estados[correo], "ok")
                return (250, "ok")

            def quit(self):
                pass

        monkeypatch.setattr("smtplib.SMTP", FalsoSMTP)
        cls = fw.module_manager.obtener("osint/email_verify")
        mod = cls()
        mod.opciones.set("CORREOS", "si@acme.com,no@acme.com,quizas@acme.com")
        mod.opciones.set("PAUSA_MS", "0")
        r = mod.ejecutar()
        assert r["confirmados"] == ["si@acme.com"]
        assert r["inexistentes"] == ["no@acme.com"]
        assert r["desconocidos"] == ["quizas@acme.com"]


# =====================================================================
# framework: attack + engagement (comandos y enforcement)
# =====================================================================
class TestComandoAttack:
    def test_lista_tecnicas(self, fw):
        fw._procesar("attack")
        # sin excepción basta; filtramos ahora
        fw._procesar("attack T1558")

    def test_filtro_sin_resultados(self, fw):
        fw._procesar("attack T9999")

    def test_ad_tiene_tags(self, fw):
        cls = fw.module_manager.obtener("ad/passwd_spray")
        assert "T1110.003" in cls.ATTCK


class TestComandoEngagement:
    def _engagement(self, fw, tmp_path, **datos):
        base = {"nombre": "lab", "alcance": ["corp.local", "10.0.0.0/24"],
                "excluidos": [], "permitir_fuera_alcance": False}
        base.update(datos)
        fichero = tmp_path / "eng.json"
        fichero.write_text(json.dumps(base), encoding="utf-8")
        fw._procesar(f"engagement load {fichero}")
        return fichero

    def test_load_y_estado(self, fw, tmp_path):
        self._engagement(fw, tmp_path)
        assert fw.engagement.activo()
        fw._procesar("engagement")            # muestra panel
        fw._procesar("engagement clear")
        assert not fw.engagement.activo()

    def test_load_inexistente(self, fw, tmp_path):
        fw._procesar(f"engagement load {tmp_path}/no.json")
        assert not fw.engagement.activo()

    def test_run_bloqueado_fuera_scope(self, fw, tmp_path):
        self._engagement(fw, tmp_path)
        fw._procesar("use osint/reverse_ip")
        fw._procesar("set TARGET evil.com")
        fw._procesar("run")
        assert fw.reporter.ultimo_reporte is None

    def test_run_permite_dentro_scope(self, fw, tmp_path, monkeypatch):
        self._engagement(fw, tmp_path)
        fw._procesar("use osint/reverse_ip")
        fw._procesar("set TARGET dc01.corp.local")
        monkeypatch.setattr("requests.get", lambda *a, **k: _RespuestaFalsa(
            texto="otro1.com\notro2.com"))
        fw._procesar("run")
        assert fw.reporter.ultimo_reporte is not None

    def test_run_bloqueado_kill_date(self, fw, tmp_path):
        self._engagement(fw, tmp_path, kill_date="2020-01-01")
        fw._procesar("use osint/reverse_ip")
        fw._procesar("set TARGET dc01.corp.local")
        fw._procesar("run")
        assert fw.reporter.ultimo_reporte is None

    def test_run_permitido_fuera_con_flag(self, fw, tmp_path, monkeypatch):
        self._engagement(fw, tmp_path, permitir_fuera_alcance=True)
        fw._procesar("use osint/reverse_ip")
        fw._procesar("set TARGET fuera.com")
        monkeypatch.setattr("requests.get", lambda *a, **k: _RespuestaFalsa(texto="x.com"))
        fw._procesar("run")
        assert fw.reporter.ultimo_reporte is not None


# =====================================================================
# E2E corto de consola v1.3
# =====================================================================
class TestE2EV13:
    def test_flujo_completo(self, fw, tmp_path, monkeypatch):
        engagement = tmp_path / "eng.json"
        engagement.write_text(json.dumps(
            {"nombre": "lab-e2e", "kill_date": "2099-12-31",
             "alcance": ["acme.com"], "excluidos": []}), encoding="utf-8")
        monkeypatch.setattr("requests.get", lambda *a, **k: _RespuestaFalsa(
            texto=json.dumps([["original", "mimetype", "statuscode"]])))
        for linea in ("attack",
                      "engagement load " + str(engagement),
                      "use osint/wayback_urls",
                      "set TARGET acme.com",
                      "run",
                      "back",
                      "info ad/ldap_enum",
                      "engagement clear"):
            fw._procesar(linea)
        assert fw.reporter.ultimo_reporte is not None
