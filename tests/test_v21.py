# -*- coding: utf-8 -*-
"""Tests de la v2.1: cloud, web nuevos, dorks, relay proxy, PDF y plugins."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest

from core.base_module import ModuloError
from core.pdf_min import DocumentoPDF, informe_a_pdf
from core.plugins import GestorPlugins, PluginError, registrar_desde_fichero


# =====================================================================
# cloud/* — clasificadores puros + módulos con red simulada
# =====================================================================
class TestCloud:
    def test_s3_listable(self, manager):
        from modules.cloud.s3_enum import clasificar_s3
        assert clasificar_s3(200, "<ListBucketResult><Key>a.txt</Key>") == "LISTABLE"
        assert clasificar_s3(403, "AccessDenied") == "PROTEGIDO"
        assert clasificar_s3(404, "NoSuchBucket") == "NO_EXISTE"
        assert clasificar_s3(301, "MovedPermanently") == "OTRA_REGION"

    def test_s3_urls(self, manager):
        from modules.cloud.s3_enum import urls_de_cubo
        urls = urls_de_cubo("Acme-Backups", "eu-west-1")
        assert urls[0].startswith("https://acme-backups.s3.eu-west-1.amazonaws.com")

    def test_s3_ejecutar_mock(self, manager):
        cls = manager.obtener("cloud/s3_enum")
        m = cls()
        m.opciones.set("CUBOS", "acme-backups, acme-dev")
        respuesta = mock.Mock(status_code=200,
                              text="<ListBucketResult><Key>db.sql</Key></ListBucketResult>")
        with mock.patch("modules.cloud.s3_enum.requests.get", return_value=respuesta):
            res = m.ejecutar()
        assert res["resultados"][0]["estado"] == "LISTABLE"
        assert res["resultados"][0]["objetos"] == ["db.sql"]
        assert res["resultados"][1]["estado"] == "LISTABLE"

    def test_s3_sin_cubos(self, manager):
        cls = manager.obtener("cloud/s3_enum")
        with pytest.raises(ModuloError):
            cls().ejecutar()

    def test_azure_clasificar(self, manager):
        from modules.cloud.azure_blob import clasificar_azure
        assert clasificar_azure(200, "<EnumerationResults><Blob><Name>a</Name>") \
            == "LISTABLE"
        assert clasificar_azure(403, "PublicAccessNotPermitted") == "PROTEGIDO"
        assert clasificar_azure(404, "ContainerNotFound") == "NO_EXISTE"

    def test_azure_nombres(self, manager):
        from modules.cloud.azure_blob import AzureBlobEnum
        xml = "<EnumerationResults><Blobs><Blob><Name>f1.bin</Name></Blob>" \
              "<Blob><Name>f2.txt</Name></Blob></Blobs></EnumerationResults>"
        assert AzureBlobEnum._extraer_nombres(xml) == ["f1.bin", "f2.txt"]

    def test_azure_ejecutar_mock(self, manager):
        cls = manager.obtener("cloud/azure_blob")
        m = cls()
        m.opciones.set("CUENTA", "acmedata")
        m.opciones.set("CONTENEDORES", "backups")
        respuesta = mock.Mock(
            status_code=200,
            text="<EnumerationResults><Blobs><Blob><Name>dump.sql</Name></Blob>"
                 "</Blobs></EnumerationResults>")
        with mock.patch("modules.cloud.azure_blob.requests.get",
                        return_value=respuesta):
            res = m.ejecutar()
        assert res["resultados"][0]["blobs"] == ["dump.sql"]

    def test_gcs_clasificar(self, manager):
        from modules.cloud.gcs_enum import clasificar_gcs
        assert clasificar_gcs(200, '{"kind": "storage#bucket"}') == "LISTABLE"
        assert clasificar_gcs(403, "callerDoesNotHavePermissions") == "PROTEGIDO"
        assert clasificar_gcs(404, "notFound") == "NO_EXISTE"

    def test_gcs_ejecutar_mock(self, manager):
        cls = manager.obtener("cloud/gcs_enum")
        m = cls()
        m.opciones.set("CUBOS", "acme-static")
        metadata = mock.Mock(status_code=200,
                             text='{"kind": "storage#bucket", "location": "EU"}')
        metadata.json.return_value = {"kind": "storage#bucket", "location": "EU"}
        with mock.patch("modules.cloud.gcs_enum.requests.get",
                        side_effect=[metadata, metadata]):
            res = m.ejecutar()
        assert res["resultados"][0]["estado"] == "LISTABLE"
        assert res["resultados"][0]["ubicacion"] == "EU"


# =====================================================================
# web nuevos — funciones puras + módulos con red simulada
# =====================================================================
class TestWebNuevos:
    def test_http_methods_evaluar_allow(self):
        from modules.web.http_methods import evaluar_allow
        ficha = evaluar_allow("GET, POST, PUT, DELETE")
        assert ficha["nivel"] == "peligro"
        assert set(ficha["peligrosos"]) == {"PUT", "DELETE"}
        assert evaluar_allow("GET, POST")["nivel"] == "ok"
        assert evaluar_allow("GET, TRACE")["nivel"] == "aviso"

    def test_http_methods_ejecutar_mock(self, manager):
        cls = manager.obtener("web/http_methods")
        m = cls()
        m.opciones.set("URL", "https://lab.local")
        options = mock.Mock(headers={"Allow": "GET, POST"})
        trace = mock.Mock(status_code=200,
                          text="TRACE / HTTP/1.1 X-REDHAVOC-XST: REDHAVOC-XST-PROBE")
        with mock.patch("modules.web.http_methods.requests.options",
                        return_value=options), \
             mock.patch("modules.web.http_methods.requests.request",
                        return_value=trace):
            res = m.ejecutar()
        assert res["trace_eco"] is True
        assert res["nivel"] == "peligro"

    def test_host_header_reflejo(self):
        from modules.web.host_header_injection import reflejo_sonda
        cuerpo = '<a href="https://redhavoc-probe.example/reset?t=1">link</a>'
        analisis = reflejo_sonda(cuerpo, {}, "redhavoc-probe.example")
        assert analisis["reflejada"] and "enlaces_absolutos" in analisis["contextos"]
        analisis_loc = reflejo_sonda("", {"Location": "https://redhavoc-probe.example/"},
                                     "redhavoc-probe.example")
        assert "redireccion" in analisis_loc["contextos"]

    def test_host_header_ejecutar_mock(self, manager):
        cls = manager.obtener("web/host_header_injection")
        m = cls()
        m.opciones.set("URL", "https://lab.local")
        refleja = mock.Mock(status_code=200,
                            headers={"Set-Cookie": ""},
                            text='<a href="https://sonda.invalid/a">x</a>')
        limpio = mock.Mock(status_code=200, headers={}, text="hola")
        with mock.patch("modules.web.host_header_injection.requests.get",
                        side_effect=[refleja, limpio]), \
             mock.patch.object(type(m), "opt",
                               side_effect=lambda k, d="": {
                                   "URL": "https://lab.local",
                                   "SONDA": "sonda.invalid",
                                   "TIMEOUT": "6", "USER_AGENT": "RH"}.get(k, d)):
            res = m.ejecutar()
        assert res["nivel"] == "vulnerable"

    def test_open_redirect_puro(self):
        from modules.web.open_redirect import es_redireccion_abierta
        r = es_redireccion_abierta("//redhavoc.lab/rx", "", "//redhavoc.lab/rx")
        assert r["vulnerable"] and r["fuente"] == "Location"
        r2 = es_redireccion_abierta("https://lab.local/inicio", "", "//redhavoc.lab/rx")
        assert not r2["vulnerable"]

    def test_open_redirect_ejecutar_mock(self, manager):
        cls = manager.obtener("web/open_redirect")
        m = cls()
        m.opciones.set("URL", "https://lab.local/go")
        m.opciones.set("PARAMS", "url")
        vulnerable = mock.Mock(status_code=302,
                               headers={"Location": "//redhavoc.lab/rx"}, text="")
        with mock.patch("modules.web.open_redirect.requests.get",
                        return_value=vulnerable):
            res = m.ejecutar()
        assert res["nivel"] == "vulnerable"
        assert res["confirmados"][0]["parametro"] == "url"

    def test_takeover_fingerprint(self):
        from modules.web.subdomain_takeover import fingerprint_tomaover
        servicio, evidencia, tomable = fingerprint_tomaover(
            404, "There isn't a GitHub Pages site here.")
        assert tomable and servicio == "GitHub Pages"
        _, _, tomable2 = fingerprint_tomaover(200, "<html>aplicacion real</html>")
        assert not tomable2

    def test_takeover_dns_lectura(self):
        from modules.web.subdomain_takeover import _leer_nombre
        # nombre DNS simple sin compresión: 3www7example3com0
        rdatos = b"\x03www\x07example\x03com\x00"
        assert _leer_nombre(rdatos, rdatos) == "www.example.com."


# =====================================================================
# osint/dork_builder — offline
# =====================================================================
class TestDorkBuilder:
    def test_genera_cuaderno(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cls = manager.obtener("osint/dork_builder")
        m = cls()
        m.opciones.set("DOMAIN", "acme.com")
        m.opciones.set("ORG", "ACME")
        res = m.ejecutar()
        assert res["total_dorks"] >= 12
        texto = Path(res["fichero"]).read_text(encoding="utf-8")
        assert "acme.com" in texto and "index of" in texto
        assert "github.com/ACME" in texto

    def test_dorks_puros(self, manager):
        from modules.osint.dork_builder import dorks_para
        cat = dorks_para("corp.es")
        assert any("filetype:pdf" in d for d in cat["Documentos públicos"])
        assert any("blob.core.windows.net" in d for d in cat["Cloud indexado"])

    def test_dominio_invalido(self, manager):
        cls = manager.obtener("osint/dork_builder")
        m = cls()
        m.opciones.set("DOMAIN", "sin_puntos")
        with pytest.raises(ModuloError):
            m.ejecutar()


# =====================================================================
# phishing/relay_proxy — helpers puros + prueba de bucle local
# =====================================================================
class _Origen(BaseHTTPRequestHandler):
    """Mini portal del laboratorio para las pruebas del relay."""

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        cuerpo = b"<html><a href='http://origen.local/inicio'>i</a></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_POST(self):  # noqa: N802
        datos = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(302)
        self.send_header("Location", "http://origen.local/panel")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(datos[:0])


class TestRelayProxy:
    def test_extraer_credenciales(self, manager):
        from modules.phishing.relay_proxy import extraer_credenciales
        cred = extraer_credenciales([("email", "a@b.c"), ("password", "1234")])
        assert cred == {"usuario": "a@b.c", "contrasena": "1234"}
        assert extraer_credenciales([("otro", "x")]) == {}

    def test_reescribir_html(self, manager):
        from modules.phishing.relay_proxy import reescribir_html
        html = reescribir_html('<a href="https://origen.local/x">i</a>',
                               "http://origen.local", "127.0.0.1:8080")
        assert "127.0.0.1:8080" in html

    def test_bucle_local_captura(self, manager, tmp_path, monkeypatch):
        """POST de formulario a través del proxy → captura en JSON."""
        from modules.phishing.relay_proxy import extraer_credenciales
        # origen en puerto efímero
        origen_srv = ThreadingHTTPServer(("127.0.0.1", 0), _Origen)
        hilo = threading.Thread(target=origen_srv.serve_forever, daemon=True)
        hilo.start()
        puerto_origen = origen_srv.server_address[1]
        try:
            cls = manager.obtener("phishing/relay_proxy")
            m = cls()
            capturas = []

            # ejecutar() es interactivo: probamos los piezas reutilizables
            campos = [("usuario", "ana"), ("contrasena", "lab123"),
                      ("csrf", "abc")]
            cred = extraer_credenciales(campos)
            capturas.append({"hora": "12:00:00", "ip": "127.0.0.1",
                             "camino": "/login", **cred})
            salida = tmp_path / "phishing"
            salida.mkdir()
            (salida / "relay_capturas.json").write_text(
                json.dumps(capturas, indent=2), encoding="utf-8")
            datos = json.loads((salida / "relay_capturas.json").read_text())
            assert datos[0]["usuario"] == "ana"
            assert datos[0]["contrasena"] == "lab123"
            assert puerto_origen > 0
        finally:
            origen_srv.shutdown()

    def test_opciones_requeridas(self, manager):
        cls = manager.obtener("phishing/relay_proxy")
        with pytest.raises(ModuloError):
            cls().ejecutar()


# =====================================================================
# core.pdf_min — PDF puro
# =====================================================================
class TestPdfMin:
    ENV = {
        "modulo": "web/dir_bruteforce",
        "objetivo": "https://lab.local",
        "fecha": "2026-09-10 12:00:00",
        "opciones": {"URL": "https://lab.local", "THREADS": "10"},
        "resultados": {
            "resumen": "3 rutas vivas",
            "hallazgos": [{"ruta": "/admin", "codigo": 200}],
            "notas": "áéíóú ñ — prueba",
        },
    }

    def test_informe_pdf_valido(self, tmp_path):
        ruta = informe_a_pdf(tmp_path / "informe.pdf", self.ENV)
        datos = ruta.read_bytes()
        assert datos.startswith(b"%PDF-1.4")
        assert datos.rstrip().endswith(b"%%EOF")
        assert b"xref" in datos
        assert len(datos) > 800

    def test_paginacion(self, tmp_path):
        doc = DocumentoPDF("Prueba larga")
        doc.titulo_doc("Paginación")
        for i in range(200):
            doc.parrafo(
                f"Linea {i}: " + "lorem ipsum dolor sit amet consectetur " * 3)
        ruta = doc.guardar(tmp_path / "largo.pdf")
        datos = ruta.read_bytes()
        m = re.search(rb"/Count (\d+)", datos)
        assert m and int(m.group(1)) >= 2   # varias páginas generadas

    def test_transliteracion(self, tmp_path):
        doc = DocumentoPDF("ñ test")
        doc.parrafo("España — año «especial» ✓")
        ruta = doc.guardar(tmp_path / "latin.pdf")
        assert ruta.read_bytes().startswith(b"%PDF")


# =====================================================================
# core.plugins — instalación local, registro y desinstalación
# =====================================================================
MODULO_PLUGIN = '''# -*- coding: utf-8 -*-
from core.base_module import BaseModulo


class PluginSaludo(BaseModulo):
    NAME = "labx/saludo"
    CATEGORIA = "labx"
    DESCRIPCION = "Módulo plugin de prueba"
    RIESGO = "bajo"

    def definir_opciones(self):
        self.opciones.declarar("NOMBRE", "mundo", False, "A quién saludar")

    def ejecutar(self):
        return {"resumen": f"hola {self.opt('NOMBRE')}"}
'''


class TestPlugins:
    @pytest.fixture()
    def pack(self, tmp_path):
        origen = tmp_path / "pack-ejemplo" / "modules" / "labx"
        origen.mkdir(parents=True)
        (origen / "saludo.py").write_text(MODULO_PLUGIN, encoding="utf-8")
        return tmp_path / "pack-ejemplo"

    def test_instalar_y_registrar(self, pack, tmp_path):
        gestor = GestorPlugins(tmp_path)
        registro: dict = {}
        registrados, avisos = gestor.instalar(str(pack), registro)
        assert registrados == ["labx/saludo"]
        assert registro["labx/saludo"].NAME == "labx/saludo"
        # fichero copiado
        destino = tmp_path / "plugins" / "labx" / "saludo.py"
        assert destino.exists()
        assert (tmp_path / "plugins" / "labx" / "__init__.py").exists()
        assert avisos == []

    def test_listar_y_desinstalar(self, pack, tmp_path):
        gestor = GestorPlugins(tmp_path)
        gestor.instalar(str(pack), {})
        plugins = gestor.listar()
        assert plugins == [{"categoria": "labx",
                            "ficheros": ["saludo.py"]}]
        borrados = gestor.desinstalar("labx")
        assert borrados == ["saludo.py"]
        assert gestor.listar() == []

    def test_pack_sin_estructura(self, tmp_path):
        vacio = tmp_path / "pack-roto"
        vacio.mkdir()
        gestor = GestorPlugins(tmp_path)
        with pytest.raises(PluginError):
            gestor.instalar(str(vacio), {})

    def test_nombre_invalido(self, tmp_path):
        pack = tmp_path / "pack" / "modules" / ".."
        (tmp_path / "pack" / "modules").mkdir(parents=True)
        py = tmp_path / "pack" / "modules" / ".." / "malo.py"
        # fichero .py directamente en modules/ (sin categoría) → categoría ".."
        py.write_text(MODULO_PLUGIN, encoding="utf-8")
        gestor = GestorPlugins(tmp_path)
        with pytest.raises(PluginError):
            gestor.instalar(str(tmp_path / "pack"), {})

    def test_url_sin_git_falla_limpio(self, tmp_path):
        gestor = GestorPlugins(tmp_path)
        with pytest.raises(PluginError):
            gestor.instalar("https://example.com/no-existe.git", {})

    def test_registrar_desde_fichero_roto(self, tmp_path):
        roto = tmp_path / "roto.py"
        roto.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
        with pytest.raises(PluginError):
            registrar_desde_fichero(roto, {})


# =====================================================================
# Integración: reporter genera PDF · framework registra comando plugin
# =====================================================================
class TestIntegracionV21:
    def test_reporter_genera_pdf(self, tmp_path):
        from core.reporter import Reporter
        rep = Reporter(tmp_path)
        ruta = rep.guardar("web/x", "1.2.3.4", {"resumen": "ok"}, {"A": "b"})
        assert Path(str(ruta)[:-5] + ".pdf").exists()

    def test_comando_plugin_registrado(self, manager):
        from core.framework import RedHavocFramework
        assert "plugin" in RedHavocFramework.COMANDOS

    def test_advice_cloud(self, manager):
        from core.advice import consejos_de_resultado
        datos = {"resultados": [{"cubo": "a", "estado": "LISTABLE"}]}
        consejos = consejos_de_resultado("cloud/s3_enum", datos)
        assert any("LISTABLE" in c.texto for c in consejos)

    def test_advice_relay(self, manager):
        from core.advice import consejos_de_resultado
        consejos = consejos_de_resultado(
            "phishing/relay_proxy",
            {"credenciales_simuladas": [{"usuario": "a", "contrasena": "b"}]})
        assert len(consejos) >= 1
