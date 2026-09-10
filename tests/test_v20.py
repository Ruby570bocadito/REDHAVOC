# -*- coding: utf-8 -*-
"""v2.0.0: AES puro + GPP cpassword + 6 módulos nuevos + workspaces múltiples +
persistencia de opciones + SMTP enum / clickjack / xss / traversal / telnet."""
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.framework import RedHavocFramework  # noqa: E402
from core.workspace_db import NOMBRE_DEFECTO, WorkspaceDB, ruta_de_workspace  # noqa: E402


class _Cap:
    """Consola Rich de prueba que escribe a un buffer (con el tema del framework)."""

    def __init__(self):
        from rich.console import Console
        from core.colors import TEMA
        self.file = io.StringIO()
        self.c = Console(file=self.file, force_terminal=False,
                         width=120, theme=TEMA, highlight=False)

    def __getattr__(self, nombre):
        return getattr(self.c, nombre)


@pytest.fixture()
def fw(tmp_path, monkeypatch):
    """Framework con raíz temporal (aislado del workspace real)."""
    monkeypatch.setattr("core.colors.console", _Cap().c)
    marco = RedHavocFramework(tmp_path)
    marco.console_cap = _Cap()
    monkeypatch.setattr("core.framework.console", marco.console_cap.c)
    return marco


def salida(marco) -> str:
    return marco.console_cap.file.getvalue()


# ======================================================================
# 1. AES puro (core/aes_min) — vectores oficiales
# ======================================================================
from core.aes_min import (cifrar_bloque, descifrar_bloque, cifrar_cbc,  # noqa: E402
                          descifrar_cbc, _mul, _xt)


class TestAesMin:
    def test_multiplicacion_galois(self):
        assert _mul(0x57, 0x83) == 0xC1      # ejemplo clásico FIPS-197
        assert _mul(0x57, 0x02) == 0xAE
        assert _mul(0x57, 0x00) == 0x00
        assert _xt(0x80) == 0x1B             # reducción con el polinomio

    def test_fips197_128(self):
        k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        p = bytes.fromhex("00112233445566778899aabbccddeeff")
        c = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        assert cifrar_bloque(p, k) == c
        assert descifrar_bloque(c, k) == p

    def test_fips197_256(self):
        k = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                          "101112131415161718191a1b1c1d1e1f")
        p = bytes.fromhex("00112233445566778899aabbccddeeff")
        c = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        assert cifrar_bloque(p, k) == c
        assert descifrar_bloque(c, k) == p

    def test_sp800_38a_cbc_256(self):
        k = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                          "1f352c073b6108d72d9810a30914dff4")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        p = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                          "ae2d8a571e03ac9c9eb76fac45af8e51")
        c = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                          "9cfc4e967edb808d679f777bc6702c7d")
        assert cifrar_cbc(p, k, iv)[:32] == c
        assert descifrar_cbc(cifrar_cbc(p, k, iv), k, iv) == p

    def test_roundtrip_utf8(self):
        clave = b"K" * 32
        mensaje = "GPP contraseña secreta ñandú".encode("utf-8")
        cifrado = cifrar_cbc(mensaje, clave, bytes(16))
        assert descifrar_cbc(cifrado, clave, bytes(16)) == mensaje

    def test_entradas_invalidas(self):
        with pytest.raises(ValueError):
            cifrar_bloque(b"corto", b"a" * 16)
        with pytest.raises(ValueError):
            cifrar_bloque(b"x" * 16, b"clave-mala")
        with pytest.raises(ValueError):
            descifrar_cbc(b"x" * 20, b"a" * 32, bytes(16))
        with pytest.raises(ValueError):
            descifrar_cbc(b"x" * 16, b"a" * 32, b"iv-corto")


# ======================================================================
# 2. ad/gpp_cpassword
# ======================================================================
from core.aes_min import cifrar_cbc as _cifrar  # noqa: E402
from modules.ad.gpp_cpassword import (CLAVE_GPP, descifrar_cpassword,  # noqa: E402
                                      extraer_cpasswords, GppCpassword)
from core.base_module import ModuloError  # noqa: E402


def _cpassword_de(secreto: str) -> str:
    """Cifra un secreto como lo haría una GPP (AES-256-CBC, UTF-16LE, IV 0)."""
    cifrado = _cifrar(secreto.encode("utf-16-le"), CLAVE_GPP, bytes(16))
    return __import__("base64").b64encode(cifrado).decode()


class TestGppCpassword:
    def test_descifrar_roundtrip(self):
        for secreto in ("P4ssw0rd2023!", "secreta", "clave-larga-con-ñ-1234567890"):
            cifrado_base64 = _cpassword_de(secreto)
            assert descifrar_cpassword(cifrado_base64) == secreto

    def test_descifrar_sin_relleno_base64(self):
        secreto = "lab-pass"
        completo = _cpassword_de(secreto)
        sin_relleno = completo.rstrip("=")
        assert descifrar_cpassword(sin_relleno) == secreto

    def test_extraer_cpasswords_xml(self):
        xml = f'''<?xml version="1.0"?>
<Groups clsid="{{3125E937}}">
  <User name="svc_backup" action="CREATE" userName="svc_backup"
        cpassword="{_cpassword_de('Backup2023!')}"/>
  <User name="otro" action="CREATE" userName="otro" cpassword="x"/>
</Groups>'''
        hallazgos = extraer_cpasswords(xml)
        assert len(hallazgos) == 2
        assert hallazgos[0]["usuario"] == "svc_backup"
        assert hallazgos[0]["elemento"] == "User"

    def test_extraer_xml_invalido(self):
        with pytest.raises(ValueError):
            extraer_cpasswords("<no-cerrado")

    def test_modulo_ejecutar_fichero(self, tmp_path):
        xml = tmp_path / "Groups.xml"
        secreto = "S3cr3ta_GPP"
        xml.write_text(
            '<User userName="svc_sql" cpassword="'
            + _cpassword_de(secreto) + '"/>', encoding="utf-8")
        modulo = GppCpassword()
        modulo.opciones.set("RUTA", str(xml))
        resultado = modulo.ejecutar()
        assert resultado["cpasswords"][0]["usuario"] == "svc_sql"
        assert resultado["cpasswords"][0]["contrasena"] == secreto

    def test_modulo_ruta_inexistente(self):
        modulo = GppCpassword()
        modulo.opciones.set("RUTA", "/no/existe/Groups.xml")
        with pytest.raises(ModuloError):
            modulo.ejecutar()

    def test_modulo_sin_cpassword(self, tmp_path):
        xml = tmp_path / "Groups.xml"
        xml.write_text('<User userName="limpia"/>', encoding="utf-8")
        modulo = GppCpassword()
        modulo.opciones.set("RUTA", str(xml))
        with pytest.raises(ModuloError):
            modulo.ejecutar()


# ======================================================================
# 3. recon/smtp_enum — funciones puras + mocks de socket
# ======================================================================
from modules.recon.smtp_enum import (clasificar_respuesta, parsear_saludo,  # noqa: E402
                                     SmtpEnum)


class TestSmtpEnum:
    def test_clasificar_respuestas(self):
        assert clasificar_respuesta(250, "250 2.1.5 <juan@corp>") == "existe"
        assert clasificar_respuesta(550, "550 5.1.1 user unknown") == "no_existe"
        assert clasificar_respuesta(252, "252 2.1.5 Cannot VRFY user") == "no_divulga"
        assert clasificar_respuesta(502, "502 5.5.2 VRFY disabled") == "no_divulga"
        assert clasificar_respuesta(450, "450 greylisted") == "error"

    def test_parsear_saludo(self):
        ficha = parsear_saludo("220 mail.corp ESMTP Postfix (Ubuntu)")
        assert ficha["mta"] == "Postfix"
        assert parsear_saludo("220 x Microsoft ESMTP MAIL Service")["mta"] == \
            "Microsoft Exchange"

    def test_cargar_usuarios(self, tmp_path):
        lista = tmp_path / "u.txt"
        lista.write_text("juan\n# comentario\nmaria\n", encoding="utf-8")
        assert SmtpEnum._cargar_usuarios(f"@{lista}") == ["juan", "maria"]
        assert SmtpEnum._cargar_usuarios("a, b ,c") == ["a", "b", "c"]
        assert SmtpEnum._cargar_usuarios("") == []

    def test_metodo_invalido(self):
        modulo = SmtpEnum()
        modulo.opciones.set("RHOST", "127.0.0.1")
        modulo.opciones.set("USUARIOS", "a")
        modulo.opciones.set("METODO", "PEPE")
        with pytest.raises(ModuloError):
            modulo.ejecutar()


# ======================================================================
# 4. web/clickjack — evaluación pura
# ======================================================================
from modules.web.clickjack import evaluar_proteccion  # noqa: E402


class TestClickjack:
    def test_vulnerable_sin_cabeceras(self):
        ficha = evaluar_proteccion("", "")
        assert ficha["nivel"] == "vulnerable"

    def test_protegido_xfo(self):
        ficha = evaluar_proteccion("SAMEORIGIN", "")
        assert ficha["nivel"] == "protegido"
        assert evaluar_proteccion("DENY", "")["nivel"] == "protegido"

    def test_protegido_csp(self):
        ficha = evaluar_proteccion("", "default-src 'self'; frame-ancestors 'none'")
        assert ficha["nivel"] == "protegido"

    def test_allow_from_deprecado(self):
        ficha = evaluar_proteccion("ALLOW-FROM https://aliado.com", "")
        assert ficha["nivel"] == "vulnerable"
        assert any("IGNORAN" in m for m in ficha["motivos"])

    def test_modulo_registra_vuln(self, fw):
        modulo = fw.module_manager.obtener("web/clickjack")()
        modulo.ctx = fw.ctx
        fw.workspace_db.add_host("10.0.0.9")
        # simula respuesta vulnerable sin red: parchea requests.get del módulo
        class _Resp:
            headers = {"Content-Type": "text/html"}
            text = "<html></html>"
        import modules.web.clickjack as cj
        orig = cj.requests.get
        cj.requests.get = lambda *a, **k: _Resp()
        try:
            modulo.opciones.set("URL", "http://10.0.0.9/app")
            res = modulo.ejecutar()
        finally:
            cj.requests.get = orig
        assert res["nivel"] == "vulnerable"
        assert fw.workspace_db.total_vulns() == 1


# ======================================================================
# 5. web/xss_reflected — marcador inerte y contextos
# ======================================================================
from modules.web.xss_reflected import (clasificar_contexto, construir_url,  # noqa: E402
                                       generar_marcador, riesgos_de)


class TestXssReflected:
    def test_marcador_unico(self):
        a, b = generar_marcador()
        assert a.startswith("rhv") and a.endswith("zz")
        assert b == f"<{a}>"
        c, d = generar_marcador()
        assert a != c  # aleatorio (probabilidad negligible de colisión)

    def test_contexto_html_y_sin_filtrar(self):
        _, etiqueta = generar_marcador()
        marcador = etiqueta[1:-1]
        html = f"<p>Hola {etiqueta}</p>"
        ctx = clasificar_contexto(html, marcador)
        assert "html" in ctx and "sin_filtrar" in ctx
        assert riesgos_de(ctx) == "alto"

    def test_contexto_atributo(self):
        marcador, _ = generar_marcador()
        html = f'<input value="hola {marcador} mundo">'
        assert "atributo" in clasificar_contexto(html, marcador)
        assert riesgos_de(["atributo"]) == "medio"

    def test_contexto_script(self):
        marcador, _ = generar_marcador()
        html = f"<script>var x = '{marcador}';</script>"
        assert "script" in clasificar_contexto(html, marcador)

    def test_contexto_comentario(self):
        marcador, _ = generar_marcador()
        html = f"<!-- nota {marcador} -->"
        assert "comentario" in clasificar_contexto(html, marcador)

    def test_sin_reflexion(self):
        marcador, _ = generar_marcador()
        assert clasificar_contexto("<p>nada</p>", marcador) == []
        assert riesgos_de([]) == "ok"

    def test_construir_url_reemplaza_y_anade(self):
        base = "http://h/buscar?q=x&page=1"
        assert construir_url(base, "q", "NUEVO") == "http://h/buscar?q=NUEVO&page=1"
        assert construir_url(base, "nuevo", "v") == \
            "http://h/buscar?q=x&page=1&nuevo=v"


# ======================================================================
# 6. web/path_traversal — payloads y firmas
# ======================================================================
from modules.web.path_traversal import (detectar_firma, generar_payloads,  # noqa: E402
                                        FIRMA_UNIX)


class TestPathTraversal:
    def test_generar_payloads_variados(self):
        payloads = generar_payloads(4, "/etc/passwd")
        assert len(payloads) == len(set(payloads))          # sin duplicados
        assert any(p.startswith("../../../../") for p in payloads)
        assert any("%2e%2e%2f" in p for p in payloads)
        assert any("%252e%252e" in p for p in payloads)     # doble encode
        assert any(p.startswith("....//") for p in payloads)
        assert "/etc/passwd" in payloads                    # absoluto directo

    def test_profundidad_acotada(self):
        assert len(generar_payloads(0)) >= 1
        assert "../" * 12 in generar_payloads(50)[0]

    def test_detectar_firma_unix(self):
        passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:..."
        assert detectar_firma(passwd) == "unix"
        assert detectar_firma("<html>ok</html>") == ""
        assert detectar_firma("[fonts]\n[extensions]\nwin.ini") == "windows"


# ======================================================================
# 7. brute/telnet_login — intérprete puro de sesión
# ======================================================================
from modules.brute.telnet_login import interpreta_sesion, siguiente_prompt  # noqa: E402


class TestTelnetLogin:
    def test_sesion_valida(self):
        t = "Welcome\r\nrouter> \r\nRHV_OK_01\r\n"
        assert interpreta_sesion(t, "RHV_OK_01") is True

    def test_sesion_fallida_relogin(self):
        t = "Username: admin\r\nPassword: \r\nLogin incorrect\r\nUsername:"
        assert interpreta_sesion(t, "RHV_OK_01") is False

    def test_sin_marca(self):
        assert interpreta_sesion("nada relevante", "RHV_OK_01") is False

    def test_prompts(self):
        assert siguiente_prompt("Bienvenido\nLogin: ") == "login"
        assert siguiente_prompt("Password: ") == "password"
        assert siguiente_prompt("router#") == "shell"
        assert siguiente_prompt("") is None


# ======================================================================
# 8. Workspaces múltiples
# ======================================================================
class TestWorkspacesMultiples:
    def test_ruta_por_nombre(self, tmp_path):
        assert ruta_de_workspace(tmp_path, "principal").name == "db.json"
        assert ruta_de_workspace(tmp_path, "acme").name == "ws_acme.json"

    def test_listado(self, tmp_path):
        a = WorkspaceDB(tmp_path, "acme")
        a.add_host("10.0.0.1")
        WorkspaceDB(tmp_path, "beta").add_nota("hola")
        workspaces = {w.nombre: w for w in WorkspaceDB.listar(tmp_path)}
        assert set(workspaces) == {"principal", "acme", "beta"}
        assert workspaces["principal"].total_hosts() == 0
        assert workspaces["acme"].total_hosts() == 1
        assert workspaces["beta"].total_notas() == 1

    def test_comandos_workspace(self, fw):
        fw._procesar("workspace new acme")
        assert "Workspace activo: acme" in salida(fw)
        fw.workspace_db.add_host("10.0.0.7")
        fw._procesar("workspace use principal")
        assert fw.workspace_db.total_hosts() == 0
        fw._procesar("workspace use acme")
        assert fw.workspace_db.total_hosts() == 1
        fw._procesar("workspace use principal")
        fw._procesar("workspace del acme")
        assert "borrado" in salida(fw)
        assert not (fw.raiz / "workspace" / "ws_acme.json").exists()

    def test_del_protegido(self, fw):
        fw._procesar("workspace del principal")
        assert "no se puede borrar" in salida(fw)
        fw._procesar("workspace del fantasma")
        assert "No existe" in salida(fw)

    def test_nombre_invalido(self, fw):
        fw._procesar("workspace new NO*VALIDO")
        assert "inválido" in salida(fw)
        assert fw.nombre_workspace == NOMBRE_DEFECTO

    def test_aislamiento_y_persistencia(self, fw):
        fw._procesar("workspace new op2")
        fw.workspace_db.add_cred("10.0.0.2", "admin", "toor", "smb")
        fw2 = RedHavocFramework(fw.raiz)
        assert fw2.nombre_workspace == "op2"           # restaura el último activo
        assert fw2.workspace_db.total_creds() == 1
        fw2._procesar("workspace use principal")
        assert fw2.workspace_db.total_creds() == 0     # aislado


# ======================================================================
# 9. Persistencia de opciones
# ======================================================================
class TestPersistenciaOpciones:
    def test_set_persiste_y_restaura(self, fw):
        fw._procesar("use recon/port_scanner")
        fw._procesar("set TARGET 10.5.5.5")
        fw._procesar("set BANNER false")
        fw._procesar("setg TIMEOUT 12")
        fw._procesar("unset BANNER")
        datos = json.loads((fw.raiz / "workspace" / "opciones.json").read_text())
        assert datos["modulos"]["recon/port_scanner"]["TARGET"] == "10.5.5.5"
        assert "BANNER" not in datos["modulos"]["recon/port_scanner"]
        assert datos["global"]["TIMEOUT"] == "12"

    def test_authorized_nunca_persiste(self, fw):
        fw._procesar("setg TIMEOUT 9")        # garantiza que el fichero exista
        fw._procesar("set AUTHORIZED true")
        datos = json.loads((fw.raiz / "workspace" / "opciones.json").read_text())
        assert "AUTHORIZED" not in datos["global"]
        assert datos["global"]["TIMEOUT"] == "9"

    def test_opciones_sobreviven_sesiones(self, fw):
        fw._procesar("use ad/smb_login")
        fw._procesar("set RHOST 10.0.0.10")
        fw._procesar("set DOMINIO CORP")
        fw2 = RedHavocFramework(fw.raiz)
        fw2._procesar("use ad/smb_login")
        assert fw2.modulo_actual.opt("RHOST") == "10.0.0.10"
        assert fw2.modulo_actual.opt("DOMINIO") == "CORP"

    def test_unset_desconocido_no_persiste_nada(self, fw):
        fw._procesar("unset NOEXISTE")
        ruta = fw.raiz / "workspace" / "opciones.json"
        contenido = ruta.read_text() if ruta.exists() else ""
        assert "NOEXISTE" not in contenido


# ======================================================================
# 10. Integración: consejos nuevos + registro en el arsenal
# ======================================================================
class TestIntegracionV20:
    def test_73_modulos_registrados(self, manager):
        assert manager.total_modulos() == 79
        for nombre in ("ad/gpp_cpassword", "recon/smtp_enum", "web/clickjack",
                       "web/xss_reflected", "web/path_traversal",
                       "brute/telnet_login"):
            assert manager.obtener(nombre).NAME == nombre

    def test_consejos_gpp(self):
        from core.advice import consejos_de_resultado
        datos = {"cpasswords": [{"contrasena": "x", "usuario": "svc"}]}
        consejos = consejos_de_resultado("ad/gpp_cpassword", datos)
        assert any("smb_login" in c.comando for c in consejos if c.comando)

    def test_consejos_smtp(self):
        from core.advice import consejos_de_resultado
        consejos = consejos_de_resultado(
            "recon/smtp_enum", {"validos": ["juan"], "usuarios": []})
        assert consejos  # al menos una recomendación

    def test_consejos_clickjack_vulnerable(self):
        from core.advice import consejos_de_resultado
        consejos = consejos_de_resultado("web/clickjack", {"nivel": "vulnerable"})
        assert any("cookie_audit" in c.comando for c in consejos if c.comando)

    def test_comando_en_ayuda_y_tab(self, fw):
        fw._procesar("help")
        texto = salida(fw)
        assert "workspace" in texto
        fw._procesar("workspace ")
        # candidatos TAB (sin readline activo en test → vía _candidatos_para)
        candidatos = fw._candidatos_para("", "workspace ")
        assert candidatos == ["new", "use", "del"]
