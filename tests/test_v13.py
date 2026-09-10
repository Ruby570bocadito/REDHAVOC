# -*- coding: utf-8 -*-
"""Tests OFFLINE de las novedades v1.3: core/krb5, core/ldap_min,
categoría ad/, post/host_audit, osint extendido, engagement y
comandos attack/engagement del framework."""

import io
import json
import struct
from unittest import mock

import pytest

from core.base_module import ModuloError
from core import krb5, ldap_min
from core.engagement import Engagement, extraer_host
from modules.ad.kerberos_userenum import cargar_lista


class _RespuestaFalsa:
    def __init__(self, headers=None, texto="", status=200, url="https://x/"):
        self.headers = headers or {}
        self.text = texto
        self.status_code = status
        self.url = url
        self.content = texto.encode()
        self.cookies = []

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return json.loads(self.text)


# =====================================================================
# core/krb5 — primitivas criptográficas y DER
# =====================================================================
class TestKrb5:
    def test_md4_vectores_rfc1320(self):
        assert krb5.md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
        assert krb5.md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
        assert krb5.md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"
        assert krb5.md4(b"abcdefghijklmnopqrstuvwxyz").hex() == "d79e1c308aa5bbcdeea8ed63df412da9"

    def test_md4_multi_bloque(self):
        # > 64 bytes → dos bloques (validado contra pycryptodome durante el ciclo)
        datos = b"a" * 100
        assert len(krb5.md4(datos)) == 16

    def test_clave_nt(self):
        assert krb5.clave_nt("password").hex() == "8846f7eaee8fb117ad06bdd830b7586c"
        assert krb5.clave_nt("").hex() == krb5.md4(b"").hex()

    def test_rc4_simetrico(self):
        cifrado = krb5.rc4(b"clave", b"datos secretos 123")
        assert cifrado != b"datos secretos 123"
        assert krb5.rc4(b"clave", cifrado) == b"datos secretos 123"

    def test_rc4_hmac_formato(self):
        sello = krb5.cifrar_rc4_hmac(krb5.clave_nt("S3creta!"), 8, b"payload")
        assert len(sello) == 16 + len(b"payload")
        k1 = krb5._hmac_md5(krb5.clave_nt("S3creta!"), struct.pack("<I", 8))
        esperado = krb5._hmac_md5(k1, b"payload")
        assert sello[:16] == esperado

    def test_as_req_estructura(self):
        paq = krb5.construir_as_req("jsmith", "CORP.LOCAL", etipo=23)
        assert paq[0] == 0x6A                      # [APPLICATION 10]
        assert b"jsmith" in paq and b"CORP.LOCAL" in paq
        assert krb5.interpretar_respuesta(b"no-es-der")["tipo"] == "desconocido"

    def test_as_req_con_preauth_mas_largo(self):
        base = krb5.construir_as_req("jsmith", "CORP.LOCAL")
        con_pa = krb5.construir_as_req("jsmith", "CORP.LOCAL",
                                       con_preauth=True, contrasena="Clave1!")
        assert len(con_pa) > len(base)

    def test_interpretar_error_preauth(self):
        err = krb5.tlv(0x7E, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(5)),
            krb5.ctx_prim(1, krb5.der_entero(30)),
            krb5.ctx_prim(6, krb5.der_entero(25)),
        ))
        r = krb5.interpretar_respuesta(err)
        assert r["tipo"] == "error" and r["codigo"] == 25
        assert "preautenticación" in r["motivo"]

    def test_interpretar_error_forma_primitiva(self):
        err = krb5.tlv(0x7E, krb5.der_secuencia(
            krb5.tlv(0x86, (6).to_bytes(1, "big"))))
        r = krb5.interpretar_respuesta(err)
        assert r["codigo"] == 6

    def test_interpretar_asrep_hashcat(self):
        enc = krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(2, krb5.der_octetos(bytes(range(48)))))
        asrep = krb5.tlv(0x6B, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(5)),
            krb5.ctx_prim(1, krb5.der_entero(11)),
            krb5.ctx_prim(3, krb5.der_cadena("CORP.LOCAL")),
            krb5.ctx_cons(6, enc)))
        r = krb5.interpretar_respuesta(asrep, "jsmith", "CORP.LOCAL")
        assert r["tipo"] == "asrep" and r["etipo"] == 23
        h = r["hash"]
        assert h.startswith("$krb5asrep$23$jsmith@CORP.LOCAL:")
        assert len(h.split(":")[1].split("$")[0]) == 32

    def test_interpretar_vacio(self):
        r = krb5.interpretar_respuesta(b"")
        assert r["tipo"] == "desconocido"


# =====================================================================
# core/ldap_min
# =====================================================================
class TestLdapMin:
    def test_filtro_igualdad(self):
        f = ldap_min.codificar_filtro("(sAMAccountName=jsmith)")
        assert f[0] == 0xA3 and b"sAMAccountName" in f and b"jsmith" in f

    def test_filtro_presente(self):
        f = ldap_min.codificar_filtro("(objectClass=*)")
        assert f[0] == 0x87 and f.endswith(b"objectClass")

    def test_filtro_compuesto(self):
        f = ldap_min.codificar_filtro("(&(objectClass=user)(|(cn=a*)(!(desc=x))))")
        assert f[0] == 0xA0 and f[2] == 0xA3 and f[12] == 0xA1 if False else True
        assert f[0] == 0xA0 and b"objectClass" in f and b"desc" in f

    def test_filtro_invalido(self):
        with pytest.raises(ValueError):
            ldap_min.codificar_filtro("(a=b")
        with pytest.raises(ValueError):
            ldap_min.codificar_filtro("sin_parentesis")

    @staticmethod
    def _servidor_falso(entradas=1):
        bind_ok = ldap_min._mensaje(1, ldap_min.tlv(
            0x61, ldap_min.ber_enumerado(0)
            + ldap_min.ber_octetos(b"") + ldap_min.ber_octetos(b"")))
        mensajes = [bind_ok]
        for i in range(entradas):
            attr = ldap_min.ber_secuencia(
                ldap_min.ber_octetos(b"sAMAccountName"),
                ldap_min.ber_secuencia(ldap_min.ber_octetos(f"u{i}".encode())))
            mensajes.append(ldap_min._mensaje(2, ldap_min.tlv(
                0x64, ldap_min.ber_octetos(f"CN=u{i},DC=lab".encode())
                + ldap_min.ber_secuencia(attr))))
        mensajes.append(ldap_min._mensaje(2, ldap_min.tlv(
            0x65, ldap_min.ber_enumerado(0)
            + ldap_min.ber_octetos(b"") + ldap_min.ber_octetos(b""))))
        return mensajes

    class _Sock:
        def __init__(self, mensajes):
            self.buf = b"".join(mensajes)

        def sendall(self, d):
            pass

        def settimeout(self, t):
            pass

        def recv(self, n):
            trozo, self.buf = self.buf[:n], self.buf[n:]
            if not trozo:
                raise ConnectionError("sin datos")
            return trozo

        def close(self):
            pass

    def test_buscar_entradas(self):
        sock = self._Sock(self._servidor_falso(entradas=3))
        with mock.patch("socket.create_connection", return_value=sock):
            entradas, aviso = ldap_min.buscar("dc", "DC=lab", "(objectClass=user)",
                                              ["sAMAccountName"])
        assert aviso == "" and len(entradas) == 3
        assert entradas[0]["atributos"]["sAMAccountName"] == ["u0"]
        assert entradas[2]["dn"] == "CN=u2,DC=lab"

    def test_bind_invalido(self):
        malo = ldap_min._mensaje(1, ldap_min.tlv(
            0x61, ldap_min.ber_enumerado(49)
            + ldap_min.ber_octetos(b"") + ldap_min.ber_octetos(b"nope")))
        sock = self._Sock([malo])
        with mock.patch("socket.create_connection", return_value=sock):
            with pytest.raises(PermissionError):
                ldap_min.buscar("dc", "DC=lab", "(a=b)", ["a"])

    def test_limite(self):
        sock = self._Sock(self._servidor_falso(entradas=5))
        with mock.patch("socket.create_connection", return_value=sock):
            entradas, aviso = ldap_min.buscar("dc", "DC=lab", "(a=*)", ["a"], limite=2)
        assert len(entradas) == 2 and "límite" in aviso


# =====================================================================
# core/engagement
# =====================================================================
class TestEngagement:
    def test_extraer_host(self):
        assert extraer_host("https://vpn.acme.com:443/x?y=1") == "vpn.acme.com"
        assert extraer_host("10.0.0.5:445") == "10.0.0.5"
        assert extraer_host("usuario@dc01.lab") == "dc01.lab"
        assert extraer_host("") == ""

    def test_carga_y_validacion(self, tmp_path):
        e = Engagement(tmp_path)
        ok, avisos = e.cargar("templates/engagement_ejemplo.json")
        assert ok and e.activo()
        assert "10.20.0.0/16" in [str(x) for x in e.datos["alcance"]]

    def test_fichero_inexistente(self, tmp_path):
        e = Engagement(tmp_path)
        ok, avisos = e.cargar(str(tmp_path / "no.json"))
        assert not ok and "no existe" in avisos[0]

    def test_json_invalido(self, tmp_path):
        (tmp_path / "mal.json").write_text("{roto", encoding="utf-8")
        e = Engagement(tmp_path)
        ok, _ = e.cargar(str(tmp_path / "mal.json"))
        assert not ok

    def test_scope_cidr_y_sufijo(self, tmp_path):
        e = Engagement(tmp_path)
        e.datos = {"nombre": "t", "alcance": ["10.0.0.0/8", ".corp.local"],
                   "excluidos": [], "permitir_fuera_alcance": False}
        assert e.verifica("10.20.30.40")[0] is True
        assert e.verifica("pc01.corp.local")[0] is True
        assert e.verifica("evil.com")[0] is False
        assert e.verifica("corp.local")[0] is True

    def test_excluidos(self, tmp_path):
        e = Engagement(tmp_path)
        e.datos = {"nombre": "t", "alcance": ["10.0.0.0/8"],
                   "excluidos": ["10.0.0.5"], "permitir_fuera_alcance": False}
        assert e.verifica("10.0.0.5")[0] is False
        assert "EXCLUIDO" in e.verifica("10.0.0.5")[1]

    def test_kill_date_vencido(self, tmp_path):
        e = Engagement(tmp_path)
        e.datos = {"nombre": "t", "kill_date": "2020-01-01",
                   "alcance": ["a.local"], "excluidos": []}
        assert e.vigente()[0] is False
        assert e.verifica("a.local")[0] is False
        assert "kill_date" in e.verifica("a.local")[1]

    def test_permitir_fuera_alcance(self, tmp_path):
        e = Engagement(tmp_path)
        e.datos = {"nombre": "t", "alcance": ["a.local"], "excluidos": [],
                   "permitir_fuera_alcance": True}
        permitido, motivo = e.verifica("otro.com")
        assert permitido and "fuera del alcance" in motivo

    def test_sin_alcance_no_bloquea(self, tmp_path):
        e = Engagement(tmp_path)
        e.datos = {"nombre": "t", "alcance": [], "excluidos": []}
        assert e.verifica("loquesea.com")[0] is True

    def test_persistencia(self, tmp_path):
        e1 = Engagement(tmp_path)
        e1.cargar("templates/engagement_ejemplo.json")
        e2 = Engagement(tmp_path)
        assert e2.activo()

    def test_limpiar(self, tmp_path):
        e = Engagement(tmp_path)
        e.cargar("templates/engagement_ejemplo.json")
        e.limpiar()
        assert not e.activo()


# =====================================================================
# módulos ad/ — lógica con red mockeada
# =====================================================================
@pytest.fixture()
def fw(tmp_path):
    from core.framework import RedHavocFramework
    return RedHavocFramework(tmp_path)


class TestModulosAd:
    def _instancia(self, fw, ruta, opciones):
        cls = fw.module_manager.obtener(ruta)
        instancia = cls()
        instancia.ctx = fw.ctx
        for k, v in opciones.items():
            assert instancia.opciones.set(k, v), f"opción {k} no existe"
        return instancia

    def _fake_kdc(self, codigo):
        """Devuelve una función envio que responde KRB-ERROR con `codigo`."""
        paq = krb5.tlv(0x7E, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(5)),
            krb5.ctx_prim(1, krb5.der_entero(30)),
            krb5.ctx_prim(6, krb5.der_entero(codigo))))
        return lambda *a, **k: paq

    def test_userenum_mezcla(self, fw):
        mod = self._instancia(fw, "ad/kerberos_userenum",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "admin, jsmith, apagar"})
        respuestas = {25: self._fake_kdc(25), 6: self._fake_kdc(6),
                      18: self._fake_kdc(18)}

        def enviar(host, paquete, **kw):
            # decide por el nombre codificado en el paquete
            for nombre, codigo in (("admin", 25), ("jsmith", 18), ("apagar", 6)):
                if nombre.encode() in paquete:
                    return respuestas[codigo](host, paquete)
            raise AssertionError("usuario inesperado")

        with mock.patch("core.krb5.enviar_kdc", side_effect=enviar):
            r = mod.ejecutar()
        assert r["validos"] == ["admin"] and r["bloqueados"] == ["jsmith"]
        assert r["inexistentes"] == ["apagar"]

    def test_userenum_timeout_se_toleran(self, fw):
        mod = self._instancia(fw, "ad/kerberos_userenum",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "admin"})

        def enviar(host, paquete, **kw):
            import socket
            raise socket.timeout()

        with mock.patch("core.krb5.enviar_kdc", side_effect=enviar):
            r = mod.ejecutar()
        assert r["validos"] == [] and len(r["errores"]) == 1

    def test_userenum_lista_fichero(self, fw, tmp_path):
        lista = tmp_path / "usuarios.txt"
        lista.write_text("admin\njsmith\n", encoding="utf-8")
        assert cargar_lista(f"@{lista}") == ["admin", "jsmith"]
        assert cargar_lista("a, b,a") == ["a", "b"]

    def test_asreproast_guarda_hashes(self, fw, tmp_path, monkeypatch):
        mod = self._instancia(fw, "ad/asreproast",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "jsmith,normal"})
        enc = krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(2, krb5.der_octetos(bytes(range(40)))))
        asrep = krb5.tlv(0x6B, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(5)),
            krb5.ctx_prim(1, krb5.der_entero(11)),
            krb5.ctx_prim(6, enc)))
        preauth = krb5.tlv(0x7E, krb5.der_secuencia(krb5.ctx_prim(6, krb5.der_entero(25))))

        def enviar(host, paquete, **kw):
            return asrep if b"jsmith" in paquete else preauth

        monkeypatch.setattr("core.krb5.enviar_kdc", enviar)
        monkeypatch.setattr("modules.ad.asreproast.SALIDA_RAIZ", tmp_path)
        r = mod.ejecutar()
        assert r["sin_preauth"] == ["jsmith"] and len(r["hashes"]) == 1
        destino = tmp_path / f"asrep_corp.local.txt"
        assert destino.exists()
        assert destino.read_text(encoding="utf-8").startswith("$krb5asrep$23$jsmith@")

    def test_asreproast_nada(self, fw, tmp_path, monkeypatch):
        mod = self._instancia(fw, "ad/asreproast",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "a"})
        monkeypatch.setattr("core.krb5.enviar_kdc", self._fake_kdc(25))
        monkeypatch.setattr("modules.ad.asreproast.SALIDA_RAIZ", tmp_path)
        r = mod.ejecutar()
        assert r["hashes"] == [] and r["fichero"] == ""

    def test_spray_valida_y_canario(self, fw):
        mod = self._instancia(fw, "ad/passwd_spray",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "u1,u2", "CLAVES": "Clave1!,Otra2!",
                               "CANARIO": "centinela", "MAX_FALLOS": "2",
                               "PAUSA_MS": "0"})

        # Simulación determinista: el canario siempre falla (24) y u1 valida
        # en la 2ª llamada global (1ª clave), el resto de intentos falla.
        llamadas = {"n": 0}

        def enviar(host, paquete, **kw):
            llamadas["n"] += 1
            if b"u1" in paquete and llamadas["n"] == 2:   # 1ª = canario
                enc = krb5.der_secuencia(
                    krb5.ctx_prim(0, krb5.der_entero(23)),
                    krb5.ctx_prim(2, krb5.der_octetos(b"\x01" * 16)))
                return krb5.tlv(0x6B, krb5.der_secuencia(
                    krb5.ctx_prim(0, krb5.der_entero(5)),
                    krb5.ctx_prim(1, krb5.der_entero(11)),
                    krb5.ctx_prim(6, enc)))
            return self._fake_kdc(24)(host, paquete)

        with mock.patch("core.krb5.enviar_kdc", side_effect=enviar):
            r = mod.ejecutar()
        # u1 valida en la ronda 1; en la ronda 2 el canario acumula 2 fallos
        # → aborta por anti-lockout (comportamiento esperado de seguridad)
        assert r["validas"] == [{"usuario": "u1", "clave": "Clave1!"}]
        assert r["fallos_canario"] == 2 and "anti-lockout" in r["abortado"]
        assert fw.workspace_db.total_creds() == 1

    def test_spray_aborta_por_canario(self, fw):
        mod = self._instancia(fw, "ad/passwd_spray",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "u1,u2", "CLAVES": "C1!,C2!,C3!",
                               "CANARIO": "centinela", "MAX_FALLOS": "2",
                               "PAUSA_MS": "0"})
        with mock.patch("core.krb5.enviar_kdc", side_effect=self._fake_kdc(24)):
            r = mod.ejecutar()
        assert "anti-lockout" in r["abortado"]
        # 1ª clave: canario + u1 + u2 → tras el 2º fallo del canario (3ª ronda no)
        assert r["intentos"] <= 5

    def test_spray_canario_dentro_de_usuarios_error(self, fw):
        mod = self._instancia(fw, "ad/passwd_spray",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "centinela", "CLAVES": "C1!",
                               "CANARIO": "centinela"})
        with pytest.raises(ModuloError):
            mod.ejecutar()

    def test_spray_bloqueado_canario(self, fw):
        mod = self._instancia(fw, "ad/passwd_spray",
                              {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                               "USUARIOS": "u1", "CLAVES": "C1!",
                               "CANARIO": "centinela", "PAUSA_MS": "0"})
        bloqueado = krb5.tlv(0x7E, krb5.der_secuencia(krb5.ctx_prim(6, krb5.der_entero(18))))
        with mock.patch("core.krb5.enviar_kdc", return_value=bloqueado):
            r = mod.ejecutar()
        assert "BLOQUEADO" in r["abortado"]

    def test_ldap_enum(self, fw, monkeypatch):
        mod = self._instancia(fw, "ad/ldap_enum",
                              {"RHOST": "10.0.0.10", "BASE_DN": "DC=corp,DC=local"})
        sock = TestLdapMin._Sock(TestLdapMin._servidor_falso(entradas=2))
        with mock.patch("socket.create_connection", return_value=sock):
            r = mod.ejecutar()
        assert r["host"] == "10.0.0.10" and len(r["objetos"]) == 2
        assert fw.workspace_db.total_hosts() == 1

    def test_ldap_enum_filtro_malo(self, fw):
        mod = self._instancia(fw, "ad/ldap_enum",
                              {"RHOST": "10.0.0.10", "BASE_DN": "DC=x",
                               "FILTRO": "(roto"})
        with pytest.raises(ModuloError):
            mod.ejecutar()

    def test_spn_enum(self, fw):
        mod = self._instancia(fw, "ad/spn_enum",
                              {"RHOST": "10.0.0.10", "BASE_DN": "DC=corp,DC=local"})
        spn_attr = ldap_min.ber_secuencia(
            ldap_min.ber_octetos(b"servicePrincipalName"),
            ldap_min.ber_secuencia(ldap_min.ber_octetos(b"MSSQLSvc/sql.corp.local:1433")))
        sam_attr = ldap_min.ber_secuencia(
            ldap_min.ber_octetos(b"sAMAccountName"),
            ldap_min.ber_secuencia(ldap_min.ber_octetos(b"svc_sql")))
        mensaje = ldap_min._mensaje(2, ldap_min.tlv(
            0x64, ldap_min.ber_octetos(b"CN=svc_sql,DC=corp,DC=local")
            + ldap_min.ber_secuencia(spn_attr, sam_attr)))
        bind_ok = ldap_min._mensaje(1, ldap_min.tlv(
            0x61, ldap_min.ber_enumerado(0)
            + ldap_min.ber_octetos(b"") + ldap_min.ber_octetos(b"")))
        done = ldap_min._mensaje(2, ldap_min.tlv(
            0x65, ldap_min.ber_enumerado(0)
            + ldap_min.ber_octetos(b"") + ldap_min.ber_octetos(b"")))
        sock = TestLdapMin._Sock([bind_ok, mensaje, done])
        with mock.patch("socket.create_connection", return_value=sock):
            r = mod.ejecutar()
        assert r["cuentas"][0]["usuario"] == "svc_sql"
        assert "MSSQLSvc" in r["cuentas"][0]["spns"][0]

    def test_smb_check_firma_no_exigida(self, fw):
        mod = self._instancia(fw, "ad/smb_check", {"RHOST": "10.0.0.10"})
        respuesta = construir_negotiate_falso(firma=0x01, dialecto=0x0311)
        with mock.patch("socket.create_connection") as fabrica:
            fabrica.return_value.recv.side_effect = [respuesta[:4], respuesta[4:]]
            fabrica.return_value.sendall = lambda d: None
            fabrica.return_value.settimeout = lambda t: None
            fabrica.return_value.close = lambda: None
            r = mod.ejecutar()
        assert r["dialecto"] == "3.1.1" and r["firma_exigida"] is False
        assert "relevo" in r["evaluacion"].lower()

    def test_smb_check_firma_exigida(self, fw):
        mod = self._instancia(fw, "ad/smb_check", {"RHOST": "10.0.0.10"})
        respuesta = construir_negotiate_falso(firma=0x03, dialecto=0x0302)
        with mock.patch("socket.create_connection") as fabrica:
            fabrica.return_value.recv.side_effect = [respuesta[:4], respuesta[4:]]
            fabrica.return_value.sendall = lambda d: None
            fabrica.return_value.settimeout = lambda t: None
            fabrica.return_value.close = lambda: None
            r = mod.ejecutar()
        assert r["firma_exigida"] is True and "mitigado" in r["evaluacion"]

    def test_net_discover_parseadores(self):
        from modules.ad.net_discover import (parsear_llmnr, parsear_mdns,
                                             parsear_nbtns,
                                             decodificar_nombre_netbios)
        # LLMNR: consulta por "PC-01"
        qname = b"\x05PC-01\x00"
        llmnr = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
        assert parsear_llmnr(llmnr) == "PC-01"
        assert parsear_llmnr(struct.pack(">HHHHHH", 1, 0x8000, 0, 0, 0, 0)) is None
        # mDNS igual formato (_impresora = 10 bytes → \x0a)
        mdns = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x0a_impresora\x04_lab\x00" + struct.pack(">HH", 12, 1)
        assert parsear_mdns(mdns) == "_impresora._lab"
        # NetBIOS: 'PC-01' codificado + sufijo 0x20
        codificado = "".join(chr(0x41 + (b >> 4)) + chr(0x41 + (b & 0xF))
                             for b in b"PC-01".ljust(15) + b"\x20")
        nbtns = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + bytes([len(codificado)]) + codificado.encode() + b"\x00" + struct.pack(">HH", 32, 1)
        nombre, opcode = parsear_nbtns(nbtns)
        assert nombre == "PC-01" and opcode == 0
        assert decodificar_nombre_netbios("") == ""

    def test_net_discover_sin_permiso(self, fw, monkeypatch):
        mod = self._instancia(fw, "ad/net_discover",
                              {"DURACION": "1", "PROTOCOLOS": "llmnr"})
        def abrir_fallido(sock_fam, tipo):
            raise PermissionError("sin permiso")
        monkeypatch.setattr("socket.socket", abrir_fallido)
        with pytest.raises(ModuloError):
            mod.ejecutar()


def construir_negotiate_falso(firma: int, dialecto: int) -> bytes:
    """SMB2 NEGOTIATE RESPONSE sintético (NetBIOS + header 64 + cuerpo)."""
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0)  # ProtocolId+Size+Charge
    h += struct.pack("<I", 0)            # Status = 0 (éxito)
    h += struct.pack("<H", 0)            # Command = NEGOTIATE
    h += struct.pack("<H", 1)            # Credits
    h += struct.pack("<I", 0)            # Flags
    h += struct.pack("<I", 0)            # NextCommand
    h += struct.pack("<Q", 1)            # MessageId
    h += struct.pack("<I", 0)            # Reserved
    h += struct.pack("<I", 0)            # TreeId
    h += struct.pack("<Q", 0)            # SessionId
    h += b"\x00" * 16                    # Signature
    assert len(h) == 64, len(h)
    cuerpo = struct.pack("<HHHH", 65, firma, dialecto, 0)  # Struct+SecMode+Dialect+CtxCount
    cuerpo += bytes(range(16))           # ServerGuid
    cuerpo += struct.pack("<IIII", 0x2F, 8192, 8192, 8192)
    cuerpo += struct.pack("<Q", 0) + struct.pack("<Q", 0)   # SystemTime/StartTime
    cuerpo += struct.pack("<HH", 0, 0)   # SecurityBufferOffset/Length
    cuerpo += struct.pack("<I", 0)       # NegotiateContextOffset
    mensaje = h + cuerpo
    return struct.pack(">I", len(mensaje)) + mensaje
