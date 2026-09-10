# -*- coding: utf-8 -*-
"""Tests v1.4: TGS/kerberoast (krb5), smb_min (NTLMv2), módulos ad/kerberoast,
ad/smb_login, ad/smb_share_enum, web/jwt_analyzer, web/cookie_audit,
web/ssti_scanner, tabla vulns y comandos vulns/resource."""

import base64
import hashlib
import hmac
import io
import json
import struct
from unittest import mock

import pytest

from core import krb5, smb_min
from core.base_module import ModuloError

from tests.test_v13 import construir_negotiate_falso


@pytest.fixture()
def fw(tmp_path):
    from core.framework import RedHavocFramework
    return RedHavocFramework(tmp_path)


# =====================================================================
# Utilidades: sockets falsos y respuestas SMB2 sintéticas
# =====================================================================
class SockFalso:
    """Socket que responde con una cola de respuestas NetBIOS completas."""

    def __init__(self, respuestas):
        self._cola = []
        for r in respuestas:
            self._cola.append(r[:4])
            self._cola.append(r[4:])
        self.enviados = []

    def settimeout(self, t):
        pass

    def sendall(self, datos):
        self.enviados.append(datos)

    def recv(self, n):
        return self._cola.pop(0) if self._cola else b""

    def close(self):
        pass


def _header_smb(comando, status=0, mid=0, session_id=0, tree_id=0):
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0)
    h += struct.pack("<I", status)
    h += struct.pack("<H", comando) + struct.pack("<H", 1)
    h += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", mid)
    h += struct.pack("<I", 0) + struct.pack("<I", tree_id)
    h += struct.pack("<Q", session_id) + b"\x00" * 16
    assert len(h) == 64, len(h)
    return h


def blob_type2_falso():
    """NTLMSSP CHALLENGE mínimo (reto fijo, sin TargetInfo)."""
    return (b"NTLMSSP\x00" + struct.pack("<I", 2)
            + b"CORP\x00\x00\x00\x00"[:8]       # target name (8)
            + struct.pack("<I", 0x8201)         # flags
            + b"\x11" * 8                       # reto servidor @24
            + b"\x00" * 8                       # reservado @32
            + struct.pack("<HHI", 0, 0, 64))    # target_info vacío @40


def respuesta_setup(status, blob=b"", session_id=0x1234):
    cuerpo = struct.pack("<HHHH", 9, 0, 72, len(blob))
    msg = _header_smb(1, status=status, session_id=session_id) + cuerpo + blob
    return struct.pack(">I", len(msg)) + msg


def respuesta_tree(status=0, tree_id=0, tipo=1):
    cuerpo = (struct.pack("<H", 16) + bytes([tipo]) + b"\x00"
              + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 0x1FF))
    msg = _header_smb(3, status=status, tree_id=tree_id) + cuerpo
    return struct.pack(">I", len(msg)) + msg


class RespuestaSesionFalsa:
    """Respuesta `requests` mínima."""

    def __init__(self, texto="", status=200, headers=None):
        self.text = texto
        self.status_code = status
        self.headers = headers or {}
        self.cookies = []


# =====================================================================
# core.krb5 — bloque TGS (kerberoast)
# =====================================================================
def as_rep_sintetico(reino, cname, contrasena):
    """AS-REP cuyo enc-part descifra con `contrasena` y trae ticket."""
    clave_sesion = b"\x33" * 16
    llano = krb5.der_secuencia(
        krb5.ctx_cons(0, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(1, krb5.der_octetos(clave_sesion)))))
    cifrado = krb5.cifrar_rc4_hmac(krb5.clave_nt(contrasena), 8, llano)
    ticket = krb5.tlv(0x63, krb5.der_secuencia(
        krb5.ctx_prim(0, krb5.der_entero(5)),
        krb5.ctx_prim(1, krb5.der_cadena(reino)),
        krb5.ctx_cons(2, krb5._principal("krbtgt/" + reino)),
        krb5.ctx_cons(3, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(2, krb5.der_octetos(b"\x00" * 24))))))
    cuerpo = krb5.der_secuencia(
        krb5.ctx_prim(0, krb5.der_entero(5)),
        krb5.ctx_prim(1, krb5.der_entero(11)),
        krb5.ctx_prim(2, krb5.der_cadena(reino)),
        krb5.ctx_cons(3, krb5._principal(cname)),
        krb5.ctx_cons(5, ticket),
        krb5.ctx_cons(6, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(2, krb5.der_octetos(cifrado)))))
    return krb5.tlv(0x6B, cuerpo)


def tgs_rep_sintetico(reino, cname, clave_servicio):
    """TGS-REP con enc-part etype 23 (el objetivo del kerberoast)."""
    enc = krb5.cifrar_rc4_hmac(clave_servicio, 2, b"ABCD" * 8)
    cuerpo = krb5.der_secuencia(
        krb5.ctx_prim(0, krb5.der_entero(5)),
        krb5.ctx_prim(1, krb5.der_entero(13)),
        krb5.ctx_prim(2, krb5.der_cadena(reino)),
        krb5.ctx_cons(3, krb5._principal(cname)),
        krb5.ctx_cons(5, krb5.der_secuencia(
            krb5.ctx_prim(0, krb5.der_entero(23)),
            krb5.ctx_prim(2, krb5.der_octetos(enc)))))
    return krb5.tlv(0x6D, cuerpo)


class TestKrb5Tgs:
    def test_descifrar_roundtrip(self):
        clave = krb5.clave_nt("LabPassword1!")
        sellado = krb5.cifrar_rc4_hmac(clave, 2, b"payload-de-prueba")
        llano, uso = krb5.descifrar_rc4_hmac(clave, (8, 3, 2), sellado)
        assert llano == b"payload-de-prueba" and uso == 2
        mal, uso2 = krb5.descifrar_rc4_hmac(krb5.clave_nt("otra"), 2, sellado)
        assert mal is None and uso2 is None

    def test_tgs_req_embute_el_ticket(self):
        ticket = b"\x63\x0f" + b"\x00" * 13
        tgs = krb5.construir_tgs_req("CORP.LOCAL", "usuario",
                                     "cifs/dc.corp.local", ticket, b"\x11" * 16)
        assert tgs[0] == 0x6C            # [APPLICATION 12]
        assert ticket in tgs             # AP-REQ reutiliza el TGT

    def test_interpretar_tgs_rep_y_error(self):
        rep = tgs_rep_sintetico("CORP.LOCAL", "usuario", krb5.clave_nt("SvcPass"))
        r = krb5.interpretar_tgs_rep(rep, "usuario", "CORP.LOCAL", "cifs/dc")
        assert r["tipo"] == "tgsrep"
        assert r["hash"].startswith("$krb5tgs$23$*usuario$CORP.LOCAL$")
        err = krb5.tlv(0x7E, krb5.der_secuencia(
            krb5.ctx_prim(6, krb5.der_entero(7))))
        r2 = krb5.interpretar_tgs_rep(err, "u", "CORP.LOCAL", "x")
        assert r2["tipo"] == "error" and r2["codigo"] == 7

    def test_verificar_y_crackear_18200_13100(self):
        # 18200 (AS-REP)
        enc1 = krb5.cifrar_rc4_hmac(krb5.clave_nt("ClaveAsrep"), 8, b"X" * 20)
        h1 = f"$krb5asrep$23$u@CORP.LOCAL:{enc1[:16].hex()}${enc1[16:].hex()}"
        # 13100 (TGS)
        enc2 = krb5.cifrar_rc4_hmac(krb5.clave_nt("ClaveTgs"), 2, b"Y" * 20)
        h2 = f"$krb5tgs$23$*svc$CORP.LOCAL$cifs/dc*${enc2[:16].hex()}${enc2[16:].hex()}"
        assert krb5.verificar_hash_kerberos(h1, "ClaveAsrep")
        assert not krb5.verificar_hash_kerberos(h1, "mala")
        crakeados = krb5.crackear_hashes_kerberos([h1, h2],
                                                  ["nope", "ClaveTgs", "ClaveAsrep"])
        assert crakeados == {h1: "ClaveAsrep", h2: "ClaveTgs"}

    def test_obtener_tgs_flujo_completo(self):
        as_rep = as_rep_sintetico("CORP.LOCAL", "usuario", "LabPassword1!")
        tgs_rep = tgs_rep_sintetico("CORP.LOCAL", "usuario", krb5.clave_nt("SvcPass"))
        with mock.patch("core.krb5.enviar_kdc", side_effect=[as_rep, tgs_rep]):
            r = krb5.obtener_tgs("10.0.0.10", "usuario", "LabPassword1!",
                                 "CORP.LOCAL", "cifs/dc.corp.local")
        assert r["tipo"] == "tgsrep" and r["hash"].startswith("$krb5tgs$23$")

    def test_obtener_tgs_password_mala(self):
        as_rep = as_rep_sintetico("CORP.LOCAL", "usuario", "OtraPassword!")
        with mock.patch("core.krb5.enviar_kdc", return_value=as_rep):
            r = krb5.obtener_tgs("10.0.0.10", "usuario", "LabPassword1!",
                                 "CORP.LOCAL", "cifs/dc.corp.local")
        assert r["tipo"] == "error" and r["fase"] == "asreq"

    def test_obtener_tgs_kdc_error(self):
        err = krb5.tlv(0x7E, krb5.der_secuencia(
            krb5.ctx_prim(6, krb5.der_entero(24))))
        with mock.patch("core.krb5.enviar_kdc", return_value=err):
            r = krb5.obtener_tgs("10.0.0.10", "u", "x", "CORP.LOCAL", "cifs/dc")
        assert r["tipo"] == "error" and r["fase"] == "asreq"


# =====================================================================
# core.smb_min — NTLMSSP y framing
# =====================================================================
class TestSmbMin:
    def test_type1_type3_estructura(self):
        t1 = smb_min.construir_type1()
        assert t1[:8] == b"NTLMSSP\x00" and t1[8:12] == b"\x01\x00\x00\x00"
        t3 = smb_min.construir_type3("admin", "CORP", b"\x11" * 8, b"",
                                     smb_min._hash_nt("clave"),
                                     timestamp=1, reto_cliente=b"\x22" * 8)
        assert t3[:8] == b"NTLMSSP\x00" and t3[8:12] == b"\x03\x00\x00\x00"
        assert b"\x00" * 24 in t3            # LM a cero

    def test_ntlmv2_determinista_y_sensible(self):
        nt = smb_min._hash_nt("clave")
        base = smb_min.respuesta_ntlmv2(nt, "admin", "CORP", b"\x11" * 8,
                                        b"", timestamp=1, reto_cliente=b"\x22" * 8)
        assert base == smb_min.respuesta_ntlmv2(nt, "admin", "CORP", b"\x11" * 8,
                                                b"", timestamp=1,
                                                reto_cliente=b"\x22" * 8)
        otro_reto = smb_min.respuesta_ntlmv2(nt, "admin", "CORP", b"\x99" * 8,
                                             b"", timestamp=1,
                                             reto_cliente=b"\x22" * 8)
        assert base[:16] != otro_reto[:16]
        # dominio normalizado a mayúsculas (mismo enfoque que smbprotocol)
        mayus = smb_min.respuesta_ntlmv2(nt, "ADMIN", "corp", b"\x11" * 8,
                                         b"", timestamp=1, reto_cliente=b"\x22" * 8)
        assert base[:16] == mayus[:16]

    def test_parsear_type2(self):
        tipo2 = smb_min.parsear_type2(blob_type2_falso())
        assert tipo2["reto"] == b"\x11" * 8 and tipo2["target_info"] == b""

    def test_parsear_type2_blob_malo(self):
        with pytest.raises(smb_min.ModuloError):
            smb_min.parsear_type2(b"XXXX\x00\x00")

    def test_framing_session_y_tree(self):
        p = smb_min.construir_session_setup(b"blob", message_id=2)
        assert p[12:16] == b"\x00\x00\x00\x00"       # status de petición = 0
        tc = smb_min.construir_tree_connect("DC01", "SYSVOL", 7, 9)
        assert "SYSVOL".encode("utf-16-le") in tc
        td = smb_min.construir_tree_disconnect(5, 7, 10)
        assert len(td) == 4 + 64 + 4

    def test_cliente_login_ok(self):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0)]
        sock = SockFalso(respuestas)
        with mock.patch("socket.create_connection", return_value=sock):
            cliente = smb_min.ClienteSMB("10.0.0.10")
            estado = cliente.iniciar_sesion("admin", "clave", "CORP")
        assert estado == smb_min.NT_SUCCESS
        assert cliente.dialecto == "3.1.1"
        assert len(sock.enviados) == 3               # negotiate + setup1 + setup2

    def test_cliente_login_fallo(self):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0xC000006A)]
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            cliente = smb_min.ClienteSMB("10.0.0.10")
            assert cliente.iniciar_sesion("admin", "mala", "CORP") \
                == smb_min.NT_LOGON_FAILURE

    def test_cliente_sondear_shares(self):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0),
                      respuesta_tree(0, tree_id=0x21, tipo=1),
                      respuesta_tree(0),               # disconnect SYSVOL
                      respuesta_tree(0xC00000CC)]      # C$ → NO EXISTE
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            cliente = smb_min.ClienteSMB("10.0.0.10")
            assert cliente.iniciar_sesion("admin", "clave", "CORP") == smb_min.NT_SUCCESS
            ok = cliente.sondear_share("SYSVOL")
            no = cliente.sondear_share("C$")
        assert ok["resultado"] == "LEGIBLE" and ok["tipo"] == "disco"
        assert no["resultado"] == "NO EXISTE"


# =====================================================================
# ad/kerberoast
# =====================================================================
class TestKerberoast:
    def _instancia(self, fw, opciones, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ad.kerberoast.SALIDA_RAIZ",
                            tmp_path / "output" / "ad")
        cls = fw.module_manager.obtener("ad/kerberoast")
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_sin_spns_error(self, fw, tmp_path, monkeypatch):
        mod = self._instancia(fw, {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                                   "USUARIO": "u", "PASSWORD": "x"},
                              tmp_path, monkeypatch)
        with pytest.raises(ModuloError):
            mod.ejecutar()

    def test_spns_del_informe_de_spn_enum(self, fw, tmp_path, monkeypatch):
        salida = tmp_path / "output"
        salida.mkdir(exist_ok=True)
        (salida / "2026-01-01_ad-spn_enum.json").write_text(json.dumps({
            "framework": "REDHAVOC", "modulo": "ad/spn_enum",
            "resultados": {"cuentas": [
                {"usuario": "svc_sql", "spns": ["MSSQLSvc/sql:1433"]}]}}),
            encoding="utf-8")
        monkeypatch.setattr("modules.ad.kerberoast.SALIDA_RAIZ",
                            salida / "ad")
        as_rep = as_rep_sintetico("CORP.LOCAL", "usuario", "LabPassword1!")
        tgs_rep = tgs_rep_sintetico("CORP.LOCAL", "usuario", krb5.clave_nt("SvcPass"))
        cls = fw.module_manager.obtener("ad/kerberoast")
        mod = cls()
        mod.ctx = fw.ctx
        mod.opciones.set("RHOST", "10.0.0.10")
        mod.opciones.set("REINO", "CORP.LOCAL")
        mod.opciones.set("USUARIO", "usuario")
        mod.opciones.set("PASSWORD", "LabPassword1!")
        with mock.patch("core.krb5.enviar_kdc", side_effect=[as_rep, tgs_rep]), \
                mock.patch("modules.ad.kerberoast.SALIDA_RAIZ", salida / "ad"):
            r = mod.ejecutar()
        assert r["spns"] == ["MSSQLSvc/sql:1433"]
        assert len(r["hashes"]) == 1

    def test_kerberoast_completo_con_crack(self, fw, tmp_path, monkeypatch):
        monkeypatch.chdir(fw.raiz)
        mod = self._instancia(fw, {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                                   "USUARIO": "usuario", "PASSWORD": "LabPassword1!",
                                   "SPNS": "cifs/dc.corp.local",
                                   "CRACK": "true",
                                   "WORDLIST": "@templates/wordlists/ad_claves.txt"},
                              tmp_path, monkeypatch)
        as_rep = as_rep_sintetico("CORP.LOCAL", "usuario", "LabPassword1!")
        clave_svc = krb5.clave_nt("CifradoDeServicio2026!")
        tgs_rep = tgs_rep_sintetico("CORP.LOCAL", "usuario", clave_svc)
        destino_crack = tmp_path / "claves.txt"
        destino_crack.write_text("CifradoDeServicio2026!\n", encoding="utf-8")
        mod.opciones.set("WORDLIST", f"@{destino_crack}")
        with mock.patch("core.krb5.enviar_kdc", side_effect=[as_rep, tgs_rep]):
            r = mod.ejecutar()
        assert len(r["hashes"]) == 1
        assert r["crackeados"][0]["password"] == "CifradoDeServicio2026!"
        assert mod.opciones is not None

    def test_password_mala_aborta(self, fw, tmp_path, monkeypatch):
        mod = self._instancia(fw, {"RHOST": "10.0.0.10", "REINO": "CORP.LOCAL",
                                   "USUARIO": "usuario", "PASSWORD": "LabPassword1!",
                                   "SPNS": "cifs/dc.corp.local"},
                              tmp_path, monkeypatch)
        as_rep = as_rep_sintetico("CORP.LOCAL", "usuario", "OtraPassword!")
        with mock.patch("core.krb5.enviar_kdc", return_value=as_rep):
            with pytest.raises(ModuloError):
                mod.ejecutar()


# =====================================================================
# ad/smb_login y ad/smb_share_enum (módulo completo con socket falso)
# =====================================================================
class TestSmbLogin:
    def _instancia(self, fw, ruta, opciones):
        cls = fw.module_manager.obtener(ruta)
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_pares_con_dominio(self):
        from modules.ad.smb_login import SmbLogin
        pares = SmbLogin._pares("CORP\\admin:Clave 1, bob:sec2")
        assert pares == [("admin", "Clave 1", "CORP"), ("bob", "sec2", "")]
        assert SmbLogin._pares("sin-dos-puntos") == []

    def test_login_valido_registra_credencial(self, fw):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0)]
        mod = self._instancia(fw, "ad/smb_login",
                              {"RHOST": "10.0.0.10",
                               "CREDENCIALES": "CORP\\admin:Lab123"})
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            r = mod.ejecutar()
        assert r["validas"] == [{"usuario": "admin", "dominio": "CORP",
                                 "contrasena": "Lab123"}]
        assert fw.workspace_db.total_creds() == 1
        assert r["probadas"] == 1

    def test_login_mezcla_y_lockout(self, fw):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0xC000006A),            # admin → mala
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0xC0000234)]            # bob → BLOQUEADA
        mod = self._instancia(fw, "ad/smb_login",
                              {"RHOST": "10.0.0.10",
                               "CREDENCIALES": "admin:mala, bob:x"})
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            r = mod.ejecutar()
        assert r["validas"] == []
        assert r["estados"][-1]["estado"] == smb_min.NT_ACCOUNT_LOCKED
        assert "LOCKOUT" in r["resumen"]


class TestSmbShareEnum:
    def _instancia(self, fw, opciones):
        cls = fw.module_manager.obtener("ad/smb_share_enum")
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_clasifica_shares_y_avisa(self, fw):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0),                     # login OK
                      respuesta_tree(0, tree_id=0x21),        # SYSVOL
                      respuesta_tree(0),                      # disconnect
                      respuesta_tree(0, tree_id=0x22),        # ADMIN$
                      respuesta_tree(0),                      # disconnect
                      respuesta_tree(0xC0000022)]             # C$ → DENEGADO
        mod = self._instancia(fw, {"RHOST": "10.0.0.10",
                                   "USUARIO": "admin", "PASSWORD": "x",
                                   "DOMINIO": "CORP",
                                   "SHARES": "SYSVOL, ADMIN$, C$"})
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            r = mod.ejecutar()
        assert r["legibles"] == ["SYSVOL", "ADMIN$"]
        assert r["denegados"] == ["C$"]
        assert any("Share administrativo" in a for a in r["avisos"])
        assert any("SYSVOL" in a for a in r["avisos"])
        assert fw.workspace_db.vulns()[0]["severidad"] == "alto"

    def test_login_rechazado_aborta(self, fw):
        respuestas = [construir_negotiate_falso(firma=0x03, dialecto=0x0311),
                      respuesta_setup(0xC0000016, blob_type2_falso()),
                      respuesta_setup(0xC000006A)]
        mod = self._instancia(fw, {"RHOST": "10.0.0.10",
                                   "USUARIO": "admin", "PASSWORD": "mala",
                                   "SHARES": "IPC$"})
        with mock.patch("socket.create_connection", return_value=SockFalso(respuestas)):
            with pytest.raises(ModuloError):
                mod.ejecutar()


# =====================================================================
# web/jwt_analyzer
# =====================================================================
def jwt_falso(alg="HS256", secreto="secret", claims=None, firmar=True):
    def b64(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    cabecera = b64(json.dumps({"alg": alg}).encode())
    payload = b64(json.dumps(claims or {"sub": "ana", "exp": 9999999999}).encode())
    if not firmar:
        return f"{cabecera}.{payload}"
    firma = b64(hmac.new(secreto.encode(), f"{cabecera}.{payload}".encode(),
                         hashlib.sha256).digest())
    return f"{cabecera}.{payload}.{firma}"


class TestJwtAnalyzer:
    def _mod(self, fw, opciones):
        cls = fw.module_manager.obtener("web/jwt_analyzer")
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_alg_none_es_critico(self, fw):
        mod = self._mod(fw, {"TOKEN": jwt_falso(firmar=False)})
        r = mod.ejecutar()
        severidades = [h["severidad"] for h in r["hallazgos"]]
        assert "critico" in severidades and r["gravedad"] == "critico"
        assert fw.workspace_db.total_vulns() == 1

    def test_secreto_debil_se_detecta(self, fw):
        mod = self._mod(fw, {"TOKEN": jwt_falso(secreto="changeme")})
        r = mod.ejecutar()
        assert r["secreto_roto"] == "changeme"
        assert any("secreto" in h["titulo"] for h in r["hallazgos"])

    def test_token_sano_y_caducado(self, fw):
        sano = self._mod(fw, {"TOKEN": jwt_falso(secreto="xK9-muy-fuerte-2026")})
        r = sano.ejecutar()
        assert r['gravedad'] == 'ok' and r['secreto_roto'] == ''
        caducado = self._mod(fw, {"TOKEN": jwt_falso(secreto="xK9-muy-fuerte-2026",
                                                      claims={"sub": "a", "exp": 1000})})
        r2 = caducado.ejecutar()
        assert any("caducado" in h["titulo"] for h in r2["hallazgos"])

    def test_token_invalido(self, fw):
        mod = self._mod(fw, {"TOKEN": "no-es-un-jwt"})
        with pytest.raises(ModuloError):
            mod.ejecutar()


# =====================================================================
# web/cookie_audit
# =====================================================================
class TestCookieAudit:
    def _mod(self, fw, opciones):
        cls = fw.module_manager.obtener("web/cookie_audit")
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_cookie_insegura_registra_vuln(self, fw):
        respuesta = RespuestaSesionFalsa(headers={"Set-Cookie": "SESSION=abcdef1234; Path=/"})
        mod = self._mod(fw, {"URL": "https://objetivo.test/"})
        with mock.patch("modules.web.cookie_audit.requests.get", return_value=respuesta):
            r = mod.ejecutar()
        assert r["problematicas"] == ["SESSION"]
        assert fw.workspace_db.total_vulns() == 1

    def test_sin_cookies(self, fw):
        respuesta = RespuestaSesionFalsa(texto="hola")
        mod = self._mod(fw, {"URL": "objetivo.test"})
        with mock.patch("modules.web.cookie_audit.requests.get", return_value=respuesta):
            r = mod.ejecutar()
        assert r["cookies"] == [] and "sin cookies" in r["resumen"]


# =====================================================================
# web/ssti_scanner
# =====================================================================
class TestSstiScanner:
    class _SesionFalsa:
        def __init__(self, textos):
            self._textos = list(textos)
            self.headers = {}

        def get(self, url, **kw):
            texto = self._textos.pop(0) if len(self._textos) > 1 else self._textos[0]
            return RespuestaSesionFalsa(texto=texto)

        def post(self, url, **kw):
            return self.get(url)

    def _mod(self, fw, opciones):
        cls = fw.module_manager.obtener("web/ssti_scanner")
        mod = cls()
        mod.ctx = fw.ctx
        for k, v in opciones.items():
            assert mod.opciones.set(k, v), k
        return mod

    def test_ssti_confirmado(self, fw):
        sesion = self._SesionFalsa(["<html>base</html>", "resultado: rvh49 fin"])
        mod = self._mod(fw, {"URL": "https://t.test/saludo?nombre=x"})
        with mock.patch("modules.web.ssti_scanner.requests.Session", return_value=sesion):
            r = mod.ejecutar()
        assert len(r["confirmados"]) == 1
        assert r["confirmados"][0]["motor"] == "Jinja2/Twig"
        assert fw.workspace_db.total_vulns() == 1

    def test_sin_ssti(self, fw):
        sesion = self._SesionFalsa(["<html>base</html>", "sin eco"] * 5)
        mod = self._mod(fw, {"URL": "https://t.test/?q=x"})
        with mock.patch("modules.web.ssti_scanner.requests.Session", return_value=sesion):
            r = mod.ejecutar()
        assert r["confirmados"] == [] and len(r["pruebas"]) == 5

    def test_url_sin_parametros(self, fw):
        mod = self._mod(fw, {"URL": "https://t.test/ruta"})
        with pytest.raises(ModuloError):
            mod.ejecutar()


# =====================================================================
# workspace.vulns + comandos framework (vulns, resource)
# =====================================================================
class TestVulnsYResource:
    def test_add_vuln_dedup_y_orden(self, tmp_path):
        from core.workspace_db import WorkspaceDB
        db = WorkspaceDB(tmp_path / "ws")
        db.add_vuln("h1", "critico A", "critico")
        db.add_vuln("h1", "medio B", "medio")
        db.add_vuln("h1", "critico A", "alto")      # duplicado → ignorado
        db.add_vuln("h2", "alto C", "alto")
        db.add_vuln("h3", "sin severidad", "rara")  # inválida → medio
        vs = db.vulns()
        assert len(vs) == 4
        assert vs[0]["titulo"] == "critico A"      # crítico primero
        assert vs[1]["titulo"] == "alto C"
        assert vs[3]["severidad"] == "medio"
        assert db.resumen().endswith("4 hallazgos · 0 notas")

    def test_cmd_vulns(self, fw):
        fw.workspace_db.add_vuln("10.0.0.5", "X", "alto", "d", "m")
        fw.cmd_vulns([])                       # tabla, sin excepción
        fw.cmd_vulns(["-c"])
        assert fw.workspace_db.total_vulns() == 0

    def test_cmd_resource_ejecuta_comandos(self, fw, tmp_path):
        guion = tmp_path / "op.rc"
        guion.write_text("# guion de ejemplo\nset AUTHORIZED true\nvulns\n",
                         encoding="utf-8")
        fw.cmd_resource([str(guion)])
        assert fw.globales.get_bool("AUTHORIZED") is True

    def test_cmd_resource_inexistente(self, fw, capsys):
        fw.cmd_resource(["/no/existe/x.rc"])   # no debe lanzar excepción
        salida = capsys.readouterr().out
        assert "no existe" in salida.lower()

    def test_cmd_resource_sale_con_exit(self, fw, tmp_path):
        guion = tmp_path / "salir.rc"
        guion.write_text("exit\nset AUTHORIZED true\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            fw.cmd_resource([str(guion)])
        assert fw.globales.get_bool("AUTHORIZED") is False
