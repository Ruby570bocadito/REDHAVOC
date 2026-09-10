# -*- coding: utf-8 -*-
"""
Tests v2.2 — módulos nuevos:
    recon/redis_enum · recon/snmp_enum · web/graphql_probe
    web/crlf_scan · cloud/k8s_enum · ad/rootdse_enum

Estrategia: funciones puras de clasificación + servidores locales reales
(TCP/UDP/HTTP) para validar los clientes de protocolo sin red externa.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.base_module import ModuloError


# =====================================================================
# Servidores de laboratorio locales
# =====================================================================
class RedisLab(threading.Thread):
    """Mini-Redis RESP en localhost: responde PONG/INFO/DBSIZE."""

    INFO = (
        "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
        "os:Linux 5.15\r\ntcp_port:6379\r\n"
        "# Clients\r\nconnected_clients:3\r\n"
        "# Persistence\r\n\r\n"
    )

    def __init__(self):
        super().__init__(daemon=True)
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.servidor.bind(("127.0.0.1", 0))
        self.servidor.listen(4)
        self.puerto = self.servidor.getsockname()[1]
        self.vivo = threading.Event()
        self.vivo.set()

    def run(self):
        while self.vivo.is_set():
            try:
                conn, _ = self.servidor.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                while True:
                    try:
                        datos = conn.recv(4096)
                    except (OSError, socket.timeout):
                        break
                    if not datos:
                        break
                    texto = datos.decode("utf-8", "replace").upper()
                    if "PING" in texto:
                        conn.sendall(b"+PONG\r\n")
                    elif "INFO" in texto:
                        cuerpo = self.INFO.encode()
                        conn.sendall(b"$" + str(len(cuerpo)).encode() + b"\r\n"
                                     + cuerpo + b"\r\n")
                    elif "DBSIZE" in texto:
                        conn.sendall(b":42\r\n")
                    else:
                        conn.sendall(b"-ERR comando no soportado\r\n")

    def parar(self):
        self.vivo.clear()
        self.servidor.close()


class SnmpLab(threading.Thread):
    """Mini-agente SNMP en localhost (UDP): responde GET de sysDescr."""

    def __init__(self, comunidad="public"):
        super().__init__(daemon=True)
        self.comunidad = comunidad
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.puerto = self.sock.getsockname()[1]
        self.vivo = threading.Event()
        self.vivo.set()

    def run(self):
        from modules.recon.snmp_enum import _tlv, _entero, _oid_a_bytes, _cadena
        while self.vivo.is_set():
            try:
                datos, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            # Extrae la comunidad del paquete (3.º TLV de nivel 1)
            try:
                _tag, cuerpo, pos = _leer_tlvs(datos)
                _tag, _ver, pos = _leer_tlvs(cuerpo, 0)
                _tag, com, pos = _leer_tlvs(cuerpo, pos)
            except Exception:
                continue
            if com.decode("utf-8", "replace") != self.comunidad:
                continue
            # GET-RESPONSE con sysDescr
            varbind = _tlv(0x30, _tlv(0x06, _oid_a_bytes("1.3.6.1.2.1.1.1.0"))
                           + _tlv(0x04, b"Linux lab 5.15.0 x86_64"))
            pdu = _tlv(0xA2, _entero(1) + _entero(0) + _entero(0)
                       + _tlv(0x30, varbind))
            paquete = _tlv(0x30, _entero(1) + _cadena(self.comunidad) + pdu)
            self.sock.sendto(paquete, peer)

    def parar(self):
        self.vivo.clear()
        self.sock.close()


def _leer_tlvs(datos, pos=0):
    tag = datos[pos]
    pos += 1
    longitud = datos[pos]
    pos += 1
    if longitud & 0x80:
        n = longitud & 0x7F
        longitud = int.from_bytes(datos[pos:pos + n], "big")
        pos += n
    return tag, datos[pos:pos + longitud], pos + longitud


class _LabHTTP(BaseHTTPRequestHandler):
    """HTTP de laboratorio configurable vía clase (sin logs)."""

    def log_message(self, *_args):        # silencio total
        pass

    def _contestar(self):
        ruta = self.path.lower()
        if "graphql" in ruta:
            cuerpo = b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif "marcador" in ruta:
            self.send_response(200)
            self.send_header("Xrhvcmarcador", "inyectada")   # canario reflejado
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        else:
            cuerpo = b"<html><body>lab</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        self._contestar()

    def do_POST(self):
        longitud = int(self.headers.get("Content-Length") or 0)
        if longitud:
            self.rfile.read(longitud)
        self._contestar()


class HttpLab(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.httpd = HTTPServer(("127.0.0.1", 0), _LabHTTP)
        self.puerto = self.httpd.server_port

    def run(self):
        self.httpd.serve_forever(poll_interval=0.1)

    def parar(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# =====================================================================
# recon/redis_enum
# =====================================================================
class TestRedisEnum:
    def test_comando_resp(self, manager):
        from modules.recon.redis_enum import comando_resp
        assert comando_resp("PING") == b"*1\r\n$4\r\nPING\r\n"

    def test_clasificar(self, manager):
        from modules.recon.redis_enum import clasificar_respuesta
        assert clasificar_respuesta({"PING": "PONG"}) == "SIN_AUTH"
        assert clasificar_respuesta(
            {"PING": "NOAUTH Authentication required."}) == "PROTEGIDA"
        assert clasificar_respuesta(
            {"PING": "DENIED Redis is running in protected mode"}) == "PROTEGIDA"
        assert clasificar_respuesta(
            {"PING": "HTTP/1.1 400 Bad Request"}) == "NO_REDIS"
        assert clasificar_respuesta({}) == "NO_REDIS"

    def test_parsear_info(self, manager):
        from modules.recon.redis_enum import parsear_info
        campos = parsear_info(
            "# Server\r\nredis_version:7.2.4\r\ntcp_port:6379\r\nbasura\r\n")
        assert campos["redis_version"] == "7.2.4"
        assert campos["tcp_port"] == "6379"
        assert "basura" not in campos

    def test_redis_real_sin_auth(self, manager):
        lab = RedisLab()
        lab.start()
        try:
            cls = manager.obtener("recon/redis_enum")
            m = cls()
            m.opciones.set("RHOST", "127.0.0.1")
            m.opciones.set("PUERTO", str(lab.puerto))
            m.opciones.set("TIMEOUT", "3")
            res = m.ejecutar()
            assert res["resultados"][0]["estado"] == "SIN_AUTH"
            assert res["resultados"][0]["info"]["redis_version"] == "7.2.4"
            assert res["resultados"][0]["claves"] == "42"
        finally:
            lab.parar()

    def test_redis_inaccesible(self, manager):
        cls = manager.obtener("recon/redis_enum")
        m = cls()
        m.opciones.set("RHOST", "127.0.0.1")
        # Puerto cerrado (refuso inmediato en localhost) → ModuloError
        m.opciones.set("PUERTO", "1")
        m.opciones.set("TIMEOUT", "2")
        with pytest.raises(ModuloError):
            m.ejecutar()

    def test_sin_rhost(self, manager):
        cls = manager.obtener("recon/redis_enum")
        m = cls()
        with pytest.raises(ModuloError):
            m.ejecutar()


# =====================================================================
# recon/snmp_enum
# =====================================================================
class TestSnmpEnum:
    def test_oid_codificacion(self, manager):
        from modules.recon.snmp_enum import _expander_oid, _oid_a_bytes
        octetos = _oid_a_bytes("1.3.6.1.2.1.1.1.0")
        assert _expander_oid(octetos) == [1, 3, 6, 1, 2, 1, 1, 1, 0]

    def test_peticion_get_estructura(self, manager):
        from modules.recon.snmp_enum import peticion_get
        paquete = peticion_get("public", "1.3.6.1.2.1.1.1.0")
        assert paquete[0] == 0x30

    def test_decodificar_roundtrip(self):
        from modules.recon.snmp_enum import (
            _cadena, _entero, _oid_a_bytes, _tlv, decodificar_respuesta)
        varbind = _tlv(0x30, _tlv(0x06, _oid_a_bytes("1.3.6.1.2.1.1.1.0"))
                       + _tlv(0x04, b"Linux lab 5.15.0 x86_64"))
        pdu = _tlv(0xA2, _entero(1) + _entero(0) + _entero(0)
                   + _tlv(0x30, varbind))
        paquete = _tlv(0x30, _entero(1) + _cadena("public") + pdu)
        valores = decodificar_respuesta(paquete)
        assert valores["1.3.6.1.2.1.1.1.0"] == "Linux lab 5.15.0 x86_64"
        assert decodificar_respuesta(b"\x30\x03\x02\x01\x01") == {}

    def test_snmp_real(self, manager):
        lab = SnmpLab("public")
        lab.start()
        try:
            cls = manager.obtener("recon/snmp_enum")
            m = cls()
            m.opciones.set("RHOST", "127.0.0.1")
            m.opciones.set("PUERTO", str(lab.puerto))
            m.opciones.set("COMUNIDADES", "private,public")
            m.opciones.set("TIMEOUT", "2")
            res = m.ejecutar()
            assert res["comunidad"] == "public"
            campos = {f["campo"] for f in res["resultados"]}
            assert "sysDescr" in campos
        finally:
            lab.parar()

    def test_snmp_sin_comunidad(self, manager):
        lab = SnmpLab("oculta")
        lab.start()
        try:
            cls = manager.obtener("recon/snmp_enum")
            m = cls()
            m.opciones.set("RHOST", "127.0.0.1")
            m.opciones.set("PUERTO", str(lab.puerto))
            m.opciones.set("COMUNIDADES", "public,private")
            m.opciones.set("TIMEOUT", "1")
            res = m.ejecutar()
            assert "comunidad" not in res or res.get("comunidad", "") == ""
            assert "comunidades_probadas" in res["resultados"][0]
        finally:
            lab.parar()


# =====================================================================
# web/graphql_probe
# =====================================================================
class TestGraphQLProbe:
    def test_clasificar_sonda(self):
        from modules.web.graphql_probe import clasificar_sonda
        assert clasificar_sonda(
            200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}') \
            == "INTROSPECCION_ABIERTA"
        assert clasificar_sonda(403, "Forbidden") == "PROTEGIDO"
        assert clasificar_sonda(200, '{"data":{"usuario":"x"}}') \
            == "ENDPOINT_ACTIVO"
        assert clasificar_sonda(200, "<html>hola</html>") == "NO_GRAPHQL"
        assert clasificar_sonda(400, '{"errors":["query"]}') \
            == "ENDPOINT_ACTIVO"

    def test_detectar_playground(self):
        from modules.web.graphql_probe import detectar_playground
        assert detectar_playground('<div id="graphiql">') == "GraphiQL"
        assert detectar_playground("Altair GraphQL") == "Altair"
        assert detectar_playground("nada") == ""

    def test_graphql_real(self, manager):
        lab = HttpLab()
        lab.start()
        try:
            cls = manager.obtener("web/graphql_probe")
            m = cls()
            m.opciones.set("URL", f"http://127.0.0.1:{lab.puerto}")
            m.opciones.set("RUTAS", "graphql,no_hay")
            m.opciones.set("TIMEOUT", "3")
            res = m.ejecutar()
            estados = {r["estado"] for r in res["resultados"]}
            assert "INTROSPECCION_ABIERTA" in estados
        finally:
            lab.parar()

    def test_sin_url(self, manager):
        cls = manager.obtener("web/graphql_probe")
        m = cls()
        with pytest.raises(ModuloError):
            m.ejecutar()


# =====================================================================
# web/crlf_scan
# =====================================================================
class TestCrlfScan:
    def test_partes(self):
        from modules.web.crlf_scan import _partes
        partes = _partes("https://sitio.com/buscar?q=1&pag=2")
        assert partes["base"] == "https://sitio.com/buscar"
        assert partes["pares"] == ["q=1", "pag=2"]

    def test_respuesta_refleja(self):
        from modules.web.crlf_scan import respuesta_refleja_crlf
        assert respuesta_refleja_crlf(
            200, {"Xrhvcmarcador": "inyectada"}, "", "clásico") == "INYECTADA"
        assert respuesta_refleja_crlf(
            200, {}, "cuerpo con Xrhvcmarcador suelto", "clásico") == "REFLEJADA"
        assert respuesta_refleja_crlf(
            200, {"Otro": "v"}, "<html>ok</html>", "clásico") == ""

    def test_crlf_lab(self, manager):
        lab = HttpLab()
        lab.start()
        try:
            cls = manager.obtener("web/crlf_scan")
            m = cls()
            m.opciones.set("URL", f"http://127.0.0.1:{lab.puerto}/r?x=1")
            m.opciones.set("TIMEOUT", "3")
            res = m.ejecutar()
            # El lab refleja el canario como cabecera → inyección confirmada
            assert res["resultados"][0]["inyectadas"], res
        finally:
            lab.parar()


# =====================================================================
# cloud/k8s_enum
# =====================================================================
class TestK8sEnum:
    def test_clasificar_api(self):
        from modules.cloud.k8s_enum import clasificar_api_k8s
        assert clasificar_api_k8s(
            200, '{"major":"1","gitVersion":"v1.29.1"}') == "ANONIMO_META"
        assert clasificar_api_k8s(
            200, '{"kind":"PodList","apiVersion":"v1","items":[]}') == "ANONIMO_PODS"
        assert clasificar_api_k8s(403, "forbidden") == "PROTEGIDO"
        assert clasificar_api_k8s(200, "<html/>") == "NO_K8S"

    def test_resumen_pods(self):
        from modules.cloud.k8s_enum import resumen_pods
        pods = resumen_pods(
            '{"items":[{"metadata":{"name":"api","namespace":"prod"}},'
            '{"metadata":{"name":"web","namespace":"dev"}}]}')
        assert pods == ["prod/api", "dev/web"]
        assert resumen_pods("no-json") == []

    def test_k8s_lab(self, manager):
        # Servimos una respuesta de API k8s en el lab HTTP (puerto configurable)
        class K8sLab(_LabHTTP):
            def _contestar(self):
                cuerpo = b'{"major":"1","gitVersion":"v1.29.1"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

        lab = HttpLab()
        lab.httpd.RequestHandlerClass = K8sLab
        lab.start()
        try:
            cls = manager.obtener("cloud/k8s_enum")
            m = cls()
            m.opciones.set("RHOST", "127.0.0.1")
            m.opciones.set("PUERTO_DOCKER", str(lab.puerto))
            m.opciones.set("PUERTO_K8S", str(lab.puerto))
            m.opciones.set("PUERTO_KUBELET", str(lab.puerto))
            m.opciones.set("TIMEOUT", "3")
            res = m.ejecutar()
            docker_meta = [r for r in res["resultados"]
                           if r["servicio"] == "Docker API"]
            assert docker_meta and docker_meta[0]["estado"] == "ANONIMO_META"
        finally:
            lab.parar()


# =====================================================================
# ad/rootdse_enum
# =====================================================================
class TestRootDseEnum:
    def test_nivel_windows(self):
        from modules.ad.rootdse_enum import nivel_windows
        assert nivel_windows("7") == "Windows Server 2016"
        assert nivel_windows("2019") == "Windows Server 2019"
        assert nivel_windows("") == "?"
        assert nivel_windows("abc") == "abc"

    def test_resumen_rootdse(self):
        from modules.ad.rootdse_enum import resumen_rootdse
        resumen = resumen_rootdse([{
            "defaultNamingContext": "DC=corp,DC=local",
            "dnsHostName": "dc01.corp.local",
            "domainFunctionality": "7",
            "namingContexts": ["DC=corp,DC=local", "CN=Configuration,DC=corp"],
        }])
        assert resumen["dominio_dn"] == "DC=corp,DC=local"
        assert resumen["dc_hostname"] == "dc01.corp.local"
        assert resumen["nivel_dominio"] == "Windows Server 2016"
        assert len(resumen["naming_contexts"]) == 2
        assert resumen_rootdse([]) == {}

    def test_sin_rhost(self, manager):
        cls = manager.obtener("ad/rootdse_enum")
        m = cls()
        with pytest.raises(ModuloError):
            m.ejecutar()


# =====================================================================
# Consejos de los módulos nuevos
# =====================================================================
class TestConsejosV22:
    def test_redis_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado(
            "recon/redis_enum", {"estado": "SIN_AUTH", "resultados": []})
        assert c and "requirepass" in c[0].texto

    def test_rootdse_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado(
            "ad/rootdse_enum", {"siguiente_dn": "DC=corp,DC=local"})
        assert c and "ldap_enum" in c[0].comando

    def test_k8s_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado("cloud/k8s_enum", {"resultados": [
            {"servicio": "Docker API", "estado": "ANONIMO_META"}]})
        assert c and "RBAC" in c[0].texto

    def test_graphql_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado("web/graphql_probe", {"resultados": [
            {"url": "x", "estado": "INTROSPECCION_ABIERTA"}]})
        assert c and "esquema" in c[0].texto.lower()

    def test_crlf_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado("web/crlf_scan", {"inyectadas": [{"url": "x"}]})
        assert c and "cookie" in c[0].texto.lower()

    def test_snmp_consejos(self):
        from core.advice import consejos_de_resultado
        c = consejos_de_resultado("recon/snmp_enum", {"comunidad": "public"})
        assert c and "sysDescr" in c[0].texto
