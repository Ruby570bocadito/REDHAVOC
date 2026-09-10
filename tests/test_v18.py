# -*- coding: utf-8 -*-
"""v1.8.0: mejorar · optimizar · pulir —

1. Limpieza SELECTIVA del workspace: `hosts -c`, `creds -c` y `vulns -c`
   antes borraban la DB entera (hosts + creds + vulns) — bug de destrucción
   de datos. Ahora cada comando limpia solo su tabla.
2. Paridad msf: `use <n>` / `info <n>` cargan por índice de la última búsqueda.
3. Paridad msf: `setg` / `unsetg` fijan opciones globales aunque haya módulo
   cargado.
4. `sessions -k all` cierra todas las sesiones de golpe.
5. recon/dns_enum consulta los tipos en paralelo (peor caso 1 timeout).
"""
import io
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.framework import RedHavocFramework  # noqa: E402
from core.workspace_db import WorkspaceDB  # noqa: E402


class _Cap:
    """Consola Rich de prueba que escribe a un buffer."""

    def __init__(self):
        from rich.console import Console
        self.file = io.StringIO()
        self.c = Console(file=self.file, force_terminal=False,
                         width=120, theme=None, highlight=False)

    def __getattr__(self, nombre):
        return getattr(self.c, nombre)


# ----------------------------------------------------------------------
# 1. Limpieza selectiva del workspace
# ----------------------------------------------------------------------
class TestLimpiezaSelectiva:
    @pytest.fixture()
    def db(self, tmp_path):
        base = WorkspaceDB(tmp_path)
        base.add_host("10.0.0.5", hostname="dc01.corp.local", notas="KDC")
        base.add_cred("10.0.0.5", "CORP\\admin", "P@ss123", "SMB")
        base.add_vuln("10.0.0.5", "Firma SMB no exigida", "medio", modulo="ad/smb_check")
        return base

    def test_hosts_c_conserva_creds_y_vulns(self, db):
        db.limpiar_hosts()
        assert db.hosts() == []
        assert db.total_creds() == 1
        assert db.total_vulns() == 1

    def test_creds_c_conserva_hosts_y_vulns(self, db):
        db.limpiar_creds()
        assert db.creds() == []
        assert db.total_hosts() == 1
        assert db.total_vulns() == 1

    def test_vulns_c_conserva_hosts_y_creds(self, db):
        db.limpiar_vulns()
        assert db.vulns() == []
        assert db.total_hosts() == 1
        assert db.total_creds() == 1

    def test_limpieza_persiste_en_disco(self, db, tmp_path):
        db.limpiar_hosts()
        rehecho = WorkspaceDB(tmp_path)   # recarga desde db.json
        assert rehecho.total_hosts() == 0
        assert rehecho.total_creds() == 1  # lo demás sobrevive al reinicio

    def test_limpieza_total_sigue_existiendo(self, db):
        db.limpiar()
        assert db.total_hosts() == 0 and db.total_creds() == 0 and db.total_vulns() == 0


# ----------------------------------------------------------------------
# 2. use <n> / info <n> por índice de la última búsqueda
# ----------------------------------------------------------------------
class TestUsePorIndice:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    def test_search_guarda_resultados(self, fw):
        fw.cmd_search(["smb"])
        assert fw._ultima_busqueda, "search debe recordar los resultados"
        assert all("smb" in c.NAME for c in fw._ultima_busqueda)

    def test_use_indice_carga_el_modulo(self, fw):
        fw.cmd_search(["smb"])
        esperado = fw._ultima_busqueda[0].NAME
        fw.cmd_use(["1"])
        assert fw.modulo_actual is not None
        assert fw.modulo_actual.NAME == esperado

    def test_use_indice_medio(self, fw):
        fw.cmd_search([])                      # todos los módulos
        fw._ultima_busqueda.sort(key=lambda c: c.NAME)
        idx = len(fw._ultima_busqueda)
        esperado = fw._ultima_busqueda[idx - 1].NAME
        fw.cmd_use([str(idx)])
        assert fw.modulo_actual.NAME == esperado

    def test_use_sin_busqueda_previa(self, fw, tmp_path):
        fw.cmd_use(["1"])
        assert fw.modulo_actual is None        # aviso, no excepción

    def test_use_indice_fuera_de_rango(self, fw):
        fw.cmd_search(["kerberoast"])          # 1 resultado
        fw.cmd_use(["5"])
        assert fw.modulo_actual is None
        fw.cmd_use(["0"])
        assert fw.modulo_actual is None

    def test_use_nombre_sigue_funcionando(self, fw):
        fw.cmd_use(["recon/ip_info"])
        assert fw.modulo_actual.NAME == "recon/ip_info"

    def test_info_indice(self, fw):
        fw.cmd_search(["whois"])               # whois_lookup + rdap_lookup
        esperado = fw._ultima_busqueda[0].NAME
        fw.cmd_info(["1"])                     # no debe lanzar excepción
        assert esperado == fw._ultima_busqueda[0].NAME
        assert esperado in fw.module_manager.nombres()

    def test_search_nuevo_reemplaza_indice(self, fw):
        fw.cmd_search(["smb"])
        antes = len(fw._ultima_busqueda)
        fw.cmd_search(["kerberos_userenum"])   # 1 resultado
        assert len(fw._ultima_busqueda) == 1
        assert antes >= 1

    def test_setg_completa_globales_en_tab(self, fw):
        cand = fw._candidatos_para("time", "setg time")
        assert cand == ["TIMEOUT"]

    def test_comandos_nuevos_en_lista(self, fw):
        for cmd in ("setg", "unsetg"):
            assert cmd in fw.COMANDOS
            assert cmd in fw._candidatos_para(cmd, "")


# ----------------------------------------------------------------------
# 3. setg / unsetg — globales con módulo cargado
# ----------------------------------------------------------------------
class TestSetgUnsetg:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    def test_setg_con_modulo_cargado(self, fw):
        fw.cmd_use(["recon/port_scanner"])
        fw.cmd_set(["TIMEOUT", "9"], solo_global=True)
        assert fw.globales.get("TIMEOUT") == "9"
        # la opción del módulo no se ve afectada (port_scanner no declara TIMEOUT,
        # así que comprobamos que el módulo sigue cargado y sin cambios globales raros)
        assert fw.modulo_actual is not None

    def test_set_normal_no_toca_global(self, fw):
        fw.cmd_use(["recon/port_scanner"])
        fw.cmd_set(["PORTS", "80"])
        assert fw.modulo_actual.opt("PORTS") == "80"
        assert fw.globales.get("PORTS") == ""   # global intacto

    def test_setg_y_set_conviven(self, fw):
        fw.cmd_use(["recon/port_scanner"])
        fw.cmd_set(["TIMEOUT", "3"])                    # va al módulo (no declarada → aviso)
        fw.cmd_set(["TIMEOUT", "4"], solo_global=True)  # setg explícito
        assert fw.globales.get("TIMEOUT") == "4"

    def test_unsetg_restaura_por_defecto(self, fw):
        fw.cmd_set(["THREADS", "25"], solo_global=True)
        assert fw.globales.get("THREADS") == "25"
        fw.cmd_set(["THREADS"], deshacer=True, solo_global=True)
        assert fw.globales.get("THREADS") == "10"       # valor por defecto

    def test_setg_opcion_desconocida(self, fw):
        fw.cmd_set(["NO_EXISTE", "x"], solo_global=True)  # no debe lanzar
        assert "NO_EXISTE" not in fw.globales


# ----------------------------------------------------------------------
# 4. sessions -k all
# ----------------------------------------------------------------------
class _ConnFalso:
    def __init__(self):
        self.cerrado = False

    def close(self):
        self.cerrado = True


class TestSessionsKillAll:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    def _con_sesiones(self, fw, n=3):
        for _ in range(n):
            sid = fw._siguiente_id_sesion
            fw.sesiones[sid] = {"conn": _ConnFalso(),
                                "addr": ("127.0.0.1", 40000 + sid),
                                "abierta": time.time()}
            fw._siguiente_id_sesion += 1
        return fw

    def test_kill_all_cierra_todas(self, fw):
        self._con_sesiones(fw, 3)
        fw.cmd_sessions(["-k", "all"])
        assert fw.sesiones == {}

    def test_kill_all_cierra_los_sockets(self, fw):
        self._con_sesiones(fw, 2)
        conns = [ses["conn"] for ses in fw.sesiones.values()]
        fw.cmd_sessions(["-k", "all"])
        assert all(c.cerrado for c in conns)

    def test_kill_all_sin_sesiones(self, fw):
        fw.cmd_sessions(["-k", "all"])          # no debe lanzar
        assert fw.sesiones == {}

    def test_kill_individual_sigue_funcionando(self, fw):
        self._con_sesiones(fw, 2)
        fw.cmd_sessions(["-k", "1"])
        assert list(fw.sesiones.keys()) == [2]


# ----------------------------------------------------------------------
# 5. dns_enum en paralelo
# ----------------------------------------------------------------------
class TestDnsEnumParalelo:
    @pytest.fixture()
    def modulo(self, manager):
        return manager.obtener("recon/dns_enum")()

    def test_todos_los_tipos_responden_con_resolver_sordo(self, modulo, monkeypatch):
        """Resolver que no responde: cada tipo degrada a '(timeout)' y el
        total tarda UN timeout, no siete (antes en serie)."""
        import modules.recon.dns_enum as dns

        def sordo(*args, **kwargs):
            time.sleep(0.3)
            raise socket.timeout("tiempo agotado")

        monkeypatch.setattr(dns, "_consultar", sordo)
        modulo.opciones.set("DOMAIN", "lab.local")
        modulo.opciones.set("RESOLVER", "127.0.0.1")
        modulo.opciones.set("TIPOS", "A,AAAA,MX,NS,TXT,SOA,CNAME")

        t0 = time.time()
        res = modulo.ejecutar()
        lapso = time.time() - t0

        assert lapso < 1.2, f"las consultas no van en paralelo ({lapso:.2f}s)"
        for tipo in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            assert res["registros"][tipo] == ["(timeout)"]
        assert res["registros"]["A"] == ["(timeout)"]

    def test_respuesta_real_sigue_parseando(self, modulo, monkeypatch):
        """Un resolver que responde A sigue devolviendo la IP."""
        import modules.recon.dns_enum as dns
        import struct

        def fabricar_respuesta(nombre, tipo, ttl=300, ip="203.0.113.7"):
            # cabecera + pregunta + respuesta A
            cab = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
            qname = b"".join(bytes([len(p)]) + p.encode() for p in nombre.split(".")) + b"\x00"
            pregunta = qname + struct.pack(">HH", tipo, 1)
            respuesta = struct.pack(">HHHIH", 0xC00C, tipo, 1, 1, 4) + socket.inet_aton(ip)
            return cab + pregunta + respuesta

        def respondedor(resolver, nombre, tipo, timeout):
            if tipo == 1:
                return fabricar_respuesta(nombre, tipo)
            raise socket.timeout("sin respuesta")

        monkeypatch.setattr(dns, "_consultar", respondedor)
        modulo.opciones.set("DOMAIN", "lab.local")
        modulo.opciones.set("RESOLVER", "127.0.0.1")

        res = modulo.ejecutar()
        assert res["registros"]["A"] == ["203.0.113.7"]
        assert res["registros"]["TXT"] == ["(timeout)"]

    def test_tipos_invalidos_siguen_fallando_limpio(self, modulo):
        from core.base_module import ModuloError
        modulo.opciones.set("DOMAIN", "lab.local")
        modulo.opciones.set("TIPOS", "A,BOGUS")
        with pytest.raises(ModuloError):
            modulo.ejecutar()
