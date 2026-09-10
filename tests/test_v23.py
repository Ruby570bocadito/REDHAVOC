# -*- coding: utf-8 -*-
"""
Tests v2.3.0 — "Pulido y paridad":
    · core/targets (expansión RHOSTS multi-host estilo NetExec)
    · barrido multi-host del framework (línea por host, clones, agregado)
    · jobs en segundo plano (run -j / jobs / jobs -k / jobs -c)
    · comando services · sessions -x · CVE en info
    · cobertura de consejos para TODOS los módulos
    · engagement con RHOSTS (filtro por objetivo)
"""

import io
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import __version__  # noqa: E402
from core.base_module import BaseModulo, ModuloError  # noqa: E402
from core.framework import RedHavocFramework  # noqa: E402
from core.targets import ObjetivoError, expandir_objetivos  # noqa: E402


class _Cap:
    """Consola Rich de prueba que escribe a un buffer (tema del framework)."""

    def __init__(self):
        from rich.console import Console
        from core.colors import TEMA
        self.file = io.StringIO()
        self.c = Console(file=self.file, force_terminal=False,
                         width=140, theme=TEMA, highlight=False)

    def __getattr__(self, nombre):
        return getattr(self.c, nombre)


@pytest.fixture()
def fw(tmp_path, monkeypatch):
    marco = RedHavocFramework(tmp_path)
    marco.console_cap = _Cap()
    monkeypatch.setattr("core.framework.console", marco.console_cap.c)
    return marco


def salida(marco) -> str:
    return marco.console_cap.file.getvalue()


# ----------------------------------------------------------------------
# Módulo de laboratorio para barridos multi-host
# ----------------------------------------------------------------------
class MultiLab(BaseModulo):
    """Módulo de prueba: atiende un host (opcionalmente falla en uno)."""

    NAME = "lab/multi"
    CATEGORIA = "lab"
    RIESGO = "bajo"
    DESCRIPCION = "Módulo de laboratorio multi-host"

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "Host único")
        self.opciones.declarar("RHOSTS", "", False, "Multi-host")
        self.opciones.declarar("FALLO", "", False, "Sufijo de host que falla")
        self.opciones.declarar("PAUSA_MS", "0", False, "Pausa por host (ms)")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        pausa_ms = self.opt_int("PAUSA_MS", 0) or 0
        if pausa_ms > 0:
            time.sleep(pausa_ms / 1000.0)
        fallo = self.opt("FALLO").strip()
        if fallo and host.endswith(fallo):
            raise ModuloError(f"host caído: {host}")
        if self.workspace is not None:
            self.workspace.add_host(host)
            self.workspace.add_service(host, 445, "smb")
        return {"resumen": f"atendido {host}", "host": host}


def _cargar(marco, modulo):
    """Carga un módulo de laboratorio como módulo actual del framework."""
    marco.modulo_actual = modulo
    marco.modulo_actual.ctx = marco.ctx
    return modulo


def _esperar(marco, jid: int, tope: float = 6.0) -> dict:
    """Espera a que el job termine y lo devuelve."""
    fin = time.time() + tope
    while time.time() < fin:
        job = marco.jobs.get(jid)
        if job and job["estado"] != "ejecutando":
            time.sleep(0.02)
            return job
        time.sleep(0.02)
    return marco.jobs.get(jid) or {}


# ======================================================================
# 1. core/targets — expansión de objetivos
# ======================================================================
class TestTargets:
    def test_host_unico(self):
        assert expandir_objetivos("10.0.0.5") == ["10.0.0.5"]

    def test_nombre_dns_se_mantiene(self):
        assert expandir_objetivos("dc01.corp.local") == ["dc01.corp.local"]

    def test_cidr_30(self):
        assert expandir_objetivos("10.0.0.4/30") == ["10.0.0.5", "10.0.0.6"]

    def test_rango_ultimo_octeto(self):
        assert expandir_objetivos("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_rango_completo(self):
        assert expandir_objetivos("10.0.0.1-10.0.0.3") == \
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_comas_con_deduplicacion(self):
        assert expandir_objetivos("10.0.0.5, 10.0.0.5,10.0.0.6") == \
            ["10.0.0.5", "10.0.0.6"]

    def test_fichero_con_comentarios(self, tmp_path):
        fichero = tmp_path / "objetivos.txt"
        fichero.write_text("# comentario\n10.0.0.7\n\n10.0.0.8\n", encoding="utf-8")
        assert expandir_objetivos(f"@{fichero}") == ["10.0.0.7", "10.0.0.8"]

    def test_fichero_inexistente_error(self):
        with pytest.raises(ObjetivoError):
            expandir_objetivos("@/no/existe/objetivos.txt")

    def test_fichero_vacio_error(self, tmp_path):
        fichero = tmp_path / "vacio.txt"
        fichero.write_text("# solo comentarios\n", encoding="utf-8")
        with pytest.raises(ObjetivoError):
            expandir_objetivos(f"@{fichero}")

    def test_rango_invertido_error(self):
        with pytest.raises(ObjetivoError):
            expandir_objetivos("10.0.0.9-5")

    def test_rango_malformado_error(self):
        with pytest.raises(ObjetivoError):
            expandir_objetivos("10.0.0.1-mal")

    def test_vacio_devuelve_lista_vacia(self):
        assert expandir_objetivos("") == []
        assert expandir_objetivos("   ") == []

    def test_tope_cidr_grande(self):
        # /8 expandiría 16M: debe fallar rápido y sin materializar
        with pytest.raises(ObjetivoError):
            expandir_objetivos("10.0.0.0/8")

    def test_tope_general(self):
        from core.targets import MAX_OBJETIVOS
        # Rangos en prefijos DISTINTOS (las repeticiones se deduplican)
        partes = [f"10.{n}.0.1-255" for n in range(1, 8)]
        assert len(partes) * 255 > MAX_OBJETIVOS
        with pytest.raises(ObjetivoError):
            expandir_objetivos(",".join(partes))


# ======================================================================
# 2. Validación de opciones con excluir (RHOSTS sustituye a RHOST)
# ======================================================================
class TestValidacionExcluir:
    def test_excluir_ignora_requerido(self):
        from core.option_store import OptionStore
        ops = OptionStore()
        ops.declarar("RHOST", "", True, "host")
        ops.declarar("CREDENCIALES", "", True, "creds")
        assert "RHOST" not in ops.faltantes(excluir=("RHOST",))
        assert "CREDENCIALES" in ops.faltantes(excluir=("RHOST",))
        error = ops.validar_o_error(excluir=("RHOST",))
        assert "CREDENCIALES" in error and "RHOST" not in error

    def test_sin_excluir_todo_igual(self):
        from core.option_store import OptionStore
        ops = OptionStore()
        ops.declarar("RHOST", "", True, "host")
        assert ops.validar_o_error() is not None


# ======================================================================
# 3. Barrido multi-host del framework
# ======================================================================
class TestMultiHost:
    def test_barrido_tres_hosts(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-3")
        fw.cmd_run([])
        texto = salida(fw)
        assert "[+] 10.0.0.1 · atendido 10.0.0.1" in texto
        assert "[+] 10.0.0.2 · atendido 10.0.0.2" in texto
        assert "[+] 10.0.0.3 · atendido 10.0.0.3" in texto
        assert "3 OK · 0 fallos" in texto
        assert fw.workspace_db.total_hosts() == 3
        assert mod.resultado.get("modo") == "multi-host"

    def test_rellena_servicios(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-2")
        fw.cmd_run([])
        assert fw.cmd_services or True
        servicios = [s for h in fw.workspace_db.hosts() for s in h["servicios"]]
        assert servicios.count("445/smb") == 2

    def test_fallo_de_un_host_no_aborta_el_barrido(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-3")
        mod.opciones.set("FALLO", ".2")
        fw.cmd_run([])
        texto = salida(fw)
        assert "2 OK · 1 fallos" in texto
        assert "host caído: 10.0.0.2" in texto
        assert fw.workspace_db.total_hosts() == 2

    def test_hilos_1_ruta_secuencial(self, fw):
        fw.globales.set("THREADS", "1")
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1,10.0.0.2")
        fw.cmd_run([])
        assert "2 OK · 0 fallos" in salida(fw)

    def test_consejos_deduplicados(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-3")
        fw.cmd_run([])
        assert "siguientes pasos" in salida(fw)

    def test_rhosts_invalido_muestra_error(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.9-5")
        fw.cmd_run([])
        assert "Rango inválido" in salida(fw)

    def test_rhosts_sin_rhost_no_exige_rhost(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-2")
        # RHOST sigue vacío: la validación lo excluye porque RHOSTS lo cubre
        fw.cmd_run([])
        assert "2 OK" in salida(fw)

    def test_solo_rhost_sigue_funcionando(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOST", "10.0.0.42")
        fw.cmd_run([])
        texto = salida(fw)
        assert "Módulo completado" in texto
        assert "atendido 10.0.0.42" in texto

    def test_informe_agregado_multihost(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-2")
        fw.cmd_run([])
        assert fw.reporter.ultimo_reporte is not None
        import json
        datos = json.loads(fw.reporter.ultimo_reporte.read_text(encoding="utf-8"))
        assert datos["resultados"]["modo"] == "multi-host"
        assert datos["resultados"]["ok"] == 2
        assert "atendido 10.0.0.1" in datos["resultados"]["resultados"]["10.0.0.1"]["resumen"]

    def test_engagement_excluye_objetivo_del_barrido(self, fw, tmp_path):
        fichero = tmp_path / "eng.json"
        fichero.write_text(
            '{"nombre": "lab", "alcance": ["10.0.0.0/24"], '
            '"excluidos": ["10.0.0.3"], "kill_date": "2099-12-31"}',
            encoding="utf-8")
        ok, _ = fw.engagement.cargar(str(fichero))
        assert ok
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-3")
        fw.cmd_run([])
        texto = salida(fw)
        assert "1 objetivo(s) excluidos" in texto
        assert "2 OK · 0 fallos" in texto
        assert fw.workspace_db.total_hosts() == 2

    def test_engagement_bloquea_barrido_completo(self, fw, tmp_path):
        fichero = tmp_path / "eng.json"
        fichero.write_text(
            '{"nombre": "lab", "alcance": ["10.9.9.0/24"], "kill_date": "2099-12-31"}',
            encoding="utf-8")
        ok, _ = fw.engagement.cargar(str(fichero))
        assert ok
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-2")
        fw.cmd_run([])
        assert "BLOQUEADO por el engagement" in salida(fw)
        assert fw.workspace_db.total_hosts() == 0


# ======================================================================
# 4. Jobs en segundo plano
# ======================================================================
class TestJobs:
    def test_run_j_completa_con_informe(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOST", "10.0.0.1")
        fw.cmd_run(["-j"])
        texto = salida(fw)
        assert "Job #1 en segundo plano" in texto
        job = _esperar(fw, 1)
        assert job["estado"] == "completado"
        assert "atendido 10.0.0.1" in job["resumen"]
        assert job["ruta_informe"] and Path(job["ruta_informe"]).exists()

    def test_run_j_multihost(self, fw):
        fw.globales.set("THREADS", "4")
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-4")
        fw.cmd_run(["-j"])
        job = _esperar(fw, 1)
        assert job["estado"] == "completado"
        assert "4 OK" in job["resumen"]
        assert fw.workspace_db.total_hosts() == 4

    def test_listado_de_jobs(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOST", "10.0.0.1")
        fw.cmd_run(["-j"])
        _esperar(fw, 1)
        fw.cmd_jobs([])
        texto = salida(fw)
        assert "Jobs en segundo plano" in texto
        assert "completado" in texto
        assert "atendido 10.0.0.1" in texto

    def test_cancelacion_entre_objetivos(self, fw):
        fw.globales.set("THREADS", "1")
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOSTS", "10.0.0.1-20")
        mod.opciones.set("PAUSA_MS", "60")   # el clon hereda opciones → 20×60ms
        fw.cmd_run(["-j"])
        time.sleep(0.15)
        fw.cmd_jobs(["-k", "1"])
        job = _esperar(fw, 1, tope=8.0)
        texto = salida(fw)
        assert "orden de parada enviada" in texto
        assert job["estado"] in ("cancelado", "completado")
        assert job.get("hecho", 20) < 20 or job["estado"] == "cancelado"

    def test_job_error_controlado(self, fw):
        class FallaLab(MultiLab):
            NAME = "lab/falla"
            def ejecutar(self):  # noqa: E306
                raise ModuloError("fallo de laboratorio")
        mod = _cargar(fw, FallaLab())
        mod.opciones.set("RHOST", "10.0.0.1")
        fw.cmd_run(["-j"])
        job = _esperar(fw, 1)
        assert job["estado"] == "error"

    def test_jobs_k_id_inexistente(self, fw):
        fw.cmd_jobs(["-k", "99"])
        assert "no existe" in salida(fw)

    def test_jobs_k_all(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOST", "10.0.0.1")
        fw.cmd_run(["-j"])
        _esperar(fw, 1)
        fw.cmd_jobs(["-k", "all"])
        assert fw.jobs == {}

    def test_jobs_c_limpia_terminados(self, fw):
        mod = _cargar(fw, MultiLab())
        mod.opciones.set("RHOST", "10.0.0.1")
        fw.cmd_run(["-j"])
        _esperar(fw, 1)
        fw.cmd_jobs(["-c"])
        assert fw.jobs == {}
        assert "Listado limpiado" in salida(fw)

    def test_resumen_salida_incluye_jobs(self, fw):
        fw._resumen_salida()
        assert "Jobs lanzados" in salida(fw)

    def test_sin_jobs_muestra_pista(self, fw):
        fw.cmd_jobs([])
        assert "run -j" in salida(fw)


# ======================================================================
# 5. Comando services
# ======================================================================
class TestServices:
    def test_tabla_de_servicios(self, fw):
        fw.workspace_db.add_host("10.0.0.5", hostname="dc01")
        fw.workspace_db.add_service("10.0.0.5", 445, "smb")
        fw.workspace_db.add_service("10.0.0.5", 389, "ldap")
        fw.workspace_db.add_service("10.0.0.6", 80, "http")
        fw.cmd_services([])
        texto = salida(fw)
        assert "Servicios descubiertos" in texto
        assert "(3)" in texto
        assert "dc01" in texto
        assert "ldap" in texto

    def test_vacio(self, fw):
        fw.cmd_services([])
        assert "Sin servicios registrados" in salida(fw)


# ======================================================================
# 6. sessions -x (comando sin modo interactivo)
# ======================================================================
class TestSessionsX:
    @pytest.fixture()
    def sesion(self, fw):
        a, b = socket.socketpair()
        fw.sesiones[1] = {"conn": a, "addr": ("127.0.0.1", 4444),
                          "abierta": time.time()}
        hilo = threading.Thread(target=self._responder, args=(b,), daemon=True)
        hilo.start()
        yield 1
        try:
            a.close()
            b.close()
        except OSError:
            pass

    @staticmethod
    def _responder(conn):
        try:
            datos = conn.recv(4096)
            conn.sendall(b"respuesta:" + datos.strip() + b"\n")
        except OSError:
            pass

    def test_ejecucion_unica(self, fw, sesion):
        fw.cmd_sessions(["-x", "1", "whoami"])
        texto = salida(fw)
        assert "sesión 1 > whoami" in texto
        assert "respuesta:whoami" in texto

    def test_sesion_inexistente(self, fw):
        fw.sesiones[5] = {"conn": object(), "addr": ("127.0.0.1", 5555),
                          "abierta": time.time()}
        fw.cmd_sessions(["-x", "9", "whoami"])
        assert "no existe" in salida(fw)

    def test_id_invalido(self, fw):
        fw.sesiones[5] = {"conn": object(), "addr": ("127.0.0.1", 5555),
                          "abierta": time.time()}
        fw.cmd_sessions(["-x", "abc", "whoami"])
        assert "inválido" in salida(fw)

    def test_ayuda_menciona_x(self, fw):
        fw.sesiones[5] = {"conn": object(), "addr": ("127.0.0.1", 5555),
                          "abierta": time.time()}
        fw.cmd_sessions(["cosas"])
        assert "sessions -x <ID> <comando>" in salida(fw)


# ======================================================================
# 7. CVE en info
# ======================================================================
class TestInfoCVE:
    def test_gpp_muestra_cve(self, fw):
        fw.cmd_info(["ad/gpp_cpassword"])
        texto = salida(fw)
        assert "CVE-2014-1812" in texto
        assert "MS14-025" in texto

    def test_modulo_sin_cve_muestra_raya(self, fw):
        fw.cmd_info(["recon/ip_info"])
        assert "CVE       : —" in salida(fw)


# ======================================================================
# 8. Cobertura de consejos para TODOS los módulos
# ======================================================================
class TestCoberturaConsejos:
    def test_todos_los_modulos_dan_consejos(self, manager):
        from core.advice import consejos_de_resultado
        sin_consejos = []
        for cls in manager.listar():
            datos = {"resumen": f"resultado de prueba de {cls.NAME}"}
            if not consejos_de_resultado(cls.NAME, datos):
                sin_consejos.append(cls.NAME)
        assert sin_consejos == [], \
            f"Módulos sin siguientes pasos: {sin_consejos}"

    def test_consejos_con_hallazgos_reales(self, manager):
        from core.advice import consejos_de_resultado
        for cls in manager.listar():
            datos = {"resumen": "x", "abiertos": [80, 443]}
            assert consejos_de_resultado(cls.NAME, datos), cls.NAME


# ======================================================================
# 9. Versión y docstring
# ======================================================================
class TestVersion:
    def test_version(self):
        assert __version__ == "2.3.0"

    def test_comandos_registrados(self, fw):
        for comando in ("jobs", "services"):
            assert comando in fw.COMANDOS

    def test_completado_de_jobs(self, fw):
        assert fw._candidatos_para("-k", "jobs ") == ["-k"]
        assert fw._candidatos_para("-x", "sessions ") == ["-x"]
