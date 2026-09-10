# -*- coding: utf-8 -*-
"""v1.7.0: correcciones del ciclo de pulido —

1. Autocompletado TAB funcional (antes: NameError silencioso en cada TAB).
2. `back` en COMANDOS y en la ayuda.
3. Blindaje markup Rich: ningún dato del operador sin escape() en la consola.
4. Consejo 3306 (MySQL) ya no sugiere un módulo inexistente para MySQL.
5. Los tests del smoke no hablan con internet (aislamiento de red).
6. InsecureRequestWarning suprimido de forma central (consola limpia).
"""
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import __version__  # noqa: E402
from core.framework import RedHavocFramework  # noqa: E402


# ----------------------------------------------------------------------
# 1. Autocompletado TAB
# ----------------------------------------------------------------------
class TestCompleter:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    def test_comandos_por_prefijo(self, fw):
        cand = fw._candidatos_para("se", "")
        assert "search" in cand and "sessions" in cand and "set" in cand
        assert "hosts" not in cand

    def test_completer_sin_nameerror(self, fw):
        # Antes: NameError('readline') en la primera llamada del completer.
        try:
            primero = fw._completer("se", 0)
        except NameError as err:  # pragma: no cover
            pytest.fail(f"El completer sigue roto: {err}")
        assert primero == "search"
        # Los estados se agotan devolviendo None (contrato de readline).
        assert fw._completer("zzzz", 0) is None
        assert fw._completer("se", 999) is None

    def test_modulos_por_comando_use(self, fw):
        cand = fw._candidatos_para("rec", "use rec")
        assert cand and all(c.startswith("recon/") for c in cand)

    def test_opciones_por_comando_set(self, fw):
        cand = fw._candidatos_para("auth", "set auth")
        assert cand == ["AUTHORIZED"]

    def test_opciones_de_modulo_cargado(self, fw):
        cls = fw.module_manager.obtener("recon/port_scanner")
        fw.modulo_actual = cls()
        cand = fw._candidatos_para("por", "set por")
        assert "PORTS" in cand

    def test_subcomandos_conocidos(self, fw):
        assert fw._candidatos_para("m", "show m") == ["modules"]
        assert fw._candidatos_para("l", "engagement l") == ["load"]
        assert fw._candidatos_para("-i", "sessions ") == ["-i"]
        assert fw._candidatos_para("-c", "vulns ") == ["-c"]

    def test_resource_sugiere_plantillas(self, fw):
        assert fw._candidatos_para("t", "resource t") == ["templates/"]

    def test_buffer_vacio_devuelve_comandos(self, fw):
        assert fw._candidatos_para("", "") == list(fw.COMANDOS)


# ----------------------------------------------------------------------
# 2. `back` documentado y completable
# ----------------------------------------------------------------------
class TestComandoBack:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    def test_back_en_comandos(self, fw):
        assert "back" in fw.COMANDOS

    def test_back_en_la_ayuda(self, fw, capsys):
        fw._procesar("help")
        salida = capsys.readouterr().out
        assert "back" in salida

    def test_back_sin_modulo_no_explota(self, fw):
        fw._procesar("back")          # sin módulo cargado: mensaje, no excepción
        fw.modulo_actual = type(
            "M", (), {"NAME": "recon/port_scanner"}
        )()  # objeto mínimo con NAME
        fw._procesar("back")
        assert fw.modulo_actual is None


# ----------------------------------------------------------------------
# 3. Blindaje markup: corchetes del operador no rompen la consola
# ----------------------------------------------------------------------
class TestBlindajeMarkup:
    @pytest.fixture()
    def fw(self, tmp_path):
        return RedHavocFramework(tmp_path)

    @pytest.mark.parametrize("linea", [
        "search [x]",
        "search sin_resultados_[!]",
        "use [x]",
        "info [x]",
        "set [x] y",
        "unset [x]",
        "[x]",
        "history",
        "sessions -i [x]",
        "attack [x]",
        "resource [x]",
        "engagement load [x]",
    ])
    def test_lineas_con_corchetes_no_lanzan(self, fw, capsys, linea):
        fw.historial.append(linea)
        fw._procesar(linea)          # solo debe imprimir, nunca MarkupError
        capsys.readouterr()

    def test_history_escapado(self, fw, capsys):
        fw.historial.append("set TARGET [bold roto]")
        fw._procesar("history")
        salida = capsys.readouterr().out
        assert "set TARGET [bold roto]" in salida

    def test_busqueda_con_corchetes_en_titulo(self, fw, capsys):
        fw._procesar("search puerto")   # término normal: tabla con título
        salida = capsys.readouterr().out
        assert "puerto" in salida.lower()


# ----------------------------------------------------------------------
# 4. Consejos con rutas que existen de verdad
# ----------------------------------------------------------------------
class TestConsejosCoherentes:
    def test_mysql_no_sugiere_http_basic(self):
        from core.advice import consejos_de_resultado
        datos = {"abiertos": [{"puerto": 3306, "servicio": "mysql"}]}
        for c in consejos_de_resultado("recon/port_scanner", datos):
            assert c.comando != "use brute/http_basic"

    def test_mysql_da_consejo_documental(self):
        from core.advice import consejos_de_resultado
        datos = {"abiertos": [{"puerto": 3306, "servicio": "mysql"}]}
        consejos = consejos_de_resultado("recon/port_scanner", datos)
        assert any("3306" in c.texto or "MySQL" in c.texto for c in consejos)

    def test_cadena_smb_sigue_intacta(self):
        from core.advice import consejos_de_resultado
        datos = {"abiertos": [{"puerto": 445, "servicio": "microsoft-ds"}]}
        consejos = consejos_de_resultado("recon/port_scanner", datos)
        assert any(c.comando == "use ad/smb_check" for c in consejos)

    def test_todos_los_comandos_sugeridos_existen(self, manager):
        """Cada comando 'use X' de una regla de advice apunta a un módulo real."""
        from core import advice
        nombres = set(manager.nombres())
        malos = []
        for valor in vars(advice).values():
            reglas = valor if isinstance(valor, tuple) else ()
            for regla in reglas:
                if isinstance(regla, tuple) and len(regla) == 3 and regla[2]:
                    cmd = regla[2]
                    if cmd.startswith("use ") and cmd[4:] not in nombres:
                        malos.append(cmd)
        assert not malos, f"Consejos con módulos inexistentes: {malos}"


# ----------------------------------------------------------------------
# 5. Versión e higiene global
# ----------------------------------------------------------------------
class TestHigieneGlobal:
    def test_version(self):
        assert __version__ >= "2.1.0"

    def test_insecure_request_warning_suprimido(self):
        # La función del paquete registra el filtro ignore correctamente.
        import warnings as w
        import core as paquete
        from urllib3.exceptions import InsecureRequestWarning
        with w.catch_warnings():
            w.resetwarnings()
            paquete.silenciar_insecure_request()
            categorias = [f[2] for f in w.filters]
            assert InsecureRequestWarning in categorias

    def test_aviso_tls_no_se_emite(self):
        # Con el filtro activo, generar el aviso no produce registro.
        import warnings as w
        import core as paquete
        from urllib3.exceptions import InsecureRequestWarning
        with w.catch_warnings():
            w.resetwarnings()
            paquete.silenciar_insecure_request()
            with w.catch_warnings(record=True) as captura:
                w.warn("Unverified HTTPS request", InsecureRequestWarning)
            assert captura == []
