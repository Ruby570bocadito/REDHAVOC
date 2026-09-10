# -*- coding: utf-8 -*-
"""v1.9.0: continuar mejorando · optimizando · puliendo —

1. `notes` — cuaderno libre del operador persistido en el workspace
   (add / listar / -c selectivo / persistencia entre instancias).
2. `export json|csv|md` — export del workspace a output/ con escape CSV
   correcto y Markdown listo para el informe.
3. `audit [N]` — traza de auditoría ética visible en consola.
4. Historial persistente entre sesiones + `history -c` + resumen de
   operación al salir (exit).
5. Validación amable de opciones numéricas en `set` (THREADS/TIMEOUT).
6. `search` con filtros cat:<categoría> y riesgo:<nivel>.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.framework import RedHavocFramework  # noqa: E402
from core.workspace_db import WorkspaceDB  # noqa: E402


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


import io  # noqa: E402  (tras _Cap para mantener el patrón del resto de suites)


@pytest.fixture()
def fw(tmp_path, monkeypatch):
    """Framework con raíz temporal (aislado del workspace real)."""
    monkeypatch.setattr("core.colors.console", _Cap().c)
    marco = RedHavocFramework(tmp_path)
    marco.console_cap = _Cap()
    # Redirige la consola global usada por el framework a la de captura
    monkeypatch.setattr("core.framework.console", marco.console_cap.c)
    return marco


def salida(marco) -> str:
    return marco.console_cap.file.getvalue()


# ----------------------------------------------------------------------
# 1. Notas del operador
# ----------------------------------------------------------------------
class TestNotas:
    def test_add_y_listar(self, fw):
        fw.cmd_notes(["add", "DMZ", "con", "red", "plana"])
        fw.cmd_notes([])
        assert "DMZ con red plana" in salida(fw)
        assert "Notas del operador" in salida(fw)

    def test_add_vacio_muestra_uso(self, fw):
        fw.cmd_notes(["add"])
        assert "Uso" in salida(fw)

    def test_persistencia(self, tmp_path):
        a = WorkspaceDB(tmp_path)
        a.add_nota("nota de sesión 1")
        b = WorkspaceDB(tmp_path)
        assert b.notas()[0]["texto"] == "nota de sesión 1"

    def test_limpiar_selectivo(self, fw):
        fw.workspace_db.add_nota("temporal")
        fw.workspace_db.add_host("10.0.0.9")
        fw.cmd_notes(["-c"])
        assert fw.workspace_db.notas() == []
        assert fw.workspace_db.total_hosts() == 1  # lo demás se conserva

    def test_total_y_resumen(self, fw):
        fw.workspace_db.add_nota("cuenta")
        assert fw.workspace_db.total_notas() == 1
        assert "1 notas" in fw.workspace_db.resumen()

    def test_subcomando_desconocido(self, fw):
        fw.cmd_notes(["frobnicate"])
        assert "Uso" in salida(fw)


# ----------------------------------------------------------------------
# 2. Export del workspace
# ----------------------------------------------------------------------
class TestExport:
    @pytest.fixture()
    def poblado(self, fw):
        fw.workspace_db.add_host("10.0.0.5", hostname="dc01")
        fw.workspace_db.add_service("10.0.0.5", 445, "smb")
        fw.workspace_db.add_cred("10.0.0.5", "CORP\\admin", "P@ss,123", "SMB")
        fw.workspace_db.add_vuln("10.0.0.5", "SMBv1", "alto")
        fw.workspace_db.add_nota("revisar segmentación")
        return fw

    def test_formato_invalido(self, fw):
        fw.cmd_export(["xlsx"])
        assert "Uso" in salida(fw)

    def test_workspace_vacio(self, fw):
        fw.cmd_export(["json"])
        assert "vacío" in salida(fw)

    def test_export_json(self, poblado):
        poblado.cmd_export(["json"])
        ruta = list(Path(poblado.reporter.carpeta).glob("export_*.json"))[0]
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        assert datos["framework"] == "REDHAVOC"
        assert len(datos["hosts"]) == 1
        assert datos["creds"][0]["secreto"] == "P@ss,123"
        assert len(datos["notas"]) == 1

    def test_export_csv_escape(self, poblado):
        poblado.cmd_export(["csv"])
        rutas = sorted(Path(poblado.reporter.carpeta).glob("export_*_*.csv"))
        assert rutas, "debe escribir al menos un CSV"
        csv_creds = [r for r in rutas if "creds" in r.name][0]
        contenido = csv_creds.read_text(encoding="utf-8")
        # la coma del secreto exige comillas
        assert '"P@ss,123"' in contenido

    def test_export_md(self, poblado):
        poblado.cmd_export(["md"])
        ruta = list(Path(poblado.reporter.carpeta).glob("export_*.md"))[0]
        texto = ruta.read_text(encoding="utf-8")
        assert "# REDHAVOC — Export del workspace" in texto
        assert "dc01" in texto
        assert "revisar segmentación" in texto
        assert texto.count("## ") >= 4  # hosts, creds, vulns, notas

    def test_celda_csv_listas(self, fw):
        celda = fw._celda_csv(["445/smb", "80/http"])
        assert celda == "445/smb; 80/http"
        celda2 = fw._celda_csv({'a': 1})
        assert celda2.startswith('"')   # dict serializado y citado
        assert "a" in celda2 and "1" in celda2


# ----------------------------------------------------------------------
# 3. Traza de auditoría
# ----------------------------------------------------------------------
class TestAudit:
    def test_sin_eventos(self, fw):
        fw.cmd_audit([])
        assert "Sin eventos" in salida(fw)

    def test_con_eventos(self, fw):
        fw.ethics.auditar("RUN", "recon/port_scanner -> 10.0.0.5 (1.2s)")
        fw.ethics.auditar("BLOQUEO_RIESGO_ALTO", "dos/stress_http")
        fw.cmd_audit([])
        texto = salida(fw)
        assert "Traza de auditoría" in texto
        assert "RUN" in texto
        assert "BLOQUEO_RIESGO_ALTO" in texto

    def test_limite_n(self, fw):
        for i in range(30):
            fw.ethics.auditar("RUN", f"op-{i}")
        fw.cmd_audit(["5"])
        texto = salida(fw)
        assert "op-29" in texto
        assert "op-20" not in texto

    def test_arg_invalido(self, fw):
        fw.cmd_audit(["abc"])
        assert "Uso" in salida(fw)


# ----------------------------------------------------------------------
# 4. Historial persistente y resumen de salida
# ----------------------------------------------------------------------
class TestHistorialYSalida:
    def test_historial_guarda_y_recarga(self, tmp_path):
        a = RedHavocFramework(tmp_path)
        a.historial = ["search smb", "use ad/smb_check"]
        a._guardar_historial()
        b = RedHavocFramework(tmp_path)
        assert b.historial[-2:] == ["search smb", "use ad/smb_check"]

    def test_history_c(self, fw):
        fw.historial = ["algo"]
        fw.cmd_history(["-c"])
        assert fw.historial == []
        assert not fw._ruta_historial.exists() or \
            fw._ruta_historial.read_text(encoding="utf-8") == ""

    def test_exit_guarda_historial_y_resumen(self, fw):
        fw.historial = ["search ad"]
        fw.workspace_db.add_host("10.0.0.5")
        fw.workspace_db.add_nota("pendiente revisar")
        with pytest.raises(SystemExit):
            fw.cmd_exit([])
        texto = salida(fw)
        assert "resumen de la operación" in texto
        assert "Informes generados" in texto
        assert "Notas del operador" in texto
        recargado = RedHavocFramework(fw.raiz)
        assert "search ad" in recargado.historial

    def test_exit_cierra_sesiones(self, fw):
        class _FalsoConn:
            cerrado = False

            def close(self):
                self.cerrado = True
        conn = _FalsoConn()
        fw.sesiones[1] = {"conn": conn, "addr": ("10.0.0.5", 4444), "abierta": 0}
        with pytest.raises(SystemExit):
            fw.cmd_exit([])
        assert conn.cerrado
        assert fw.sesiones == {}


# ----------------------------------------------------------------------
# 5. Validación numérica en set
# ----------------------------------------------------------------------
class TestValidacionNumerica:
    def test_threads_no_numerico_rechazado(self, fw):
        fw.cmd_set(["THREADS", "muchos"], solo_global=True)
        assert "entero positivo" in salida(fw)
        assert fw.globales.get("THREADS") == "10"  # default intacto

    def test_timeout_negativo_rechazado(self, fw):
        fw.cmd_set(["TIMEOUT", "-3"], solo_global=True)
        assert "entero positivo" in salida(fw)

    def test_threads_valido_aceptado(self, fw):
        fw.cmd_set(["THREADS", "32"], solo_global=True)
        assert "32" in salida(fw)
        assert fw.globales.get("THREADS") == "32"

    def test_otras_opciones_no_afectadas(self, fw):
        fw.cmd_set(["AUTHORIZED", "true"], solo_global=True)
        assert fw.globales.get_bool("AUTHORIZED") is True


# ----------------------------------------------------------------------
# 6. Filtros de search
# ----------------------------------------------------------------------
class TestSearchFiltros:
    def test_parse_filtros_mixto(self):
        texto, filtros = RedHavocFramework._parse_filtros(
            ["smb", "cat:ad", "riesgo:medio"])
        assert texto == "smb"
        assert filtros == {"cat": "ad", "riesgo": "medio"}

    def test_parse_filtros_solo_texto(self):
        texto, filtros = RedHavocFramework._parse_filtros(["puerto", "80"])
        assert texto == "puerto 80"
        assert filtros == {}

    def test_search_por_categoria(self, fw):
        fw.cmd_search(["cat:ad"])
        texto = salida(fw)
        assert "Módulos que coinciden" in texto
        assert "cat=ad" in texto
        # todo el listado es de la categoría ad
        assert "ad/" in texto

    def test_search_por_riesgo(self, fw):
        fw.cmd_search(["riesgo:alto"])
        texto = salida(fw)
        assert "riesgo=alto" in texto
        assert fw._ultima_busqueda, "debe guardar la búsqueda para use <n>"

    def test_search_sin_resultados_con_filtros(self, fw):
        fw.cmd_search(["cat:categoria_inexistente_xyz"])
        assert "Sin resultados" in salida(fw)

    def test_filtros_usan_categorias_reales(self, fw):
        """cat:web solo devuelve módulos cuya categoría ES web."""
        fw.cmd_search(["cat:web"])
        for cls in fw._ultima_busqueda:
            assert cls.CATEGORIA == "web"
