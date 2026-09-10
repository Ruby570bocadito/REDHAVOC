# -*- coding: utf-8 -*-
"""v1.6.0: motor de consejos (siguientes pasos), comando `consejos`,
estilo profesional y smoke de TODOS los módulos (cada uno debe producir
resultados o fallar LIMPIO, sin excepciones inesperadas)."""
import socket
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.advice import Consejo, consejos_de_resultado, plan_de_workspace  # noqa: E402
from core.base_module import ModuloError  # noqa: E402
from core.colors import console  # noqa: E402
from core.render import mostrar_consejos, mostrar_plan  # noqa: E402
from core.workspace_db import WorkspaceDB  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent


class _Cap:
    """Consola Rich de prueba que escribe a un buffer."""

    def __init__(self):
        from rich.console import Console
        import io
        self.file = io.StringIO()
        self.c = Console(file=self.file, force_terminal=False,
                         width=120, theme=None, highlight=False)

    def __getattr__(self, nombre):
        return getattr(self.c, nombre)


# ----------------------------------------------------------------------
# Motor de consejos: reglas por módulo
# ----------------------------------------------------------------------
def test_puerto_445_sugiere_cadena_ad():
    datos = {"resumen": "ok", "abiertos": [
        {"puerto": 135, "servicio": "rpc"},
        {"puerto": 445, "servicio": "smb"},
    ]}
    consejos = consejos_de_resultado("recon/port_scanner", datos)
    texto = " ".join(c.texto.lower() for c in consejos)
    comandos = [c.comando for c in consejos]
    assert "smb" in texto
    assert "use ad/smb_check" in comandos
    assert any(c.comando == "hosts" for c in consejos)


def test_puerto_88_y_389_sugieren_kerberos_ldap():
    datos = {"abiertos": [{"puerto": 88, "servicio": "kerberos"},
                          {"puerto": 389, "servicio": "ldap"}]}
    comandos = [c.comando for c in consejos_de_resultado("recon/port_scanner", datos)]
    assert "use ad/kerberos_userenum" in comandos
    assert "use ad/ldap_enum" in comandos


def test_puerto_web_sugiere_tech_detect():
    datos = {"abiertos": [{"puerto": 8080, "servicio": "http"}]}
    comandos = [c.comando for c in consejos_de_resultado("recon/port_scanner", datos)]
    assert "use web/tech_detect" in comandos


def test_port_scanner_sin_abiertos_da_alternativa():
    consejos = consejos_de_resultado("recon/port_scanner", {"abiertos": []})
    assert consejos and all(isinstance(c, Consejo) for c in consejos)


def test_spn_enum_sugiere_kerberoast():
    datos = {"cuentas": [{"cuenta": "svc_sql", "spn": "MSSQL/DC"}]}
    comandos = [c.comando for c in consejos_de_resultado("ad/spn_enum", datos)]
    assert "use ad/kerberoast" in comandos


def test_kerberoast_con_hashes_sugiere_crack():
    datos = {"hashes": ["$krb5tgs$23$*u$r$*abc*def"], "crackeados": []}
    consejos = consejos_de_resultado("ad/kerberoast", datos)
    assert any(c.comando == "use ad/kerberoast" and "crack" in c.texto.lower()
               for c in consejos)
    assert any(c.comando == "use ad/smb_login" for c in consejos)


def test_kerberos_userenum_sugiere_asrep_y_spray():
    datos = {"validos": ["labadmin"], "inexistentes": ["nope"]}
    comandos = [c.comando for c in consejos_de_resultado("ad/kerberos_userenum", datos)]
    assert "use ad/asreproast" in comandos
    assert "use ad/passwd_spray" in comandos


def test_smb_login_validas_sugiere_shares():
    datos = {"validas": [{"usuario": "labadmin", "clave": "x"}]}
    comandos = [c.comando for c in consejos_de_resultado("ad/smb_login", datos)]
    assert "use ad/smb_share_enum" in comandos


def test_jwt_secreto_roto_sugiere_lab():
    datos = {"secreto_roto": "clave123", "hallazgos": [{"severidad": "critico"}]}
    texto = " ".join(c.texto.lower() for c in consejos_de_resultado("web/jwt_analyzer", datos))
    assert "laboratorio" in texto


def test_bloque_smb_share_enum_legibles():
    datos = {"shares": [{"nombre": "SYSVOL", "estado": "LEGIBLE"},
                        {"nombre": "IPC$", "estado": "ACCESIBLE"}]}
    texto = " ".join(c.texto.lower() for c in consejos_de_resultado("ad/smb_share_enum", datos))
    assert "sysvol" in texto


def test_opsec_fuga_sugiere_corregir():
    datos = {"fuga_detectada": True}
    texto = " ".join(c.texto.lower() for c in consejos_de_resultado("opsec/proxy_check", datos))
    assert "fuga" in texto


# ----------------------------------------------------------------------
# Motor de consejos: fallbacks y robustez
# ----------------------------------------------------------------------
def test_sin_hallazgos_sugiere_ampliar():
    # post/host_audit sin ficheros → regla no dispara → fallback general
    consejos = consejos_de_resultado("post/host_audit", {})
    assert any(c.comando == "use osint/cert_transparency" for c in consejos)
    # dns_enum SIEMPRE sugiere AXFR y SPF (reglas propias del módulo)
    dns = consejos_de_resultado("recon/dns_enum", {"resolver": []})
    assert any(c.comando == "use osint/zone_transfer" for c in dns)


def test_con_datos_genericos_menciona_informe():
    consejos = consejos_de_resultado("web/whatever", {"cosas": [1, 2, 3]})
    assert any("informe" in c.texto.lower() for c in consejos)


def test_maximo_cuatro_consejos():
    datos = {"abiertos": [{"puerto": p, "servicio": "x"} for p in
                          (21, 22, 80, 445, 88, 389, 3306)]}
    assert len(consejos_de_resultado("recon/port_scanner", datos)) <= 4


@pytest.mark.parametrize("malos", [None, {}, {"abiertos": "rarooo"},
                                   {"abiertos": [None, 3, {"puerto": "x"}]},
                                   {"cuentas": {"dict": "no lista"}}])
def test_datos_raros_no_rompen(malos):
    for nombre in ("recon/port_scanner", "ad/spn_enum", "modulo/inexistente"):
        assert isinstance(consejos_de_resultado(nombre, malos), list)


# ----------------------------------------------------------------------
# Plan de batalla del workspace
# ----------------------------------------------------------------------
def test_plan_workspace_vacio_arranca_recon(tmp_path):
    plan = plan_de_workspace(WorkspaceDB(tmp_path))
    assert any(c.comando == "use recon/ip_info" for c in plan)


def test_plan_workspace_smb(tmp_path):
    db = WorkspaceDB(tmp_path)
    db.add_host("10.0.0.5")
    db.add_service("10.0.0.5", 445, "smb")
    plan = plan_de_workspace(db)
    assert any(c.comando == "use ad/smb_check" for c in plan)


def test_plan_workspace_creds_y_vulns(tmp_path):
    db = WorkspaceDB(tmp_path)
    db.add_cred("10.0.0.5", "labadmin", "x", "smb")
    db.add_vuln("10.0.0.5", "SMB sin firma", "critico")
    plan = plan_de_workspace(db)
    texto = " ".join(c.texto.lower() for c in plan)
    assert "credenciales" in texto
    assert "prioriza" in texto


def test_plan_workspace_tolerante_a_none():
    assert plan_de_workspace(None)  # nunca explota


# ----------------------------------------------------------------------
# Render de consejos y comando `consejos`
# ----------------------------------------------------------------------
def test_render_siguientes_pasos():
    cap = _Cap()
    mostrar_consejos("recon/port_scanner",
                     {"abiertos": [{"puerto": 445, "servicio": "smb"}]}, cap)
    texto = cap.file.getvalue()
    assert "siguientes pasos" in texto
    assert "use ad/smb_check" in texto


def test_render_plan_de_batalla(tmp_path):
    cap = _Cap()
    mostrar_plan(cap, WorkspaceDB(tmp_path))
    assert "plan de batalla" in cap.file.getvalue()


def test_comando_consejos_registrado(tmp_path, monkeypatch):
    from core import ethics
    from core.framework import RedHavocFramework

    monkeypatch.setattr(ethics.EthicsGate, "autorizado", staticmethod(lambda: True))
    fw = RedHavocFramework(tmp_path)
    assert "consejos" in fw.COMANDOS
    fw._procesar("consejos")            # no debe lanzar
    fw._procesar("help")


# ----------------------------------------------------------------------
# Metadata sana de TODOS los módulos
# ----------------------------------------------------------------------
def test_metadata_sana_todos(manager):
    assert manager.total_modulos() >= 58
    for cls in manager.listar():
        partes = cls.NAME.split("/")
        assert len(partes) == 2, f"NAME mal formado: {cls.NAME}"
        assert cls.CATEGORIA == partes[0], cls.NAME
        assert cls.RIESGO in ("bajo", "medio", "alto"), cls.NAME
        assert cls.DESCRIPCION.strip(), f"{cls.NAME} sin descripción"
        assert all(isinstance(t, str) and t.strip() for t in cls.ATTCK), cls.NAME
        instancia = cls()
        for o in instancia.opciones:
            assert o.descripcion.strip(), f"{cls.NAME}:{o.nombre} sin descripción"


# ----------------------------------------------------------------------
# Smoke de TODOS los módulos: cada uno devuelve dict o falla LIMPIO
# ----------------------------------------------------------------------
VALORES_SEGUROS = {
    "TARGET": "127.0.0.1",
    "URL": "http://127.0.0.1:9/",
    "DOMAIN": "no-such.invalid",
    "RHOST": "127.0.0.1",
    "HOST": "127.0.0.1",
    "CIDR": "127.0.0.1/32",
    "BASE_DN": "DC=lab,DC=local",
    "REINO": "LAB.LOCAL",
    "USUARIO": "labadmin",
    "PASSWORD": "Clave-Lab-123",
    "CLAVE": "Clave-Lab-123",
    "USUARIOS": "labadmin,invitado",
    "CLAVES": "P@ssw0rd1,Clave-Lab-123",
    "CREDENCIALES": "labadmin:Clave-Lab-123",
    "ALIAS": "usuario_lab",
    "CORREOS": "prueba@no-such.invalid",
    "URLS": "http://127.0.0.1:9/doc.docx",
    "TO": "prueba@no-such.invalid",
    "SMTP_HOST": "127.0.0.1",
    "TIMEOUT": "1",
    "THREADS": "5",
    "DURACION": "1",
    "ESPERA": "1",
    "PUERTOS": "9",
    "RPS": "1",
    "HILOS": "2",
}


def _preparar(cls):
    """Instancia el módulo con opciones seguras (objetivos inertes y esperas mínimas).

    Los knobs de tiempo (DURACION/ESPERA/TIMEOUT/...) se fuerzan SIEMPRE:
    algunos tienen por defecto '0 = hasta Ctrl+C' y colgarían el smoke.
    """
    inst = cls()
    for o in inst.opciones:
        if o.nombre in VALORES_SEGUROS:
            inst.opciones.set(o.nombre, VALORES_SEGUROS[o.nombre])
    return inst


def _sin_red(*_a, **_k):
    """Sustituto de requests.get/Session.get para el smoke: cero tráfico real."""
    raise requests.exceptions.ConnectionError("smoke aislado de la red")


def test_todos_los_modulos_ejecutan_o_fallan_limpio(manager, monkeypatch):
    """LA PRUEBA CENTRAL: ejecuta los 58 módulos contra objetivos inertes.

    Cada módulo debe devolver un dict de resultados o lanzar ModuloError
    (fallo controlado). Cualquier otra excepción = BUG.
    """
    # Aislamiento: ningún test debe hablar con internet (ni filtrar actividad
    # de laboratorio a plataformas reales como t.me/github/crt.sh).
    monkeypatch.setattr(requests, "get", _sin_red)
    monkeypatch.setattr(requests.Session, "get", _sin_red)
    fallos = []
    for cls in manager.listar():
        print(f"[smoke] {cls.NAME}", flush=True)
        inst = _preparar(cls)
        try:
            resultado = inst.ejecutar()
            assert isinstance(resultado, dict), f"{cls.NAME} devolvió {type(resultado)}"
        except ModuloError:
            pass  # fallo controlado: aceptable (host inexistente, ssh ausente...)
        except Exception as err:  # noqa: BLE001
            fallos.append(f"{cls.NAME}: {type(err).__name__}: {err}")
    assert not fallos, "Módulos con excepciones inesperadas:\n" + "\n".join(fallos)


def test_todos_los_modulos_consejos_no_explotan(manager, monkeypatch):
    """El motor de consejos produce sugerencias para lo que devuelva cada módulo."""
    monkeypatch.setattr(requests, "get", _sin_red)
    monkeypatch.setattr(requests.Session, "get", _sin_red)
    for cls in manager.listar():
        inst = _preparar(cls)
        try:
            datos = inst.ejecutar()
        except Exception:  # noqa: BLE001 — aunque el módulo falle, los consejos existen
            datos = {}
        consejos = consejos_de_resultado(cls.NAME, datos or {})
        assert isinstance(consejos, list) and consejos, cls.NAME
        assert all(c.texto.strip() for c in consejos), cls.NAME


# ----------------------------------------------------------------------
# E2E: run con resultado → panel de resultados + panel de siguientes pasos
# ----------------------------------------------------------------------
def test_e2e_run_muestra_resultados_y_consejos(tmp_path, monkeypatch):
    """port_scanner contra un puerto local vivo → tabla + siguientes pasos + informe."""
    from core import ethics
    from core.framework import RedHavocFramework

    # Servidor de lab real en un puerto efímero (garantiza 1 puerto abierto)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    puerto = srv.getsockname()[1]

    try:
        monkeypatch.setattr(ethics.EthicsGate, "autorizado", staticmethod(lambda: True))
        fw = RedHavocFramework(tmp_path)
        fw._procesar("use recon/port_scanner")
        fw._procesar(f"set TARGET 127.0.0.1")
        fw._procesar(f"set PORTS {puerto}")
        fw._procesar("set TIMEOUT 2")
        fw._procesar("run")
        assert fw.modulo_actual is not None

        # El host quedó en el workspace → el comando consejos da la cadena
        assert fw.workspace_db.total_hosts() == 1
        fw._procesar("consejos")

        # Informe triple generado
        jsons = list((tmp_path / "output").glob("*.json"))
        assert jsons, "No se generó informe JSON"
    finally:
        srv.close()
