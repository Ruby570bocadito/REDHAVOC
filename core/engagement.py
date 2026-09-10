# -*- coding: utf-8 -*-
"""
core.engagement
===============
Gestión de engagement estilo suite red team: un fichero JSON central con el
alcance autorizado (domains, IPs, CIDRs), fecha de caducidad (kill-date) y
regla de exclusión. El framework lo consulta ANTES de ejecutar cualquier
módulo: si el objetivo queda fuera del alcance o el engagement está vencido,
la ejecución se bloquea con un motivo claro.

Fichero de ejemplo en templates/engagement_ejemplo.json. Comandos REPL:

    engagement              Estado del engagement cargado
    engagement load <fich>  Cargar (o recargar) un engagement
    engagement clear        Descartar el engagement activo
"""

import ipaddress
import json
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional, Tuple

# Opciones que el framework considera "objetivo" a la hora de verificar scope
NOMBRES_OBJETIVO = ("TARGET", "URL", "DOMAIN", "HOST", "RHOST", "CIDR")


def extraer_host(valor: str) -> str:
    """Extrae el host de una URL, IP:puerto, host o CIDR arbitrario."""
    valor = (valor or "").strip()
    for prefijo in ("https://", "http://"):
        if valor.lower().startswith(prefijo):
            valor = valor[len(prefijo):]
    valor = valor.split("/")[0]
    if "@" in valor:                      # usuario@host
        valor = valor.split("@")[-1]
    # IPv6 con corchetes
    if valor.startswith("[") and "]" in valor:
        return valor[1:valor.index("]")]
    if valor.count(":") == 1:             # host:puerto (IPv4 o nombre)
        valor = valor.split(":")[0]
    return valor


class Engagement:
    """Estado del engagement (scope + kill-date) persistido en el workspace."""

    RUTA = "engagement.json"

    def __init__(self, carpeta_workspace: Path) -> None:
        self.carpeta = Path(carpeta_workspace)
        self.carpeta.mkdir(parents=True, exist_ok=True)
        self.ruta = self.carpeta / self.RUTA
        self.datos: dict = {}
        self._cargar()

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def _cargar(self) -> None:
        if self.ruta.exists():
            try:
                datos = json.loads(self.ruta.read_text(encoding="utf-8"))
                if isinstance(datos, dict) and datos.get("nombre"):
                    self.datos = datos
            except (json.JSONDecodeError, OSError):
                self.datos = {}

    def _guardar(self) -> None:
        try:
            if self.datos:
                self.ruta.write_text(json.dumps(self.datos, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
            elif self.ruta.exists():
                self.ruta.unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Carga y validación
    # ------------------------------------------------------------------
    def cargar(self, fichero: str) -> Tuple[bool, List[str]]:
        """Carga un engagement desde fichero JSON. Devuelve (ok, avisos)."""
        avisos: List[str] = []
        ruta = Path(fichero)
        if not ruta.exists():
            return False, [f"El fichero {fichero} no existe"]
        try:
            datos = json.loads(ruta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as err:
            return False, [f"JSON inválido: {err}"]
        if not isinstance(datos, dict) or not str(datos.get("nombre", "")).strip():
            return False, ["El engagement necesita al menos un campo 'nombre'"]

        datos.setdefault("alcance", [])
        datos.setdefault("excluidos", [])
        datos.setdefault("permitir_fuera_alcance", False)
        datos.setdefault("cliente", "")
        datos.setdefault("kill_date", "")
        datos.setdefault("notas", "")

        if not datos["alcance"]:
            avisos.append("El alcance está vacío: NO se bloqueará ningún objetivo "
                          "hasta que definas 'alcance'")
        if not self._parsear_fecha(str(datos["kill_date"])):
            avisos.append("kill_date vacío o con formato incorrecto (usa AAAA-MM-DD): "
                          "se considerará el engagement SIEMPRE vigente")
        # CIDRs inválidos se avisan pero se conservan como texto
        for entrada in list(datos["alcance"]) + list(datos["excluidos"]):
            texto = str(entrada)
            if "/" in texto:
                try:
                    ipaddress.ip_network(texto, strict=False)
                except ValueError:
                    avisos.append(f"CIDR inválido: {texto}")

        self.datos = datos
        self._guardar()
        return True, avisos

    def limpiar(self) -> None:
        self.datos = {}
        self._guardar()

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------
    def activo(self) -> bool:
        return bool(self.datos)

    def _parsear_fecha(self, texto: str) -> Optional[date]:
        texto = (texto or "").strip()
        if not texto:
            return None
        for formato in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                return datetime.strptime(texto, formato).date()
            except ValueError:
                continue
        return None

    def vigente(self) -> Tuple[bool, str]:
        """True si el engagement está activo y no ha pasado el kill-date."""
        if not self.activo():
            return False, "no hay engagement cargado"
        limite = self._parsear_fecha(str(self.datos.get("kill_date", "")))
        if limite and date.today() > limite:
            return False, (f"kill_date superado ({limite.isoformat()}): "
                           "toda ejecución queda bloqueada")
        return True, ""

    def _coincide(self, objetivo: str, entrada: str) -> bool:
        """Compara un objetivo (host/IP/CIDR) con una entrada del alcance."""
        entrada = str(entrada).strip().lower()
        objetivo = objetivo.strip().lower()
        if not entrada or not objetivo:
            return False
        if "/" in entrada:                     # CIDR
            try:
                red = ipaddress.ip_network(entrada, strict=False)
                return ipaddress.ip_address(objetivo) in red
            except ValueError:
                return False
        if entrada.startswith("*."):
            entrada = entrada[1:]              # *.corp.local → .corp.local
        if objetivo.startswith("*."):
            objetivo = objetivo[1:]
        if entrada.startswith("."):
            return objetivo == entrada[1:] or objetivo.endswith(entrada)
        if entrada.startswith("*."):
            return objetivo == entrada[2:] or objetivo.endswith("." + entrada[2:])
        # dominio bare: coincide el dominio exacto y sus subdominios
        # (convención habitual en los scopes de engagement)
        return objetivo == entrada or objetivo.endswith("." + entrada)

    def verifica(self, valor: str) -> Tuple[bool, str]:
        """Verifica un objetivo contra scope/kill-date.

        Devuelve (permitido, motivo). Un objetivo vacío se permite (no
        aporta información de scope). Los excluidos bloquean siempre,
        aunque esté dentro del alcance.
        """
        objetivo = extraer_host(valor)
        if not objetivo:
            return True, ""
        vigente, motivo = self.vigente()
        if not vigente and self.activo():
            return False, motivo
        alcance = [str(x) for x in self.datos.get("alcance", [])]
        excluidos = [str(x) for x in self.datos.get("excluidos", [])]
        if not alcance:
            return True, "sin alcance definido: no se aplica control"
        for entrada in excluidos:
            if self._coincide(objetivo, entrada):
                return False, f"{objetivo} está EXCLUIDO del engagement ({entrada})"
        for entrada in alcance:
            if self._coincide(objetivo, entrada):
                return True, f"{objetivo} ∈ alcance"
        if self.datos.get("permitir_fuera_alcance"):
            return True, (f"{objetivo} fuera del alcance, permitido por "
                          "'permitir_fuera_alcance' (queda auditado)")
        return False, f"{objetivo} FUERA del alcance del engagement"

    # ------------------------------------------------------------------
    # Presentación
    # ------------------------------------------------------------------
    def resumen(self) -> str:
        if not self.activo():
            return "sin engagement"
        vigente, _ = self.vigente()
        estado = "VIGENTE" if vigente else "VENCIDO"
        return (f"{self.datos.get('nombre')} [{estado}] · alcance: "
                f"{len(self.datos.get('alcance', []))} entradas")
