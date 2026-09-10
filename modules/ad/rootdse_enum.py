# -*- coding: utf-8 -*-
"""
Módulo ad/rootdse_enum
======================
Consulta la RootDSE del dominio por LDAP (389) SIN credenciales.

La RootDSE es el "cartel de la puerta" de un Controlador de Dominio y por
defecto CUALQUIERA autenticado (e incluso anónimo en muchos dominios)
puede leerla. Revela:

    • defaultNamingContext     → el DN base del dominio (para ldap_enum)
    • domainControllerFunctionality / domainFunctionality
                               → nivel funcional del bosque/dominio
    • dnsHostName              → FQDN del DC
    • namingContexts           → dominio, configuración y esquema
    • subschemaSubentry        → donde vive el esquema

Es SIEMPRE el primer paso de una enumeración AD: sin el DN base, los
demás módulos LDAP no pueden ejecutarse.

Riesgo: BAJO (una lectura anónima estándar).
ATT&CK: T1018 (Remote System Discovery) · T1016.
"""

from typing import Dict, List

from core.base_module import BaseModulo, ModuloError
from core.ldap_min import buscar

ATRIBUTOS = (
    "defaultNamingContext",
    "namingContexts",
    "dnsHostName",
    "domainControllerFunctionality",
    "domainFunctionality",
    "forestFunctionality",
    "subschemaSubentry",
    "rootDomainNamingContext",
    "schemaNamingContext",
    "configurationNamingContext",
)

NIVEL_WIN = {
    "2016": 7, "2019": 8, "2022": 10, "2025": 12,
}


def nivel_windows(valor: str) -> str:
    """Traduce un entero de funcionalidad a versión Windows Server (pura)."""
    try:
        n = int(valor)
    except (TypeError, ValueError):
        return valor or "?"
    inverso = {v: k for k, v in NIVEL_WIN.items()}
    return f"Windows Server {inverso.get(n, n)}"


def resumen_rootdse(entradas: List[Dict]) -> Dict[str, object]:
    """Reduce la respuesta RootDSE a un resumen legible (función pura).

    Tolerante a atributos ausentes y a valores en cualquier estructura que
    produzca _parsear_entrada (dict plano).
    """
    if not entradas:
        return {}
    plana = entradas[0]
    contexto = plana.get("defaultNamingContext") or \
        (plana.get("namingContexts") or [""])[0] \
        if isinstance(plana.get("namingContexts"), list) \
        else plana.get("defaultNamingContext", "")
    if isinstance(contexto, list):
        contexto = contexto[0] if contexto else ""
    return {
        "dominio_dn": contexto or "",
        "dc_hostname": plana.get("dnsHostName", ""),
        "nivel_dominio": nivel_windows(str(
            plana.get("domainFunctionality", ""))),
        "nivel_dc": nivel_windows(str(
            plana.get("domainControllerFunctionality", ""))),
        "naming_contexts": (plana.get("namingContexts") or [])
            if isinstance(plana.get("namingContexts"), list) else [],
    }


class RootDseEnum(BaseModulo):
    """Lee la RootDSE del DC por LDAP anónimo (naming contexts y niveles)."""

    NAME = "ad/rootdse_enum"
    CATEGORIA = "ad"
    DESCRIPCION = ("RootDSE anónima del DC: naming contexts, DN base del "
                   "dominio y niveles funcionales — prerequisite de ldap_enum")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "RFC 4512 (RootDSE) · BloodHound methodology"
    ATTCK = ("T1018", "T1016")

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "RHOST", "", True, "Controlador de dominio (IP o FQDN)")
        self.opciones.declarar(
            "PUERTO", "389", False, "Puerto LDAP (389 claro o 636 LDAPS)")
        self.opciones.declarar(
            "TIMEOUT", "6", False, "Timeout por conexión en segundos")

    def ejecutar(self) -> dict:
        host = self.opt("RHOST").strip()
        if not host:
            raise ModuloError("Indica el DC objetivo: set RHOST dc01.corp.local")
        try:
            puerto = int(self.opt("PUERTO", "389"))
        except ValueError:
            puerto = 389
        timeout = self.opt_int("TIMEOUT", 6) or 6

        try:
            entradas, aviso = buscar(
                host, "", "(objectClass=*)", list(ATRIBUTOS),
                puerto=puerto, timeout=timeout)
        except OSError as exc:
            raise ModuloError(f"Sin conexión LDAP a {host}:{puerto} ({exc})")

        if not entradas:
            detalle = f" ({aviso})" if aviso else ""
            raise ModuloError(
                f"El DC respondió sin RootDSE{detalle}. ¿Es un controlador "
                f"de dominio? ¿El puerto es LDAP y no otro servicio?")

        resumen = resumen_rootdse(entradas)
        dn = str(resumen.get("dominio_dn") or "")

        if dn and self.workspace is not None:
            # La RootDSE por sí sola no es vuln; es inteligencia de arranque
            self.workspace.add_nota(
                f"RootDSE {host}: dominio={dn} · "
                f"nivel={resumen.get('nivel_dominio', '?')}")

        return {
            "resumen": (f"RootDSE {host}:{puerto} → "
                        f"{dn or 'sin defaultNamingContext'} · "
                        f"nivel {resumen.get('nivel_dominio', '?')}"),
            "resultados": [resumen],
            "siguiente_dn": dn,
            "nota": ("Con el DN base ya puedes enumerar el dominio: "
                     "use ad/ldap_enum · set RHOST " + host)
                    if dn else "Sin DN base: el DC puede requerir autenticación "
                               "(prueba 636 con credenciales válidas).",
        }
