# -*- coding: utf-8 -*-
"""
Módulo web/graphql_probe
========================
Descubre endpoints GraphQL en un sitio web y audita su configuración:

    • Rutas típicas: /graphql, /api/graphql, /graphiql, /v2/graphql, ...
    • Sonda IntrospectionQuery mínima (solo __schema.typename)
    • Detecta: ENDPOINT_ACTIVO, INTROSPECCION_ABIERTA, PLAYGROUND,
      PROTEGIDO (401/403), NO_GRAPHQL

La introspección abierta le entrega al atacante el esquema COMPLETO de la
API (tipos, mutaciones, campos internos): es el primer paso de casi todos
los ataques GraphQL (batching, field suggestion, deep query DoS).

Riesgo: BAJO (peticiones GET/POST de sondeo, solo lectura).
ATT&CK: T1190 (Exploit Public-Facing Application) · CWE-200.
"""

from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sonda mínima de introspección: pregunta solo por el nombre del tipo raíz
SONDA_INTROSPECCION = '{"query":"{ __schema { queryType { name } } }"}'

RUTAS_DEFECTO = (
    "graphql,api/graphql,api/v1/graphql,api/v2/graphql,graphiql,playground,"
    "graphql/console,gql,api/gql,query,api/query,graphql/v1,graphql/batch,"
    "altair,hasura/v1/graphql,swapi/graphql"
)


def clasificar_sonda(codigo: int, cuerpo: str) -> str:
    """Clasifica la respuesta de una sonda GraphQL (función pura).

    Estados: INTROSPECCION_ABIERTA | ENDPOINT_ACTIVO | PROTEGIDO |
             NO_GRAPHQL
    """
    texto = (cuerpo or "")[:20_000]
    bajo = texto.lower()
    if codigo in (401, 403):
        return "PROTEGIDO"
    if codigo == 200 and '"querytype"' in bajo:
        return "INTROSPECCION_ABIERTA"
    if codigo == 200 and ('graphql' in bajo or '"data"' in bajo
                          or '"errors"' in bajo):
        return "ENDPOINT_ACTIVO"
    if codigo in (400, 405, 415) and ('graphql' in bajo or 'query' in bajo):
        return "ENDPOINT_ACTIVO"
    if codigo == 200 and ('graphiql' in bajo or 'playground' in bajo):
        return "PLAYGROUND"
    return "NO_GRAPHQL"


def detectar_playground(html: str) -> str:
    """Identifica el IDE GraphQL servido en una página (función pura)."""
    bajo = (html or "").lower()
    if "graphiql" in bajo:
        return "GraphiQL"
    if "altair" in bajo:
        return "Altair"
    if "playground" in bajo:
        return "GraphQL Playground"
    if "apollo" in bajo and "graphql" in bajo:
        return "Apollo (posible)"
    return ""


class GraphQLProbe(BaseModulo):
    """Descubre endpoints GraphQL y audita la introspección."""

    NAME = "web/graphql_probe"
    CATEGORIA = "web"
    DESCRIPCION = ("Descubre endpoints GraphQL (14 rutas típicas) y audita "
                   "introspección abierta y playgrounds expuestos")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP GraphQL Security · CWE-200"
    ATTCK = ("T1190",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "URL", "", True, "URL base del sitio (http(s)://host)")
        self.opciones.declarar(
            "RUTAS", RUTAS_DEFECTO, False,
            "Rutas candidatas separadas por coma")
        self.opciones.declarar(
            "METODO", "GET", False, "Método de la sonda de introspección (GET/POST)")
        self.opciones.declarar(
            "TIMEOUT", "8", False, "Timeout por petición en segundos")

    def ejecutar(self) -> dict:
        base = self.opt("URL").strip().rstrip("/")
        if not base:
            raise ModuloError("Indica el objetivo: set URL https://sitio.com")
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        if not self._objetivo_host(base):
            raise ModuloError("URL sin host válido: set URL https://sitio.com")
        rutas = [r.strip().lstrip("/") for r in
                 self.opt("RUTAS", RUTAS_DEFECTO).split(",") if r.strip()]
        metodo = self.opt("METODO", "GET").upper()
        timeout = self.opt_int("TIMEOUT", 8) or 8
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        host = self._objetivo_host(base)
        hallazgos: List[Dict] = []
        for ruta in rutas:
            url = f"{base}/{ruta}"
            try:
                # 1) Sondeo de introspección
                if metodo == "POST":
                    resp = requests.post(
                        url, data=SONDA_INTROSPECCION, timeout=timeout,
                        verify=False, headers={**ua, "Content-Type": "application/json"})
                else:
                    resp = requests.get(
                        url, params={"query": "{ __schema { queryType { name } } }"},
                        timeout=timeout, verify=False, headers=ua)
                estado = clasificar_sonda(resp.status_code, resp.text)
            except requests.RequestException:
                continue

            # 2) GET plano para cazar playgrounds (solo si aún no hay introspección)
            playground = ""
            if estado in ("NO_GRAPHQL", "ENDPOINT_ACTIVO"):
                try:
                    plano = requests.get(url, timeout=timeout, verify=False,
                                         headers={"User-Agent": ua["User-Agent"],
                                                  "Accept": "text/html"})
                    if plano.status_code == 200 and "<html" in plano.text.lower():
                        playground = detectar_playground(plano.text)
                        if playground and estado == "NO_GRAPHQL":
                            estado = "PLAYGROUND"
                except requests.RequestException:
                    pass

            if estado == "NO_GRAPHQL":
                continue

            fila = {"url": url, "estado": estado}
            if playground:
                fila["playground"] = playground
            if estado == "INTROSPECCION_ABIERTA":
                fila["esquema"] = "oculto en el informe (ver JSON completo)"
            hallazgos.append(fila)

            if estado == "INTROSPECCION_ABIERTA" and self.workspace is not None:
                self.workspace.add_vuln(
                    host, "GraphQL con introspección abierta", "medio",
                    f"{url} expone el esquema completo sin autenticación",
                    self.NAME)

        if not hallazgos:
            return {
                "resumen": (f"Ningún endpoint GraphQL en {len(rutas)} rutas "
                            f"probadas de {base}"),
                "resultados": [],
                "nota": "Sin GraphQL en las rutas típicas. Si la app es SPA, "
                        "revisa los bundles JS (web/exposed_files) por rutas internas.",
            }

        intros = sum(1 for h in hallazgos if h["estado"] == "INTROSPECCION_ABIERTA")
        return {
            "resumen": (f"{len(hallazgos)} endpoint(s) GraphQL: "
                        f"{intros} con introspección abierta"),
            "resultados": hallazgos,
            "nota": "Con introspección abierta, exporta el esquema y revisa "
                    "mutaciones sensibles y límites de profundidad/batching.",
        }
