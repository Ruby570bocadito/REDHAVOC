# -*- coding: utf-8 -*-
"""
Módulo cloud/k8s_enum
=====================
Audita planos de control de contenedores expuestos SIN credenciales:

    • Kubernetes API  (6443)   → /version, /api, /api/v1/pods (anónimo)
    • Kubelet         (10250)  → /pods, /runningpods
    • Docker API      (2375)   → /version, /containers/json

Una API de contenedores sin autenticación es hallazgo CRÍTICO: permite
listar pods/contenedores (secretos en variables de entorno), ejecutar
comandos vía /exec y, en el caso de Docker 2375 abierto, control TOTAL
del host con un simple POST /containers/create (fuera del alcance de este
módulo: solo lectura).

Riesgo: MEDIO (peticiones GET anónimas contra servicios de gestión).
ATT&CK: T1613 (Container and Resource Discovery) · CWE-306.
"""

from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def clasificar_api_k8s(codigo: int, cuerpo: str) -> str:
    """Clasifica la respuesta de la API Kubernetes (función pura).

    Estados: ANONIMO_PODS | ANONIMO_META | PROTEGIDO | NO_K8S
    """
    texto = (cuerpo or "")[:50_000].lower()
    if codigo == 200 and '"kind":"podlist"' in texto.replace(" ", ""):
        return "ANONIMO_PODS"
    if codigo == 200 and ('"major"' in texto and '"gitversion"' in texto):
        return "ANONIMO_META"
    if codigo == 200 and '"kind"' in texto and '"apiversion"' in texto:
        return "ANONIMO_META"
    if codigo in (401, 403):
        return "PROTEGIDO"
    return "NO_K8S"


def resumen_pods(cuerpo: str, limite: int = 15) -> List[str]:
    """Extrae una vista mínima de pods del JSON de /pods (función pura).

    Devuelve cadenas 'ns/nombre' SIN metadatos sensibles (solo identificación).
    """
    import json
    try:
        datos = json.loads(cuerpo)
    except (ValueError, TypeError):
        return []
    items = datos.get("items") or []
    salida: List[str] = []
    for item in items:
        meta = (item.get("metadata") or {})
        nombre = meta.get("name") or "?"
        ns = meta.get("namespace") or "default"
        salida.append(f"{ns}/{nombre}")
        if len(salida) >= limite:
            break
    return salida


class K8sEnum(BaseModulo):
    """Enumera Kubernetes API / kubelet / Docker API sin credenciales."""

    NAME = "cloud/k8s_enum"
    CATEGORIA = "cloud"
    DESCRIPCION = ("Planos de control de contenedores sin auth: Kubernetes "
                   "(6443), kubelet (10250) y Docker API (2375) — solo GET")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "CIS Kubernetes Benchmark · CWE-306"
    ATTCK = ("T1613",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "RHOST", "", True, "Host objetivo (nodo o master del clúster)")
        self.opciones.declarar(
            "PUERTO_K8S", "6443", False, "Puerto de la API Kubernetes")
        self.opciones.declarar(
            "PUERTO_KUBELET", "10250", False, "Puerto del kubelet")
        self.opciones.declarar(
            "PUERTO_DOCKER", "2375", False, "Puerto de la Docker API")
        self.opciones.declarar(
            "TIMEOUT", "6", False, "Timeout por petición en segundos")

    def ejecutar(self) -> dict:
        host = self.opt("RHOST").strip()
        if not host:
            raise ModuloError("Indica el objetivo: set RHOST <host>")
        timeout = self.opt_int("TIMEOUT", 6) or 6
        ua = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}
        host_limpio = self._objetivo_host(host)

        def _puerto(nombre, defecto):
            try:
                return int(self.opt(nombre, str(defecto)) or defecto)
            except ValueError:
                return defecto

        sondas = (
            ("Kubernetes API", "https", _puerto("PUERTO_K8S", 6443),
             "/version", None),
            ("Kubernetes pods", "https", _puerto("PUERTO_K8S", 6443),
             "/api/v1/pods", "ANONIMO_PODS"),
            ("Kubelet pods", "https", _puerto("PUERTO_KUBELET", 10250),
             "/pods", "ANONIMO_PODS"),
            ("Docker API", "http", _puerto("PUERTO_DOCKER", 2375),
             "/version", None),
            ("Docker contenedores", "http", _puerto("PUERTO_DOCKER", 2375),
             "/containers/json", None),
        )

        resultados: List[Dict] = []
        criticos = 0
        for nombre, esquema, puerto, ruta, umbral in sondas:
            url = f"{esquema}://{host_limpio}:{puerto}{ruta}"
            estado, detalle, pods = "INALCANZABLE", "", []
            try:
                resp = requests.get(url, timeout=timeout, verify=False, headers=ua)
                estado = clasificar_api_k8s(resp.status_code, resp.text)
                if umbral and estado == umbral:
                    pods = resumen_pods(resp.text)
                if estado == "ANONIMO_META":
                    detalle = resp.text[:120].replace("\n", " ")
            except requests.RequestException:
                pass

            fila = {"servicio": nombre, "url": url, "estado": estado}
            if pods:
                fila["pods"] = pods
            if detalle and estado == "ANONIMO_META":
                fila["detalle"] = detalle
            resultados.append(fila)

            if estado in ("ANONIMO_PODS",) or \
               (nombre == "Docker contenedores" and estado == "ANONIMO_META"):
                criticos += 1
                if self.workspace is not None:
                    gravedad = "alto" if nombre != "Docker contenedores" else "alto"
                    self.workspace.add_vuln(
                        host_limpio, f"{nombre} sin autenticación", gravedad,
                        f"{url} accesible de forma anónima (solo lectura)",
                        self.NAME)

        abiertos = [r for r in resultados if r["estado"].startswith("ANONIMO")]
        return {
            "resumen": (f"Contenedores {host_limpio}: {criticos} servicio(s) "
                        f"anónimo(s) de {len(sondas)} sondeados"),
            "resultados": resultados,
            "nota": "Solo GET. Un plano de control anónimo es crítico: activa "
                    "RBAC/autenticación, cierra 2375 (usa socket UNIX) y "
                    "restinge kubelet con webhook de autorización.",
        }
