# -*- coding: utf-8 -*-
"""
Módulo cloud/s3_enum
====================
Audita el acceso ANÓNIMO a cubos de Amazon S3 (sin credenciales):

    • LISTABLE   → el cubo permite listar objetos (ListObjectsV2 anónimo)
    • PROTEGIDO  → existe pero rechaza el listado (403 AccessDenied)
    • NO_EXISTE  → 404 NoSuchBucket
    • INALCANZABLE → sin respuesta (DNS/red)

Un cubo LISTABLE expone la estructura de ficheros (y a veces los ficheros
mismos: backups, .env, dumps SQL). Es una de las fugas más frecuentes en
auditorías de nube. El módulo SOLO LEE: nunca escribe ni borra.

Riesgo: BAJO (peticiones GET anónimas).
ATT&CK: T1619 (Cloud Storage Object Discovery) · CWE-732.
"""

from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Firma XML de un listado anónimo exitoso (ListObjectsV2 / ListBucket)
_LISTA_OK = "listbucketresult"
_NUMELEM = "<key>"


def clasificar_s3(codigo: int, cuerpo: str) -> str:
    """Clasifica la respuesta HTTP anónima del cubo (función pura).

    Estados: LISTABLE | PROTEGIDO | NO_EXISTE | INALCANZABLE
    """
    if codigo == 200:
        bajo = cuerpo.lower()
        if _LISTA_OK in bajo or _NUMELEM in bajo:
            return "LISTABLE"
        # 200 sin XML: el cubo sirve un sitio web estático (website endpoint)
        return "LISTABLE" if cuerpo.strip() else "PROTEGIDO"
    if codigo == 403:
        return "PROTEGIDO"
    if codigo == 404:
        return "NO_EXISTE"
    if codigo in (301, 400):
        # 301: cubo en otra región · 400: región mal formada
        return "OTRA_REGION" if codigo == 301 else "PROTEGIDO"
    return "PROTEGIDO"


def urls_de_cubo(cubo: str, region: str) -> List[str]:
    """Construye las URLs candidatas del cubo (función pura)."""
    cubo = cubo.strip().lower()
    region = (region or "us-east-1").strip().lower()
    return [
        f"https://{cubo}.s3.{region}.amazonaws.com/?list-type=2&max-keys=20",
        f"https://{cubo}.s3.amazonaws.com/?list-type=2&max-keys=20",
    ]


class S3Enum(BaseModulo):
    """Audita acceso anónimo a cubos S3 (listado público)."""

    NAME = "cloud/s3_enum"
    CATEGORIA = "cloud"
    DESCRIPCION = ("Cubos S3 con listado anónimo (ListObjectsV2 sin credenciales): "
                   "LISTABLE / PROTEGIDO / NO_EXISTE — solo lectura")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "AWS S3 security best practices · CWE-732"
    ATTCK = ("T1619",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "CUBOS", "", True,
            "Cubos a auditar, separados por coma (p. ej. backups-acme,acme-dev)")
        self.opciones.declarar(
            "REGION", "us-east-1", False, "Región AWS del cubo")
        self.opciones.declarar(
            "MAX_OBJETOS", "20", False, "Máximo de objetos a listar por cubo")

    def ejecutar(self) -> dict:
        bruto = self.opt("CUBOS")
        cubos = [c.strip() for c in bruto.replace(";", ",").split(",") if c.strip()]
        if not cubos:
            raise ModuloError("Indica al menos un cubo: set CUBOS nombre1,nombre2")
        region = self.opt("REGION", "us-east-1")
        try:
            max_obj = max(1, min(100, int(self.opt("MAX_OBJETOS", "20") or 20)))
        except ValueError:
            max_obj = 20
        timeout = self.opt_int("TIMEOUT", 8) or 8

        resultados: List[Dict] = []
        for cubo in cubos:
            estado, objetos, url_usada = "INALCANZABLE", [], ""
            for url in urls_de_cubo(cubo, region):
                url = url.replace("max-keys=20", f"max-keys={max_obj}")
                try:
                    resp = requests.get(
                        url, timeout=timeout, verify=False,
                        headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
                except requests.RequestException:
                    continue
                url_usada = url.split("?")[0]
                estado = clasificar_s3(resp.status_code, resp.text[:50_000])
                if estado == "LISTABLE":
                    objetos = self._extraer_claves(resp.text)[:max_obj]
                    break
                if estado in ("PROTEGIDO", "NO_EXISTE", "OTRA_REGION"):
                    break

            fila = {"cubo": cubo, "estado": estado, "url": url_usada}
            if objetos:
                fila["objetos"] = objetos
            resultados.append(fila)

            if estado == "LISTABLE" and self.workspace is not None:
                self.workspace.add_vuln(
                    cubo, "Cubo S3 con listado anónimo", "alto",
                    f"{len(objetos)} objetos visibles sin credenciales ({url_usada})",
                    self.NAME)

        listables = sum(1 for r in resultados if r["estado"] == "LISTABLE")
        protegidos = sum(1 for r in resultados if r["estado"] == "PROTEGIDO")
        return {
            "resumen": (f"{len(cubos)} cubos auditados: {listables} LISTABLE(s), "
                        f"{protegidos} protegido(s)"),
            "resultados": resultados,
            "nota": "Solo lectura. Un cubo LISTABLE es hallazgo alto: "
                    "restringe el listado y revisa cifrado y políticas.",
        }

    @staticmethod
    def _extraer_claves(xml: str) -> List[str]:
        """Extrae las claves <Key>…</Key> del XML de listado (sin parseo pesado)."""
        claves: List[str] = []
        inicio = 0
        while True:
            i = xml.lower().find("<key>", inicio)
            if i < 0:
                break
            j = xml.lower().find("</key>", i)
            if j < 0:
                break
            claves.append(xml[i + 5:j])
            inicio = j + 6
            if len(claves) >= 100:
                break
        return claves
