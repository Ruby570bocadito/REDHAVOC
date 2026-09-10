# -*- coding: utf-8 -*-
"""
Módulo cloud/azure_blob
=======================
Audita el acceso ANÓNIMO a contenedores de Azure Blob Storage:

    • LISTABLE   → `restype=container&comp=list` responde con XML de blobs
    • PROTEGIDO  → existe pero exige Authorization (403 PublicAccessNotPermitted)
    • NO_EXISTE  → 404/409 ContainerNotFound
    • INALCANZABLE → sin respuesta

Igual que en S3, un contenedor listable expone backups y ficheros internos.
El módulo SOLO LEE: nunca descarga blobs en bloque ni escribe.

Riesgo: BAJO (peticiones GET anónimas).
ATT&CK: T1619 (Cloud Storage Object Discovery) · CWE-732.
"""

from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def clasificar_azure(codigo: int, cuerpo: str) -> str:
    """Clasifica la respuesta anónima del contenedor (función pura)."""
    if codigo == 200:
        bajo = cuerpo.lower()
        if "enumerationresults" in bajo or "<blob>" in bajo or "<name>" in bajo:
            return "LISTABLE"
        return "PROTEGIDO"
    if codigo == 403:
        return "PROTEGIDO"
    if codigo in (404, 409):
        bajo = (cuerpo or "").lower()
        if "containernotfound" in bajo or "blobnotfound" in bajo or codigo == 404:
            return "NO_EXISTE"
        return "PROTEGIDO"
    return "PROTEGIDO"


class AzureBlobEnum(BaseModulo):
    """Audita acceso anónimo a contenedores de Azure Blob."""

    NAME = "cloud/azure_blob"
    CATEGORIA = "cloud"
    DESCRIPCION = ("Contenedores de Azure Blob con listado anónimo "
                   "(restype=container&comp=list) — solo lectura")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "Azure Storage access control · CWE-732"
    ATTCK = ("T1619",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "CUENTA", "", True, "Cuenta de almacenamiento (p. ej. acmedata)")
        self.opciones.declarar(
            "CONTENEDORES", "", True,
            "Contenedores a auditar, separados por coma (p. ej. backups,public)")

    def ejecutar(self) -> dict:
        cuenta = self.opt("CUENTA").strip().lower()
        if not cuenta:
            raise ModuloError("Indica la cuenta de almacenamiento: set CUENTA acmedata")
        bruto = self.opt("CONTENEDORES")
        contenedores = [c.strip() for c in bruto.replace(";", ",").split(",")
                        if c.strip()]
        if not contenedores:
            raise ModuloError("Indica contenedores: set CONTENEDORES backups,public")
        timeout = self.opt_int("TIMEOUT", 8) or 8

        resultados: List[Dict] = []
        for cont in contenedores:
            url = (f"https://{cuenta}.blob.core.windows.net/{cont}"
                   f"?restype=container&comp=list&maxresults=20")
            estado, blobs = "INALCANZABLE", []
            try:
                resp = requests.get(
                    url, timeout=timeout, verify=False,
                    headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
                estado = clasificar_azure(resp.status_code, resp.text[:50_000])
                if estado == "LISTABLE":
                    blobs = self._extraer_nombres(resp.text)[:20]
            except requests.RequestException:
                pass

            fila = {"contenedor": f"{cuenta}/{cont}", "estado": estado, "url": url}
            if blobs:
                fila["blobs"] = blobs
            resultados.append(fila)

            if estado == "LISTABLE" and self.workspace is not None:
                self.workspace.add_vuln(
                    cuenta, "Contenedor Azure Blob con listado anónimo", "alto",
                    f"{cont}: {len(blobs)} blobs visibles sin credenciales",
                    self.NAME)

        listables = sum(1 for r in resultados if r["estado"] == "LISTABLE")
        return {
            "resumen": (f"{len(contenedores)} contenedores auditados en "
                        f"{cuenta}: {listables} LISTABLE(s)"),
            "resultados": resultados,
            "nota": "Solo lectura. Bloquea el acceso público desde "
                    "'Networking' (Allow public access: Disabled) si no es necesario.",
        }

    @staticmethod
    def _extraer_nombres(xml: str) -> List[str]:
        """Extrae <Name>…</Name> de cada <Blob> del XML (sin parseo pesado)."""
        nombres: List[str] = []
        bajo = xml.lower()
        inicio = 0
        while len(nombres) < 100:
            i = bajo.find("<blob>", inicio)
            if i < 0:
                break
            fin = bajo.find("</blob>", i)
            if fin < 0:
                break
            bloque = xml[i:fin]
            j = bloque.lower().find("<name>")
            k = bloque.lower().find("</name>")
            if 0 <= j < k:
                nombres.append(bloque[j + 6:k])
            inicio = fin + 7
        return nombres
