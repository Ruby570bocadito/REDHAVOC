# -*- coding: utf-8 -*-
"""
Módulo cloud/gcs_enum
=====================
Audita el acceso ANÓNIMO a cubos de Google Cloud Storage:

    • LISTABLE   → la API JSON responde metadata + el listado público funciona
    • PROTEGIDO  → existe pero exige permisos (403 callerDoesNotHavePermissions)
    • NO_EXISTE  → 404 notFound
    • INALCANZABLE → sin respuesta

Comprueba dos cosas por cubo: la ficha de metadata (GET /storage/v1/b/<b>)
y el listado de objetos (GET /storage/v1/b/<b>/o). Ambas solo lectura.

Riesgo: BAJO (peticiones GET anónimas).
ATT&CK: T1619 (Cloud Storage Object Discovery) · CWE-732.
"""

from typing import Dict, List

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def clasificar_gcs(codigo: int, cuerpo: str) -> str:
    """Clasifica la respuesta anónima de la API GCS (función pura)."""
    if codigo == 200:
        return "LISTABLE"
    if codigo == 403:
        # 403 en metadata: el cubo existe (Google lo confirma) pero está protegido
        return "PROTEGIDO"
    if codigo == 404:
        return "NO_EXISTE"
    if codigo == 400:
        return "PROTEGIDO"      # nombre inválido → no auditamos más
    return "PROTEGIDO"


class GCSEnum(BaseModulo):
    """Audita acceso anónimo a cubos de Google Cloud Storage."""

    NAME = "cloud/gcs_enum"
    CATEGORIA = "cloud"
    DESCRIPCION = ("Cubos de Google Cloud Storage con metadata/listado anónimo "
                   "(API JSON v1) — solo lectura")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "GCP Storage IAM best practices · CWE-732"
    ATTCK = ("T1619",)

    def definir_opciones(self) -> None:
        self.opciones.declarar(
            "CUBOS", "", True,
            "Cubos a auditar, separados por coma (p. ej. acme-backups,acme-static)")

    def ejecutar(self) -> dict:
        bruto = self.opt("CUBOS")
        cubos = [c.strip() for c in bruto.replace(";", ",").split(",") if c.strip()]
        if not cubos:
            raise ModuloError("Indica al menos un cubo: set CUBOS acme-backups")
        timeout = self.opt_int("TIMEOUT", 8) or 8

        resultados: List[Dict] = []
        for cubo in cubos:
            fila = {"cubo": cubo, "estado": "INALCANZABLE", "ubicacion": "", "objetos": []}
            for etiqueta, url, es_listado in (
                ("metadata",
                 f"https://storage.googleapis.com/storage/v1/b/{cubo}", False),
                ("objetos",
                 f"https://storage.googleapis.com/storage/v1/b/{cubo}/o?maxResults=20",
                 True),
            ):
                try:
                    resp = requests.get(
                        url, timeout=timeout, verify=False,
                        headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
                except requests.RequestException:
                    continue
                estado = clasificar_gcs(resp.status_code, resp.text[:20_000])
                if es_listado is False:
                    fila["estado"] = estado
                    if estado == "LISTABLE":
                        try:
                            ficha = resp.json()
                            fila["ubicacion"] = str(ficha.get("location", "")) \
                                if isinstance(ficha, dict) else ""
                        except (ValueError, AttributeError):
                            pass
                else:
                    if fila["estado"] == "LISTABLE" and resp.status_code == 200:
                        fila["objetos"] = self._extraer_nombres(resp.text)[:20]
                    elif fila["estado"] == "LISTABLE":
                        # metadata pública pero listado protegido
                        fila["estado"] = "METADATA_PUBLICA"
            if fila["estado"] == "INALCANZABLE" and fila["objetos"]:
                fila["estado"] = "LISTABLE"
            resultados.append(fila)

            if fila["estado"] in ("LISTABLE", "METADATA_PUBLICA") \
                    and self.workspace is not None:
                self.workspace.add_vuln(
                    cubo, "Cubo GCS con información anónima", "medio",
                    f"estado {fila['estado']} ({len(fila['objetos'])} objetos)",
                    self.NAME)

        listables = sum(1 for r in resultados
                        if r["estado"] in ("LISTABLE", "METADATA_PUBLICA"))
        return {
            "resumen": (f"{len(cubos)} cubos GCS auditados: {listables} "
                        f"con acceso anónimo parcial o total"),
            "resultados": resultados,
            "nota": "Solo lectura. Usa 'allUsers' role removal y Uniform "
                    "bucket-level access para endurecer.",
        }

    @staticmethod
    def _extraer_nombres(json_txt: str) -> List[str]:
        """Extrae 'name': '…' del listado JSON de objetos (sin json.loads total)."""
        import json as _json
        try:
            datos = _json.loads(json_txt)
        except ValueError:
            return []
        return [str(i.get("name", "")) for i in datos.get("items", [])
                if isinstance(i, dict) and i.get("name")]
