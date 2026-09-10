# -*- coding: utf-8 -*-
"""
Módulo osint/wayback_urls
=========================
URLs históricas del dominio desde la Wayback Machine (CDX API):
endpoints con parámetros, documentos olvidados y subdominios que
aparecieron alguna vez en el archivo web.

Ideas de: reconmap (módulo wayback) · reconftw.
Riesgo: BAJO (consulta pública).
ATT&CK: T1596 (Search Open Technical Databases).
"""

import requests

from core.base_module import BaseModulo, ModuloError

CDX = ("https://web.archive.org/cdx/search/cdx"
       "?url={dominio}/*&output=json&collapse=urlkey"
       "&fl=original,mimetype,statuscode&limit={limite}")


class WaybackUrls(BaseModulo):
    """Recupera URLs históricas del dominio desde el archivo web."""

    NAME = "osint/wayback_urls"
    CATEGORIA = "osint"
    DESCRIPCION = ("URLs históricas del dominio vía Wayback Machine CDX: endpoints "
                   "con parámetros, documentos y subdominios olvidados. Pasivo.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (módulo wayback) · MITRE ATT&CK T1596"
    ATTCK = ("T1596",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Dominio objetivo")
        self.opciones.declarar("LIMITE", "1000", False, "Máximo de filas del CDX")
        self.opciones.declarar("MIME", "", False,
                               "Filtro mimetype (vacío = todo; p. ej. application/pdf)")

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("TARGET")).lower()
        limite = self.opt_int("LIMITE", 1000) or 1000
        mime = self.opt("MIME").strip()
        timeout = self.opt_int("TIMEOUT", 20) or 20
        url = CDX.format(dominio=dominio, limite=limite)
        if mime:
            url += "&filter=mimetype:" + mime

        try:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"Consulta CDX falló: {err}")
        if resp.status_code != 200:
            raise ModuloError(f"CDX respondió HTTP {resp.status_code}")
        try:
            filas = resp.json()
        except ValueError as err:
            raise ModuloError(f"CDX devolvió JSON inválido: {err}")
        if not filas or len(filas) < 2:
            return {"resumen": f"Wayback {dominio}: sin URLs archivadas",
                    "dominio": dominio, "endpoints": [], "documentos": [],
                    "subdominios": [], "con_parametros": []}

        endpoints, docs, subdominios, con_params = [], [], set(), []
        for original, mimetype, estado in filas[1:]:
            original = (original or "").strip()
            if not original:
                continue
            endpoints.append({"url": original, "mime": mimetype, "estado": estado})
            if mimetype in ("application/pdf", "application/msword",
                            "application/vnd.ms-excel",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
                docs.append(original)
            if "?" in original and "=" in original.split("?", 1)[1]:
                con_params.append(original)
            resto = original.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
            if resto.endswith(dominio) and resto != dominio and resto != f"www.{dominio}":
                subdominios.add(resto)

        return {
            "resumen": (f"Wayback {dominio}: {len(endpoints)} URLs, {len(docs)} documentos, "
                        f"{len(subdominios)} subdominios históricos"),
            "dominio": dominio,
            "total": len(endpoints),
            "endpoints": endpoints[:300],
            "documentos": docs[:100],
            "subdominios": sorted(subdominios),
            "con_parametros": con_params[:100],
            "nota": "Los endpoints con parámetros son candidatos clásicos a SQLi/IDOR.",
        }
