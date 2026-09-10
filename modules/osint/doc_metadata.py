# -*- coding: utf-8 -*-
"""
Módulo osint/doc_metadata
=========================
Metadatos de documentos públicos (estilo FOCA / módulo «metadata» de
reconmap): descarga PDF/DOCX/XLSX/PPTX que hayan quedado indexados o
archivados y extrae autores, software, empresa, fechas y correos que
revelan personas y tecnología interna.

DOCX/XLSX/PPTX se leen con zipfile+XML (stdlib); los PDF usan pypdf si
está instalado (degradación elegante si falta).
Riesgo: BAJO (solo descarga y lee ficheros públicos).
ATT&CK: T1592.002 (Gather Victim Host Information: Software).
"""

import io
import re
import zipfile
from pathlib import Path

import requests

from core.base_module import BaseModulo, ModuloError

SALIDA_RAIZ = Path(__file__).resolve().parent.parent.parent / "output" / "metadatos"
CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _meta_docx_xlsx(contenido: bytes) -> dict:
    """Lee docProps/core.xml y app.xml de un contenedor OOXML (zip)."""
    meta: dict = {}
    with zipfile.ZipFile(io.BytesIO(contenido)) as z:
        if "docProps/core.xml" in z.namelist():
            xml = z.read("docProps/core.xml").decode("utf-8", errors="replace")
            for etiqueta in ("dc:creator", "cp:lastModifiedBy", "dc:title",
                             "dc:subject", "cp:revision"):
                m = re.search(f"<{etiqueta}[^>]*>(.*?)</{etiqueta}>", xml, re.S)
                if m and m.group(1).strip():
                    meta[etiqueta.split(":")[-1].lower()] = m.group(1).strip()
        if "docProps/app.xml" in z.namelist():
            xml = z.read("docProps/app.xml").decode("utf-8", errors="replace")
            for etiqueta in ("Application", "Company", "AppVersion", "TotalTime"):
                m = re.search(f"<{etiqueta}[^>]*>(.*?)</{etiqueta}>", xml, re.S)
                if m and m.group(1).strip():
                    meta[etiqueta.lower()] = m.group(1).strip()
    return meta


def _meta_pdf(contenido: bytes) -> dict:
    """Metadatos de PDF con pypdf; fallback a regex del trailer."""
    meta: dict = {}
    try:
        from pypdf import PdfReader  # noqa: PLC0415
        lector = PdfReader(io.BytesIO(contenido))
        info = lector.metadata or {}
        for clave in ("/Author", "/Creator", "/Producer", "/Title",
                      "/ModDate", "/CreationDate"):
            valor = info.get(clave)
            if valor:
                meta[clave.strip("/").lower()] = str(valor)
        return meta
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 — PDF corrupto → fallback
        pass
    texto = contenido[:200000].decode("latin-1", errors="replace")
    for clave in ("Author", "Creator", "Producer", "Title"):
        m = re.search(rf"/{clave}\s*\((.*?)\)", texto)
        if m:
            meta[clave.lower()] = m.group(1)[:120]
    return meta


class DocMetadata(BaseModulo):
    """Extrae metadatos de documentos públicos (FOCA-style)."""

    NAME = "osint/doc_metadata"
    CATEGORIA = "osint"
    DESCRIPCION = ("Metadatos de documentos públicos (PDF/DOCX/XLSX/PPTX): autores, "
                   "software, empresa y correos internos (estilo FOCA). Baja los "
                   "ficheros indicados en URLS o en el fichero @ruta.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (módulo metadata) · FOCA · MITRE ATT&CK T1592.002"
    ATTCK = ("T1592.002",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("URLS", "", True,
                               "URLs de documentos separadas por comas, o fichero @ruta")
        self.opciones.declarar("LIMITE", "20", False, "Máximo de documentos a descargar")

    def ejecutar(self) -> dict:
        texto = self.opt("URLS").strip()
        if texto.startswith("@"):
            try:
                texto = Path(texto[1:]).read_text(encoding="utf-8")
            except OSError as err:
                raise ModuloError(f"No se pudo leer la lista: {err}")
        urls = [u.strip() for u in texto.replace("\n", ",").split(",") if u.strip()]
        if not urls:
            raise ModuloError("Sin URLs de documentos")
        limite = self.opt_int("LIMITE", 20) or 20
        timeout = self.opt_int("TIMEOUT", 20) or 20
        cabeceras = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        documentos, personas, correos, errores = [], {}, set(), []
        for url in urls[:limite]:
            try:
                resp = requests.get(url, timeout=timeout, headers=cabeceras)
                resp.raise_for_status()
            except requests.RequestException as err:
                errores.append({"url": url, "error": str(err)})
                continue
            contenido = resp.content
            meta = {"url": url, "bytes": len(contenido), "tipo": "?"}
            if contenido[:2] == b"PK":
                meta["tipo"] = "ooxml"
                meta.update(_meta_docx_xlsx(contenido))
            elif contenido[:4] == b"%PDF":
                meta["tipo"] = "pdf"
                meta.update(_meta_pdf(contenido))
            else:
                meta["aviso"] = "formato no reconocido (se omite)"
            documentos.append(meta)
            for clave, valor in meta.items():
                if clave in ("url", "bytes", "tipo", "aviso"):
                    continue
                for m in CORREO.findall(str(valor)):
                    correos.add(m.lower())
                if clave in ("creator", "author", "lastmodifiedby"):
                    nombre = str(valor).strip()
                    if nombre and "@" not in nombre:
                        personas.setdefault(nombre, []).append(url.split("/")[-1])

        SALIDA_RAIZ.mkdir(parents=True, exist_ok=True)
        resumen = (f"{len(documentos)} documentos analizados: "
                   f"{len(personas)} autores, {len(correos)} correos, "
                   f"{len(errores)} errores")
        return {
            "resumen": resumen,
            "documentos": documentos,
            "personas": sorted(personas),
            "correos": sorted(correos),
            "errores": errores,
            "nota": "Autores y software interno son pistas de alto valor para "
                    "phishing dirigido y perfiles de atacante.",
        }
