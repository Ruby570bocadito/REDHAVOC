# -*- coding: utf-8 -*-
"""
core.pdf_min
============
Generador de PDF mínimo en Python puro (sin dependencias) para los
informes de REDHAVOC (roadmap v2.1: exportación de informes a PDF).

Implementa el subconjunto de PDF 1.4 que necesita un informe de módulo:

    • Páginas A4 con márgenes y paginación automática
    • Fuentes base Helvetica / Helvetica-Bold / Courier (sin incrustar)
    • Texto con color, envoltura de línea aproximada y pie de página
    • Tablas monoespaciadas simples con anchos calculados

Diseñado para informes: texto latino (WinAnsiEncoding). Los caracteres
fuera de Latin-1 se transliteran con NFKD y, como último recurso, '?'.
"""

import unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Geometría A4 en puntos (1/72")
ANCHO_A4, ALTO_A4 = 595.0, 842.0
MARGEN_IZQ, MARGEN_DER, MARGEN_SUP, MARGEN_INF = 56.0, 56.0, 56.0, 52.0

# Colores RGB (0..1) del tema del informe
_TINTA = (0.10, 0.12, 0.18)          # cuerpo
_ACENTO = (0.82, 0.16, 0.21)         # rojo REDHAVOC (títulos/secciones)
_SUAVE = (0.42, 0.47, 0.55)          # metadatos
_LINEA = (0.78, 0.80, 0.84)          # filetes

_ANCHO_HELV = 0.52                    # ancho medio de carácter Helvetica / tamaño
_ANCHO_COURIER = 0.60                 # ancho fijo Courier / tamaño


def _transliterar(texto: str) -> str:
    """Convierte Unicode a Latin-1 aproximado (NFKD + sustitución final)."""
    if not texto:
        return ""
    decompuesto = unicodedata.normalize("NFKD", texto)
    plano = "".join(c for c in decompuesto if not unicodedata.combining(c))
    # algunos símbolos frecuentes antes del fallback
    reemplazos = {"—": "-", "–": "-", "·": "-", "»": ">", "«": "<",
                  "“": '"', "”": '"', "’": "'", "‘": "'", "…": "...",
                  "€": "EUR", "✓": "OK", "●": "*", "→": "->"}
    for origen, destino in reemplazos.items():
        plano = plano.replace(origen, destino)
    return plano.encode("latin-1", errors="replace").decode("latin-1")


def _escapar_pdf(texto: str) -> str:
    """Escapa una cadena para un literal PDF (...)."""
    return (texto.replace("\\", "\\\\")
                 .replace("(", "\\(")
                 .replace(")", "\\)"))


class DocumentoPDF:
    """Constructor de un PDF de informe con paginación automática."""

    def __init__(self, titulo: str = "Informe") -> None:
        self.titulo = titulo
        self._lineas: List[Tuple[str, float, Tuple[float, float, float], float, str]] = []
        # (texto, tam_fuente, color, salto_despues, fuente)
        self._y: float = 0.0
        self._paginas: List[List[str]] = []
        self._actual: List[str] = []
        self._pie: Optional[str] = None
        self._nueva_pagina()

    # ------------------------------------------------------------------
    # API de composición
    # ------------------------------------------------------------------
    def titulo_doc(self, texto: str) -> None:
        self._push(_transliterar(texto).upper(), 17, _ACENTO, 6, "F2")

    def meta(self, clave: str, valor: str) -> None:
        self._push(f"{clave}: {_transliterar(valor)}", 9.5, _SUAVE, 2, "F1")

    def seccion(self, texto: str) -> None:
        self._espacio(6)
        self._push(_transliterar(texto).upper(), 11.5, _ACENTO, 4, "F2")
        self._regla()

    def parrafo(self, texto: str) -> None:
        for linea in self._envolver(_transliterar(texto), 10, ANCHO_A4
                                    - MARGEN_IZQ - MARGEN_DER, _ANCHO_HELV):
            self._push(linea, 10, _TINTA, 3, "F1")

    def bullet(self, texto: str, nivel: int = 0) -> None:
        prefijo = "  " + "    " * nivel + ("- " if nivel == 0 else "- ")
        for i, linea in enumerate(self._envolver(
                _transliterar(texto), 10,
                ANCHO_A4 - MARGEN_IZQ - MARGEN_DER - len(prefijo) * 5.2,
                _ANCHO_HELV)):
            self._push((prefijo if i == 0 else " " * len(prefijo)) + linea,
                       10, _TINTA, 2, "F1")

    def tabla(self, filas: List[Dict], columnas: Optional[List[str]] = None,
              max_ancho: int = 30) -> None:
        """Tabla Courier con anchos calculados (recorta celdas largas)."""
        filas = filas or []
        if not filas:
            self.parrafo("(sin datos)")
            return
        if columnas is None:
            columnas = list(filas[0].keys())
        columnas = columnas[:8]

        def celda(fila, col):
            v = fila.get(col, "")
            if isinstance(v, (list, dict)):
                v = "; ".join(str(x) for x in v) if isinstance(v, list) \
                    else str(v)
            texto = _transliterar(str(v if v is not None else ""))
            return texto[:max_ancho]

        anchos = {c: min(max_ancho, max(len(c) + 1,
                  *(len(celda(f, c)) for f in filas))) + 1 for c in columnas}

        def fila_pdf(valores: List[str], negrita: bool) -> None:
            linea = " ".join(v.ljust(anchos[c]) for v, c in zip(valores, columnas))
            self._push(linea.rstrip(), 8.2, _ACENTO if negrita else _TINTA,
                       1.5, "F3" if not negrita else "F2")

        fila_pdf(columnas, True)
        for f in filas:
            fila_pdf([celda(f, c) for c in columnas], False)
        self._espacio(4)

    def guardar(self, ruta) -> Path:
        """Ensambla y escribe el fichero PDF. Devuelve la ruta."""
        self._cerrar_pagina()
        bytes_doc = self._ensamblar()
        ruta = Path(ruta)
        ruta.write_bytes(bytes_doc)
        return ruta

    # ------------------------------------------------------------------
    # Motor de composición
    # ------------------------------------------------------------------
    def _push(self, texto: str, tam: float, color, salto: float, fuente: str) -> None:
        # paginar si no cabe
        if self._y - (tam * 1.35) < MARGEN_INF:
            self._cerrar_pagina()
            self._nueva_pagina()
        x = MARGEN_IZQ
        self._actual.append(
            f"BT /{fuente} {tam:.1f} Tf {color[0]:.2f} {color[1]:.2f} "
            f"{color[2]:.2f} rg 1 0 0 1 {x:.1f} {self._y:.1f} Tm "
            f"({_escapar_pdf(texto)}) Tj ET")
        self._y -= tam + salto

    def _regla(self) -> None:
        y = self._y + 3
        self._actual.append(
            f"{_LINEA[0]:.2f} {_LINEA[1]:.2f} {_LINEA[2]:.2f} RG 0.6 w "
            f"{MARGEN_IZQ:.1f} {y:.1f} m {ANCHO_A4 - MARGEN_DER:.1f} {y:.1f} l S")
        self._y -= 4

    def _espacio(self, puntos: float) -> None:
        self._y -= puntos

    def _nueva_pagina(self) -> None:
        self._actual = []
        self._y = ALTO_A4 - MARGEN_SUP

    def _cerrar_pagina(self) -> None:
        if self._actual or not self._paginas:
            self._paginas.append(self._actual)

    # ------------------------------------------------------------------
    # Envoltura de texto
    # ------------------------------------------------------------------
    @staticmethod
    def _envolver(texto: str, tam: float, ancho_pt: float,
                  factor: float) -> List[str]:
        ancho_car = factor * tam
        max_chars = max(10, int(ancho_pt / ancho_car))
        palabras = texto.split()
        lineas: List[str] = []
        actual = ""
        for palabra in palabras:
            prueba = f"{actual} {palabra}".strip()
            if len(prueba) <= max_chars:
                actual = prueba
            else:
                if actual:
                    lineas.append(actual)
                # palabra larguísima: corta con guion
                while len(palabra) > max_chars:
                    lineas.append(palabra[:max_chars - 1] + "-")
                    palabra = palabra[max_chars - 1:]
                actual = palabra
        if actual:
            lineas.append(actual)
        return lineas or [""]

    # ------------------------------------------------------------------
    # Ensamblado del PDF
    # ------------------------------------------------------------------
    def _ensamblar(self) -> bytes:
        objetos: List[bytes] = []

        n_paginas = len(self._paginas)
        # Numeración de objetos:
        # 1 catálogo, 2 páginas, 3-5 fuentes, página i → obj 6 + 2*i,
        # contenido i → obj 7 + 2*i
        primer_obj_pagina = 6
        hijos = " ".join(f"{primer_obj_pagina + 2 * i} 0 R"
                         for i in range(n_paginas))

        objetos.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objetos.append(
            f"<< /Type /Pages /Kids [{hijos}] /Count {n_paginas} >>".encode())
        objetos.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                       b"/Encoding /WinAnsiEncoding >>")
        objetos.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                       b"/Encoding /WinAnsiEncoding >>")
        objetos.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                       b"/Encoding /WinAnsiEncoding >>")

        for i, contenido in enumerate(self._paginas):
            flujo = "\n".join(contenido).encode("latin-1", errors="replace")
            pie = (f"REDHAVOC - uso exclusivo en pruebas AUTORIZADAS - "
                   f"pagina {i + 1} de {n_paginas}")
            flujo += (f"\nBT /F1 8 Tf {_SUAVE[0]:.2f} {_SUAVE[1]:.2f} {_SUAVE[2]:.2f} "
                      f"rg 1 0 0 1 {MARGEN_IZQ:.1f} {MARGEN_INF - 20:.1f} Tm "
                      f"({_escapar_pdf(pie)}) Tj ET").encode("latin-1")

            obj_pag = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
                       f"{ANCHO_A4:.0f} {ALTO_A4:.0f}] /Resources << /Font "
                       f"<< /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                       f"/Contents {primer_obj_pagina + 1 + 2 * i} 0 R >>").encode()
            objetos.append(obj_pag)
            objetos.append(f"<< /Length {len(flujo)} >>\nstream\n".encode()
                           + flujo + b"\nendstream")

        # xref
        pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for numero, cuerpo in enumerate(objetos, 1):
            offsets.append(len(pdf))
            pdf += f"{numero} 0 obj\n".encode() + cuerpo + b"\nendobj\n"
        inicio_xref = len(pdf)
        pdf += f"xref\n0 {len(objetos) + 1}\n".encode()
        pdf += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            pdf += f"{off:010d} 00000 n \n".encode()
        pdf += (f"trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R >>\n"
                f"startxref\n{inicio_xref}\n%%EOF\n").encode()
        return bytes(pdf)


def informe_a_pdf(ruta_pdf, envoltura: Dict) -> Path:
    """Convierte la envoltura de un informe de módulo en PDF.

    Espeja el contenido que el Reporter escribe en JSON/MD/HTML.
    """
    doc = DocumentoPDF(f"REDHAVOC - {envoltura.get('modulo', 'informe')}")
    doc.titulo_doc(f"REDHAVOC - Informe de modulo")
    doc.meta("Modulo", envoltura.get("modulo", "-"))
    doc.meta("Objetivo", envoltura.get("objetivo", "-"))
    doc.meta("Fecha", envoltura.get("fecha", "-"))

    doc.seccion("Opciones utilizadas")
    opciones = envoltura.get("opciones") or {}
    if opciones:
        doc.tabla([{"Opcion": k, "Valor": str(v)} for k, v in opciones.items()],
                  ["Opcion", "Valor"])
    else:
        doc.parrafo("(sin opciones)")

    doc.seccion("Resultados")
    _render_nodo(doc, envoltura.get("resultados", {}), 0)
    return doc.guardar(ruta_pdf)


def _render_nodo(doc: DocumentoPDF, valor, nivel: int) -> None:
    """Render recursivo de la estructura de resultados (paridad con el MD)."""
    if isinstance(valor, dict):
        for clave, sub in valor.items():
            if isinstance(sub, (dict, list)):
                doc.bullet(f"{clave}:", nivel)
                _render_nodo(doc, sub, nivel + 1)
            else:
                texto = str(sub)
                if len(texto) > 300:
                    texto = texto[:297] + "..."
                doc.bullet(f"{clave}: {texto}", nivel)
    elif isinstance(valor, list):
        if not valor:
            doc.bullet("(vacio)", nivel)
        for item in valor:
            if isinstance(item, (dict, list)):
                _render_nodo(doc, item, nivel + 1)
            else:
                doc.bullet(str(item), nivel)
    else:
        doc.bullet(str(valor), nivel)
