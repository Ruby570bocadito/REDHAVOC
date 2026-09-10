# -*- coding: utf-8 -*-
"""
Módulo osint/dork_builder
=========================
Genera un cuaderno de Google/GitHub DORKS personalizadas para el dominio
objetivo (inspirado en dorks-eye, con un cambio profesional importante:
NO scrapea Google — construye las consultas y te deja ejecutarlas a mano
respetando los términos de uso del buscador).

Categorías generadas:
    • Documentos públicos (pdf/docx/xlsx/csv)
    • Directorios indexados (intitle:"index of")
    • Paneles de administración y login
    • Ficheros de configuración y backups (ext:env, ext:sql, ext:bak)
    • Almacenamiento cloud indexado (S3, Azure, GCS)
    • Fugas de código en GitHub (org: "password", "api_key"...)

100% offline: escribe el cuaderno en output/ (MD listo para el informe).

Riesgo: BAJO (no hay red).
ATT&CK: T1593.003 (Search Open Websites/Domains: Code Repositories).
"""

import time
from pathlib import Path
from typing import Dict, List

from core.base_module import BaseModulo, ModuloError


def dorks_para(dominio: str, org: str = "") -> Dict[str, List[str]]:
    """Construye el catálogo de dorks para el dominio (función pura)."""
    dominio = dominio.strip().lower()
    org = (org or dominio.split(".")[0]).strip()
    g = f"site:{dominio}"
    return {
        "Documentos públicos": [
            f'{g} filetype:pdf',
            f'{g} (filetype:docx OR filetype:doc)',
            f'{g} (filetype:xlsx OR filetype:xls OR filetype:csv)',
            f'{g} (filetype:pptx OR filetype:ppt)',
        ],
        "Directorios indexados": [
            f'intitle:"index of" site:{dominio}',
            f'intitle:"index of" site:{dominio} (backup OR dumps OR logs OR conf)',
        ],
        "Paneles de acceso": [
            f'{g} (inurl:admin OR inurl:login OR inurl:signin)',
            f'{g} (inurl:wp-admin OR inurl:phpmyadmin OR inurl:jira)',
        ],
        "Configuración y backups": [
            f'{g} (ext:env OR ext:ini OR ext:conf OR ext:cfg)',
            f'{g} (ext:sql OR ext:bak OR ext:old OR ext:zip OR ext:tar)',
            f'{g} intext:"DB_PASSWORD" OR intext:"api_key"',
        ],
        "Cloud indexado": [
            f's3.amazonaws.com "{org}"',
            f'{g} "storage.googleapis.com"',
            f'{g} "blob.core.windows.net"',
        ],
        "GitHub (código): revisa a mano en github.com/search": [
            f'github.com/{org} "password"',
            f'github.com/{org} "api_key" OR "apikey" OR "secret"',
            f'github.com/{org} "jdbc:" OR "mongodb://" OR "smtp"',
        ],
        "Búsquedas de personas/correos": [
            f'@{dominio} (intext:"@{dominio}") -site:{dominio}',
            f'"{org}" (site:linkedin.com OR site:about.me)',
        ],
    }


class DorkBuilder(BaseModulo):
    """Genera un cuaderno de dorks personalizado (offline)."""

    NAME = "osint/dork_builder"
    CATEGORIA = "osint"
    DESCRIPCION = ("Cuaderno de Google/GitHub dorks para el dominio "
                   "(documentos, backups, paneles, cloud, código) — "
                   "offline, estilo dorks-eye sin scrapear")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "BullsEye0/dorks-eye (concepto) · MITRE T1593.003"
    ATTCK = ("T1593.003",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio objetivo (p. ej. acme.com)")
        self.opciones.declarar(
            "ORG", "", False,
            "Nombre de organización para GitHub/cloud (por defecto: primer dominio)")

    def ejecutar(self) -> dict:
        dominio = self.opt("DOMAIN").strip().lower()
        if not dominio or "." not in dominio:
            raise ModuloError("Indica un dominio válido: set DOMAIN acme.com")
        org = self.opt("ORG").strip() or dominio.split(".")[0]
        catalogo = dorks_para(dominio, org)

        total = sum(len(v) for v in catalogo.values())
        lineas = [
            f"# Cuaderno de dorks — {dominio}",
            "",
            f"Generado por REDHAVOC · {time.strftime('%Y-%m-%d %H:%M')} · "
            f"{total} consultas",
            "",
            "> Ejecuta las consultas A MANO en el buscador (respetando sus "
            "términos); este cuaderno no automatiza búsquedas contra Google.",
            "",
        ]
        for categoria, dorks in catalogo.items():
            lineas.append(f"## {categoria}")
            lineas.append("")
            for d in dorks:
                lineas.append(f"- [ ] `{d}`")
            lineas.append("")

        salida = Path("output")
        salida.mkdir(parents=True, exist_ok=True)
        ruta = salida / f"dorks_{dominio.replace('.', '_')}.md"
        ruta.write_text("\n".join(lineas), encoding="utf-8")

        if self.workspace is not None:
            self.workspace.add_nota(
                f"Dorks generados para {dominio}: {ruta} ({total} consultas)")

        return {
            "resumen": f"{total} dorks para {dominio} en {ruta}",
            "dominio": dominio,
            "organizacion": org,
            "total_dorks": total,
            "fichero": str(ruta),
            "categorias": {cat: len(d) for cat, d in catalogo.items()},
            "ejemplos": [d for lista in list(catalogo.values())[:2] for d in lista][:4],
        }
