# -*- coding: utf-8 -*-
"""
Módulo web/exposed_files
========================
Comprobación de ficheros y rutas sensibles expuestas en el servidor web
(ideas "Git Repository Exposure Check", "Exposed Environment Files",
"Robots.txt Analyzer" y "Security.txt Check" de Argus).

Cada ruta tiene una firma de contenido para evitar falsos positivos y se
clasifica: CRÍTICO (fuga), INTERESANTE (recon) o INFORMATIVO (buenas
prácticas presentes).

Riesgo: MEDIO (peticiones GET a rutas conocidas).
"""

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ruta → (firma esperada, gravedad, explicación)
FICHEROS = {
    "/.git/HEAD": ("ref: refs/", "CRÍTICO", "Repositorio Git expuesto: descargable con git-dumper"),
    "/.env": (r"(APP_KEY|DB_PASSWORD|AWS_|SECRET)", "CRÍTICO", "Fichero .env con secretos/credenciales"),
    "/.svn/entries": (r"^\d+$", "CRÍTICO", "Repositorio SVN expuesto"),
    "/.DS_Store": ("Bud1", "INTERESANTE", "Índice de directorios de macOS"),
    "/backup.zip": ("PK\x03\x04", "CRÍTICO", "Backup del sitio descargable"),
    "/backup.sql": ("-- MySQL dump", "CRÍTICO", "Volcado de base de datos expuesto"),
    "/db.sql": ("-- MySQL dump", "CRÍTICO", "Volcado de base de datos expuesto"),
    "/site.tar.gz": ("\x1f\x8b", "CRÍTICO", "Backup comprimido descargable"),
    "/phpinfo.php": ("phpinfo()", "INTERESANTE", "phpinfo() expone configuración y rutas"),
    "/info.php": ("phpinfo()", "INTERESANTE", "phpinfo() expone configuración y rutas"),
    "/server-status": ("Apache Server Status", "INTERESANTE", "Estado de Apache accesible"),
    "/composer.json": ("\"require\"", "INTERESANTE", "Dependencias PHP visibles"),
    "/package.json": ("\"dependencies\"", "INTERESANTE", "Dependencias Node visibles"),
    "/.well-known/security.txt": ("Contact:", "INFORMATIVO", "security.txt presente: buena práctica"),
    "/robots.txt": (None, "INFORMATIVO", "robots.txt: lista rutas ocultas declaradas"),
    "/sitemap.xml": ("<urlset", "INFORMATIVO", "Sitemap: inventario de URLs"),
}


class ExposedFiles(BaseModulo):
    """Busca ficheros sensibles expuestos con firmas anti-falso-positivo."""

    NAME = "web/exposed_files"
    CATEGORIA = "web"
    DESCRIPCION = ("Comprueba ficheros sensibles expuestos (.git, .env, backups, "
                   "phpinfo...) con firmas de contenido, además de robots/sitemap.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (Git Exposure / Env Files / Robots / security.txt)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL base del objetivo")

    def ejecutar(self) -> dict:
        base = self.opt("URL").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        timeout = self.opt_int("TIMEOUT", 5) or 5

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})

        import re
        hallazgos = []
        rutas_robots = []
        for ruta, (firma, gravedad, explicacion) in FICHEROS.items():
            try:
                resp = sesion.get(base + ruta, timeout=timeout, verify=False, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code >= 400:
                continue
            cuerpo = resp.text[:100_000]

            if firma is None:                       # solo presencia (robots.txt)
                if ruta == "/robots.txt":
                    rutas_robots = [l.split(":", 1)[1].strip()
                                    for l in cuerpo.splitlines()
                                    if l.lower().startswith("disallow") and ":" in l]
                hallazgos.append({"ruta": ruta, "gravedad": gravedad, "explicacion": explicacion,
                                  "estado": resp.status_code})
                continue

            if firma.startswith("PK") or firma.startswith("\x1f") or firma.startswith("Bud1"):
                coincidencia = cuerpo[:1000].startswith(firma) or firma in cuerpo[:1000]
            else:
                coincidencia = re.search(firma, cuerpo) is not None
            if coincidencia:
                hallazgos.append({"ruta": ruta, "gravedad": gravedad, "explicacion": explicacion,
                                  "estado": resp.status_code})

        criticos = [h for h in hallazgos if h["gravedad"] == "CRÍTICO"]
        resumen = (f"{base}: {len(criticos)} CRÍTICO(s), "
                   f"{len([h for h in hallazgos if h['gravedad'] == 'INTERESANTE'])} interesante(s)")
        return {
            "resumen": resumen,
            "url_base": base,
            "hallazgos": hallazgos,
            "robots_disallow": rutas_robots[:50],
            "recomendacion": ("Bloquea el acceso web a .git/.env/backups (server config), "
                              "retira phpinfo y revisa rutas de robots.txt expuestas."
                              if criticos or rutas_robots else ""),
        }
