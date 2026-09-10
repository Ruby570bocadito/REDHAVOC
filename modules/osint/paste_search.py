# -*- coding: utf-8 -*-
"""
Módulo osint/paste_search
=========================
Búsqueda del dominio/empresa en pastebins públicos (psbdmp.ws): los
pastes que mencionan el dominio suelen contener credenciales filtradas,
listas de correos de empleados o conversaciones internas filtradas.

Ideas de: reconmap (módulo psbdmp) · mailrecon.
Riesgo: BAJO (consulta pública).
ATT&CK: T1596.005 (Search Open Technical Databases).
"""

import requests

from core.base_module import BaseModulo, ModuloError

API_BUSCAR = "https://psbdmp.ws/api/search/{termino}"


class PasteSearch(BaseModulo):
    """Busca pastes públicos que mencionen el término objetivo."""

    NAME = "osint/paste_search"
    CATEGORIA = "osint"
    DESCRIPCION = ("Busca pastes públicos (psbdmp.ws) que mencionen el dominio o "
                   "empresa: credenciales filtradas, correos internos, conversaciones.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "reconmap (psbdmp) · MITRE ATT&CK T1596.005"
    ATTCK = ("T1596.005",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Dominio o término a buscar")
        self.opciones.declarar("LIMITE", "10", False, "Máximo de pastes a recuperar")

    def ejecutar(self) -> dict:
        termino = self.opt("TARGET").strip()
        if not termino:
            raise ModuloError("TARGET vacío")
        limite = self.opt_int("LIMITE", 10) or 10
        timeout = self.opt_int("TIMEOUT", 15) or 15
        cabeceras = {"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"}

        try:
            resp = requests.get(API_BUSCAR.format(termino=termino),
                                timeout=timeout, headers=cabeceras)
        except requests.RequestException as err:
            raise ModuloError(f"Consulta psbdmp falló: {err}")
        if resp.status_code != 200:
            raise ModuloError(f"psbdmp respondió HTTP {resp.status_code}")
        try:
            datos = resp.json()
        except ValueError as err:
            raise ModuloError(f"psbdmp devolvió JSON inválido: {err}")

        ids = datos.get("data") or []
        if isinstance(ids, dict):
            ids = list(ids.keys())
        ids = [str(i) for i in ids][:limite]

        pastes = []
        for pid in ids:
            try:
                detalle = requests.get(f"https://psbdmp.ws/api/paste/{pid}",
                                       timeout=timeout, headers=cabeceras)
                if detalle.status_code != 200:
                    continue
                cuerpo = detalle.json()
            except (requests.RequestException, ValueError):
                continue
            texto = str(cuerpo.get("text") or "")
            coincidencias = [linea.strip()[:200] for linea in texto.splitlines()
                             if termino.lower() in linea.lower()]
            pastes.append({
                "id": pid,
                "url": f"https://psbdmp.ws/{pid}",
                "coincidencias": coincidencias[:5],
                "bytes": len(texto),
            })

        return {
            "resumen": (f"psbdmp '{termino}': {len(ids)} pastes indexados, "
                        f"{sum(1 for p in pastes if p['coincidencias'])} con coincidencias"),
            "termino": termino,
            "total_indexado": len(ids),
            "pastes": pastes,
            "nota": "Un paste con credenciales del dominio es un hallazgo CRÍTICO "
                    "para el informe (rotación inmediata).",
        }
