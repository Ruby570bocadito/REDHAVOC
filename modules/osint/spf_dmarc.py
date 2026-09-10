# -*- coding: utf-8 -*-
"""
Módulo osint/spf_dmarc
======================
Validación de la configuración anti-spoofing de correo de un dominio:
SPF, DKIM y DMARC (idea "SPF / DKIM / DMARC Validator" de Argus, y
"Email Config").

Usa el cliente DNS TXT propio de REDHAVOC (recon/dns_enum) — sin
dependencias externas.

Evalúa:
    • SPF: existencia, sintaxis base, "all" permisivo (+all / ?all)
    • DMARC: existencia, política (none/quarantine/reject) y porcentaje
    • DKIM: sondas de selectores habituales (default, google, selector1...)

Riesgo: BAJO (consultas DNS).
"""

from core.base_module import BaseModulo
from modules.recon.dns_enum import _consultar, _parsear_respuesta, TIPOS


def _txt(resolver: str, nombre: str, timeout: int) -> list:
    """Consulta TXT a través del cliente DNS propio y une cadenas."""
    try:
        paquete = _consultar(resolver, nombre, TIPOS["TXT"], timeout)
        return _parsear_respuesta(paquete, TIPOS["TXT"])["respuestas"]
    except Exception:  # noqa: BLE001 — DNS caído = registro ausente
        return []


class SpfDmarc(BaseModulo):
    """Valida la postura anti-spoofing (SPF/DKIM/DMARC) de un dominio."""

    NAME = "osint/spf_dmarc"
    CATEGORIA = "osint"
    DESCRIPCION = ("Valida SPF, DMARC y selectores DKIM de un dominio con el "
                   "cliente DNS propio. Detecta políticas permisivas.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "jasonxtn/argus (SPF / DKIM / DMARC Validator)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("DOMAIN", "", True, "Dominio de correo objetivo")
        self.opciones.declarar("SELECTORES_DKIM", "default,google,selector1,selector2,k1,mail,s1", False,
                               "Selectores DKIM a sondear, separados por coma")

    def _analiza_spf(self, registros: list) -> dict:
        spf = next((r for r in registros if r.lower().startswith("v=spf1")), None)
        if not spf:
            return {"presente": False, "problema": "Sin SPF: cualquier servidor puede suplantar el dominio"}
        permisivo = ("+all" in spf) or ("?all" in spf)
        return {
            "presente": True,
            "registro": spf,
            "politica_all": ("PERMISIVA (+all/?all)" if permisivo else "restrictiva"),
            "problema": ("SPF con all permisivo: no protege contra suplantación" if permisivo else ""),
        }

    def _analiza_dmarc(self, resolver: str, dominio: str, timeout: int) -> dict:
        registros = _txt(resolver, f"_dmarc.{dominio}", timeout)
        dmarc = next((r for r in registros if r.lower().startswith("v=dmarc1")), None)
        if not dmarc:
            return {"presente": False, "problema": "Sin DMARC: los receptores no saben qué hacer con suplantaciones"}
        politica = "none"
        for clave in ("p=reject", "p=quarantine", "p=none"):
            if clave in dmarc.lower():
                politica = clave.split("=")[1]
                break
        return {
            "presente": True,
            "registro": dmarc,
            "politica": politica,
            "problema": ("DMARC p=none: solo monitoriza, no bloquea" if politica == "none" else ""),
        }

    def _sondea_dkim(self, resolver: str, dominio: str, selectores: list, timeout: int) -> dict:
        encontrados = []
        for selector in selectores:
            nombre = f"{selector}._domainkey.{dominio}"
            registros = _txt(resolver, nombre, timeout)
            if registros:
                encontrados.append({"selector": selector, "registro": registros[0][:200]})
        return {
            "selectores_probados": len(selectores),
            "encontrados": encontrados,
            "problema": ("" if encontrados else
                         "Ningún selector DKIM habitual publicado (puede ser correcto o no usar DKIM)"),
        }

    def ejecutar(self) -> dict:
        dominio = self._objetivo_host(self.opt("DOMAIN"))
        timeout = self.opt_int("TIMEOUT", 5) or 5

        resolver = self.opt("RESOLVER")
        if not resolver:
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as fh:
                    for linea in fh:
                        if linea.startswith("nameserver"):
                            resolver = linea.split()[1]
                            break
            except OSError:
                pass
            resolver = resolver or "1.1.1.1"

        spf = self._analiza_spf(_txt(resolver, dominio, timeout))
        dmarc = self._analiza_dmarc(resolver, dominio, timeout)
        selectores = [s.strip() for s in self.opt("SELECTORES_DKIM").split(",") if s.strip()]
        dkim = self._sondea_dkim(resolver, dominio, selectores, timeout)

        problemas = [d["problema"] for d in (spf, dmarc, dkim) if d.get("problema")]
        if not problemas:
            resumen = f"{dominio}: SPF y DMARC correctos, DKIM OK"
        else:
            resumen = f"{dominio}: {len(problemas)} problema(s) de configuración de correo"

        return {
            "resumen": resumen,
            "dominio": dominio,
            "resolver": resolver,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "problemas": problemas,
        }
