# -*- coding: utf-8 -*-
"""
Módulo ad/spn_enum
==================
Enumeración de Service Principal Names vía LDAP: los SPN revelan qué
cuentas ejecutan servicios (MSSQL, HTTP, cifs…) y por tanto qué cuentas
son objetivo de Kerberoasting (T1558.003) en el siguiente paso.

Cliente LDAP propio (core.ldap_min). Ideas de: GetUserSPNs.py (impacket)
· goteo (LDAP de la suite).

Riesgo: MEDIO (lectura del directorio).
ATT&CK: T1087.002 · T1046 (discovery de servicios).
"""

from core.base_module import BaseModulo, ModuloError
from core import ldap_min


class SpnEnum(BaseModulo):
    """Lista cuentas con servicePrincipalName desde el directorio."""

    NAME = "ad/spn_enum"
    CATEGORIA = "ad"
    DESCRIPCION = ("Enumera cuentas con SPN vía LDAP (prepara Kerberoasting): "
                   "qué servicios corren bajo qué cuentas. Cliente LDAP propio.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "impacket GetUserSPNs · MITRE ATT&CK T1558.003 (fase previa)"
    ATTCK = ("T1087.002", "T1046")

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio")
        self.opciones.declarar("BASE_DN", "", True, "Base DN (p. ej. DC=corp,DC=local)")
        self.opciones.declarar("USUARIO", "", False, "Usuario para bind simple (vacío = anónimo)")
        self.opciones.declarar("CLAVE", "", False, "Clave del usuario (vacío = anónimo)")
        self.opciones.declarar("PUERTO", "389", False, "Puerto LDAP")
        self.opciones.declarar("LIMITE", "200", False, "Máximo de objetos a recuperar")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        base_dn = self.opt("BASE_DN").strip()
        puerto = self.opt_int("PUERTO", 389) or 389
        limite = self.opt_int("LIMITE", 200) or 200
        timeout = self.opt_int("TIMEOUT", 5) or 5

        try:
            entradas, aviso = ldap_min.buscar(
                host, base_dn, "(servicePrincipalName=*)",
                ["sAMAccountName", "servicePrincipalName", "memberOf"],
                usuario=self.opt("USUARIO"), clave=self.opt("CLAVE"),
                puerto=puerto, timeout=timeout, limite=limite)
        except ValueError as err:
            raise ModuloError(f"Filtro LDAP inválido: {err}")
        except PermissionError as err:
            raise ModuloError(str(err))
        except (ConnectionError, OSError) as err:
            raise ModuloError(f"No se pudo hablar LDAP con {host}:{puerto} → {err}")

        cuentas = []
        for e in entradas:
            spns = e["atributos"].get("servicePrincipalName", [])
            if not spns:
                continue
            sam = e["atributos"].get("sAMAccountName", ["?"])[0]
            cuentas.append({"usuario": sam, "spns": spns, "dn": e["dn"]})

        total_spn = sum(len(c["spns"]) for c in cuentas)
        self.ctx.workspace.add_host(host, notas="LDAP SPN")
        self.ctx.workspace.add_service(host, puerto, "LDAP")

        return {
            "resumen": (f"{host}: {len(cuentas)} cuentas con SPN "
                        f"({total_spn} SPN en total)" + (f" · {aviso}" if aviso else "")),
            "host": host,
            "base_dn": base_dn,
            "cuentas": cuentas,
            "aviso": aviso,
            "siguiente_paso": ("Con una cuenta válida puedes pedir TGS de esos SPN "
                               "(Kerberoasting, T1558.003) y crackearlos offline."),
        }
