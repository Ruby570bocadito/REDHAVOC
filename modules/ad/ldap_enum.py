# -*- coding: utf-8 -*-
"""
Módulo ad/ldap_enum
===================
Enumeración de objetos del directorio (usuarios, equipos, grupos, SPNs…)
con un cliente LDAP propio (core.ldap_min) sobre TCP/389. Acepta bind
anónimo o credenciales simples, y un filtro LDAP clásico.

Ideas de: goteo (protocolo LDAP de la suite) · NetExec (ldap) · reconmap.

Riesgo: MEDIO (leer el directorio revela estructura organizativa).
ATT&CK: T1087.002 (Account Discovery: Domain Account).
"""

from core.base_module import BaseModulo, ModuloError
from core import ldap_min


class LdapEnum(BaseModulo):
    """Enumera objetos del directorio Active Directory vía LDAP."""

    NAME = "ad/ldap_enum"
    CATEGORIA = "ad"
    DESCRIPCION = ("Enumera objetos del directorio vía LDAP (usuarios, equipos, "
                   "grupos) con bind anónimo o simple. Cliente LDAP propio.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "goteo (suite propia) · NetExec · MITRE ATT&CK T1087.002"
    ATTCK = ("T1087.002",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio")
        self.opciones.declarar(
            "RHOSTS", "", False,
            "Multi-host estilo NetExec: 10.0.0.0/24, 10.0.0.1-20, n1,n2 o @fichero")
        self.opciones.declarar("BASE_DN", "", True, "Base DN (p. ej. DC=corp,DC=local)")
        self.opciones.declarar("USUARIO", "", False, "Usuario para bind simple (vacío = anónimo)")
        self.opciones.declarar("CLAVE", "", False, "Clave del usuario (vacío = anónimo)")
        self.opciones.declarar("PUERTO", "389", False, "Puerto LDAP (389 claro)")
        self.opciones.declarar("FILTRO", "(objectClass=person)", False,
                               "Filtro LDAP (=, *, &, |, !)")
        self.opciones.declarar("ATRIBUTOS", "sAMAccountName,dn,mail,description", False,
                               "Atributos a devolver, separados por coma")
        self.opciones.declarar("LIMITE", "200", False, "Máximo de objetos a recuperar")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        base_dn = self.opt("BASE_DN").strip()
        filtro = self.opt("FILTRO").strip() or "(objectClass=*)"
        atributos = [a.strip() for a in self.opt("ATRIBUTOS").split(",") if a.strip()]
        puerto = self.opt_int("PUERTO", 389) or 389
        limite = self.opt_int("LIMITE", 200) or 200
        timeout = self.opt_int("TIMEOUT", 5) or 5

        try:
            entradas, aviso = ldap_min.buscar(
                host, base_dn, filtro, atributos,
                usuario=self.opt("USUARIO"), clave=self.opt("CLAVE"),
                puerto=puerto, timeout=timeout, limite=limite)
        except ValueError as err:
            raise ModuloError(f"Filtro LDAP inválido: {err}")
        except PermissionError as err:
            raise ModuloError(str(err))
        except (ConnectionError, OSError) as err:
            raise ModuloError(f"No se pudo hablar LDAP con {host}:{puerto} → {err}")

        # Resumen por tipo de objeto según el atributo pedido
        objetos = []
        for e in entradas:
            fila = {"dn": e["dn"]}
            for atributo, valores in e["atributos"].items():
                fila[atributo.lower()] = valores[0] if len(valores) == 1 else valores
            objetos.append(fila)

        self.ctx.workspace.add_host(host, notas="LDAP")
        self.ctx.workspace.add_service(host, puerto, "LDAP")

        resumen = (f"{host}: {len(objetos)} objetos listados con el filtro {filtro}"
                   + (f" · {aviso}" if aviso else ""))
        return {
            "resumen": resumen,
            "host": host,
            "base_dn": base_dn,
            "filtro": filtro,
            "aviso": aviso,
            "objetos": objetos,
        }
