# -*- coding: utf-8 -*-
"""
Módulo ad/smb_share_enum
========================
Sondea qué shares SMB existen y cuáles son legibles con las credenciales
del contexto (equivalente ligero a `netexec smb host --shares`). Para cada
nombre de la lista lanza TREE_CONNECT y clasifica:

    LEGIBLE   → el share existe y aceptó la conexión (TREE_CONNECT OK)
    DENEGADO  → existe pero ACCESS_DENIED (STATUS_ACCESS_DENIED)
    NO EXISTE → STATUS_BAD_NETWORK_NAME

El contraste ADMIN$ legible (con credenciales) o IPC$/SYSVOL anónimos
indican configuraciones peligrosas. Cliente SMB2 propio (core.smb_min).

Riesgo: MEDIO ( TREE_CONNECT visible en el log de Samba/Windows).
ATT&CK: T1135 (Network Share Discovery).
"""

from core import smb_min
from core.base_module import BaseModulo, ModuloError
from modules.ad.kerberos_userenum import cargar_lista

# Shares por defecto: administrativos + típicos de_DC + recursos comunes
SHARES_DEFECTO = ("ADMIN$, C$, IPC$, SYSVOL, NETLOGON, print$, "
                  "Users, Public, Compartido, datos, backups")


class SmbShareEnum(BaseModulo):
    """Clasifica shares SMB existentes y legibles con credenciales."""

    NAME = "ad/smb_share_enum"
    CATEGORIA = "ad"
    DESCRIPCION = ("Descubre shares SMB con TREE_CONNECT propio: clasifica "
                   "LEGIBLE / DENEGADO / NO EXISTE (estilo NetExec --shares).")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "NetExec --shares · MITRE ATT&CK T1135"
    ATTCK = ("T1135",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del host / controlador")
        self.opciones.declarar("USUARIO", "", False,
                               "Usuario (vacío = intentar NULL/invitado)")
        self.opciones.declarar("PASSWORD", "", False, "Contraseña del usuario")
        self.opciones.declarar("DOMINIO", "", False, "Dominio NetBIOS (p. ej. CORP)")
        self.opciones.declarar("SHARES", SHARES_DEFECTO, False,
                               "Lista de shares separados por comas o fichero @ruta")
        self.opciones.declarar("PUERTO", "445", False, "Puerto SMB")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        puerto = self.opt_int("PUERTO", 445) or 445
        usuario = self.opt("USUARIO").strip()
        contrasena = self.opt("PASSWORD")
        dominio = self.opt("DOMINIO").strip()
        shares = cargar_lista(self.opt("SHARES"))
        if not shares:
            raise ModuloError("Lista de shares vacía")

        cliente = smb_min.ClienteSMB(host, puerto=puerto,
                                     timeout=self.opt_int("TIMEOUT", 5) or 5)
        try:
            if usuario:
                estado = cliente.iniciar_sesion(usuario, contrasena, dominio)
                if estado != smb_min.NT_SUCCESS:
                    etiqueta = smb_min.ESTADOS_NT.get(estado, f"0x{estado:08X}")
                    raise ModuloError(f"Login fallido para {usuario}: {etiqueta}")

            resultados = [cliente.sondear_share(share) for share in shares]
        finally:
            cliente.cerrar()

        legibles = [r["share"] for r in resultados if r["resultado"] == "LEGIBLE"]
        no_existe = [r["share"] for r in resultados if r["resultado"] == "NO EXISTE"]
        denegados = [r["share"] for r in resultados if r["resultado"] == "DENEGADO"]

        # Evaluación del riesgo
        avisos = []
        if "ADMIN$" in legibles or "C$" in legibles:
            avisos.append("Share administrativo LEGIBLE: ejecución remota posible "
                          "(psexec/WMI) con estas credenciales")
            self.ctx.workspace.add_vuln(
                host, "Share administrativo SMB legible (ADMIN$/C$)", "alto",
                "Con estas credenciales es posible ejecución remota "
                "(psexec/WMI) y volcado de credenciales en memoria (LSASS).",
                self.NAME)
        if not usuario and "IPC$" in legibles:
            avisos.append("IPC$ accesible sin credenciales: enumeración RPC anónima "
                          "posible (T1018/T1087)")
        if "SYSVOL" in legibles and usuario:
            avisos.append("SYSVOL legible: revisar GPP/GPO en busca de cpassword "
                          "(MS14-025) con ad/ldap_enum")

        self.ctx.workspace.add_host(host, notas="SMB shares")
        self.ctx.workspace.add_service(host, puerto, "SMB")

        resumen = (f"{host}: {len(legibles)} legibles · {len(denegados)} denegados "
                   f"· {len(no_existe)} inexistentes"
                   + (f" ({', '.join(legibles)})" if legibles else ""))
        return {
            "resumen": resumen,
            "host": host,
            "usuario": usuario or "(anónimo)",
            "shares": resultados,
            "legibles": legibles,
            "denegados": denegados,
            "no_existe": no_existe,
            "avisos": avisos,
        }
