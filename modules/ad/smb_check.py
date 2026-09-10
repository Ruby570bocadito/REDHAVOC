# -*- coding: utf-8 -*-
"""
Módulo ad/smb_check
===========================
Comprueba la negociación SMB2 de un host Windows: dialecto máximo,
si exige firma SMB (SecurityMode), ServerGuid y soporte NTLM.
Un DC que NO exige firma es candidato a ataque de relevo NTLM
(T1557.001/2), por eso este check es básico en cualquier engagement AD.

Implementación: cliente SMB2 NEGOTIATE mínimo en TCP/445 (core.smb_min,
sin libs).
Ideas de: NetExec (smb signing) · CrackMapExec.

Riesgo: MEDIO (solo NEGOTIATE; no autentica).
ATT&CK: T1046 (Network Service Discovery).
"""

import socket
import struct

from core.base_module import BaseModulo, ModuloError
from core.smb_min import DIALECTOS, construir_negotiate, parsear_negotiate  # noqa: F401


class SmbCheck(BaseModulo):
    """Audita la configuración SMB2 de un host (firma, dialecto, NTLM)."""

    NAME = "ad/smb_check"
    CATEGORIA = "ad"
    DESCRIPCION = ("Comprueba la negociación SMB2/3 de un host: firma exigida, "
                   "dialecto máximo, ServerGuid y soporte NTLM (riesgo de relevo). "
                   "Cliente SMB2 mínimo propio.")
    RIESGO = "medio"
    AUTOR = "REDHAVOC"
    REFERENCIA = "NetExec (smb signing) · MITRE ATT&CK T1557 (relevo NTLM)"
    ATTCK = ("T1046", "T1557.001")

    def definir_opciones(self) -> None:
        self.opciones.declarar("RHOST", "", True, "IP o nombre del host / controlador")
        self.opciones.declarar("PUERTO", "445", False, "Puerto SMB (445 directo)")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("RHOST"))
        puerto = self.opt_int("PUERTO", 445) or 445
        timeout = self.opt_int("TIMEOUT", 5) or 5

        paquete = construir_negotiate()
        try:
            sock = socket.create_connection((host, puerto), timeout=timeout)
        except OSError as err:
            raise ModuloError(f"No se pudo conectar a {host}:{puerto} → {err}")
        try:
            sock.settimeout(timeout)
            sock.sendall(paquete)
            cab = sock.recv(4)
            if len(cab) < 4:
                raise ModuloError("El host cerró la conexión durante el negotiate")
            largo = struct.unpack(">I", cab)[0]
            cuerpo_resp = b""
            while len(cuerpo_resp) < largo:
                trozo = sock.recv(largo - len(cuerpo_resp))
                if not trozo:
                    break
                cuerpo_resp += trozo
        finally:
            sock.close()

        info = parsear_negotiate(cab + cuerpo_resp)

        # Evaluación defensiva del resultado
        if not info["firma_exigida"]:
            riesgo = ("FIRMA NO EXIGIDA: el host aceptaría sesiones sin firmar → "
                      "riesgo real de relevo NTLM (T1557) en redes no segmentadas")
            self.ctx.workspace.add_vuln(
                host, "SMB firma no exigida (relevo NTLM posible)", "alto",
                riesgo, self.NAME)
        elif not info["firma_activada"]:
            riesgo = "Firma negociable pero no activada: revisar GPO"
        else:
            riesgo = "Firma SMB exigida: relevo NTLM mitigado a este nivel"

        self.ctx.workspace.add_host(host, notas=f"SMB {info['dialecto']}")
        self.ctx.workspace.add_service(host, puerto, "SMB")

        return {
            "resumen": (f"{host}: SMB {info['dialecto']} · firma "
                        f"{'EXIGIDA' if info['firma_exigida'] else 'NO exigida'} · "
                        f"NTLM {'sí' if info['ntlm'] else 'no'}"),
            "host": host,
            **info,
            "evaluacion": riesgo,
        }
