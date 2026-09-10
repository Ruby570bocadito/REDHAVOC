# -*- coding: utf-8 -*-
"""
core.smb_min
============
Cliente SMB2 mínimo (TCP/445) escrito a mano y sin dependencias,
inspirado en el motor SMB de impacket y en las comprobaciones de NetExec.

Proporciona:
    • NEGOTIATE SMB2/3 (mismo paquete que audita ad/smb_check).
    • SESSION_SETUP con NTLMv2 puro: NTLMSSP type 1/2/3, respuesta
      NTLMv2 (HMAC-MD5 + blob con TargetInfo del servidor).
    • TREE_CONNECT / TREE_DISCONNECT para sondear shares (estilo
      `netexec smb host --shares`).
    • Clase ClienteSMB que encapsula la sesión completa.

Solo cubre el subconjunto estricto que usan los módulos ad/smb_login y
ad/smb_share_enum. Sin firma de paquetes, sin SMB1, sin DFS.
"""

import hmac
import os
import socket
import struct
from datetime import datetime, timezone

from core.base_module import ModuloError

# ---------------------------------------------------------------------------
# Estados NT (subset operacional)
# ---------------------------------------------------------------------------
NT_SUCCESS = 0x00000000
NT_MORE_PROCESSING = 0xC0000016
NT_LOGON_FAILURE = 0xC000006A
NT_PASSWORD_EXPIRED = 0xC0000071
NT_ACCOUNT_DISABLED = 0xC0000072
NT_ACCOUNT_RESTRICTION = 0xC0000074
NT_ACCESS_DENIED = 0xC0000022
NT_BAD_NETWORK_NAME = 0xC00000CC
NT_LOGON_TYPE_NOT_GRANTED = 0xC000015B
NT_ACCOUNT_LOCKED = 0xC0000234
NT_USER_NOT_FOUND = 0xC0000064

ESTADOS_NT = {
    NT_SUCCESS: "correcto",
    NT_MORE_PROCESSING: "continuar (more processing required)",
    NT_LOGON_FAILURE: "credenciales incorrectas",
    NT_PASSWORD_EXPIRED: "contraseña caducada",
    NT_ACCOUNT_DISABLED: "cuenta deshabilitada",
    NT_ACCOUNT_RESTRICTION: "restricción de cuenta (horas/estación)",
    NT_ACCESS_DENIED: "acceso denegado",
    NT_BAD_NETWORK_NAME: "el share no existe",
    NT_LOGON_TYPE_NOT_GRANTED: "tipo de inicio de sesión no concedido",
    NT_ACCOUNT_LOCKED: "cuenta BLOQUEADA (lockout)",
    NT_USER_NOT_FOUND: "usuario no existe",
}

# Dialectos SMB2/3 (reutilizados por ad/smb_check)
DIALECTOS = {
    0x0202: "2.0.2",
    0x0210: "2.1.0",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}

# Flags NTLMSSP que usamos
NTLM_UNICODE = 0x00000001
NTLM_REQUEST_TARGET = 0x00000004
NTLM_NTLM = 0x00000200
NTLM_EXTENDED_SESSIONSECURITY = 0x00080000
NTLM_TARGET_INFO = 0x00800000
NTLM_128 = 0x20000000

# Comandos SMB2
CMD_NEGOTIATE = 0
CMD_SESSION_SETUP = 1
CMD_LOGOFF = 2
CMD_TREE_CONNECT = 3
CMD_TREE_DISCONNECT = 4


# ===========================================================================
# NEGOTIATE (igual que audita ad/smb_check)
# ===========================================================================
def construir_negotiate() -> bytes:
    """SMB2 NEGOTIATE con dialectos 2.0.2…3.1.1 envuelto en NetBIOS (TCP)."""
    cabecera = _cabecera(CMD_NEGOTIATE)
    dialectos = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    cuerpo = struct.pack("<H", 36)           # StructureSize = 36
    cuerpo += struct.pack("<H", len(dialectos))  # DialectCount
    cuerpo += struct.pack("<H", 0x0001)      # SecurityMode: signing enabled
    cuerpo += struct.pack("<H", 0)           # Reserved
    cuerpo += struct.pack("<I", 0x3F)        # Capabilities
    cuerpo += bytes(range(16))               # ClientGuid (lab)
    cuerpo += struct.pack("<I", 0)           # NegotiateContextOffset
    cuerpo += struct.pack("<H", 0)           # NegotiateContextCount
    cuerpo += struct.pack("<H", 0)           # Reserved2
    for d in dialectos:
        cuerpo += struct.pack("<H", d)
    return _netbios(cabecera + cuerpo)


def parsear_negotiate(respuesta: bytes) -> dict:
    """Extrae firma/dialecto/NTLM de la respuesta NEGOTIATE (ad/smb_check)."""
    if len(respuesta) < 4 + 64 + 8:
        raise ModuloError("Respuesta SMB demasiado corta")
    if respuesta[4:8] != b"\xfeSMB":
        raise ModuloError("La respuesta no es SMB2 (¿host sin SMB2?)")
    estado = struct.unpack("<I", respuesta[12:16])[0]
    comando = struct.unpack("<H", respuesta[16:18])[0]
    if estado != 0:
        raise ModuloError(f"Negotiate rechazado (status NT 0x{estado:08X})")
    if comando != 0:
        raise ModuloError("La respuesta no es un NEGOTIATE")
    cuerpo = respuesta[68:]
    estructura, modo_seg, dialecto = struct.unpack("<HHH", cuerpo[:6])
    guid = cuerpo[8:24]
    capacidades, max_trans, max_read, max_write = struct.unpack("<IIII", cuerpo[24:40])
    desplazamiento_seg, largo_seg = struct.unpack("<HH", cuerpo[40:44])
    return {
        "estructura": estructura,
        "firma_activada": bool(modo_seg & 0x01),
        "firma_exigida": bool(modo_seg & 0x02),
        "dialecto": DIALECTOS.get(dialecto, f"0x{dialecto:04X}"),
        "guid": guid.hex(),
        "ntlm": largo_seg > 0,
        "max_read": max_read,
        "max_write": max_write,
    }


# ===========================================================================
# Enmarcado SMB2
# ===========================================================================
def _cabecera(comando: int, creditos: int = 1, session_id: int = 0,
              message_id: int = 0, tree_id: int = 0) -> bytes:
    """Cabecera SMB2 de 64 bytes."""
    return (b"\xfeSMB"
            + struct.pack("<H", 64)         # StructureSize
            + struct.pack("<H", 0)          # CreditCharge
            + struct.pack("<I", 0)          # Status (petición)
            + struct.pack("<H", comando)
            + struct.pack("<H", creditos)
            + struct.pack("<I", 0)          # Flags
            + struct.pack("<I", 0)          # NextCommand
            + struct.pack("<Q", message_id)
            + struct.pack("<I", 0xFEFF)     # ProcessId (cualquiera)
            + struct.pack("<I", tree_id)
            + struct.pack("<Q", session_id)
            + b"\x00" * 16)                 # Signature


def _netbios(mensaje: bytes) -> bytes:
    return struct.pack(">I", len(mensaje)) + mensaje


def estado_de(respuesta: bytes) -> int:
    """Status NT de la respuesta (con prefijo NetBIOS)."""
    if len(respuesta) < 16:
        raise ModuloError("Respuesta SMB demasiado corta")
    return struct.unpack("<I", respuesta[12:16])[0]


def session_id_de(respuesta: bytes) -> int:
    """SessionId del header SMB2 de la respuesta."""
    return struct.unpack("<Q", respuesta[44:52])[0]


def _pares_campos(campos) -> tuple:
    """Serializa una lista de (valor) calculando offsets consecutivos."""
    cabecera_len = 8 + 4 + 8 * len(campos) + 4
    partes, payload = [], b""
    for valor in campos:
        largo = len(valor)
        partes.append(struct.pack("<HHI", largo, largo, cabecera_len + len(payload)))
        payload += valor
    if not payload:
        # los offsets apuntan al final del header igualmente
        partes = [struct.pack("<HHI", 0, 0, cabecera_len) for _ in campos]
    return b"".join(partes), payload


# ===========================================================================
# NTLMSSP: type1 / type2 / type3 con NTLMv2 puro
# ===========================================================================
def construir_type1() -> bytes:
    """NEGOTIATE_MESSAGE (type 1) mínimo con flags de NTLMv2."""
    flags = (NTLM_UNICODE | NTLM_REQUEST_TARGET | NTLM_NTLM |
             NTLM_EXTENDED_SESSIONSECURITY | NTLM_TARGET_INFO | NTLM_128)
    return (b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", flags)
            + struct.pack("<HHI", 0, 0, 32)     # domain vacío
            + struct.pack("<HHI", 0, 0, 32))    # workstation vacío


def parsear_type2(datos: bytes) -> dict:
    """CHALLENGE_MESSAGE (type 2): reto del servidor, flags y TargetInfo."""
    if len(datos) < 48 or datos[:8] != b"NTLMSSP\x00":
        raise ModuloError("Blob NTLMSSP no reconocido (no es type 2)")
    tipo = struct.unpack("<I", datos[8:12])[0]
    if tipo != 2:
        raise ModuloError(f"NTLMSSP type {tipo} inesperado (se esperaba 2)")
    flags = struct.unpack("<I", datos[20:24])[0]
    reto = datos[24:32]
    largo_ti, _, offset_ti = struct.unpack("<HHI", datos[40:48])
    target_info = datos[offset_ti:offset_ti + largo_ti] if largo_ti else b""
    return {"reto": reto, "flags": flags, "target_info": target_info}


def _tiempo_nt() -> int:
    """Timestamp NT (100 ns desde 1601-01-01)."""
    epoca_nt = 11644473600
    return int((datetime.now(timezone.utc).timestamp() + epoca_nt) * 10_000_000)


def respuesta_ntlmv2(nt_hash: bytes, usuario: str, dominio: str, reto: bytes,
                     target_info: bytes, timestamp: int | None = None,
                     reto_cliente: bytes | None = None) -> bytes:
    """Calcula la respuesta NTLMv2 (16 bytes HMAC + blob).

    NTLMv2 hash = HMAC-MD5(NT, upper(user) + domain en UTF-16LE)
    blob        = 01010000 + 00000000 + tiempo(8) + reto_cliente(8) +
                  00000000 + target_info
    respuesta   = HMAC-MD5(ntlmv2_hash, reto + blob) + blob
    """
    if timestamp is None:
        timestamp = _tiempo_nt()
    if reto_cliente is None:
        reto_cliente = os.urandom(8)
    identidad = (usuario.upper() + dominio.upper()).encode("utf-16-le")
    hash_v2 = hmac.new(nt_hash, identidad, "md5").digest()
    blob = (b"\x01\x01\x00\x00" + b"\x00" * 4
            + struct.pack("<Q", timestamp)
            + reto_cliente
            + b"\x00" * 4
            + target_info)
    prueba = hmac.new(hash_v2, reto + blob, "md5").digest()
    return prueba + blob


def construir_type3(usuario: str, dominio: str, reto: bytes, target_info: bytes,
                    nt_hash: bytes, timestamp: int | None = None,
                    reto_cliente: bytes | None = None) -> bytes:
    """AUTHENTICATE_MESSAGE (type 3) con respuesta NTLMv2.

    LM se deja a cero (24 bytes): los servidores NTLMv2 con session
    security extendida lo aceptan (mismo enfoque que smbprotocol).
    """
    flags = (NTLM_UNICODE | NTLM_REQUEST_TARGET | NTLM_NTLM |
             NTLM_EXTENDED_SESSIONSECURITY | NTLM_TARGET_INFO | NTLM_128)
    nt_resp = respuesta_ntlmv2(nt_hash, usuario, dominio, reto, target_info,
                               timestamp, reto_cliente)
    campos = [b"\x00" * 24,          # LM (vacío)
              nt_resp,
              dominio.encode("utf-16-le"),
              usuario.encode("utf-16-le"),
              b"",                  # workstation
              b""]                  # session key
    tabla, payload = _pares_campos(campos)
    return (b"NTLMSSP\x00" + struct.pack("<I", 3) + tabla
            + struct.pack("<I", flags) + payload)


# ===========================================================================
# SESSION_SETUP / TREE_CONNECT
# ===========================================================================
def construir_session_setup(blob: bytes, session_id: int = 0,
                            message_id: int = 0) -> bytes:
    """SESSION_SETUP (Command 1) completo con el blob NTLMSSP indicado."""
    return _netbios(_cabecera(CMD_SESSION_SETUP, session_id=session_id,
                              message_id=message_id) + _cuerpo_setup(blob))


def _blob_de(respuesta: bytes) -> bytes:
    """Extrae el SecurityBuffer de una respuesta SESSION_SETUP."""
    if len(respuesta) < 68 + 8:
        return b""
    _, _, offset, largo = struct.unpack("<HHHH", respuesta[68:76])
    if not largo:
        return b""
    # offset relativo al header SMB2; la respuesta lleva prefijo NetBIOS de 4
    return respuesta[4 + offset:4 + offset + largo]


def construir_tree_connect(host: str, share: str, session_id: int,
                           message_id: int) -> bytes:
    """TREE_CONNECT (Command 3) completo para \\host\\share."""
    return _netbios(_cabecera(CMD_TREE_CONNECT, session_id=session_id,
                              message_id=message_id)
                    + _cuerpo_tree(host, share))


def construir_tree_disconnect(tree_id: int, session_id: int,
                              message_id: int) -> bytes:
    """TREE_DISCONNECT (Command 4)."""
    cabecera = _cabecera(CMD_TREE_DISCONNECT, session_id=session_id,
                         message_id=message_id, tree_id=tree_id)
    cuerpo = struct.pack("<H", 4)        # StructureSize
    cuerpo += struct.pack("<H", 0)       # Reserved
    return _netbios(cabecera + cuerpo)


# ===========================================================================
# Cliente de sesión completa
# ===========================================================================
class ClienteSMB:
    """Sesión SMB2 contra un host: negotiate → login NTLMv2 → tree connects.

    Uso típico (ad/smb_login y ad/smb_share_enum):

        cliente = ClienteSMB("10.0.0.10")
        estado = cliente.iniciar_sesion("usuario", "clave", "CORP")
        if estado == NT_SUCCESS: ...
        estado_share = cliente.sondear_share("SYSVOL")
    """

    def __init__(self, host: str, puerto: int = 445, timeout: int = 5) -> None:
        self.host = host
        self.puerto = puerto
        self.timeout = timeout
        self.session_id = 0
        self.message_id = 0
        self.tree_id = 0
        self.dialecto = ""
        try:
            self.sock = socket.create_connection((host, puerto), timeout=timeout)
        except OSError as err:
            raise ModuloError(f"No se pudo conectar a {host}:{puerto} → {err}")
        self.sock.settimeout(timeout)
        self._negociar()

    # -- transporte --------------------------------------------------------
    def _enviar(self, paquete: bytes) -> bytes:
        """Envía un paquete NetBIOS y lee la respuesta COMPLETA (con el
        prefijo NetBIOS de 4 bytes incluido: todos los parsers lo esperan)."""
        self.sock.sendall(paquete)
        cab = self._recibir_exacto(4)
        largo = struct.unpack(">I", cab)[0]
        return cab + self._recibir_exacto(largo)

    def _recibir_exacto(self, n: int) -> bytes:
        trozos = bytearray()
        while len(trozos) < n:
            trozo = self.sock.recv(n - len(trozos))
            if not trozo:
                break
            trozos.extend(trozo)
        return bytes(trozos)

    def _siguiente(self, comando: int, cuerpo: bytes, tree_id: int = 0) -> bytes:
        self.message_id += 1
        paquete = _cabecera(comando, session_id=self.session_id,
                            message_id=self.message_id, tree_id=tree_id) + cuerpo
        return self._enviar(_netbios(paquete))

    # -- fases -------------------------------------------------------------
    def _negociar(self) -> None:
        respuesta = self._enviar(construir_negotiate())
        info = parsear_negotiate(respuesta)
        self.dialecto = info["dialecto"]
        self.message_id = 1                     # el negotiate fue el mensaje 0→1

    def iniciar_sesion(self, usuario: str, contrasena: str,
                       dominio: str = "") -> int:
        """Autenticación NTLMv2. Devuelve el status NT final.

        NT_SUCCESS → credenciales válidas; NT_LOGON_FAILURE → incorrectas;
        otros códigos describen el estado de la cuenta (ESTADOS_NT).
        """
        respuesta = self._siguiente(CMD_SESSION_SETUP, _cuerpo_setup(construir_type1()))
        estado = estado_de(respuesta)
        if estado != NT_MORE_PROCESSING:
            return estado
        self.session_id = session_id_de(respuesta)
        tipo2 = parsear_type2(_blob_de(respuesta))
        nt_hash = _hash_nt(contrasena)
        tipo3 = construir_type3(usuario, dominio, tipo2["reto"],
                                tipo2["target_info"], nt_hash)
        respuesta2 = self._siguiente(CMD_SESSION_SETUP, _cuerpo_setup(tipo3))
        return estado_de(respuesta2)

    def sondear_share(self, share: str) -> dict:
        """TREE_CONNECT a \\host\\share y desconexión inmediata.

        Devuelve {"share": ..., "estado": int, "resultado": texto}.
        """
        respuesta = self._siguiente(CMD_TREE_CONNECT, _cuerpo_tree(self.host, share))
        estado = estado_de(respuesta)
        if estado == NT_SUCCESS:
            self.tree_id = struct.unpack("<I", respuesta[40:44])[0]
            tipo_share = respuesta[70] if len(respuesta) > 70 else 0
            self._siguiente(CMD_TREE_DISCONNECT, b"\x04\x00\x00\x00",
                            tree_id=self.tree_id)
            clases = {1: "disco", 2: "impresora", 3: "dispositivo", 4: "ipc"}
            return {"share": share, "estado": estado, "resultado": "LEGIBLE",
                    "tipo": clases.get(tipo_share, "?")}
        return {"share": share, "estado": estado,
                "resultado": ("NO EXISTE" if estado == NT_BAD_NETWORK_NAME
                              else "DENEGADO" if estado == NT_ACCESS_DENIED
                              else ESTADOS_NT.get(estado, f"0x{estado:08X}")),
                "tipo": ""}

    def cerrar(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.cerrar()


# ---------------------------------------------------------------------------
# Cuerpos auxiliares (fuera de la clase para testearlos sueltos)
# ---------------------------------------------------------------------------
def _cuerpo_setup(blob: bytes) -> bytes:
    cuerpo = struct.pack("<H", 25) + struct.pack("<B", 0) + struct.pack("<B", 1)
    cuerpo += struct.pack("<I", 0) + struct.pack("<I", 0)
    cuerpo += struct.pack("<H", 88) + struct.pack("<H", len(blob))
    cuerpo += struct.pack("<Q", 0)
    return cuerpo + blob


def _cuerpo_tree(host: str, share: str) -> bytes:
    ruta = f"\\\\{host}\\{share}".encode("utf-16-le")
    return (struct.pack("<H", 9) + struct.pack("<H", 0)
            + struct.pack("<H", 72) + struct.pack("<H", len(ruta)) + ruta)


def _hash_nt(contrasena: str) -> bytes:
    """NT-hash delegando en el MD4 puro de core.krb5 (evita import circular
    pesado: krb5 no importa smb_min)."""
    from core.krb5 import clave_nt
    return clave_nt(contrasena)
