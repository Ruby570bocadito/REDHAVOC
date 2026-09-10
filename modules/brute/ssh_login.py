# -*- coding: utf-8 -*-
"""
Módulo brute/ssh_login
======================
Auditoría de credenciales débiles sobre SSH mediante paramiko.

paramiko es una dependencia OPCIONAL: si no está instalada el módulo
devuelve un error limpio explicando cómo instalarla
    pip install paramiko
y no rompe el framework.

Riesgo: ALTO → exige AUTHORIZED. Guarda los aciertos en el workspace.
"""

from core.base_module import BaseModulo, ModuloError
from modules.brute import claves_desde_listas, usuarios_desde_listas

try:
    import paramiko  # type: ignore
    PARAMIKO_OK = True
except ImportError:  # pragma: no cover - depende del entorno
    PARAMIKO_OK = False


class SshLogin(BaseModulo):
    """Prueba pares usuario/clave contra un servicio SSH."""

    NAME = "brute/ssh_login"
    CATEGORIA = "brute"
    DESCRIPCION = ("Auditoría de credenciales débiles/default en SSH (paramiko "
                   "opcional). Para servidores propios o autorizados. Guarda "
                   "los aciertos en el workspace.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "hydra ssh · thc-hydra (acotado)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Host SSH objetivo (IP o dominio)")
        self.opciones.declarar("PORT", "22", False, "Puerto SSH")
        self.opciones.declarar("USERS", "root,admin,ubuntu,pi,usuario", False,
                               "Wordlist de usuarios incluida, ruta o lista CSV")
        self.opciones.declarar("PASS", "claves_lab.txt", False,
                               "Wordlist de claves incluida, ruta o lista CSV")
        self.opciones.declarar("MAX_INTENTOS", "30", False, "Máximo de pares a probar")

    def ejecutar(self) -> dict:
        if not PARAMIKO_OK:
            raise ModuloError("paramiko no está instalado. Instálalo con: pip install paramiko")

        host = self._objetivo_host(self.opt("TARGET"))
        puerto = self.opt_int("PORT", 22)
        timeout = self.opt_int("TIMEOUT", 5) or 5
        max_intentos = max(1, min(self.opt_int("MAX_INTENTOS", 30), 100))

        usuarios = usuarios_desde_listas(self.opt("USERS"), max_intentos)
        claves = claves_desde_listas(self.opt("PASS"), max_intentos)
        if not usuarios or not claves:
            raise ModuloError("No se han resuelto usuarios o claves de las listas")

        # Banner SSH del servidor
        import socket
        try:
            with socket.create_connection((host, puerto), timeout=timeout) as sock:
                banner = sock.recv(128).decode(errors="replace").strip()
        except OSError as err:
            raise ModuloError(f"No se puede conectar a {host}:{puerto} — {err}")
        if not banner.startswith("SSH-"):
            raise ModuloError(f"{host}:{puerto} no parece un servicio SSH (banner: '{banner[:40]}')")

        probados = 0
        validos = []
        cliente = paramiko.SSHClient()
        cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            for usuario in usuarios:
                for clave in claves:
                    if probados >= max_intentos:
                        break
                    probados += 1
                    try:
                        cliente.connect(host, port=puerto, username=usuario,
                                        password=clave, timeout=timeout,
                                        allow_agent=False, look_for_keys=False)
                    except paramiko.AuthenticationException:
                        continue          # credencial rechazada
                    except (paramiko.SSHException, OSError) as err:
                        raise ModuloError(f"Error de conexión SSH: {err}")
                    # Autenticación correcta
                    validos.append({"usuario": usuario, "clave": clave})
                    self._registrar_credencial(host, usuario, clave)
                    cliente.close()
                    break
                if validos or probados >= max_intentos:
                    break
        finally:
            try:
                cliente.close()
            except Exception:  # noqa: BLE001
                pass

        return {
            "resumen": (f"SSH {host}:{puerto} — {probados} pares probados, "
                        f"{len(validos)} válidos"),
            "host": host,
            "puerto": puerto,
            "banner": banner[:100],
            "pares_probados": probados,
            "credenciales_validas": validos,
        }

    def _registrar_credencial(self, host: str, usuario: str, clave: str) -> None:
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)
        if db is not None:
            try:
                db.add_cred(host, usuario, clave, servicio="ssh")
            except Exception:  # noqa: BLE001
                pass
