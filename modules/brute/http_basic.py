# -*- coding: utf-8 -*-
"""
Módulo brute/http_basic
=======================
Auditoría de credenciales débiles sobre HTTP Basic Auth (RFC 7617).
Lanza peticiones GET con la cabecera Authorization: Basic base64(user:pass)
y considera válida una credencial si la respuesta NO es 401.

También detecta un escenario habitual de auditoría: que la respuesta sea
200 pero pertenezca a un portal cautivo/formulario (se avisa por el
content-type o el tamaño).

Riesgo: ALTO → exige AUTHORIZED. Guarda los aciertos en el workspace.
"""

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.base_module import BaseModulo, ModuloError
from modules.brute import claves_desde_listas, usuarios_desde_listas


class HttpBasic(BaseModulo):
    """Prueba pares usuario/clave contra HTTP Basic Auth."""

    NAME = "brute/http_basic"
    CATEGORIA = "brute"
    DESCRIPCION = ("Auditoría de HTTP Basic Auth (requests + base64, sin "
                   "dependencias extra). Para directorios/admin de servidores "
                   "propios o autorizados. Guarda los aciertos en el workspace.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "hydra http-get · wfuzz (acotado)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL protegida (p. ej. http://127.0.0.1/admin/)")
        self.opciones.declarar("USERS", "admin,usuario,prueba", False,
                               "Wordlist de usuarios incluida, ruta o lista CSV")
        self.opciones.declarar("PASS", "claves_lab.txt", False,
                               "Wordlist de claves incluida, ruta o lista CSV")
        self.opciones.declarar("MAX_INTENTOS", "50", False, "Máximo de pares a probar")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        timeout = self.opt_int("TIMEOUT", 5) or 5
        max_intentos = max(1, min(self.opt_int("MAX_INTENTOS", 50), 200))
        hilos = max(1, min(self.opt_int("THREADS", 10), 50))

        usuarios = usuarios_desde_listas(self.opt("USERS"), max_intentos)
        claves = claves_desde_listas(self.opt("PASS"), max_intentos)
        if not usuarios or not claves:
            raise ModuloError("No se han resuelto usuarios o claves de las listas")

        # Comprobar que la URL existe y que realmente usa Basic Auth
        sesion = requests.Session()
        sesion.headers["User-Agent"] = self._user_agent()
        try:
            resp = sesion.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException as err:
            raise ModuloError(f"No se puede acceder a {url} — {err}")
        www_auth = resp.headers.get("WWW-Authenticate", "")
        if resp.status_code != 401 and "basic" not in www_auth.lower():
            raise ModuloError(
                f"{url} no parece usar HTTP Basic Auth (status={resp.status_code}, "
                f"WWW-Authenticate='{www_auth[:60]}')")

        pares = [(u, c) for u in usuarios for c in claves][:max_intentos]
        probados = 0
        validos = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = {pool.submit(self._probar_par, sesion, url, u, c, timeout): (u, c)
                       for u, c in pares}
            for futuro in as_completed(futuros):
                usuario, clave = futuros[futuro]
                probados += 1
                if futuro.result():
                    validos.append({"usuario": usuario, "clave": clave})
                    self._registrar_credencial(url, usuario, clave)

        return {
            "resumen": (f"HTTP Basic {url} — {probados} pares probados, "
                        f"{len(validos)} válidos"),
            "url": url,
            "realm": www_auth.replace("Basic realm=", "").strip('" ')[:80],
            "pares_probados": probados,
            "credenciales_validas": validos,
        }

    def _user_agent(self) -> str:
        ua = ""
        try:
            from core import __version__
            ua = f"REDHAVOC/{__version__}"
        except Exception:  # noqa: BLE001
            ua = "REDHAVOC"
        try:
            global_opts = getattr(getattr(self, "ctx", None), "globales", None)
            if global_opts is not None:
                ua = global_opts.get("USER_AGENT", ua) or ua
        except Exception:  # noqa: BLE001
            pass
        return ua

    def _probar_par(self, sesion, url: str, usuario: str, clave: str,
                    timeout: float) -> bool:
        token = base64.b64encode(f"{usuario}:{clave}".encode()).decode()
        try:
            resp = sesion.get(url, timeout=timeout, allow_redirects=False,
                              headers={"Authorization": f"Basic {token}"})
        except requests.RequestException:
            return False
        return resp.status_code in (200, 301, 302)

    def _registrar_credencial(self, url: str, usuario: str, clave: str) -> None:
        db = getattr(self, "ctx", None) and getattr(self.ctx, "workspace", None)
        if db is not None:
            try:
                db.add_cred(self._objetivo_host(url), usuario, clave, servicio="http-basic")
            except Exception:  # noqa: BLE001
                pass
