# -*- coding: utf-8 -*-
"""
Módulo web/cookie_audit
=======================
Audita los atributos de las cookies de una URL (Set-Cookie de la respuesta
y cookies de sesión):

    • Secure     → sin él la cookie viaja por HTTP en claro (T1557/OWASP A02)
    • HttpOnly   → sin él un XSS puede robar la sesión (T1185 en la práctica)
    • SameSite   → sin él CSRF / relevo entre sitios (T1185/CWE-1275)
    • __Host-    → prefijo mal usado (Secure/Path=/ obligatorios)
    • Expiración → cookies de sesión largas o _Max-Age_ excesivo

Riesgo: BAJO (peticiones GET normales, sin credenciales).
ATT&CK: T1557.001 (Adversary-in-the-Middle) · OWASP A05.
"""

import requests

from core.base_module import BaseModulo, ModuloError

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def auditar_cookie(nombre: str, valor: str, atributos: dict) -> dict:
    """Evalúa una cookie y devuelve su ficha de riesgo (función pura).

    `atributos`: dict normalizado en minúsculas con claves secure, httponly,
    samesite, maxage, expires, path, domain.
    """
    problemas = []
    if not atributos.get("secure"):
        problemas.append("sin Secure: puede viajar por HTTP en claro")
    if not atributos.get("httponly"):
        problemas.append("sin HttpOnly: robo de sesión por XSS")
    samesite = (atributos.get("samesite") or "").lower()
    if not samesite:
        problemas.append("sin SameSite: CSRF posible")
    elif samesite == "none" and not atributos.get("secure"):
        problemas.append("SameSite=None sin Secure: la rechazan los navegadores "
                         "y además es insegura")
    if nombre.startswith("__Host-"):
        if not atributos.get("secure") or atributos.get("path") != "/":
            problemas.append("prefijo __Host- exige Secure y Path=/")
        if atributos.get("domain"):
            problemas.append("prefijo __Host- no debe llevar Domain")
    try:
        maxage = int(atributos.get("maxage") or 0)
    except ValueError:
        maxage = 0
    if maxage > 7776000:  # 90 días
        problemas.append(f"Max-Age muy largo ({maxage}s > 90 días)")
    return {
        "nombre": nombre,
        "valor": (valor[:4] + "…" + valor[-4:]) if len(valor) > 10 else valor,
        "secure": bool(atributos.get("secure")),
        "httponly": bool(atributos.get("httponly")),
        "samesite": samesite or "(vacío)",
        "max_age": maxage,
        "problemas": problemas,
        # sin Secure (o prefijo __Host- mal usado) → alto: intercepción pasiva;
        # sin HttpOnly/SameSite o Max-Age largo → medio (necesitan otro vector)
        "riesgo": ("alto" if any(
            ("claro" in p or "__Host-" in p or "insegura" in p) for p in problemas)
            else "medio" if problemas else "ok"),
    }


def parsear_set_cookie(cabecera: str) -> dict:
    """Convierte una cabecera Set-Cookie en (nombre, valor, atributos).

    Función pura testeada sin red. Los atributos se normalizan a minúsculas.
    """
    fragmentos = [f.strip() for f in cabecera.split(";")]
    if not fragmentos or "=" not in fragmentos[0]:
        return None
    par = fragmentos[0].split("=", 1)
    atributos = {}
    for fragmento in fragmentos[1:]:
        if "=" in fragmento:
            k, v = fragmento.split("=", 1)
        else:
            k, v = fragmento, "true"        # flags: Secure, HttpOnly…
        k = k.strip().lower()
        atributos[k] = v.strip()
    return {"nombre": par[0].strip(), "valor": par[1].strip(),
            "atributos": atributos}


class CookieAudit(BaseModulo):
    """Audita atributos Secure/HttpOnly/SameSite de las cookies del objetivo."""

    NAME = "web/cookie_audit"
    CATEGORIA = "web"
    DESCRIPCION = ("Audita cookies del objetivo: Secure, HttpOnly, SameSite, "
                   "prefijos __Host-, Max-Age excesivo. Clasifica por cookie.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "OWASP Secure Cookie Attributes · MDN Set-Cookie"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo que fija cookies")
        self.opciones.declarar("SEGUIR", "false", False,
                               "Seguir redirecciones antes de leer las cookies")

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        timeout = self.opt_int("TIMEOUT", 5) or 5

        try:
            resp = requests.get(url, timeout=timeout, verify=False,
                                allow_redirects=self.opt_bool("SEGUIR", False),
                                headers={"User-Agent": self.opt("USER_AGENT") or "REDHAVOC"})
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde: {err}")

        fichas, ya_vistas = [], set()
        # 1) Set-Cookie explícitos de la respuesta (pueden repetirse)
        for cabecera in resp.headers.get("Set-Cookie", "").split("\n"):
            cabecera = cabecera.strip()
            if not cabecera:
                continue
            cruda = parsear_set_cookie(cabecera)
            if cruda is None or cruda["nombre"] in ya_vistas:
                continue
            ya_vistas.add(cruda["nombre"])
            fichas.append(auditar_cookie(cruda["nombre"], cruda["valor"],
                                         cruda["atributos"]))
        # 2) Jar de la sesión (cookies que requests ya aceptó)
        for cookie in resp.cookies:
            if cookie.name in ya_vistas:
                continue
            ya_vistas.add(cookie.name)
            atributos = {
                "secure": "secure" if cookie.secure else "",
                "httponly": "httponly" if getattr(cookie, "_rest", {}).get("HttpOnly")
                            or getattr(cookie, "_rest", {}).get("httponly") else "",
                "samesite": getattr(cookie, "_rest", {}).get("SameSite", ""),
                "path": cookie.path or "",
                "domain": cookie.domain or "",
            }
            fichas.append(auditar_cookie(cookie.name, cookie.value or "", atributos))

        malas = [f for f in fichas if f["riesgo"] in ("alto", "medio")]
        # Cookies de riesgo alto → workspace.vulns
        for f in fichas:
            if f["riesgo"] == "alto":
                self.ctx.workspace.add_vuln(
                    url.split("//")[-1].split("/")[0],
                    f"Cookie {f['nombre']} con atributos inseguros", "alto",
                    "; ".join(f["problemas"]), self.NAME)
        resumen = (f"{url}: {len(fichas)} cookie(s) auditadas · {len(malas)} con "
                   f"problemas" if fichas else f"{url}: sin cookies fijadas")
        return {
            "resumen": resumen,
            "url": url,
            "cookies": fichas,
            "problematicas": [f["nombre"] for f in malas],
            "consejo": ("Añade Secure; HttpOnly y SameSite=Lax/Strict a las "
                        "cookies de sesión (Set-Cookie: …; Secure; HttpOnly; "
                        "SameSite=Lax)") if malas else "",
        }
