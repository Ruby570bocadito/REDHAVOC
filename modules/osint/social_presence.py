# -*- coding: utf-8 -*-
"""
Módulo osint/social_presence
============================
Búsqueda de un alias/usuario en ~20 plataformas públicas (estilo Sherlock,
idea también presente en Argus como "Social Media Presence").

Comprueba si existe el perfil {PLATAFORMA}/{ALIAS} mediante GET y analiza
código de estado + URL final (algunas plataformas redirigen a "no encontrado"
o devuelven 200 siempre: se marcan como "verificar manualmente").

Riesgo: BAJO (consultas públicas de perfiles, sin contacto con el objetivo).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.base_module import BaseModulo, ModuloError

# plataforma → plantilla de URL de perfil
PLATAFORMAS = {
    "GitHub": "https://github.com/{a}",
    "GitLab": "https://gitlab.com/{a}",
    "Bitbucket": "https://bitbucket.org/{a}/",
    "Reddit": "https://www.reddit.com/user/{a}",
    "X (Twitter)": "https://x.com/{a}",
    "Instagram": "https://www.instagram.com/{a}/",
    "Facebook": "https://www.facebook.com/{a}",
    "TikTok": "https://www.tiktok.com/@{a}",
    "YouTube": "https://www.youtube.com/@{a}",
    "Twitch": "https://www.twitch.tv/{a}",
    "Pinterest": "https://www.pinterest.com/{a}/",
    "Tumblr": "https://{a}.tumblr.com",
    "Medium": "https://medium.com/@{a}",
    "Spotify": "https://open.spotify.com/user/{a}",
    "SoundCloud": "https://soundcloud.com/{a}",
    "Vimeo": "https://vimeo.com/{a}",
    "Flickr": "https://www.flickr.com/people/{a}",
    "Telegram": "https://t.me/{a}",
    "WordPress": "https://{a}.wordpress.com",
    "Slideshare": "https://www.slideshare.net/{a}",
}


def _comprueba(sesion: requests.Session, plataforma: str, plantilla: str,
               alias: str, timeout: int):
    """Devuelve (plataforma, estado, url_final)."""
    url = plantilla.format(a=alias)
    try:
        resp = sesion.get(url, timeout=timeout, allow_redirects=True, verify=False)
    except requests.RequestException:
        return plataforma, "error", url

    final = resp.url.rstrip("/").lower()
    objetivo = url.rstrip("/").lower()

    if resp.status_code == 404:
        return plataforma, "no encontrado", url
    # Redirects a páginas de "usuario no existe" (patrones habituales)
    patrones_noexiste = ("/usernotfound", "/urlgone", "signup", "login", "404", "error")
    if final != objetivo and any(p in final for p in patrones_noexiste):
        return plataforma, "no encontrado", url
    if resp.status_code == 200:
        # Algunas plataformas devuelven 200 siempre → se marca como dudoso
        dudosas = ("LinkedIn", "Instagram", "Facebook", "X (Twitter)", "TikTok")
        if plataforma in dudosas:
            return plataforma, "posible (verificar)", url
        return plataforma, "ENCONTRADO", url
    if resp.status_code in (401, 403):
        return plataforma, "bloqueado (verificar)", url
    return plataforma, f"HTTP {resp.status_code}", url


class SocialPresence(BaseModulo):
    """Busca un alias/usuario en plataformas públicas."""

    NAME = "osint/social_presence"
    CATEGORIA = "osint"
    DESCRIPCION = ("Busca un alias/usuario en ~20 plataformas públicas "
                   "(estilo Sherlock) y clasifica cada hallazgo.")
    RIESGO = "bajo"
    AUTOR = "REDHAVOC"
    REFERENCIA = "sherlock-project/sherlock · jasonxtn/argus (Social Media Presence)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("ALIAS", "", True, "Alias/usuario a buscar (sin @)")
        self.opciones.declarar("EXCLUIR", "", False, "Plataformas a excluir, separadas por coma")

    def ejecutar(self) -> dict:
        alias = self.opt("ALIAS").strip().lstrip("@").replace(" ", "")
        if not alias:
            raise ModuloError("ALIAS vacío")
        timeout = self.opt_int("TIMEOUT", 5) or 5
        hilos = min(self.opt_int("THREADS", 10) or 10, len(PLATAFORMAS))
        excluir = {e.strip().lower() for e in self.opt("EXCLUIR").split(",") if e.strip()}

        sesion = requests.Session()
        sesion.headers.update({"User-Agent": self.opt("USER_AGENT") or
                              "Mozilla/5.0 (X11; Linux x86_64) REDHAVOC"})

        hallazgos = []
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = {pool.submit(_comprueba, sesion, p, t, alias, timeout): p
                       for p, t in PLATAFORMAS.items() if p.lower() not in excluir}
            for futuro in as_completed(futuros):
                plataforma, estado, url = futuro.result()
                hallazgos.append({"plataforma": plataforma, "estado": estado, "url": url})

        encontrados = sorted(
            (h for h in hallazgos if h["estado"].startswith("ENCONTRADO")),
            key=lambda h: h.get("plataforma", ""))
        posibles = sorted(
            (h for h in hallazgos if "posible" in h["estado"]),
            key=lambda h: h.get("plataforma", ""))
        resumen = f"Alias '{alias}': {len(encontrados)} confirmados, {len(posibles)} a verificar"
        return {
            "resumen": resumen,
            "alias": alias,
            "confirmados": encontrados,
            "verificar_manualmente": posibles,
            "todo": sorted(hallazgos, key=lambda h: h["plataforma"]),
        }
