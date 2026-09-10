# -*- coding: utf-8 -*-
"""
Módulo dos/stress_http
======================
Prueba de estrés HTTP CONTROLADA para validar la resiliencia de tu propia
infraestructura (o de un entorno con autorización expresa): lanza peticiones
GET concurrentes durante un tiempo acotado y mide latencias, códigos de
respuesta y errores.

Salvaguardas de diseño (NO desactivables):
    • Riesgo ALTO → exige AUTHORIZED=true (además del disclaimer normal).
    • DURACION_MAX = 60 s e HILOS_MAX = 50, tope duro en código.
    • Un único objetivo (URL); sin amplificación ni spoofing.

Métricas devueltas: peticiones enviadas, códigos HTTP recibidos, latencia
media/máxima y tasa de error — el informe típico que se entrega tras una
prueba de carga.

Riesgo: ALTO → exige AUTHORIZED.
"""

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import requests

from core.base_module import BaseModulo, ModuloError

# --- Salvaguardas no negociables ---------------------------------------
DURACION_MAX = 60   # segundos
HILOS_MAX = 50
RPS_MAX = 200       # peticiones por segundo máximas por diseño


class StressHttp(BaseModulo):
    """Prueba de estrés HTTP controlada con métricas de disponibilidad."""

    NAME = "dos/stress_http"
    CATEGORIA = "dos"
    DESCRIPCION = ("Prueba de estrés HTTP CONTROLADA (solo infraestructura "
                   "propia/autorizada): GETs concurrentes acotados por tiempo "
                   "e hilos, con métricas de códigos, latencia y errores.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "DDoS-Ripper (concepto) → versión ética acotada · locust (métricas)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("URL", "", True, "URL objetivo de TU infraestructura")
        self.opciones.declarar("DURACION", "10", False, "Segundos de prueba (máx. 60)")
        self.opciones.declarar("HILOS", "10", False, "Hilos concurrentes (máx. 50)")
        self.opciones.declarar("RPS", "20", False, "Peticiones/seg por hilo (máx. global 200)")

    @staticmethod
    def acotar(duracion: int, hilos: int, rps: int) -> tuple:
        """Aplica los topes duros de diseño. Devuelve (duracion, hilos, rps_hilo)."""
        duracion = max(1, min(duracion, DURACION_MAX))
        hilos = max(1, min(hilos, HILOS_MAX))
        rps_hilo = max(1, min(rps, max(1, RPS_MAX // hilos)))
        return duracion, hilos, rps_hilo

    def ejecutar(self) -> dict:
        url = self.opt("URL").strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        duracion, hilos, rps_por_hilo = self.acotar(
            self.opt_int("DURACION", 10), self.opt_int("HILOS", 10), self.opt_int("RPS", 20))
        pausa = 1.0 / rps_por_hilo
        timeout = min(self.opt_int("TIMEOUT", 5) or 5, 10)

        # Verificación previa: el objetivo debe responder antes de estresar
        try:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": "REDHAVOC-stress/1.0"})
            estado_inicial = resp.status_code
        except requests.RequestException as err:
            raise ModuloError(f"El objetivo no responde antes de la prueba: {err}")

        alto = Event()
        codigos: Counter = Counter()
        errores: list = [0]
        latencias: list = []
        _lock = __import__("threading").Lock()

        def trabajador():
            sesion = requests.Session()
            sesion.headers["User-Agent"] = "REDHAVOC-stress/1.0"
            while not alto.is_set():
                inicio = time.time()
                try:
                    r = sesion.get(url, timeout=timeout)
                    with _lock:
                        codigos[r.status_code] += 1
                        latencias.append(time.time() - inicio)
                except requests.RequestException:
                    with _lock:
                        errores[0] += 1
                # ritmo: rps_por_hilo + restante de pausa
                demora = pausa - (time.time() - inicio)
                if demora > 0:
                    time.sleep(demora)

        fin_en = time.time() + duracion
        with ThreadPoolExecutor(max_workers=hilos) as pool:
            futuros = [pool.submit(trabajador) for _ in range(hilos)]
            while time.time() < fin_en:
                time.sleep(0.25)
            alto.set()
            for f in futuros:
                f.result()

        total = sum(codigos.values()) + errores[0]
        lat_media = (sum(latencias) / len(latencias) * 1000) if latencias else 0.0
        lat_max = (max(latencias) * 1000) if latencias else 0.0
        resumen = (f"Estrés {url} — {total} peticiones en {duracion}s "
                   f"({total / duracion:.1f} req/s), {errores[0]} errores")

        return {
            "resumen": resumen,
            "url": url,
            "duracion_s": duracion,
            "hilos": hilos,
            "peticiones_enviadas": total,
            "codigos_http": dict(codigos),
            "errores_red": errores[0],
            "latencia_media_ms": round(lat_media, 1),
            "latencia_max_ms": round(lat_max, 1),
            "estado_inicial": estado_inicial,
            "aviso": "Resultado orientativo; usa herramientas dedicadas (k6/locust) "
                     "para pruebas de carga formales.",
        }
