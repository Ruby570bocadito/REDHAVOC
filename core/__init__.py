# -*- coding: utf-8 -*-
"""
Paquete principal de REDHAVOC.
Contiene la consola, gestor de módulos, opciones, reportería y ética.
"""

import warnings


def silenciar_insecure_request() -> None:
    """Suprime el aviso InsecureRequestWarning de urllib3.

    Una herramienta ofensiva habla con muchos TLS sin verificar (laboratorios,
    paneles internos): el aviso ensuciaría la consola profesional. Se llama
    una vez al importar el paquete (y los tests la ejercitan directamente).
    """
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    except Exception:  # pragma: no cover — urllib3 ausente (imposible con requests)
        pass


silenciar_insecure_request()

__version__ = "2.3.0"
__nombre__ = "REDHAVOC"
__eslogan__ = "Red Team Havoc Framework"
__autor__ = "Proyecto REDHAVOC"
