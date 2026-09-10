# -*- coding: utf-8 -*-
"""
Paquete dos — pruebas de estrés / disponibilidad.

ÉTICA Y LEGALIDAD
-----------------
Los ataques de denegación de servicio contra sistemas de terceros son
ILEGALES en la mayoría de jurisdicciones. Los módulos de esta categoría
existen ÚNICAMENTE para validar la resiliencia de TU propia infraestructura
o de sistemas con autorización expresa (pruebas de carga controladas).

Salvaguardas impuestas por diseño:
    • Riesgo ALTO → el framework exige AUTHORIZED=true.
    • Tope duro de duración (60 s) e hilos (50), no configurable.
    • Una sola URL objetivo; sin generación de tráfico masivo.
"""
