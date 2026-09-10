# Informe Ejecutivo de Pentest — {{ORGANIZACION}}

> Plantilla de informe ejecutivo (REDHAVOC v1.4). Rellena los marcadores
> `{{...}}` con los datos de la operación. El público objetivo es dirección
> técnica/CISO: sin jerga de herramientas, foco en riesgo y decisiones.

- **Cliente**: {{ORGANIZACION}}
- **Operación**: {{NOMBRE_ENGAGEMENT}}
- **Fechas**: {{FECHA_INICIO}} — {{FECHA_FIN}} (kill-date: {{KILL_DATE}})
- **Autor de la prueba**: {{TESTER}} ({{EQUIPO}})
- **Alcance autorizado**: {{ALCANCE_RESUMEN}}
- **Referencia de informe detallado**: {{RUTA_REPORTE_JSON}}

---

## 1. Resumen ejecutivo

Durante el periodo de la prueba se realizó una evaluación ofensiva del
alcance autorizado, combinando reconocimiento, explotación controlada y
escenarios de movimiento lateral{{ESCENARIO_EXTRA}}. En total se
**confirmaron {{TOTAL_HALLAZGOS}} hallazgos**, de los cuales
{{CRITICOS}} son de gravedad crítica y {{ALTOS}} de gravedad alta.

El riesgo agregado del entorno se valora como **{{RIESGO_GLOBAL}}**
{{JUSTIFICACION_RIESGO}}. Los vectores iniciales observados dependen
principalmente de {{VECTOR_PRINCIPAL}}, lo que indica que las medidas de
prevención existentes {{VALORACION_CONTROLES}}.

## 2. Métricas clave

| Métrica | Valor |
|---|---|
| Hosts identificados | {{HOSTS}} |
| Servicios descubiertos | {{SERVICIOS}} |
| Hallazgos confirmados | {{TOTAL_HALLAZGOS}} |
| — Críticos | {{CRITICOS}} |
| — Altos | {{ALTOS}} |
| — Medios/Bajos | {{MEDIOS_BAJOS}} |
| Credenciales expuestas | {{CREDS}} |
| Phishing (clics/entregas) | {{PHISHING_METRICAS}} |

## 3. Top hallazgos (resumen)

| # | Severidad | Hallazgo | Impacto de negocio | Recomendación corta |
|---|---|---|---|---|
| 1 | {{SEV_1}} | {{HALLAZGO_1}} | {{IMPACTO_1}} | {{RECOMENDACION_1}} |
| 2 | {{SEV_2}} | {{HALLAZGO_2}} | {{IMPACTO_2}} | {{RECOMENDACION_2}} |
| 3 | {{SEV_3}} | {{HALLAZGO_3}} | {{IMPACTO_3}} | {{RECOMENDACION_3}} |
| 4 | {{SEV_4}} | {{HALLAZGO_4}} | {{IMPACTO_4}} | {{RECOMENDACION_4}} |
| 5 | {{SEV_5}} | {{HALLAZGO_5}} | {{IMPACTO_5}} | {{RECOMENDACION_5}} |

## 4. Impacto en negocio

- {{IMPACTO_NEGOCIO_1}}
- {{IMPACTO_NEGOCIO_2}}
- {{IMPACTO_NEGOCIO_3}}

## 5. Priorización de remediación (30 / 60 / 90 días)

- **Inmediato (0-7 días)**: {{ACCION_INMEDIATA}}
- **30 días**: {{ACCION_30}}
- **60 días**: {{ACCION_60}}
- **90 días**: {{ACCION_90}}

## 6. Metodología y límites

Se siguió un enfoque de *adversary emulation* mapeado a MITRE ATT&CK
{{TECNICAS_PRINCIPALES}}, con las restricciones del engagement
(engagement.json, sin fuera de alcance, kill-date {{KILL_DATE}}).
La prueba se limitó a {{LIMITACIONES}}; los resultados no garantizan la
ausencia de vulnerabilidades fuera del alcance autorizado.

## 7. Agradecimientos y cierre

Se agradece la colaboración del equipo de IT de {{ORGANIZACION}} durante
la operación. Los datos sensibles generados (credenciales, hashes, tokens)
han sido {{DISPOSICION_DATOS}} al finalizar la prueba.
