# AVISO LEGAL Y ÉTICO — REDHAVOC

## 1. Propósito

REDHAVOC es un framework de ciberseguridad ofensiva desarrollado con fines
EXCLUSIVAMENTE educativos, de investigación y de auditoría autorizada:

- Pruebas de penetración con **autorización expresa y por escrito** del
  propietario de los sistemas evaluados.
- Práctica en **laboratorios propios** y entornos aislados (máquinas
  virtuales, rangos dedicados tipo HackTheBox/TryHackMe/Labs).
- Formación en ciberseguridad, divulgación y desarrollo de controles
  defensivos.

## 2. Uso prohibido

Queda TERMINANTEMENTE PROHIBIDO utilizar REDHAVOC:

- Contra sistemas, redes o servicios de terceros **sin autorización
  previa, explícita y por escrito**.
- Con ánimo de lucro ilícito, extorsión, sabotaje o daño.
- Para acceder, modificar o destruir datos ajenos.
- Para eludir medidas de seguridad de sistemas que no administras.

El acceso no autorizado a sistemas informáticos constituye delito en la
mayoría de jurisdicciones (por ejemplo, artículos 197 y siguientes del
Código Penal español; Computer Fraud and Abuse Act en EE. UU.; y normas
equivalentes locales).

## 3. Responsabilidad

Los autores y colaboradores de REDHAVOC **no se responsabilizan** del mal
uso de la herramienta ni de los daños derivados de su utilización
indebida. El usuario final asume íntegramente la responsabilidad legal de
sus acciones.

## 4. Salvaguardas técnicas integradas

REDHAVOC incorpora controles para fomentar el uso responsable:

1. **Puerta de aceptación**: el primer arranque exige leer y escribir
   `ACEPTO`; el consentimiento se registra con fecha.
2. **Autorización operacional**: los módulos de riesgo ALTO exigen
   `set AUTHORIZED true` (o la variable de entorno `REDHAVOC_AUTHORIZED=1`),
   declarando el operador bajo su responsabilidad disponer de permisos.
3. **Auditoría**: cada ejecución se registra en `workspace/audit.log`
   (módulo, objetivo, duración).
4. **Cargas inocuas**: las plantillas de payload usan shellcode de
   marcador sin funcionalidad dañina y documentan detección/mitigación.

Estas salvaguardas son disuasorias y trazables, no sustituyen la ley ni la
ética profesional.

## 5. Compromiso del operador

Al usar REDHAVOC declaras que:

- Dispones de los permisos necesarios sobre los sistemas objetivo.
- Respetarás el alcance, la confidencialidad y las reglas de engagement
  acordadas.
- Notificarás cualquier hallazgo de forma responsable.
