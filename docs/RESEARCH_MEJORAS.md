# REDHAVOC — Investigación de mejora y razonamiento técnico

> Estudio interno previo a la iteración v2.3. Compara REDHAVOC v2.2.0 con los
> proyectos de referencia actuales y justifica, con razonamiento, qué mejorar,
> qué pulir y qué implementar después. Fecha: 2026-09.

---

## 1. Metodología

Para decidir qué mejorar no bastan las ganas: hay que medir contra quien marca el
estándar. Se han elegido **seis referentes** con un criterio explícito — son las
herramientas que un operador real pone en la mesa cuando juzga un framework
consola-msf en Python, y cubren los cuatro planos en los que REDHAVOC compite
(ejecución, datos, técnicas, producto):

| # | Referente | Por qué se estudia |
|---|-----------|--------------------|
| 1 | **NetExec** (sucesor de CrackMapExec) | El estándar de oro de la ejecución contra redes grandes: multi-host, una línea de resultado por host, base de datos integrada. En 2025 añadió RDP y mantiene módulos de coerción (PetitPotam, DFSCoerce, PrinterBug, MSEven, ShadowCoerce). Es el espejo natural de nuestra categoría `ad`. |
| 2 | **Metasploit Framework** | El modelo de consola que REDHAVOC imita. Sus diferencias residuales (jobs, loot, pivoting, metadata de módulos con rank/referencias/CVE) son exactamente las expectativas que trae todo usuario nuevo. |
| 3 | **Sliver / Mythic / Havoc** | Los C2 open source de referencia: sesiones interactivas *vs* beacons asíncronos, multi-protocolo, pivoting (SOCKS/portfwd), loot y almacén de credenciales. Definen el techo de lo que la comunidad espera de la post-explotación. |
| 4 | **Osmedeus v5 / Recon-ng** | La orquestación es el siguiente paso natural de un framework de módulos: workflows declarativos (YAML auditable en Osmedeus 5), encadenamiento de módulos y base de datos que se rellena sola. |
| 5 | **Certipy y el ecosistema AD 2021-2025** | ADCS (ESC1-ESC8), coerción y relay son la superficie AD más citada de la última media década. Certipy demuestra que la enumeración ADCS es viable 100% sobre LDAP. |
| 6 | **Reporting moderno (pwndoc, PentestPad, informes BreachLock 2025)** | El estándar de un entregable profesional: CVSS por hallazgo, evidencia, remediación, resumen ejecutivo + sección técnica, mapeo ATT&CK. Un informe sin esto se percibe amateur. |

Método de contraste: para cada capacidad de los referentes se comprobó su
presencia en el código real de REDHAVOC (no en el README): `core/workspace_db.py`,
`core/base_module.py`, `core/framework.py` y el inventario de 79 módulos.

---

## 2. Inventario verificado de REDHAVOC v2.2.0

Lo que **ya existe** (verificado en código, no en documentación):

- **Consola msf-like**: `search` con filtros `cat:`/`riesgo:`, `use <n>`,
  `set`/`setg`/`unset`, `show options`, `run`, `back`, TAB-completion real,
  historial persistente, `resource` (.rc), `plugin` (instalación Git con revisión).
- **79 módulos** en 12 categorías: recon (10), web (19), osint (13), ad (12),
  phishing (5), payloads (3), post (2), opsec (3), brute (4), iot (3), cloud (4),
  dos (1).
- **AD con clientes propios**: Kerberos (AS-REQ/TGS-REQ), LDAP/BER, SMB2/NTLMv2,
  AES-256 puro; kerberoast + crackeo offline, AS-REP, spray con canario,
  enum de shares, GPP cpassword, RootDSE, LLMNR pasivo.
- **Workspace**: hosts/servicios, creds, vulns, notas; workspaces múltiples;
  opciones persistentes; export JSON/CSV/MD/PDF; audit consultable.
- **Gobernanza**: engagement con scope + kill-date que bloquea `run` fuera de
  alcance; puerta ética; mapa MITRE ATT&CK; motor de consejos accionables.
- **Calidad**: 484 tests en verde, suite sin red, E2E con PTY real.

Lo que **no existe** (huecos detectados en código): sin `RHOSTS` multi-host,
sin jobs en segundo plano, sin `loot`, sin CVSS/remediación/evidencia en vulns,
sin ADCS, sin detección de coerción, sin WinRM, sin workflows, sin CI.

---

## 3. Qué hace cada referente y qué aprendemos

### 3.1 NetExec — la lección es multi-host, no AD

NetExec no gana por saber más Kerberos que nadie: gana porque **un solo comando
abarca una red entera** y cada host produce una línea coloreada
(`SMB 10.0.0.1 445 DC01 [*] Windows Server 2022...`) que a su vez alimenta una base
de datos. REDHAVOC tiene protocolos AD muy sólidos (NTLMv2 propio, shares,
kerberoast con crackeo integrado) pero **todos los módulos apuntan a un único
TARGET/RHOST**: contra una /24, el operador tendría que repetir `set`+`run` 254
veces. Este es el hueco de mayor impacto de todo el estudio porque su solución
multiplica el valor de los 79 módulos existentes de golpe.

Aprendizajes concretos: expansión CIDR/rangos/`@archivo` → lista de hosts;
paralelismo con `THREADS`; salida de una línea por host con estado
(`[+]`/`[-]`/`[*]`); relleno automático del workspace por host.

### 3.2 Metasploit — jobs, loot y metadata

Frente a msfconsole faltan tres piezas estructurales, no cosméticas:

1. **Jobs**: en msf, `run -j` manda el módulo a segundo plano (`jobs`, `kill <id>`).
   Hoy en REDHAVOC `run` bloquea la consola (salvo el listener que se interrumpe
   con Ctrl+C). Sin jobs no se puede hacer "arranco el handler y mientras tanto
   escaneo".
2. **Loot**: msf y los C2 distinguen *datos recolectados* (hashes, cookies,
   volcados, capturas) de credenciales y vulnerabilidades. REDHAVOC genera
   artefactos valiosos (hashes 13100/18200, cookies del relay_proxy, capturas de
   la campaña de phishing) que hoy viven solo en la salida del módulo.
3. **Metadata de módulos**: rank, referencias y CVEs en `info`. Barato de añadir
   y aporta seriedad instantánea (y permite el consejo "lee el advisory").

El pivoting (route/portfwd) existe en msf y en los C2, pero es el hueco más caro;
va al apartado de visión a futuro.

### 3.3 C2 (Sliver/Mythic/Havoc) — techo de post-explotación

REDHAVOC ya tiene el esqueleto (multi_handler con TLS, sesiones interactivas,
`background`, `sessions -k all`). De los C2 tomamos tres ideas *alcanzables*:
`sessions -x "<cmd>"` para ejecutar sin entrar en modo interactivo; `loot` como
almacén centralizado por host; y la idea (para el roadmap) de beacons asíncronos
y pivoting SOCKS. Lo que **no** copiamos: cifrado evasivo, generación de implants
ofuscados — Sliver/Mythic lo hacen bien y no es nuestro niche ni encaja con el
DISCLAIMER educativo.

### 3.4 Osmedeus v5 / Recon-ng — orquestación declarativa

Osmedeus 5 convierte los pipelines en **YAML auditable**: definir "flujo recon"
como una lista de pasos (módulo + opciones + inyección de resultados del paso
anterior) es exactamente lo que falta para que REDHAVOC pase de "79 módulos
sueltos" a "playbooks ejecutables". Recon-ng añade el precedente de DB que se
rellena sola y de generación de reporte final desde la DB — nuestra DB ya existe;
falta la capa de encadenamiento. El riesgo es bajo porque puede construirse
encima de `resource` (que ya ejecuta guiones) añadiendo **inyección de datos**.

### 3.5 Certipy / AD 2021-2025 — ADCS es el hueco técnico más citado

La enumeración de ADCS es viable con puro LDAP: leer la configuración de servicios
(`CN=Enrollment Services`), plantillas (`CN=Certificate Templates`), sus flags
(`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, EKUs, permisos de enrolamiento) y computar
las condiciones de ESC1/ESC2/ESC8 es **solo lectura** — encaja perfecto con
nuestro `core/ldap_min.py` existente y con el espíritu "detector, no explotador".
Ídem la detección de superficie de coerción: sondear si los pipes `efsrpc` /
`spoolss` / `lsarpc` están expuestos en IPC$ con nuestro cliente SMB (detección
pasiva de superficie, sin forzar callbacks). Estos dos módulos sitúan a la
categoría `ad` a la altura de lo que se pide en 2025-2026.

### 3.6 Reporting moderno — CVSS, remediación, evidencia

Los generadores líderes (pwndoc, PentestPad, el estándar de los informes de
BreachLock 2025) comparten esqueleto: cada hallazgo con **CVSS v3.1**, vector,
**remediación** concreta, **evidencia** adjunta, y el informe en resumen
ejecutivo + detalle técnico + mapeo ATT&CK. REDHAVOC ya tiene informe en
JSON/MD/HTML/PDF (generador puro, logro real) y mapeo ATT&CK, pero sus hallazgos
solo llevan severidad textual. Añadir CVSS+remediación+evidencia es la diferencia
entre "salida de herramienta" y "entregable de auditoría".

---

## 4. Matriz de huecos (gap analysis)

| # | Hueco | Referente | Estado REDHAVOC | Valor operador | Coste estimado |
|---|-------|-----------|-----------------|----------------|----------------|
| G1 | RHOSTS multi-host (CIDR/@archivo) + línea por host | NetExec | ❌ solo TARGET único | ★★★★★ | Medio |
| G2 | Jobs en segundo plano (`run -j`, `jobs`, `kill`) | Metasploit | ❌ run bloquea | ★★★★ | Medio |
| G3 | Loot (artefactos capturados por host) | msf / C2 | ❌ solo creds/vulns | ★★★★ | Bajo-medio |
| G4 | CVSS + remediación + evidencia en hallazgos | Reporting | ❌ severidad textual | ★★★★★ | Medio |
| G5 | ADCS: enum de plantillas + detección ESC | Certipy | ❌ | ★★★★ | Medio-alto |
| G6 | Detección de coerción (pipes IPC$) | NetExec | ❌ | ★★★ | Medio |
| G7 | WinRM (SOAP) check + exec autenticado | NetExec | ❌ | ★★★ | Medio |
| G8 | Workflows YAML (encadenar módulos) | Osmedeus | ❌ (solo `resource`) | ★★★★ | Medio |
| G9 | Metadata de módulos (referencias/CVE) en `info` | msf | ❌ | ★★ | Bajo |
| G10 | Comando `services` dedicado | msf | ⚠️ datos sí, comando no | ★★ | Bajo |
| G11 | `sessions -x` (ejecutar comando en sesión) | msf / C2 | ❌ | ★★ | Bajo |
| G12 | CI (GitHub Actions) + badge de tests | Producto | ❌ (prometido en roadmap) | ★★ | Bajo |
| G13 | README desactualizado (tablas dicen 73; son 79; faltan 6 módulos en tablas) | Producto | ⚠️ | ★★ (credibilidad) | Bajo |
| G14 | Verbose por módulo | Producto | ❌ (prometido) | ★★ | Bajo |
| G15 | Pivoting (portfwd/SOCKS) · beacons · relay SMB | msf / C2 | ❌ | ★★★ | Alto |

---

## 5. Propuestas priorizadas (con razonamiento)

### P0 — Pulido inmediato (coste bajo, confianza alta, v2.3)

1. **G13 — README/MODULES al día**: un README que dice 73 en las tablas y 79 en
   las features resta credibilidad en la primera impresión (y GitHub es la carta
   de presentación). Añadir las 6 fichas que faltan (redis_enum, snmp_enum,
   graphql_probe, crlf_scan, k8s_enum, rootdse_enum).
2. **G12 — CI con badge**: `.github/workflows/ci.yml` con `compileall` + `pytest`
   sobre Python 3.9-3.12; badge en el README. Es lo más barato que hay y el
   badge verde es señal de seriedad instantánea para todo visitante.
3. **G9 + G10 + G11 — paridad barata**: referencias/CVE en módulos (`info`),
   comando `services`, `sessions -x`. Cada una es una tarde corta y suman msf-parity.
4. **Test de cobertura de consejos**: garantizar que **todos** los 79 módulos
   producen "siguientes pasos" (extiende la garantía actual, que solo valida que
   los `use X` citados existen). Cierra el círculo de la feature estrella.

### P1 — El salto de paridad (el corazón de v2.3/v2.4)

5. **G1 — RHOSTS multi-host** *(la mejora nº 1 del estudio)*. Diseño:
   opción especial `RHOSTS` (CIDR, `a.b.c.d-e`, `@archivo`, coma) expandida por
   el framework; el módulo declara `MULTI_HOST = True` y el core itera hosts con
   `THREADS`, capturando el resultado por host para pintar la línea estilo
   NetExec (`[+] 10.0.0.5:445 — firma exigida`) y rellenar el workspace.
   Razonamiento: multiplica el valor de TODOS los módulos existentes sin tocar
   su lógica (los módulos pasan de "ejecuto una vez" a "me llaman por host"),
   y es la primera pregunta que hará cualquier usuario de NetExec que pruebe
   REDHAVOC. Empieza por `ad/smb_check`, `ad/smb_login`, `ad/smb_share_enum`,
   `ad/passwd_spray`, `brute/*` y `recon/port_scanner`.
6. **G2 — Jobs**: `run -j` en background con `jobs`/`jobs -k <id>`; los jobs
   escriben en el workspace con el mismo reporter. Permite el patrón real
   "handler en background + escaneo en foreground".
7. **G3 — Loot**: tabla `loot` (tipo, host, ruta del artefacto, nota) + comando
   `loot` + guardado automático en `output/loot/` desde kerberoast/asreproast
   (hashes), relay_proxy (cookies), campaign_server (capturas) y export md/json/pdf.
8. **G4 — Informe de nivel auditoría**: campo CVSS v3.1 (vector + base score
   calculada) y `remediacion` en `add_vuln`; el reporter del PDF pasa a tener
   resumen ejecutivo con distribución de severidad, ficha por hallazgo con
   evidencia (ruta a artefacto) y mapeo ATT&CK. Razonamiento: es lo que separa
   un informe amateur de uno audit-ready según el estándar 2025-2026.

### P2 — Nuevas capacidades ofensivas de laboratorio (v2.5)

9. **G5 — `ad/adcs_enum`**: LDAP read-only de CA + plantillas; detecta ESC1
   (`ENROLLEE_SUPPLIES_SUBJECT` + EKU client-auth + derechos de enrolamiento),
   ESC2 (Any Purpose/SubCA) y ESC8 (enrolamiento NTLM en endpoints web).
   Reutiliza `ldap_min`; hallazgo alto con remediación incluida.
10. **G6 — `ad/coerce_check`**: sondeo de pipes (`efsrpc`, `spoolss`, `lsarpc`)
    sobre IPC$ con nuestro SMB; superficie de coerción PetitPotam/PrinterBug
    marcada como hallazgo medio. Detección pasiva, sin provocar callbacks.
11. **G7 — `post/winrm_check` + `post/winrm_exec`**: WinRM es SOAP sobre HTTP;
    un cliente mínimo puro es viable (el mismo enfoque que ya hicimos con SMB/
    LDAP/Kerberos). `exec` solo con AUTHORIZED y engagement cargado.
12. **G8 — Workflows YAML**: `workflow run recetas/recon_completo.yaml` — lista
    de pasos `use/set/run` con inyección de resultados previos (ej.: los hosts
    con 445 del paso 1 alimentan `smb_check` del paso 2). Reutiliza el motor de
    `resource` + la DB. Recetas incluidas: `recon_completo`, `web_basico`,
    `ad_inicial`.

### P3 — Visión a futuro (declarar, no comprometer)

13. **G15**: pivoting básico (portfwd sobre sesión TCP), beacons asíncronos del
    agente de lab, relay SMB→LDAP de laboratorio (firmando `smb_check` como
    prerrequisito ya existente), grafo AD estilo BloodHound-lite exportable a
    JSON desde `ldap_enum`.

### Qué NO haremos (razonamiento negativo)

- **Exploits reales, evasión AV/AMSI, obfuscación de implants**: conflicto directo
  con el DISCLAIMER educativo, coste legal/ético y de mantenimiento altísimo,
  y ya cubierto por proyectos especializados.
- **C2 evasivo completo**: no es el niche (REDHAVOC = orquestador de evaluación
  con cadenas protocolo puro), y los C2 mencionados son imbatibles ahí.
- **Dependencias obligatorias o APIs con clave**: rompería "puro Python +
  rich/requests", la filosofía que hizo viables 79 módulos y 484 tests sin red.
- **IA externa en el informe**: dependencia de red + fuga potencial de datos del
  engagement; los consejos deterministas ya cubren la guía del operador.

---

## 6. Plan de ejecución propuesto

| Versión | Tema | Contenido |
|---------|------|-----------|
| **v2.3.0 — Pulido y paridad** | P0 + arranque de P1 | README al día, CI+badge, referencias/CVE, `services`, `sessions -x`, test de consejos total, **RHOSTS multi-host** en 8-10 módulos estrella, jobs |
| **v2.4.0 — Auditoría y loot** | resto de P1 | Loot + guardado automático, CVSS/remediación/evidencia en informe PDF, RHOSTS al resto de módulos |
| **v2.5.0 — AD 2025 y orquestación** | P2 | adcs_enum, coerce_check, winrm_check/exec, workflows YAML con recetas |

Criterio de aceptación transversal (no negociable): suite en verde sin red,
E2E con PTY de cada flujo nuevo, capturas regeneradas si cambia la UI, ZIP
≤ 50 MB, token de GitHub jamás commiteado.

---

## 7. Fuentes consultadas

- NetExec wiki y releases (netexec.wiki; github.com/Pennyw0rth/NetExec) — soporte
  SMB/LDAP/MSSQL/WinRM/SSH/RDP/WMI/FTP/NFS; módulos de coerción (2025-2026).
- Metasploit Unleashed / Rapid7 — jobs, resource scripts, sesiones, irb.
- BishopFox "Top Red Team Tools & C2 Frameworks 2025"; Red Canary Threat
  Detection Report (C2); Immersive Labs (Havoc); Team Cymru (Mythic).
- Osmedeus v5 (j3ssie/osmedeus) — orquestación declarativa YAML auditable;
  Recon-ng — DB + reportes.
- Certipy / PetitPotam / Optiv / Truesec / adsecurity.org — ADCS ESC1-ESC8 y
  superficie de coerción.
- MITRE ctid (ATT&CK↔CVE), PentestPad 2026, BreachLock 2025 — estándar de
  reporting (CVSS, evidencia, remediación, resumen ejecutivo).
