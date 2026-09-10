# Changelog — REDHAVOC

Todos los cambios notables de REDHAVOC se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.0] — 2026-09-10 (protocolos nuevos: Redis · SNMP · GraphQL · CRLF · contenedores · RootDSE)

### Added
- **6 módulos nativos nuevos (73 → 79)**, todos con cliente de protocolo
  propio (sin herramientas externas) y funciones de clasificación puras:
  - **`recon/redis_enum`** — enumera instancias Redis por RESP propio sobre
    socket TCP (PING/INFO/DBSIZE de solo lectura): SIN_AUTH / PROTEGIDA /
    NO_REDIS. Una Redis sin contraseña es hallazgo alto automático.
  - **`recon/snmp_enum`** — agente SNMP v2c con codificación ASN.1 BER
    hecha a mano (sin dependencias) y decodificador de GET-RESPONSE:
    prueba comunidades típicas y lee sysDescr/sysName/sysUpTime/sysLocation.
  - **`web/graphql_probe`** — descubre endpoints GraphQL en 14 rutas
    típicas, sonda de introspección mínima (`__schema.queryType`) y
    detección de playgrounds (GraphiQL/Altair/Apollo). Introspección
    abierta = hallazgo medio automático.
  - **`web/crlf_scan`** — sondeo de inyección CRLF / HTTP Response
    Splitting con 3 variantes (%0d%0a clásico, doble-codificado y
    reflejado-en-cuerpo) y cabecera canaria; distingue inyección
    confirmada de reflejo sin confirmar.
  - **`cloud/k8s_enum`** — audita planos de control de contenedores sin
    credenciales: Kubernetes API (6443, /version y /api/v1/pods), kubelet
    (10250, /pods) y Docker API (2375, /version y /containers/json).
    Puertos configurables (PUERTO_K8S/KUBELET/DOCKER).
  - **`ad/rootdse_enum`** — RootDSE anónima por LDAP con el cliente
    propio: naming contexts, DN base del dominio y niveles funcionales
    (traduce el entero a "Windows Server 2016/2019/2022/2025"). Es el
    prerequisite de `ad/ldap_enum` y deja el DN en el workspace.
- **Consejos accionables para los 6 módulos nuevos** en `core/advice.py`:
  Redis SIN_AUTH → requirepass/TLS; comunidad SNMP válida → mapeo de red;
  introspección GraphQL → exportar esquema y BOLA; CRLF confirmado →
  envenenado de caché; plano anónimo → RBAC/2375; RootDSE → `ad/ldap_enum`
  con el DN descubierto.
- **30 tests nuevos** (`tests/test_v22.py`, total de la suite: 484):
  laboratorios reales en localhost para cada protocolo — mini-Redis RESP,
  mini-agente SNMP UDP, servidor HTTP para GraphQL/CRLF/k8s — más tests
  puros de clasificadores y del decoder SNMP (round-trip codificar→decodificar).

### Fixed
- Bug de decodificación SNMP: el request-id se leía dos veces y el parser
  se saltaba la lista de varbinds (detectado por el round-trip del test).
- Normalización de mayúsculas en `clasificar_respuesta` (Redis) y en el
  reflejo del canario CRLF; ambos fallaban con respuestas mixtas.

## [2.1.0] — 2026-09-10 (roadmap completado · cloud · PDF · plugins · relay)

### Added
- **Roadmap completado al 100 %** — las tres líneas pendientes de v2.0 son
  realidad en v2.1:
  - **Exportación de informes a PDF** (`core/pdf_min.py`): generador de PDF 1.4
    en Python puro (sin dependencias): páginas A4 con paginación automática,
    fuentes base Helvetica/Helvetica-Bold/Courier (WinAnsiEncoding), color,
    tablas monoespaciadas con anchos calculados, filetes y pie de página con
    numeración. Cada ejecución ahora genera **JSON + MD + HTML + PDF** en
    `output/`, y `export pdf` vuelca el workspace completo a PDF ejecutivo.
    Validado con poppler (pdftotext/pdfinfo).
  - **Relay inverso de phishing** (`phishing/relay_proxy`): proxy inverso de
    SIMULACIÓN estilo evilginx2 para el laboratorio — espeja el portal
    objetivo, reescribe los enlaces del HTML, detecta los formularios de
    login y registra usuario/contraseña y cookies en
    `output/phishing/relay_capturas.json`. HTTP plano, Ctrl+C para parar,
    exige AUTHORIZED. Sin DNS/certificados por diseño (demo y formación
    defensiva).
  - **Plugins desde Git** (`core/plugins.py` + comando `plugin`):
    `plugin install <ruta|URL.git>` clona el pack (o usa una ruta local),
    valida nombres, copia los `.py` a `plugins/<categoria>/` y **registra los
    módulos en caliente** (sin reiniciar la consola). Los packs remotos
    exigen AUTHORIZED + confirmación REVISADO (instalar código de terceros
    es una acción de máxima confianza) y todo queda en la traza ética.
    `plugin list` y `plugin del <categoria>` completan el ciclo.
- **Categoría nueva `cloud` (3 módulos)** — auditoría de almacenamiento
  anónimo, solo lectura (MITRE T1619):
  - `cloud/s3_enum` — cubos S3: ListObjectsV2 anónimo → LISTABLE /
    PROTEGIDO / NO_EXISTE / OTRA_REGION, con extracción de claves y
    hallazgo alto automático.
  - `cloud/azure_blob` — contenedores de Azure Blob (restype=container&
    comp=list) con las mismas cuatro fases y extracción de nombres.
  - `cloud/gcs_enum` — cubos GCS vía API JSON v1 (metadata + listado),
    distingue METADATA_PUBLICA de LISTABLE.
- **4 módulos web nuevos (13 → 17)**:
  - `web/http_methods` — métodos aceptados: Allow de OPTIONS, eco TRACE
    (XST) con marcador inerte y métodos peligrosos declarados
    (PUT/DELETE/WebDAV...). Sin escritura, por diseño.
  - `web/host_header_injection` — reflexión de Host/X-Forwarded-Host con
    dominio sonda inexistente: Location, enlaces absolutos y cookies de
    dominio (password reset poisoning, cache poisoning).
  - `web/open_redirect` — sonda relativo-protocolo sobre los parámetros
    candidatos (url/next/redirect...) sin seguir la redirección;
    clasifica Location y meta-refresh.
  - `web/subdomain_takeover` — CNAME con cliente DNS propio (UDP/53, con
    compresión DNS) + 15 firmas de servicios colgados (GitHub Pages, S3,
    Azure, CloudFront, Heroku, Shopify, Surge, Zendesk, Fastly, Bitbucket,
    Pantheon, Unbounce, HelpJuice, Tumblr...).
- **1 módulo osint nuevo (12 → 13)**: `osint/dork_builder` — cuaderno de
  Google/GitHub dorks personalizado (documentos, índices abiertos, paneles,
  configs, cloud indexado, código) 100 % offline, inspirado en dorks-eye
  pero sin scrapear buscadores (genera las consultas, las ejecuta el
  operador). Escribe `output/dorks_<dominio>.md`.
- **Consejos nuevos** para los 9 módulos añadidos + heurística de categoría
  cloud (recursos LISTABLE → bloqueo de acceso público y auditoría de
  contenido; sin hallazgos → dorks y nombres derivados de la org).

### Fixed
- **Banner**: la última letra del arte ASCII dibujaba una segunda "O"
  (REDHAVOO) en lugar de una "C" — regenerado con la forma correcta de la
  C en ANSI Shadow, verificada en consola y capturas.

### Changed
- Tab completion: `plugin install|list|del` y `export pdf` añadidos al
  autocompletado; `help` documenta el comando plugin y el PDF.
- Icono de categoría `cloud` (☁️) en `show modules`; versión 2.1.0 en el
  User-Agent por defecto y el banner.
- README, MODULES.md y ARCHITECTURE.md ampliados (73 módulos, 12
  categorías, capturas regeneradas con el banner corregido).

### Tests
- 37 tests nuevos (`tests/test_v21.py`): clasificadores cloud puros +
  ejecuciones con red simulada; funciones puras de los 4 web nuevos;
  dorks offline; helpers del relay; PDF (estructura %PDF/EOF/xref,
  paginación multi-página, transliteración Latin-1) e integración del
  reporter; plugins (instalación local con registro en caliente, listado,
  desinstalación, packs rotos, nombres inválidos, URL sin git, import
  fallido) y consejos de las categorías nuevas.
- Suite total: **454 passed, 1 skipped** (417 en v2.0).

## [2.0.0] — 2026-09-10 (más módulos · AES puro · workspaces múltiples)

### Added
- **AES-256 puro (`core/aes_min.py`)**: implementación educativa de Rijndael
  (FIPS-197) con ECB/CBC, claves 128/192/256 y relleno PKCS#7, sin
  dependencias criptográficas externas — verificada contra los vectores
  oficiales FIPS-197 y NIST SP 800-38A.
- **`ad/gpp_cpassword` (nuevo módulo)**: descifra las contraseñas `cpassword`
  de Group Policy Preferences (MS14-025 / CVE-2014-1812) de Groups.xml y los
  5 XML más de SYSVOL, con AES propio. Extrae usuario/elemento, registra
  hallazgo alto y credenciales en el workspace, y sugiere `smb_login` +
  rotación. Modo RECURSIVO para barrrer la carpeta de Policies exportada.
- **5 módulos nuevos (58 → 64)**:
  - `recon/smtp_enum` — enumeración de buzones con VRFY/EXPN/RCPT sobre
    socket propio (estilo smtp-user-enum), clasificación por código y detección de MTA.
  - `web/clickjack` — auditoría anti-clickjacking: X-Frame-Options (incluido
    el ALLOW-FROM obsoleto), CSP frame-ancestors e iframes embebidos.
  - `web/xss_reflected` — detector EDUCATIVO de XSS reflejado con marcador
    INERTE (sin payloads activos) y clasificación de contexto
    (HTML/atributo/script/comentario/sin filtrar).
  - `web/path_traversal` — detector EDUCATIVO de LFI con 7 variantes
    (../, %2e, doble encode, ..%2f, ....//, absoluto) y firma inequívoca
    (/etc/passwd o win.ini).
  - `brute/telnet_login` — auditoría de credenciales Telnet con socket puro,
    prompts gestionados y verificación por eco (evita falsos positivos).
- **Workspaces múltiples (estilo msf)**: `workspace` lista los espacios con
  su contenido y marca el activo; `workspace new/use/del <nombre>` crea,
  cambia y borra (el 'principal' es intocable). Cada workspace tiene su
  propia DB (hosts/creds/vulns/notas) en `workspace/ws_<nombre>.json`; el
  activo se restaura en el siguiente arranque. Retrocompatible: el
  principal sigue siendo `workspace/db.json`.
- **Persistencia de opciones entre sesiones**: cada `set`/`setg`/`unset`/
  `unsetg` queda registrado en `workspace/opciones.json` (globales y por
  módulo); al arrancar se restauran las globales y al cargar un módulo sus
  valores guardados. **AUTHORIZED nunca se persiste** (la autorización es
  por sesión, por diseño).
- **Capturas reales para el README**: 8 pantallas capturadas en un PTY de
  102 columnas (puerta ética, banner, help, search AD, opciones, port scan
  contra un lab local, workspace/consejos y mapa ATT&CK) y renderizadas a
  PNG con chrome de ventana moderno (`assets/img/`).

### Changed
- Consejos nuevos para los 6 módulos añadidos (smtp_enum → passwd_spray;
  gpp_cpassword → smb_login + rotación; xss/path_traversal/clickjack →
  validación manual y fixes; telnet_login comparte el playbook de brute).
- TAB completa `workspace new|use|del`; `help` incluye el comando nuevo; el
  resumen de salida muestra el workspace activo.
- README renovado con sección de capturas, feature de workspaces y roadmap
  actualizado; MODULES.md y ARCHITECTURE.md ampliados.

### Tests
- 51 tests nuevos (`tests/test_v20.py`): AES contra FIPS-197/SP800-38A +
  roundtrips + entradas inválidas; GPP (roundtrip, base64 sin relleno,
  parseo XML, ejecución con fichero temporal); SMTP (clasificador, saludo,
  cargador de usuarios); clickjack (evaluación pura + registro de vuln con
  requests parcheado); XSS (marcadores, 4 contextos, construcción de URL);
  traversal (variantes, acotado, firmas); telnet (intérprete de sesión y
  prompts); workspaces múltiples (rutas, listado, comandos, protección de
  'principal', aislamiento y restauración); persistencia de opciones
  (set/unset/setg, exclusión de AUTHORIZED, supervivencia entre sesiones);
  integración (64 módulos, consejos nuevos, TAB).
- Suite completa: **417 passed + 1 skipped**.

## [1.9.0] — 2026-09-10 (mejorar · optimizar · pulir II)

### Added
- **`notes` — cuaderno del operador**: `notes add <texto>`, `notes` (tabla
  numerada) y `notes -c` (borra SOLO notas). Persistidas en
  `workspace/db.json` junto a hosts/creds/vulns; `resumen()` ahora incluye
  el contador de notas.
- **`export json | csv | md`**: vuelca el workspace completo (hosts, creds,
  vulns y notas) a `output/` para anexarlo al informe del cliente. CSV con
  escape correcto de comas/comillas (un secreto con coma no rompe el fichero)
  y listados serializados (`445/smb; 80/http`); MD consolidado con tablas por
  sección; JSON único procesable por otras herramientas.
- **`audit [N]`**: los últimos N eventos (por defecto 20) de la traza ética
  `workspace/audit.log` en tabla legible (evento + detalle). Traza completa
  siempre en disco; RUN y bloqueos éticos quedan documentados para el informe.
- **Historial persistente entre sesiones** (estilo bash): se guarda en
  `workspace/historial.txt` al salir y se restaura al arrancar (máx. 500
  líneas). `history -c` vacía memoria y fichero.
- **Resumen de la operación al salir**: `exit`/`quit` cierran sesiones,
  persisten el historial y muestran un panel con duración de la sesión,
  hosts, credenciales, hallazgos, notas e informes generados — el cierre
  profesional de un engagement.
- **Filtros en `search`**: `search cat:ad`, `search riesgo:alto` y combinados
  (`search smb riesgo:medio`). Los filtros usan CATEGORIA/RIESGO reales y
  `use <n>` sigue funcionando sobre el resultado filtrado.

### Changed
- **Validación amable en `set`**: THREADS/TIMEOUT/PUERTOS_HILOS exigen entero
  positivo — `set TIMEOUT abc` avisa al instante en vez de fallar dentro del
  módulo a mitad de run.
- TAB completa los nuevos comandos (`notes add|-c`, `export json|csv|md`,
  `history -c`); `help` y docstring actualizados.

### Tests
- 30 tests nuevos (`tests/test_v19.py`): notas (add/listar/limpiar/
  persistencia), export (json/csv/md + escape CSV + celdas de listas),
  auditoría (sin eventos, con eventos, límite N, arg inválido), historial
  persistente + resumen de salida + cierre de sesiones, validación numérica
  y filtros de search (parseo, categoría real, riesgo, sin resultados).
- Suite: 366 passed + 1 skipped.

## [1.8.0] — 2026-09-10 (mejorar · optimizar · pulir)

### Fixed
- **`hosts -c`, `creds -c` y `vulns -c` borraban la base de datos ENTERA**
  (los tres llamaban a `limpiar()`, que vacía hosts + creds + vulns): un
  `hosts -c` destruyó credenciales y hallazgos acumulados de la operación.
  Nuevos métodos `limpiar_hosts()` / `limpiar_creds()` / `limpiar_vulns()` en
  `core/workspace_db.py`; cada comando limpia SOLO su tabla, persiste en disco
  y lo indica en el mensaje ("creds y hallazgos se conservan").

### Added
- **Paridad Metasploit — `use <n>` / `info <n>` por índice**: `search smb`
  lista resultados numerados y `use 2` carga el segundo sin teclear la ruta.
  Fuera de rango o sin búsqueda previa → aviso limpio (nunca excepción).
- **Paridad Metasploit — `setg` / `unsetg`**: fijan opciones GLOBALES aunque
  haya un módulo cargado (`setg TIMEOUT 9`); `set` sigue dirigiéndose al
  módulo. TAB completa opciones globales tras `setg`/`unsetg`; `help` y el
  docstring documentados.
- **`sessions -k all`**: cierra todas las sesiones activas de golpe (los
  sockets se cierran de verdad); `sessions -k <ID>` sigue igual.

### Changed
- **`recon/dns_enum` en paralelo**: las 7 consultas (A/AAAA/MX/NS/TXT/SOA/
  CNAME) salen a la vez con `ThreadPoolExecutor` — el peor caso (resolver
  sordo) tarda UN timeout en lugar de siete en serie. Los fallos por tipo se
  degradan a texto (`(timeout)` / `(error: …)`) como antes.

### Tests
- 27 tests nuevos (`tests/test_v18.py`): limpieza selectiva + persistencia en
  disco, índices de búsqueda (válido, sin búsqueda, fuera de rango, 0),
  convivencia set/setg, restauración unsetg al valor por defecto, kill-all de
  sesiones con sockets reales falsos, y DNS paralelo (tiempo < 1.2s con
  resolver sordo + parseo real de respuesta A fabricada).
- Suite: 336 passed + 1 skipped.

## [1.7.0] — 2026-09-10 (ciclo de test, pulido y bugs)

### Fixed
- **Autocompletado TAB estaba roto desde v1** (`core/framework.py`): el
  completer referenciaba `readline` importado como variable local de otro
  método → `NameError` silencioso en cada TAB. Ahora `readline` se importa a
  nivel de módulo (con fallback limpio) y la lógica de candidatos vive en
  `_candidatos_para()`, testeable sin TTY. Verificado E2E con PTY real:
  `use recon/por<TAB>` completa a `recon/port_scanner`.
- **Markup Rich a prueba del operador**: `search`, `use`, `info`, `set`,
  `unset`, `history`, comando desconocido y errores de módulo imprimían datos
  del usuario sin `escape()` → `MarkupError`/inyección de estilos con
  corchetes. Todo dato dinámico pasa ahora por `escape()` (también
  `redhavoc.py` y el mensaje de `ModuloNoEncontrado`).
- **Comando `back` documentado**: faltaba en `COMANDOS` (no se autocompletaba)
  y en la tabla de `help`.
- **Consejo 3306 engañoso** (`core/advice.py`): un MySQL abierto sugería
  `brute/http_basic` (módulo HTTP, no MySQL). Ahora es consejo documental sin
  comando falso; nuevo test garantiza que TODOS los comandos sugeridos por
  las reglas apuntan a módulos reales.
- **Escaneo de puertos 5x más rápido**: el banner grabbing esperaba el
  timeout completo en servicios que no envían nada al conectar (HTTP espera
  nuestra petición) → ventana de banner acotada a 1s (los banners reales
  SSH/FTP/SMTP llegan en milisegundos). 1 puerto: 5.0s → 1.0s.
- **Consola limpia**: `InsecureRequestWarning` de urllib3 se suprime una vez,
  centralmente (`core.silenciar_insecure_request`), para los 12 módulos que
  hablan TLS sin verificar en lab — sin warnings ensuciando la salida.

### Changed
- **Suite 2x más rápida y sin red**: el smoke de los 58 módulos hablaba con
  plataformas reales (t.me, github, crt.sh, archive.org, psbdmp, rdap…)
  porque los objetivos inertes no cubrían APIs OSINT de terceros — filtraba
  actividad de lab y causaba los 40 warnings. Ahora `requests.get` y
  `Session.get` se parchean en el smoke: 309 tests en 1:45 (antes 277 en
  3:08), deterministas y con cero tráfico externo.

## [1.6.0] — 2026-09-10 (consejos accionables, estilo profesional y verificación total)

### Added
- **Motor de consejos** (`core/advice.py`): cada resultado de módulo genera
  *Siguientes pasos* accionables (1–4) — playbook de red team integrado:
  - Heurísticas por módulo: puertos abiertos → cadena recomendada
    (445→smb_check, 88→kerberos_userenum, 389→ldap_enum, 80/443→tech_detect…),
    SPNs→kerberoast, hashes→crack offline, usuarios válidos→as-rep/spray,
    credenciales válidas→reuso, CMS→sqli/dirs, JWT roto→demo en lab,
    fuga OPSEC→corregir antes de seguir, etc.
  - Fallbacks inteligentes: sin hallazgos → cómo ampliar la recolección;
    con hallazgos → qué documentar en el informe.
  - Cada consejo lleva el **comando exacto** para ejecutarlo
    (`→ use ad/smb_check`), pintado con el acento del tema.
- **Comando `consejos`**: plan de batalla leído del workspace
  (hallazgos críticos → priorizar; creds → reuso; hosts con SMB/web →
  cadena recomendada); actualizado tras cada ejecución.
- **Panel "siguientes pasos"** tras cada `run` (`core/render.py`),
  a prueba de datos raros (nunca rompe la ejecución).

### Changed
- **Rediseño visual profesional** (peticiones: "moderna, estilo Metasploit,
  pulida, no estilo hacker"):
  - Paleta neutra (cromo blanco/gris) con **único acento frío** (#6ea8fe)
    para módulos, comandos sugeridos y focos; el rojo queda reservado a
    errores y severidades altas.
  - Banner flat pizarra (degradado sutil #64748b→#94a3b8) en lugar del
    degradado "fuego" rojo→ámbar.
  - Prompt limpio `redhavoc >` / `redhavoc (modulo) >`.
  - Animaciones **sutiles**: spinner de puntos a ritmo suave con cronómetro
    discreto (`nombre · 3.4s`), arranque más corto (0.8 s) y colores calmados.
- Panel de resultado con título/borde neutros (antes rojo).

### Fixed
- **Smoke total de los 58 módulos** (`tests/test_v16.py`): cada módulo se
  ejecuta contra objetivos inertes y debe devolver dict o fallar LIMPIO
  (`ModuloError`). Bugs encontrados y corregidos:
  1. `phishing/campaign_server`: el módulo llamaba `_ruta_pagina()` que solo
     existía en el handler HTTP → `AttributeError` en la consola real;
     además markup Rich `[dim]` sin cerrar en el mismo `print` (MarkupError).
     Ahora el método vive en el módulo y el handler delega; impresión
     balanceada y escapada.
  2. `osint/social_presence`: `sorted()` de dicts sin `key` → `TypeError`
     con más de un resultado; ahora ordena por plataforma.
  3. `ad/asreproast`, `ad/kerberos_userenum`, `ad/passwd_spray`: usaban
     `self.ctx.workspace` directamente y explotaban fuera de la consola;
     ahora toleran ausencia de contexto (patrón `workspace` defensivo de
     `BaseModulo`, igual que port_scanner).
  4. `post/multi_handler`: idem para `ctx.sesiones/globales` — funciona sin
     framework con sesiones locales (`_ctx_seguro()`).
- Knobs de tiempo forzados en el smoke (`DURACION=1`): varios módulos tienen
  por defecto "0 = hasta Ctrl+C" y colgaban la ejecución en modo lote.

### Tests
- 30 tests nuevos (`tests/test_v16.py`): reglas del motor de consejos por
  módulo, fallbacks, robustez ante datos raros, plan de batalla, render y
  comando `consejos`, metadata sana de los 58 módulos, smoke de ejecución
  de TODOS los módulos y E2E de `run` con servidor de lab real.
- Suite: 277 passed + 1 skipped.

## [1.5.0] — 2026-09-10 (consola pulida: resultados en terminal, animaciones y TLS)

### Added
- **Los resultados de los módulos ahora se pintan EN la terminal** al terminar
  cada `run` (`core/render.py`):
  - Panel destacado con el `resumen` del módulo.
  - Tablas para listas de objetos (puertos abiertos, hallazgos, hashes…),
    columnas compactas para listas de textos, vista numerada para textos
    largos y tabla clave/valor para dicts.
  - Línea de totales (`· Puertos abiertos: 3 · Hallazgos: 2`).
  - Celdas `severidad` coloreadas (critico/alto/medio/bajo/info).
  - Truncado inteligente (25 filas / 60 columnas) con aviso "… +N más";
    el detalle completo sigue en los informes JSON/MD/HTML.
  - Todo dato dinámico pasa por `escape()`: un valor con corchetes no puede
    romper el markup ni inyectar estilos. El render nunca rompe un run.
- **Spinner con cronómetro** (`core.colors.trabajo`): nuevo estado animado
  `modulo en ejecución · 3.4s` con frames braille propios ("redhavoc",
  registrados en `rich.spinner.SPINNERS`); se actualiza 10 veces/seg y las
  impresiones del módulo se apilan encima en tiempo real. Sin TTY es
  silencioso (tuberías y tests limpios).
- **Animación de arranque** (`core/boot.py`): barra de progreso rápida que
  recorre las categorías del arsenal al iniciar la consola (transitoria);
  en no-TTY se degrada a una línea.
- **Banner con degradado**: el arte ASCII se pinta con interpolación RGB
  rojo→ámbar línea a línea.
- **`show modules` en árbol**: explorador Rich `Tree` por categorías con
  iconos y contadores.
- **Panel al cargar módulo** (`use`): nombre, riesgo coloreado, técnicas
  ATT&CK y descripción en un panel compacto.
- **TLS en `post/multi_handler`** (roadmap): nuevas opciones `TLS`,
  `CERTFILE` y `KEYFILE` (stdlib `ssl`); handshake por conexión con
  descarte limpio de clientes que no hablan TLS; resultado incluye `tls`.
  `templates/payloads/agent_shell.py` gana el flag `--tls` (contexto sin
  verificación, certificado autofirmado de lab).

### Tests
- `tests/test_v15.py` (+24): render (resumen/totales, tablas, severidad,
  truncado, escape, formas raras), spinner TTY/no-TTY, boot, gradiente del
  banner, panel `use`, árbol `show modules`, render tras `run` y handler
  TLS completo (handshake real contra certificado de lab en
  `tests/assets/`, sesión registrada, cliente plano descartado).

### Fixed
- `multi_handler`: bucles de accept duplicados unificados (mismo camino para
  DURACION>0 e infinito); fracasos de handshake TLS ya no dejan sockets a medias.
- `cmd_run` ahora escapa el objetivo en el mensaje "Ejecutando…" (antes un
  objetivo con corchetes podía romper el markup Rich).

## [1.4.0] — 2026-09-10 (kerberoasting, SMB/NTLMv2, hallazgos y resource)

### Added
- **Cadena Kerberos completa (kerberoasting, T1558.003)** sobre `core/krb5.py`:
  - TGS-REQ con PA-TGS-REQ (AP-REQ propio: authenticator RC4-HMAC uso 7,
    ticket del AS-REP reutilizado) y parseo de TGS-REP → formato
    hashcat -m 13100 (`$krb5tgs$23$*user$realm$spn*$checksum$cipher`).
  - `descifrar_rc4_hmac`: descifrado con verificación de checksum y
    múltiples key-usage (8/3 para AS-REP, 2 para TGS-REP).
  - **Crackeo offline puro en Python** de hashes 18200/13100 con wordlist
    (`verificar_hash_kerberos`, `crackear_hashes_kerberos`) — sin hashcat.
- **`ad/kerberoast`** (T1558.003): TGT con preauth → TGS por SPN → hashes
  13100 en `output/ad/`; reutiliza el informe más reciente de `ad/spn_enum`;
  opción `CRACK=true` con `WORDLIST` para romper en local. `ad/asreproast`
  gana la misma opción `CRACK` para sus hashes 18200.
- **`core/smb_min.py`**: cliente SMB2 propio (TCP/445): NEGOTIATE
  (reutilizado por `ad/smb_check`), **SESSION_SETUP con NTLMv2 puro**
  (NTLMSSP type1/2/3, respuesta NTLMv2 con HMAC-MD5 y blob TargetInfo),
  TREE_CONNECT/TREE_DISCONNECT y clase `ClienteSMB` de sesión completa.
- **`ad/smb_login`** (T1110, ALTO + AUTHORIZED): validación de pares
  usuario:contraseña por SMB2/NTLMv2 estilo NetExec; distingue clave mala,
  cuenta deshabilitada, **lockout (aborta de inmediato)** y otros estados
  NT; registra las válidas en el workspace.
- **`ad/smb_share_enum`** (T1135): clasifica shares como LEGIBLE / DENEGADO /
  NO EXISTE (estilo `netexec --shares`); aviso y hallazgo si ADMIN$/C$ es
  legible, aviso de GPP si SYSVOL es legible.
- **Web (3 módulos)**:
  - `web/jwt_analyzer`: decodifica JWT (b64url propio), detecta alg=none,
    secretos débiles HS256 (HMAC-SHA256 contra lista integrada), exp/nbf,
    kid con caracteres de inyección.
  - `web/cookie_audit`: Secure/HttpOnly/SameSite/prefijos `__Host-`/
    Max-Age>90d con clasificación por severidad.
  - `web/ssti_scanner`: sondas matemáticas inocuas (`rvh{{7*7}}` → `rvh49`)
    para Jinja2/Twig/FreeMarker/ERB/Smarty, en query o POST, sin payloads
    destructivos.
- **Tabla `vulns` del workspace**: `add_vuln`/`vulns`/`total_vulns` con
  deduplicación por host+título y orden por severidad; comando **`vulns`**
  en el REPL. Ahora registran hallazgos `ad/smb_check` (firma no exigida),
  `ad/smb_share_enum` (ADMIN$ legible), `web/jwt_analyzer`, `web/cookie_audit`
  y `web/ssti_scanner`.
- **Comando `resource <fichero.rc>`**: guiones de comandos de consola al
  estilo msf (`#` comentarios, una orden por línea, `exit` sale).
- Plantillas phishing nuevas: `teams_login` (Microsoft Teams) y
  `docusign_firma` (firma electrónica de documento). Plantilla de
  **informe ejecutivo** en `templates/reportes/informe_ejecutivo.md`.
- Total: **58 módulos en 11 categorías** (52→58) · **~223 tests**.

### Fixed
- `core/krb5`: el parseo del EncASRepPart desenvuelve el TLV del texto claro
  ([APPLICATION 25] o SEQUENCE directa); los hashes 13100/18200 se generan y
  verifican con el formato hashcat canónico (`*$checksum$cipher`).
- `core/smb_min`: el cliente devuelve la respuesta con su prefijo NetBIOS
  (los offsets de TreeId/SecurityBuffer son relativos al header SMB2).
- `web/cookie_audit`: los flags sin valor (Secure, HttpOnly) cuentan como
  presentes; la severidad distingue intercepción pasiva (alto) de vectores
  que requieren XSS/CSRF (medio).
- `modules/ad/smb_check` refactorizado para reutilizar `core/smb_min`
  (una sola implementación del NEGOTIATE).

## [1.3.0] — 2026-09-10 (Active Directory + OSINT de reconmap + engagement)

### Added
- **Categoría ad/ (Active Directory, 7 módulos)** con clientes de protocolo
  escritos a mano y sin dependencias:
  - `core/krb5.py`: cliente Kerberos mínimo (RFC 4120) — codificador DER,
    AS-REQ con/sin PA-ENC-TIMESTAMP, envío UDP/TCP 88, interpretación de
    KRB-ERROR/AS-REP, **MD4 puro** (vectores RFC 1320 validados), RC4 y
    RC4-HMAC (RFC 4757) para el sello de preautenticación.
  - `core/ldap_min.py`: cliente LDAP mínimo (RFC 4511) — bind simple/anónimo,
    search con mini-parser de filtros (`=`, `*`, `&`, `|`, `!`), lectura de
    entradas y SearchResultDone.
  - `ad/ldap_enum`: enumeración de objetos del directorio (T1087.002).
  - `ad/kerberos_userenum`: enumeración de usuarios estilo kerbrute por
    diferencia de errores del KDC (25/6/18) (T1087.002).
  - `ad/asreproast`: AS-REP roasting → hashes hashcat -m 18200 (T1558.004).
  - `ad/spn_enum`: cuentas con SPN vía LDAP (fase previa al kerberoasting).
  - `ad/smb_check`: negotiate SMB2 propio — firma exigida, dialecto, GUID,
    NTLM (evalúa riesgo de relevo) (T1046/T1557.001).
  - `ad/passwd_spray`: password spray Kerberos **con canario anti-lockout y
    pausa** (idea directa de goteo) (T1110.003, riesgo ALTO + AUTHORIZED).
  - `ad/net_discover`: escucha PASIVA de LLMNR/NBT-NS/mDNS (recon previa a
    Responder; no envenena) (T1557.001).
- **OSINT extendido (6 módulos)** con ideas de reconmap (suite propia):
  - `osint/cert_transparency`: subdominios vía CT logs (crt.sh + CertSpotter).
  - `osint/wayback_urls`: URLs históricas vía Wayback CDX (endpoints con
    parámetros, documentos, subdominios olvidados).
  - `osint/rdap_lookup`: ficha RDAP de dominio o IP (registrar, ASN, abuse).
  - `osint/doc_metadata`: metadatos FOCA-style de PDF/DOCX/XLSX/PPTX
    (autores, software, correos) — pypdf opcional, degradación elegante.
  - `osint/paste_search`: pastes filtrados en psbdmp.ws.
  - `osint/email_verify`: verificación SMTP de buzones (RCPT TO sin envío,
    MX resuelto con el cliente DNS propio).
- **post/host_audit**: generador de script PowerShell de auditoría de host
  inspirado en *EvasiveAudit v4* (sistema, red, defensas, usuarios,
  procesos, servicios, tareas, recientes, apps, navegadores, ficheros de
  credenciales, WiFi opcional) con salida JSON base64. **Sin técnicas de
  evasión por diseño** (sin AMSI bypass) — solo colecta para el lab
  (T1082/T1016/T1087.001/T1057/T1005, riesgo ALTO + AUTHORIZED).
- **Engagement (core/engagement.py + comando `engagement`)**: fichero JSON
  central con alcance (dominios, sufijos, CIDRs, wildcards), excluidos,
  kill-date y `permitir_fuera_alcance`. El framework **bloquea** `run` si
  el objetivo (TARGET/URL/DOMAIN/HOST/RHOST/CIDR) queda fuera del alcance
  o el kill-date ha pasado; todo queda auditado. Plantilla:
  `templates/engagement_ejemplo.json`.
- **Tags MITRE ATT&CK**: los módulos declaran `ATTCK`; `info` muestra la
  técnica y el nuevo comando **`attack [técnica]`** lista el mapa
  módulo ↔ técnica (idea de volcan/adversary emulation).
- Plantillas phishing nuevas: `office365_login`, `vpn_portal`,
  `portal_sspr` (restablecimiento de contraseña — temática AD).
- Wordlists AD: `templates/wordlists/ad_usuarios.txt` (64 usuarios) y
  `ad_claves.txt` (40 claves de laboratorio).
- Total: **52 módulos en 11 categorías** (38→52) · **~160 tests**.

### Fixed
- MD4 propio comparado contra implementación de referencia (passlib /
  pycryptodome): la ronda 3 usa rotaciones 3/9/11/**15** (no 19).
- Parser DER: desenvuelven SEQUENCE internas y toleran tags explícitos
  (RFC 4120 usa EXPLICIT TAGS) o primitivos según la implementación del KDC.
- `core/ldap_min`: el protocolOp se extrae tras saltar el messageID.

## [1.2.0] — 2026-09-09 (workspace, brute/dos/opsec, túnel, reporte HTML)

### Added
- `core/workspace_db.py`: DB JSON estilo msf (hosts/servicios/creds) +
  comandos `hosts`/`creds` en el REPL; port_scanner y brute la rellenan.
- Reporte HTML oscuro autocontenido (además de JSON + MD) con escapado
  anti-inyección; `report` muestra las 3 rutas.
- 9 módulos: `brute/ftp_login`, `brute/http_basic`, `brute/ssh_login`
  (paramiko opcional), `dos/stress_http` (topes duros 60s/50hilos/200rps),
  `opsec/proxy_check`, `opsec/mac_changer`, `phishing/tunnel` (SSH inverso
  serveo/localhost.run), `recon/ping_sweep` (TCP-ping sin root),
  `web/waf_detect` (7 firmas + sonda).
- 3 plantillas phishing (red social, banca, nube de archivos).

## [1.1.0] — 2026-09-08 (ideas de Argus + Scanners-Box)

### Added
- 11 módulos: `osint/email_harvest`, `osint/social_presence` (20 plataformas),
  `osint/spf_dmarc`, `osint/zone_transfer` (AXFR por TCP/53),
  `osint/typosquat` (dnstwist-lite), `osint/reverse_ip`, `iot/device_scan`
  (huella Telnet/RTSP/MQTT/Modbus/S7/DNP3/BACnet), `iot/upnp_discover`
  (SSDP), `iot/default_creds` (telnet+basic, SOLO lab, AUTHORIZED),
  `web/exposed_files` (.git/.env/backups), `web/cors_scan`.

## [1.0.0] — 2026-09-08 (versión inicial)

### Added
- Consola REPL estilo Metasploit (`rtf > `) con Rich: `search/use/info/
  show/set/unset/run/sessions/back/report/banner/history`, TAB-completado
  e historial.
- 18 módulos nativos en 7 categorías (recon, web, phishing, payloads,
  post, opsec + plantillas y wordlists).
- Puerta ética: disclaimer persistente, `AUTHORIZED` para riesgo alto,
  `audit.log` de todas las ejecuciones.
- Reportes JSON + Markdown por módulo, sesiones reales del handler,
  agente de laboratorio (`templates/payloads/agent_shell.py`).
- Suite de tests pytest (51) y documentación completa en `docs/`.
