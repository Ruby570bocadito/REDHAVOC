# Arquitectura de REDHAVOC

## 1. Visión general

REDHAVOC sigue una arquitectura de **núcleo + plugins** (módulos), igual que
Metasploit: un motor mínimo (consola, registro de módulos, opciones,
reportes, ética) y módulos intercambiables que solo implementan su lógica.

```text
┌──────────────────────────────────────────────────────────────┐
│                        redhavoc.py (CLI)                     │
└──────────────┬───────────────────────────────────────────────┘
               │ inicializa
┌──────────────▼───────────────────────────────────────────────┐
│                   RedHavocFramework (core.framework)         │
│                                                              │
│  ┌────────────┐  ┌───────────────┐  ┌──────────────────────┐ │
│  │ ModuleMgr  │  │ OptionStore   │  │ EthicsGate           │ │
│  │ (registro) │  │ (globales+mod)│  │ (disclaimer+audit)   │ │
│  └─────┬──────┘  └───────────────┘  └──────────────────────┘ │
│        │ clases                                              │
│  ┌─────▼──────────────────────────────────────────────────┐  │
│  │  REPL: help/search/use(n)/set/setg/show/run/sessions/…   │  │
│  └─────┬──────────────────────────────────────────────────┘  │
│        │ ejecuta instancias                                  │
│  ┌─────▼──────────────┐   ┌───────────────────────────────┐   │
│  │ BaseModulo (ABC)   │──▶│ Reporter (JSON + Markdown)    │   │
│  │ NAME/RISK/options  │   └───────────────────────────────┘   │
│  │ ejecutar() → dict  │   ┌───────────────────────────────┐   │
│  └────────────────────┘   │ Ctx (sesiones, globales, ...) │   │
│                           └───────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
               │ import dinámico (pkgutil.walk_packages)
┌──────────────▼───────────────────────────────────────────────┐
│   modules/recon · modules/web · modules/phishing ·           │
│   modules/payloads · modules/post · modules/opsec            │
└──────────────────────────────────────────────────────────────┘
```

## 2. Componentes del núcleo

### 2.1 `core.framework.RedHavocFramework`
El REPL. Responsabilidades:
- **Parseo de comandos**: `shlex` para respetar comillas; `set` captura el
  resto de la línea tal cual (para URLs con `&` o `=`).
- **Despacho**: diccionario comando→método (`cmd_help`, `cmd_run`, ...).
- **Ciclo de vida del módulo**: `use` instancia la clase; `back` la descarga;
  el prompt cambia de `redhavoc >` a `redhavoc (categoria/nombre) >`.
- **Autocompletado TAB** vía `readline`: comandos, rutas de módulos y opciones.
- **Gestión de sesiones**: registro compartido `{id: socket}` que rellena
  `post/multi_handler` y consume `sessions -i/-k`.

### 2.2 `core.module_manager.ModuleManager`
- Escanea `modules/` con `pkgutil.walk_packages` e importa cada fichero.
- Registra toda clase que herede de `BaseModulo` con `NAME` definido.
- Un módulo roto **no tumba el framework**: se avisa y continúa.
- Búsqueda tolerante: por categoría, descripción o sufijo único
  (`use whois_lookup` == `use recon/whois_lookup` si no hay ambigüedad).

### 2.3 `core.base_module.BaseModulo` (ABC)
Contrato de cada módulo:

```python
class MiModulo(BaseModulo):
    NAME = "categoria/nombre"      # ruta única
    CATEGORIA = "categoria"
    DESCRIPCION = "..."            # aparece en search
    RIESGO = "bajo|medio|alto"     # alto exige AUTHORIZED
    INTERACTIVO = False            # True: sin spinner (handlers)

    def definir_opciones(self):    # declara parámetros
        self.opciones.declarar("TARGET", "", True, "objetivo")

    def ejecutar(self) -> dict:    # lógica; devuelve resultados
        ...
```

Errores controlados → `raise ModuloError("mensaje limpio")` (sin traceback).
`ModuloCancelado` reserva la interrupción por el operador.

### 2.4 `core.option_store.OptionStore`
Opciones estilo msf: `declarar/set/unset/get` con tipos interpretados
(`como_bool`, `como_int`) y validación de requeridas (`validar_o_error`).
Re-declarar una opción conservando el valor del operador permite que
el framework comparta globales (AUTHORIZED, THREADS, TIMEOUT...) sin
pisar configuración.

### 2.5 `core.reporter.Reporter`
Cada `run` produce:
- `output/<fecha>_<modulo>.json` — envoltura {modulo, objetivo, fecha,
  opciones, resultados}, processable por otras herramientas.
- `output/<fecha>_<modulo>.md` — el mismo contenido en Markdown legible
  para entregar al cliente.
- `output/<fecha>_<modulo>.html` (v1.2) — informe oscuro autocontenido
  (CSS inline, sin dependencias), con `html.escape` en todo valor para
  evitar inyección por datos del objetivo.

El render Markdown/HTML es recursivo (dict/list arbitrarias), así los
módulos pueden devolver estructuras ricas sin preocuparse del formato.

### 2.6 `core.workspace_db.WorkspaceDB` (v1.2, vulns v1.4, notas v1.9, multi v2.0)
Base de datos JSON estilo Metasploit con cuatro
colecciones: `hosts` (ip → {hostname, servicios[], visto, notas}), `creds`
({ip, usuario, secreto, servicio, hora}), `vulns` desde v1.4
({host, titulo, severidad, detalle, modulo, hora}) sin duplicados y `notas`
desde v1.9 ({texto, autor, hora}) — el cuaderno libre del operador.

- Se inyecta en los módulos vía `Ctx.workspace`.
- `recon/port_scanner` y `recon/ping_sweep` la rellenan tras cada escaneo.
- Los módulos de brute guardan las credenciales válidas.
- `add_vuln` registra hallazgos (dedupe por host+título); `vulns()` los
  devuelve ordenados por severidad (crítico primero).
- Consulta desde la consola: `hosts` / `creds` / `vulns` / `notes` (y `-c`
  limpia SOLO esa tabla).
- **Export** (v1.9): `export json|csv|md` vuelca las cuatro colecciones a
  `output/` (CSV con escape de comas/comillas, MD consolidado por secciones).
- **Workspaces múltiples** (v2.0): `WorkspaceDB(carpeta, nombre)` apunta a
  `db.json` (principal, retrocompatible) o `ws_<nombre>.json`; `listar()`
  enumera todos. El REPL cambia con `workspace new/use/del` y restaura el
  activo al arrancar (`workspace/actual.txt`).
- Thread-safe (lock interno) y tolerante a ficheros corruptos.

### 2.8 `core.engagement.Engagement` (v1.3)
Engagement estilo suite red team: fichero JSON central
(`workspace/engagement.json`) con `nombre`, `cliente`, `kill_date`,
`alcance` (dominios bare con subdominios, sufijos `.dominio`, wildcards
`*.dominio` y CIDRs IPv4/IPv6), `excluidos` (siempre bloquean) y
`permitir_fuera_alcance`. El REPL lo gestiona con `engagement
[load|clear]` y **`cmd_run` verifica antes de ejecutar**: si alguna
opción objetivo (TARGET/URL/DOMAIN/HOST/RHOST/CIDR) queda fuera del
alcance o el kill-date ha pasado, la ejecución se bloquea y se audita
(`BLOQUEO_ENGAGEMENT`). Plantilla: `templates/engagement_ejemplo.json`.

### 2.9 `core.krb5` y `core.ldap_min` (v1.3, TGS en v1.4)
Clientes de protocolo escritos a mano para la categoría `ad/`:
- `krb5`: DER mínimo (codificador+lector tolerante a tags explícitos),
  AS-REQ (RFC 4120) con/sin PA-ENC-TIMESTAMP, transporte UDP/TCP 88,
  interpretación de KRB-ERROR/AS-REP (formato hashcat 18200), MD4 puro
  (ronda 3 con rotaciones 3/9/11/15, validado contra vectores RFC 1320),
  RC4 y RC4-HMAC (RFC 4757) para el sello de preauth del spray. En v1.4:
  TGS-REQ con PA-TGS-REQ (AP-REQ con authenticator RC4-HMAC uso 7),
  interpretación de TGS-REP → hashcat 13100, `descifrar_rc4_hmac`
  (verificación de checksum con múltiples key-usage 8/3/2) y crackeo
  offline de hashes 18200/13100 con wordlist.
- `ldap_min`: BER mínimo, bind simple/anónimo, mini-parser de filtros
  (`=`/`*`/`&`/`|`/`!`), search request y lectura de entradas/done.

### 2.9b `core.aes_min` (v2.0) y persistencia de opciones
- **`aes_min`**: AES puro (Rijndael, FIPS-197) — key schedule, SubBytes/
  ShiftRows/MixColumns y su inverso, ECB y CBC con PKCS#7, claves
  128/192/256. Tablas (S-box, RCON) generadas por código a partir del
  inverso multiplicativo en GF(2^8). Validado contra FIPS-197 Appendix C,
  NIST SP 800-38A F.2.5 y roundtrips. Lo consume `ad/gpp_cpassword`
  (MS-GPPREF: AES-256-CBC, IV a ceros, UTF-16LE) — el framework sigue sin
  depender de librerías criptográficas externas.
- **Persistencia de opciones** (framework): `set`/`setg`/`unset`/`unsetg`
  escriben `workspace/opciones.json` (`{"global": {...}, "modulos":
  {name: {...}}}`). Al arrancar se restauran las globales; al `use` un
  módulo, sus valores guardados. AUTHORIZED queda excluido por diseño.

### 2.10 `core.smb_min` (v1.4)
Cliente SMB2 propio (TCP/445) con enmarcado NetBIOS:
- NEGOTIATE (compartido con `ad/smb_check`, que reexporta sus funciones).
- SESSION_SETUP con NTLMSSP type 1/2/3: parseo del CHALLENGE (reto,
  TargetInfo) y respuesta NTLMv2 pura (`HMAC-MD5(NT, upper(user)+domain)`,
  blob con timestamp NT y reto cliente; LM a cero, mismo enfoque que
  smbprotocol).
- TREE_CONNECT/TREE_DISCONNECT para sondear shares y clase `ClienteSMB`
  (negotiate → login → sondeo) que consumen `ad/smb_login` y
  `ad/smb_share_enum`.
- Convención de respuestas: todo `_enviar` devuelve el paquete CON el
  prefijo NetBIOS de 4 bytes; los offsets (TreeId, SecurityBuffer) son
  relativos al header SMB2 y se corrigen con +4.

### 2.11 Guiones `resource` (v1.4)
`resource <fichero.rc>` ejecuta comandos de consola uno por línea
(`#` comentarios) reutilizando `_procesar`; permite preparar sesiones de
laboratorio reproducibles al estilo de los `.rc` de Metasploit.

### 2.12 Presentación: `core.render`, `core.boot` y spinner con cronómetro (v1.5)
- **`core.render.mostrar_resultado`**: traduce el dict que devuelve
  `ejecutar()` a salida Rica homogénea: panel de `resumen`, tablas para
  listas de dicts (máx. 6 columnas), columnas para listas cortas, vista
  numerada para textos largos y tabla clave/valor para dicts. Trunca a
  25 filas / 60 columnas con aviso "… +N más" (el detalle completo queda
  en los informes). Todo dato pasa por `escape()` y el render nunca
  lanza excepciones hacia `cmd_run` (degrada a impresión cruda).
- **`core.colors.trabajo(nombre)`**: context manager que envuelve
  `ejecutar()`. Con TTY abre un `console.status` con el spinner braille
  "redhavoc" (registrado en `rich.spinner.SPINNERS`) y un hilo que
  repinta el texto 10 veces/seg con el cronómetro (`· 3.4s`); las
  impresiones del módulo se apilan encima del spinner (Live de Rich).
  Sin TTY es un no-op silencioso (tuberías/tests limpios). El spinner se
  marca `transient` (Rich 14 lo hace por defecto en Status).
- **`core.boot.Boot.animar`**: barra de progreso transitoria que recorre
  las categorías cargadas al arrancar la consola; en no-TTY imprime una
  sola línea. El banner (`core.banner`) pinta el arte ASCII con un
  degradado RGB rojo→ámbar línea a línea (`_gradiente_hex`).

### 2.13 TLS en `post/multi_handler` (v1.5)
Con `TLS=true` el handler carga `CERTFILE`/`KEYFILE` en un
`ssl.SSLContext(PROTOCOL_TLS_SERVER)` y envuelve CADA conexión aceptada
(`wrap_socket(server_side=True)`). Un handshake fallido (cliente plano,
escáner) descarta la conexión sin romper el listener ni crear sesión.
El agente del lab (`templates/payloads/agent_shell.py --tls`) usa un
contexto sin verificación para aceptar el certificado autofirmado.

- `aceptacion.json` en `workspace/`: consentimiento persistente con fecha.
- Módulos de riesgo alto: se bloquean sin `AUTHORIZED` (global o entorno).
- `audit.log`: línea por evento (`RUN`, `BLOQUEO_RIESGO_ALTO`, fallos).

### 2.14 Motor de consejos `core.advice` (v1.6)
Funciones puras que convierten resultados en playbook:
`consejos_de_resultado(nombre, datos)` aplica heurísticas por categoría
(recon/web/ad/osint + resto) y devuelve 1–4 `Consejo(texto, comando)`;
`plan_de_workspace(workspace)` lee hosts/creds/vulns para el comando
`consejos`. Nunca lanzan: cualquier dato raro degrada a sin-consejos.
`core.render.mostrar_consejos` pinta el panel "siguientes pasos" tras cada
`run` y el comando sugiere comandos concretos con el acento del tema.

### 2.15 Tema visual profesional (v1.6)
Paleta neutra con acento frío `#6ea8fe` (`core.colors.ACENTO`): módulos,
prompt y comandos sugeridos; rojo reservado a errores y severidades.
Banner flat pizarra (#64748b→#94a3b8). Spinner de puntos suave con
cronómetro `nombre · Xs`; boot 0.8 s con barra discreta.

### 2.16 Generador PDF `core.pdf_min` y plugins (v2.1)
- **`pdf_min`**: PDF 1.4 en Python puro para los informes. Objetos mínimos
  (catálogo, páginas, 3 fuentes base Helvetica/Helvetica-Bold/Courier con
  WinAnsiEncoding, páginas + streams), xref calculada, `%EOF`. Composición:
  A4 con márgenes, paginación automática por altura, envoltura de línea
  aproximada (ancho medio por fuente), tablas Courier con anchos calculados,
  filetes y pie con numeración. `Reporter.guardar` añade el `.pdf` al
  JSON/MD/HTML (un fallo del PDF jamás rompe el informe) y `export pdf`
  vuelca el workspace completo. Unicode → Latin-1 por NFKD con tabla de
  símbolos frecuentes.
- **`plugins` + comando `plugin`**: packs con estructura
  `<pack>/modules/<categoria>/<modulo>.py`. Instalación desde ruta local o
  `git clone --depth 1`; validación de nombres (regex estricta), copia a
  `plugins/<categoria>/` con `__init__.py`, e import por
  `importlib.util.spec_from_file_location` con registro EN CALIENTE en el
  `ModuleManager._registro` (sin reiniciar). Remotos exigen AUTHORIZED +
  confirmación literal `REVISADO`; eventos `INSTALACION_PLUGIN` /
  `DESINSTALACION_PLUGIN` en la traza ética.

## 3. Flujo de una ejecución (`run`)

```text
run → ¿hay módulo? → validar opciones requeridas
    → si RIESGO==alto: ¿AUTHORIZED? (global/env) → si no, BLOQUEO + audit
    → snapshot de opciones usadas y objetivo (TARGET/URL/DOMAIN/LHOST)
    → ejecutar(): dentro de trabajo() (spinner+cronómetro; en vivo si INTERACTIVO)
    → capturar ModuloError (limpio) / KeyboardInterrupt (cancelado)
    → render.mostrar_resultado: resultados pintados en la terminal
    → si REPORT=true: guardar JSON+MD+HTML en output/
    → audit.log: RUN modulo -> objetivo (duracion)
```

## 4. Decisiones de diseño

| Decisión | Motivo |
|---|---|
| Cliente DNS propio (UDP/53) | Cero dependencias; pedagógico; permite parseo fino |
| WHOIS por socket 43 | Igual: sin librerías, follow de `refer:` de IANA |
| `INTERACTIVO` en módulos | El spinner de Rich corrompería la salida en vivo de handlers |
| Sesiones en `Ctx` compartido | El handler vive dentro de `run`, pero las sesiones sobreviven tras `Ctrl+C` |
| Reportes automáticos | Toda acción ofensiva debe dejar evidencia documentable |
| Sin dependencias de binarios externos | Funciona en Termux/Linux/macOS sin instalar nmap/whois |

## 5. Extensión

Para añadir módulos, ver [DEVELOPMENT.md](DEVELOPMENT.md): basta un fichero
en `modules/<categoria>/` con una clase `BaseModulo`; el gestor lo detecta
en el siguiente arranque. Los comandos del REPL no requieren cambios.
