# -*- coding: utf-8 -*-
"""
core.advice
===========
Motor de consejos de REDHAVOC: convierte los resultados de un módulo en
*Siguientes pasos* accionables (estilo playbook de red team).

Dos entradas públicas:

    consejos_de_resultado(nombre, datos, workspace=None) -> list[Consejo]
        Heurísticas por módulo sobre el dict de resultados: si hay puertos
        SMB abiertos sugiere la cadena AD; si hay SPNs sugiere kerberoast;
        si no se encontró nada sugiere cómo ampliar la recolección...

    plan_de_workspace(workspace) -> list[Consejo]
        Lectura de la base de datos (hosts/servicios/creds/vulns) para
        producir un plan de batalla con el comando `consejos`.

Cada Consejo lleva un `texto` y, si procede, un `comando` ejecutable en la
consola. Todo es puro y silencioso: NUNCA lanza ante datos inesperados.
"""

from dataclasses import dataclass

# ----------------------------------------------------------------------
# Modelo
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Consejo:
    """Un siguiente paso accionable."""
    texto: str
    comando: str = ""


def _c(cond, texto, comando=""):
    """Helper: devuelve el Consejo solo si se cumple la condición."""
    return [Consejo(texto, comando)] if cond else []


def _puertos(datos) -> list:
    """Extrae la lista de puertos (ints) de claves típicas."""
    for clave in ("abiertos", "servicios"):
        filas = datos.get(clave) or []
        salida = []
        for fila in filas:
            if isinstance(fila, dict):
                p = fila.get("puerto")
                if isinstance(p, int):
                    salida.append(p)
        if salida:
            return salida
    return []


def _n(clave, datos) -> int:
    """Longitud segura de una clave-lista."""
    valor = datos.get(clave)
    return len(valor) if isinstance(valor, (list, dict, str)) else 0


# ----------------------------------------------------------------------
# PUERTO → siguiente movimiento (para recon/port_scanner, iot, ...)
# ----------------------------------------------------------------------
_RUTA_PUERTOS = (
    (445, "SMB abierto: enumera firmas y shares antes de nada",
     "use ad/smb_check"),
    (139, "NetBIOS visible: confirma SMB con el módulo ad/smb_check",
     "use ad/smb_check"),
    (88,  "Kerberos accesible: enumera usuarios válidos del reino",
     "use ad/kerberos_userenum"),
    (389, "LDAP abierto: enumera usuarios y grupos del dominio",
     "use ad/ldap_enum"),
    (636, "LDAPS disponible: repite la enumeración LDAP por TLS",
     "use ad/ldap_enum"),
    (21,  "FTP: prueba credenciales débiles SOLO con autorización expresa",
     "use brute/ftp_login"),
    (22,  "SSH: prueba credenciales débiles SOLO con autorización expresa",
     "use brute/ssh_login"),
    (23,  "Telnet heredado: audita credenciales de fábrica en laboratorio",
     "use iot/default_creds"),
    (25,  "SMTP abierto: verifica qué cuentas de correo existen",
     "use osint/email_verify"),
    (80,  "HTTP: detecta la pila tecnológica del sitio",
     "use web/tech_detect"),
    (443, "HTTPS: detecta la pila tecnológica del sitio",
     "use web/tech_detect"),
    (8080,"Servidor alternativo detectado: perfila la app",
     "use web/tech_detect"),
    (554, "RTSP: probable cámara IP; identifica el dispositivo",
     "use iot/device_scan"),
    (1900,"UPnP: descubre dispositivos y servicios expuestos",
     "use iot/upnp_discover"),
    (3306,"MySQL expuesto: sin módulo nativo — verifica versión/banner y "
          "documéntalo; solo con autorización expresa en lab", ""),
    (3389, "RDP expuesto: verifica NLA y bloqueo por cuentas; sin módulo nativo "
           "— documéntalo en el informe", ""),
)


# ----------------------------------------------------------------------
# Heurísticas por módulo (categoria/nombre → función(datos) -> list)
# ----------------------------------------------------------------------
def _con_recon(nombre, datos):
    c = []
    if nombre == "recon/port_scanner":
        pts = _puertos(datos)
        if pts:
            for puerto, texto, comando in _RUTA_PUERTOS:
                if puerto in pts:
                    c.append(Consejo(texto, comando))
                if len(c) >= 3:
                    break
            c.append(Consejo("Los puertos quedaron en el workspace: revísalos con hosts",
                             "hosts"))
        else:
            c.append(Consejo("Sin puertos abiertos: prueba un rango mayor (PORTS 1-1000) "
                             "o confirma si hay filtrado con recon/ping_sweep",
                             "use recon/ping_sweep"))
    elif nombre == "recon/ping_sweep":
        if _n("vivos", datos):
            c.append(Consejo("Escanea puertos de los hosts vivos (empieza por el 1-1000)",
                             "use recon/port_scanner"))
            c.append(Consejo("Si es red interna, detecta hosts por LLMNR/NBT-NS en paralelo",
                             "use ad/net_discover"))
        else:
            c.append(Consejo("Red aparentemente vacía: revisa el CIDR o prueba ICMP "
                             "(ICMP true) y el mapeo de ARP"))
    elif nombre == "recon/subdomain_scan":
        if _n("encontrados", datos):
            c.append(Consejo("Comprueba qué subdominios sirven HTTP y con qué cabeceras",
                             "use recon/http_headers"))
            c.append(Consejo("¿Más subdominios? Cruza con certificados en transparente",
                             "use osint/cert_transparency"))
        else:
            c.append(Consejo("Sin subdominios por fuerza bruta: prueba fuentes pasivas",
                             "use osint/cert_transparency"))
    elif nombre == "recon/dns_enum":
        c.append(Consejo("Intenta una transferencia de zona (AXFR) contra los NS listados",
                         "use osint/zone_transfer"))
        c.append(Consejo("Revisa la postura anti-spoofing del dominio",
                         "use osint/spf_dmarc"))
    elif nombre == "recon/http_headers":
        if _n("seguridad_ausentes", datos):
            c.append(Consejo("Cabeceras de seguridad ausentes: búscalas en el informe y "
                             "añádelas al hallazgo (puntuación en el resultado)"))
        c.append(Consejo("Audita las cookies de la sesión sobre esta URL",
                         "use web/cookie_audit"))
    elif nombre == "recon/ip_info":
        c.append(Consejo("¿Qué más hay alojado en esta IP?",
                         "use osint/reverse_ip"))
        c.append(Consejo("Si la IP está en el alcance autorizado: escaneo de puertos",
                         "use recon/port_scanner"))
    elif nombre == "recon/redis_enum":
        if datos.get("estado") == "SIN_AUTH":
            c.append(Consejo("Redis SIN autenticación: hallazgo alto — documenta "
                             "las claves visibles y exige requirepass/TLS; "
                             "NUNCA uses CONFIG SET contra producción"))
            c.append(Consejo("Registra el hallazgo para el informe", "vulns"))
        elif datos.get("estado") == "PROTEGIDA":
            c.append(Consejo("Redis con auth: prueba credenciales por defecto SOLO "
                             "en lab o documenta el puerto expuesto como hallazgo "
                             "informativo"))
        else:
            c.append(Consejo("Sin Redis en ese puerto: confirma el servicio con "
                             "recon/port_scanner antes de descartarlo",
                             "use recon/port_scanner"))
    elif nombre == "recon/snmp_enum":
        if datos.get("comunidad"):
            c.append(Consejo(f"Comunidad válida '{datos.get('comunidad')}': usa el "
                             "sysDescr para saber versión/firmware y márcalo en "
                             "el informe como exposición de información"))
            c.append(Consejo("En red interna: mapea el resto de equipos con la "
                             "misma comunidad (solo lectura)",
                             "use recon/ping_sweep"))
        else:
            c.append(Consejo("Sin comunidad válida: prueba más comunidades con "
                             "set COMUNIDADES o pasa a host/broker distintos",
                             "use recon/snmp_enum"))
    elif nombre == "recon/whois_lookup":
        c.append(Consejo("Datos de registro completos vía RDAP (JSON normalizado)",
                         "use osint/rdap_lookup"))
        c.append(Consejo("Detecta dominios typosquat del principal",
                         "use osint/typosquat"))
    elif nombre == "recon/smtp_enum":
        if _n("validos", datos):
            c.append(Consejo("Buzones confirmados: son candidatos al spray de "
                             "contraseñas (AUTHORIZED, con canario)",
                             "use ad/passwd_spray"))
            c.append(Consejo("Revisa la postura anti-spoofing del dominio para "
                             "simulaciones de phishing internas",
                             "use osint/spf_dmarc"))
        else:
            c.append(Consejo("El MTA no divulga buzones: prueba el método RCPT "
                             "(METODO RCPT) o una wordlist más corta y real",
                             "use recon/smtp_enum"))
    return c


def _con_web(nombre, datos):
    c = []
    if nombre == "web/tech_detect":
        tec = str(datos.get("tecnologias", "")).lower()
        if "wordpress" in tec or "joomla" in tec or "drupal" in tec:
            c.append(Consejo("CMS detectado: confirma versión y vulnerabilidades conocidas",
                             "use web/cms_detect"))
        c.append(Consejo("Comprueba si hay un WAF delante antes de seguir",
                         "use web/waf_detect"))
        c.append(Consejo("Busca ficheros expuestos (.git/.env/backups)",
                         "use web/exposed_files"))
    elif nombre == "web/dir_bruteforce":
        if _n("hallazgos", datos):
            c.append(Consejo("Rutas vivas encontradas: audita cookies y sesión sobre ellas",
                             "use web/cookie_audit"))
            c.append(Consejo("¿Parámetros en las rutas? Son candidatos a inyección SQL",
                             "use web/sqli_scanner"))
        else:
            c.append(Consejo("Sin rutas: amplía el diccionario o pasa a ficheros expuestos",
                             "use web/exposed_files"))
    elif nombre == "web/exposed_files":
        if _n("hallazgos", datos):
            c.append(Consejo("Ficheros expuestos: descarga .env/.git SOLO con permiso "
                             "escrito y extrae credenciales al workspace"))
            c.append(Consejo("Documentación/office expuestos: extrae metadatos de autor",
                             "use osint/doc_metadata"))
    elif nombre == "web/cms_detect":
        if datos.get("cms_principal"):
            c.append(Consejo("CMS confirmado: prueba parámetros típicos del CMS contra "
                             "inyección SQL (con permiso)", "use web/sqli_scanner"))
            c.append(Consejo("Fuerza bruta de rutas de administración del CMS",
                             "use web/dir_bruteforce"))
    elif nombre == "web/sqli_scanner":
        if _n("candidatos", datos):
            c.append(Consejo("Candidatos a SQLi: confírmalos a mano y documenta evidencia "
                             "sin payloads destructivos (no es explotación automática)"))
            c.append(Consejo("Registra el hallazgo para el informe final (vulns)"))
        else:
            c.append(Consejo("Sin candidatos: prueba URLs con parámetros ?id= reales"))
    elif nombre == "web/waf_detect":
        if datos.get("waf"):
            c.append(Consejo("WAF detectado: los escaneos ruidosos serán bloqueados y "
                             "quedarán en logs; coordina ventanas de prueba con el cliente"))
        c.append(Consejo("Perfila la superficie CORS del objetivo",
                         "use web/cors_scan"))
    elif nombre == "web/jwt_analyzer":
        if datos.get("secreto_roto"):
            c.append(Consejo("Secreto HS256 roto: firma tokens falsos SOLO en tu laboratorio "
                             "y demuestra el impacto (no alteres tokens reales en producción)"))
        if _n("hallazgos", datos):
            c.append(Consejo("Hallazgos en el JWT: inclúyelos en vulns si son críticos",
                             "vulns"))
        c.append(Consejo("Audita también las cookies de la aplicación",
                         "use web/cookie_audit"))
    elif nombre == "web/cookie_audit":
        if _n("problematicas", datos):
            c.append(Consejo("Cookies sin Secure/HttpOnly/SameSite: propón el fix y "
                             "re-audita tras el parche", "use web/cookie_audit"))
    elif nombre == "web/ssti_scanner":
        if _n("confirmados", datos):
            c.append(Consejo("SSTI confirmada: hallazgo CRÍTICO — documenta el render "
                             "(7*7=49) y NO lance payloads destructivos"))
    elif nombre == "web/cors_scan":
        c.append(Consejo("Si hay reflejo de Origin: documenta el robo de datos "
                         "autenticados como impacto y añádelo a vulns"))
    elif nombre == "web/xss_reflected":
        if _n("reflejos", datos):
            c.append(Consejo("Reflexión detectada: valida el contexto a mano antes "
                             "de reportar XSS explotable (el marcador es inerte)"))
            c.append(Consejo("Si la app usa cookies: sin HttpOnly el robo de sesión "
                             "sería el impacto real", "use web/cookie_audit"))
        else:
            c.append(Consejo("Sin reflexión: prueba parámetros con OUTPUT real "
                             "(búsquedas, filtros, errores) y re-sondea"))
    elif nombre == "web/path_traversal":
        if _n("confirmados", datos):
            c.append(Consejo("LFI confirmado: hallazgo ALTO — busca inyección de logs "
                             "o subidas para RCE SOLO en el lab autorizado"))
            c.append(Consejo("Revisa ficheros de config expuestos para encontrar "
                             "credenciales", "use web/exposed_files"))
        else:
            c.append(Consejo("Sin lectura: sube PROFUNDIDAD, prueba WIN true en "
                             "Windows o busca parámetros de fichero con "
                             "web/dir_bruteforce"))
    elif nombre == "web/clickjack":
        if datos.get("nivel") == "vulnerable":
            c.append(Consejo("Sin anti-clickjacking: añade CSP frame-ancestors 'self' "
                             "+ XFO SAMEORIGIN y re-audita",
                             "use web/clickjack"))
        c.append(Consejo("Audita las cookies de la misma URL (el impacto del "
                         "clickjacking crece con sesiones persistentes)",
                         "use web/cookie_audit"))
    elif nombre == "web/http_methods":
        if datos.get("trace_eco"):
            c.append(Consejo("TRACE con eco: desactiva TraceEnable en el servidor "
                             "y verifica el impacto sobre cookies HttpOnly",
                             "use web/cookie_audit"))
        if "peligro" == str(datos.get("nivel")):
            c.append(Consejo("Métodos de escritura declarados: prueba PUT SOLO con "
                             "autorización y marcador inocuo, y documenta el fix "
                             "(DisableWebDAV / límites de método)"))
        c.append(Consejo("Completa la superficie: ficheros y rutas ocultas",
                         "use web/dir_bruteforce"))
    elif nombre == "web/host_header_injection":
        if datos.get("nivel") == "vulnerable":
            c.append(Consejo("Reflexión de Host: hallazgo ALTO si hay reset de "
                             "contraseña — valida el enlace generado en un lab "
                             "y exige allowlist de hosts en el servidor"))
            c.append(Consejo("Si hay CDN: prueba el envenenamiento de caché con "
                             "dos peticiones (una de siembra y una de víctima) "
                             "SOLO en lab", "use web/waf_detect"))
        c.append(Consejo("Revisa cabeceras de seguridad generales de la URL",
                         "use recon/http_headers"))
    elif nombre == "web/open_redirect":
        if datos.get("nivel") == "vulnerable":
            c.append(Consejo("Open redirect: documenta el PoC con la sonda inerte "
                             "y el impacto de phishing con dominio legítimo "
                             "(T1566.002) — no encadenes a producción"))
            c.append(Consejo("Combina con la campaña de simulación del lab",
                             "use phishing/template_gen"))
        else:
            c.append(Consejo("Sin redirección: prueba parámetros en rutas de "
                             "login/logout reales (set URL con ?return=)",
                             "use web/open_redirect"))
    elif nombre == "web/subdomain_takeover":
        if datos.get("nivel") == "vulnerable":
            c.append(Consejo("Candidato a takeover: hallazgo CRÍTICO — reclama el "
                             "recurso SOLO si el dominio es del cliente y el "
                             "proveedor permite verificar propiedad"))
            c.append(Consejo("Amplía la superficie con más subdominios pasivos",
                             "use osint/cert_transparency"))
        else:
            c.append(Consejo("Sin CNAME colgados: re-audita tras bajas de servicios "
                             "y revisa TXT de verificación sin eliminar"))
    elif nombre == "web/graphql_probe":
        intros = [r for r in (datos.get("resultados") or [])
                  if isinstance(r, dict)
                  and r.get("estado") == "INTROSPECCION_ABIERTA"]
        if intros:
            c.append(Consejo("Introspección abierta: exporta el esquema y revisa "
                             "mutaciones sensibles, límites de profundidad y "
                             "autorización por campo (BOLA)"))
            c.append(Consejo("Prueba field suggestion (campos mal escritos) para "
                             "deducir el esquema si lo cierran",
                             "use web/graphql_probe"))
        elif datos.get("resultados"):
            c.append(Consejo("Endpoint GraphQL activo sin introspección: documenta "
                             "la ruta y audita cookies/headers de la sesión",
                             "use web/cookie_audit"))
        else:
            c.append(Consejo("Sin GraphQL en rutas típicas: revisa los bundles JS "
                             "de la SPA en busca de rutas internas",
                             "use web/exposed_files"))
    elif nombre == "web/crlf_scan":
        if datos.get("inyectadas"):
            c.append(Consejo("CRLF confirmado: hallazgo alto — demuestra el impacto "
                             "con una cookie de sesión falsa en el PoC del informe "
                             "(sin atacar usuarios reales)"))
            c.append(Consejo("Comprueba si el proxy/CDN también es vulnerable: "
                             "el envenenado de caché encadena con este hallazgo",
                             "use web/waf_detect"))
        else:
            c.append(Consejo("Sin CRLF: el framework normaliza %0d%0a. Prueba "
                             "open redirect en parámetros de login",
                             "use web/open_redirect"))
    return c


def _con_ad(nombre, datos):
    c = []
    if nombre == "ad/rootdse_enum":
        dn = datos.get("siguiente_dn") or ""
        if dn:
            c.append(Consejo(f"DN base '{dn}' confirmado: enumera usuarios y grupos "
                             "del dominio", "use ad/ldap_enum"))
            c.append(Consejo("Descubre hosts vivos de la subred del DC",
                             "use ad/net_discover"))
        else:
            c.append(Consejo("Sin DN base: el DC exige autenticación; consigue "
                             "credenciales y repite, o prueba 636 (LDAPS)",
                             "use ad/rootdse_enum"))
    elif nombre == "ad/smb_check":
        evalua = str(datos.get("evaluacion", "")).lower()
        if "firma" in evalua or "no exigida" in evalua:
            c.append(Consejo("SMB sin firma exigida: hallazgo alto — guarda la cadena "
                             "de relay y enumera shares", "use ad/smb_share_enum"))
        c.append(Consejo("Prueba credenciales válidas o contraseñas débiles (AUTHORIZED)",
                         "use ad/smb_login"))
    elif nombre == "ad/smb_share_enum":
        shares = datos.get("shares") or []
        legibles = [s for s in shares if isinstance(s, dict)
                    and "LEGIBLE" in str(s.get("estado", "")).upper()]
        if legibles:
            c.append(Consejo("Shares legibles: revisa SYSVOL (GPP cpassword) y documenta "
                             "lo que contengan; ADMIN$ legible es crítico"))
        c.append(Consejo("Reutiliza credenciales válidas contra LDAP para ampliar "
                         "la enumeración", "use ad/ldap_enum"))
    elif nombre == "ad/spn_enum":
        if _n("cuentas", datos):
            c.append(Consejo("Cuentas con SPN: pide TGS y monta los hashes kerberoast",
                             "use ad/kerberoast"))
    elif nombre == "ad/kerberoast":
        if _n("hashes", datos):
            c.append(Consejo("Crackea los hashes 13100 offline (CRACK true + WORDLIST)",
                             "use ad/kerberoast"))
            c.append(Consejo("¿Clave obtenida? Valídala contra SMB y guárdala en creds",
                             "use ad/smb_login"))
    elif nombre == "ad/asreproast":
        if _n("hashes", datos):
            c.append(Consejo("Crackea los hashes 18200 offline (CRACK true + WORDLIST)",
                             "use ad/asreproast"))
            c.append(Consejo("Con la clave: valida contra SMB y añádela a creds",
                             "use ad/smb_login"))
    elif nombre == "ad/kerberos_userenum":
        if _n("validos", datos):
            c.append(Consejo("Usuarios válidos: busca cuentas sin preauth (AS-REP)",
                             "use ad/asreproast"))
            c.append(Consejo("Con cuidado del lockout: spray de contraseñas canario",
                             "use ad/passwd_spray"))
    elif nombre == "ad/ldap_enum":
        if _n("objetos", datos):
            c.append(Consejo("Enumera cuentas de servicio con SPN a partir de lo hallado",
                             "use ad/spn_enum"))
    elif nombre == "ad/passwd_spray":
        if _n("validas", datos):
            c.append(Consejo("Credenciales vivas: reutilízalas en SMB para enumerar shares",
                             "use ad/smb_share_enum"))
            c.append(Consejo("Revisa el workspace de creds acumuladas", "creds"))
    elif nombre == "ad/smb_login":
        if _n("validas", datos):
            c.append(Consejo("Sesión válida: enumera shares con esas credenciales",
                             "use ad/smb_share_enum"))
            c.append(Consejo("Amplía la enumeración LDAP autenticado",
                             "use ad/ldap_enum"))
    elif nombre == "ad/net_discover":
        if _n("observaciones", datos) or _n("nombres_unicos", datos):
            c.append(Consejo("Hosts anunciados: verifica SMB y su firma",
                             "use ad/smb_check"))
            c.append(Consejo("Añade los IPs descubiertos al engagement (scope) "
                             "antes de interactuar"))
    elif nombre == "ad/gpp_cpassword":
        if any(d.get("contrasena") for d in datos.get("cpasswords", [])
               if isinstance(d, dict)):
            c.append(Consejo("Contraseñas GPP descifradas: valídalas contra SMB y "
                             "guárdalas en creds", "use ad/smb_login"))
            c.append(Consejo("Hallazgo MS14-025: exige rotación de esas credenciales "
                             "y limpieza de cpassword en las GPO"))
        else:
            c.append(Consejo("Sin cpassword en este XML: busca el resto de "
                             "Preferences en SYSVOL (Drives, ScheduledTasks…) "
                             "con RECURSIVO true"))
    return c


def _con_osint(nombre, datos):
    c = []
    if nombre == "osint/email_harvest":
        if _n("emails", datos) or _n("encontrados", datos):
            c.append(Consejo("Verifica qué correos existen realmente por SMTP",
                             "use osint/email_verify"))
            c.append(Consejo("¿Correos filtrados en pastebin? Búsqueda pasiva",
                             "use osint/paste_search"))
    elif nombre == "osint/cert_transparency":
        if _n("subdominios", datos):
            c.append(Consejo("Comprueba qué subdominios están vivos y sirven contenido",
                             "use recon/http_headers"))
    elif nombre == "osint/wayback_urls":
        if _n("con_parametros", datos):
            c.append(Consejo("URLs históricas con parámetros: candidatos a SQLi",
                             "use web/sqli_scanner"))
    elif nombre == "osint/typosquat":
        if _n("registradas", datos):
            c.append(Consejo("Investiga el WHOIS de los dominios registrados",
                             "use osint/whois_lookup"))
            c.append(Consejo("Revisa si alojan phishing: http_headers + contenido"))
    elif nombre == "osint/zone_transfer":
        if _n("registros", datos) or _n("zonas", datos):
            c.append(Consejo("AXFR EXITOSO: hallazgo crítico — todo el mapa DNS público "
                             "queda expuesto; documéntalo en vulns"))
    elif nombre == "osint/email_verify":
        if _n("confirmados", datos):
            c.append(Consejo("Correos válidos: simula la campaña de phishing autorizada",
                             "use phishing/template_gen"))
    elif nombre == "osint/doc_metadata":
        if _n("hallazgos", datos):
            c.append(Consejo("Metadatos con usuarios/rutas: úsalos para usuarios "
                             "plausibles de AD", "use ad/kerberos_userenum"))
    elif nombre == "osint/paste_search":
        if _n("pastes", datos):
            c.append(Consejo("Pastes relacionados: revísalos a mano — credenciales "
                             "filtradas son hallazgo crítico para creds"))
    elif nombre == "osint/reverse_ip":
        c.append(Consejo("Perfila los co-alojados con detección tecnológica",
                         "use web/tech_detect"))
    elif nombre == "osint/spf_dmarc":
        c.append(Consejo("Política débil (p=none / ~all): hallazgo de spoofing — "
                         "documéntalo y propón DMARC p=reject"))
    elif nombre == "osint/dork_builder":
        c.append(Consejo("Cuaderno generado: ejecuta las consultas a mano y añade "
                         "los hallazgos al workspace con notes add"))
        c.append(Consejo("¿Ficheros expuestos encontrados por los dorks? "
                         "Confírmalos de forma sistemática",
                         "use web/exposed_files"))
        c.append(Consejo("Extrae metadatos de los documentos públicos",
                         "use osint/doc_metadata"))
    return c


def _con_cloud(nombre, datos):
    c = []
    if nombre == "cloud/k8s_enum":
        criticos = [r for r in (datos.get("resultados") or [])
                    if isinstance(r, dict)
                    and str(r.get("estado", "")).startswith("ANONIMO")]
        if criticos:
            c.append(Consejo("Plano de control anónimo: hallazgo CRÍTICO — activa "
                             "RBAC, cierra 2375 (socket UNIX) y bloquea 6443/10250 "
                             "desde redes no confiables"))
            c.append(Consejo("Registra los pods visibles en el informe y revisa "
                             "secretos montados en variables de entorno"))
        else:
            c.append(Consejo("Contenedores protegidos: prueba otros nodos del "
                             "clúster o el kubelet 10255 (read-only) si existe",
                             "use cloud/k8s_enum"))
        return c
    listables = 0
    if isinstance(datos.get("resultados"), list):
        listables = sum(1 for r in datos["resultados"]
                        if isinstance(r, dict)
                        and "LISTABLE" in str(r.get("estado", "")).upper())
    if listables:
        c.append(Consejo(f"{listables} recurso(s) LISTABLE(s): hallazgo alto — "
                         "bloquea el acceso público y audita el contenido "
                         "(backups, .env, dumps) antes de valorar el impacto"))
        c.append(Consejo("Registra los hallazgos para el informe final", "vulns"))
    else:
        c.append(Consejo("Sin listado anónimo: prueba nombres derivados de la org "
                         "(org-backups, org-dev, org-public) o dorks indexados",
                         "use osint/dork_builder"))
    return c


def _con_resto(nombre, datos):
    c = []
    if nombre in ("brute/ftp_login", "brute/ssh_login", "brute/http_basic",
                  "brute/telnet_login"):
        if _n("credenciales_validas", datos):
            c.append(Consejo("Credenciales válidas en el workspace: pruébalas en el resto "
                             "de servicios (reuso de contraseñas)", "creds"))
            c.append(Consejo("Con acceso FTP: revisa webroot para colar una webshell "
                             "SOLO en lab autorizado"))
    elif nombre == "phishing/template_gen":
        c.append(Consejo("Sirve la plantilla generada con el servidor de campaña",
                         "use phishing/campaign_server"))
    elif nombre == "phishing/campaign_server":
        c.append(Consejo("Expón el servidor fuera del lab con el túnel",
                         "use phishing/tunnel"))
        c.append(Consejo("Envía el correo simulado con mailer (autorización requerida)",
                         "use phishing/mailer"))
    elif nombre == "phishing/tunnel":
        c.append(Consejo("Usa la URL pública en los correos y vigila las capturas en "
                         "output/phishing/"))
    elif nombre == "phishing/relay_proxy":
        if _n("credenciales_simuladas", datos):
            c.append(Consejo("Credenciales de simulación capturadas: demuestra el "
                             "robo de sesión con las cookies guardadas y cierra "
                             "con recomendaciones (2FA/FIDO2, WebAuthn)",
                             "report"))
        c.append(Consejo("Envía el enlace del lab con el mailer (autorización "
                         "requerida) o a mano en la demo", "use phishing/mailer"))
    elif nombre in ("payloads/dll_sideload", "payloads/loader_gen", "payloads/macro_gen"):
        c.append(Consejo("Prueba el artefacto en el lab y recibe la conexión con TLS",
                         "use post/multi_handler"))
        c.append(Consejo("Recuerda: los artefactos son para entornos de laboratorio "
                         "con consentimiento explícito"))
    elif nombre == "post/multi_handler":
        if _n("conexiones_aceptadas", datos) or datos.get("sesiones"):
            c.append(Consejo("Interactúa con la sesión establecida", "sessions"))
        c.append(Consejo("Recoge evidencia del host con el script de auditoría",
                         "use post/host_audit"))
    elif nombre == "post/host_audit":
        if _n("ficheros", datos):
            c.append(Consejo("Ejecuta el .ps1 en el host de lab e importa el JSON "
                             "al informe final"))
    elif nombre == "opsec/tor_check":
        if not datos.get("es_salida_tor", True):
            c.append(Consejo("No sales por TOR: revisa PROXY y la cadena de anonimato "
                             "antes de ejecutar módulos ruidosos", "use opsec/proxy_check"))
    elif nombre == "opsec/proxy_check":
        if datos.get("fuga_detectada"):
            c.append(Consejo("FUGA detectada: corrige la cadena (PROXY/TOR) antes de "
                             "seguir — cada petición expone tu IP real"))
    elif nombre == "opsec/mac_changer":
        c.append(Consejo("Al terminar, restaura la MAC original (RESTAURAR true)",
                         "use opsec/mac_changer"))
    elif nombre == "iot/device_scan":
        if _n("servicios", datos):
            c.append(Consejo("Dispositivos identificados: audita credenciales de fábrica "
                             "en laboratorio", "use iot/default_creds"))
    elif nombre == "iot/upnp_discover":
        if _n("dispositivos", datos):
            c.append(Consejo("Huella los servicios descubiertos por banner",
                             "use iot/device_scan"))
    elif nombre == "iot/default_creds":
        if _n("hallazgos", datos):
            c.append(Consejo("Credenciales de fábrica vivas: incluye remediarlo en el "
                             "informe (cambio de claves, cierre de Telnet)"))
    elif nombre == "dos/stress_http":
        c.append(Consejo("Métricas orientativas: para capacidades reales usa k6/locust; "
                         "NUNCA contra producción sin ventana acordada"))
    return c


_SOLICITANTES = {
    "recon": _con_recon,
    "web": _con_web,
    "ad": _con_ad,
    "osint": _con_osint,
    "cloud": _con_cloud,
}


# ----------------------------------------------------------------------
# API principal
# ----------------------------------------------------------------------
def consejos_de_resultado(nombre_modulo: str, datos: dict) -> list:
    """Consejos accionables a partir del resultado de un módulo.

    Devuelve entre 1 y 4 Consejos (nunca lanza): heurística de categoría +
    fallbacks generales si el módulo no encontró nada.
    """
    try:
        nombre = (nombre_modulo or "").strip()
        datos = datos if isinstance(datos, dict) else {}
        categoria = nombre.split("/", 1)[0]
        regla = _SOLICITANTES.get(categoria, _con_resto)
        consejos = regla(nombre, datos)

        if not consejos:  # módulo sin regla específica o sin hallazgos
            hay_datos = any(isinstance(v, (list, dict)) and v
                            for k, v in datos.items()
                            if k not in ("resumen", "nota", "aviso"))
            if hay_datos:
                consejos.append(Consejo(
                    "Resultado registrado: revisa el informe completo (report) "
                    "y añade a vulns lo que aplique"))
            else:
                consejos.extend([
                    Consejo("Sin hallazgos: amplía la superficie con OSINT pasivo",
                            "use osint/cert_transparency"),
                    Consejo("O prueba rutas y ficheros comunes del objetivo web",
                            "use web/dir_bruteforce"),
                ])
        return consejos[:4]
    except Exception:  # noqa: BLE001 — los consejos jamás rompen un run
        return []


def plan_de_workspace(workspace) -> list:
    """Plan de batalla leído de la base de datos del workspace."""
    try:
        c = []
        hosts = workspace.hosts() if workspace else []
        creds = workspace.creds() if workspace else []
        vulns = workspace.vulns() if workspace else []

        criticos = [v for v in vulns if str(v.get("severidad")) in ("critico", "alto")]
        if criticos:
            c.append(Consejo(
                f"{len(criticos)} hallazgos altos/críticos: prioriza su verificación "
                "y corrección en el informe"))
        if creds:
            c.append(Consejo(
                f"{len(creds)} credenciales válidas: prueba reuso en otros servicios "
                "(SMB/LDAP) antes de continuar el ataque", "creds"))
        con_smb = [h for h in hosts if any("445" in s or "smb" in s
                   for s in h.get("servicios", []))]
        if con_smb:
            c.append(Consejo(
                f"{len(con_smb)} host(s) con SMB: comienza la cadena AD con smb_check",
                "use ad/smb_check"))
        con_web = [h for h in hosts if any(
            s.startswith(("80/", "443/", "8080/")) for s in h.get("servicios", []))]
        if con_web:
            c.append(Consejo(
                f"{len(con_web)} host(s) web: perfila la pila tecnológica",
                "use web/tech_detect"))
        if not c:
            c.extend([
                Consejo("Workspace vacío: empieza por reconocer el objetivo",
                        "use recon/ip_info"),
                Consejo("O descubre hosts vivos en la red autorizada",
                        "use recon/ping_sweep"),
            ])
        return c[:6]
    except Exception:  # noqa: BLE001
        return [Consejo("No se pudo leer el workspace: prueba use recon/ping_sweep")]
