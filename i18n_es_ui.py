"""Spanish catalog for the user interface: domaininfo.py, terminal_ui.py, render.py,
completions.py and the legacy report.py/traceroute.py helpers.

Keys are the English source strings; placeholders must match exactly (tests/test_i18n.py).
"""

STRINGS = {
    # --- domaininfo.py: validation and module messages --------------------------------------
    "Empty target or target with spaces/control characters": "Objetivo vacío o con espacios/caracteres de control",
    "Only HTTP/HTTPS URLs are accepted": "Solo se aceptan URLs HTTP/HTTPS",
    "Credentials are not accepted in the target": "No se aceptan credenciales en el objetivo",
    "Port out of range": "Puerto fuera de rango",
    "The target name is missing": "Falta el nombre del objetivo",
    "Invalid domain": "Dominio inválido",
    "Invalid IPv4 address": "Dirección IPv4 inválida",
    "domains only": "solo para dominios",
    "Local name: system addresses only": "Nombre local: solo direcciones del sistema",
    "RDAP answered HTTP {status}": "RDAP respondió HTTP {status}",
    "RDAP response too large": "Respuesta RDAP demasiado grande",
    "No registration data and no Wayback Machine data": "Sin datos de registro ni de Wayback Machine",
    "Missing headers are observations; they do not prove a vulnerability":
        "Headers ausentes son observaciones; no prueban una vulnerabilidad",
    "Install traceroute/tracepath; TCP hops are not simulated":
        "Instala traceroute/tracepath; no se simulan saltos TCP",
    "Traceroute finished with an error": "Traceroute terminó con error",
    "Must be an integer": "Debe ser un entero",
    "Must be between {low} and {high}": "Debe estar entre {low} y {high}",
    "Invalid timeout": "Timeout inválido",
    "Timeout must be between 0.1 and 60 seconds": "Timeout debe estar entre 0.1 y 60 segundos",
    "Invalid ports: use 22,80,443 (1-65535)": "Puertos inválidos: usa 22,80,443 (1-65535)",
    "stdlib; no root or pip needed": "stdlib; sin root ni pip",
    "Invalid host in --scope: {host}": "Host inválido en --scope: {host}",

    # --- domaininfo.py: help --------------------------------------------------------------
    """\
examples:
  domaininfo                                    guided menu
  domaininfo example.com                        quick analysis (DNS + registration)
  domaininfo -m web example.com                 website, headers and TLS certificate
  domaininfo -m ports --ports 22,80,443 10.0.0.5
  domaininfo -m full -s traceroute example.com  everything except the network route
  domaininfo -f targets.txt -m web --format html
  domaininfo -m mikrotik 192.168.88.1
  domaininfo -m mikrotik --offline --routeros-version 7.24.2
  domaininfo -m web --watch 300 example.com     watch and report changes
  domaininfo -m webapp --url https://example.com/login
                                                passive web security review of one URL
  domaininfo -m webapp --url https://app.example.com/ --scope auth.example.com
                                                allows following redirects to another authorized host
  domaininfo example.com --json --pretty        indented JSON
  domaininfo example.com | jq .                 in a pipe the output is JSON automatically
  domaininfo --lang es example.com              output in Spanish (or set DOMAININFO_LANG=es)

output:
  At a terminal you get a readable, colored summary. If the output goes to another
  program or a file, or you use --json/-q, the usual JSON is printed (one per target).
  NO_COLOR disables colors. Exit codes: 0 success, 1 errors in modules or
  targets, 2 invalid arguments, 130 interrupted.

Use the network modes only on systems you are authorized to review.""": """\
ejemplos:
  domaininfo                                    menú guiado
  domaininfo example.com                        análisis rápido (DNS + registro)
  domaininfo -m web example.com                 web, cabeceras y certificado TLS
  domaininfo -m ports --ports 22,80,443 10.0.0.5
  domaininfo -m full -s traceroute example.com  todo menos la ruta de red
  domaininfo -f objetivos.txt -m web --format html
  domaininfo -m mikrotik 192.168.88.1
  domaininfo -m mikrotik --offline --routeros-version 7.24.2
  domaininfo -m web --watch 300 example.com     vigilar y avisar de cambios
  domaininfo -m webapp --url https://example.com/login
                                                seguridad web pasiva de una URL concreta
  domaininfo -m webapp --url https://app.example.com/ --scope auth.example.com
                                                permite seguir redirecciones a otro host autorizado
  domaininfo example.com --json --pretty        JSON con sangría
  domaininfo example.com | jq .                 en una tubería sale JSON automáticamente
  domaininfo --lang en example.com              salida en inglés (o DOMAININFO_LANG=en)

salida:
  En una terminal se muestra un resumen legible con colores. Si la salida va a otro
  programa o archivo, o usas --json/-q, se imprime el JSON de siempre (uno por objetivo).
  NO_COLOR desactiva los colores. Códigos de salida: 0 correcto, 1 errores en módulos u
  objetivos, 2 argumentos inválidos, 130 interrumpido.

Usa los modos de red solo sobre sistemas que tengas autorización para revisar.""",
    "usage: ": "uso: ",
    "DomainInfo: portable diagnostics for domains and IPs": "DomainInfo: diagnóstico portable de dominios e IPs",
    "arguments": "argumentos",
    "domain, IPv4, IPv6 or HTTP/HTTPS URL": "dominio, IPv4, IPv6 o URL HTTP/HTTPS",
    "show this help and exit": "muestra esta ayuda y sale",
    "show the version and exit": "muestra la versión y sale",
    "open the guided menu": "abre el menú guiado",
    "local diagnostics of this computer, no scans": "diagnóstico local del equipo, sin escaneos",
    "update DomainInfo to the latest version": "actualiza DomainInfo a la última versión",
    "print the autocompletion script for your shell": "imprime el script de autocompletado para tu shell",
    "output language (default: DOMAININFO_LANG, else en)": "idioma de la salida (por defecto: DOMAININFO_LANG o en)",
    "audit": "auditoría",
    "quick: DNS and registration · web: HTTP, headers and TLS · ports: TCP ports · "
    "full: everything · mikrotik: RouterOS · webapp: one specific URL (default: %(default)s)":
        "quick: DNS y registro · web: HTTP, cabeceras y TLS · ports: puertos TCP · "
        "full: todo · mikrotik: RouterOS · webapp: una URL concreta (por defecto: %(default)s)",
    "webapp: full URL to audit; port, path and parameters are kept":
        "webapp: URL completa a auditar; se conservan puerto, ruta y parámetros",
    "FILE": "ARCHIVO",
    "UTF-8 file with one target per line (# for comments)": "archivo UTF-8 con un objetivo por línea (# para comentarios)",
    "MODULE": "MÓDULO",
    "skip a module; can be repeated: {modules}": "omite un módulo; se puede repetir: {modules}",
    "subdomains: besides certificates, also try the word list":
        "subdominios: además de los certificados, probar la lista de palabras",
    "TLS: do not check which versions the server accepts (faster)":
        "TLS: no comprobar qué versiones acepta el servidor (más rápido)",
    "SECONDS": "SEGUNDOS",
    "repeat the review every N seconds and report only changes (CTRL+C to quit)":
        "repite la revisión cada N segundos y avisa solo de los cambios (CTRL+C para salir)",
    "network": "red",
    "simultaneous TCP connections, 1-64 (default: %(default)s)":
        "conexiones TCP simultáneas, 1-64 (por defecto: %(default)s)",
    "DNS server for MX/TXT/NS (default: the system's; if it does not answer, DNS over HTTPS)":
        "servidor DNS para MX/TXT/NS (por defecto el del sistema; si no responde, DNS sobre HTTPS)",
    "SEC": "SEG",
    "maximum wait per connection, 0.1-60 s (default: %(default)s)":
        "espera máxima por conexión, 0.1-60 s (por defecto: %(default)s)",
    "LIST": "LISTA",
    "comma-separated TCP ports, e.g. 22,80,443 (default depends on the mode)":
        "puertos TCP separados por comas, p. ej. 22,80,443 (por defecto según el modo)",
    "protocol for the web mode (default: %(default)s)": "protocolo para el modo web (por defecto: %(default)s)",
    "PORT": "PUERTO",
    "web server port (default 443 or 80)": "puerto del servidor web (por defecto 443 o 80)",
    "scope and safety (webapp)": "alcance y seguridad (webapp)",
    "extra hosts authorized for following redirects, e.g. auth.example.com,*.cdn.example.com":
        "hosts adicionales autorizados para seguir redirecciones, p. ej. auth.example.com,*.cdn.example.com",
    "allow a public target to redirect or resolve to internal networks (only if authorized)":
        "permite que un objetivo público redirija o resuelva a redes internas (solo si está autorizado)",
    "read the page even if its certificate is not valid (noted in the report)":
        "lee la página aunque su certificado no sea válido (queda indicado en el reporte)",
    "VERSION": "VERSIÓN",
    "declared RouterOS version, for example 7.25": "versión RouterOS declarada, por ejemplo 7.25",
    "SSH port to read the banner, without authentication (default: %(default)s)":
        "puerto SSH para leer el banner, sin autenticación (por defecto: %(default)s)",
    "evaluate the version without connecting to any device": "evalúa la versión sin conectar con ningún equipo",
    "output": "salida",
    "print JSON even at a terminal": "imprime JSON aunque estés en una terminal",
    "indented JSON, easier to read": "JSON con sangría, más fácil de leer",
    "JSON only on stdout, no progress": "solo JSON en stdout, sin progreso",
    "FOLDER": "CARPETA",
    "reports folder (default: %(default)s)": "carpeta de reportes (por defecto: %(default)s)",
    "report formats to save (default: %(default)s)": "formatos de reporte que se guardan (por defecto: %(default)s)",
    "open the HTML report when finished": "abre el reporte HTML al terminar",
    "show report paths on stderr": "muestra las rutas de los reportes en stderr",

    # --- domaininfo.py: runtime messages ---------------------------------------------------
    "Installed: v{version} · latest published: {latest}": "Instalada: v{version} · última publicada: {latest}",
    "Installed: v{version}": "Instalada: v{version}",
    "Could not update with git. Check whether you have local changes in {path}":
        "No se pudo actualizar con git. Revisa si tienes cambios locales en {path}",
    "This copy is not a git repository. Update with the method you used to install it:":
        "Esta copia no es un repositorio git. Actualiza con el método que usaste al instalar:",
    "Could not open the browser: {path}": "No se pudo abrir el navegador: {path}",
    "Addresses": "Direcciones",
    "HTTP status": "Estado HTTP",
    "Missing headers": "Cabeceras ausentes",
    "Certificate expiry": "Caducidad del certificado",
    "Certificate serial number": "Número de serie del certificado",
    "TLS protocol": "Protocolo TLS",
    "Open ports": "Puertos abiertos",
    "RouterOS version": "Versión RouterOS",
    "Mail grade": "Nota del correo",
    "DMARC policy": "Política DMARC",
    "Active subdomains": "Subdominios activos",
    "Subdomains open to takeover": "Subdominios con posible toma",
    "Technologies": "Tecnologías",
    "Registered lookalike domains": "Dominios parecidos registrados",
    "Security grade": "Nota de seguridad",
    "HTTP status of the URL": "Estado HTTP de la URL",
    "Confirmed or likely web findings": "Hallazgos web confirmados o probables",
    "Module {name}": "Módulo {name}",
    "Could not save the report: {error}": "No se pudo guardar reporte: {error}",
    "Reports: {paths}": "Reportes: {paths}",
    "Batch: {count} items shared between targets · {paths}": "Lote: {count} elementos compartidos entre objetivos · {paths}",
    "Could not save the batch summary: {error}": "No se pudo guardar el resumen del lote: {error}",
    "Watching {count} target(s) every {seconds} s. CTRL+C to quit.":
        "Vigilando {count} objetivo(s) cada {seconds} s. CTRL+C para salir.",
    "[{time}] {target}: no changes": "[{time}] {target}: sin cambios",
    "Watch stopped.": "Vigilancia detenida.",
    "--resolver must be one or more comma-separated IP addresses": "--resolver debe ser una o varias IP separadas por comas",
    "--routeros-version and --offline require -m mikrotik": "--routeros-version y --offline requieren -m mikrotik",
    "--offline requires --routeros-version and does not accept targets/files":
        "--offline requiere --routeros-version y no acepta objetivos/archivos",
    "--url requires -m webapp": "--url requiere -m webapp",
    "Use --url, a target or --file, not several at once": "Usa --url, un objetivo o --file, no varios a la vez",
    "Use a target or --file, not both": "Usa un objetivo o --file, no ambos",
    "--interactive does not accept a target, --file or --offline; choose inside the menu":
        "--interactive no acepta objetivo, --file ni --offline; elige dentro del menú",
    "Give a target, --file or --doctor": "Indica un objetivo, --file o --doctor",
    "Invalid target {target}: {error}": "Objetivo inválido {target}: {error}",
    "No valid targets": "No hay objetivos válidos",
    "Interrupted": "Interrumpido",

    # --- terminal_ui.py: labels ----------------------------------------------------------
    "Quick analysis": "Análisis rápido",
    "Resolve IPs and look up the domain registration": "Resolver IPs y consultar el registro del dominio",
    "Website and certificate": "Sitio web y certificado",
    "HTTP, security headers and TLS connection": "HTTP, cabeceras de seguridad y conexión TLS",
    "TCP ports": "Puertos TCP",
    "Check which services are reachable from your computer": "Comprobar servicios accesibles en tu equipo",
    "Full diagnostics": "Diagnóstico completo",
    "Everything: DNS, registration, network, web, TLS, mail, subdomains and ports":
        "Todo: DNS, registro, red, web, TLS, correo, subdominios y puertos",
    "Domain mail": "Correo del dominio",
    "SPF, DMARC, DKIM and MTA-STS: can the domain be spoofed?":
        "SPF, DMARC, DKIM y MTA-STS: ¿se puede suplantar el dominio?",
    "OSINT reconnaissance": "Reconocimiento OSINT",
    "Subdomains, network (ASN), technologies and domain history":
        "Subdominios, red (ASN), tecnologías e historia del dominio",
    "Brand and phishing": "Marca y phishing",
    "Registered lookalike domains that could imitate yours": "Dominios parecidos registrados que podrían imitar el tuyo",
    "Version, management services and applicable advisories": "Versión, servicios de gestión y avisos aplicables",
    "Web application security": "Seguridad de aplicación web",
    "One specific URL: forms, CSRF, cookies, CSP, CORS and errors":
        "Una URL concreta: formularios, CSRF, cookies, CSP, CORS y errores",
    "CONFIRMED": "CONFIRMADO",
    "LIKELY": "PROBABLE",
    "PENDING VERIFICATION": "PENDIENTE DE VERIFICAR",
    "NOT APPLICABLE": "NO APLICA",
    "NOT EVALUATED": "NO EVALUADO",
    "token in <meta> (check that it is sent)": "token en <meta> (revisar envío)",
    "no token; SameSite cookies": "sin token; cookies SameSite",
    "no visible protection (pending verification)": "sin protección visible (pendiente de verificar)",
    "not applicable (GET)": "no aplica (GET)",
    "Address resolution": "Resolución de direcciones",
    "RDAP registration": "Registro RDAP",
    "Website and HTTP headers": "Sitio y cabeceras HTTP",
    "TLS certificate": "Certificado TLS",
    "TCP services": "Servicios TCP",
    "Network route": "Ruta de red",
    "RouterOS audit": "Auditoría RouterOS",
    "Network and operator (ASN)": "Red y operador (ASN)",
    "Mail security": "Seguridad del correo",
    "Technologies and headers": "Tecnologías y cabeceras",
    "Subdomains": "Subdominios",
    "Domain history": "Historia del dominio",
    "Lookalike domains": "Dominios parecidos",
    "IPv4/IPv6 addresses the system returns for the target.": "Direcciones IPv4/IPv6 que el sistema devuelve para el objetivo.",
    "Public registration data of the domain or of the IP address block.":
        "Datos públicos del registro del dominio o del bloque de direcciones IP.",
    "Page response and headers that state the site's security policies.":
        "Respuesta de la página y cabeceras que indican políticas de seguridad del sitio.",
    "Negotiated encrypted protocol and certificate validated by Python.":
        "Protocolo cifrado negociado y certificado validado por Python.",
    "TCP services that answered from this computer during the review.":
        "Servicios TCP que respondieron desde este equipo durante la revisión.",
    "Network hops reported by the system's route tool.": "Saltos de red informados por la herramienta de ruta del sistema.",
    "Comparison of the RouterOS version with the advisories of the dated catalog.":
        "Comparación de la versión RouterOS con los avisos del catálogo fechado.",
    "Autonomous system, network block, country, operator and reverse name of each IP.":
        "Sistema autónomo, bloque de red, país, operador y nombre inverso de cada IP.",
    "SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI: whether someone can send fake mail on behalf of the domain.":
        "SPF, DMARC, DKIM, MTA-STS, TLS-RPT y BIMI: si alguien puede enviar correo falso en nombre del dominio.",
    "Detected technologies, security header grade, cookies, favicon and security.txt.":
        "Tecnologías detectadas, nota de las cabeceras de seguridad, cookies, favicon y security.txt.",
    "Subdomains published in certificate logs and subdomains that could be taken over.":
        "Subdominios publicados en registros de certificados y subdominios que podrían ser tomados.",
    "Registration age and expiry, registrar and Wayback Machine captures.":
        "Antigüedad y caducidad del registro, registrador y capturas en la Wayback Machine.",
    "Name variants (typos, homoglyphs, other TLDs) that are registered.":
        "Variantes del nombre (errores de tecleo, homoglifos, otros TLD) que están registradas.",
    "Passive analysis of the requested URL (GET only): forms, CSRF, cookies, headers, CORS, "
    "technical errors and exposed data, compared with the site root.":
        "Análisis pasivo de la URL pedida (solo GET): formularios, CSRF, cookies, cabeceras, CORS, "
        "errores técnicos y datos expuestos, comparado con la raíz del sitio.",
    "HIGH": "ALTA",
    "MEDIUM": "MEDIA",
    "LOW": "BAJA",
    "high": "alta",
    "medium": "media",
    "low": "baja",
    "REVIEW: version included in the advisory": "REVISAR: versión incluida en el aviso",
    "Version outside the affected range": "Versión fuera del intervalo afectado",
    "NOT EVALUATED: the version is missing": "SIN EVALUAR: falta la versión",
    "NO CONCLUSION: review the version manually": "SIN CONCLUSIÓN: revisar la versión manualmente",
    "[WARNING]": "[AVISO]",
    "[MISSING]": "[FALTA]",

    # --- terminal_ui.py: menus and screens ---------------------------------------------
    "MAIN MENU": "MENÚ PRINCIPAL",
    "DNS + domain registration": "DNS + registro del dominio",
    "HTTP + headers + TLS": "HTTP + cabeceras + TLS",
    "Reachable TCP services": "Servicios TCP accesibles",
    "All general modules": "Todos los módulos generales",
    "Router on the network or offline version": "Router en red o versión offline",
    "Can the mail be spoofed?": "¿Se puede suplantar el correo?",
    "Subdomains, network and technologies": "Subdominios, red y tecnologías",
    "Domains that imitate yours": "Dominios que imitan el tuyo",
    "Full URL: login, cookies, CSP": "URL completa: login, cookies, CSP",
    "Several targets": "Varios objetivos",
    "Audit from a file": "Auditoría desde un archivo",
    "My reports": "Mis reportes",
    "Results and exports": "Resultados y exportaciones",
    "Preferences": "Preferencias",
    "Connections, timeouts, formats and language": "Conexiones, tiempos, formatos e idioma",
    "Computer diagnostics": "Diagnóstico del equipo",
    "Status of the tools": "Estado de las herramientas",
    "Classic audits": "Auditorías clásicas",
    "ISP / WebApp / LAN with Bash": "ISP / WebApp / LAN con Bash",
    "01 / AUDITS": "01 / AUDITORÍAS",
    "02 / TOOLS": "02 / HERRAMIENTAS",
    "AUDITS": "AUDITORÍAS",
    "TOOLS": "HERRAMIENTAS",
    "NAVIGATION": "NAVEGACIÓN",
    "[h] Quick help     [0] Exit": "[h] Ayuda rápida     [0] Salir",
    "Press the option's key to start.": "Pulsa la tecla de la opción para comenzar.",
    "Press a key · 0 to exit": "Pulsa una tecla · 0 para salir",
    "Choose a module to start. NUMBER + ENTER": "Elige un módulo para comenzar. NÚMERO + ENTER",
    "NUMBER + ENTER · 0 to exit": "NÚMERO + ENTER · 0 para salir",
    "DOMAINS / NETWORKS / ROUTEROS": "DOMINIOS / REDES / ROUTEROS",
    "ANALYSIS PANEL": "PANEL DE ANÁLISIS",
    "[0 / r] Back to the previous menu": "[0 / r] Regresar al menú anterior",
    "You are already at the main menu. Use 0 to exit.": "Ya estás en el menú principal. Usa 0 para salir.",
    "Type a value or 0 to go back.": "Escribe un valor o 0 para volver.",
    "Invalid option. Press one of the menu keys; 0 to go back.":
        "Opción no válida. Pulsa una de las teclas del menú; 0 para volver.",
    "Choose an option": "Elige una opción",
    "Invalid option. Use the menu numbers; 0 to go back.": "Opción no válida. Usa los números del menú; 0 para volver.",
    "[0 / r] Back · ENTER to continue...": "[0 / r] Regresar · ENTER para continuar...",
    "Action cancelled. You can choose another option.": "Acción cancelada. Puedes elegir otra opción.",
    "Session closed.": "Sesión cerrada.",
    "Full URL with path. Example: https://example.com/login": "URL completa con ruta. Ejemplo: https://example.com/login",
    "Only GET requests are made: no forms or credentials are submitted.":
        "Solo se hacen peticiones GET: no se envían formularios ni credenciales.",
    "URL (0 to go back)": "URL (0 para volver)",
    "Accepts a domain, IPv4, IPv6 or URL. Example: 192.168.88.1": "Acepta dominio, IPv4, IPv6 o URL. Ejemplo: 192.168.88.1",
    "Target (0 to go back)": "Objetivo (0 para volver)",
    "Version from your inventory. Examples: 7.25, 7.23.8.": "Versión de tu inventario. Ejemplos: 7.25, 7.23.8.",
    "ENTER without a version: it will try to detect it from public banners.":
        "ENTER sin versión: se intentará detectar mediante banners públicos.",
    "RouterOS version (0 to go back)": "Versión RouterOS (0 para volver)",
    "Step 1 · Choose the type of review.": "Paso 1 · Elige el tipo de revisión.",
    "Check a router on the network": "Revisar un router en la red",
    "Reachable services, banners and advisories by version": "Servicios accesibles, banners y avisos por versión",
    "Check a version only": "Revisar solo una versión",
    "No connection to routers or Internet services": "Sin conexión a routers ni servicios de Internet",
    "Step 1 · Choose the target.": "Paso 1 · Elige el objetivo.",
    "The file contains no valid targets.": "El archivo no contiene objetivos válidos.",
    "UTF-8 file with one target per line; comments and duplicates are skipped.":
        "Archivo UTF-8 con un objetivo por línea; se omiten comentarios y duplicados.",
    "File path (0 to go back)": "Ruta del archivo (0 para volver)",
    "Step 1 · Load your file. 0 to go back.": "Paso 1 · Carga tu archivo. 0 para volver.",
    "{targets} targets ready; {ignored} invalid or duplicate lines skipped.":
        "{targets} objetivos preparados; {ignored} líneas inválidas o duplicadas omitidas.",
    "Type of audit": "Tipo de auditoría",
    "This file cannot be used in {mode}: {error}": "No se puede usar este archivo en {mode}: {error}",
    "The version you give applies to every device; leave it empty if they differ.":
        "La versión indicada se aplicará a todos los equipos; déjala vacía si difieren.",
    "Ready to review": "Todo listo para revisar",
    "Step 2 · Check the options and choose Start.": "Paso 2 · Revisa las opciones y elige Iniciar.",
    "Audit: {mode}": "Auditoría: {mode}",
    "Target: RouterOS version, no network connections": "Objetivo: versión RouterOS, sin conexiones de red",
    "File: {path}": "Archivo: {path}",
    "Targets: {count} · skipped/duplicates: {ignored}": "Objetivos: {count} · omitidos/duplicados: {ignored}",
    "Preview: {targets}": "Vista previa: {targets}",
    "Target: {target}": "Objetivo: {target}",
    "RouterOS: {version}": "RouterOS: {version}",
    "detection from banners; it may not be published": "detección por banners; puede no publicarse",
    "Time per connection: {timeout} s · connections: {threads}": "Tiempo por conexión: {timeout} s · conexiones: {threads}",
    "Web: {scheme} · port {port}": "Web: {scheme} · puerto {port}",
    "default": "predeterminado",
    "TCP ports: {ports}": "Puertos TCP: {ports}",
    "the mode's recommended list": "lista recomendada del modo",
    "Scope: the URL's host + {hosts}; redirects outside it are not followed":
        "Alcance: el host de la URL + {hosts}; redirecciones fuera de él no se siguen",
    "Scope: the URL's host; redirects outside it are not followed":
        "Alcance: el host de la URL; redirecciones fuera de él no se siguen",
    "GET requests only: no forms or credentials are submitted.":
        "Solo peticiones GET: no se envían formularios ni credenciales.",
    "Modules: {modules}": "Módulos: {modules}",
    "none selected": "ninguno seleccionado",
    "RDAP will look up the target's registration through rdap.org.":
        "RDAP consultará el registro del objetivo a través de rdap.org.",
    "Reports: {folder} · {format}": "Reportes: {folder} · {format}",
    "Start audit": "Iniciar auditoría",
    "Change version": "Cambiar versión",
    "Change file": "Cambiar archivo",
    "Change target": "Cambiar objetivo",
    "Adjust options for this audit": "Ajustar opciones para esta auditoría",
    "Set or change the RouterOS version": "Indicar o cambiar versión RouterOS",
    "Back to the main menu": "Volver al menú principal",
    "Enable at least one module from Adjust options.": "Activa al menos un módulo desde Ajustar opciones.",
    "Options for this audit": "Opciones de esta auditoría",
    "Session preferences": "Preferencias de la sesión",
    "Changes apply when you go back; 0 to go back.": "Los cambios se aplican al volver; 0 para volver.",
    "Time per connection: {timeout} seconds": "Tiempo por conexión: {timeout} segundos",
    "Simultaneous connections: {threads}": "Conexiones simultáneas: {threads}",
    "Reports folder: {folder}": "Carpeta de reportes: {folder}",
    "Format: {format}": "Formato: {format}",
    "recommended": "recomendados",
    "Choose modules": "Elegir módulos",
    "SSH port: {port}": "Puerto SSH: {port}",
    "Language: {language}": "Idioma: {language}",
    "Restore default values": "Restablecer valores predeterminados",
    "Save and go back": "Guardar y volver",
    "Seconds (0.1 to 60)": "Segundos (0.1 a 60)",
    "Connections (1 to 64)": "Conexiones (1 a 64)",
    "That path is a file. Choose a folder.": "Esa ruta es un archivo. Elige una carpeta.",
    "Folder": "Carpeta",
    "All: HTML + JSON + TXT": "Todos: HTML + JSON + TXT",
    "HTML only": "Solo HTML",
    "JSON only": "Solo JSON",
    "TXT only": "Solo TXT",
    "Example: 22,80,443. Type auto for the recommended list.": "Ejemplo: 22,80,443. Escribe auto para la lista recomendada.",
    "Ports": "Puertos",
    "HTTPS (encrypted)": "HTTPS (cifrado)",
    "Web port (auto for the default)": "Puerto web (auto para predeterminado)",
    "SSH port": "Puerto SSH",
    "Audit modules": "Módulos de la auditoría",
    "Select one to enable/disable it. 0 to go back.": "Selecciona uno para activarlo/desactivarlo. 0 para volver.",
    "Audit in progress": "Auditoría en curso",
    "Finished results are saved even if you cancel later.": "Los resultados terminados se guardan aunque canceles después.",
    "Target {index}/{total} · {target}": "Objetivo {index}/{total} · {target}",
    "RUNNING": "EN CURSO",
    "DONE": "LISTO",
    "SKIPPED": "OMITIDO",
    "Could not save the reports: {error}": "No se pudieron guardar los reportes: {error}",
    "Saved: {path}": "Guardado: {path}",
    "Batch finished: {count} targets. See the recent ones in My reports.":
        "Batch terminado: {count} objetivos. Consulta los recientes en Mis reportes.",

    # --- terminal_ui.py: summaries -------------------------------------------------------
    "SUMMARY": "RESUMEN",
    "Checks: {done} finished / {errors} with errors / {skipped} skipped":
        "Comprobaciones: {done} terminadas / {errors} con error / {skipped} omitidas",
    "Security grade: {grade} ({score}/100) · {high} high, {medium} medium, {low} low":
        "Nota de seguridad: {grade} ({score}/100) · {high} altos, {medium} medios, {low} bajos",
    "no details": "sin detalle",
    "{module}: skipped ({reason})": "{module}: omitido ({reason})",
    "{module}: skipped": "{module}: omitido",
    "Addresses: {addresses}": "Direcciones: {addresses}",
    "none": "ninguna",
    "DNS servers: {servers}": "Servidores DNS: {servers}",
    "Mail (MX): {hosts}": "Correo (MX): {hosts}",
    "Alias (CNAME): {names}": "Alias (CNAME): {names}",
    "DNSSEC: {dnssec} · CAA: {caa}": "DNSSEC: {dnssec} · CAA: {caa}",
    "active": "activo",
    "yes": "sí",
    "Reverse name: {names}": "Nombre inverso: {names}",
    "response available in the report": "respuesta disponible en el reporte",
    "Registration: {name} · status: {status}": "Registro: {name} · estado: {status}",
    "Registration: {name}": "Registro: {name}",
    "no title": "sin título",
    "Recommended headers missing: {headers}": "Cabeceras recomendadas ausentes: {headers}",
    "none of those checked": "ninguna de las comprobadas",
    "Reachable TCP ports: {ports}": "Puertos TCP accesibles: {ports}",
    "none in the reviewed list": "ninguno en la lista revisada",
    "No answer: {closed} of {total} ports reviewed": "Sin respuesta: {closed} de {total} puertos revisados",
    "Network route: {route}": "Ruta de red: {route}",
    "not available": "no disponible",
    "available in the details": "disponible en el detalle",
    "no public data": "sin datos públicos",
    "{ips} and {count} more": "{ips} y {count} más",
    "Network: {network} · {ips}": "Red: {network} · {ips}",
    "Mail: grade {grade} · CAN BE SPOOFED (DMARC does not block fake mail)":
        "Correo: nota {grade} · SE PUEDE SUPLANTAR (DMARC no bloquea correos falsos)",
    "Mail: grade {grade} · protected against spoofing": "Correo: nota {grade} · protegido contra suplantación",
    "SPF: {spf} · DMARC: {dmarc} · DKIM: {dkim} · MTA-STS: {mta_sts}":
        "SPF: {spf} · DMARC: {dmarc} · DKIM: {dkim} · MTA-STS: {mta_sts}",
    "no -all": "sin -all",
    "missing": "ausente",
    "not found": "no encontrado",
    "The domain does not receive mail (no MX or null MX).": "El dominio no recibe correo (sin MX o MX nulo).",
    "none identified": "no identificadas",
    "Web: {status} · security headers: grade {grade} ({points}/100)":
        "Web: {status} · cabeceras de seguridad: nota {grade} ({points}/100)",
    "Technologies: {list} · generator: {generator}": "Tecnologías: {list} · generador: {generator}",
    "Technologies: {list}": "Tecnologías: {list}",
    "Favicon: {hash} (search it in Shodan to find identical servers)":
        "Favicon: {hash} (búscalo en Shodan para hallar servidores iguales)",
    "security.txt published": "security.txt publicado",
    "{count} redirects": "{count} redirecciones",
    "{count} cookies without protections": "{count} cookies sin protecciones",
    "Subdomains: {total} found ({sources}) · {alive} active": "Subdominios: {total} encontrados ({sources}) · {alive} activos",
    "no source": "sin fuente",
    "POSSIBLE TAKEOVER": "TOMA POSIBLE",
    "REVIEW": "REVISAR",
    "registered on {date} ({days} days)": "registrado el {date} ({days} días)",
    "expires on {date}": "caduca el {date}",
    "registrar: {name}": "registrador: {name}",
    "Domain: {details}": "Dominio: {details}",
    "no public registration dates": "sin fechas de registro públicas",
    "Recent domain: a common sign of phishing sites.": "Dominio reciente: es una señal habitual de sitios de phishing.",
    "Wayback Machine: first capture {first} · last {last}": "Wayback Machine: primera captura {first} · última {last}",
    "Lookalike domains: {registered} registered out of {checked} variants · {mail} receive mail":
        "Dominios parecidos: {registered} registrados de {checked} variantes · {mail} reciben correo",
    "receives mail": "recibe correo",
    "URL: {url} · HTTP {status} · {title}": "URL: {url} · HTTP {status} · {title}",
    "Site root: it is the same URL being audited": "Raíz del sitio: es la misma URL auditada",
    "Site root: not compared ({error})": "Raíz del sitio: no comparada ({error})",
    "Site root: HTTP {status} · {title} · content differs from the requested URL":
        "Raíz del sitio: HTTP {status} · {title} · contenido distinto al de la URL pedida",
    "Site root: HTTP {status} · {title} · SAME content as the requested URL (check whether the path exists)":
        "Raíz del sitio: HTTP {status} · {title} · MISMO contenido que la URL pedida (revisa si la ruta existe)",
    "Redirect {status} → {location}": "Redirección {status} → {location}",
    "NOT FOLLOWED: {reason}": "NO SEGUIDA: {reason}",
    "Security {security}/100 · Coverage {coverage}% · Confidence {confidence}%":
        "Seguridad {security}/100 · Cobertura {coverage}% · Confianza {confidence}%",
    "form": "formulario",
    "Form {index} ({kind}): {method} → {action}": "Formulario {index} ({kind}): {method} → {action}",
    "fields {fields}": "campos {fields}",
    "Cookies: {cookies}  (S=Secure, H=HttpOnly)": "Cookies: {cookies}  (S=Secure, H=HttpOnly)",
    "no SameSite": "sin SameSite",
    "… and {count} more in the report": "… y {count} más en el reporte",
    "No confirmed or pending findings in the passive checks.":
        "Sin hallazgos confirmados ni pendientes en las comprobaciones pasivas.",
    "TLS: {protocol} · INVALID CERTIFICATE: {error}": "TLS: {protocol} · CERTIFICADO NO VÁLIDO: {error}",
    "Issued by {issuer} for {subject}": "Emitido por {issuer} para {subject}",
    "(self-signed)": "(autofirmado)",
    "Accepted TLS versions: {versions}": "Versiones TLS aceptadas: {versions}",
    "accepts old versions": "acepta versiones antiguas",
    "expiry date not available": "fecha de caducidad no disponible",
    "TLS: {protocol} · certificate EXPIRED {days} days ago ({date})":
        "TLS: {protocol} · certificado CADUCADO hace {days} días ({date})",
    "TLS: {protocol} · verified certificate · {when}": "TLS: {protocol} · certificado verificado · {when}",
    "Warning: the certificate expires in {days} days. Renew it soon.":
        "Aviso: el certificado caduca en {days} días. Conviene renovarlo pronto.",
    "TLS: {protocol} · verified certificate · {when} ({days} days)":
        "TLS: {protocol} · certificado verificado · {when} ({days} días)",
    "given by you": "indicada por ti",
    "public banner": "banner público",
    "not obtained": "no obtenida",
    "RouterOS: {version} · {source}": "RouterOS: {version} · {source}",
    "unknown": "desconocida",
    "Catalog reviewed: {date}": "Catálogo revisado: {date}",
    "no date": "sin fecha",
    "Advisories that could affect this version: {count}": "Avisos que podrían afectar esta versión: {count}",
    "Advisories that do not include this version: {count}": "Avisos que no incluyen esta versión: {count}",
    "Advisories not evaluated: {count}": "Avisos sin evaluar: {count}",
    "There are contradictory versions. Validate the version in your inventory.":
        "Hay versiones contradictorias. Valida la versión en tu inventario.",
    "The version is not published. Give it from your inventory to evaluate the advisories.":
        "La versión no se publica. Indícala desde tu inventario para evaluar los avisos.",
    "Next step: review the patches of your branch and restrict the management services.":
        "Siguiente paso: revisa los parches de tu rama y restringe los servicios de gestión.",
    "The version comparison does not confirm exploitation or certify that the router is secure.":
        "La comparación de versión no confirma explotación ni certifica que el router sea seguro.",
    "The certificate has expired. The site must renew it.": "El certificado está caducado. El sitio debe renovarlo.",
    "This computer does not recognize the authority that signed the certificate (its root is "
    "missing from the system store). That alone does not mean the site is misconfigured.":
        "Este equipo no reconoce la autoridad que firmó el certificado (falta su raíz en el "
        "almacén del sistema). No significa por sí solo que el sitio esté mal configurado.",
    "The certificate could not be validated. Check its trust, name and date.":
        "No se pudo validar el certificado. Revisa su confianza, nombre y fecha.",
    "The name could not be resolved. Check the target and the DNS connection.":
        "No se pudo resolver el nombre. Revisa el objetivo y la conexión DNS.",
    "No answer within the configured time. You can increase the wait.":
        "No respondió dentro del tiempo configurado. Puedes aumentar la espera.",
    "The host refused the connection to the service.": "El equipo rechazó la conexión al servicio.",

    # --- terminal_ui.py: details, viewer, reports, diagnostics, help ---------------------
    "Explained results": "Resultados explicados",
    "no target": "sin objetivo",
    "FINDINGS · GRADE {grade} ({score}/100)": "HALLAZGOS · NOTA {grade} ({score}/100)",
    "How to fix: {fix}": "Cómo arreglarlo: {fix}",
    "Check data.": "Datos de la comprobación.",
    "Status: skipped in the analysis options.": "Estado: omitido en las opciones del análisis.",
    "Status: could not be completed.": "Estado: no se pudo completar.",
    "Error details: {error}": "Detalle del error: {error}",
    "Advisory": "Aviso",
    "Status: {status}": "Estado: {status}",
    "no data": "sin datos",
    "What it checks: {summary}": "Qué revisa: {summary}",
    "see the source": "consulta la fuente",
    "Version that fixes this advisory in that branch: {versions}":
        "Versión que corrige este aviso en esa rama: {versions}",
    "Related ports that answered: {ports}": "Puertos asociados que respondieron: {ports}",
    "no exposure was established": "no se estableció exposición",
    "Source: {source}": "Fuente: {source}",
    "[ANSWERS]": "[RESPONDE]",
    "[NOT REACHABLE]": "[NO ACCESIBLE]",
    "Not reachable: the connection failed; it may be closed, filtered or not answering.":
        "No accesible: la conexión falló; puede estar cerrado, filtrado o no responder.",
    "limits the resources the page can load": "limita los recursos que la página puede cargar",
    "tells the browser to use HTTPS": "indica al navegador que use HTTPS",
    "prevents guessing the content type": "evita adivinar el tipo de contenido",
    "controls which URL is shared as the referrer": "controla qué URL se comparte como referencia",
    "Missing: {header} — {why}": "Ausente: {header} — {why}",
    "review the site's policy": "revisa la política del sitio",
    "TLS-RPT: {tls_rpt} · BIMI: {bimi}": "TLS-RPT: {tls_rpt} · BIMI: {bimi}",
    "robots.txt: {count} blocked paths · {sitemaps}": "robots.txt: {count} rutas bloqueadas · {sitemaps}",
    "no sitemap": "sin sitemap",
    "… and {count} more in the report.": "… y {count} más en el reporte.",
    "Identifier": "Identificador",
    "Name": "Nombre",
    "Registration country": "País del registro",
    "First IP": "IP inicial",
    "Last IP": "IP final",
    "Analysis summary": "Resumen del análisis",
    "This report has no compatible summary. You can look at the details.":
        "Este reporte no tiene un resumen compatible. Puedes consultar el detalle.",
    "View explained results": "Ver resultados explicados",
    "Open the HTML report in the browser": "Abrir reporte HTML en el navegador",
    "View file paths": "Ver rutas de los archivos",
    "View JSON data (technical details)": "Ver datos JSON (detalle técnico)",
    "Back": "Volver",
    "Part of this report could not be interpreted. Check its JSON data.":
        "No se pudo interpretar parte de este reporte. Consulta sus datos JSON.",
    "Report sent to the browser.": "Reporte enviado al navegador.",
    "No browser available. Open the file from its path.": "No hay navegador disponible. Abre el archivo desde su ruta.",
    "JSON data": "Datos JSON",
    "Complete technical information of the analysis.": "Información técnica completa del análisis.",
    "No files were saved; the result stays available during this session.":
        "No se guardaron archivos; el resultado sigue disponible durante esta sesión.",
    "Up to 20 recent results; 0 to go back.": "Hasta 20 resultados recientes; 0 para volver.",
    "No reports yet. Run an audit to see its results here.":
        "Aún no hay reportes. Ejecuta una auditoría para ver sus resultados aquí.",
    "Current folder: {folder}": "Carpeta actual: {folder}",
    "Diagnostics of this computer": "Diagnóstico de este equipo",
    "This check makes no network connections.": "Esta comprobación no realiza conexiones de red.",
    "System: {platform}": "Sistema: {platform}",
    "Portable core ready: it needs no root and no pip packages.":
        "Núcleo portable listo: no necesita root ni instalar paquetes pip.",
    "Optional tools:": "Herramientas opcionales:",
    "not installed (optional)": "no instalada (opcional)",
    "Bash modules for ISP, web applications and local network.": "Módulos Bash de ISP, aplicaciones web y red local.",
    "These modules need a Linux/WSL environment and its tools.":
        "Estos módulos necesitan un entorno Linux/WSL y sus herramientas.",
    "From that environment run: bash domaininfo.sh --legacy": "Desde ese entorno ejecuta: bash domaininfo.sh --legacy",
    "The portable MikroTik audit is still available in option 5.":
        "La auditoría MikroTik portable sigue disponible en la opción 5.",
    "Bash 4+ or classic tools are missing: {missing}": "Falta Bash 4+ o herramientas clásicas: {missing}",
    "Install them from the project folder: bash install.sh --legacy":
        "Instálalas desde la carpeta del proyecto: bash install.sh --legacy",
    "You will open the classic menu. When you leave it you will come back to this menu.":
        "Abrirás el menú clásico. Al salir volverás a este menú.",
    "Open classic menu": "Abrir menú clásico",
    "The Bash modules are not included in the pipx installation.": "Los módulos Bash no vienen en la instalación con pipx.",
    "Clone the repository to use them: git clone https://github.com/kevxngg/domaininfo":
        "Clona el repositorio para usarlos: git clone https://github.com/kevxngg/domaininfo",
    "Could not open the classic menu: {error}": "No se pudo abrir el menú clásico: {error}",
    "Quick guide": "Guía rápida",
    "1. Choose what to review. For a MikroTik router use option 5.":
        "1. Elige qué revisar. Para un router MikroTik usa la opción 5.",
    "2. Give the domain/IP or check a RouterOS version offline.":
        "2. Indica el dominio/IP o revisa una versión RouterOS sin conexión.",
    "3. Check the summary. You can change options before starting.":
        "3. Revisa el resumen. Puedes cambiar opciones antes de iniciar.",
    "4. See the result and its reports from My reports.": "4. Consulta el resultado y sus reportes desde Mis reportes.",
    "0 goes back to the previous menu; CTRL+C cancels the current action.":
        "0 vuelve al menú anterior; CTRL+C cancela la acción en curso.",
    "Preferences last for this session; you do not need to type commands.":
        "Las preferencias duran esta sesión; no necesitas escribir comandos.",
    "For a URL, scheme and port are kept; the site root is reviewed.":
        "En una URL se respeta protocolo y puerto; se revisa la raíz del sitio.",
    "Use the network modes on hosts you are authorized to review.":
        "Usa los modos de red sobre equipos que tengas autorización para revisar.",
    "running": "en curso",
    "done": "listo",
    "skipped": "omitido",
    "Reports ({kinds}) in {folder}": "Reportes ({kinds}) en {folder}",
    "JSON: --json · Help and examples: --help": "JSON: --json · Ayuda y ejemplos: --help",
    "[{time}] {target}: {count} change(s)": "[{time}] {target}: {count} cambio(s)",

    # --- render.py ---------------------------------------------------------------------
    "(summary not available; see the JSON)": "(resumen no disponible; consulta el JSON)",
    "Path": "Ruta",
    "Tool": "Herramienta",
    "Evidence": "Evidencia",
    "Impact": "Impacto",
    "Safe verification": "Verificación segura",
    "Fix": "Corrección",
    "References": "Referencias",
    "{severity} · {status} · confidence {confidence}": "{severity} · {status} · confianza {confidence}",
    "Date: {date} · mode: {mode}": "Fecha: {date} · modo: {mode}",
    "ASSESSMENT: {line}": "EVALUACIÓN: {line}",
    "FINDINGS WITH EVIDENCE": "HALLAZGOS CON EVIDENCIA",
    "SECURITY GRADE: {grade} ({score}/100)": "NOTA DE SEGURIDAD: {grade} ({score}/100)",
    "{date} · mode `{mode}` · DomainInfo {version}": "{date} · modo `{mode}` · DomainInfo {version}",
    "Security grade: **{grade}** ({score}/100)": "Nota de seguridad: **{grade}** ({score}/100)",
    "| Level | Area | Finding | How to fix |": "| Nivel | Área | Hallazgo | Cómo arreglarlo |",
    "**Assessment:** {line}": "**Evaluación:** {line}",
    "Findings with evidence": "Hallazgos con evidencia",
    "{date} · mode {mode} · DomainInfo {version}": "{date} · modo {mode} · DomainInfo {version}",
    "grade {grade} ({score}/100)": "nota {grade} ({score}/100)",
    "Findings": "Hallazgos",
    "Full technical data (JSON)": "Datos técnicos completos (JSON)",
    "Generated with DomainInfo by @kevxngg. Findings are indicative and based on "
    "public information; only review targets you are authorized to audit.":
        "Generado con DomainInfo por @kevxngg. Los hallazgos son orientativos y se basan en "
        "información pública; revisa solo objetivos que tengas autorización para auditar.",
    # Legacy score areas (enum values shown translated)
    "Mail": "Correo",
    "Registration": "Registro",
    "Brand": "Marca",

    # --- report.py / traceroute.py (legacy helpers) -------------------------------------
    "Error reading the log: {error}": "Error leyendo log: {error}",
    "Executive summary": "Resumen ejecutivo",
    "Full log": "Log completo",
    "Security findings ({count})": "Hallazgos de seguridad ({count})",
    "Authorized use only": "Uso autorizado únicamente",
    "Generated by DomainInfo v{version} — @kevxngg (Kevin)": "Generado por DomainInfo v{version} — @kevxngg (Kevin)",
    "This report is confidential. For authorized audits only.":
        "Este reporte es confidencial. Uso exclusivo para auditorías autorizadas.",
    "HTML report generated: {path}": "Reporte HTML generado: {path}",
    "Usage: python3 {script} <log_file.txt> [output.html]": "Uso: python3 {script} <log_file.txt> [output.html]",
    "Example: python3 report.py logs/domaininfo_google.com_20260411.txt":
        "Ejemplo: python3 report.py logs/domaininfo_google.com_20260411.txt",
    "Error: file not found: {path}": "Error: archivo no encontrado: {path}",
    "Cannot resolve: {host} — {error}": "No se puede resolver: {host} — {error}",
    "Traceroute to {host} ({address}), max {hops} hops": "Traceroute a {host} ({address}), máx {hops} saltos",
    "No RAW socket permission: hops cannot be measured with this method.":
        "Sin permisos RAW: no es posible medir saltos con este método.",
    "Use traceroute/tracepath or python domaininfo.py -m full.": "Usa traceroute/tracepath o python domaininfo.py -m full.",
    "Destination reached.": "Destino alcanzado.",
    "Usage: python3 {script} <host> [max_hops]": "Uso: python3 {script} <host> [max_hops]",
}
