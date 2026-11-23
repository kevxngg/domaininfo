"""Spanish catalog for the audit modules (score, infra, safety, evidence, webapp, tools...).

Keys are the English source strings passed to ``tr()``; values are the Spanish text.
"""

STRINGS = {
    # dnsclient.py
    'DNS label too long': 'Etiqueta DNS demasiado larga',
    'Truncated DNS name': 'Nombre DNS truncado',
    'Truncated DNS pointer': 'Puntero DNS truncado',
    'Invalid DNS pointer': 'Puntero DNS inválido',
    'DNS name too long': 'Nombre DNS demasiado largo',
    'DNS response too short': 'Respuesta DNS demasiado corta',
    'Response ID does not match': 'Identificador de respuesta distinto',
    'Truncated DNS record': 'Registro DNS truncado',
    'DNS connection closed': 'Conexión DNS cerrada',
    'DNS over HTTPS unavailable: {error}': 'DNS sobre HTTPS no disponible: {error}',
    # mailsec.py
    'No SPF record: anyone can claim to send mail for this domain':
        'Sin registro SPF: cualquiera puede decir que envía por este dominio',
    'Several SPF records; receivers treat this as an error (permerror)':
        'Hay varios registros SPF; los receptores lo tratan como error (permerror)',
    '{lookups} direct DNS lookups (maximum 10): SPF may fail':
        '{lookups} consultas DNS directas (máximo 10): el SPF puede fallar',
    "Missing '-all' or '~all': SPF does not reject unauthorized senders":
        "Falta '-all' o '~all': el SPF no rechaza remitentes no autorizados",
    "'+all' authorizes any server: SPF gives no protection": "'+all' autoriza a cualquier servidor: el SPF no protege",
    "'?all' tells receivers nothing": "'?all' no indica nada a los receptores",
    "The 'ptr' mechanism is discouraged (RFC 7208)": "El mecanismo 'ptr' está desaconsejado (RFC 7208)",
    'No DMARC: receivers do not know what to do with forged mail':
        'Sin DMARC: los receptores no saben qué hacer con correos falsos',
    'Several DMARC records: all of them are ignored': 'Hay varios registros DMARC: se ignoran todos',
    "DMARC policy 'p=' missing or invalid": "Política DMARC 'p=' ausente o inválida",
    'p=none only monitors: forged mail is still delivered': 'p=none solo vigila: los correos falsos siguen llegando',
    'Applied to only {pct}% of messages (pct)': 'Solo se aplica al {pct} % de los correos (pct)',
    "No 'rua': you get no reports on who sends mail in your name":
        "Sin 'rua': no recibes informes de quién envía en tu nombre",
    'Only common selectors are tried; others may exist': 'Solo se prueban selectores comunes; puede haber otros',
    # netinfo.py
    'Private or reserved address: no public network data': 'Dirección privada o reservada: sin datos públicos de red',
    'HSTS of at least 6 months with preload': 'HSTS de al menos 6 meses con preload',
    'HSTS of at least 6 months': 'HSTS de al menos 6 meses',
    'Short HSTS duration (less than 6 months)': 'HSTS con duración corta (menos de 6 meses)',
    'No HSTS: the browser could use unencrypted HTTP': 'Sin HSTS: el navegador podría usar HTTP sin cifrar',
    'The site does not use HTTPS': 'El sitio no usa HTTPS',
    'CSP present': 'CSP presente',
    "CSP present but allows 'unsafe-inline'": "CSP presente pero permite 'unsafe-inline'",
    'No Content-Security-Policy: more exposed to XSS': 'Sin Content-Security-Policy: más expuesto a XSS',
    'Clickjacking protection': 'Protección contra clickjacking',
    'No X-Frame-Options or frame-ancestors: clickjacking possible':
        'Sin X-Frame-Options ni frame-ancestors: clickjacking posible',
    'No X-Content-Type-Options: nosniff': 'Sin X-Content-Type-Options: nosniff',
    'Referrer-Policy set': 'Referrer-Policy definida',
    'No Referrer-Policy': 'Sin Referrer-Policy',
    'Permissions-Policy set': 'Permissions-Policy definida',
    'No Permissions-Policy': 'Sin Permissions-Policy',
    'Reveals the software version: {header}': 'Revela versión de software: {header}',
    'no Secure': 'sin Secure',
    'no HttpOnly': 'sin HttpOnly',
    'no SameSite': 'sin SameSite',
    # recon.py
    'Response too large': 'Respuesta demasiado grande',
    'The CNAME points to {cname}, which no longer exists': 'El CNAME apunta a {cname}, que ya no existe',
    "{service} says the resource does not exist ('{marker}')":
        "{service} responde que el recurso no existe ('{marker}')",
    'Certificate logs unavailable: {error}': 'Registros de certificados no disponibles: {error}',
    'Checked the first {checked} of {total} subdomains': 'Se comprobaron los primeros {checked} de {total} subdominios',
    'Existing does not mean malicious; review the ones that receive mail or copy your site':
        'Que exista no significa que sea malicioso; revisa los que reciben correo o imitan tu web',
    '# Infrastructure map': '# Mapa de infraestructura',
    'Targets: {targets}': 'Objetivos: {targets}',
    'No shared elements were found between the targets.':
        'No se encontraron elementos compartidos entre los objetivos.',
    'Network (ASN)': 'Red (ASN)',
    'DNS server': 'Servidor DNS',
    'Mail server': 'Servidor de correo',
    'Certificate': 'Certificado',
    'not installed: module disabled': 'no instalada: módulo desactivado',
    'could not read the version: {error}': 'no se pudo leer la versión: {error}',
    'RSA key validation in SSH authentication': 'Validación de claves RSA en autenticación SSH',
    'Session control in the bandwidth-test service': 'Control de sesiones del servicio bandwidth-test',
    'Signature verification of certificates and host keys': 'Verificación de firmas en certificados y claves de host',
    'Access control to SSH command channels': 'Control de acceso a canales de comandos SSH',
    'File access through the web interface': 'Acceso a archivos mediante la interfaz web',
    'User name handling in SSH': 'Tratamiento de nombres de usuario en SSH',
    'Only the six September 2026 advisories; this is not a security certification':
        'Solo los seis avisos de septiembre de 2026; no es una certificación de seguridad',
    'Declared version or banner not verified against an authenticated inventory':
        'Versión declarada o banner no verificado contra un inventario autenticado',
    'An open port does not prove a CVE; a closed one does not rule out the advisory':
        'Un puerto abierto no demuestra un CVE; uno cerrado no descarta el aviso',
    'Custom ports, ACLs and internal configuration need additional review':
        'Puertos personalizados, ACL y configuración interna requieren revisión adicional',
    'Beta/rc builds and branches other than 6/7 need manual review':
        'Beta/rc y ramas diferentes de 6/7 requieren revisión manual',
    'Catalog and versions are a dated snapshot, not a real-time lookup':
        'Catálogo y versiones son una instantánea fechada, no una consulta en tiempo real',
    'Review the advisories and upgrade within a branch supported by the device':
        'Revisar los avisos y actualizar dentro de una rama compatible con el equipo',
    'Restrict SSH, WebFig, Winbox and API to the management network or a VPN':
        'Restringir SSH, WebFig, Winbox y API a la red de gestión o una VPN',
    'Disable Telnet, FTP, API without TLS and bandwidth-test if unused':
        'Deshabilitar Telnet, FTP, API sin TLS y bandwidth-test si no se utilizan',
    'Review users, scripts, configuration and Flagged state from an authorized session':
        'Revisar usuarios, scripts, configuración y estado Flagged desde una sesión autorizada',
    'Invalid RouterOS version; use 7.25, 7.23.8 or 7.26beta3':
        'Versión RouterOS inválida; usa 7.25, 7.23.8 o 7.26beta3',
    'Conflicting versions: validate the inventory before concluding':
        'Versiones contradictorias: validar el inventario antes de concluir',
    # score.py
    'Invalid certificate: {reason}': 'Certificado no válido: {reason}',
    'not verified': 'no verificado',
    'Install a certificate from a recognized authority that covers the site name':
        'Instala un certificado de una autoridad reconocida que cubra el nombre del sitio',
    'Certificate expired {days} days ago': 'Certificado caducado hace {days} días',
    'Renew the certificate': 'Renueva el certificado',
    'The certificate expires in {days} days': 'El certificado caduca en {days} días',
    'Renew it or automate renewal': 'Renueva o automatiza la renovación',
    'Accepts old versions: {versions}': 'Acepta versiones antiguas: {versions}',
    'Disable TLS 1.0 and 1.1; keep only 1.2 and 1.3': 'Desactiva TLS 1.0 y 1.1; deja solo 1.2 y 1.3',
    'Does not support TLS 1.3': 'No admite TLS 1.3',
    'Enable TLS 1.3 on the server': 'Activa TLS 1.3 en el servidor',
    'Add the header on the server or the CDN': 'Añade la cabecera en el servidor o el CDN',
    'Adjust the header or hide the software version': 'Ajusta la cabecera u oculta la versión del software',
    'Cookies without Secure/HttpOnly/SameSite: {names}': 'Cookies sin Secure/HttpOnly/SameSite: {names}',
    'Mark cookies with Secure, HttpOnly and SameSite': 'Marca las cookies con Secure, HttpOnly y SameSite',
    'Missing header {header}': 'Falta la cabecera {header}',
    "Forged mail can be sent in the domain's name (DMARC does not block it)":
        'Se pueden enviar correos falsos en nombre del dominio (DMARC no los bloquea)',
    'Publish DMARC with p=quarantine or p=reject after reviewing the reports':
        'Publica DMARC con p=quarantine o p=reject tras revisar los informes',
    'No SPF record': 'Sin registro SPF',
    "Publish a TXT 'v=spf1 ... -all' listing your servers": "Publica un TXT 'v=spf1 ... -all' con tus servidores",
    'Fix the matching DNS record': 'Corrige el registro DNS correspondiente',
    'No DMARC': 'Sin DMARC',
    'Publish _dmarc with at least p=none and rua= to start': 'Publica _dmarc con al menos p=none y rua= para empezar',
    'No DKIM found on common selectors': 'No se encontró DKIM en selectores comunes',
    'Check that your provider signs with DKIM': 'Verifica que tu proveedor firme con DKIM',
    'No MTA-STS in enforce mode': 'Sin MTA-STS en modo enforce',
    'Publish MTA-STS to enforce TLS on inbound mail': 'Publica MTA-STS para forzar TLS en el correo entrante',
    'No DNSSEC': 'Sin DNSSEC',
    'Enable DNSSEC at your DNS provider and registrar': 'Activa DNSSEC en tu proveedor DNS y registrador',
    'No CAA record': 'Sin registro CAA',
    'Publish CAA to limit which authorities may issue certificates':
        'Publica CAA para limitar qué autoridades pueden emitir certificados',
    '{service} reachable on port {port}': '{service} accesible en el puerto {port}',
    'Remote Desktop (RDP)': 'Escritorio remoto (RDP)',
    'Docker without TLS': 'Docker sin TLS',
    'Close it to the public or restrict it with a firewall/VPN': 'Ciérralo al público o limítalo con cortafuegos/VPN',
    '{name}: possible subdomain takeover ({service})': '{name}: posible toma del subdominio ({service})',
    'external service': 'servicio externo',
    'Remove the CNAME or recreate the resource on the service':
        'Elimina el CNAME o vuelve a crear el recurso en el servicio',
    'Domain registered {days} days ago': 'Dominio registrado hace {days} días',
    'Newly created domains are common in phishing; verify its legitimacy':
        'Los dominios recién creados son habituales en phishing; verifica su legitimidad',
    'The domain expires in {days} days': 'El dominio caduca en {days} días',
    'Renew the domain': 'Renueva el dominio',
    '{count} registered lookalike domains can receive mail':
        '{count} dominios parecidos registrados pueden recibir correo',
    'Monitor those domains and consider registering or reporting them':
        'Vigila esos dominios y valora registrarlos o denunciarlos',
    'Indicative: summarizes the modules that ran; it does not prove anything is exploitable':
        'Orientativa: resume los módulos ejecutados; no prueba que algo sea explotable',
    # safety.py
    'Invalid host name': 'Nombre de host inválido',
    'Invalid IPv4 address': 'Dirección IPv4 inválida',
    'Empty URL or URL with spaces/control characters': 'URL vacía o con espacios/caracteres de control',
    'Only HTTP/HTTPS URLs are accepted': 'Solo se aceptan URLs HTTP/HTTPS',
    'Credentials in the URL are not accepted': 'No se aceptan credenciales en la URL',
    'Port out of range': 'Puerto fuera de rango',
    'The URL has no host': 'Falta el host de la URL',
    'Could not resolve {host}: {error}': 'No se pudo resolver {host}: {error}',
    '{host} has no addresses': '{host} no tiene direcciones',
    '{host} is outside the authorized scope': '{host} está fuera del alcance autorizado',
    '{host} resolves to a blocked address (link-local, multicast or reserved)':
        '{host} resuelve a una dirección bloqueada (enlace local, multicast o reservada)',
    '{host} resolves to an internal network; use --allow-private if authorized':
        '{host} resuelve a una red interna; usa --allow-private si está autorizado',
    'Total audit time exhausted': 'Tiempo total de la auditoría agotado',
    'Invalid TLS certificate ({reason}); use --insecure-tls only if the site is authorized and you trust the network':
        'Certificado TLS no válido ({reason}); usa --insecure-tls solo si el sitio está autorizado y confías en la red',
    'Could not connect': 'No se pudo conectar',
    'Too many redirects or a redirect loop': 'Demasiadas redirecciones o redirección en bucle',
    # evidence.py
    'Confirmed': 'Confirmado',
    'Likely': 'Probable',
    'Informational': 'Informativo',
    'Pending verification': 'Pendiente de verificar',
    'Not applicable': 'No aplicable',
    'Not evaluated': 'No evaluado',
    'Check error': 'Error de comprobación',
    '[hidden]': '[oculto]',
    'Invalid severity: {value}': 'Severidad no válida: {value}',
    'Invalid status: {value}': 'Estado no válido: {value}',
    'Invalid confidence: {value}': 'Confianza no válida: {value}',
    'security: risk of what was checked · coverage: share checked · confidence: share with direct evidence. Compare audits only if their coverage is comparable.':
        'security: riesgo de lo comprobado · coverage: parte comprobada · confidence: parte con evidencia directa. Compara auditorías solo si su cobertura es comparable.',
    # webapp.py
    'Python error traceback': 'Traza de error de Python',
    'Django debug page': 'Página de depuración de Django',
    'Java exception trace': 'Traza de excepción Java',
    'PHP error with a server path': 'Error de PHP con ruta del servidor',
    'ASP.NET error page': 'Página de error de ASP.NET',
    'Database error message': 'Mensaje de error de base de datos',
    'Laravel/Symfony exception page': 'Página de excepción de Laravel/Symfony',
    'Rails exception page': 'Página de excepción de Rails',
    'Node.js exception trace': 'Traza de excepción de Node.js',
    'Private key in the response': 'Clave privada en la respuesta',
    'AWS access key in the response': 'Clave de acceso de AWS en la respuesta',
    'GitHub token in the response': 'Token de GitHub en la respuesta',
    'Slack token in the response': 'Token de Slack en la respuesta',
    'Google API key in the response': 'Clave de API de Google en la respuesta',
    'JWT embedded in the page': 'JWT incrustado en la página',
    'Internal IP address in the response': 'Dirección IP interna en la respuesta',
    'no script-src or default-src: scripts are not restricted': 'sin script-src ni default-src: no limita los scripts',
    "'unsafe-inline' in {directive}": "'unsafe-inline' en {directive}",
    "'unsafe-eval' in {directive}": "'unsafe-eval' en {directive}",
    'wildcard source in {directive}': 'origen comodín en {directive}',
    'data: in {directive}': 'data: en {directive}',
    "missing object-src 'none'": "falta object-src 'none'",
    'missing base-uri': 'falta base-uri',
    'Invalid HTTP response: {error}': 'Respuesta HTTP no válida: {error}',
    'Passive analysis: GET requests only; no forms or credentials are sent':
        'Análisis pasivo: solo peticiones GET; no se envían formularios ni credenciales',
    'TLS certificate not verified (audited with --insecure-tls)':
        'Certificado TLS no verificado (auditado con --insecure-tls)',
    'The connection was accepted without validating the certificate':
        'La conexión se aceptó sin validar el certificado',
    'Install a valid certificate; check the TLS module': 'Instala un certificado válido; revisa el módulo TLS',
    'The page is served over unencrypted HTTP': 'La página se sirve por HTTP sin cifrar',
    'Final URL: {url}': 'URL final: {url}',
    'Serve the site over HTTPS only and redirect HTTP to HTTPS':
        'Sirve el sitio solo por HTTPS y redirige HTTP a HTTPS',
    'Anyone on the network can read or alter the page and the data sent':
        'Cualquiera en la red puede leer o alterar la página y los datos enviados',
    'Open the URL with http:// and check that it does not redirect to https://':
        'Abre la URL con http:// y comprueba que no redirige a https://',
    'Redirect from HTTPS to HTTP': 'Redirección de HTTPS a HTTP',
    'Make every redirect point to HTTPS': 'Haz que todas las redirecciones apunten a HTTPS',
    'Redirect not followed: outside the authorized scope': 'Redirección no seguida: fuera del alcance autorizado',
    'If the destination is also authorized, add it with --scope':
        'Si el destino también está autorizado, añádelo con --scope',
    'Check where the page redirects and whether that destination is yours':
        'Revisa a dónde redirige la página y si ese destino es tuyo',
    'No HSTS (Strict-Transport-Security)': 'Sin HSTS (Strict-Transport-Security)',
    'Header missing': 'Cabecera ausente',
    'Add Strict-Transport-Security: max-age=31536000; includeSubDomains':
        'Añade Strict-Transport-Security: max-age=31536000; includeSubDomains',
    'An attacker on the network can force the first visit over HTTP':
        'Un atacante en la red puede forzar la primera visita por HTTP',
    'HSTS lasts less than 6 months': 'HSTS con duración menor de 6 meses',
    'Use a max-age of at least 15552000 (6 months)': 'Usa max-age de al menos 15552000 (6 meses)',
    'No Content-Security-Policy (report-only mode only)': 'Sin Content-Security-Policy (solo en modo informe)',
    'No Content-Security-Policy': 'Sin Content-Security-Policy',
    'Report-Only only': 'Solo Report-Only',
    "Define a CSP with a restricted script-src (nonces or hashes), object-src 'none' and base-uri 'self'":
        "Define una CSP con script-src limitado (nonces o hashes), object-src 'none' y base-uri 'self'",
    'An XSS flaw would face fewer barriers': 'Un fallo de XSS tendría menos barreras',
    'Weak CSP: {issues}': 'CSP débil: {issues}',
    "Remove 'unsafe-inline'/'unsafe-eval' and wildcards; add object-src 'none' and base-uri":
        "Elimina 'unsafe-inline'/'unsafe-eval' y comodines; añade object-src 'none' y base-uri",
    'No clickjacking protection': 'Sin protección contra clickjacking',
    'Neither a valid X-Frame-Options nor CSP frame-ancestors': 'Ni X-Frame-Options válida ni CSP frame-ancestors',
    "Add CSP frame-ancestors 'self' (or X-Frame-Options: DENY)":
        "Añade CSP frame-ancestors 'self' (o X-Frame-Options: DENY)",
    'The page can be embedded in another one to trick the user':
        'La página se puede incrustar en otra para engañar al usuario',
    'Load the URL in an <iframe> from another origin': 'Carga la URL en un <iframe> desde otro origen',
    'Add X-Content-Type-Options: nosniff': 'Añade X-Content-Type-Options: nosniff',
    'Permissive Referrer-Policy: {policy}': 'Referrer-Policy permisiva: {policy}',
    'Use strict-origin-when-cross-origin or no-referrer': 'Usa strict-origin-when-cross-origin o no-referrer',
    'Full URLs (with parameters) are sent to other sites':
        'Las URL completas (con parámetros) se envían a otros sitios',
    'No Referrer-Policy (the browser default applies)': 'Sin Referrer-Policy (se aplica la del navegador)',
    'Set Referrer-Policy: strict-origin-when-cross-origin': 'Define Referrer-Policy: strict-origin-when-cross-origin',
    'Disable what you do not use: Permissions-Policy: camera=(), microphone=(), geolocation=()':
        'Desactiva lo que no uses: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    'The header reveals the software version': 'La cabecera revela la versión del software',
    'Hide the version in the server configuration': 'Oculta la versión en la configuración del servidor',
    'The response sets no cookies': 'La respuesta no crea cookies',
    'Cookie {name} without Secure': 'Cookie {name} sin Secure',
    'Mark the cookie with Secure': 'Marca la cookie con Secure',
    'It can travel over unencrypted HTTP': 'Puede viajar por HTTP sin cifrar',
    'Cookie {name} without HttpOnly': 'Cookie {name} sin HttpOnly',
    'Mark cookies that JavaScript does not need with HttpOnly':
        'Marca con HttpOnly las cookies que no necesite JavaScript',
    'An XSS could read it': 'Un XSS podría leerla',
    'Cookie {name} without an explicit SameSite': 'Cookie {name} sin SameSite explícito',
    'Set SameSite=Lax or Strict (None only with Secure, and only if essential)':
        'Define SameSite=Lax o Strict (None solo con Secure si es imprescindible)',
    "It depends on each browser's default": 'Depende del valor por defecto de cada navegador',
    'Cookie {name} with SameSite=None but no Secure': 'Cookie {name} con SameSite=None sin Secure',
    'SameSite=None requires Secure; browsers will reject the cookie or send it on third-party requests':
        'SameSite=None exige Secure; los navegadores la rechazarán o se enviará en peticiones de terceros',
    'Form {index} ({id})': 'Formulario {index} ({id})',
    'Form {index}': 'Formulario {index}',
    '{form}: CSRF token in <meta>, not in the form': '{form}: token CSRF en <meta>, no en el formulario',
    'Check that the JavaScript sends it in a header on every request':
        'Comprueba que el JavaScript lo envía en una cabecera en cada petición',
    'Check the request header in the browser developer tools':
        'Revisa en las herramientas del navegador la cabecera de la petición',
    '{form}: no visible CSRF token; relies on SameSite cookies':
        '{form}: sin token CSRF visible; depende de cookies SameSite',
    'Cookies with SameSite: {names}': 'Cookies con SameSite: {names}',
    'Add a per-session CSRF token on top of SameSite': 'Añade un token CSRF por sesión además de SameSite',
    'In an authorized environment, submit the form from another origin and check that the server rejects it':
        'En un entorno autorizado, envía el formulario desde otro origen y comprueba que el servidor lo rechaza',
    '{form}: no CSRF protection visible (pending verification)':
        '{form}: no se ve protección CSRF (pendiente de verificar)',
    '{method} {action} without a hidden token field or SameSite cookies':
        '{method} {action} sin campo oculto de token ni cookies SameSite',
    'Use a per-session CSRF token or check Origin/Referer on the server':
        'Usa un token CSRF por sesión o comprueba Origin/Referer en el servidor',
    "Without another defense, another site could submit the form on the user's behalf":
        'Si no hay otra defensa, otro sitio podría enviar el formulario en nombre del usuario',
    'The protection may live in headers or on the server: check it with a test account in an authorized environment':
        'La protección puede estar en cabeceras o en el servidor: compruébalo con una cuenta de prueba en un entorno autorizado',
    '{form}: the password is sent by GET (it ends up in the URL)':
        '{form}: la contraseña se envía por GET (queda en la URL)',
    "<form method='GET' action='{action}'> with a password field":
        "<form method='GET' action='{action}'> con campo password",
    "Use method='post' on forms with a password": "Usa method='post' en formularios con contraseña",
    'The password ends up in histories, server logs and the Referer':
        'La contraseña queda en historiales, registros del servidor y Referer',
    '{form}: the password travels over unencrypted HTTP': '{form}: la contraseña viaja por HTTP sin cifrar',
    'Page {page} · destination {action}': 'Página {page} · destino {action}',
    'Serve the page and the destination over HTTPS': 'Sirve la página y el destino por HTTPS',
    'Anyone on the network can read the password': 'Cualquiera en la red puede leer la contraseña',
    '{form}: sends data to another origin': '{form}: envía datos a otro origen',
    'destination {action}': 'destino {action}',
    'Check that the destination is yours and trusted': 'Comprueba que el destino es tuyo y de confianza',
    'CORS accepts any origin with credentials': 'CORS acepta cualquier origen con credenciales',
    'CORS accepts any origin': 'CORS acepta cualquier origen',
    'Use a closed list of allowed origins': 'Usa una lista cerrada de orígenes permitidos',
    "Another site could read the user's authenticated responses":
        'Otro sitio podría leer respuestas autenticadas del usuario',
    'Another site could read responses': 'Otro sitio podría leer respuestas',
    'Repeat the request with another Origin header and compare the response':
        'Repite la petición con otra cabecera Origin y compara la respuesta',
    'CORS allows the null origin': 'CORS permite el origen null',
    "Do not include 'null' among the allowed origins": "No incluyas 'null' entre los orígenes permitidos",
    'Public CORS (*): any site can read this response without credentials':
        'CORS público (*): cualquier sitio puede leer esta respuesta sin credenciales',
    'Fine for public content; review it if the response is private':
        'Correcto para contenido público; revísalo si la respuesta es privada',
    'Disable debug mode and show generic error pages':
        'Desactiva el modo depuración y muestra páginas de error genéricas',
    'Reveals internal paths, versions or queries that make an attack easier':
        'Revela rutas, versiones o consultas internas que facilitan un ataque',
    'HTTP {status} without visible technical details': 'HTTP {status} sin detalles técnicos visibles',
    '{count} match(es): {first}': '{count} coincidencia(s): {first}',
    'Remove the data from the response and, if it is a credential, revoke it and issue a new one':
        'Retira el dato de la respuesta y, si es una credencial, revócala y genera otra',
    'Look for the value in the source code and check with its owner whether it is still valid':
        'Busca el valor en el código fuente y comprueba si sigue siendo válido con su propietario',
}
