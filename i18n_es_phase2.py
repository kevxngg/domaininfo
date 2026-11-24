"""Spanish catalog for Phase 2 (safety.http_request, authscope, session_audit, apispec, zapclient, browser)."""

STRINGS = {
    # safety.py (Phase 2 additions)
    "Request body too large (limit {limit} bytes)": "Cuerpo de la petición demasiado grande (límite {limit} bytes)",
    "Unsupported HTTP method: {method}": "Método HTTP no admitido: {method}",
    "Only POST requests carry a body": "Solo las peticiones POST llevan cuerpo",
    "Request limit reached ({limit})": "Límite de peticiones alcanzado ({limit})",
    "A POST body is never re-sent to another origin": "Un cuerpo POST nunca se reenvía a otro origen",

    # authscope.py
    "the authorization file": "el archivo de autorización",
    "{where} must be an object": "{where} debe ser un objeto",
    "Unknown key in {where}: {key}": "Clave desconocida en {where}: {key}",
    "Missing key in {where}: {key}": "Falta la clave en {where}: {key}",
    "{where} must be a non-empty text of at most {limit} characters":
        "{where} debe ser un texto no vacío de como máximo {limit} caracteres",
    "{where} must be true or false": "{where} debe ser true o false",
    "{where} must be an integer between {low} and {high}": "{where} debe ser un entero entre {low} y {high}",
    "{where} must be a URL": "{where} debe ser una URL",
    "{where} must be an ISO 8601 date and time with a time zone":
        "{where} debe ser una fecha y hora ISO 8601 con zona horaria",
    "Unsupported authorization file version (expected {version})":
        "Versión del archivo de autorización no admitida (se esperaba {version})",
    "targets must be a list of 1 to 20 URL prefixes": "targets debe ser una lista de 1 a 20 prefijos de URL",
    "scope_hosts must be a list of at most 20 host names":
        "scope_hosts debe ser una lista de como máximo 20 nombres de host",
    "roles must be an object with 1 to {limit} roles": "roles debe ser un objeto con 1 a {limit} roles",
    "role {name}": "rol {name}",
    "accounts must be a list of 1 to {limit} test accounts":
        "accounts debe ser una lista de 1 a {limit} cuentas de prueba",
    "an account": "una cuenta",
    "window.not_after must be later than window.not_before":
        "window.not_after debe ser posterior a window.not_before",
    "The authorized window cannot exceed {days} days": "La ventana autorizada no puede superar {days} días",
    "An authorization file is required for authenticated tests":
        "Las pruebas autenticadas necesitan un archivo de autorización",
    "The authorization file is too large": "El archivo de autorización es demasiado grande",
    "{url} is not covered by the authorized targets": "{url} no está cubierta por los objetivos autorizados",
    "The authorized time window has not started yet ({start})":
        "La ventana de tiempo autorizada aún no ha empezado ({start})",
    "The authorized time window ended at {end}": "La ventana de tiempo autorizada terminó el {end}",
    "Duplicate key in the authorization file: {key}": "Clave duplicada en el archivo de autorización: {key}",
    "{where}: invalid URL ({error})": "{where}: URL no válida ({error})",
    "A target prefix cannot contain a query string": "Un prefijo de objetivo no puede contener una consulta",
    "logout.method must be GET or POST": "logout.method debe ser GET o POST",
    "Invalid role name: {name}": "Nombre de rol no válido: {name}",
    "protected_urls of role {name} must be a list of at most {limit} URLs":
        "protected_urls del rol {name} debe ser una lista de como máximo {limit} URL",
    "Invalid account id": "Identificador de cuenta no válido",
    "Account {account} uses an undefined role": "La cuenta {account} usa un rol no definido",
    "Account {account} uses the same variable for username and password":
        "La cuenta {account} usa la misma variable para el usuario y la contraseña",
    "Duplicate account id: {account}": "Identificador de cuenta duplicado: {account}",
    "limits.lockout_account must name one of the test accounts":
        "limits.lockout_account debe nombrar una de las cuentas de prueba",
    "limits.lockout_account requires lockout_check: true": "limits.lockout_account requiere lockout_check: true",
    "Cannot read the authorization file: {error}": "No se puede leer el archivo de autorización: {error}",
    "The authorization file is not valid JSON: {error}": "El archivo de autorización no es JSON válido: {error}",
    "Environment variable {name} (account {account}) is not set":
        "La variable de entorno {name} (cuenta {account}) no está definida",
    "Invalid host in scope_hosts: {host}": "Host no válido en scope_hosts: {host}",
    "login.{key} is not a valid form field name": "login.{key} no es un nombre de campo de formulario válido",
    "{key} of account {account} must be an environment variable name (A-Z, 0-9, _), never a credential":
        "{key} de la cuenta {account} debe ser el nombre de una variable de entorno (A-Z, 0-9, _), nunca una "
        "credencial",

    # session_audit.py
    "status {status}, path {path}, title '{title}', {length} characters of text":
        "estado {status}, ruta {path}, título '{title}', {length} caracteres de texto",
    "No second factor was requested for test account {account}":
        "No se pidió un segundo factor para la cuenta de prueba {account}",
    "The password alone opened a session": "La contraseña sola abrió una sesión",
    "Require MFA for privileged and, if possible, all accounts":
        "Exige MFA en las cuentas privilegiadas y, si es posible, en todas",
    "Flags of session cookie {name} are Secure={secure}, HttpOnly={httponly}, SameSite={samesite}":
        "Los atributos de la cookie de sesión {name} son Secure={secure}, HttpOnly={httponly}, SameSite={samesite}",
    "Needs a protected URL for the role and a session cookie":
        "Necesita una URL protegida para el rol y una cookie de sesión",
    "The login form posts to a URL outside the authorized targets":
        "El formulario de inicio de sesión envía a una URL fuera de los objetivos autorizados",
    "Login attempt limit reached ({limit})": "Límite de intentos de inicio de sesión alcanzado ({limit})",
    "Authenticated audit of an authorized system with test accounts; no brute force, no wordlists; secrets are "
    "never stored or shown":
        "Auditoría autenticada de un sistema autorizado con cuentas de prueba; sin fuerza bruta ni diccionarios; "
        "los secretos nunca se guardan ni se muestran",
    "No usable POST login form at the login URL":
        "No hay un formulario POST de inicio de sesión utilizable en la URL de login",
    "A second authentication step (MFA) follows the password":
        "Tras la contraseña hay un segundo paso de autenticación (MFA)",
    "After the password the application asks for a verification code":
        "Tras la contraseña la aplicación pide un código de verificación",
    "Keep MFA enforced for every account": "Mantén la MFA obligatoria en todas las cuentas",
    "The MFA step cannot be automated: session checks were not run":
        "El paso de MFA no se puede automatizar: no se ejecutaron las comprobaciones de sesión",
    "Login with test account {account} failed: check the credentials and the field names":
        "Falló el inicio de sesión con la cuenta de prueba {account}: revisa las credenciales y los nombres de campo",
    "Test accounts are often exempt: check the MFA policy for real accounts":
        "Las cuentas de prueba suelen estar exentas: revisa la política de MFA para las cuentas reales",
    "Session identifier not renewed at login (session fixation)":
        "El identificador de sesión no se renueva al iniciar sesión (fijación de sesión)",
    "Cookie {name} kept the same value before and after the login":
        "La cookie {name} mantuvo el mismo valor antes y después del inicio de sesión",
    "Issue a new session identifier on every successful login and discard the old one":
        "Emite un identificador de sesión nuevo en cada inicio de sesión correcto y descarta el anterior",
    "Only the cookie lifetime is visible; server-side timeouts are not tested":
        "Solo se ve la duración de la cookie; los tiempos de expiración del servidor no se prueban",
    "Logout neither removed the session cookie nor ended the session":
        "El cierre de sesión ni borró la cookie de sesión ni terminó la sesión",
    "After calling the logout URL, {path} still opens with the same cookie: {view}":
        "Tras llamar a la URL de cierre de sesión, {path} sigue abriéndose con la misma cookie: {view}",
    "Invalidate the session on the server and expire the cookie at logout":
        "Invalida la sesión en el servidor y caduca la cookie al cerrar sesión",
    "The session stays valid on the server after logout":
        "La sesión sigue siendo válida en el servidor tras cerrar sesión",
    "The session cookie captured before logout still opens {path}: {view}":
        "La cookie de sesión capturada antes de cerrar sesión todavía abre {path}: {view}",
    "Invalidate the session on the server at logout, not only in the browser":
        "Invalida la sesión en el servidor al cerrar sesión, no solo en el navegador",
    "Logout does not remove the session cookie from the browser":
        "El cierre de sesión no borra la cookie de sesión del navegador",
    "After logout the browser keeps cookie {name}": "Tras cerrar sesión el navegador conserva la cookie {name}",
    "Expire the session cookie in the logout response": "Caduca la cookie de sesión en la respuesta de cierre de sesión",
    "A new login reuses the previous session token": "Un nuevo inicio de sesión reutiliza el token de sesión anterior",
    "Cookie {name} has the same value in two separate logins":
        "La cookie {name} tiene el mismo valor en dos inicios de sesión distintos",
    "Generate a new random session token on every login":
        "Genera un token de sesión aleatorio nuevo en cada inicio de sesión",
    "The login accepted a wrong password": "El inicio de sesión aceptó una contraseña incorrecta",
    "A random password opened a session for the test account":
        "Una contraseña aleatoria abrió una sesión de la cuenta de prueba",
    "Check the password verification on the server": "Revisa la verificación de contraseñas en el servidor",
    "Login responses reveal whether an account exists": "Las respuestas del login revelan si una cuenta existe",
    "With a wrong password the answer is status {status_a}, '{message_a}'; with an unknown user it is "
    "status {status_b}, '{message_b}'":
        "Con una contraseña incorrecta la respuesta es estado {status_a}, '{message_a}'; con un usuario inexistente "
        "es estado {status_b}, '{message_b}'",
    "Return the same message, status and redirect for a wrong password and an unknown user":
        "Devuelve el mismo mensaje, estado y redirección para una contraseña incorrecta y un usuario inexistente",
    "Lockout or rate limiting after {count} failed attempts":
        "Bloqueo o limitación de intentos tras {count} intentos fallidos",
    "The application signalled a lockout or rate limit (429/423, Retry-After or a message)":
        "La aplicación indicó un bloqueo o una limitación (429/423, Retry-After o un mensaje)",
    "Keep the limit; make sure a locked account can be recovered safely":
        "Mantén el límite; asegúrate de que una cuenta bloqueada se puede recuperar de forma segura",
    "The test account {account} may now be locked": "La cuenta de prueba {account} puede haber quedado bloqueada",
    "No lockout or rate limit after {count} failed attempts":
        "Sin bloqueo ni limitación tras {count} intentos fallidos",
    "{count} wrong passwords for the test account got no 429/423, Retry-After or lockout message":
        "{count} contraseñas incorrectas para la cuenta de prueba no recibieron 429/423, Retry-After ni mensaje de "
        "bloqueo",
    "Limit failed logins per account and per source (lockout, delays or CAPTCHA)":
        "Limita los inicios de sesión fallidos por cuenta y por origen (bloqueo, retardos o CAPTCHA)",
    "Audit stopped: {error}": "Auditoría detenida: {error}",
    "Disabled in the authorization file (lockout_check)": "Desactivado en el archivo de autorización (lockout_check)",
    "Log in with the test account and check the second step":
        "Inicia sesión con la cuenta de prueba y comprueba el segundo paso",
    "Login with test account {account} failed": "Falló el inicio de sesión con la cuenta de prueba {account}",
    "No session cookie observed (token-based authentication?)":
        "No se observó cookie de sesión (¿autenticación por token?)",
    "An attacker who plants a session id can take over the session after the victim logs in":
        "Un atacante que plante un identificador de sesión puede apoderarse de la sesión cuando la víctima inicie "
        "sesión",
    "Note the session cookie before logging in and compare it after logging in":
        "Anota la cookie de sesión antes de iniciar sesión y compárala después",
    "No session cookie observed": "No se observó cookie de sesión",
    "Session cookie {name} travels over unencrypted HTTP": "La cookie de sesión {name} viaja por HTTP sin cifrar",
    "Serve the application over HTTPS only and mark the cookie Secure":
        "Sirve la aplicación solo por HTTPS y marca la cookie con Secure",
    "Session cookie {name} without HttpOnly": "Cookie de sesión {name} sin HttpOnly",
    "Mark the session cookie with HttpOnly": "Marca la cookie de sesión con HttpOnly",
    "Session cookie {name} without an explicit SameSite": "Cookie de sesión {name} sin SameSite explícito",
    "Set SameSite=Lax or Strict on the session cookie": "Pon SameSite=Lax o Strict en la cookie de sesión",
    "Session cookie {name} lives {days} days": "La cookie de sesión {name} dura {days} días",
    "Max-Age/Expires of {name}: about {days} days": "Max-Age/Expires de {name}: unos {days} días",
    "Use short-lived sessions with an idle timeout on the server":
        "Usa sesiones cortas con expiración por inactividad en el servidor",
    "No protected URLs configured": "No hay URL protegidas configuradas",
    "Protected URL accessible without authentication": "URL protegida accesible sin autenticación",
    "Anonymous: {anonymous} · authenticated: {authenticated}": "Anónimo: {anonymous} · autenticado: {authenticated}",
    "Require an authenticated session on every protected URL": "Exige una sesión autenticada en cada URL protegida",
    "Needs logged-in test accounts with at least two different roles":
        "Necesita cuentas de prueba con sesión iniciada de al menos dos roles distintos",
    "{account} ({role}) → {own}; {owner} ({owner_role}) → {reference}":
        "{account} ({role}) → {own}; {owner} ({owner_role}) → {reference}",
    "No logout URL in the authorization file": "No hay URL de cierre de sesión en el archivo de autorización",
    "The logout could not be verified": "No se pudo verificar el cierre de sesión",
    "Check that logout.url is the real logout action, then log out in a browser and reuse the old cookie":
        "Comprueba que logout.url es la acción real de cierre de sesión; después cierra sesión en un navegador y "
        "reutiliza la cookie antigua",
    "A stolen session cookie keeps working after the user logs out":
        "Una cookie de sesión robada sigue funcionando después de que el usuario cierre sesión",
    "Copy the session cookie, log out, send the copy and open a protected URL":
        "Copia la cookie de sesión, cierra sesión, envía la copia y abre una URL protegida",
    "The second login did not succeed": "El segundo inicio de sesión no funcionó",
    "No login attempts left": "No quedan intentos de inicio de sesión",
    "A wrong password was accepted": "Se aceptó una contraseña incorrecta",
    "An attacker can find out which accounts exist": "Un atacante puede averiguar qué cuentas existen",
    "Log in once with a wrong password and once with a made-up user and compare":
        "Inicia sesión una vez con una contraseña incorrecta y otra con un usuario inventado y compara",
    "Same status, path and text; response times are not compared":
        "Mismo estado, ruta y texto; los tiempos de respuesta no se comparan",
    "The check stops at {cap} attempts by design; confirm the policy with the application owner":
        "La prueba se detiene a propósito en {cap} intentos; confirma la política con el responsable de la aplicación",
    "Session audit failed: {error}": "Falló la auditoría de sesión: {error}",
    "Anyone on the network can steal the session": "Cualquiera en la red puede robar la sesión",
    "Session cookie {name} without Secure": "Cookie de sesión {name} sin Secure",
    "Mark the session cookie with Secure": "Marca la cookie de sesión con Secure",
    "The server-side idle and absolute timeouts must be checked by hand":
        "Las expiraciones por inactividad y absoluta del servidor hay que comprobarlas a mano",
    "Anyone can read the protected content": "Cualquiera puede leer el contenido protegido",
    "Open the URL in a private window without logging in": "Abre la URL en una ventana privada sin iniciar sesión",
    "Protected URL answers 2xx without authentication": "Una URL protegida responde 2xx sin autenticación",
    "Anonymous: {anonymous}": "Anónimo: {anonymous}",
    "Check that the URL is meant to be public; otherwise require a session":
        "Comprueba que la URL debe ser pública; si no, exige una sesión",
    "Not run (see the notes)": "No se ejecutó (ver las notas)",
    "Compare the anonymous and the authenticated page by hand": "Compara a mano la página anónima y la autenticada",
    "Role {role} can open a URL reserved for role {other}": "El rol {role} puede abrir una URL reservada al rol {other}",
    "Enforce the role check on the server for every request":
        "Aplica la comprobación de rol en el servidor en cada petición",
    "Role {role} gets a 2xx answer on a URL reserved for role {other}":
        "El rol {role} recibe una respuesta 2xx en una URL reservada al rol {other}",
    "Check that the page shows no data or function of the other role":
        "Comprueba que la página no muestra datos ni funciones del otro rol",
    "Users can reach functions or data of another role": "Los usuarios pueden llegar a funciones o datos de otro rol",
    "Log in as {account} and open the URL": "Inicia sesión como {account} y abre la URL",
    "Log in as {account}, open the URL and compare it with role {other}":
        "Inicia sesión como {account}, abre la URL y compárala con el rol {other}",

    # apispec.py
    "No OpenAPI/Swagger JSON document found": "No se encontró ningún documento JSON OpenAPI/Swagger",
    "API description published ({count} operations)": "Descripción de la API publicada ({count} operaciones)",
    "{kind} {version} at {url}": "{kind} {version} en {url}",
    "Publish the API description only if it is meant to be public":
        "Publica la descripción de la API solo si debe ser pública",
    "Passive analysis of the API description; documented operations are never called":
        "Análisis pasivo de la descripción de la API; nunca se llama a las operaciones documentadas",
    "API server declared over unencrypted HTTP": "Servidor de la API declarado sobre HTTP sin cifrar",
    "servers: {servers}": "servidores: {servers}",
    "Declare and serve the API over HTTPS only": "Declara y sirve la API solo por HTTPS",
    "The API description declares no security schemes": "La descripción de la API no declara esquemas de seguridad",
    "No components.securitySchemes / securityDefinitions": "Sin components.securitySchemes / securityDefinitions",
    "Document the authentication of the API (and require it on the server)":
        "Documenta la autenticación de la API (y exígela en el servidor)",
    "API key sent in the URL query string": "Clave de API enviada en la consulta de la URL",
    "securitySchemes: {names} (in: query)": "securitySchemes: {names} (in: query)",
    "Send API keys in a header (e.g. Authorization or X-API-Key)":
        "Envía las claves de API en una cabecera (p. ej. Authorization o X-API-Key)",
    "HTTP Basic authentication over unencrypted HTTP": "Autenticación HTTP Basic sobre HTTP sin cifrar",
    "Basic schemes {names} with servers {servers}": "Esquemas Basic {names} con servidores {servers}",
    "Serve the API over HTTPS only; prefer token-based authentication":
        "Sirve la API solo por HTTPS; mejor autenticación por token",
    "Sensitive-looking parameters in the query string": "Parámetros que parecen sensibles en la consulta de la URL",
    "Move secrets and personal data to headers or the request body":
        "Lleva los secretos y los datos personales a cabeceras o al cuerpo de la petición",
    "{count} deprecated operations are still published": "{count} operaciones obsoletas siguen publicadas",
    "Remove deprecated operations from the server and the description when no longer needed":
        "Retira las operaciones obsoletas del servidor y de la descripción cuando ya no hagan falta",
    "The API description is YAML; only JSON is parsed without dependencies (export it as JSON)":
        "La descripción de la API es YAML; sin dependencias solo se analiza JSON (expórtala como JSON)",
    "Requests and tokens can be read on the network": "Las peticiones y los tokens se pueden leer en la red",
    "Call a non-destructive operation without credentials in an authorized environment":
        "Llama a una operación no destructiva sin credenciales en un entorno autorizado",
    "{count} documented operations declare no security requirement":
        "{count} operaciones documentadas no declaran ningún requisito de seguridad",
    "Declare a security requirement on every operation that is not deliberately public":
        "Declara un requisito de seguridad en cada operación que no sea pública a propósito",
    "Keys end up in server logs, proxies and browser history":
        "Las claves acaban en los registros del servidor, los proxies y el historial del navegador",
    "Passwords travel in clear text (Base64) on every request":
        "Las contraseñas viajan en claro (Base64) en cada petición",
    "Query strings are stored in logs, proxies and the Referer header":
        "Las consultas de la URL se guardan en registros, proxies y la cabecera Referer",
    "Check whether the deprecated operations still answer on the server":
        "Comprueba si las operaciones obsoletas siguen respondiendo en el servidor",
    "Undocumented or missing authentication on API operations":
        "Autenticación ausente o sin documentar en operaciones de la API",
    "Check each listed operation on the server with a test account; this module never calls them":
        "Comprueba cada operación de la lista en el servidor con una cuenta de prueba; este módulo nunca las llama",
    "Document larger than {limit} bytes": "Documento mayor de {limit} bytes",

    # zapclient.py
    "ZAP passive mode: the target is fetched through ZAP and its passive scanner reports; no active scan is ever "
    "started":
        "Modo pasivo de ZAP: el objetivo se descarga a través de ZAP e informa su escáner pasivo; nunca se lanza un "
        "escaneo activo",
    "The ZAP API must run on this machine (127.0.0.1, ::1 or localhost)":
        "La API de ZAP debe estar en este equipo (127.0.0.1, ::1 o localhost)",
    "ZAP endpoint not allowed: {endpoint}": "Punto de la API de ZAP no permitido: {endpoint}",
    "ZAP API error on {endpoint} (HTTP {status}): {message}": "Error de la API de ZAP en {endpoint} (HTTP {status}): {message}",
    "OWASP ZAP is not available: {reason}": "OWASP ZAP no está disponible: {reason}",
    "ZAP's passive scan still had {count} records after {seconds} s":
        "El escaneo pasivo de ZAP aún tenía {count} registros tras {seconds} s",
    "ZAP is not reachable at {url}: {error}": "No se puede contactar con ZAP en {url}: {error}",
    "URL: {url}": "URL: {url}",
    "Reported by ZAP's passive scanner (plugin {plugin}, confidence {confidence}); check it by hand":
        "Lo indica el escáner pasivo de ZAP (plugin {plugin}, confianza {confidence}); compruébalo a mano",
    "The spider did not finish within {seconds} s": "La araña no terminó en {seconds} s",
    "parameter: {param}": "parámetro: {param}",
    "evidence: {value}": "evidencia: {value}",

    # browser.py
    "scheme {scheme} not allowed": "esquema {scheme} no permitido",
    "Playwright is not installed (optional). Install: {install}":
        "Playwright no está instalado (es opcional). Instalación: {install}",
    "Rendered in headless Chromium; out-of-scope requests are blocked and nothing is submitted":
        "Renderizado en Chromium sin interfaz; las peticiones fuera de alcance se bloquean y no se envía nada",
    "Mixed content: the HTTPS page loads HTTP resources": "Contenido mixto: la página HTTPS carga recursos HTTP",
    "Load every resource over HTTPS": "Carga todos los recursos por HTTPS",
    "{count} JavaScript errors in the console": "{count} errores de JavaScript en la consola",
    "Review the console errors; they may reveal internal details":
        "Revisa los errores de la consola; pueden revelar detalles internos",
    "Session-like cookie {name} is set by JavaScript": "La cookie de aspecto de sesión {name} la crea JavaScript",
    "Cookie {name} appears after rendering without a Set-Cookie header (HttpOnly={httponly})":
        "La cookie {name} aparece tras renderizar sin cabecera Set-Cookie (HttpOnly={httponly})",
    "Set session cookies from the server with HttpOnly": "Crea las cookies de sesión desde el servidor con HttpOnly",
    "Cookies written by JavaScript cannot be HttpOnly: an XSS could read them":
        "Las cookies escritas por JavaScript no pueden ser HttpOnly: un XSS podría leerlas",
    # safety.py (redirect scope and URL normalization for authenticated audits)
    "Percent-encoded dot or slash in the URL path is not accepted":
        "No se acepta un punto o una barra codificados con porcentaje en la ruta de la URL",
    "The URL is outside the authorized URL prefixes": "La URL está fuera de los prefijos de URL autorizados",
    "Redirect from HTTPS to HTTP refused while session cookies are in use":
        "Redirección de HTTPS a HTTP rechazada mientras se usan cookies de sesión",
    # Security review fixes (apispec, browser)
    "The document is not an OpenAPI/Swagger JSON object": "El documento no es un objeto JSON de OpenAPI/Swagger",
    "This Playwright version cannot filter WebSockets (needs 1.48 or newer), so the page could not open any "
    "WebSocket; update Playwright":
        "Esta versión de Playwright no puede filtrar WebSockets (necesita la 1.48 o posterior), así que la página "
        "no pudo abrir ningún WebSocket; actualiza Playwright",
}
