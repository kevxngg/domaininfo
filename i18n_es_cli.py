"""Spanish catalog for the CLI and menu wiring of the 6.0 phases (see docs/I18N.md)."""

STRINGS = {
    "No external tool ran; see each result for the reason and how to install it":
        "No se ejecutó ninguna herramienta externa; mira en cada resultado el motivo y cómo instalarla",
    "sessions, APIs and web integrations": "sesiones, API e integraciones web",
    "external tools and vulnerability intelligence": "herramientas externas e inteligencia de vulnerabilidades",
    "Security Center, history and exports": "Security Center, historial y exportaciones",
    "Optional tools (DomainInfo works without them; nothing is downloaded automatically)":
        "Herramientas opcionales (DomainInfo funciona sin ellas; no se descarga nada automáticamente)",
    "Unknown project: {name}": "Proyecto desconocido: {name}",
    "Not an existing folder: {path}": "No es una carpeta existente: {path}",
    "needs an authorization file (--auth-file)": "necesita un archivo de autorización (--auth-file)",
    "no external tool selected (use --tool)": "no se eligió ninguna herramienta externa (usa --tool)",
    "No software versions were identified, so there is nothing to correlate":
        "No se identificaron versiones de software, así que no hay nada que correlacionar",
    "Unknown tool: {names}. Available: {available}": "Herramienta desconocida: {names}. Disponibles: {available}",
    "quick: DNS and registration · web: HTTP, headers and TLS · ports: TCP ports · full: everything · "
    "mikrotik: RouterOS · webapp: one specific URL · session: authenticated session audit · apispec: "
    "documented API · zap: OWASP ZAP passive alerts · browser: page rendered with JavaScript · code: local "
    "project with code analyzers (default: %(default)s)":
        "quick: DNS y registro · web: HTTP, cabeceras y TLS · ports: puertos TCP · full: todo · mikrotik: "
        "RouterOS · webapp: una URL concreta · session: auditoría de sesiones autenticadas · apispec: API "
        "documentada · zap: alertas pasivas de OWASP ZAP · browser: página con JavaScript · code: proyecto "
        "local con analizadores de código (por defecto: %(default)s)",
    "session mode: authorization file with targets, test accounts (environment variable names) and limits; "
    "see docs/AUTHENTICATED_AUDIT.md":
        "modo session: archivo de autorización con objetivos, cuentas de prueba (nombres de variables de "
        "entorno) y límites; ver docs/AUTHENTICATED_AUDIT.md",
    "zap mode: API of the OWASP ZAP you run on this computer (loopback only)":
        "modo zap: API del OWASP ZAP que ejecutas en este equipo (solo loopback)",
    "KEY": "CLAVE",
    "zap mode: API key (or ZAP_API_KEY)": "modo zap: clave de la API (o ZAP_API_KEY)",
    "zap mode: maximum wait for the passive scan": "modo zap: espera máxima del análisis pasivo",
    "zap mode: also crawl the site with the ZAP spider (still no active scan)":
        "modo zap: recorrer también el sitio con el spider de ZAP (sigue sin escaneo activo)",
    "zap mode: maximum pages for the spider": "modo zap: páginas máximas del spider",
    "browser mode: page load timeout": "modo browser: tiempo máximo de carga de la página",
    "run optional tools, e.g. nmap,nuclei,whatweb (see --tools)":
        "ejecuta herramientas opcionales, p. ej. nmap,nuclei,whatweb (ver --tools)",
    "allow tools that send probes (nmap, nuclei, sslyze, testssl.sh…); the target must also be listed in --scope":
        "permite herramientas que envían sondas (nmap, nuclei, sslyze, testssl.sh…); el objetivo también "
        "debe estar en --scope",
    "maximum time per external tool": "tiempo máximo por herramienta externa",
    "look up known vulnerabilities (OSV, NVD, CISA KEV) for the versions found":
        "busca vulnerabilidades conocidas (OSV, NVD, CISA KEV) de las versiones encontradas",
    "show which optional tools are installed and how to install the rest":
        "muestra qué herramientas opcionales están instaladas y cómo instalar el resto",
    "PROJECT": "PROYECTO",
    "also save the results in the Security Center database under this project":
        "guarda además los resultados en la base de datos del Security Center, en este proyecto",
    "Security Center database (default: user data folder)":
        "base de datos del Security Center (por defecto: carpeta de datos del usuario)",
    "TARGET": "OBJETIVO",
    "list saved audits of a target (with --project)": "lista las auditorías guardadas de un objetivo (con --project)",
    "compare two saved audits by id (only meaningful if their coverage is comparable)":
        "compara dos auditorías guardadas por id (solo tiene sentido si su cobertura es comparable)",
    "export a project's findings: CSV, executive PDF or technical PDF":
        "exporta los hallazgos de un proyecto: CSV, PDF ejecutivo o PDF técnico",
    "project for --history and --export": "proyecto para --history y --export",
    "open the DomainInfo Security Center (local web dashboard)":
        "abre el DomainInfo Security Center (panel web local)",
    "Security Center address (default: %(default)s)": "dirección del Security Center (por defecto: %(default)s)",
    "Security Center port (default: %(default)s)": "puerto del Security Center (por defecto: %(default)s)",
    "do not open the browser automatically": "no abrir el navegador automáticamente",
    "let the Security Center listen on a non-loopback address (use an HTTPS tunnel)":
        "permite que el Security Center escuche fuera de loopback (usa un túnel HTTPS)",
    "installed {version}": "instalada {version}",
    "not installed": "no instalada",
    "--active only applies together with --tool": "--active solo se usa junto con --tool",
    "Saved in the Security Center (project {project}): audits {ids}":
        "Guardado en el Security Center (proyecto {project}): auditorías {ids}",
    "-m session needs --auth-file (see docs/AUTHENTICATED_AUDIT.md)":
        "-m session necesita --auth-file (ver docs/AUTHENTICATED_AUDIT.md)",
    "--url requires a URL mode: {modes}": "--url requiere un modo de URL: {modes}",
    "needs {minimum} or newer": "necesita {minimum} o posterior",
    "install: {hint}": "instalar: {hint}",
    "--history and --export need --project": "--history y --export necesitan --project",
    "Could not save in the Security Center: {error}": "No se pudo guardar en el Security Center: {error}",
    "Optional tools": "Herramientas opcionales",
    "DomainInfo works without them; install only what you need.":
        "DomainInfo funciona sin ellas; instala solo lo que necesites.",
    "Use them with --tool NAME (probing tools also need --active and the target in --scope).":
        "Úsalas con --tool NOMBRE (las que envían sondas necesitan además --active y el objetivo en --scope).",
    "Local dashboard with projects, history, comparisons and PDF reports.":
        "Panel local con proyectos, historial, comparaciones y reportes PDF.",
    "It listens only on 127.0.0.1 and opens your browser with a private access token.":
        "Solo escucha en 127.0.0.1 y abre tu navegador con un token de acceso privado.",
    "Press CTRL+C here to stop it and return to the menu.": "Pulsa CTRL+C aquí para detenerlo y volver al menú.",
    "Installed tools and how to add the rest": "Herramientas instaladas y cómo añadir el resto",
    "Local dashboard, history and PDF": "Panel local, historial y PDF",
    "Folder of the project to analyze. Example: C:\\code\\my-app or ~/code/my-app":
        "Carpeta del proyecto que se analizará. Ejemplo: C:\\code\\mi-app o ~/code/mi-app",
    "Folder (0 to go back)": "Carpeta (0 para volver)",
    "Not evaluated: {reason}": "No evaluado: {reason}",
    "Components checked: {count} · known vulnerabilities matched: {matches}":
        "Componentes revisados: {count} · vulnerabilidades conocidas relacionadas: {matches}",
    "No confirmed or pending findings.": "Sin hallazgos confirmados ni pendientes.",
    "login": "inicio de sesión",
    "Step 1 · Choose the authorization file.": "Paso 1 · Elige el archivo de autorización.",
    "Only for systems you are authorized to test, with test accounts. The file lists the targets, the "
    "environment variables that hold the credentials and the limits (docs/AUTHENTICATED_AUDIT.md).":
        "Solo para sistemas que tienes autorización para probar, con cuentas de prueba. El archivo indica los "
        "objetivos, las variables de entorno con las credenciales y los límites (docs/AUTHENTICATED_AUDIT.md).",
    "Authorization file (0 to go back)": "Archivo de autorización (0 para volver)",
    "Install the extra with: pip install \"domaininfo[server]\"":
        "Instala el extra con: pip install \"domaininfo[server]\"",
    "optional component not available": "componente opcional no disponible",
    "Authenticated sessions": "Sesiones autenticadas",
    "Login, cookies, logout, roles and lockout with authorized test accounts":
        "Inicio de sesión, cookies, cierre, roles y bloqueo con cuentas de prueba autorizadas",
    "Documented API": "API documentada",
    "OpenAPI/Swagger: endpoints, security schemes and risky parameters":
        "OpenAPI/Swagger: endpoints, esquemas de seguridad y parámetros de riesgo",
    "OWASP ZAP (passive)": "OWASP ZAP (pasivo)",
    "Passive alerts from the ZAP you run on this computer": "Alertas pasivas del ZAP que ejecutas en este equipo",
    "Page with JavaScript": "Página con JavaScript",
    "Render in headless Chromium: dynamic forms, JS cookies, mixed content":
        "Renderizado en Chromium sin interfaz: formularios dinámicos, cookies de JS, contenido mixto",
    "Project code": "Código del proyecto",
    "Semgrep, Bandit, pip-audit, Trivy and Gitleaks on a local folder":
        "Semgrep, Bandit, pip-audit, Trivy y Gitleaks sobre una carpeta local",
    "OWASP ZAP alerts": "Alertas de OWASP ZAP",
    "External tools": "Herramientas externas",
    "Known vulnerabilities": "Vulnerabilidades conocidas",
    "Login flow, session cookies, fixation, expiry, logout, role access, user enumeration and a capped lockout "
    "check, only with the test accounts of the authorization file.":
        "Flujo de inicio de sesión, cookies de sesión, fijación, caducidad, cierre de sesión, acceso por roles, "
        "enumeración de usuarios y una prueba de bloqueo limitada, solo con las cuentas de prueba del archivo "
        "de autorización.",
    "Documented OpenAPI/Swagger operations, servers, security schemes and risky parameters; the operations are "
    "never called.":
        "Operaciones OpenAPI/Swagger documentadas, servidores, esquemas de seguridad y parámetros de riesgo; "
        "las operaciones nunca se llaman.",
    "Passive alerts that your local OWASP ZAP raised for the URL; no active scan.":
        "Alertas pasivas que tu OWASP ZAP local generó para la URL; sin escaneo activo.",
    "The page after JavaScript runs: dynamic forms, cookies set by scripts, console errors and mixed content.":
        "La página tras ejecutar JavaScript: formularios dinámicos, cookies creadas por scripts, errores de "
        "consola y contenido mixto.",
    "Results of the optional external tools, normalized with their evidence and coverage.":
        "Resultados de las herramientas externas opcionales, normalizados con su evidencia y cobertura.",
    "Known vulnerabilities (OSV, NVD, CISA KEV) for the software versions found; a match by name alone is never "
    "confirmed.":
        "Vulnerabilidades conocidas (OSV, NVD, CISA KEV) de las versiones de software encontradas; una "
        "coincidencia solo por nombre nunca se confirma.",
    "Unexpected error in the module ({kind}): {error}": "Error inesperado en el módulo ({kind}): {error}",
    "Sessions": "Sesiones",
    "Tools": "Herramientas",
    "Vulnerabilities": "Vulnerabilidades",
    "Test accounts, logout, roles": "Cuentas de prueba, cierre de sesión, roles",
    "OpenAPI / Swagger review": "Revisión OpenAPI / Swagger",
    "Passive alerts from your ZAP": "Alertas pasivas de tu ZAP",
    "Render with Playwright": "Renderizar con Playwright",
    "Static analysis of a folder": "Análisis estático de una carpeta",
}
