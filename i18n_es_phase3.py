"""Spanish catalog for Phase 3 (runners.py, vulnintel.py, inventory.py)."""

STRINGS = {
    # runners.py
    "Empty or invalid target": "Objetivo vacío o no válido",
    "Target contains spaces, control characters or starts with '-': {target}":
        "El objetivo contiene espacios, caracteres de control o empieza por '-': {target}",
    "Invalid hostname: {target}": "Nombre de host no válido: {target}",
    "A domain name is required: {target}": "Se necesita un nombre de dominio: {target}",
    "Invalid URL: {target}": "URL no válida: {target}",
    "Invalid local path: {target}": "Ruta local no válida: {target}",
    "Local path not found: {target}": "No se encuentra la ruta local: {target}",
    "A file is required: {target}": "Se necesita un archivo: {target}",
    "A directory is required: {target}": "Se necesita una carpeta: {target}",
    "Invalid scope entry: {entry}": "Entrada de alcance no válida: {entry}",
    "Option {option} must be an integer between {low} and {high}":
        "La opción {option} debe ser un entero entre {low} y {high}",
    "Empty nmap output": "Salida de nmap vacía",
    "Unexpected XML entities in nmap output": "Entidades XML inesperadas en la salida de nmap",
    "Tool output is not valid JSON: {error}": "La salida de la herramienta no es JSON válido: {error}",
    "Unknown tool: {tool}": "Herramienta desconocida: {tool}",
    "Cancelled before start": "Cancelado antes de empezar",
    "{tool} is not installed (optional). Install: {install}":
        "{tool} no está instalada (es opcional). Instalación: {install}",
    "{tool} {version} is older than the supported minimum {minimum}":
        "{tool} {version} es anterior a la versión mínima admitida {minimum}",
    "{tool} is an active scanner: it needs explicit authorization (allow_active) and a scope list":
        "{tool} es un escáner activo: necesita autorización explícita (allow_active) y una lista de alcance",
    "{target} is not in the authorized scope": "{target} no está en el alcance autorizado",
    "Could not detect {tool}: {error}": "No se pudo detectar {tool}: {error}",
    "Could not start {tool}: {error}": "No se pudo iniciar {tool}: {error}",
    "Cancelled by the user; the process tree was stopped":
        "Cancelado por el usuario; se detuvo el árbol de procesos",
    "{tool} exceeded the {seconds} s time limit; the process tree was killed":
        "{tool} superó el límite de {seconds} s; se terminó el árbol de procesos",
    "{tool} produced no output (exit code {code}): {stderr}":
        "{tool} no generó salida (código de salida {code}): {stderr}",
    "Could not read the {tool} output: {error}": "No se pudo leer la salida de {tool}: {error}",
    "Output larger than {size} MB was truncated": "Se recortó la salida por superar {size} MB",
    "Partial results": "Resultados parciales",
    "Completed": "Completado",
    "Invalid port list: {ports}": "Lista de puertos no válida: {ports}",
    "Nuclei tag not allowed: {tag}": "Etiqueta de Nuclei no permitida: {tag}",
    "Name outside the target domain: {name}": "Nombre fuera del dominio objetivo: {name}",
    "Nuclei: {name}": "Nuclei: {name}",
    "Template match by nuclei; reproduce the request manually before treating it as confirmed.":
        "Coincidencia de plantilla de nuclei; reproduce la petición a mano antes de darla por confirmada.",
    "Deprecated protocol {protocol} accepted": "Se acepta el protocolo obsoleto {protocol}",
    "{count} cipher suites accepted on {where}": "{count} suites de cifrado aceptadas en {where}",
    "Disable {protocol} and keep TLS 1.2 and 1.3 only.": "Desactiva {protocol} y deja solo TLS 1.2 y 1.3.",
    "Vulnerable to {name}": "Vulnerable a {name}",
    "testssl.sh: {check}": "testssl.sh: {check}",
    "Reported by testssl.sh; confirm the server configuration before acting.":
        "Indicado por testssl.sh; confirma la configuración del servidor antes de actuar.",
    "Semgrep: {rule} at {where}": "Semgrep: {rule} en {where}",
    "Bandit {test_id}: {name} at {where}": "Bandit {test_id}: {name} en {where}",
    "Static analysis result: review the code path before treating it as confirmed.":
        "Resultado de análisis estático: revisa el código antes de darlo por confirmado.",
    "{component} {version} is affected by {vuln_id}": "{component} {version} está afectado por {vuln_id}",
    "Upgrade to a fixed version: {versions}": "Actualiza a una versión corregida: {versions}",
    "Possible secret ({rule}) at {where}": "Posible secreto ({rule}) en {where}",
    "Revoke and rotate the secret, then remove it from the code and history.":
        "Revoca y rota el secreto y después elimínalo del código y del historial.",
    "Misconfiguration {check_id}: {title}": "Configuración incorrecta {check_id}: {title}",
    # vulnintel.py
    "Cancelled": "Cancelado",
    "Endpoint not allowed: {url}": "Destino no permitido: {url}",
    "HTTP {status} from {url}": "HTTP {status} desde {url}",
    "Request to {url} failed: {error}": "Falló la petición a {url}: {error}",
    "Response from {url} exceeds {size} bytes": "La respuesta de {url} supera {size} bytes",
    "Invalid JSON from {url}": "JSON no válido desde {url}",
    "Offline mode and no fresh cache for {source}": "Modo sin conexión y sin caché vigente para {source}",
    "Missing or invalid name/version": "Falta el nombre o la versión, o no son válidos",
    "Version read directly from the asset and listed as affected by the advisory.":
        "Versión leída directamente del activo e incluida como afectada en el aviso.",
    "The advisory covers this version, but the version was not read directly; confirm it.":
        "El aviso cubre esta versión, pero la versión no se leyó directamente; confírmala.",
    "Name or keyword match only: check that the product and version really match.":
        "Solo coincide el nombre o la palabra clave: comprueba que el producto y la versión coinciden de verdad.",
    "Upgrade {component} to a version that fixes {vuln_id}.":
        "Actualiza {component} a una versión que corrija {vuln_id}.",
    # inventory.py
    "Open ports and services are assets, not vulnerabilities. Paths outside the authorized scope are not listed.":
        "Los puertos abiertos y los servicios son activos, no vulnerabilidades. No se listan rutas fuera del "
        "alcance autorizado.",
}
