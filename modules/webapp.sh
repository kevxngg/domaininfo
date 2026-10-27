#!/usr/bin/env bash
# ================================================================
#  webapp.sh — Web Application Vulnerability Scanner
#  Autor: @kevxngg (Señor K)
# ================================================================

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'
BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

_h()   { echo ""; echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${B}║${W}${BOLD}  $1${NC}${B}$(printf '%*s' $((54-${#1})) '')║${NC}"; echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"; }
_s()   { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
_kv()  { printf "  ${C}%-30s${NC} ${G}%s${NC}\n" "$1" "$2"; }
_kvr() { printf "  ${C}%-30s${NC} ${R}%s${NC}\n" "$1" "$2"; }
_kvy() { printf "  ${C}%-30s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
_ok()  { echo -e "  ${G}[✓]${NC} $1"; }
_warn(){ echo -e "  ${Y}[!]${NC} $1"; }
_info(){ echo -e "  ${DIM}ℹ  $1${NC}"; }
_vuln(){ echo -e "  ${BG_R}${W}${BOLD} VULN ${NC} ${R}$1${NC}"; }
_safe(){ echo -e "  ${BG_G}${W}${BOLD} SAFE ${NC} ${G}$1${NC}"; }
_med() { echo -e "  ${BG_Y}${W}${BOLD} WARN ${NC} ${Y}$1${NC}"; }

WA_RISK=0
WA_FINDINGS=()

wa_add() { WA_FINDINGS+=("$1"); }

# Helper: HTTP request
_req() {
    local method="${1:-GET}" url="$2"
    shift 2
    curl -sk --max-time 8 -X "$method" "$@" "$url" 2>/dev/null
}
_req_headers() { curl -skI --max-time 8 "$1" 2>/dev/null; }

# ── 1. Reconocimiento base ───────────────────────────────────────
webapp_recon() {
    local url="$1"
    _h "1 ▸ RECONOCIMIENTO WEB"

    local headers body status server
    headers=$(_req_headers "$url")
    body=$(_req GET "$url" | head -200)
    status=$(echo "$headers" | head -1 | awk '{print $2}')
    server=$(echo "$headers" | grep -i "^server:" | cut -d: -f2- | xargs)

    _kv "URL"        "$url"
    _kv "HTTP Status" "${status:-N/A}"
    _kv "Servidor"   "${server:-No revelado}"

    # Tecnologías
    _s "Stack tecnológico detectado"
    local powered
    powered=$(echo "$headers" | grep -i "x-powered-by:" | cut -d: -f2- | xargs)
    [[ -n "$powered" ]] && _kvy "X-Powered-By (expuesto)" "$powered" && \
        wa_add "MEDIO: X-Powered-By expuesto: $powered" && ((WA_RISK+=5))

    # CMS
    local cms=""
    if echo "$body$headers" | grep -qi "wp-content\|wp-includes\|wordpress"; then
        cms="WordPress"; _kvy "CMS" "WordPress"
        # WordPress version
        local wpver
        wpver=$(curl -sk --max-time 5 "${url%/}/readme.html" 2>/dev/null | grep -oE 'Version [0-9.]+' | head -1)
        [[ -n "$wpver" ]] && { _vuln "WordPress readme.html expuesto — $wpver"; wa_add "ALTO: readme.html expone versión WordPress"; ((WA_RISK+=10)); }
    elif echo "$body" | grep -qi "joomla"; then
        cms="Joomla"; _kvy "CMS" "Joomla"
    elif echo "$body" | grep -qi "drupal"; then
        cms="Drupal"; _kvy "CMS" "Drupal"
    elif echo "$body" | grep -qi "laravel"; then
        _kv "Framework" "Laravel"
    elif echo "$body" | grep -qi "django"; then
        _kv "Framework" "Django"
    fi

    # Cookies
    _s "Análisis de cookies"
    local cookies
    cookies=$(echo "$headers" | grep -i "set-cookie:")
    if [[ -n "$cookies" ]]; then
        while IFS= read -r cookie; do
            local cname; cname=$(echo "$cookie" | grep -oE 'Set-Cookie: [^=]+=' | awk '{print $2}')
            if ! echo "$cookie" | grep -qi "httponly"; then
                _vuln "Cookie sin HttpOnly: ${cname:-cookie} — accesible via JavaScript (riesgo XSS)"
                wa_add "ALTO: Cookie sin HttpOnly flag"
                ((WA_RISK+=10))
            fi
            if ! echo "$cookie" | grep -qi "secure"; then
                _warn "Cookie sin Secure flag: ${cname:-cookie} — puede enviarse por HTTP"
                wa_add "MEDIO: Cookie sin Secure flag"
                ((WA_RISK+=5))
            fi
            if ! echo "$cookie" | grep -qi "samesite"; then
                _warn "Cookie sin SameSite: ${cname:-cookie} — riesgo CSRF"
                wa_add "MEDIO: Cookie sin SameSite"
                ((WA_RISK+=5))
            fi
        done <<< "$cookies"
    else
        _info "No se detectaron cookies en la respuesta inicial"
    fi

    WA_BASE_URL="$url"
    WA_BODY="$body"
    WA_HEADERS="$headers"
}

# ── 2. Headers de seguridad ──────────────────────────────────────
webapp_security_headers() {
    _h "2 ▸ HEADERS DE SEGURIDAD (OWASP)"
    local url="$1"
    local headers="${WA_HEADERS:-$(_req_headers "$url")}"

    _s "Verificación de headers OWASP recomendados"
    echo ""
    printf "  ${W}${BOLD}%-35s %-10s %s${NC}\n" "HEADER" "ESTADO" "VALOR / OBSERVACIÓN"
    echo -e "  ${DIM}$(printf '─%.0s' {1..75})${NC}"

    check_sh() {
        local name="$1" grep_pattern="$2" risk="$3" note="$4"
        local val
        val=$(echo "$headers" | grep -i "$grep_pattern" | cut -d: -f2- | xargs)
        if [[ -n "$val" ]]; then
            printf "  ${G}%-35s %-10s${NC} ${DIM}%s${NC}\n" "$name" "PRESENTE" "$val"
        else
            printf "  ${R}%-35s %-10s${NC} ${Y}%s${NC}\n" "$name" "FALTA" "$note"
            wa_add "${risk}: Header faltante — $name"
            ((WA_RISK+=5))
        fi
    }

    check_sh "Strict-Transport-Security" "strict-transport" "ALTO" "Agregar: max-age=31536000; includeSubDomains"
    check_sh "Content-Security-Policy"   "content-security-policy" "ALTO" "Previene XSS e inyección de contenido"
    check_sh "X-Frame-Options"           "x-frame-options" "MEDIO" "Agregar: DENY o SAMEORIGIN"
    check_sh "X-Content-Type-Options"    "x-content-type-options" "MEDIO" "Agregar: nosniff"
    check_sh "Referrer-Policy"           "referrer-policy" "BAJO" "Agregar: strict-origin-when-cross-origin"
    check_sh "Permissions-Policy"        "permissions-policy\|feature-policy" "BAJO" "Controla acceso a APIs del navegador"

    # CORS
    local cors
    cors=$(echo "$headers" | grep -i "access-control-allow-origin:" | cut -d: -f2- | xargs)
    if [[ -n "$cors" ]]; then
        if [[ "$cors" == "*" ]]; then
            printf "  ${R}%-35s %-10s${NC} ${R}%s${NC}\n" "CORS (Access-Control-Allow-Origin)" "PELIGROSO" "Wildcard (*) — cualquier origen puede leer la respuesta"
            wa_add "ALTO: CORS wildcard — permite acceso desde cualquier dominio"
            ((WA_RISK+=15))
        else
            printf "  ${G}%-35s %-10s${NC} ${DIM}%s${NC}\n" "CORS" "RESTRINGIDO" "$cors"
        fi
    fi
}

# ── 3. Indicadores de SQL Injection ─────────────────────────────
webapp_sqli() {
    local url="$1"
    _h "3 ▸ SQL INJECTION — INDICADORES"
    _info "Pruebas pasivas y semi-activas (sin payloads destructivos)"

    _s "Detección de parámetros y formularios"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # Detectar formularios
    local forms
    forms=$(echo "$body" | grep -oi "<form[^>]*>" | wc -l)
    _kv "Formularios detectados" "$forms"

    # Detectar parámetros en URLs del cuerpo
    local params
    params=$(echo "$body" | grep -oE 'href="[^"]*\?[^"]*"' | grep -oE '\?[^"]+' | head -5)
    if [[ -n "$params" ]]; then
        _kvy "Parámetros GET encontrados" "$(echo "$params" | head -3)"

        # Probar con payload básico de error SQL (solo detectar, no explotar)
        _s "Prueba de error SQL (payload de diagnóstico)"
        local test_url="${url}?id=1'"
        local sql_response
        sql_response=$(_req GET "$test_url" 2>/dev/null)
        if echo "$sql_response" | grep -qi "sql syntax\|mysql_fetch\|ORA-\|PostgreSQL\|sqlite\|SQLSTATE\|syntax error.*SQL\|unclosed quotation"; then
            _vuln "Posible SQL Injection — respuesta contiene mensajes de error de BD"
            _vuln "  URL: $test_url"
            wa_add "CRITICO: Posible SQL Injection detectado — error de BD expuesto"
            ((WA_RISK+=40))
        else
            _ok "Sin mensajes de error SQL detectados"
        fi
    else
        _info "No se detectaron parámetros GET en el cuerpo de la página"
    fi

    # Error-based SQLi en página base
    if echo "$body" | grep -qi "sql syntax\|mysql_\|ORA-\|sqlite_error\|SQLSTATE"; then
        _vuln "Mensajes de error SQL visibles en la página"
        wa_add "CRITICO: Errores SQL expuestos en la página"
        ((WA_RISK+=30))
    fi
}

# ── 4. XSS indicators ───────────────────────────────────────────
webapp_xss() {
    local url="$1"
    _h "4 ▸ CROSS-SITE SCRIPTING (XSS)"

    _s "Detección de vectores de reflexión"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # Comprobar si hay campos de búsqueda o parámetros que reflejan input
    local search_param=""
    for param in "q" "search" "s" "query" "term" "keyword" "buscar"; do
        local test_val="xsstestXYZ123"
        local test_resp
        test_resp=$(_req GET "${url}?${param}=${test_val}" 2>/dev/null)
        if echo "$test_resp" | grep -q "$test_val"; then
            _med "Parámetro '$param' refleja el input — posible XSS reflected"
            wa_add "ALTO: Parámetro '$param' refleja input sin sanitizar"
            ((WA_RISK+=20))
            search_param="$param"
            break
        fi
    done
    [[ -z "$search_param" ]] && _ok "No se detectó reflexión directa de parámetros probados"

    # CSP check para XSS mitigation
    if echo "${WA_HEADERS}" | grep -qi "content-security-policy"; then
        local csp
        csp=$(echo "${WA_HEADERS}" | grep -i "content-security-policy:" | cut -d: -f2-)
        if echo "$csp" | grep -qi "unsafe-inline\|unsafe-eval"; then
            _warn "CSP con 'unsafe-inline' o 'unsafe-eval' — CSP reducida efectividad contra XSS"
            wa_add "MEDIO: CSP tiene unsafe-inline/unsafe-eval"
            ((WA_RISK+=10))
        else
            _ok "CSP sin unsafe-inline/unsafe-eval (bien configurado)"
        fi
    else
        _warn "Sin Content-Security-Policy — mayor superficie de ataque XSS"
    fi
}

# ── 5. Archivos y endpoints sensibles ───────────────────────────
webapp_sensitive_files() {
    local url="$1"
    _h "5 ▸ ARCHIVOS Y ENDPOINTS SENSIBLES"

    local paths_file
    paths_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/wordlists/paths.txt"
    local sensitive_paths=()
    if [[ -f "$paths_file" ]]; then
        while IFS= read -r p || [[ -n "$p" ]]; do
            [[ -z "$p" || "$p" == "#"* ]] && continue
            sensitive_paths+=("$p")
        done < "$paths_file"
    else
        sensitive_paths=("/.git/HEAD" "/.env" "/phpinfo.php" "/wp-config.php.bak"
                         "/server-status" "/.htaccess" "/swagger.json" "/api-docs"
                         "/config.php" "/backup.zip" "/db.sql" "/admin" "/login"
                         "/.git/config" "/composer.json" "/package.json")
    fi

    _s "Escaneando ${#sensitive_paths[@]} rutas sensibles"
    local found=0
    for path in "${sensitive_paths[@]}"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${path}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _vuln "EXPUESTO [200]: ${url%/}${path}"
            wa_add "CRITICO: Archivo sensible accesible: $path"
            ((WA_RISK+=15))
            ((found++))
        elif [[ "$code" == "403" ]]; then
            _kvy "Restringido [403]" "${path}"
        fi
    done
    echo ""
    if [[ $found -eq 0 ]]; then
        _ok "No se encontraron archivos sensibles accesibles (200 OK)"
    else
        _kvr "Archivos sensibles encontrados" "$found"
    fi
}

# ── 6. Autenticación y bypass ────────────────────────────────────
webapp_auth() {
    local url="$1"
    _h "6 ▸ AUTENTICACIÓN Y CONTROL DE ACCESO"

    _s "Análisis de mecanismos de autenticación"

    # Detectar panel de login
    local login_paths=("/login" "/admin" "/admin/login" "/wp-login.php"
                       "/administrator" "/signin" "/auth" "/panel" "/dashboard")
    for lpath in "${login_paths[@]}"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${lpath}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _kvy "Panel de login encontrado" "${url%/}${lpath}"
            wa_add "INFO: Panel de login detectado: $lpath"

            # Verificar si el form tiene CSRF token
            local login_body
            login_body=$(curl -sk --max-time 5 "${url%/}${lpath}" 2>/dev/null)
            if ! echo "$login_body" | grep -qi "csrf\|_token\|nonce\|authenticity_token"; then
                _warn "  Sin token CSRF detectado en formulario de login"
                wa_add "ALTO: Formulario de login sin protección CSRF"
                ((WA_RISK+=15))
            else
                _ok "  Token CSRF detectado en formulario"
            fi
        fi
    done

    # HTTP Basic Auth check
    _s "Verificación de HTTP Basic Auth"
    local basic_resp
    basic_resp=$(curl -sk --max-time 5 -w "\n%{http_code}" "${url%/}/admin" 2>/dev/null)
    local basic_code; basic_code=$(echo "$basic_resp" | tail -1)
    if [[ "$basic_code" == "401" ]]; then
        _warn "HTTP Basic Auth detectado en /admin"
        _info "Probar credenciales comunes: admin/admin, admin/password"
        wa_add "MEDIO: HTTP Basic Auth en /admin"
    fi

    # Verificar si admin es accesible directamente sin auth
    _s "Acceso directo a recursos protegidos"
    for admin_path in "/admin/users" "/admin/config" "/api/users" "/api/v1/users" "/dashboard"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${admin_path}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _vuln "Recurso admin accesible sin auth [200]: $admin_path"
            wa_add "CRITICO: Acceso no autorizado a $admin_path"
            ((WA_RISK+=30))
        fi
    done
}

# ── 7. Información sensible expuesta ────────────────────────────
webapp_info_leak() {
    local url="$1"
    _h "7 ▸ EXPOSICIÓN DE INFORMACIÓN"

    _s "Detección de datos sensibles en respuestas HTTP"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # IP interna
    if echo "$body$WA_HEADERS" | grep -oE '(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+' | head -1 | grep -q '.'; then
        local priv_ip
        priv_ip=$(echo "$body$WA_HEADERS" | grep -oE '(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+' | head -1)
        _vuln "IP privada expuesta en respuesta: $priv_ip"
        wa_add "MEDIO: IP privada expuesta: $priv_ip"
        ((WA_RISK+=10))
    else
        _ok "Sin IPs privadas detectadas en respuestas"
    fi

    # Stack trace / debug info
    if echo "$body" | grep -qi "stack trace\|exception\|traceback\|debug.*true\|APP_DEBUG\|Warning:.*on line\|Fatal error"; then
        _vuln "Información de debug/errores expuesta — revela stack de la aplicación"
        wa_add "ALTO: Debug info/stack trace visible al público"
        ((WA_RISK+=20))
    fi

    # Emails
    local emails
    emails=$(echo "$body" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -3)
    [[ -n "$emails" ]] && _kvy "Emails expuestos en HTML" "$emails"

    # Version info en headers
    if echo "$WA_HEADERS" | grep -iE "server:.*[0-9]\.|x-powered-by:.*[0-9]\." | grep -q .; then
        _warn "Versiones de software reveladas en headers"
        wa_add "MEDIO: Versiones de software expuestas en headers"
        ((WA_RISK+=5))
    fi

    # Comments con info sensible
    if echo "$body" | grep -qi "TODO\|FIXME\|HACK\|password\|secret\|api.key\|token" | grep -q "<!--"; then
        _warn "Posibles comentarios HTML con información sensible"
        wa_add "BAJO: Comentarios HTML con posible info sensible"
    fi
}

# ── 8. WordPress específico ──────────────────────────────────────
webapp_wordpress() {
    local url="$1"
    local body="${WA_BODY:-}"
    echo "$body" | grep -qi "wp-content\|wp-includes" || return

    _h "8 ▸ WORDPRESS — ANÁLISIS ESPECÍFICO"

    # Enumeración de usuarios via REST API
    _s "Enumeración de usuarios (WP REST API)"
    local wp_users
    wp_users=$(curl -sk --max-time 8 "${url%/}/wp-json/wp/v2/users" 2>/dev/null)
    if echo "$wp_users" | grep -qi '"name"'; then
        _vuln "Enumeración de usuarios activa via REST API"
        local unames
        unames=$(echo "$wp_users" | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | head -5 | tr '\n' ', ')
        _kvr "Usuarios expuestos" "$unames"
        wa_add "ALTO: WP REST API expone lista de usuarios: $unames"
        ((WA_RISK+=20))
    else
        _ok "Enumeración de usuarios deshabilitada"
    fi

    # xmlrpc.php
    local xmlrpc_code
    xmlrpc_code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}/xmlrpc.php" 2>/dev/null)
    if [[ "$xmlrpc_code" == "200" || "$xmlrpc_code" == "405" ]]; then
        _warn "xmlrpc.php accesible — vector de brute-force amplificado"
        wa_add "ALTO: xmlrpc.php activo — brute force sin rate limit"
        ((WA_RISK+=15))
    else
        _ok "xmlrpc.php no accesible o deshabilitado"
    fi

    # Archivos de debug WordPress
    for wpf in "/wp-content/debug.log" "/wp-content/uploads/debug.log"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${wpf}" 2>/dev/null)
        [[ "$code" == "200" ]] && { _vuln "Log de debug accesible: $wpf"; wa_add "ALTO: WP debug.log expuesto"; ((WA_RISK+=15)); }
    done
}

# ── 9. Resumen de auditoría web ──────────────────────────────────
webapp_summary() {
    local url="$1"
    _h "✦  RESUMEN — AUDITORÍA WEB"
    echo ""
    _kv "URL auditada" "$url"
    _kv "Hallazgos"   "${#WA_FINDINGS[@]}"
    echo ""

    [[ $WA_RISK -gt 100 ]] && WA_RISK=100
    local label color
    if   [[ $WA_RISK -ge 75 ]]; then label="CRÍTICO";  color="${R}"
    elif [[ $WA_RISK -ge 50 ]]; then label="ALTO";     color="${Y}"
    elif [[ $WA_RISK -ge 25 ]]; then label="MEDIO";    color="${C}"
    else                              label="BAJO";     color="${G}"
    fi

    local bar=$(( WA_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Puntuación de Riesgo:${NC} ${color}${BOLD}${WA_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0;i<bar;i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar;i<40;i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"; echo ""

    if [[ ${#WA_FINDINGS[@]} -gt 0 ]]; then
        _s "Hallazgos (${#WA_FINDINGS[@]})"
        for f in "${WA_FINDINGS[@]}"; do
            local sev="${f%%:*}"; local fc="${G}"
            [[ "$sev" == "CRITICO" ]] && fc="${R}"
            [[ "$sev" == "ALTO"    ]] && fc="${Y}"
            [[ "$sev" == "MEDIO"   ]] && fc="${C}"
            echo -e "  ${fc}[${sev}]${NC} ${f#*: }"
        done
    fi

    # Guardar log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local safe="${url//[^a-zA-Z0-9._-]/_}"
    local lf="${log_dir}/webapp_${safe:0:40}_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "WebApp Audit v3.2.0 — @kevxngg (Señor K)"
        echo "URL: $url | Riesgo: ${WA_RISK}/100 — $label | Fecha: $(date)"
        echo ""; echo "HALLAZGOS:"
        for f in "${WA_FINDINGS[@]}"; do echo "  - $f"; done
    } > "$lf"
    echo -e "  ${DIM}Log: ${W}${lf}${NC}"
}

# ── MAIN ─────────────────────────────────────────────────────────
run_webapp_audit() {
    local target="${1:-}"
    [[ -z "$target" ]] && return 1

    # Asegurar que tenga protocolo
    [[ "$target" != http* ]] && target="https://${target}"
    # Probar HTTPS, si falla HTTP
    if ! curl -sk --max-time 5 "$target" &>/dev/null; then
        target="http://${target#https://}"
    fi

    WA_RISK=0; WA_FINDINGS=()
    WA_BASE_URL="$target"; WA_BODY=""; WA_HEADERS=""

    webapp_recon "$target"
    webapp_security_headers "$target"
    webapp_sqli "$target"
    webapp_xss "$target"
    webapp_sensitive_files "$target"
    webapp_auth "$target"
    webapp_info_leak "$target"
    webapp_wordpress "$target"
    webapp_summary "$target"
}
