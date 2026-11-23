#!/usr/bin/env bash
# ================================================================
#  webapp.sh — Web Application Vulnerability Scanner
#  Author: @kevxngg (Kevin)
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

# ── 1. Basic reconnaissance ──────────────────────────────────────
webapp_recon() {
    local url="$1"
    _h "1 ▸ WEB RECONNAISSANCE"

    local headers body status server
    headers=$(_req_headers "$url")
    body=$(_req GET "$url" | head -200)
    status=$(echo "$headers" | head -1 | awk '{print $2}')
    server=$(echo "$headers" | grep -i "^server:" | cut -d: -f2- | xargs)

    _kv "URL"        "$url"
    _kv "HTTP Status" "${status:-N/A}"
    _kv "Server"     "${server:-Not disclosed}"

    # Technologies
    _s "Detected technology stack"
    local powered
    powered=$(echo "$headers" | grep -i "x-powered-by:" | cut -d: -f2- | xargs)
    [[ -n "$powered" ]] && _kvy "X-Powered-By (exposed)" "$powered" && \
        wa_add "MEDIUM: X-Powered-By exposed: $powered" && ((WA_RISK+=5))

    # CMS
    local cms=""
    if echo "$body$headers" | grep -qi "wp-content\|wp-includes\|wordpress"; then
        cms="WordPress"; _kvy "CMS" "WordPress"
        # WordPress version
        local wpver
        wpver=$(curl -sk --max-time 5 "${url%/}/readme.html" 2>/dev/null | grep -oE 'Version [0-9.]+' | head -1)
        [[ -n "$wpver" ]] && { _vuln "WordPress readme.html exposed — $wpver"; wa_add "HIGH: readme.html exposes the WordPress version"; ((WA_RISK+=10)); }
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
    _s "Cookie analysis"
    local cookies
    cookies=$(echo "$headers" | grep -i "set-cookie:")
    if [[ -n "$cookies" ]]; then
        while IFS= read -r cookie; do
            local cname; cname=$(echo "$cookie" | grep -oE 'Set-Cookie: [^=]+=' | awk '{print $2}')
            if ! echo "$cookie" | grep -qi "httponly"; then
                _vuln "Cookie without HttpOnly: ${cname:-cookie} — readable from JavaScript (XSS risk)"
                wa_add "HIGH: Cookie without HttpOnly flag"
                ((WA_RISK+=10))
            fi
            if ! echo "$cookie" | grep -qi "secure"; then
                _warn "Cookie without Secure flag: ${cname:-cookie} — may be sent over HTTP"
                wa_add "MEDIUM: Cookie without Secure flag"
                ((WA_RISK+=5))
            fi
            if ! echo "$cookie" | grep -qi "samesite"; then
                _warn "Cookie without SameSite: ${cname:-cookie} — CSRF risk"
                wa_add "MEDIUM: Cookie without SameSite"
                ((WA_RISK+=5))
            fi
        done <<< "$cookies"
    else
        _info "No cookies detected in the initial response"
    fi

    WA_BASE_URL="$url"
    WA_BODY="$body"
    WA_HEADERS="$headers"
}

# ── 2. Security headers ──────────────────────────────────────────
webapp_security_headers() {
    _h "2 ▸ SECURITY HEADERS (OWASP)"
    local url="$1"
    local headers="${WA_HEADERS:-$(_req_headers "$url")}"

    _s "Checking recommended OWASP headers"
    echo ""
    printf "  ${W}${BOLD}%-35s %-10s %s${NC}\n" "HEADER" "STATE" "VALUE / NOTE"
    echo -e "  ${DIM}$(printf '─%.0s' {1..75})${NC}"

    check_sh() {
        local name="$1" grep_pattern="$2" risk="$3" note="$4"
        local val
        val=$(echo "$headers" | grep -i "$grep_pattern" | cut -d: -f2- | xargs)
        if [[ -n "$val" ]]; then
            printf "  ${G}%-35s %-10s${NC} ${DIM}%s${NC}\n" "$name" "PRESENT" "$val"
        else
            printf "  ${R}%-35s %-10s${NC} ${Y}%s${NC}\n" "$name" "MISSING" "$note"
            wa_add "${risk}: Missing header — $name"
            ((WA_RISK+=5))
        fi
    }

    check_sh "Strict-Transport-Security" "strict-transport" "HIGH" "Add: max-age=31536000; includeSubDomains"
    check_sh "Content-Security-Policy"   "content-security-policy" "HIGH" "Prevents XSS and content injection"
    check_sh "X-Frame-Options"           "x-frame-options" "MEDIUM" "Add: DENY or SAMEORIGIN"
    check_sh "X-Content-Type-Options"    "x-content-type-options" "MEDIUM" "Add: nosniff"
    check_sh "Referrer-Policy"           "referrer-policy" "LOW" "Add: strict-origin-when-cross-origin"
    check_sh "Permissions-Policy"        "permissions-policy\|feature-policy" "LOW" "Controls access to browser APIs"

    # CORS
    local cors
    cors=$(echo "$headers" | grep -i "access-control-allow-origin:" | cut -d: -f2- | xargs)
    if [[ -n "$cors" ]]; then
        if [[ "$cors" == "*" ]]; then
            printf "  ${R}%-35s %-10s${NC} ${R}%s${NC}\n" "CORS (Access-Control-Allow-Origin)" "DANGEROUS" "Wildcard (*) — any origin can read the response"
            wa_add "HIGH: CORS wildcard — allows access from any domain"
            ((WA_RISK+=15))
        else
            printf "  ${G}%-35s %-10s${NC} ${DIM}%s${NC}\n" "CORS" "RESTRICTED" "$cors"
        fi
    fi
}

# ── 3. SQL injection indicators ─────────────────────────────────
webapp_sqli() {
    local url="$1"
    _h "3 ▸ SQL INJECTION — INDICATORS"
    _info "Passive and semi-active tests (no destructive payloads)"

    _s "Parameter and form detection"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # Detect forms
    local forms
    forms=$(echo "$body" | grep -oi "<form[^>]*>" | wc -l)
    _kv "Forms detected" "$forms"

    # Detect parameters in URLs in the body
    local params
    params=$(echo "$body" | grep -oE 'href="[^"]*\?[^"]*"' | grep -oE '\?[^"]+' | head -5)
    if [[ -n "$params" ]]; then
        _kvy "GET parameters found" "$(echo "$params" | head -3)"

        # Try a basic SQL error payload (detect only, never exploit)
        _s "SQL error test (diagnostic payload)"
        local test_url="${url}?id=1'"
        local sql_response
        sql_response=$(_req GET "$test_url" 2>/dev/null)
        if echo "$sql_response" | grep -qi "sql syntax\|mysql_fetch\|ORA-\|PostgreSQL\|sqlite\|SQLSTATE\|syntax error.*SQL\|unclosed quotation"; then
            _vuln "Possible SQL injection — the response contains database error messages"
            _vuln "  URL: $test_url"
            wa_add "CRITICAL: Possible SQL injection detected — database error exposed"
            ((WA_RISK+=40))
        else
            _ok "No SQL error messages detected"
        fi
    else
        _info "No GET parameters detected in the page body"
    fi

    # Error-based SQLi on the base page
    if echo "$body" | grep -qi "sql syntax\|mysql_\|ORA-\|sqlite_error\|SQLSTATE"; then
        _vuln "SQL error messages visible on the page"
        wa_add "CRITICAL: SQL errors exposed on the page"
        ((WA_RISK+=30))
    fi
}

# ── 4. XSS indicators ───────────────────────────────────────────
webapp_xss() {
    local url="$1"
    _h "4 ▸ CROSS-SITE SCRIPTING (XSS)"

    _s "Reflection vector detection"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # Check for search fields or parameters that reflect input
    # ("buscar" is kept on purpose: it is a common Spanish search parameter on remote sites)
    local search_param=""
    for param in "q" "search" "s" "query" "term" "keyword" "buscar"; do
        local test_val="xsstestXYZ123"
        local test_resp
        test_resp=$(_req GET "${url}?${param}=${test_val}" 2>/dev/null)
        if echo "$test_resp" | grep -q "$test_val"; then
            _med "Parameter '$param' reflects the input — possible reflected XSS"
            wa_add "HIGH: Parameter '$param' reflects unsanitized input"
            ((WA_RISK+=20))
            search_param="$param"
            break
        fi
    done
    [[ -z "$search_param" ]] && _ok "No direct reflection detected for the tested parameters"

    # CSP check for XSS mitigation
    if echo "${WA_HEADERS}" | grep -qi "content-security-policy"; then
        local csp
        csp=$(echo "${WA_HEADERS}" | grep -i "content-security-policy:" | cut -d: -f2-)
        if echo "$csp" | grep -qi "unsafe-inline\|unsafe-eval"; then
            _warn "CSP with 'unsafe-inline' or 'unsafe-eval' — CSP is less effective against XSS"
            wa_add "MEDIUM: CSP has unsafe-inline/unsafe-eval"
            ((WA_RISK+=10))
        else
            _ok "CSP without unsafe-inline/unsafe-eval (well configured)"
        fi
    else
        _warn "No Content-Security-Policy — larger XSS attack surface"
    fi
}

# ── 5. Sensitive files and endpoints ────────────────────────────
webapp_sensitive_files() {
    local url="$1"
    _h "5 ▸ SENSITIVE FILES AND ENDPOINTS"

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

    _s "Scanning ${#sensitive_paths[@]} sensitive paths"
    local found=0
    for path in "${sensitive_paths[@]}"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${path}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _vuln "EXPOSED [200]: ${url%/}${path}"
            wa_add "CRITICAL: Sensitive file reachable: $path"
            ((WA_RISK+=15))
            ((found++))
        elif [[ "$code" == "403" ]]; then
            _kvy "Restricted [403]" "${path}"
        fi
    done
    echo ""
    if [[ $found -eq 0 ]]; then
        _ok "No reachable sensitive files found (200 OK)"
    else
        _kvr "Sensitive files found" "$found"
    fi
}

# ── 6. Authentication and bypass ─────────────────────────────────
webapp_auth() {
    local url="$1"
    _h "6 ▸ AUTHENTICATION AND ACCESS CONTROL"

    _s "Authentication mechanism analysis"

    # Detect a login panel
    local login_paths=("/login" "/admin" "/admin/login" "/wp-login.php"
                       "/administrator" "/signin" "/auth" "/panel" "/dashboard")
    for lpath in "${login_paths[@]}"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${lpath}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _kvy "Login panel found" "${url%/}${lpath}"
            wa_add "INFO: Login panel detected: $lpath"

            # Check whether the form has a CSRF token
            local login_body
            login_body=$(curl -sk --max-time 5 "${url%/}${lpath}" 2>/dev/null)
            if ! echo "$login_body" | grep -qi "csrf\|_token\|nonce\|authenticity_token"; then
                _warn "  No CSRF token detected in the login form"
                wa_add "HIGH: Login form without CSRF protection"
                ((WA_RISK+=15))
            else
                _ok "  CSRF token detected in the form"
            fi
        fi
    done

    # HTTP Basic Auth check
    _s "HTTP Basic Auth check"
    local basic_resp
    basic_resp=$(curl -sk --max-time 5 -w "\n%{http_code}" "${url%/}/admin" 2>/dev/null)
    local basic_code; basic_code=$(echo "$basic_resp" | tail -1)
    if [[ "$basic_code" == "401" ]]; then
        _warn "HTTP Basic Auth detected on /admin"
        _info "Try common credentials: admin/admin, admin/password"
        wa_add "MEDIUM: HTTP Basic Auth on /admin"
    fi

    # Check whether admin resources are reachable directly without auth
    _s "Direct access to protected resources"
    for admin_path in "/admin/users" "/admin/config" "/api/users" "/api/v1/users" "/dashboard"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${admin_path}" 2>/dev/null)
        if [[ "$code" == "200" ]]; then
            _vuln "Admin resource reachable without auth [200]: $admin_path"
            wa_add "CRITICAL: Unauthorized access to $admin_path"
            ((WA_RISK+=30))
        fi
    done
}

# ── 7. Exposed sensitive information ────────────────────────────
webapp_info_leak() {
    local url="$1"
    _h "7 ▸ INFORMATION EXPOSURE"

    _s "Sensitive data detection in HTTP responses"
    local body="${WA_BODY:-$(_req GET "$url")}"

    # Internal IP
    if echo "$body$WA_HEADERS" | grep -oE '(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+' | head -1 | grep -q '.'; then
        local priv_ip
        priv_ip=$(echo "$body$WA_HEADERS" | grep -oE '(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+' | head -1)
        _vuln "Private IP exposed in the response: $priv_ip"
        wa_add "MEDIUM: Private IP exposed: $priv_ip"
        ((WA_RISK+=10))
    else
        _ok "No private IPs detected in responses"
    fi

    # Stack trace / debug info
    if echo "$body" | grep -qi "stack trace\|exception\|traceback\|debug.*true\|APP_DEBUG\|Warning:.*on line\|Fatal error"; then
        _vuln "Debug/error information exposed — reveals the application stack"
        wa_add "HIGH: Debug info/stack trace visible to the public"
        ((WA_RISK+=20))
    fi

    # Emails
    local emails
    emails=$(echo "$body" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -3)
    [[ -n "$emails" ]] && _kvy "Emails exposed in the HTML" "$emails"

    # Version info in headers
    if echo "$WA_HEADERS" | grep -iE "server:.*[0-9]\.|x-powered-by:.*[0-9]\." | grep -q .; then
        _warn "Software versions disclosed in headers"
        wa_add "MEDIUM: Software versions exposed in headers"
        ((WA_RISK+=5))
    fi

    # Comments with sensitive info
    if echo "$body" | grep -qi "TODO\|FIXME\|HACK\|password\|secret\|api.key\|token" | grep -q "<!--"; then
        _warn "Possible HTML comments with sensitive information"
        wa_add "LOW: HTML comments with possible sensitive info"
    fi
}

# ── 8. WordPress-specific ────────────────────────────────────────
webapp_wordpress() {
    local url="$1"
    local body="${WA_BODY:-}"
    echo "$body" | grep -qi "wp-content\|wp-includes" || return

    _h "8 ▸ WORDPRESS — SPECIFIC ANALYSIS"

    # User enumeration via the REST API
    _s "User enumeration (WP REST API)"
    local wp_users
    wp_users=$(curl -sk --max-time 8 "${url%/}/wp-json/wp/v2/users" 2>/dev/null)
    if echo "$wp_users" | grep -qi '"name"'; then
        _vuln "User enumeration enabled via the REST API"
        local unames
        unames=$(echo "$wp_users" | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | head -5 | tr '\n' ', ')
        _kvr "Exposed users" "$unames"
        wa_add "HIGH: WP REST API exposes the user list: $unames"
        ((WA_RISK+=20))
    else
        _ok "User enumeration disabled"
    fi

    # xmlrpc.php
    local xmlrpc_code
    xmlrpc_code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}/xmlrpc.php" 2>/dev/null)
    if [[ "$xmlrpc_code" == "200" || "$xmlrpc_code" == "405" ]]; then
        _warn "xmlrpc.php reachable — amplified brute-force vector"
        wa_add "HIGH: xmlrpc.php active — brute force without rate limiting"
        ((WA_RISK+=15))
    else
        _ok "xmlrpc.php not reachable or disabled"
    fi

    # WordPress debug files
    for wpf in "/wp-content/debug.log" "/wp-content/uploads/debug.log"; do
        local code
        code=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${url%/}${wpf}" 2>/dev/null)
        [[ "$code" == "200" ]] && { _vuln "Debug log reachable: $wpf"; wa_add "HIGH: WP debug.log exposed"; ((WA_RISK+=15)); }
    done
}

# ── 9. Web audit summary ─────────────────────────────────────────
webapp_summary() {
    local url="$1"
    _h "✦  SUMMARY — WEB AUDIT"
    echo ""
    _kv "Audited URL" "$url"
    _kv "Findings"    "${#WA_FINDINGS[@]}"
    echo ""

    [[ $WA_RISK -gt 100 ]] && WA_RISK=100
    local label color
    if   [[ $WA_RISK -ge 75 ]]; then label="CRITICAL"; color="${R}"
    elif [[ $WA_RISK -ge 50 ]]; then label="HIGH";     color="${Y}"
    elif [[ $WA_RISK -ge 25 ]]; then label="MEDIUM";   color="${C}"
    else                              label="LOW";      color="${G}"
    fi

    local bar=$(( WA_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Risk score:${NC} ${color}${BOLD}${WA_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0;i<bar;i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar;i<40;i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"; echo ""

    if [[ ${#WA_FINDINGS[@]} -gt 0 ]]; then
        _s "Findings (${#WA_FINDINGS[@]})"
        for f in "${WA_FINDINGS[@]}"; do
            local sev="${f%%:*}"; local fc="${G}"
            [[ "$sev" == "CRITICAL" ]] && fc="${R}"
            [[ "$sev" == "HIGH"     ]] && fc="${Y}"
            [[ "$sev" == "MEDIUM"   ]] && fc="${C}"
            echo -e "  ${fc}[${sev}]${NC} ${f#*: }"
        done
    fi

    # Save log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local safe="${url//[^a-zA-Z0-9._-]/_}"
    local lf="${log_dir}/webapp_${safe:0:40}_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "WebApp Audit v3.2.0 — @kevxngg (Kevin)"
        echo "URL: $url | Risk: ${WA_RISK}/100 — $label | Date: $(date)"
        echo ""; echo "FINDINGS:"
        for f in "${WA_FINDINGS[@]}"; do echo "  - $f"; done
    } > "$lf"
    echo -e "  ${DIM}Log: ${W}${lf}${NC}"
}

# ── MAIN ─────────────────────────────────────────────────────────
run_webapp_audit() {
    local target="${1:-}"
    [[ -z "$target" ]] && return 1

    # Make sure it has a scheme
    [[ "$target" != http* ]] && target="https://${target}"
    # Try HTTPS, fall back to HTTP if it fails
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
