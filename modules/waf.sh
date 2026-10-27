#!/usr/bin/env bash
# ================================================================
#  waf.sh — WAF / CDN Detection & Security Headers
#  DomainInfo v3.2.0 — @kevxngg (Señor K)
# ================================================================
# shellcheck disable=SC2034,SC1091

R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
B='\033[0;34m';  C='\033[0;36m';  M='\033[0;35m'
W='\033[1;37m';  DIM='\033[2m';   NC='\033[0m'
BOLD='\033[1m';  BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

if ! declare -f header &>/dev/null; then
    header()  { local t="$1"; local p=$(( 54 - ${#t} )); echo ""; echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${B}║${W}${BOLD}  ${t}${NC}${B}$(printf '%*s' "$p" '')║${NC}"; echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"; }
    section() { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
    kv()      { printf "  ${C}%-26s${NC} ${G}%s${NC}\n" "$1" "$2"; }
    kv_r()    { printf "  ${C}%-26s${NC} ${R}%s${NC}\n" "$1" "$2"; }
    kv_y()    { printf "  ${C}%-26s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
    ok()      { echo -e "  ${G}[✓]${NC} $1"; }
    fail()    { echo -e "  ${R}[✗]${NC} $1"; }
    warn()    { echo -e "  ${Y}[!]${NC} $1"; }
    info()    { echo -e "  ${DIM}ℹ  $1${NC}"; }
fi

module_waf() {
    is_ip "$TARGET" && return
    header "10 ▸ WAF / CDN DETECTION"
    section "Detección de Firewall de Aplicaciones Web"

    local base_url="https://${DOMAIN}"
    curl -s --max-time 5 "$base_url" &>/dev/null || base_url="http://${DOMAIN}"

    local headers
    headers=$(curl -sIL --max-time 8 "$base_url" 2>/dev/null)
    local waf_detected=""

    # Detectar WAF/CDN por headers
    if   echo "$headers" | grep -qi "cloudflare\|cf-ray\|__cfduid";           then waf_detected="Cloudflare"
    elif echo "$headers" | grep -qi "x-sucuri\|sucuri";                        then waf_detected="Sucuri WAF"
    elif echo "$headers" | grep -qi "x-akamai\|akamaighost";                  then waf_detected="Akamai"
    elif echo "$headers" | grep -qi "x-amz-cf\|x-amzn\|amazon";              then waf_detected="AWS CloudFront/WAF"
    elif echo "$headers" | grep -qi "x-forwarded-by.*imperva\|incapsula";     then waf_detected="Imperva/Incapsula"
    elif echo "$headers" | grep -qi "x-cdn.*varnish\|varnish";                then waf_detected="Varnish CDN"
    elif echo "$headers" | grep -qi "x-mod-pagespeed";                        then waf_detected="ModPageSpeed (Google)"
    elif echo "$headers" | grep -qi "server.*nginx\|server.*apache"; then
        local svr
        svr=$(echo "$headers" | grep -i "^server:" | head -1 | cut -d: -f2- | xargs)
        waf_detected="Sin WAF detectado — Servidor: $svr"
    fi

    if [[ -n "$waf_detected" ]]; then
        kv_y "WAF/CDN detectado" "$waf_detected"
        info "El WAF puede limitar algunas técnicas de reconocimiento activo"
    else
        kv "WAF/CDN" "No detectado o no identificado"
    fi

    # ── Puntuación de headers de seguridad ───────────────────────
    section "Puntuación de Headers de Seguridad"

    # TODAS las variables son locales — evita contaminar el namespace global
    local score=0 total=7
    local hsts csp xfo xcto rp pp cors_val cors_hdr

    hsts=$(echo "$headers"     | grep -i "strict-transport-security" | head -1)
    csp=$(echo "$headers"      | grep -i "content-security-policy" | head -1)
    xfo=$(echo "$headers"      | grep -i "x-frame-options" | head -1)
    xcto=$(echo "$headers"     | grep -i "x-content-type-options" | head -1)
    rp=$(echo "$headers"       | grep -i "referrer-policy" | head -1)
    pp=$(echo "$headers"       | grep -i "permissions-policy\|feature-policy" | head -1)
    cors_hdr=$(echo "$headers" | grep -i "access-control-allow-origin" | head -1)

    # Función interna (local al módulo en tiempo de ejecución)
    _check_header() {
        local name="$1" val="$2"
        if [[ -n "$val" ]]; then
            ok "$name presente"
            (( score++ ))
        else
            kv_r "✗ Falta $name" "header de seguridad ausente"
        fi
    }

    _check_header "Strict-Transport-Security" "$hsts"
    _check_header "Content-Security-Policy"   "$csp"
    _check_header "X-Frame-Options"           "$xfo"
    _check_header "X-Content-Type-Options"    "$xcto"
    _check_header "Referrer-Policy"           "$rp"
    _check_header "Permissions-Policy"        "$pp"

    # CORS — usar variable local (no global)
    if [[ -n "$cors_hdr" ]]; then
        cors_val=$(echo "$cors_hdr" | cut -d: -f2- | xargs)
        if [[ "$cors_val" == "*" ]]; then
            kv_r "⚠ CORS" "Access-Control-Allow-Origin: * (demasiado permisivo)"
        else
            ok "CORS configurado: $cors_val"
            (( score++ ))
        fi
    fi

    # Desregistrar helper interno para no ensuciar el namespace
    unset -f _check_header

    echo ""
    local grade
    if   [[ $score -ge 6 ]]; then grade="A — Excelente"
    elif [[ $score -ge 4 ]]; then grade="B — Buena"
    elif [[ $score -ge 2 ]]; then grade="C — Regular"
    else                          grade="F — Deficiente"
    fi
    kv "Puntuación headers" "$score/$total — Grado $grade"
}
