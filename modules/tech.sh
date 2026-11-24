#!/usr/bin/env bash
# Auto-generated module — DomainInfo v3.1.0 — @kevxngg (Kevin)
# shellcheck disable=SC2034,SC1091

# Colors (inherited from parent or redefined)
R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
B='\033[0;34m';  C='\033[0;36m';  M='\033[0;35m'
W='\033[1;37m';  DIM='\033[2m';   NC='\033[0m'
BOLD='\033[1m';  BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

header() { local t="$1"; local p=$(( 54 - ${#t} )); echo ""; echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${B}║${W}${BOLD}  ${t}${NC}${B}$(printf '%*s' $p '')║${NC}"; echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"; }
section() { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
kv()      { printf "  ${C}%-26s${NC} ${G}%s${NC}\n" "$1" "$2"; }
kv_r()    { printf "  ${C}%-26s${NC} ${R}%s${NC}\n" "$1" "$2"; }
kv_y()    { printf "  ${C}%-26s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
kv_b()    { printf "  ${C}%-26s${NC} ${B}%s${NC}\n" "$1" "$2"; }
ok()      { echo -e "  ${G}[✓]${NC} $1"; }
fail()    { echo -e "  ${R}[✗]${NC} $1"; }
warn()    { echo -e "  ${Y}[!]${NC} $1"; }
info()    { echo -e "  ${DIM}ℹ  $1${NC}"; }

module_tech() {
    is_ip "$TARGET" && return
    header "12 ▸ DETECTED TECHNOLOGIES"

    local base_url="https://${DOMAIN}"
    curl -s --max-time 5 "$base_url" &>/dev/null || base_url="http://${DOMAIN}"

    local body headers
    body=$(curl -skL --max-time 10 "$base_url" 2>/dev/null | head -200)
    headers=$(curl -sIL --max-time 8 "$base_url" 2>/dev/null)

    section "Technology stack"

    # CMS detection
    local cms=""
    if echo "$body$headers" | grep -qi "wp-content\|wp-includes\|wordpress"; then
        cms="WordPress"
        kv_y "CMS" "$cms"
        # WordPress specific checks
        local wp_ver
        wp_ver=$(curl -sk --max-time 5 "${base_url}/readme.html" 2>/dev/null | grep -oE 'Version [0-9.]+' | head -1)
        [[ -n "$wp_ver" ]] && kv_r "WordPress readme exposed" "$wp_ver (hide /readme.html)"
        local wp_json
        wp_json=$(curl -sk --max-time 5 "${base_url}/wp-json/wp/v2/users" 2>/dev/null | grep -o '"name":"[^"]*"' | head -3)
        [[ -n "$wp_json" ]] && kv_r "WP REST API users" "User enumeration is exposed"
    elif echo "$body" | grep -qi "joomla"; then
        cms="Joomla"; kv_y "CMS" "$cms"
    elif echo "$body" | grep -qi "drupal"; then
        cms="Drupal";  kv_y "CMS" "$cms"
    elif echo "$body" | grep -qi "laravel"; then
        cms="Laravel"; kv "Framework" "$cms"
    elif echo "$body" | grep -qi "django"; then
        cms="Django"; kv "Framework" "$cms"
    fi
    [[ -z "$cms" ]] && info "CMS/Framework not identified"

    # Server
    local server
    server=$(echo "$headers" | grep -i "^server:" | cut -d: -f2- | xargs)
    [[ -n "$server" ]] && kv "Web server" "$server"

    # PHP
    local php_ver
    php_ver=$(echo "$headers" | grep -i "x-powered-by" | cut -d: -f2- | xargs)
    if [[ -n "$php_ver" ]]; then
        kv_y "X-Powered-By (exposed)" "$php_ver"
        info "Hide X-Powered-By: header('X-Powered-By: ')  or  php_flag expose_php Off"
    fi

    # JS frameworks
    if echo "$body" | grep -qi "react\|__REACT"; then
        kv "Frontend" "React.js"
    elif echo "$body" | grep -qi "ng-version\|angular"; then
        kv "Frontend" "Angular"
    elif echo "$body" | grep -qi "__vue\|v-bind\|v-if"; then
        kv "Frontend" "Vue.js"
    fi

    # CDN
    local cdn
    cdn=$(echo "$headers" | grep -i "^x-cache\|^cf-ray\|^x-amz-cf" | head -1)
    [[ -n "$cdn" ]] && kv "CDN" "$cdn"
}

# ════════════════════════════════════════════════════════════════════
# SAVE LOG
# ════════════════════════════════════════════════════════════════════
