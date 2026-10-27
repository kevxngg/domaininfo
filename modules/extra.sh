#!/usr/bin/env bash
# Auto-generated module — DomainInfo v3.1.0 — @kevxngg (Señor K)
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

module_extra() {
    is_ip "$TARGET" && return
    header "9 ▸ RECONOCIMIENTO WEB EXTRA"

    local base_url="https://${DOMAIN}"
    # Intentar HTTP si HTTPS falla
    curl -s --max-time 5 "$base_url" &>/dev/null || base_url="http://${DOMAIN}"

    section "robots.txt"
    local robots
    robots=$(curl -sL --max-time 8 "${base_url}/robots.txt" 2>/dev/null | head -30)
    if [[ -n "$robots" && "$robots" != *"404"* && "$robots" != *"Not Found"* ]]; then
        echo "$robots" | while IFS= read -r l; do echo -e "  ${DIM}$l${NC}"; done
        # Directorios interesantes en Disallow
        local disallowed
        disallowed=$(echo "$robots" | grep -i "Disallow:" | awk '{print $2}' | head -10 | tr '\n' ' ')
        [[ -n "$disallowed" ]] && kv_y "Disallowed paths" "$disallowed"
    else
        info "robots.txt no encontrado o vacío"
    fi

    section "sitemap.xml"
    local sitemap
    sitemap=$(curl -sL --max-time 8 "${base_url}/sitemap.xml" 2>/dev/null | head -20)
    if [[ -n "$sitemap" && "$sitemap" == *"xml"* ]]; then
        local url_count
        url_count=$(echo "$sitemap" | grep -c "<loc>")
        ok "sitemap.xml encontrado ($url_count URLs en primeras 20 líneas)"
        echo "$sitemap" | grep "<loc>" | sed 's/.*<loc>//;s/<\/loc>//' | head -5 | while IFS= read -r u; do
            echo -e "  ${DIM}$u${NC}"
        done
    else
        info "sitemap.xml no encontrado"
    fi

    section "Archivos expuestos comunes"
    local sensitive_paths=()
    local paths_file="${SCRIPT_DIR}/wordlists/paths.txt"
    if [[ -f "$paths_file" ]]; then
        while IFS= read -r p || [[ -n "$p" ]]; do
            [[ -z "$p" || "$p" == "#"* ]] && continue
            sensitive_paths+=("$p")
        done < "$paths_file"
    else
        sensitive_paths=(
            "/.git/HEAD" "/.env" "/wp-config.php.bak"
            "/config.php" "/phpinfo.php" "/server-status"
            "/.htaccess" "/readme.html" "/license.txt" "/CHANGELOG.txt"
        )
    fi
    for path in "${sensitive_paths[@]}"; do
        local code
        code=$(curl -sI --max-time 5 "${base_url}${path}" 2>/dev/null | head -1 | awk '{print $2}')
        if [[ "$code" == "200" ]]; then
            kv_r "⚠ EXPUESTO" "${base_url}${path} [200 OK]"
        fi
    done
    ok "Escaneo de rutas sensibles completado"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO: RESUMEN Y GUARDADO
# ════════════════════════════════════════════════════════════════════
