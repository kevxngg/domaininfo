#!/usr/bin/env bash
# ================================================================
#  summary.sh — Resumen ejecutivo
#  DomainInfo v3.2.0 — @kevxngg (Señor K)
# ================================================================
# shellcheck disable=SC2034,SC1091

# Colores (heredados del orquestador o redefinidos como fallback)
R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
B='\033[0;34m';  C='\033[0;36m';  M='\033[0;35m'
W='\033[1;37m';  DIM='\033[2m';   NC='\033[0m'
BOLD='\033[1m';  BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

# Helpers sólo si no existen (heredados del orquestador)
if ! declare -f header &>/dev/null; then
    header()  { local t="$1"; local p=$(( 54 - ${#t} )); echo ""; echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${B}║${W}${BOLD}  ${t}${NC}${B}$(printf '%*s' "$p" '')║${NC}"; echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"; }
    section() { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
    kv()      { printf "  ${C}%-26s${NC} ${G}%s${NC}\n" "$1" "$2"; }
    kv_r()    { printf "  ${C}%-26s${NC} ${R}%s${NC}\n" "$1" "$2"; }
    kv_y()    { printf "  ${C}%-26s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
    kv_b()    { printf "  ${C}%-26s${NC} ${B}%s${NC}\n" "$1" "$2"; }
    ok()      { echo -e "  ${G}[✓]${NC} $1"; }
    fail()    { echo -e "  ${R}[✗]${NC} $1"; }
    warn()    { echo -e "  ${Y}[!]${NC} $1"; }
    info()    { echo -e "  ${DIM}ℹ  $1${NC}"; }
fi

# ════════════════════════════════════════════════════════════════
# MÓDULO: RESUMEN EJECUTIVO
# ════════════════════════════════════════════════════════════════
module_summary() {
    header "✦  RESUMEN EJECUTIVO"
    echo ""
    [[ -n "$DOMAIN"      ]] && kv   "Dominio"         "$DOMAIN"
    [[ -n "$IP"          ]] && kv   "IP principal"    "$IP"
    [[ -n "$GEO_COUNTRY" ]] && kv   "País"            "$GEO_COUNTRY"
    [[ -n "$GEO_CITY"    ]] && kv   "Ciudad"          "$GEO_CITY"
    [[ -n "$GEO_ORG"     ]] && kv   "Organización"    "$GEO_ORG"
    [[ -n "$GEO_ISP"     ]] && kv   "ISP"             "$GEO_ISP"
    [[ -n "$GEO_ASN"     ]] && kv   "ASN"             "$GEO_ASN"
    [[ -n "$registrar"   ]] && kv   "Registrar"       "$registrar"
    [[ -n "$created"     ]] && kv   "Dominio creado"  "$created"
    [[ -n "$expires"     ]] && kv   "Expira"          "$expires"

    if [[ "${LISTED:-0}" -gt 0 ]]; then
        kv_r "Blacklists"    "$LISTED listas negras"
    else
        ok "IP limpia en listas negras"
    fi

    [[ "$GEO_PROXY"   == "true" ]] && kv_r "Proxy/VPN"  "Detectado"
    [[ "$GEO_HOSTING" == "true" ]] && kv_y "Hosting/DC" "IP de datacenter"
    echo ""
}
