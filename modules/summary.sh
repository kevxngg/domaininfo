#!/usr/bin/env bash
# ================================================================
#  summary.sh — Executive summary
#  DomainInfo v3.2.0 — @kevxngg (Kevin)
# ================================================================
# shellcheck disable=SC2034,SC1091

# Colors (inherited from the orchestrator or redefined as a fallback)
R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
B='\033[0;34m';  C='\033[0;36m';  M='\033[0;35m'
W='\033[1;37m';  DIM='\033[2m';   NC='\033[0m'
BOLD='\033[1m';  BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

# Helpers only if they do not exist yet (inherited from the orchestrator)
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
# MODULE: EXECUTIVE SUMMARY
# ════════════════════════════════════════════════════════════════
module_summary() {
    header "✦  EXECUTIVE SUMMARY"
    echo ""
    [[ -n "$DOMAIN"      ]] && kv   "Domain"          "$DOMAIN"
    [[ -n "$IP"          ]] && kv   "Primary IP"      "$IP"
    [[ -n "$GEO_COUNTRY" ]] && kv   "Country"         "$GEO_COUNTRY"
    [[ -n "$GEO_CITY"    ]] && kv   "City"            "$GEO_CITY"
    [[ -n "$GEO_ORG"     ]] && kv   "Organization"    "$GEO_ORG"
    [[ -n "$GEO_ISP"     ]] && kv   "ISP"             "$GEO_ISP"
    [[ -n "$GEO_ASN"     ]] && kv   "ASN"             "$GEO_ASN"
    [[ -n "$registrar"   ]] && kv   "Registrar"       "$registrar"
    [[ -n "$created"     ]] && kv   "Domain created"  "$created"
    [[ -n "$expires"     ]] && kv   "Expires"         "$expires"

    if [[ "${LISTED:-0}" -gt 0 ]]; then
        kv_r "Blacklists"    "$LISTED blacklists"
    else
        ok "IP clean on blacklists"
    fi

    [[ "$GEO_PROXY"   == "true" ]] && kv_r "Proxy/VPN"  "Detected"
    [[ "$GEO_HOSTING" == "true" ]] && kv_y "Hosting/DC" "Datacenter IP"
    echo ""
}
