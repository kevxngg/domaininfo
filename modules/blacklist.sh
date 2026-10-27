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

module_blacklist() {
    header "6 ▸ REPUTACIÓN — LISTAS NEGRAS (DNSBL)"
    [[ -z "$IP" ]] && { warn "Sin IP para verificar"; return; }

    section "Comprobando 12 listas negras"
    local rev_ip
    rev_ip=$(echo "$IP" | awk -F'.' '{print $4"."$3"."$2"."$1}')

    local blacklists=(
        "zen.spamhaus.org"
        "bl.spamcop.net"
        "dnsbl.sorbs.net"
        "spam.dnsbl.sorbs.net"
        "cbl.abuseat.org"
        "b.barracudacentral.org"
        "dnsbl-1.uceprotect.net"
        "ix.dnsbl.manitu.net"
        "truncate.gbudb.net"
        "psbl.surriel.com"
        "dnsbl.spfbl.net"
        "multi.uribl.com"
    )

    LISTED=0
    for bl in "${blacklists[@]}"; do
        local result
        result=$(dig +short +time=3 +tries=1 "${rev_ip}.${bl}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        if [[ -n "$result" ]]; then
            kv_r "✗ LISTADO en $bl" "$result"
            ((LISTED++))
        else
            ok "Limpio en $bl"
        fi
    done

    echo ""
    if [[ $LISTED -eq 0 ]]; then
        ok "IP no listada en ninguna lista negra verificada ✓"
    else
        kv_r "⚠ Total listas negras" "$LISTED encontradas"
    fi
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO: SUBDOMINIOS
# ════════════════════════════════════════════════════════════════════
