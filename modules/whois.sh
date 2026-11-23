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

module_whois() {
    command -v whois >/dev/null 2>&1 || { warn "Optional WHOIS not available; use the portable RDAP module"; return 0; }
    header "3 ▸ WHOIS — OWNER"

    local whois_target="${DOMAIN:-$IP}"
    local WHOIS_DATA
    WHOIS_DATA=$(whois "$whois_target" 2>/dev/null)

    parse_whois() { echo "$WHOIS_DATA" | grep -i "$1" | head -1 | sed 's/.*: *//' | xargs 2>/dev/null; }

    local registrar reg_url created updated expires status_w
    local admin_email name_servers dnssec reg_org reg_country
    local abuse_email abuse_phone iana_id

    registrar=$(parse_whois "^Registrar:")
    reg_url=$(parse_whois "Registrar URL:")
    created=$(parse_whois "Creation Date\|Created On\|created:")
    updated=$(parse_whois "Updated Date\|last-modified:")
    expires=$(parse_whois "Expiry Date\|Registry Expiry Date\|Expiration")
    admin_email=$(echo "$WHOIS_DATA" | grep -iE "Registrant Email|Admin Email" | head -1 | sed 's/.*: *//' | xargs 2>/dev/null)
    name_servers=$(echo "$WHOIS_DATA" | grep -i "Name Server:" | awk '{print $NF}' | sort -u | tr '\n' ' ')
    dnssec=$(parse_whois "DNSSEC")
    reg_org=$(parse_whois "Registrant Organization\|org:")
    reg_country=$(parse_whois "Registrant Country\|country:")
    abuse_email=$(parse_whois "Registrar Abuse Contact Email\|abuse-mailbox")
    abuse_phone=$(parse_whois "Registrar Abuse Contact Phone\|phone")
    iana_id=$(parse_whois "Registrar IANA ID")

    section "Registrar data"
    kv "Registrar"           "${registrar:-N/A}"
    kv "IANA ID"             "${iana_id:-N/A}"
    kv "Registrar URL"       "${reg_url:-N/A}"
    kv "Abuse email"         "${abuse_email:-N/A}"
    kv "Abuse phone"         "${abuse_phone:-N/A}"

    section "Registrant data"
    kv "Organization"        "${reg_org:-N/A (private)}"
    kv "Registrant country"  "${reg_country:-N/A}"
    kv "Admin email"         "${admin_email:-N/A (RDAP privacy)}"

    section "Domain dates"
    kv "Creation date"       "${created:-N/A}"
    kv "Last updated"        "${updated:-N/A}"
    kv "Expiration"          "${expires:-N/A}"

    # Compute days until expiration
    if [[ -n "$expires" ]]; then
        local exp_ts now_ts days_left
        exp_ts=$(date -d "$expires" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$expires" +%s 2>/dev/null)
        now_ts=$(date +%s)
        if [[ -n "$exp_ts" ]]; then
            days_left=$(( (exp_ts - now_ts) / 86400 ))
            if [[ $days_left -lt 30 ]]; then
                kv_r "⚠ Days until expiry" "${days_left} days"
            elif [[ $days_left -lt 90 ]]; then
                kv_y "Days until expiry" "${days_left} days"
            else
                ok "Expires in ${days_left} days"
            fi
        fi
    fi

    section "Status and DNS"
    local st_line
    while IFS= read -r st_line; do
        [[ -n "$st_line" ]] && echo "$st_line" | grep -qi "prohibit" \
            && kv_y "Status" "$st_line" \
            || kv "Status" "$st_line"
    done < <(echo "$WHOIS_DATA" | grep -i "Domain Status:" | head -5 | sed 's/.*: *//')
    kv "Name Servers"        "${name_servers:-N/A}"
    kv "DNSSEC"              "${dnssec:-N/A}"

    section "Raw WHOIS (50 lines)"
    echo "$WHOIS_DATA" | head -50 | while IFS= read -r line; do
        echo -e "  ${DIM}${line}${NC}"
    done
}

# ════════════════════════════════════════════════════════════════════
# MODULE: HTTP
# ════════════════════════════════════════════════════════════════════
