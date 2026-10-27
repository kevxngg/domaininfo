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

module_dns() {
    header "1 ▸ RESOLUCIÓN DNS"

    if is_ip "$TARGET"; then
        section "PTR — Registro inverso"
        local ptr
        ptr=$(dig +short -x "$TARGET" 2>/dev/null | head -1 | sed 's/\.$//')
        [[ -n "$ptr" ]] && kv "PTR (reverso)" "$ptr" || info "Sin PTR reverso"
        IP="$TARGET"
        DOMAIN="$ptr"
        return
    fi

    DOMAIN="$TARGET"

    # ── A records
    section "Registros A — IPv4"
    local ipv4_list
    ipv4_list=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [[ -n "$ipv4_list" ]]; then
        IP=$(echo "$ipv4_list" | head -1)
        while IFS= read -r line; do
            [[ -n "$line" ]] && kv "IPv4" "$line"
        done <<< "$ipv4_list"
    else
        fail "Sin registros A"
    fi

    # ── AAAA records
    section "Registros AAAA — IPv6"
    local ipv6_list
    ipv6_list=$(dig +short AAAA "$DOMAIN" 2>/dev/null | grep -v "^;;")
    if [[ -n "$ipv6_list" ]]; then
        while IFS= read -r l; do [[ -n "$l" ]] && kv "IPv6" "$l"; done <<< "$ipv6_list"
    else
        info "Sin registros AAAA"
    fi

    # ── MX
    section "Registros MX — Correo"
    local mx_list
    mx_list=$(dig +short MX "$DOMAIN" 2>/dev/null | grep -v "^;;")
    if [[ -n "$mx_list" ]]; then
        while IFS= read -r l; do [[ -n "$l" ]] && kv "MX" "$l"; done <<< "$mx_list"
    else
        info "Sin registros MX"
    fi

    # ── NS
    section "Registros NS — Nameservers"
    local ns_list
    ns_list=$(dig +short NS "$DOMAIN" 2>/dev/null | grep -v "^;;")
    if [[ -n "$ns_list" ]]; then
        while IFS= read -r l; do [[ -n "$l" ]] && kv "NS" "$l"; done <<< "$ns_list"
    else
        info "Sin registros NS"
    fi

    # ── TXT
    section "Registros TXT — SPF / DKIM / Verificaciones"
    local txt_list
    txt_list=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -v "^;;")
    if [[ -n "$txt_list" ]]; then
        while IFS= read -r l; do
            if [[ -n "$l" ]]; then
                if echo "$l" | grep -qi "spf"; then
                    echo -e "  ${G}[SPF]${NC}  ${DIM}$l${NC}"
                elif echo "$l" | grep -qi "dkim\|domainkey"; then
                    echo -e "  ${G}[DKIM]${NC} ${DIM}$l${NC}"
                elif echo "$l" | grep -qi "verify\|google\|facebook\|zoho\|ms="; then
                    echo -e "  ${Y}[VERIF]${NC}${DIM}$l${NC}"
                else
                    echo -e "  ${DIM}$l${NC}"
                fi
            fi
        done <<< "$txt_list"
    else
        info "Sin registros TXT"
    fi

    # ── CNAME
    section "Registro CNAME"
    local cname
    cname=$(dig +short CNAME "$DOMAIN" 2>/dev/null | grep -v "^;;")
    [[ -n "$cname" ]] && kv "CNAME" "$cname" || info "Sin CNAME directo"

    # ── SOA
    section "SOA — Start of Authority"
    local soa
    soa=$(dig +short SOA "$DOMAIN" 2>/dev/null | grep -v "^;;")
    if [[ -n "$soa" ]]; then
        local primary_ns admin serial
        primary_ns=$(echo "$soa" | awk '{print $1}')
        admin=$(echo "$soa" | awk '{print $2}')
        serial=$(echo "$soa" | awk '{print $3}')
        kv "Primary NS" "$primary_ns"
        kv "Admin email (SOA)" "$admin"
        kv "Serial" "$serial"
    else
        info "Sin SOA"
    fi

    # ── CAA
    section "CAA — Autoridad de Certificados"
    local caa
    caa=$(dig +short CAA "$DOMAIN" 2>/dev/null | grep -v "^;;")
    [[ -n "$caa" ]] && echo -e "  ${G}$caa${NC}" || info "Sin CAA (cualquier CA puede emitir certs)"

    # ── DMARC
    section "DMARC — Política de correo"
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | grep -v "^;;")
    if [[ -n "$dmarc" ]]; then
        kv "DMARC" "$dmarc"
        echo "$dmarc" | grep -qi "p=reject" && ok "Política DMARC: REJECT (más estricta)" 
        echo "$dmarc" | grep -qi "p=quarantine" && kv_y "Política DMARC" "quarantine"
        echo "$dmarc" | grep -qi "p=none" && kv_r "Política DMARC" "none (no protege)"
    else
        kv_r "DMARC" "No configurado"
    fi

    # ── DNSKEY / DNSSEC
    section "DNSSEC"
    local dnssec
    dnssec=$(dig +short DNSKEY "$DOMAIN" 2>/dev/null | grep -v "^;;" | head -2)
    [[ -n "$dnssec" ]] && ok "DNSSEC activo" || kv_r "DNSSEC" "No firmado (sin DNSSEC)"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO: GEOLOCALIZACIÓN
# ════════════════════════════════════════════════════════════════════
