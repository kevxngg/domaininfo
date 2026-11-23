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

module_ssl_vulns() {
    is_ip "$TARGET" && return
    header "11 ▸ SSL/TLS VULNERABILITIES"

    if ! timeout 3 bash -c "echo >/dev/tcp/${DOMAIN}/443" 2>/dev/null; then
        info "Port 443 not reachable — skipping SSL analysis"
        return
    fi

    section "Supported protocol versions"

    # Check TLS 1.0 (obsolete and insecure)
    local tls10 tls11 tls12 tls13
    tls10=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" -tls1 2>/dev/null | grep -E 'Cipher is|Cipher *:' | grep -vE 'NONE|0000' | head -1)
    tls11=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" -tls1_1 2>/dev/null | grep -E 'Cipher is|Cipher *:' | grep -vE 'NONE|0000' | head -1)
    tls12=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" -tls1_2 2>/dev/null | grep -E 'Cipher is|Cipher *:' | grep -vE 'NONE|0000' | head -1)
    tls13=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" -tls1_3 2>/dev/null | grep -E 'Cipher is|Cipher *:' | grep -vE 'NONE|0000' | head -1)

    if [[ -n "$tls10" ]] && ! echo "$tls10" | grep -q "no peer\|error\|failure"; then
        kv_r "TLS 1.0" "SUPPORTED — obsolete (POODLE/BEAST risk)"
    else
        info "TLS 1.0: negotiation not confirmed (server or local policy)"
    fi

    if [[ -n "$tls11" ]] && ! echo "$tls11" | grep -q "no peer\|error\|failure"; then
        kv_r "TLS 1.1" "SUPPORTED — obsolete"
    else
        info "TLS 1.1: negotiation not confirmed (server or local policy)"
    fi

    if [[ -n "$tls12" ]] && ! echo "$tls12" | grep -q "no peer\|error\|failure"; then
        ok "TLS 1.2 supported"
    else
        kv_y "TLS 1.2" "Not available"
    fi

    if [[ -n "$tls13" ]] && ! echo "$tls13" | grep -q "no peer\|error\|failure"; then
        ok "TLS 1.3 supported — optimal"
    else
        kv_y "TLS 1.3" "Not available (enabling it is recommended)"
    fi

    section "SSL certificate"
    local cert_info
    cert_info=$(echo | timeout 5 openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
    if [[ -n "$cert_info" ]]; then
        local not_after
        not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        local issuer
        issuer=$(echo "$cert_info" | grep "issuer" | cut -d= -f2-)
        [[ -n "$not_after"  ]] && kv "Expires" "$not_after"
        [[ -n "$issuer"     ]] && kv "Issuer" "$issuer"
        # Check whether it has expired
        if [[ -n "$not_after" ]]; then
            local exp_epoch
            exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
            local now_epoch
            now_epoch=$(date +%s)
            if [[ -n "$exp_epoch" ]] && [[ "$exp_epoch" -lt "$now_epoch" ]]; then
                kv_r "⚠ CERTIFICATE" "EXPIRED"
            else
                ok "Certificate is valid"
            fi
        fi
    else
        warn "Could not retrieve certificate information"
    fi
}

# ════════════════════════════════════════════════════════════════════
# MODULE: TECHNOLOGIES AND CMS
# ════════════════════════════════════════════════════════════════════
