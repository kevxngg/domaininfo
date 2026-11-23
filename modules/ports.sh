#!/usr/bin/env bash
# ================================================================
#  ports.sh — Port scanning
#  DomainInfo v3.2.0 — @kevxngg (Kevin)
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

module_ports() {
    header "5 ▸ PORT SCAN"
    local scan_target="${IP:-$TARGET}"
    [[ -z "$scan_target" ]] && { warn "No target to scan"; return; }

    if command -v nmap &>/dev/null; then
        section "Nmap — Top 100 ports + version detection"
        warn "This may take 30-60 seconds..."
        echo ""
        local nmap_out
        nmap_out=$(nmap -sT -T4 --host-timeout 90s --top-ports 100 -sV --open \
            --script "banner,http-title,ssl-cert,ftp-bounce" \
            "$scan_target" 2>/dev/null)
        local open_ports
        open_ports=$(echo "$nmap_out" | grep "^[0-9]" | grep "open")

        if [[ -n "$open_ports" ]]; then
            printf "  ${W}${BOLD}%-22s %-10s %-15s %s${NC}\n" "PORT" "STATE" "SERVICE" "VERSION"
            echo -e "  ${DIM}$(printf '─%.0s' {1..56})${NC}"
            while IFS= read -r line; do
                local port state service version
                port=$(echo "$line"    | awk '{print $1}')
                state=$(echo "$line"   | awk '{print $2}')
                service=$(echo "$line" | awk '{print $3}')
                version=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | xargs)
                printf "  ${G}%-22s${NC} %-10s ${C}%-15s${NC} ${DIM}%s${NC}\n" \
                    "$port" "$state" "$service" "$version"
            done <<< "$open_ports"
        else
            info "No open ports detected (top 100)"
        fi

        section "NSE script results"
        echo "$nmap_out" | grep -A2 "| " | grep -v "^--$" | while IFS= read -r l; do
            [[ -n "$l" ]] && echo -e "  ${DIM}$l${NC}"
        done

    else
        # ── Fallback: manual check with proper parallelism ──
        section "Manual check of common ports"
        warn "nmap not available — using fallback (may take ~30s)"
        echo ""

        local common_ports=(21 22 23 25 53 80 110 143 443 445 587 993 995 3306 3389 5432 6379 8080 8443 27017)
        local tmpdir; tmpdir=$(mktemp -d) || return 1
        # shellcheck disable=SC2064
        _TMPDIR_GLOBAL="$tmpdir"

        printf "  ${W}${BOLD}%-20s %s${NC}\n" "PORT" "STATE"
        echo -e "  ${DIM}$(printf '─%.0s' {1..30})${NC}"

        for port in "${common_ports[@]}"; do
            # Each check in its own subshell with an independent timeout
            (
                if timeout 3 bash -c "echo >/dev/tcp/${scan_target}/${port}" 2>/dev/null; then
                    echo "$port" >> "${tmpdir}/open"
                fi
            ) &
        done
        # Wait for all port checks
        wait

        if [[ -f "${tmpdir}/open" ]]; then
            sort -n "${tmpdir}/open" | while IFS= read -r p; do
                printf "  ${G}%-20s${NC} ${G}%s${NC}\n" "$p/tcp" "OPEN"
            done
        else
            info "No open ports found in the common list"
        fi
    fi
}
