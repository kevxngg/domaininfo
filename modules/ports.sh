#!/usr/bin/env bash
# ================================================================
#  ports.sh — Escaneo de puertos
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

module_ports() {
    header "5 ▸ ESCANEO DE PUERTOS"
    local scan_target="${IP:-$TARGET}"
    [[ -z "$scan_target" ]] && { warn "Sin objetivo para escanear"; return; }

    if command -v nmap &>/dev/null; then
        section "Nmap — Top 100 puertos + detección de versión"
        warn "Esto puede tardar 30-60 segundos..."
        echo ""
        local nmap_out
        nmap_out=$(nmap -sT -T4 --host-timeout 90s --top-ports 100 -sV --open \
            --script "banner,http-title,ssl-cert,ftp-bounce" \
            "$scan_target" 2>/dev/null)
        local open_ports
        open_ports=$(echo "$nmap_out" | grep "^[0-9]" | grep "open")

        if [[ -n "$open_ports" ]]; then
            printf "  ${W}${BOLD}%-22s %-10s %-15s %s${NC}\n" "PUERTO" "ESTADO" "SERVICIO" "VERSIÓN"
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
            info "No se detectaron puertos abiertos (top 100)"
        fi

        section "Resultados de scripts NSE"
        echo "$nmap_out" | grep -A2 "| " | grep -v "^--$" | while IFS= read -r l; do
            [[ -n "$l" ]] && echo -e "  ${DIM}$l${NC}"
        done

    else
        # ── Fallback: comprobación manual con paralelismo correcto ──
        section "Comprobación manual de puertos comunes"
        warn "nmap no disponible — usando fallback (puede tardar ~30s)"
        echo ""

        local common_ports=(21 22 23 25 53 80 110 143 443 445 587 993 995 3306 3389 5432 6379 8080 8443 27017)
        local tmpdir; tmpdir=$(mktemp -d) || return 1
        # shellcheck disable=SC2064
        _TMPDIR_GLOBAL="$tmpdir"

        printf "  ${W}${BOLD}%-20s %s${NC}\n" "PUERTO" "ESTADO"
        echo -e "  ${DIM}$(printf '─%.0s' {1..30})${NC}"

        for port in "${common_ports[@]}"; do
            # Cada check en su propio subshell con timeout independiente
            (
                if timeout 3 bash -c "echo >/dev/tcp/${scan_target}/${port}" 2>/dev/null; then
                    echo "$port" >> "${tmpdir}/open"
                fi
            ) &
        done
        # Esperar todos los checks de puertos
        wait

        if [[ -f "${tmpdir}/open" ]]; then
            sort -n "${tmpdir}/open" | while IFS= read -r p; do
                printf "  ${G}%-20s${NC} ${G}%s${NC}\n" "$p/tcp" "ABIERTO"
            done
        else
            info "No se encontraron puertos abiertos en la lista común"
        fi
    fi
}
