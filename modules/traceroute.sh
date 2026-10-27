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

module_traceroute() {
    header "8 ▸ TRACEROUTE — RUTA DE RED"
    local target="${IP:-$TARGET}"
    warn "Ejecutando traceroute (15 saltos máx, puede tardar 20-30s)..."
    echo ""

    if command -v traceroute &>/dev/null; then
        traceroute -m 15 -w 2 -q 1 "$target" 2>/dev/null | while IFS= read -r line; do
            echo -e "  ${DIM}$line${NC}"
        done
    elif command -v tracepath &>/dev/null; then
        tracepath -m 15 "$target" 2>/dev/null | head -20 | while IFS= read -r line; do
            echo -e "  ${DIM}$line${NC}"
        done
    else
        info "traceroute/tracepath no disponible en este sistema"
        if command -v python3 &>/dev/null; then
            section "Traceroute Python (ICMP/TTL)"
            python3 "$SCRIPT_DIR/traceroute.py" "$target" 2>/dev/null || info "Script Python no disponible"
        fi
    fi
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO: EXTRA — ROBOTS, SITEMAP, EMAILS
# ════════════════════════════════════════════════════════════════════
