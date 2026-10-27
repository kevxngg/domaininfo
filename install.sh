#!/usr/bin/env bash
# ================================================================
#  install.sh — Instalador para DomainInfo v3.2.0
#  Autor  : @kevxngg (Señor K)
#  GitHub : https://github.com/kevxngg/domaininfo
# ================================================================

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; W='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "  ${G}[✓]${NC} $1"; }
fail() { echo -e "  ${R}[✗]${NC} $1"; }
warn() { echo -e "  ${Y}[!]${NC} $1"; }
info() { echo -e "  ${B}[i]${NC} $1"; }

echo -e "${B}"
echo '  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗██╗███╗   ██╗███████╗ ██████╗'
echo '  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║██║████╗  ██║██╔════╝██╔═══██╗'
echo '  ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║██║██╔██╗ ██║█████╗  ██║   ██║'
echo '  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║██║██║╚██╗██║██╔══╝  ██║   ██║'
echo '  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║██║██║ ╚████║██║     ╚██████╔╝'
echo '  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝'
echo -e "${NC}"
echo -e "  ${W}${BOLD}Instalador v3.2.0${NC} — ${B}@kevxngg (Señor K)${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IS_TERMUX=false
[[ -d "/data/data/com.termux" ]] && IS_TERMUX=true

# ── Detectar sistema ─────────────────────────────────────────────
detect_os() {
    if $IS_TERMUX; then
        echo "termux"
    elif [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${ID:-linux}"
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "macos"
    else
        echo "linux"
    fi
}

OS=$(detect_os)
info "Sistema detectado: $OS"
echo ""

# ── Instalar dependencias ────────────────────────────────────────
install_deps() {
    echo -e "  ${W}${BOLD}Instalando dependencias...${NC}"
    echo ""

    local tools_required=(curl dig whois host)
    local tools_optional=(nmap traceroute openssl python3 nc netcat)

    case "$OS" in
        termux)
            pkg update -y &>/dev/null
            pkg install -y curl dnsutils whois nmap openssl-tool python traceroute netcat-openbsd \
                2>&1 | grep -E "installed|upgraded|already" | head -20
            ;;
        debian|ubuntu|kali|parrot)
            apt-get update -qq 2>/dev/null
            apt-get install -y curl dnsutils whois nmap openssl python3 traceroute netcat-openbsd \
                2>&1 | grep -E "installed|upgraded|already" | head -20
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm curl bind-tools whois nmap openssl python traceroute gnu-netcat \
                2>&1 | tail -5
            ;;
        fedora|rhel|centos)
            dnf install -y curl bind-utils whois nmap openssl python3 traceroute nmap-ncat \
                2>&1 | tail -5
            ;;
        macos)
            if command -v brew &>/dev/null; then
                brew install curl nmap openssl python3 2>&1 | tail -5
            else
                warn "Homebrew no encontrado. Instala brew: https://brew.sh"
            fi
            ;;
        *)
            warn "OS no reconocido — instala manualmente: curl dig whois nmap openssl python3"
            ;;
    esac

    echo ""
    echo -e "  ${W}${BOLD}Verificando herramientas:${NC}"
    for tool in "${tools_required[@]}"; do
        command -v "$tool" &>/dev/null && ok "$tool" || fail "$tool — FALTA (requerido)"
    done
    for tool in "${tools_optional[@]}"; do
        command -v "$tool" &>/dev/null && ok "$tool" || warn "$tool — no disponible (opcional)"
    done
}

# ── Configurar permisos ──────────────────────────────────────────
setup_permissions() {
    echo ""
    echo -e "  ${W}${BOLD}Configurando permisos...${NC}"
    chmod +x "${SCRIPT_DIR}/domaininfo.sh"
    # Dar permisos a todos los módulos
    find "${SCRIPT_DIR}/modules" -name "*.sh" -exec chmod +x {} \;
    chmod +x "${SCRIPT_DIR}/report.py"   2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/traceroute.py" 2>/dev/null || true
    mkdir -p "${SCRIPT_DIR}/logs"
    ok "Permisos configurados"
}

# ── Crear alias global ───────────────────────────────────────────
setup_alias() {
    echo ""
    echo -e "  ${W}${BOLD}Configurando alias...${NC}"

    local shell_rc=""
    if $IS_TERMUX; then
        shell_rc="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        shell_rc="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        shell_rc="$HOME/.bashrc"
    fi

    if [[ -n "$shell_rc" ]]; then
        # ── BACKUP antes de modificar (buena práctica) ──────────────
        local backup="${shell_rc}.bak_domaininfo_$(date +%Y%m%d_%H%M%S)"
        cp "$shell_rc" "$backup" 2>/dev/null && ok "Backup: $backup"

        local alias_line="alias domaininfo='bash ${SCRIPT_DIR}/domaininfo.sh'"
        if ! grep -q "alias domaininfo=" "$shell_rc" 2>/dev/null; then
            {
                echo ""
                echo "# DomainInfo v3.2.0 — @kevxngg"
                echo "$alias_line"
            } >> "$shell_rc"
            ok "Alias agregado en $shell_rc"
            info "Ejecuta: source $shell_rc  para activar"
        else
            ok "Alias ya existe en $shell_rc"
        fi
    else
        warn "No se encontró .bashrc/.zshrc — alias no configurado"
        info "Agrega manualmente: alias domaininfo='bash ${SCRIPT_DIR}/domaininfo.sh'"
    fi

    # ── Symlink a /usr/local/bin — SÓLO si hay permisos de escritura ──
    if ! $IS_TERMUX; then
        if [[ -w "/usr/local/bin" ]]; then
            ln -sf "${SCRIPT_DIR}/domaininfo.sh" /usr/local/bin/domaininfo 2>/dev/null \
                && ok "Symlink creado: /usr/local/bin/domaininfo"
        elif command -v sudo &>/dev/null; then
            info "Creando symlink con sudo..."
            sudo ln -sf "${SCRIPT_DIR}/domaininfo.sh" /usr/local/bin/domaininfo 2>/dev/null \
                && ok "Symlink creado: /usr/local/bin/domaininfo" \
                || warn "No se pudo crear symlink — usa el alias o ejecuta con 'bash domaininfo.sh'"
        else
            warn "/usr/local/bin no es escribible y sudo no disponible"
            info "Usa: bash ${SCRIPT_DIR}/domaininfo.sh"
        fi
    fi
}

# ── Main ─────────────────────────────────────────────────────────
install_deps
setup_permissions
setup_alias

echo ""
echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${B}║${G}${BOLD}  ✓  DomainInfo v3.2.0 instalado correctamente           ${NC}${B}║${NC}"
echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${W}${BOLD}Comandos disponibles:${NC}"
echo -e "  ${G}domaininfo${NC} google.com        — Dominio (requiere 'source ~/.bashrc')"
echo -e "  ${G}bash domaininfo.sh${NC}            — Menú interactivo (funciona siempre)"
echo -e "  ${G}bash domaininfo.sh${NC} 8.8.8.8   — Análisis directo de IP"
echo -e "  ${G}bash domaininfo.sh${NC} -h         — Ver todas las opciones"
echo ""
