#!/usr/bin/env bash
# ================================================================
#  domaininfo.sh — Domain & IP Intelligence Tool v3.2.0
#  Author : @kevxngg (Kevin)
#  GitHub : https://github.com/kevxngg/domaininfo
#  Version: 3.2.0  |  License: MIT
# ================================================================

# The portable CLI is available without Bash-specific dependencies.
if [[ "${1:-}" == "--portable" || "${1:-}" == "--mikrotik" || "${1:-}" == "--menu" ||
      ( $# == 0 && "${BASH_SOURCE[0]}" == "$0" ) ]]; then
    _portable_mode="${1:---menu}"
    [[ $# -gt 0 ]] && shift
    [[ "$_portable_mode" == "--menu" ]] && set -- --interactive "$@"
    [[ "$_portable_mode" == "--mikrotik" ]] && set -- -m mikrotik "$@"
    _portable_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for _python in python3 python; do
        if command -v "$_python" >/dev/null 2>&1; then
            exec "$_python" "$_portable_dir/domaininfo.py" "$@"
        fi
    done
    echo 'Install Python 3.10+ with bash install.sh.' >&2; exit 1
fi
if [[ "${1:-}" == "--legacy" ]]; then shift; fi
if (( BASH_VERSINFO[0] < 4 )); then
    echo 'The classic modules need Bash 4+. Use python3 domaininfo.py or Homebrew Bash.' >&2
    exit 1
fi
VERSION="4.3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR VERSION

# ── Colors ───────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'
W='\033[1;37m'; DIM='\033[2m';  NC='\033[0m'; BOLD='\033[1m'
export R G Y B C M W DIM NC BOLD

# ── Global helpers ───────────────────────────────────────────────
header()  {
    local t="$1" p=$(( 54 - ${#1} ))
    echo ""; printf "${B}╔══════════════════════════════════════════════════════════╗\n${NC}"
    printf "${B}║${W}${BOLD}  %s${NC}${B}%*s║\n${NC}" "$t" "$p" ""
    printf "${B}╚══════════════════════════════════════════════════════════╝\n${NC}"
}
section() { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
kv()      { printf "  ${C}%-26s${NC} ${G}%s${NC}\n" "$1" "$2"; }
kv_r()    { printf "  ${C}%-26s${NC} ${R}%s${NC}\n" "$1" "$2"; }
kv_y()    { printf "  ${C}%-26s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
kv_b()    { printf "  ${C}%-26s${NC} ${B}%s${NC}\n" "$1" "$2"; }
ok()      { echo -e "  ${G}[✓]${NC} $1"; }
fail()    { echo -e "  ${R}[✗]${NC} $1"; }
warn()    { echo -e "  ${Y}[!]${NC} $1"; }
info()    { echo -e "  ${DIM}ℹ  $1${NC}"; }
export -f header section kv kv_r kv_y kv_b ok fail warn info

# ── Global state variables ───────────────────────────────────────
MODE="full"; QUIET=false; VERBOSE=false; THREADS=15
JSON_OUTPUT=false; REPORT_HTML=true
FILE_INPUT=""; MODULES_SKIP=()
declare -A JSON_DATA

# ── Scan variables (reset between scans) ─────────────────────────
reset_scan_vars() {
    TARGET=""; DOMAIN=""; IP=""
    registrar=""; created=""; expires=""
    GEO_COUNTRY=""; GEO_CITY=""; GEO_ORG=""; GEO_ISP=""; GEO_ASN=""
    GEO_PROXY=""; GEO_HOSTING=""; LISTED=0
    JSON_DATA=()
}

# ── Trap SIGINT/SIGTERM — kill the child process tree ────────────
# Prevents zombie processes when the user presses Ctrl+C
_cleanup() {
    echo -e "\n\n  ${Y}[!]${NC} Interrupt received — cleaning up processes..."
    # Kill every background job of the current shell
    local pids
    pids=$(jobs -p 2>/dev/null)
    if [[ -n "$pids" ]]; then
        # shellcheck disable=SC2086
        kill $pids 2>/dev/null
        # Allow 1 second for a clean shutdown, then SIGKILL
        sleep 1
        kill -9 $pids 2>/dev/null
    fi
    # Remove temporary files if any
    [[ -n "${_TMPDIR_GLOBAL:-}" ]] && rm -rf "$_TMPDIR_GLOBAL" 2>/dev/null
    exit 130
}
trap '_cleanup' SIGINT SIGTERM

# ════════════════════════════════════════════════════════════════
# STRICT INPUT SANITIZATION
# ════════════════════════════════════════════════════════════════
validate_target() {
    local i="$1"
    # Strip protocol, path and whitespace
    i="${i#http://}"; i="${i#https://}"; i="${i%%/*}"; i="${i%%:*}"
    i="${i//$'\r'/}"
    [[ "$i" == *[[:space:]]* ]] && return 1

    [[ -z "$i" ]] && { echo ""; return 1; }

    # Validate IPv4
    if [[ "$i" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local o1 o2 o3 o4
        IFS='.' read -r o1 o2 o3 o4 <<< "$i"
        if (( 10#$o1<=255 && 10#$o2<=255 && 10#$o3<=255 && 10#$o4<=255 )); then
            printf '%s' "$i"; return 0
        fi
        return 1
    fi

    # Validate FQDN
    if [[ "$i" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]; then
        printf '%s' "$i"; return 0
    fi

    # Simple hostname (no dot)
    if [[ "$i" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$ ]]; then
        printf '%s' "$i"; return 0
    fi

    return 1
}

is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

# ════════════════════════════════════════════════════════════════
# DYNAMIC MODULE LOADING
# ════════════════════════════════════════════════════════════════
load_modules() {
    local dir="${SCRIPT_DIR}/modules"
    [[ -d "$dir" ]] || { fail "modules/ directory not found: $dir"; return 1; }
    local n=0
    for f in "${dir}"/*.sh; do
        [[ -f "$f" ]] || continue
        # shellcheck source=/dev/null
        if source "$f"; then
            (( n++ ))
        else
            warn "Could not load: $f"
        fi
    done
    $VERBOSE && info "Modules loaded: $n"
}

# ════════════════════════════════════════════════════════════════
# CHECK DEPENDENCIES
# ════════════════════════════════════════════════════════════════
check_deps() {
    local missing=()
    for cmd in curl dig; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "Missing tools: ${missing[*]}"
        [[ -d /data/data/com.termux ]] \
            && info "Termux: pkg install ${missing[*]} dnsutils" \
            || info "Linux: apt install ${missing[*]} dnsutils"
        return 1
    fi
    return 0
}

# ════════════════════════════════════════════════════════════════
# JSON — correct escaping of special characters
# ════════════════════════════════════════════════════════════════
# _json_escape: escapes a string so it is JSON-safe
_json_escape() {
    local s="$1"
    # Escape backslash first, then quotes, then control chars
    s="${s//\\/\\\\}"      # \ → \\
    s="${s//\"/\\\"}"      # " → \"
    s="${s//$'\n'/\\n}"   # newline → \n
    s="${s//$'\r'/\\r}"   # CR → \r
    s="${s//$'\t'/\\t}"   # tab → \t
    # Remove remaining non-printable control characters (U+0000–U+001F)
    s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
    printf '%s' "$s"
}

json_set() {
    JSON_DATA["$1"]="$(_json_escape "$2")"
}

json_export() {
    local out="$1"
    local first=true
    {
        printf '{\n'
        printf '  "meta":{"tool":"DomainInfo","version":"%s","author":"@kevxngg","target":"%s","date":"%s","mode":"%s"},\n' \
            "$(_json_escape "$VERSION")" \
            "$(_json_escape "$TARGET")" \
            "$(_json_escape "$(date '+%Y-%m-%dT%H:%M:%S%z')")" \
            "$(_json_escape "$MODE")"
        printf '  "data":{\n'
        for k in "${!JSON_DATA[@]}"; do
            $first || printf ',\n'
            printf '    "%s":"%s"' "$(_json_escape "$k")" "${JSON_DATA[$k]}"
            first=false
        done
        printf '\n  }\n'
        printf '}\n'
    } > "$out"
    ok "JSON: $out"
}

# ════════════════════════════════════════════════════════════════
# SKIP / RUN MODULE
# ════════════════════════════════════════════════════════════════
should_skip() { for s in "${MODULES_SKIP[@]}"; do [[ "$s" == "$1" ]] && return 0; done; return 1; }

run_module() {
    local fn="module_$1"
    should_skip "$1" && { $VERBOSE && info "Skipped: $1"; return; }
    if declare -f "$fn" &>/dev/null; then
        "$fn" 2>/dev/null || warn "Module '$1' finished with warnings"
    else
        $VERBOSE && warn "Function not found: $fn"
    fi
}

# ════════════════════════════════════════════════════════════════
# PARALLEL SUBDOMAINS
# ════════════════════════════════════════════════════════════════
module_subdomains() {
    is_ip "$TARGET" && return
    header "7 ▸ SUBDOMAINS — PARALLEL (${THREADS} threads)"
    section "Concurrent DNS brute-force"

    local wl="${SCRIPT_DIR}/wordlists/subdomains.txt"
    local subs=()
    if [[ -f "$wl" ]]; then
        while IFS= read -r s || [[ -n "$s" ]]; do
            [[ -z "$s" || "$s" == "#"* ]] && continue; subs+=("$s")
        done < "$wl"
    else
        subs=(www mail ftp api dev staging admin vpn git db cdn)
    fi

    # Temporary directory, always cleaned up when the function returns
    local tmpdir
    tmpdir=$(mktemp -d) || { warn "Could not create temporary directory"; return 1; }
    # Register for global cleanup (in case SIGINT interrupts)
    _TMPDIR_GLOBAL="$tmpdir"
    printf "\n  ${W}${BOLD}%-40s %s${NC}\n" "SUBDOMAIN" "IP"
    echo -e "  ${DIM}$(printf '─%.0s' {1..56})${NC}"

    local jobs=0
    for sub in "${subs[@]}"; do
        (
            local r
            r=$(dig +short +time=3 +tries=1 A "${sub}.${DOMAIN}" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
            [[ -n "$r" ]] && printf '%s|%s\n' "${sub}.${DOMAIN}" "$r" >> "${tmpdir}/found"
        ) &
        (( jobs++ ))
        # Concurrency control: wait for a free job slot when the pool is full
        if (( jobs >= THREADS )); then
            wait -n 2>/dev/null || wait
            (( jobs-- ))
        fi
    done
    # Wait for all remaining jobs
    wait

    local fc=0
    if [[ -f "${tmpdir}/found" ]]; then
        sort "${tmpdir}/found" | while IFS='|' read -r sd ip; do
            printf "  ${G}%-40s${NC} ${C}%s${NC}\n" "$sd" "$ip"
        done
        fc=$(wc -l < "${tmpdir}/found")
    fi

    echo ""
    (( fc == 0 )) && info "No subdomains found" || ok "$fc subdomains found"

    rm -rf "$tmpdir"
    _TMPDIR_GLOBAL=""
}

# ════════════════════════════════════════════════════════════════
# SAVE LOG
# ════════════════════════════════════════════════════════════════
save_log() {
    local log_dir="${SCRIPT_DIR}/logs"; mkdir -p "$log_dir"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local safe="${TARGET//[^a-zA-Z0-9._-]/_}"
    LOG_FILE="${log_dir}/domaininfo_${safe}_${ts}.txt"
    {
        echo "=========================================================="
        echo " DomainInfo v${VERSION} — Report: $TARGET"
        echo " Date   : $(date '+%Y-%m-%d %H:%M:%S') | Mode: $MODE"
        echo " Auditor: @kevxngg (Kevin)"
        echo "=========================================================="
        echo "Domain     : ${DOMAIN:-N/A}"
        echo "IP         : ${IP:-N/A}"
        echo "Country    : ${GEO_COUNTRY:-N/A} / ${GEO_CITY:-N/A}"
        echo "Org        : ${GEO_ORG:-N/A}"
        echo "ISP        : ${GEO_ISP:-N/A}"
        echo "ASN        : ${GEO_ASN:-N/A}"
        echo "Registrar  : ${registrar:-N/A}"
        echo "Created    : ${created:-N/A}"
        echo "Expires    : ${expires:-N/A}"
        echo "Blacklists : ${LISTED:-0}"
        echo "Proxy/VPN  : ${GEO_PROXY:-N/A}"
        echo "Hosting/DC : ${GEO_HOSTING:-N/A}"
    } > "$LOG_FILE"

    $QUIET || echo -e "  ${DIM}Log: ${W}${LOG_FILE}${NC}"

    if $JSON_OUTPUT; then
        local jf="${LOG_FILE%.txt}.json"
        json_set "domain"     "${DOMAIN:-}"
        json_set "ip"         "${IP:-}"
        json_set "country"    "${GEO_COUNTRY:-}"
        json_set "city"       "${GEO_CITY:-}"
        json_set "org"        "${GEO_ORG:-}"
        json_set "isp"        "${GEO_ISP:-}"
        json_set "asn"        "${GEO_ASN:-}"
        json_set "blacklists" "${LISTED:-0}"
        json_set "proxy"      "${GEO_PROXY:-}"
        json_set "hosting"    "${GEO_HOSTING:-}"
        json_export "$jf"
    fi

    if $REPORT_HTML && command -v python3 &>/dev/null && [[ -f "${SCRIPT_DIR}/report.py" ]]; then
        local hf="${LOG_FILE%.txt}_report.html"
        python3 "${SCRIPT_DIR}/report.py" "$LOG_FILE" "$hf" 2>/dev/null
        $QUIET || echo -e "  ${DIM}HTML: ${W}${hf}${NC}"
    fi
}

# ════════════════════════════════════════════════════════════════
# SCAN MODE
# ════════════════════════════════════════════════════════════════
run_scan() {
    if $QUIET; then
        ( QUIET=false; run_scan ) >/dev/null
        return $?
    fi
    # Resolve IP / domain
    if is_ip "$TARGET"; then
        IP="$TARGET"; DOMAIN="$TARGET"
    else
        DOMAIN="$TARGET"
        IP=$(dig +short +time=3 +tries=1 A "$TARGET" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
    fi

    $QUIET || {
        echo ""
        echo -e "  ${C}Target:${NC} ${W}${BOLD}${TARGET}${NC}   ${DIM}mode:${MODE}  threads:${THREADS}  $(date '+%H:%M:%S')${NC}"
        echo -e "  ${DIM}$(printf '═%.0s' {1..58})${NC}"
        echo ""
    }

    case "$MODE" in
        quick)
            run_module dns; run_module geo; run_module whois
            ;;
        ports)
            run_module dns; run_module geo; run_module ports
            ;;
        web)
            run_module dns; run_module http; run_module waf
            run_module ssl_vulns; run_module tech
            ;;
        full)
            for m in dns geo whois http ports blacklist subdomains \
                     traceroute extra waf ssl_vulns tech; do
                run_module "$m"
            done
            ;;
        *)
            warn "Unknown mode: '$MODE' — using 'full'"
            MODE="full"
            for m in dns geo whois http ports blacklist subdomains \
                     traceroute extra waf ssl_vulns tech; do
                run_module "$m"
            done
            ;;
    esac

    declare -f module_summary &>/dev/null && module_summary
    save_log

    $QUIET || {
        echo ""
        echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${B}║${G}${BOLD}  ✓  Analysis complete — @kevxngg v${VERSION}                ${NC}${B}║${NC}"
        echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"
    }
}

# ════════════════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════════════════
show_banner() {
    [[ -t 1 && -n "${TERM:-}" ]] && clear
    echo -e "${B}"
    echo '  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗██╗███╗   ██╗███████╗ ██████╗'
    echo '  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║██║████╗  ██║██╔════╝██╔═══██╗'
    echo '  ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║██║██╔██╗ ██║█████╗  ██║   ██║'
    echo '  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║██║██║╚██╗██║██╔══╝  ██║   ██║'
    echo '  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║██║██║ ╚████║██║     ╚██████╔╝'
    echo '  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝'
    echo -e "${NC}"
    echo -e "  ${W}${BOLD}Domain & IP Intelligence Suite${NC}   ${DIM}v${VERSION} — @kevxngg (Kevin)${NC}"
    echo -e "  ${DIM}github.com/kevxngg/domaininfo${NC}"
    echo -e "  ${DIM}$(printf '═%.0s' {1..58})${NC}"
    echo ""
}

# ════════════════════════════════════════════════════════════════
# HELP
# ════════════════════════════════════════════════════════════════
show_help() {
    echo -e "${W}${BOLD}DomainInfo v${VERSION}${NC} — @kevxngg (Kevin)"
    echo -e "\n${W}${BOLD}USAGE:${NC}  domaininfo [options] <domain|IP>"
    echo -e "\n${W}${BOLD}OPTIONS:${NC}"
    echo -e "  ${G}-f <file>${NC}      Batch: multiple targets (one per line)"
    echo -e "  ${G}-m <mode>${NC}      full | quick | ports | web  (default: full)"
    echo -e "  ${G}-t <threads>${NC}   Subdomain scan threads (default: 15)"
    echo -e "  ${G}-s <module>${NC}    Skip a module (can be repeated)"
    echo -e "  ${G}-j${NC}            Export JSON next to the log"
    echo -e "  ${G}-q${NC}            Quiet mode (no console output)"
    echo -e "  ${G}-v${NC}            Verbose (shows loaded modules)"
    echo -e "  ${G}-h${NC}            This help"
    echo -e "\n${W}${BOLD}EXAMPLES:${NC}"
    echo -e "  bash domaininfo.sh google.com"
    echo -e "  bash domaininfo.sh -m quick 8.8.8.8"
    echo -e "  bash domaininfo.sh -m full -j -t 20 example.com"
    echo -e "  bash domaininfo.sh -s traceroute -s blacklist example.com"
    echo -e "  bash domaininfo.sh -f targets.txt"
}

# ════════════════════════════════════════════════════════════════
# INTERACTIVE MENU
# ════════════════════════════════════════════════════════════════
interactive_menu() {
    while true; do
        show_banner
        echo -e "  ${W}${BOLD}SELECT A MODULE:${NC}\n"
        echo -e "  ${B}── DOMAIN / PUBLIC IP ANALYSIS ───────────────────────${NC}"
        echo -e "  ${G}[1]${NC} Quick analysis           (DNS + Geo + WHOIS)"
        echo -e "  ${G}[2]${NC} Port analysis            (DNS + Geo + Ports)"
        echo -e "  ${G}[3]${NC} Web analysis             (HTTP + WAF + SSL + Tech)"
        echo -e "  ${G}[4]${NC} Full analysis            (all modules)"
        echo -e "  ${G}[5]${NC} Advanced web audit       (OWASP, XSS, SQLi, Auth)"
        echo -e "  ${G}[6]${NC} ISP/Company audit        (equipment, CVEs, risk)"
        echo -e "  ${G}[9]${NC} Current MikroTik RouterOS (version advisories, Python)"
        echo ""
        echo -e "  ${B}── LOCAL NETWORK / WIFI ──────────────────────────────${NC}"
        echo -e "  ${G}[7]${NC} Local network scan       (hosts, gateway, IoT, WiFi)"
        echo ""
        echo -e "  ${B}── BATCH ──────────────────────────────────────────────${NC}"
        echo -e "  ${G}[8]${NC} Multiple targets         (from a .txt file)"
        echo ""
        echo -e "  ${R}[0]${NC} Exit"
        echo -e "  ${DIM}$(printf '─%.0s' {1..58})${NC}\n"

        local choice
        printf "  ${W}${BOLD}Option [0-9]: ${NC}"
        read -r choice || return 0

        case "$choice" in
            9)
                local routeros_target routeros_version routeros_python
                printf '  MikroTik domain or IP: '
                read -r routeros_target || return 0
                printf '  RouterOS version (ENTER to try to detect it): '
                read -r routeros_version || return 0
                routeros_python=""
                for candidate in python3 python; do
                    if command -v "$candidate" >/dev/null 2>&1; then routeros_python="$candidate"; break; fi
                done
                if [[ -z "$routeros_python" ]]; then
                    warn "Install Python 3.10+ for the modern RouterOS audit"
                elif [[ -n "$routeros_version" ]]; then
                    "$routeros_python" "$SCRIPT_DIR/domaininfo.py" -m mikrotik --routeros-version "$routeros_version" -- "$routeros_target"
                else
                    "$routeros_python" "$SCRIPT_DIR/domaininfo.py" -m mikrotik -- "$routeros_target"
                fi
                printf '  Press ENTER to return to the menu...'
                read -r || return 0
                ;;
            1|2|3|4|5|6)
                local raw_input validated
                printf "  ${W}${BOLD}Enter a domain or IP: ${NC}"
                read -r raw_input

                validated=$(validate_target "$raw_input")
                if [[ -z "$validated" ]]; then
                    echo ""
                    fail "Invalid input: '${raw_input}'"
                    fail "Accepts IPv4 (e.g. 8.8.8.8) or a domain (e.g. google.com)"
                    echo ""
                    printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                    read -r
                    continue
                fi

                reset_scan_vars
                TARGET="$validated"

                case "$choice" in
                    1) MODE="quick" ;;
                    2) MODE="ports" ;;
                    3) MODE="web"   ;;
                    4) MODE="full"  ;;
                    5)
                        echo ""
                        info "Starting OWASP web audit on: $validated"
                        sleep 1
                        if declare -f run_webapp_audit &>/dev/null; then
                            run_webapp_audit "$validated"
                        else
                            fail "webapp module not loaded"
                        fi
                        echo ""
                        printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                        read -r
                        continue
                        ;;
                    6)
                        echo ""
                        info "Starting ISP/Network audit on: $validated"
                        sleep 1
                        if declare -f run_isp_audit &>/dev/null; then
                            run_isp_audit "$validated"
                        else
                            fail "isp_audit module not loaded"
                        fi
                        echo ""
                        printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                        read -r
                        continue
                        ;;
                esac

                run_scan

                echo ""
                printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                read -r
                ;;

            7)
                echo ""
                info "Starting local network scan..."
                if declare -f run_localnet_audit &>/dev/null; then
                    run_localnet_audit
                else
                    fail "localnet module not loaded"
                fi
                echo ""
                printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                read -r
                ;;

            8)
                printf "  ${W}${BOLD}File path (one target per line): ${NC}"
                read -r FILE_INPUT
                if [[ ! -f "$FILE_INPUT" ]]; then
                    fail "File not found: $FILE_INPUT"
                    sleep 2; continue
                fi
                echo ""
                local line_count=0
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" || "$line" == "#"* ]] && continue
                    local validated
                    validated=$(validate_target "$line")
                    if [[ -z "$validated" ]]; then
                        warn "Ignored (invalid): '$line'"; continue
                    fi
                    reset_scan_vars
                    TARGET="$validated"
                    MODE="quick"
                    echo -e "\n${Y}${BOLD}══ Target $((++line_count)): $TARGET ══${NC}"
                    run_scan
                done < "$FILE_INPUT"
                echo ""
                ok "Batch complete: $line_count targets processed"
                printf "  ${DIM}Press ENTER to return to the menu...${NC}"
                read -r
                ;;

            0)
                echo ""
                exit 0
                ;;

            *)
                warn "Invalid option: '$choice'"
                sleep 1
                ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════════
# CLI WITH getopts
# ════════════════════════════════════════════════════════════════
parse_args() {
    [[ "$1" == "--help"    ]] && { show_help; exit 0; }
    [[ "$1" == "--version" ]] && { echo "DomainInfo v${VERSION}"; exit 0; }

    local OPTIND opt
    while getopts ":f:m:t:s:jqvh" opt; do
        case "$opt" in
            f) FILE_INPUT="$OPTARG" ;;
            m) MODE="$OPTARG" ;;
            t) THREADS="$OPTARG" ;;
            s) MODULES_SKIP+=("$OPTARG") ;;
            j) JSON_OUTPUT=true ;;
            q) QUIET=true ;;
            v) VERBOSE=true ;;
            h) show_help; exit 0 ;;
            :) fail "-$OPTARG requires an argument"; exit 1 ;;
           \?) fail "Unknown option: -$OPTARG"; exit 1 ;;
        esac
    done
    shift $(( OPTIND - 1 ))
    CLI_TARGET="${1:-}"
    [[ $# -le 1 ]] || { fail "Too many targets; use -f"; exit 2; }
    [[ "$MODE" =~ ^(quick|full|web|ports)$ ]] || { fail "Invalid mode: $MODE"; exit 2; }
    [[ "$THREADS" =~ ^[0-9]+$ ]] && (( 10#$THREADS >= 1 && 10#$THREADS <= 64 )) || {
        fail "Threads must be between 1 and 64"; exit 2;
    }
    THREADS=$((10#$THREADS))
    [[ -z "$FILE_INPUT" || -z "$CLI_TARGET" ]] || { fail "Use -f or a single target, not both"; exit 2; }
}

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    if ! command -v timeout >/dev/null 2>&1 && command -v gtimeout >/dev/null 2>&1; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    fi
    check_deps || exit 1
    load_modules

    # No arguments → interactive menu
    if [[ -z "${CLI_TARGET:-}" && -z "$FILE_INPUT" ]]; then
        interactive_menu
        exit 0
    fi

    # Batch from the CLI (-f file)
    if [[ -n "$FILE_INPUT" && -z "${CLI_TARGET:-}" ]]; then
        if [[ ! -f "$FILE_INPUT" ]]; then
            fail "File not found: $FILE_INPUT"; exit 1
        fi
        local line_count=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            local v; v=$(validate_target "$line")
            [[ -z "$v" ]] && { warn "Ignored: '$line'"; continue; }
            reset_scan_vars; TARGET="$v"
            $QUIET || echo -e "\n${Y}${BOLD}══ Target $((++line_count)): $TARGET ══${NC}"
            run_scan
        done < "$FILE_INPUT"
        exit 0
    fi

    # Single target from the CLI
    local v; v=$(validate_target "${CLI_TARGET:-}")
    if [[ -z "$v" ]]; then
        fail "Invalid input: '${CLI_TARGET:-}'"
        fail "Accepts: IPv4 (8.8.8.8) or FQDN (google.com)"
        exit 1
    fi

    reset_scan_vars; TARGET="$v"
    $QUIET || show_banner
    run_scan
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
