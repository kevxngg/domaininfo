#!/usr/bin/env bash
# ================================================================
#  localnet.sh — Local Network Scanner (WiFi/LAN)
#  Finds devices, vulnerabilities and attack vectors
#  Author: @kevxngg (Kevin)
# ================================================================

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'
BG_R='\033[41m'; BG_G='\033[42m'; BG_Y='\033[43m'

_h()   { echo ""; echo -e "${B}╔══════════════════════════════════════════════════════════╗${NC}"; echo -e "${B}║${W}${BOLD}  $1${NC}${B}$(printf '%*s' $((54-${#1})) '')║${NC}"; echo -e "${B}╚══════════════════════════════════════════════════════════╝${NC}"; }
_s()   { echo -e "\n${M}▶  ${W}${BOLD}$1${NC}"; echo -e "${DIM}$(printf '─%.0s' {1..58})${NC}"; }
_kv()  { printf "  ${C}%-30s${NC} ${G}%s${NC}\n" "$1" "$2"; }
_kvr() { printf "  ${C}%-30s${NC} ${R}%s${NC}\n" "$1" "$2"; }
_kvy() { printf "  ${C}%-30s${NC} ${Y}%s${NC}\n" "$1" "$2"; }
_ok()  { echo -e "  ${G}[✓]${NC} $1"; }
_fail(){ echo -e "  ${R}[✗]${NC} $1"; }
_warn(){ echo -e "  ${Y}[!]${NC} $1"; }
_info(){ echo -e "  ${DIM}ℹ  $1${NC}"; }
_vuln(){ echo -e "  ${BG_R}${W}${BOLD} VULN ${NC} ${R}$1${NC}"; }
_safe(){ echo -e "  ${BG_G}${W}${BOLD} SAFE ${NC} ${G}$1${NC}"; }
_med() { echo -e "  ${BG_Y}${W}${BOLD} WARN ${NC} ${Y}$1${NC}"; }

LN_RISK=0
LN_FINDINGS=()
LN_HOSTS=()

# ── 1. Network interface information ────────────────────────────
localnet_iface_info() {
    _h "1 ▸ LOCAL NETWORK INFORMATION"

    _s "Active interface and configuration"
    local iface gateway local_ip subnet cidr

    # Detect the active interface (works on Linux and Termux)
    iface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    [[ -z "$iface" ]] && iface=$(route -n 2>/dev/null | grep '^0.0.0.0' | awk '{print $8}' | head -1)
    [[ -z "$iface" ]] && iface="wlan0"  # Termux default

    gateway=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    local_ip=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    cidr=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    subnet="${cidr%/*}"

    _kv "Active interface"  "${iface:-Not detected}"
    _kv "Local IP"          "${local_ip:-N/A}"
    _kv "CIDR network"      "${cidr:-N/A}"
    _kv "Gateway/Router"    "${gateway:-N/A}"

    # Gateway info (home router)
    if [[ -n "$gateway" ]]; then
        local gw_vendor
        gw_vendor=$(arp -n "$gateway" 2>/dev/null | awk '{print $3}' | head -1)
        [[ -n "$gw_vendor" ]] && _kv "Gateway MAC" "$gw_vendor"
    fi

    # WiFi info if available
    if command -v iwconfig &>/dev/null; then
        _s "WiFi information"
        local wifi_info
        wifi_info=$(iwconfig "$iface" 2>/dev/null)
        if [[ -n "$wifi_info" ]]; then
            local ssid bssid freq quality
            ssid=$(echo "$wifi_info" | grep -oP 'ESSID:"\K[^"]+')
            bssid=$(echo "$wifi_info" | grep -oP 'Access Point: \K[\w:]+')
            freq=$(echo "$wifi_info" | grep -oP 'Frequency:\K[^ ]+')
            quality=$(echo "$wifi_info" | grep -oP 'Link Quality=\K[^ ]+')
            [[ -n "$ssid"    ]] && _kv "SSID"           "$ssid"
            [[ -n "$bssid"   ]] && _kv "BSSID (AP MAC)" "$bssid"
            [[ -n "$freq"    ]] && _kv "Frequency"      "$freq GHz"
            [[ -n "$quality" ]] && _kv "Signal quality" "$quality"
        fi
    elif command -v termux-wifi-connectioninfo &>/dev/null 2>&1; then
        _s "WiFi (Termux API)"
        termux-wifi-connectioninfo 2>/dev/null | while IFS= read -r l; do
            echo -e "  ${DIM}$l${NC}"
        done
    fi

    # Export for use by other modules
    LN_IFACE="$iface"
    LN_LOCAL_IP="$local_ip"
    LN_GATEWAY="$gateway"
    LN_CIDR="$cidr"

    # Derive the network range to scan
    if [[ -n "$local_ip" ]]; then
        local base; base=$(echo "$local_ip" | cut -d. -f1-3)
        LN_NETWORK="${base}.0/24"
    fi
}

# ── 2. Discover hosts on the local network ──────────────────────
localnet_discover() {
    _h "2 ▸ HOST DISCOVERY"

    [[ -n "${LN_NETWORK:-}" ]] || { _warn "Network not detected; a guessed range will not be scanned"; return 1; }
    local network="$LN_NETWORK"
    _info "Network to scan: $network"
    _warn "This may take 30-60 seconds..."
    echo ""

    local base; base=$(echo "$network" | cut -d. -f1-3)
    local tmpdir; tmpdir=$(mktemp -d) || return 1
    _TMPDIR_GLOBAL="$tmpdir"

    printf "  ${W}${BOLD}%-18s %-20s %-20s %s${NC}\n" "IP" "MAC" "VENDOR" "STATE"
    echo -e "  ${DIM}$(printf '─%.0s' {1..70})${NC}"

    # Method 1: nmap ping scan
    if command -v nmap &>/dev/null; then
        nmap -sn --min-rate 500 "$network" 2>/dev/null | \
        awk '/Nmap scan report/{ip=$NF} /MAC Address/{mac=$3; vendor=substr($0,index($0,$4)); print ip" "mac" "vendor}' | \
        while IFS=' ' read -r ip mac vendor; do
            ip="${ip//(\)/}"; ip="${ip//(/)}"
            printf "  ${G}%-18s${NC} %-20s %-20s ${G}%s${NC}\n" "$ip" "$mac" "$vendor" "ONLINE"
            echo "$ip" >> "${tmpdir}/hosts"
            LN_HOSTS+=("$ip")
        done
    else
        # Method 2: parallel ping sweep
        for i in $(seq 1 254); do
            (
                local host="${base}.${i}"
                if ping -c 1 -W 1 "$host" &>/dev/null; then
                    local mac
                    mac=$(arp -n "$host" 2>/dev/null | awk '{print $3}' | grep -E '^[0-9a-f:]{17}$' | head -1)
                    printf "  ${G}%-18s${NC} %-20s %-20s ${G}%s${NC}\n" "$host" "${mac:-N/A}" "" "ONLINE"
                    echo "$host" >> "${tmpdir}/hosts"
                fi
            ) &
        done
        wait
    fi

    # Read the hosts found
    if [[ -f "${tmpdir}/hosts" ]]; then
        mapfile -t LN_HOSTS < "${tmpdir}/hosts"
        echo ""
        _ok "${#LN_HOSTS[@]} host(s) found on $network"
    else
        echo ""
        _info "No hosts found (an ARP scan may require root)"
    fi

    rm -rf "$tmpdir"
    _TMPDIR_GLOBAL=""

    # ARP table complement
    _s "Local ARP table"
    arp -n 2>/dev/null | grep -v "incomplete\|Address" | while IFS= read -r l; do
        echo -e "  ${DIM}$l${NC}"
    done
}

# ── 3. Analysis of each host found ──────────────────────────────
localnet_analyze_host() {
    local ip="$1"
    echo ""
    echo -e "  ${Y}${BOLD}── Analyzing: $ip ──────────────────────────${NC}"

    # Quick administration ports
    local open=()
    for port in 21 22 23 80 443 445 3306 5900 8080 8443 8291 8333 9000 10000; do
        timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null && open+=("$port")
    done

    if [[ ${#open[@]} -gt 0 ]]; then
        _kvy "Open ports" "${open[*]}"
        for p in "${open[@]}"; do
            case $p in
                23)  _vuln "  Telnet (23) open — plain text" ; LN_FINDINGS+=("$ip: Telnet exposed"); ((LN_RISK+=15)) ;;
                445) _warn "  SMB (445) open — check for EternalBlue" ; LN_FINDINGS+=("$ip: SMB open") ;;
                5900) _warn "  VNC (5900) — check whether it requires a password" ; LN_FINDINGS+=("$ip: VNC open") ;;
                8291) _warn "  Winbox (8291) — MikroTik device" ; LN_FINDINGS+=("$ip: MikroTik Winbox") ;;
                3306) _warn "  MySQL (3306) — exposed database" ; LN_FINDINGS+=("$ip: MySQL exposed") ; ((LN_RISK+=10)) ;;
            esac
        done
    else
        _ok "  No exposed administration ports"
    fi

    # Identify the device type
    local dtype=""
    for port in 80 443 8080 8333; do
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            local body
            body=$(curl -sk --max-time 3 "http://${ip}:${port}" 2>/dev/null | head -50)
            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig"; then
                dtype="MikroTik RouterOS"
            elif echo "$body" | grep -qi "huawei"; then
                dtype="Huawei"
            elif echo "$body" | grep -qi "tplink\|tp-link"; then
                dtype="TP-Link"
            elif echo "$body" | grep -qi "asus"; then
                dtype="ASUS Router"
            elif echo "$body" | grep -qi "ubiquiti\|unifi"; then
                dtype="Ubiquiti"
            elif echo "$body" | grep -qi "dd-wrt\|openwrt\|tomato"; then
                dtype="Router with alternative firmware (DD-WRT/OpenWrt)"
            fi
            [[ -n "$dtype" ]] && break
        fi
    done

    # Hostname via PTR
    local hostname
    hostname=$(dig +short -x "$ip" 2>/dev/null | head -1)
    [[ -n "$hostname" ]] && _kv "  Hostname" "$hostname"
    [[ -n "$dtype"    ]] && _kvy "  Detected device" "$dtype"

    # Default credentials if there is a web panel
    if [[ -n "$dtype" ]] && [[ ${#open[@]} -gt 0 ]]; then
        _info "  Check default credentials: admin/(empty), admin/admin, admin/1234"
    fi
}

# ── 4. Router/gateway analysis ──────────────────────────────────
localnet_gateway_audit() {
    local gw="${LN_GATEWAY}"
    [[ -z "$gw" ]] && return

    _h "3 ▸ GATEWAY (ROUTER) AUDIT"
    _kv "Gateway" "$gw"

    # Ports
    _s "Ports exposed on the gateway"
    local open_gw=()
    for port in 21 22 23 53 80 443 1900 2000 5900 8080 8291 8333 8443 8728 8729 9000 10000; do
        timeout 1 bash -c "echo >/dev/tcp/$gw/$port" 2>/dev/null && {
            open_gw+=("$port")
            case $port in
                23)   _vuln "Port 23 (Telnet) OPEN on the gateway" ; LN_FINDINGS+=("Gateway: Telnet active") ; ((LN_RISK+=20)) ;;
                1900) _warn "Port 1900 (UPnP) — check whether it allows unauthorized port forwarding" ; LN_FINDINGS+=("Gateway: UPnP active") ;;
                8291) _warn "Port 8291 (Winbox) — the gateway is a MikroTik" ;;
                80)   _kvy "Port 80 (HTTP)" "Unencrypted web panel" ;;
                443)  _ok  "Port 443 (HTTPS) available" ;;
            esac
        }
    done

    [[ ${#open_gw[@]} -gt 0 ]] && _kvy "Open ports" "${open_gw[*]}"

    # Gateway web panel
    _s "Gateway fingerprinting"
    for port in 80 8080 443; do
        local proto="http"; [[ "$port" == "443" ]] && proto="https"
        if timeout 1 bash -c "echo >/dev/tcp/$gw/$port" 2>/dev/null; then
            local body hdr vendor_gw
            hdr=$(curl -skI --max-time 4 "${proto}://${gw}:${port}" 2>/dev/null)
            body=$(curl -skL --max-time 4 "${proto}://${gw}:${port}" 2>/dev/null | head -100)
            vendor_gw=$(echo "$hdr" | grep -i "server:" | cut -d: -f2- | xargs)
            [[ -n "$vendor_gw" ]] && _kvy "Web server" "$vendor_gw"

            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig"; then
                _kvy "Device" "MikroTik RouterOS"
                if ! echo "$body" | grep -qi "login\|password"; then
                    _vuln "Panel without a login screen — possible unauthenticated access"
                    LN_FINDINGS+=("Gateway MikroTik: panel without auth")
                    ((LN_RISK+=30))
                fi
            elif echo "$body" | grep -qi "huawei"; then
                _kvy "Device" "Huawei"
            elif echo "$body" | grep -qi "tp-link\|tplink"; then
                _kvy "Device" "TP-Link"
            elif echo "$body" | grep -qi "dd-wrt"; then
                _kvy "Firmware" "DD-WRT"
            elif echo "$body" | grep -qi "openwrt"; then
                _kvy "Firmware" "OpenWrt"
            fi
            break
        fi
    done

    # UPnP check
    _s "UPnP — Universal Plug and Play"
    if timeout 2 bash -c "echo >/dev/tcp/$gw/1900" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/udp/$gw/1900" 2>/dev/null; then
        _warn "UPnP active — lets devices on the network set up port forwarding automatically"
        _info "Malware on the network can open ports on the router via UPnP"
        LN_FINDINGS+=("Gateway: UPnP enabled — risk of unauthorized port forwarding")
        ((LN_RISK+=15))
    else
        _ok "UPnP not detected (good)"
    fi

    # DNS leak check
    _s "DNS leak — name resolution"
    local dns_server
    dns_server=$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' | head -1)
    _kv "Configured DNS" "${dns_server:-Not detected}"
    if [[ "$dns_server" == "$gw" ]]; then
        _info "The gateway acts as the DNS server (common on home networks)"
    fi
}

# ── 5. IoT/vulnerable device detection ──────────────────────────
localnet_iot_scan() {
    _h "4 ▸ IoT AND POTENTIALLY VULNERABLE DEVICES"

    if [[ ${#LN_HOSTS[@]} -eq 0 ]]; then
        _info "No hosts to analyze. Run the discovery first."
        return
    fi

    _s "Analyzing the hosts found"
    for host in "${LN_HOSTS[@]}"; do
        [[ "$host" == "$LN_LOCAL_IP" ]] && continue  # skip ourselves
        localnet_analyze_host "$host"
    done
}

# ── 6. WiFi network vulnerabilities ─────────────────────────────
localnet_wifi_vulns() {
    _h "5 ▸ WIFI NETWORK VULNERABILITIES"

    _s "WiFi security analysis"

    # Security protocol
    if command -v iwconfig &>/dev/null; then
        local security
        security=$(iwconfig "${LN_IFACE:-wlan0}" 2>/dev/null | grep -i "Encryption\|WPA\|WEP")
        if [[ -n "$security" ]]; then
            echo -e "  ${DIM}$security${NC}"
            if echo "$security" | grep -qi "WEP"; then
                _vuln "WEP detected — BROKEN protocol, crackable in minutes"
                LN_FINDINGS+=("WiFi: WEP protocol — CRITICAL")
                ((LN_RISK+=50))
            elif echo "$security" | grep -qi "WPA2\|WPA3"; then
                _ok "WPA2/WPA3 — secure protocol"
            elif echo "$security" | grep -qi 'WPA[^23]'; then
                _warn "WPA (v1) — vulnerable to TKIP attacks"
                LN_FINDINGS+=("WiFi: WPA v1 — vulnerable")
                ((LN_RISK+=20))
            fi
        fi
    fi

    # KRACK vulnerability check (WPA2 - conceptual)
    _s "Known WiFi attack vectors"
    echo -e "  ${DIM}Conceptual check (specialized tools are needed to confirm)${NC}"
    echo ""
    local vectors=(
        "KRACK (CVE-2017-13077)|WPA2 — key reinstallation|Update router and client firmware"
        "PMKID Attack|WPA2/WPA3 — hash capture without clients|Use a long, complex password (20+ chars)"
        "Deauth Attack (802.11)|Client disconnection|Enable 802.11w (Protected Management Frames)"
        "Evil Twin/Rogue AP|Fake AP with the same SSID|Check the BSSID before connecting"
        "WPS PIN Brute Force|If WPS is enabled|DISABLE WPS on the router"
        "Local DNS Spoofing|Poisoning if DNS = gateway|Use DNS over HTTPS (DoH)"
        "ARP Spoofing|Man-in-the-middle on the LAN|Use a VPN or switches with ARP inspection"
    )

    printf "  ${W}${BOLD}%-35s %-30s %s${NC}\n" "VECTOR" "MECHANISM" "MITIGATION"
    echo -e "  ${DIM}$(printf '─%.0s' {1..90})${NC}"
    for v in "${vectors[@]}"; do
        IFS='|' read -r name mech fix <<< "$v"
        printf "  ${Y}%-35s${NC} %-30s ${G}%s${NC}\n" "$name" "$mech" "$fix"
    done

    # WPS check
    _s "WPS — Wi-Fi Protected Setup"
    if command -v wash &>/dev/null; then
        _info "wash available — run: wash -i ${LN_IFACE:-wlan0} to detect APs with WPS"
    else
        _info "To check WPS: install aircrack-ng (Kali/NetHunter)"
        _info "  apt install aircrack-ng  or  pkg install aircrack-ng (Termux)"
    fi
}

# ── 7. Local network recommendations ────────────────────────────
localnet_mitigations() {
    _h "6 ▸ LOCAL NETWORK MITIGATIONS"
    echo ""

    local items=(
        "Change the router password|Open 192.168.1.1 → change admin/(empty)|CRITICAL"
        "Disable WPS on the router|Admin panel → WiFi → disable WPS|HIGH"
        "Use WPA3 or WPA2 with AES|Do not use WEP or WPA(v1)|HIGH"
        "Long WiFi password (20+ chars)|Mix upper case, numbers, symbols|HIGH"
        "Update the router firmware|Admin panel → System → Firmware Update|CRITICAL"
        "Disable admin access over WiFi|Allow admin only over Ethernet|MEDIUM"
        "Disable UPnP|Admin panel → Advanced → UPnP → Off|MEDIUM"
        "Segment with a VLAN or guest network|IoT on a network separate from main devices|MEDIUM"
        "Enable 802.11w (PMF)|Protects against deauthentication attacks|MEDIUM"
        "Use encrypted DNS (DoH/DoT)|Set 1.1.1.1 or 8.8.8.8 with TLS|LOW"
        "Disable Telnet/FTP on devices|Use SSH only|HIGH"
        "Monitor the ARP table regularly|arp -n — detect spoofing|LOW"
    )

    printf "  ${W}${BOLD}%-45s %-35s %s${NC}\n" "ACTION" "HOW" "PRIORITY"
    echo -e "  ${DIM}$(printf '─%.0s' {1..90})${NC}"
    for item in "${items[@]}"; do
        IFS='|' read -r action how priority <<< "$item"
        local col="${G}"
        [[ "$priority" == "CRITICAL" ]] && col="${R}"
        [[ "$priority" == "HIGH"     ]] && col="${Y}"
        [[ "$priority" == "MEDIUM"   ]] && col="${C}"
        printf "  %-45s %-35s ${col}%s${NC}\n" "$action" "$how" "$priority"
    done
}

# ── 8. Summary and score ────────────────────────────────────────
localnet_summary() {
    _h "✦  SUMMARY — LOCAL NETWORK AUDIT"
    echo ""

    _kv "Scanned network"  "${LN_NETWORK:-N/A}"
    _kv "Gateway"         "${LN_GATEWAY:-N/A}"
    _kv "Local IP"        "${LN_LOCAL_IP:-N/A}"
    _kv "Hosts found"     "${#LN_HOSTS[@]}"
    _kv "Findings"        "${#LN_FINDINGS[@]}"
    echo ""

    [[ $LN_RISK -gt 100 ]] && LN_RISK=100
    local label color
    if   [[ $LN_RISK -ge 75 ]]; then label="CRITICAL"; color="${R}"
    elif [[ $LN_RISK -ge 50 ]]; then label="HIGH";     color="${Y}"
    elif [[ $LN_RISK -ge 25 ]]; then label="MEDIUM";   color="${C}"
    else                              label="LOW";      color="${G}"
    fi

    local bar=$(( LN_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Risk score:${NC} ${color}${BOLD}${LN_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0;i<bar;i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar;i<40;i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"; echo ""

    if [[ ${#LN_FINDINGS[@]} -gt 0 ]]; then
        _s "Findings"
        for f in "${LN_FINDINGS[@]}"; do
            local sev="${f%%:*}"; local col="${C}"
            echo "$f" | grep -qi "CRITICAL\|Telnet\|without auth\|WEP" && col="${R}"
            echo "$f" | grep -qi "UPnP\|SMB\|MySQL\|VNC" && col="${Y}"
            echo -e "  ${col}▸${NC} $f"
        done
    fi

    # Save log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local lf="${log_dir}/localnet_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "LocalNet Audit v3.2.0 — @kevxngg (Kevin)"
        echo "Network: ${LN_NETWORK:-N/A} | Gateway: ${LN_GATEWAY:-N/A} | Hosts: ${#LN_HOSTS[@]}"
        echo "Risk: ${LN_RISK}/100 — $label | Date: $(date)"
        echo ""; echo "FINDINGS:"
        for f in "${LN_FINDINGS[@]}"; do echo "  - $f"; done
    } > "$lf"
    echo -e "  ${DIM}Log: ${W}${lf}${NC}"
}

# ── MAIN ────────────────────────────────────────────────────────
run_localnet_audit() {
    LN_RISK=0; LN_FINDINGS=(); LN_HOSTS=()
    LN_IFACE=""; LN_LOCAL_IP=""; LN_GATEWAY=""; LN_CIDR=""; LN_NETWORK=""

    localnet_iface_info
    localnet_discover
    localnet_gateway_audit
    localnet_iot_scan
    localnet_wifi_vulns
    localnet_mitigations
    localnet_summary
}
