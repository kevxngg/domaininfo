#!/usr/bin/env bash
# ================================================================
#  isp_audit.sh — ISP / Network Device Auditor
#  Detects the company, equipment and vulnerabilities of any public IP
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

ISP_RISK=0
ISP_FINDINGS=()

isp_add_finding() { ISP_FINDINGS+=("$1"); }

# ── 1. Company and ISP identification ───────────────────────────
isp_identify() {
    local ip="$1"
    _h "1 ▸ PROVIDER IDENTIFICATION"

    _s "Querying geolocation databases"
    local data1 data2 data3

    # ipinfo.io
    data1=$(curl -s --max-time 8 "https://ipinfo.io/${ip}/json" 2>/dev/null)
    # ip-api.com
    data2=$(curl -s --max-time 8 "http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,asname,query,proxy,hosting,mobile" 2>/dev/null)
    # Shodan InternetDB (no API key)
    data3=$(curl -s --max-time 8 "https://internetdb.shodan.io/${ip}" 2>/dev/null)

    # Extract data
    local org isp asn country city lat lon hostname
    org=$(echo "$data1" | grep -o '"org": *"[^"]*"' | cut -d'"' -f4)
    hostname=$(echo "$data1" | grep -o '"hostname": *"[^"]*"' | cut -d'"' -f4)
    country=$(echo "$data2" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
    city=$(echo "$data2" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
    isp=$(echo "$data2" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
    asn=$(echo "$data2" | grep -o '"as":"[^"]*"' | cut -d'"' -f4)
    lat=$(echo "$data2" | grep -o '"lat":[^,}]*' | cut -d: -f2)
    lon=$(echo "$data2" | grep -o '"lon":[^,}]*' | cut -d: -f2)
    local is_hosting is_proxy
    is_hosting=$(echo "$data2" | grep -o '"hosting":[^,}]*' | cut -d: -f2)
    is_proxy=$(echo "$data2" | grep -o '"proxy":[^,}]*' | cut -d: -f2)

    _kv  "Analyzed IP"         "$ip"
    [[ -n "$org"      ]] && _kv  "Organization"        "$org"
    [[ -n "$isp"      ]] && _kv  "ISP / Provider"      "$isp"
    [[ -n "$asn"      ]] && _kv  "ASN"                 "$asn"
    [[ -n "$country"  ]] && _kv  "Country"             "$country"
    [[ -n "$city"     ]] && _kv  "City"                "$city"
    [[ -n "$lat"      ]] && _kv  "Coordinates"         "${lat}, ${lon}"
    [[ -n "$hostname" ]] && _kv  "Hostname"            "$hostname"
    [[ "$is_hosting" == "true" ]] && _kvy "Type"       "Datacenter / Hosting"
    [[ "$is_proxy"   == "true" ]] && _kvy "Proxy/VPN"  "Detected"

    # Ports and CPEs from Shodan InternetDB
    _s "Shodan InternetDB data (no API key)"
    local shodan_ports shodan_vulns shodan_cpes
    shodan_ports=$(echo "$data3" | grep -o '"open_ports":\[[^]]*\]' | grep -oE '[0-9]+' | tr '\n' ', ')
    shodan_vulns=$(echo "$data3" | grep -o '"vulns":\[[^]]*\]' | grep -oE 'CVE-[^"]+' | head -10)
    shodan_cpes=$(echo "$data3" | grep -o '"cpes":\[[^]]*\]' | grep -oE 'cpe:[^"]+' | head -5)

    if [[ -n "$shodan_ports" ]]; then
        _kvy "Ports seen on Shodan" "${shodan_ports%, }"
    else
        _info "No previous data in Shodan InternetDB"
    fi

    if [[ -n "$shodan_vulns" ]]; then
        while IFS= read -r cve; do
            [[ -n "$cve" ]] && _vuln "Known CVE: $cve"
            isp_add_finding "CRITICAL: $cve detected on Shodan"
            ((ISP_RISK+=15))
        done <<< "$shodan_vulns"
    fi

    if [[ -n "$shodan_cpes" ]]; then
        _s "CPEs (equipment identified by Shodan)"
        while IFS= read -r cpe; do
            [[ -n "$cpe" ]] && _kvy "Equipment" "$cpe"
        done <<< "$shodan_cpes"
    fi

    # WHOIS for more company info
    _s "WHOIS — IP block information"
    local whois_data
    whois_data=$(whois "$ip" 2>/dev/null | head -40)
    local netname netrange descr abuse
    netname=$(echo "$whois_data" | grep -i "^netname:\|^NetName:" | head -1 | awk -F: '{print $2}' | xargs)
    netrange=$(echo "$whois_data" | grep -i "^inetnum:\|^NetRange:" | head -1 | awk -F: '{print $2}' | xargs)
    descr=$(echo "$whois_data" | grep -i "^descr:\|^OrgName:" | head -1 | awk -F: '{print $2}' | xargs)
    abuse=$(echo "$whois_data" | grep -i "abuse\|OrgAbuseEmail" | grep "@" | head -1 | awk '{print $NF}')

    [[ -n "$netname"  ]] && _kv "Network name (WHOIS)"  "$netname"
    [[ -n "$netrange" ]] && _kv "Assigned IP range"     "$netrange"
    [[ -n "$descr"    ]] && _kv "Description"           "$descr"
    [[ -n "$abuse"    ]] && _kv "Abuse email"           "$abuse"

    ISP_ORG="${isp:-${org:-$netname}}"
    ISP_COUNTRY="$country"
    ISP_CITY="$city"
}

# ── 2. Equipment and vendor detection ───────────────────────────
isp_device_detect() {
    local ip="$1"
    _h "2 ▸ EQUIPMENT AND VENDOR DETECTION"

    local device_vendor="" device_model="" device_os=""

    # Banner grabbing on common ports
    _s "Banner grabbing (HTTP, SSH, Telnet, FTP)"

    # HTTP banner
    for port in 80 8080 8333 8443 443; do
        if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            local proto="http"; [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
            local banner
            banner=$(curl -skI --max-time 5 "${proto}://${ip}:${port}" 2>/dev/null | head -15)
            local server
            server=$(echo "$banner" | grep -i "^server:" | cut -d: -f2- | xargs)
            if [[ -n "$server" ]]; then
                _kv "HTTP server:${port}" "$server"
                # Detect vendor from the Server header
                if echo "$server" | grep -qi "mikrotik\|routeros"; then
                    device_vendor="MikroTik"; device_os="RouterOS"
                    local ver; ver=$(echo "$server" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
                    [[ -n "$ver" ]] && device_model="RouterOS $ver"
                elif echo "$server" | grep -qi "cisco"; then
                    device_vendor="Cisco"
                elif echo "$server" | grep -qi "huawei"; then
                    device_vendor="Huawei"
                elif echo "$server" | grep -qi "ubiquiti\|unifi"; then
                    device_vendor="Ubiquiti"
                elif echo "$server" | grep -qi "tplink\|tp-link"; then
                    device_vendor="TP-Link"
                elif echo "$server" | grep -qi "zyxel"; then
                    device_vendor="ZyXEL"
                elif echo "$server" | grep -qi "juniper"; then
                    device_vendor="Juniper"
                fi
            fi
            # Body fingerprint
            local body
            body=$(curl -skL --max-time 5 "${proto}://${ip}:${port}" 2>/dev/null | head -100)
            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig\|winbox"; then
                device_vendor="MikroTik"; device_os="RouterOS"
            elif echo "$body" | grep -qi "cisco ios\|cisco systems"; then
                device_vendor="Cisco"
            elif echo "$body" | grep -qi "huawei.*router\|hg8\|ont\|onu"; then
                device_vendor="Huawei"; device_model="Possible ONT/ONU/HG"
            elif echo "$body" | grep -qi "ubiquiti\|airmax\|airfiber"; then
                device_vendor="Ubiquiti"
            elif echo "$body" | grep -qi "tenda\|tendacn"; then
                device_vendor="Tenda"
            fi
        fi
    done

    # SSH banner
    if timeout 2 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
        local ssh_banner
        ssh_banner=$(timeout 3 bash -c "echo '' | nc -w 2 $ip 22 2>/dev/null" 2>/dev/null | head -2)
        if [[ -n "$ssh_banner" ]]; then
            _kv "SSH Banner" "$ssh_banner"
            if echo "$ssh_banner" | grep -qi "routeros\|mikrotik"; then
                device_vendor="MikroTik"; device_os="RouterOS"
                local ver; ver=$(echo "$ssh_banner" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
                [[ -n "$ver" ]] && device_model="RouterOS $ver"
            elif echo "$ssh_banner" | grep -qi "cisco"; then
                device_vendor="Cisco"; device_os="IOS"
            elif echo "$ssh_banner" | grep -qi "junos"; then
                device_vendor="Juniper"; device_os="JunOS"
            elif echo "$ssh_banner" | grep -qi "dropbear"; then
                device_vendor="Unknown"; device_os="Linux/Dropbear"
            elif echo "$ssh_banner" | grep -qi "huawei\|vrp"; then
                device_vendor="Huawei"; device_os="VRP"
            fi
        fi
    fi

    # Telnet banner
    if timeout 2 bash -c "echo >/dev/tcp/$ip/23" 2>/dev/null; then
        local tel_banner
        tel_banner=$(timeout 3 bash -c "(echo; sleep 1) | nc -w 3 $ip 23 2>/dev/null" 2>/dev/null | strings | head -5)
        if [[ -n "$tel_banner" ]]; then
            _kv "Telnet Banner" "$(echo "$tel_banner" | head -2)"
            echo "$tel_banner" | grep -qi "mikrotik\|routeros" && device_vendor="MikroTik"
            echo "$tel_banner" | grep -qi "cisco"              && device_vendor="Cisco"
            echo "$tel_banner" | grep -qi "huawei"             && device_vendor="Huawei"
            echo "$tel_banner" | grep -qi "zyxel"              && device_vendor="ZyXEL"
        fi
    fi

    # SNMP community string 'public' check (UDP 161) — if snmpwalk is available
    if command -v snmpwalk &>/dev/null; then
        _s "SNMP — sysDescr (UDP 161)"
        local snmp_desc
        snmp_desc=$(timeout 5 snmpwalk -v2c -c public -t 3 "$ip" sysDescr 2>/dev/null | head -3)
        if [[ -n "$snmp_desc" ]]; then
            _vuln "SNMP community 'public' accepted — exposes system information"
            echo "$snmp_desc" | while IFS= read -r l; do _kvy "SNMP sysDescr" "$l"; done
            isp_add_finding "CRITICAL: SNMP with community 'public' reachable (info leak)"
            ((ISP_RISK+=25))
            # Extract equipment info
            echo "$snmp_desc" | grep -qi "mikrotik\|routeros" && device_vendor="MikroTik"
            echo "$snmp_desc" | grep -qi "cisco"              && device_vendor="Cisco"
            echo "$snmp_desc" | grep -qi "huawei"             && device_vendor="Huawei"
            echo "$snmp_desc" | grep -qi "juniper\|junos"     && device_vendor="Juniper"
            local extracted_model
            extracted_model=$(echo "$snmp_desc" | grep -oE 'RouterOS [0-9.]+|IOS [0-9.]+|VRP [^,]+' | head -1)
            [[ -n "$extracted_model" ]] && device_model="$extracted_model"
        else
            _ok "SNMP community 'public' not reachable (good)"
        fi
    fi

    # Detection result
    _s "Fingerprinting result"
    if [[ -n "$device_vendor" ]]; then
        _kvy "Detected vendor" "$device_vendor"
        [[ -n "$device_model" ]] && _kvy "Model/Version" "$device_model"
        [[ -n "$device_os"    ]] && _kvy "Operating system" "$device_os"
        ISP_DEVICE="$device_vendor ${device_model}"
    else
        _info "Vendor not identified from banner analysis"
        _info "Try nmap -sV for deeper fingerprinting"
        ISP_DEVICE="Unknown"
    fi
}

# ── 3. Port scan with access analysis ────────────────────────────
isp_ports() {
    local ip="$1"
    _h "3 ▸ PORTS — ACCESS AND RISK ANALYSIS"

    # Map of critical ports for network/ISP equipment
    declare -A PORT_INFO=(
        [21]="FTP — file transfer (insecure)"
        [22]="SSH — remote administration"
        [23]="Telnet — plain-text admin (DANGEROUS)"
        [25]="SMTP — mail server"
        [53]="DNS — name server"
        [69]="TFTP — transfer without auth"
        [80]="HTTP — unencrypted web panel"
        [161]="SNMP UDP — network management (possibly exposed)"
        [443]="HTTPS — encrypted web panel"
        [445]="SMB — Windows file shares"
        [554]="RTSP — media streaming"
        [1723]="PPTP VPN — VPN protocol (insecure)"
        [2000]="Bandwidth Test (MikroTik)"
        [2601]="Zebra/Quagga — routing daemon"
        [3128]="HTTP proxy (Squid)"
        [3306]="MySQL — database"
        [4899]="Radmin — remote control"
        [5900]="VNC — remote desktop"
        [6881]="BitTorrent"
        [7547]="TR-069 — CPE management (CWMP)"
        [8080]="Alternative HTTP"
        [8081]="Alternative HTTP 2"
        [8291]="Winbox (MikroTik)"
        [8333]="WebFig (MikroTik)"
        [8443]="Alternative HTTPS"
        [8728]="MikroTik API without TLS"
        [8729]="MikroTik API with TLS"
        [8888]="Generic admin panel"
        [9000]="Alternative admin panel"
        [9090]="Web panel / Prometheus"
        [10000]="Webmin — admin panel"
    )

    declare -A PORT_RISK=(
        [21]=20 [23]=35 [69]=25 [161]=25 [445]=20
        [1723]=15 [2000]=5 [4899]=30 [5900]=25
        [7547]=30 [8291]=20 [8728]=25 [10000]=20
    )

    local open_ports=()
    _s "Scanning administration and risky ports"
    echo ""
    printf "  ${W}${BOLD}%-8s %-35s %-12s %s${NC}\n" "PORT" "SERVICE" "STATE" "RISK"
    echo -e "  ${DIM}$(printf '─%.0s' {1..70})${NC}"

    for port in 21 22 23 25 53 69 80 161 443 445 554 1723 2000 2601 3128 3306 4899 5900 7547 8080 8081 8291 8333 8443 8728 8729 8888 9000 9090 10000; do
        local service="${PORT_INFO[$port]:-Unknown service}"
        local risk_add="${PORT_RISK[$port]:-0}"
        local state

        if timeout 2 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            state="OPEN"
            open_ports+=("$port")

            # Determine the risk level per port
            local risk_level color_risk
            case $port in
                23|69|4899)      risk_level="CRITICAL"; color_risk="${R}" ;;
                21|161|5900|7547|8291|8728) risk_level="HIGH"; color_risk="${Y}" ;;
                22|80|3306|10000) risk_level="MEDIUM"; color_risk="${C}" ;;
                *)               risk_level="INFO";   color_risk="${G}" ;;
            esac

            printf "  ${G}%-8s${NC} %-35s ${color_risk}%-12s %s${NC}\n" \
                   "$port" "$service" "$state" "$risk_level"

            ((ISP_RISK+=risk_add))
            [[ "$risk_level" == "CRITICAL" || "$risk_level" == "HIGH" ]] && \
                isp_add_finding "${risk_level}: Port $port open — $service"

            # Port-specific access test
            case $port in
                23)
                    _warn "   → Telnet active: plain-text credentials. Try: telnet $ip 23"
                    ;;
                7547)
                    _warn "   → TR-069/CWMP: CPE remote management protocol. Vectors: CVE-2017-14462"
                    isp_add_finding "CRITICAL: TR-069 exposed — mass attack vector (CVE-2017-14462)"
                    ((ISP_RISK+=20))
                    ;;
                8291)
                    _warn "   → Winbox reachable: this does not confirm a CVE"
                    _info "   Current RouterOS audit: python3 domaininfo.py -m mikrotik $ip"
                    ;;
                161)
                    _warn "   → SNMP UDP: check for default community strings"
                    ;;
                5900)
                    _warn "   → VNC: check whether it requires a password"
                    ;;
            esac
        else
            printf "  ${DIM}%-8s %-35s %-12s %s${NC}\n" "$port" "$service" "closed" ""
        fi
    done

    echo ""
    if [[ ${#open_ports[@]} -gt 0 ]]; then
        _kvy "Total open ports" "${#open_ports[@]}: ${open_ports[*]}"
    else
        _ok "No exposed administration ports found"
    fi

    # Deeper nmap scan if available
    if command -v nmap &>/dev/null && [[ ${#open_ports[@]} -gt 0 ]]; then
        _s "Nmap — version detection on open ports"
        local port_list; port_list=$(IFS=,; echo "${open_ports[*]}")
        nmap -sV --version-intensity 5 -p "$port_list" --open "$ip" 2>/dev/null \
            | grep -E "^[0-9]+|open|VERSION" \
            | while IFS= read -r l; do echo -e "  ${DIM}$l${NC}"; done
    fi

    ISP_OPEN_PORTS="${open_ports[*]}"
}

# ── 4. Firewall detection ────────────────────────────────────────
isp_firewall() {
    local ip="$1"
    _h "4 ▸ FIREWALL DETECTION"

    _s "Port behavior analysis"
    local fw_type="Unknown"
    local filtered_count=0 closed_count=0

    # Probe ports that are typically filtered vs closed
    local test_ports=(135 139 256 666 1025 1026 1900 4444 6667 12345)
    for port in "${test_ports[@]}"; do
        local result
        # ICMP unreachable = closed. No response = filtered (firewall)
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            : # open
        else
            # Try to tell RST apart from a timeout
            local nc_result
            nc_result=$(timeout 1 nc -z -w 1 "$ip" "$port" 2>&1)
            if echo "$nc_result" | grep -qi "refused"; then
                ((closed_count++))
            else
                ((filtered_count++))
            fi
        fi
    done

    if [[ $filtered_count -gt 5 ]]; then
        fw_type="Active firewall (most ports filtered/no response)"
        _ok "Firewall detected — silent port blocking"
    elif [[ $closed_count -gt 5 ]]; then
        fw_type="No apparent firewall or an RST policy (closed ports)"
        _warn "Possibly no firewall — ports answer with RST"
        isp_add_finding "MEDIUM: No-firewall behavior detected (RST on ports)"
        ((ISP_RISK+=10))
    else
        fw_type="Mixed — partial firewall or varied policies"
        _info "Mixed behavior — some ports filtered, others closed"
    fi

    _kvy "Inferred firewall type" "$fw_type"

    # WAF if it serves web
    if timeout 2 bash -c "echo >/dev/tcp/$ip/80" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/tcp/$ip/443" 2>/dev/null; then
        _s "Web WAF detection"
        local waf_headers
        for port in 80 443 8080 8333; do
            local proto="http"; [[ "$port" == "443" ]] && proto="https"
            waf_headers=$(curl -skI --max-time 5 "${proto}://${ip}:${port}" 2>/dev/null)
            if [[ -n "$waf_headers" ]]; then
                if echo "$waf_headers" | grep -qi "cloudflare\|cf-ray"; then
                    _kv "WAF/CDN" "Cloudflare"
                elif echo "$waf_headers" | grep -qi "x-sucuri\|sucuri"; then
                    _kv "WAF" "Sucuri"
                elif echo "$waf_headers" | grep -qi "x-akamai\|akamaighost"; then
                    _kv "WAF/CDN" "Akamai"
                elif echo "$waf_headers" | grep -qi "imperva\|incapsula"; then
                    _kv "WAF" "Imperva/Incapsula"
                else
                    _info "Web WAF not identified on port $port"
                fi
                break
            fi
        done
    fi

    # TTL-based OS detection
    _s "OS detection by TTL (ping)"
    local ttl
    ttl=$(ping -c 1 -W 2 "$ip" 2>/dev/null | grep -oE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
    if [[ -n "$ttl" ]]; then
        _kv "Received TTL" "$ttl"
        if   [[ $ttl -le 64  ]]; then _kv "Estimated OS" "Linux / Unix / Android / Networking OS"
        elif [[ $ttl -le 128 ]]; then _kv "Estimated OS" "Windows"
        elif [[ $ttl -le 255 ]]; then _kv "Estimated OS" "Cisco IOS / Solaris / others"
        fi
    else
        _info "ICMP blocked — cannot determine TTL"
    fi

    ISP_FIREWALL="$fw_type"
}

# ── 5. Known vulnerabilities ─────────────────────────────────────
isp_vulns() {
    local ip="$1"
    _h "5 ▸ KNOWN VULNERABILITIES"

    _s "Checking common vectors"

    # TR-069 / CWMP (port 7547) — massive ISP attack vector
    if timeout 2 bash -c "echo >/dev/tcp/$ip/7547" 2>/dev/null; then
        _vuln "TR-069 (CWMP) exposed on port 7547"
        _vuln "  CVE-2017-14462: Code execution on modems with TR-069"
        _vuln "  CVE-2016-10372: RCE on TalkTalk/Deutsche Telekom devices"
        _info "  Millions of routers hit by Mirai/Hajime via TR-069"
        isp_add_finding "CRITICAL: TR-069 exposed — botnet vector (CVE-2017-14462)"
        ((ISP_RISK+=30))
    else
        _ok "TR-069 (port 7547) not reachable from outside"
    fi

    # Check whether the WebFig/HTTP panel allows access without login
    for port in 80 8080 8333; do
        if timeout 2 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            local body
            body=$(curl -sk --max-time 5 "http://${ip}:${port}" 2>/dev/null)
            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig"; then
                if ! echo "$body" | grep -qi "login\|password\|username"; then
                    _vuln "Administration panel without a login screen detected (port $port)"
                    isp_add_finding "CRITICAL: Admin panel reachable without authentication on port $port"
                    ((ISP_RISK+=35))
                else
                    _med "Admin panel with login on port $port — check for default credentials"
                    isp_add_finding "MEDIUM: Admin panel with login — try admin/(empty), admin/admin"
                    ((ISP_RISK+=10))
                fi
            fi
        fi
    done

    # Open recursive DNS
    if timeout 2 bash -c "echo >/dev/tcp/$ip/53" 2>/dev/null || \
       dig @"$ip" google.com A +time=3 +tries=1 &>/dev/null; then
        local dns_test
        dns_test=$(dig @"$ip" google.com A +short +time=3 +tries=1 2>/dev/null)
        if [[ -n "$dns_test" ]]; then
            _vuln "Open recursive DNS — answers third-party queries"
            _info "  Can be abused for DNS amplification attacks (DDoS)"
            isp_add_finding "HIGH: Open recursive DNS — DDoS amplification vector"
            ((ISP_RISK+=20))
        else
            _ok "DNS is not recursive or does not answer external queries"
        fi
    fi

    # Open proxy
    if timeout 2 bash -c "echo >/dev/tcp/$ip/3128" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/tcp/$ip/8080" 2>/dev/null; then
        local proxy_test
        for pport in 3128 8080 8081; do
            proxy_test=$(curl -sk --max-time 5 --proxy "http://${ip}:${pport}" \
                         "http://httpbin.org/ip" 2>/dev/null | grep -o '"origin":[^"]*"[^"]*"' | head -1)
            if [[ -n "$proxy_test" ]]; then
                _vuln "Open HTTP proxy on port $pport — allows anonymizing traffic"
                isp_add_finding "HIGH: Open proxy on port $pport"
                ((ISP_RISK+=20))
                break
            fi
        done
    fi

    # NTP amplification
    if timeout 2 bash -c "echo >/dev/udp/$ip/123" 2>/dev/null; then
        _warn "NTP port (123/UDP) may be active — check for amplification"
        _info "  If it answers monlist: amplified DDoS vector"
    fi
}

# ── 6. Mitigation recommendations ───────────────────────────────
isp_mitigations() {
    local ip="$1"
    _h "6 ▸ MITIGATION RECOMMENDATIONS"
    echo ""

    echo -e "  ${W}${BOLD}For the provider's network team:${NC}\n"

    local mitigations=(
        "Disable Telnet|/ip service disable telnet (RouterOS)|CRITICAL"
        "Disable TR-069/CWMP if not actively used|Configure an ACL or disable it in firmware|CRITICAL"
        "Change default credentials|Strong password on every admin service|CRITICAL"
        "Block WebFig/Winbox from the WAN|Firewall: allow only known admin IPs|HIGH"
        "Disable the SNMP community 'public'|Use SNMPv3 with auth or disable SNMP|HIGH"
        "Close recursive DNS to third parties|Restrict DNS queries to own customers|HIGH"
        "Disable FTP if not used|/ip service disable ftp (RouterOS)|HIGH"
        "Update firmware/RouterOS|Always keep the latest stable version|CRITICAL"
        "Deploy fail2ban or brute-force protection|Limit login attempts per IP|MEDIUM"
        "Use a VPN for administrative access|Do not expose admin panels to the Internet|HIGH"
        "Segment the management network|Separate VLAN for administration|MEDIUM"
        "Deploy centralized logging|SIEM or external syslog for auditing|MEDIUM"
    )

    printf "  ${W}${BOLD}%-50s %-35s %s${NC}\n" "MITIGATION" "HOW" "PRIORITY"
    echo -e "  ${DIM}$(printf '─%.0s' {1..95})${NC}"
    for item in "${mitigations[@]}"; do
        IFS='|' read -r action how priority <<< "$item"
        local col="${G}"
        [[ "$priority" == "CRITICAL" ]] && col="${R}"
        [[ "$priority" == "HIGH"     ]] && col="${Y}"
        [[ "$priority" == "MEDIUM"   ]] && col="${C}"
        printf "  %-50s %-35s ${col}%s${NC}\n" "$action" "$how" "$priority"
    done
}

# ── 7. Score and summary ─────────────────────────────────────────
isp_summary() {
    local ip="$1"
    _h "✦  EXECUTIVE SUMMARY — ISP AUDIT"
    echo ""

    _kv "Audited IP"     "$ip"
    _kv "ISP/Company"    "${ISP_ORG:-N/A}"
    _kv "Location"       "${ISP_CITY:-N/A}, ${ISP_COUNTRY:-N/A}"
    _kv "Equipment"      "${ISP_DEVICE:-Unknown}"
    _kv "Firewall"       "${ISP_FIREWALL:-Not determined}"
    _kv "Open ports"     "${ISP_OPEN_PORTS:-None}"
    echo ""

    # Cap the maximum risk at 100
    [[ $ISP_RISK -gt 100 ]] && ISP_RISK=100
    local label color bar_len
    if   [[ $ISP_RISK -ge 75 ]]; then label="CRITICAL"; color="${R}"
    elif [[ $ISP_RISK -ge 50 ]]; then label="HIGH";     color="${Y}"
    elif [[ $ISP_RISK -ge 25 ]]; then label="MEDIUM";   color="${C}"
    else                              label="LOW";      color="${G}"
    fi

    bar_len=$(( ISP_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Risk score:${NC} ${color}${BOLD}${ISP_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0; i<bar_len; i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar_len; i<40; i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"
    echo ""

    if [[ ${#ISP_FINDINGS[@]} -gt 0 ]]; then
        _s "Identified findings (${#ISP_FINDINGS[@]})"
        for f in "${ISP_FINDINGS[@]}"; do
            local sev="${f%%:*}" msg="${f#*: }"
            local fc="${G}"
            [[ "$sev" == "CRITICAL" ]] && fc="${R}"
            [[ "$sev" == "HIGH"     ]] && fc="${Y}"
            [[ "$sev" == "MEDIUM"   ]] && fc="${C}"
            echo -e "  ${fc}[${sev}]${NC} $msg"
        done
    fi

    # Save log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local lf="${log_dir}/isp_audit_${ip//[^0-9]/_}_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "ISP Audit v3.2.0 — @kevxngg (Kevin)"
        echo "IP: $ip | ISP: ${ISP_ORG:-N/A} | Equipment: ${ISP_DEVICE:-N/A}"
        echo "Risk: ${ISP_RISK}/100 — $label | Date: $(date)"
        echo ""; echo "FINDINGS:"
        for f in "${ISP_FINDINGS[@]}"; do echo "  - $f"; done
    } > "$lf"
    echo -e "\n  ${DIM}Log: ${W}${lf}${NC}"
}

# ── Module MAIN ──────────────────────────────────────────────────
run_isp_audit() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}Usage: ISP option from the main menu${NC}"
        return 1
    fi

    ISP_RISK=0; ISP_FINDINGS=()
    ISP_ORG=""; ISP_COUNTRY=""; ISP_CITY=""
    ISP_DEVICE=""; ISP_FIREWALL=""; ISP_OPEN_PORTS=""

    isp_identify "$ip"
    isp_device_detect "$ip"
    isp_ports "$ip"
    isp_firewall "$ip"
    isp_vulns "$ip"
    isp_mitigations "$ip"
    isp_summary "$ip"
}
