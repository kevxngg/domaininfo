#!/usr/bin/env bash
# ================================================================
#  isp_audit.sh — ISP / Network Device Auditor
#  Detecta empresa, equipo, vulnerabilidades de cualquier IP pública
#  Autor: @kevxngg (Kevin)
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

# ── 1. Identificación de empresa e ISP ──────────────────────────
isp_identify() {
    local ip="$1"
    _h "1 ▸ IDENTIFICACIÓN DEL PROVEEDOR"

    _s "Consulta a bases de datos de geolocalización"
    local data1 data2 data3

    # ipinfo.io
    data1=$(curl -s --max-time 8 "https://ipinfo.io/${ip}/json" 2>/dev/null)
    # ip-api.com
    data2=$(curl -s --max-time 8 "http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,asname,query,proxy,hosting,mobile" 2>/dev/null)
    # Shodan InternetDB (sin API key)
    data3=$(curl -s --max-time 8 "https://internetdb.shodan.io/${ip}" 2>/dev/null)

    # Extraer datos
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

    _kv  "IP Analizada"        "$ip"
    [[ -n "$org"      ]] && _kv  "Organización"        "$org"
    [[ -n "$isp"      ]] && _kv  "ISP / Proveedor"     "$isp"
    [[ -n "$asn"      ]] && _kv  "ASN"                 "$asn"
    [[ -n "$country"  ]] && _kv  "País"                "$country"
    [[ -n "$city"     ]] && _kv  "Ciudad"              "$city"
    [[ -n "$lat"      ]] && _kv  "Coordenadas"         "${lat}, ${lon}"
    [[ -n "$hostname" ]] && _kv  "Hostname"            "$hostname"
    [[ "$is_hosting" == "true" ]] && _kvy "Tipo"       "Datacenter / Hosting"
    [[ "$is_proxy"   == "true" ]] && _kvy "Proxy/VPN"  "Detectado"

    # Puertos y CPEs desde Shodan InternetDB
    _s "Datos Shodan InternetDB (sin API key)"
    local shodan_ports shodan_vulns shodan_cpes
    shodan_ports=$(echo "$data3" | grep -o '"open_ports":\[[^]]*\]' | grep -oE '[0-9]+' | tr '\n' ', ')
    shodan_vulns=$(echo "$data3" | grep -o '"vulns":\[[^]]*\]' | grep -oE 'CVE-[^"]+' | head -10)
    shodan_cpes=$(echo "$data3" | grep -o '"cpes":\[[^]]*\]' | grep -oE 'cpe:[^"]+' | head -5)

    if [[ -n "$shodan_ports" ]]; then
        _kvy "Puertos vistos en Shodan" "${shodan_ports%, }"
    else
        _info "No hay datos previos en Shodan InternetDB"
    fi

    if [[ -n "$shodan_vulns" ]]; then
        while IFS= read -r cve; do
            [[ -n "$cve" ]] && _vuln "CVE conocido: $cve"
            isp_add_finding "CRITICO: $cve detectado en Shodan"
            ((ISP_RISK+=15))
        done <<< "$shodan_vulns"
    fi

    if [[ -n "$shodan_cpes" ]]; then
        _s "CPEs (equipos identificados por Shodan)"
        while IFS= read -r cpe; do
            [[ -n "$cpe" ]] && _kvy "Equipo" "$cpe"
        done <<< "$shodan_cpes"
    fi

    # WHOIS para más info de la empresa
    _s "WHOIS — Información del bloque IP"
    local whois_data
    whois_data=$(whois "$ip" 2>/dev/null | head -40)
    local netname netrange descr abuse
    netname=$(echo "$whois_data" | grep -i "^netname:\|^NetName:" | head -1 | awk -F: '{print $2}' | xargs)
    netrange=$(echo "$whois_data" | grep -i "^inetnum:\|^NetRange:" | head -1 | awk -F: '{print $2}' | xargs)
    descr=$(echo "$whois_data" | grep -i "^descr:\|^OrgName:" | head -1 | awk -F: '{print $2}' | xargs)
    abuse=$(echo "$whois_data" | grep -i "abuse\|OrgAbuseEmail" | grep "@" | head -1 | awk '{print $NF}')

    [[ -n "$netname"  ]] && _kv "Nombre de red (WHOIS)" "$netname"
    [[ -n "$netrange" ]] && _kv "Rango IP asignado"     "$netrange"
    [[ -n "$descr"    ]] && _kv "Descripción"           "$descr"
    [[ -n "$abuse"    ]] && _kv "Email abuso"           "$abuse"

    ISP_ORG="${isp:-${org:-$netname}}"
    ISP_COUNTRY="$country"
    ISP_CITY="$city"
}

# ── 2. Detección de equipo y fabricante ─────────────────────────
isp_device_detect() {
    local ip="$1"
    _h "2 ▸ DETECCIÓN DE EQUIPO Y FABRICANTE"

    local device_vendor="" device_model="" device_os=""

    # Banner grabbing en puertos comunes
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
                _kv "Servidor HTTP:${port}" "$server"
                # Detectar fabricante por server header
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
                device_vendor="Huawei"; device_model="Posible ONT/ONU/HG"
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
                device_vendor="Desconocido"; device_os="Linux/Dropbear"
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

    # SNMP community string 'public' check (UDP 161) — si snmpwalk disponible
    if command -v snmpwalk &>/dev/null; then
        _s "SNMP — sysDescr (UDP 161)"
        local snmp_desc
        snmp_desc=$(timeout 5 snmpwalk -v2c -c public -t 3 "$ip" sysDescr 2>/dev/null | head -3)
        if [[ -n "$snmp_desc" ]]; then
            _vuln "SNMP community 'public' aceptado — expone información del sistema"
            echo "$snmp_desc" | while IFS= read -r l; do _kvy "SNMP sysDescr" "$l"; done
            isp_add_finding "CRITICO: SNMP con community 'public' accesible (info leak)"
            ((ISP_RISK+=25))
            # Extraer info del equipo
            echo "$snmp_desc" | grep -qi "mikrotik\|routeros" && device_vendor="MikroTik"
            echo "$snmp_desc" | grep -qi "cisco"              && device_vendor="Cisco"
            echo "$snmp_desc" | grep -qi "huawei"             && device_vendor="Huawei"
            echo "$snmp_desc" | grep -qi "juniper\|junos"     && device_vendor="Juniper"
            local extracted_model
            extracted_model=$(echo "$snmp_desc" | grep -oE 'RouterOS [0-9.]+|IOS [0-9.]+|VRP [^,]+' | head -1)
            [[ -n "$extracted_model" ]] && device_model="$extracted_model"
        else
            _ok "SNMP community 'public' no accesible (bien)"
        fi
    fi

    # Resultado de detección
    _s "Resultado de fingerprinting"
    if [[ -n "$device_vendor" ]]; then
        _kvy "Fabricante detectado" "$device_vendor"
        [[ -n "$device_model" ]] && _kvy "Modelo/Versión" "$device_model"
        [[ -n "$device_os"    ]] && _kvy "Sistema Operativo" "$device_os"
        ISP_DEVICE="$device_vendor ${device_model}"
    else
        _info "Fabricante no identificado por análisis de banners"
        _info "Prueba con nmap -sV para fingerprinting más profundo"
        ISP_DEVICE="Desconocido"
    fi
}

# ── 3. Escaneo de puertos con análisis de acceso ─────────────────
isp_ports() {
    local ip="$1"
    _h "3 ▸ PUERTOS — ANÁLISIS DE ACCESO Y RIESGO"

    # Mapa de puertos críticos para equipos de red/ISP
    declare -A PORT_INFO=(
        [21]="FTP — transferencia archivos (inseguro)"
        [22]="SSH — administración remota"
        [23]="Telnet — admin en texto plano (PELIGROSO)"
        [25]="SMTP — servidor de correo"
        [53]="DNS — servidor de nombres"
        [69]="TFTP — transferencia sin auth"
        [80]="HTTP — panel web sin cifrar"
        [161]="SNMP UDP — gestión red (potencialmente expuesto)"
        [443]="HTTPS — panel web cifrado"
        [445]="SMB — recursos compartidos Windows"
        [554]="RTSP — streaming multimedia"
        [1723]="PPTP VPN — protocolo VPN (inseguro)"
        [2000]="Bandwidth Test (MikroTik)"
        [2601]="Zebra/Quagga — routing daemon"
        [3128]="Proxy HTTP (Squid)"
        [3306]="MySQL — base de datos"
        [4899]="Radmin — control remoto"
        [5900]="VNC — escritorio remoto"
        [6881]="BitTorrent"
        [7547]="TR-069 — gestión CPE (CWMP)"
        [8080]="HTTP Alternativo"
        [8081]="HTTP Alternativo 2"
        [8291]="Winbox (MikroTik)"
        [8333]="WebFig (MikroTik)"
        [8443]="HTTPS Alternativo"
        [8728]="API MikroTik sin TLS"
        [8729]="API MikroTik con TLS"
        [8888]="Panel administración genérico"
        [9000]="Panel administración alternativo"
        [9090]="Panel web / Prometheus"
        [10000]="Webmin — panel administración"
    )

    declare -A PORT_RISK=(
        [21]=20 [23]=35 [69]=25 [161]=25 [445]=20
        [1723]=15 [2000]=5 [4899]=30 [5900]=25
        [7547]=30 [8291]=20 [8728]=25 [10000]=20
    )

    local open_ports=()
    _s "Escaneando puertos de administración y riesgo"
    echo ""
    printf "  ${W}${BOLD}%-8s %-35s %-12s %s${NC}\n" "PUERTO" "SERVICIO" "ESTADO" "RIESGO"
    echo -e "  ${DIM}$(printf '─%.0s' {1..70})${NC}"

    for port in 21 22 23 25 53 69 80 161 443 445 554 1723 2000 2601 3128 3306 4899 5900 7547 8080 8081 8291 8333 8443 8728 8729 8888 9000 9090 10000; do
        local service="${PORT_INFO[$port]:-Servicio desconocido}"
        local risk_add="${PORT_RISK[$port]:-0}"
        local state

        if timeout 2 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            state="ABIERTO"
            open_ports+=("$port")

            # Determinar nivel de riesgo por puerto
            local risk_level color_risk
            case $port in
                23|69|4899)      risk_level="CRITICO"; color_risk="${R}" ;;
                21|161|5900|7547|8291|8728) risk_level="ALTO"; color_risk="${Y}" ;;
                22|80|3306|10000) risk_level="MEDIO";  color_risk="${C}" ;;
                *)               risk_level="INFO";   color_risk="${G}" ;;
            esac

            printf "  ${G}%-8s${NC} %-35s ${color_risk}%-12s %s${NC}\n" \
                   "$port" "$service" "$state" "$risk_level"

            ((ISP_RISK+=risk_add))
            [[ "$risk_level" == "CRITICO" || "$risk_level" == "ALTO" ]] && \
                isp_add_finding "${risk_level}: Puerto $port abierto — $service"

            # Test de acceso específico por puerto
            case $port in
                23)
                    _warn "   → Telnet activo: credenciales en texto plano. Probar: telnet $ip 23"
                    ;;
                7547)
                    _warn "   → TR-069/CWMP: protocolo de gestión remota CPE. Vectores: CVE-2017-14462"
                    isp_add_finding "CRITICO: TR-069 expuesto — vector de ataque masivo (CVE-2017-14462)"
                    ((ISP_RISK+=20))
                    ;;
                8291)
                    _warn "   → Winbox: verificar CVE-2018-14847 (cred leak RouterOS < 6.42.1)"
                    ;;
                161)
                    _warn "   → SNMP UDP: verificar community strings por defecto"
                    ;;
                5900)
                    _warn "   → VNC: verificar si requiere contraseña"
                    ;;
            esac
        else
            printf "  ${DIM}%-8s %-35s %-12s %s${NC}\n" "$port" "$service" "cerrado" ""
        fi
    done

    echo ""
    if [[ ${#open_ports[@]} -gt 0 ]]; then
        _kvy "Total puertos abiertos" "${#open_ports[@]}: ${open_ports[*]}"
    else
        _ok "No se encontraron puertos de administración expuestos"
    fi

    # nmap más profundo si disponible
    if command -v nmap &>/dev/null && [[ ${#open_ports[@]} -gt 0 ]]; then
        _s "Nmap — detección de versión en puertos abiertos"
        local port_list; port_list=$(IFS=,; echo "${open_ports[*]}")
        nmap -sV --version-intensity 5 -p "$port_list" --open "$ip" 2>/dev/null \
            | grep -E "^[0-9]+|open|VERSION" \
            | while IFS= read -r l; do echo -e "  ${DIM}$l${NC}"; done
    fi

    ISP_OPEN_PORTS="${open_ports[*]}"
}

# ── 4. Detección de firewall ─────────────────────────────────────
isp_firewall() {
    local ip="$1"
    _h "4 ▸ DETECCIÓN DE FIREWALL"

    _s "Análisis de comportamiento de puertos"
    local fw_type="Desconocido"
    local filtered_count=0 closed_count=0

    # Probar puertos tipicamente filtrados vs cerrados
    local test_ports=(135 139 256 666 1025 1026 1900 4444 6667 12345)
    for port in "${test_ports[@]}"; do
        local result
        # ICMP unreachable = cerrado. Sin respuesta = filtrado (firewall)
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            : # abierto
        else
            # Intentar detectar RST vs timeout
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
        fw_type="Firewall activo (mayoría de puertos filtrados/sin respuesta)"
        _ok "Firewall detectado — bloqueo de puertos silencioso"
    elif [[ $closed_count -gt 5 ]]; then
        fw_type="Sin firewall aparente o con política de RST (puertos cerrados)"
        _warn "Posible ausencia de firewall — puertos responden con RST"
        isp_add_finding "MEDIO: Comportamiento sin firewall detectado (RST en puertos)"
        ((ISP_RISK+=10))
    else
        fw_type="Mixto — firewall parcial o politicas variadas"
        _info "Comportamiento mixto — algunos puertos filtrados, otros cerrados"
    fi

    _kvy "Tipo de firewall inferido" "$fw_type"

    # WAF si tiene web
    if timeout 2 bash -c "echo >/dev/tcp/$ip/80" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/tcp/$ip/443" 2>/dev/null; then
        _s "Detección de WAF web"
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
                    _info "WAF web no identificado en puerto $port"
                fi
                break
            fi
        done
    fi

    # TTL-based OS detection
    _s "Detección de OS por TTL (ping)"
    local ttl
    ttl=$(ping -c 1 -W 2 "$ip" 2>/dev/null | grep -oE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
    if [[ -n "$ttl" ]]; then
        _kv "TTL recibido" "$ttl"
        if   [[ $ttl -le 64  ]]; then _kv "OS estimado" "Linux / Unix / Android / Networking OS"
        elif [[ $ttl -le 128 ]]; then _kv "OS estimado" "Windows"
        elif [[ $ttl -le 255 ]]; then _kv "OS estimado" "Cisco IOS / Solaris / otros"
        fi
    else
        _info "ICMP bloqueado — no se puede determinar TTL"
    fi

    ISP_FIREWALL="$fw_type"
}

# ── 5. Vulnerabilidades conocidas ────────────────────────────────
isp_vulns() {
    local ip="$1"
    _h "5 ▸ VULNERABILIDADES CONOCIDAS"

    _s "Verificación de vectores comunes"

    # TR-069 / CWMP (puerto 7547) — masivo vector de ataque ISP
    if timeout 2 bash -c "echo >/dev/tcp/$ip/7547" 2>/dev/null; then
        _vuln "TR-069 (CWMP) expuesto en puerto 7547"
        _vuln "  CVE-2017-14462: Code execution en módems con TR-069"
        _vuln "  CVE-2016-10372: RCE en dispositivos TalkTalk/Deutsche Telekom"
        _info "  Millones de routers afectados por Mirai/Hajime via TR-069"
        isp_add_finding "CRITICO: TR-069 expuesto — vector de botnets (CVE-2017-14462)"
        ((ISP_RISK+=30))
    else
        _ok "TR-069 (puerto 7547) no accesible desde exterior"
    fi

    # Verificar si WebFig/HTTP panel permite acceso sin login
    for port in 80 8080 8333; do
        if timeout 2 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            local body
            body=$(curl -sk --max-time 5 "http://${ip}:${port}" 2>/dev/null)
            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig"; then
                if ! echo "$body" | grep -qi "login\|password\|username"; then
                    _vuln "Panel de administración sin pantalla de login detectado (puerto $port)"
                    isp_add_finding "CRITICO: Panel admin accesible sin autenticación en puerto $port"
                    ((ISP_RISK+=35))
                else
                    _med "Panel de admin con login en puerto $port — verificar credenciales por defecto"
                    isp_add_finding "MEDIO: Panel admin con login — probar admin/(vacío), admin/admin"
                    ((ISP_RISK+=10))
                fi
            fi
        fi
    done

    # DNS recursivo abierto
    if timeout 2 bash -c "echo >/dev/tcp/$ip/53" 2>/dev/null || \
       dig @"$ip" google.com A +time=3 +tries=1 &>/dev/null; then
        local dns_test
        dns_test=$(dig @"$ip" google.com A +short +time=3 +tries=1 2>/dev/null)
        if [[ -n "$dns_test" ]]; then
            _vuln "DNS Recursivo Abierto — responde a consultas de terceros"
            _info "  Puede ser usado para ataques DNS Amplification (DDoS)"
            isp_add_finding "ALTO: DNS recursivo abierto — vector de amplificación DDoS"
            ((ISP_RISK+=20))
        else
            _ok "DNS no recursivo o no responde a consultas externas"
        fi
    fi

    # Proxy abierto
    if timeout 2 bash -c "echo >/dev/tcp/$ip/3128" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/tcp/$ip/8080" 2>/dev/null; then
        local proxy_test
        for pport in 3128 8080 8081; do
            proxy_test=$(curl -sk --max-time 5 --proxy "http://${ip}:${pport}" \
                         "http://httpbin.org/ip" 2>/dev/null | grep -o '"origin":[^"]*"[^"]*"' | head -1)
            if [[ -n "$proxy_test" ]]; then
                _vuln "Proxy HTTP abierto en puerto $pport — permite anonimizar tráfico"
                isp_add_finding "ALTO: Proxy abierto en puerto $pport"
                ((ISP_RISK+=20))
                break
            fi
        done
    fi

    # Amplificación NTP
    if timeout 2 bash -c "echo >/dev/udp/$ip/123" 2>/dev/null; then
        _warn "Puerto NTP (123/UDP) puede estar activo — verificar amplificación"
        _info "  Si responde a monlist: vector de DDoS amplificado"
    fi
}

# ── 6. Recomendaciones de mitigación ────────────────────────────
isp_mitigations() {
    local ip="$1"
    _h "6 ▸ RECOMENDACIONES DE MITIGACIÓN"
    echo ""

    echo -e "  ${W}${BOLD}Para el equipo de red del proveedor:${NC}\n"

    local mitigations=(
        "Deshabilitar Telnet|/ip service disable telnet (RouterOS)|CRITICO"
        "Deshabilitar TR-069/CWMP si no se usa activamente|Configurar ACL o deshabilitar en firmware|CRITICO"
        "Cambiar credenciales por defecto|Contraseña fuerte en todos los servicios admin|CRITICO"
        "Bloquear WebFig/Winbox desde WAN|Firewall: permitir solo desde IPs admin conocidas|ALTO"
        "Deshabilitar SNMP community 'public'|Usar SNMPv3 con auth o deshabilitar SNMP|ALTO"
        "Cerrar DNS recursivo a terceros|Restringir consultas DNS a clientes propios|ALTO"
        "Deshabilitar FTP si no se usa|/ip service disable ftp (RouterOS)|ALTO"
        "Actualizar firmware/RouterOS|Mantener siempre la última versión estable|CRITICO"
        "Implementar fail2ban o brute-force protection|Limitar intentos de login por IP|MEDIO"
        "Usar VPN para acceso administrativo|No exponer paneles admin a Internet|ALTO"
        "Segmentar red de gestión|VLAN separada para administración|MEDIO"
        "Implementar logging centralizado|SIEM o syslog externo para auditoría|MEDIO"
    )

    printf "  ${W}${BOLD}%-50s %-35s %s${NC}\n" "MITIGACIÓN" "CÓMO" "PRIORIDAD"
    echo -e "  ${DIM}$(printf '─%.0s' {1..95})${NC}"
    for item in "${mitigations[@]}"; do
        IFS='|' read -r action how priority <<< "$item"
        local col="${G}"
        [[ "$priority" == "CRITICO" ]] && col="${R}"
        [[ "$priority" == "ALTO"    ]] && col="${Y}"
        [[ "$priority" == "MEDIO"   ]] && col="${C}"
        printf "  %-50s %-35s ${col}%s${NC}\n" "$action" "$how" "$priority"
    done
}

# ── 7. Puntuación y resumen ──────────────────────────────────────
isp_summary() {
    local ip="$1"
    _h "✦  RESUMEN EJECUTIVO — AUDITORÍA ISP"
    echo ""

    _kv "IP auditada"    "$ip"
    _kv "ISP/Empresa"    "${ISP_ORG:-N/A}"
    _kv "Ubicación"      "${ISP_CITY:-N/A}, ${ISP_COUNTRY:-N/A}"
    _kv "Equipo"         "${ISP_DEVICE:-Desconocido}"
    _kv "Firewall"       "${ISP_FIREWALL:-No determinado}"
    _kv "Puertos abiertos" "${ISP_OPEN_PORTS:-Ninguno}"
    echo ""

    # Ajustar riesgo máximo a 100
    [[ $ISP_RISK -gt 100 ]] && ISP_RISK=100
    local label color bar_len
    if   [[ $ISP_RISK -ge 75 ]]; then label="CRÍTICO";  color="${R}"
    elif [[ $ISP_RISK -ge 50 ]]; then label="ALTO";     color="${Y}"
    elif [[ $ISP_RISK -ge 25 ]]; then label="MEDIO";    color="${C}"
    else                              label="BAJO";     color="${G}"
    fi

    bar_len=$(( ISP_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Puntuación de Riesgo:${NC} ${color}${BOLD}${ISP_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0; i<bar_len; i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar_len; i<40; i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"
    echo ""

    if [[ ${#ISP_FINDINGS[@]} -gt 0 ]]; then
        _s "Hallazgos identificados (${#ISP_FINDINGS[@]})"
        for f in "${ISP_FINDINGS[@]}"; do
            local sev="${f%%:*}" msg="${f#*: }"
            local fc="${G}"
            [[ "$sev" == "CRITICO" ]] && fc="${R}"
            [[ "$sev" == "ALTO"    ]] && fc="${Y}"
            [[ "$sev" == "MEDIO"   ]] && fc="${C}"
            echo -e "  ${fc}[${sev}]${NC} $msg"
        done
    fi

    # Guardar log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local lf="${log_dir}/isp_audit_${ip//[^0-9]/_}_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "ISP Audit v3.2.0 — @kevxngg (Kevin)"
        echo "IP: $ip | ISP: ${ISP_ORG:-N/A} | Equipo: ${ISP_DEVICE:-N/A}"
        echo "Riesgo: ${ISP_RISK}/100 — $label | Fecha: $(date)"
        echo ""; echo "HALLAZGOS:"
        for f in "${ISP_FINDINGS[@]}"; do echo "  - $f"; done
    } > "$lf"
    echo -e "\n  ${DIM}Log: ${W}${lf}${NC}"
}

# ── MAIN del módulo ──────────────────────────────────────────────
run_isp_audit() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -e "${R}Uso: opción ISP desde el menú principal${NC}"
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
