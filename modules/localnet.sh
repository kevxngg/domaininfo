#!/usr/bin/env bash
# ================================================================
#  localnet.sh — Local Network Scanner (WiFi/LAN)
#  Encuentra dispositivos, vulnerabilidades y vectores de ataque
#  Autor: @kevxngg (Señor K)
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

# ── 1. Información de la interfaz de red ────────────────────────
localnet_iface_info() {
    _h "1 ▸ INFORMACIÓN DE RED LOCAL"

    _s "Interfaz activa y configuración"
    local iface gateway local_ip subnet cidr

    # Detectar interfaz activa (funciona en Linux y Termux)
    iface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    [[ -z "$iface" ]] && iface=$(route -n 2>/dev/null | grep '^0.0.0.0' | awk '{print $8}' | head -1)
    [[ -z "$iface" ]] && iface="wlan0"  # Termux default

    gateway=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    local_ip=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    cidr=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    subnet="${cidr%/*}"

    _kv "Interfaz activa"   "${iface:-No detectada}"
    _kv "IP local"          "${local_ip:-N/A}"
    _kv "Red CIDR"          "${cidr:-N/A}"
    _kv "Gateway/Router"    "${gateway:-N/A}"

    # Info del gateway (router doméstico)
    if [[ -n "$gateway" ]]; then
        local gw_vendor
        gw_vendor=$(arp -n "$gateway" 2>/dev/null | awk '{print $3}' | head -1)
        [[ -n "$gw_vendor" ]] && _kv "MAC del gateway" "$gw_vendor"
    fi

    # WiFi info si disponible
    if command -v iwconfig &>/dev/null; then
        _s "Información WiFi"
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
            [[ -n "$freq"    ]] && _kv "Frecuencia"     "$freq GHz"
            [[ -n "$quality" ]] && _kv "Calidad señal"  "$quality"
        fi
    elif command -v termux-wifi-connectioninfo &>/dev/null 2>&1; then
        _s "WiFi (Termux API)"
        termux-wifi-connectioninfo 2>/dev/null | while IFS= read -r l; do
            echo -e "  ${DIM}$l${NC}"
        done
    fi

    # Exportar para uso en otros módulos
    LN_IFACE="$iface"
    LN_LOCAL_IP="$local_ip"
    LN_GATEWAY="$gateway"
    LN_CIDR="$cidr"

    # Derivar rango de red para escaneo
    if [[ -n "$local_ip" ]]; then
        local base; base=$(echo "$local_ip" | cut -d. -f1-3)
        LN_NETWORK="${base}.0/24"
    fi
}

# ── 2. Descubrir hosts en la red local ──────────────────────────
localnet_discover() {
    _h "2 ▸ DESCUBRIMIENTO DE HOSTS"

    local network="${LN_NETWORK:-192.168.1.0/24}"
    _info "Red a escanear: $network"
    _warn "Esto puede tardar 30-60 segundos..."
    echo ""

    local base; base=$(echo "$network" | cut -d. -f1-3)
    local tmpdir; tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' RETURN

    printf "  ${W}${BOLD}%-18s %-20s %-20s %s${NC}\n" "IP" "MAC" "FABRICANTE" "ESTADO"
    echo -e "  ${DIM}$(printf '─%.0s' {1..70})${NC}"

    # Método 1: nmap ping scan
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
        # Método 2: ping sweep paralelo
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

    # Leer hosts encontrados
    if [[ -f "${tmpdir}/hosts" ]]; then
        mapfile -t LN_HOSTS < "${tmpdir}/hosts"
        echo ""
        _ok "${#LN_HOSTS[@]} host(s) encontrados en $network"
    else
        echo ""
        _info "No se encontraron hosts (puede requerir root para ARP scan)"
    fi

    # ARP table complement
    _s "Tabla ARP local"
    arp -n 2>/dev/null | grep -v "incomplete\|Address" | while IFS= read -r l; do
        echo -e "  ${DIM}$l${NC}"
    done
}

# ── 3. Análisis de cada host encontrado ─────────────────────────
localnet_analyze_host() {
    local ip="$1"
    echo ""
    echo -e "  ${Y}${BOLD}── Analizando: $ip ──────────────────────────${NC}"

    # Puertos de administración rápidos
    local open=()
    for port in 21 22 23 80 443 445 3306 5900 8080 8443 8291 8333 9000 10000; do
        timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null && open+=("$port")
    done

    if [[ ${#open[@]} -gt 0 ]]; then
        _kvy "Puertos abiertos" "${open[*]}"
        for p in "${open[@]}"; do
            case $p in
                23)  _vuln "  Telnet (23) abierto — texto plano" ; LN_FINDINGS+=("$ip: Telnet expuesto"); ((LN_RISK+=15)) ;;
                445) _warn "  SMB (445) abierto — verificar EternalBlue" ; LN_FINDINGS+=("$ip: SMB abierto") ;;
                5900) _warn "  VNC (5900) — verificar si requiere contraseña" ; LN_FINDINGS+=("$ip: VNC abierto") ;;
                8291) _warn "  Winbox (8291) — dispositivo MikroTik" ; LN_FINDINGS+=("$ip: Winbox MikroTik") ;;
                3306) _warn "  MySQL (3306) — base de datos expuesta" ; LN_FINDINGS+=("$ip: MySQL expuesto") ; ((LN_RISK+=10)) ;;
            esac
        done
    else
        _ok "  Sin puertos de administración expuestos"
    fi

    # Identificar tipo de dispositivo
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
                dtype="Router con firmware alternativo (DD-WRT/OpenWrt)"
            fi
            [[ -n "$dtype" ]] && break
        fi
    done

    # Hostname via PTR
    local hostname
    hostname=$(dig +short -x "$ip" 2>/dev/null | head -1)
    [[ -n "$hostname" ]] && _kv "  Hostname" "$hostname"
    [[ -n "$dtype"    ]] && _kvy "  Dispositivo detectado" "$dtype"

    # Credenciales por defecto si hay panel web
    if [[ -n "$dtype" ]] && [[ ${#open[@]} -gt 0 ]]; then
        _info "  Verificar credenciales por defecto: admin/(vacío), admin/admin, admin/1234"
    fi
}

# ── 4. Análisis del router/gateway ──────────────────────────────
localnet_gateway_audit() {
    local gw="${LN_GATEWAY}"
    [[ -z "$gw" ]] && return

    _h "3 ▸ AUDITORÍA DEL GATEWAY (ROUTER)"
    _kv "Gateway" "$gw"

    # Puertos
    _s "Puertos expuestos en el gateway"
    local open_gw=()
    for port in 21 22 23 53 80 443 1900 2000 5900 8080 8291 8333 8443 8728 8729 9000 10000; do
        timeout 1 bash -c "echo >/dev/tcp/$gw/$port" 2>/dev/null && {
            open_gw+=("$port")
            case $port in
                23)   _vuln "Puerto 23 (Telnet) ABIERTO en el gateway" ; LN_FINDINGS+=("Gateway: Telnet activo") ; ((LN_RISK+=20)) ;;
                1900) _warn "Puerto 1900 (UPnP) — verificar si permite port forwarding no autorizado" ; LN_FINDINGS+=("Gateway: UPnP activo") ;;
                8291) _warn "Puerto 8291 (Winbox) — gateway es MikroTik" ;;
                80)   _kvy "Puerto 80 (HTTP)" "Panel web sin cifrar" ;;
                443)  _ok  "Puerto 443 (HTTPS) disponible" ;;
            esac
        }
    done

    [[ ${#open_gw[@]} -gt 0 ]] && _kvy "Puertos abiertos" "${open_gw[*]}"

    # Panel web del gateway
    _s "Fingerprinting del gateway"
    for port in 80 8080 443; do
        local proto="http"; [[ "$port" == "443" ]] && proto="https"
        if timeout 1 bash -c "echo >/dev/tcp/$gw/$port" 2>/dev/null; then
            local body hdr vendor_gw
            hdr=$(curl -skI --max-time 4 "${proto}://${gw}:${port}" 2>/dev/null)
            body=$(curl -skL --max-time 4 "${proto}://${gw}:${port}" 2>/dev/null | head -100)
            vendor_gw=$(echo "$hdr" | grep -i "server:" | cut -d: -f2- | xargs)
            [[ -n "$vendor_gw" ]] && _kvy "Servidor web" "$vendor_gw"

            if echo "$body" | grep -qi "mikrotik\|routeros\|webfig"; then
                _kvy "Dispositivo" "MikroTik RouterOS"
                if ! echo "$body" | grep -qi "login\|password"; then
                    _vuln "Panel sin pantalla de login — posible acceso sin autenticación"
                    LN_FINDINGS+=("Gateway MikroTik: panel sin auth")
                    ((LN_RISK+=30))
                fi
            elif echo "$body" | grep -qi "huawei"; then
                _kvy "Dispositivo" "Huawei"
            elif echo "$body" | grep -qi "tp-link\|tplink"; then
                _kvy "Dispositivo" "TP-Link"
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
        _warn "UPnP activo — permite que dispositivos de la red hagan port forwarding automático"
        _info "Un malware en la red puede abrir puertos en el router via UPnP"
        LN_FINDINGS+=("Gateway: UPnP habilitado — riesgo de port forwarding no autorizado")
        ((LN_RISK+=15))
    else
        _ok "UPnP no detectado (bien)"
    fi

    # DNS leak check
    _s "DNS leak — resolución de nombres"
    local dns_server
    dns_server=$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' | head -1)
    _kv "DNS configurado" "${dns_server:-No detectado}"
    if [[ "$dns_server" == "$gw" ]]; then
        _info "El gateway actúa como servidor DNS (común en redes domésticas)"
    fi
}

# ── 5. Detección de dispositivos IoT/vulnerables ────────────────
localnet_iot_scan() {
    _h "4 ▸ DISPOSITIVOS IoT Y POTENCIALMENTE VULNERABLES"

    if [[ ${#LN_HOSTS[@]} -eq 0 ]]; then
        _info "No hay hosts para analizar. Ejecuta primero el descubrimiento."
        return
    fi

    _s "Analizando hosts encontrados"
    for host in "${LN_HOSTS[@]}"; do
        [[ "$host" == "$LN_LOCAL_IP" ]] && continue  # skip ourselves
        localnet_analyze_host "$host"
    done
}

# ── 6. Vulnerabilidades de la red WiFi ──────────────────────────
localnet_wifi_vulns() {
    _h "5 ▸ VULNERABILIDADES DE RED WIFI"

    _s "Análisis de seguridad WiFi"

    # Protocolo de seguridad
    if command -v iwconfig &>/dev/null; then
        local security
        security=$(iwconfig "${LN_IFACE:-wlan0}" 2>/dev/null | grep -i "Encryption\|WPA\|WEP")
        if [[ -n "$security" ]]; then
            echo -e "  ${DIM}$security${NC}"
            if echo "$security" | grep -qi "WEP"; then
                _vuln "WEP detectado — protocolo ROTO, descifrable en minutos"
                LN_FINDINGS+=("WiFi: Protocolo WEP — CRITICO")
                ((LN_RISK+=50))
            elif echo "$security" | grep -qi "WPA2\|WPA3"; then
                _ok "WPA2/WPA3 — protocolo seguro"
            elif echo "$security" | grep -qi 'WPA[^23]'; then
                _warn "WPA (v1) — vulnerable a ataques TKIP"
                LN_FINDINGS+=("WiFi: WPA v1 — vulnerable")
                ((LN_RISK+=20))
            fi
        fi
    fi

    # KRACK vulnerability check (WPA2 - conceptual)
    _s "Vectores de ataque conocidos en WiFi"
    echo -e "  ${DIM}Verificación conceptual (requiere herramientas especializadas para confirmar)${NC}"
    echo ""
    local vectors=(
        "KRACK (CVE-2017-13077)|WPA2 — reinstalación de clave|Actualizar firmware del router y clientes"
        "PMKID Attack|WPA2/WPA3 — captura de hash sin clientes|Usar contraseña larga y compleja (20+ chars)"
        "Deauth Attack (802.11)|Desconexión de clientes|Habilitar 802.11w (Protected Management Frames)"
        "Evil Twin/Rogue AP|AP falso con mismo SSID|Verificar BSSID antes de conectar"
        "WPS PIN Brute Force|Si WPS habilitado|DESHABILITAR WPS en el router"
        "DNS Spoofing local|Poisoning si DNS = gateway|Usar DNS sobre HTTPS (DoH)"
        "ARP Spoofing|Man-in-the-middle en LAN|Usar VPN o switches con ARP inspection"
    )

    printf "  ${W}${BOLD}%-35s %-30s %s${NC}\n" "VECTOR" "MECANISMO" "MITIGACIÓN"
    echo -e "  ${DIM}$(printf '─%.0s' {1..90})${NC}"
    for v in "${vectors[@]}"; do
        IFS='|' read -r name mech fix <<< "$v"
        printf "  ${Y}%-35s${NC} %-30s ${G}%s${NC}\n" "$name" "$mech" "$fix"
    done

    # WPS check
    _s "WPS — Wi-Fi Protected Setup"
    if command -v wash &>/dev/null; then
        _info "wash disponible — ejecutar: wash -i ${LN_IFACE:-wlan0} para detectar APs con WPS"
    else
        _info "Para verificar WPS: instalar aircrack-ng (Kali/NetHunter)"
        _info "  apt install aircrack-ng  o  pkg install aircrack-ng (Termux)"
    fi
}

# ── 7. Recomendaciones para red local ───────────────────────────
localnet_mitigations() {
    _h "6 ▸ MITIGACIONES PARA RED LOCAL"
    echo ""

    local items=(
        "Cambiar contraseña del router|Acceder a 192.168.1.1 → cambiar admin/(vacío)|CRITICO"
        "Deshabilitar WPS en el router|Panel admin → WiFi → deshabilitar WPS|ALTO"
        "Usar WPA3 o WPA2 con AES|No usar WEP ni WPA(v1)|ALTO"
        "Contraseña WiFi larga (+20 chars)|Mezclar mayúsculas, números, símbolos|ALTO"
        "Actualizar firmware del router|Panel admin → System → Firmware Update|CRITICO"
        "Deshabilitar acceso admin desde WiFi|Permitir admin solo desde Ethernet|MEDIO"
        "Deshabilitar UPnP|Panel admin → Advanced → UPnP → Off|MEDIO"
        "Segmentar red con VLAN o red de invitados|IoT en red separada de dispositivos principales|MEDIO"
        "Activar 802.11w (PMF)|Protege contra ataques de deautenticación|MEDIO"
        "Usar DNS cifrado (DoH/DoT)|Configurar 1.1.1.1 o 8.8.8.8 con TLS|BAJO"
        "Deshabilitar Telnet/FTP en dispositivos|Solo usar SSH|ALTO"
        "Monitorear ARP table regularmente|arp -n — detectar spoofing|BAJO"
    )

    printf "  ${W}${BOLD}%-45s %-35s %s${NC}\n" "ACCIÓN" "CÓMO" "PRIORIDAD"
    echo -e "  ${DIM}$(printf '─%.0s' {1..90})${NC}"
    for item in "${items[@]}"; do
        IFS='|' read -r action how priority <<< "$item"
        local col="${G}"
        [[ "$priority" == "CRITICO" ]] && col="${R}"
        [[ "$priority" == "ALTO"    ]] && col="${Y}"
        [[ "$priority" == "MEDIO"   ]] && col="${C}"
        printf "  %-45s %-35s ${col}%s${NC}\n" "$action" "$how" "$priority"
    done
}

# ── 8. Resumen y puntuación ─────────────────────────────────────
localnet_summary() {
    _h "✦  RESUMEN — AUDITORÍA DE RED LOCAL"
    echo ""

    _kv "Red escaneada"    "${LN_NETWORK:-N/A}"
    _kv "Gateway"         "${LN_GATEWAY:-N/A}"
    _kv "IP local"        "${LN_LOCAL_IP:-N/A}"
    _kv "Hosts encontrados" "${#LN_HOSTS[@]}"
    _kv "Hallazgos"       "${#LN_FINDINGS[@]}"
    echo ""

    [[ $LN_RISK -gt 100 ]] && LN_RISK=100
    local label color
    if   [[ $LN_RISK -ge 75 ]]; then label="CRÍTICO";  color="${R}"
    elif [[ $LN_RISK -ge 50 ]]; then label="ALTO";     color="${Y}"
    elif [[ $LN_RISK -ge 25 ]]; then label="MEDIO";    color="${C}"
    else                              label="BAJO";     color="${G}"
    fi

    local bar=$(( LN_RISK * 40 / 100 ))
    echo -e "  ${W}${BOLD}Puntuación de Riesgo:${NC} ${color}${BOLD}${LN_RISK}/100 — ${label}${NC}"
    echo -ne "  ["
    for ((i=0;i<bar;i++)); do echo -ne "${color}█${NC}"; done
    for ((i=bar;i<40;i++)); do echo -ne "${DIM}░${NC}"; done
    echo "]"; echo ""

    if [[ ${#LN_FINDINGS[@]} -gt 0 ]]; then
        _s "Hallazgos"
        for f in "${LN_FINDINGS[@]}"; do
            local sev="${f%%:*}"; local col="${C}"
            echo "$f" | grep -qi "CRITICO\|Telnet\|sin auth\|WEP" && col="${R}"
            echo "$f" | grep -qi "UPnP\|SMB\|MySQL\|VNC" && col="${Y}"
            echo -e "  ${col}▸${NC} $f"
        done
    fi

    # Guardar log
    local log_dir
    log_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
    mkdir -p "$log_dir"
    local lf="${log_dir}/localnet_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "LocalNet Audit v3.2.0 — @kevxngg (Señor K)"
        echo "Red: ${LN_NETWORK:-N/A} | Gateway: ${LN_GATEWAY:-N/A} | Hosts: ${#LN_HOSTS[@]}"
        echo "Riesgo: ${LN_RISK}/100 — $label | Fecha: $(date)"
        echo ""; echo "HALLAZGOS:"
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
