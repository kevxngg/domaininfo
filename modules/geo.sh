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

module_geo() {
    header "2 ▸ GEOLOCATION AND IP INFO"
    [[ -z "$IP" ]] && { warn "No IP to geolocate"; return; }

    # ipinfo.io
    section "ipinfo.io"
    local geo
    geo=$(curl -s --max-time 10 "https://ipinfo.io/${IP}/json" 2>/dev/null)
    if [[ -n "$geo" && "$geo" != *"error"* ]]; then
        GEO_ORG=$(echo     "$geo" | grep -oP '"org"\s*:\s*"\K[^"]+')
        GEO_CITY=$(echo    "$geo" | grep -oP '"city"\s*:\s*"\K[^"]+')
        GEO_REGION=$(echo  "$geo" | grep -oP '"region"\s*:\s*"\K[^"]+')
        GEO_COUNTRY=$(echo "$geo" | grep -oP '"country"\s*:\s*"\K[^"]+')
        GEO_POSTAL=$(echo  "$geo" | grep -oP '"postal"\s*:\s*"\K[^"]+')
        GEO_COORDS=$(echo  "$geo" | grep -oP '"loc"\s*:\s*"\K[^"]+')
        GEO_TZ=$(echo      "$geo" | grep -oP '"timezone"\s*:\s*"\K[^"]+')
        GEO_HOST=$(echo    "$geo" | grep -oP '"hostname"\s*:\s*"\K[^"]+')

        kv "IP"             "$IP"
        kv "Hostname"       "${GEO_HOST:-N/A}"
        kv "Organization"   "${GEO_ORG:-N/A}"
        kv "City"           "${GEO_CITY:-N/A}"
        kv "Region"         "${GEO_REGION:-N/A}"
        kv "Country (code)" "${GEO_COUNTRY:-N/A}"
        kv "Postal code"    "${GEO_POSTAL:-N/A}"
        kv "Coordinates"    "${GEO_COORDS:-N/A}"
        kv "Time zone"      "${GEO_TZ:-N/A}"
        [[ -n "$GEO_COORDS" ]] && kv "Google Maps" "https://maps.google.com/?q=${GEO_COORDS}"
    else
        fail "Could not reach ipinfo.io"
    fi

    # ip-api.com
    section "ip-api.com — ASN, ISP, Flags"
    local geo2
    geo2=$(curl -s --max-time 10 \
        "http://ip-api.com/json/${IP}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query,continent,continentCode,currency,district" \
        2>/dev/null)
    if [[ -n "$geo2" && "$(echo "$geo2" | grep -o '"status":"success"')" != "" ]]; then
        GEO_ISP=$(echo    "$geo2" | grep -oP '"isp"\s*:\s*"\K[^"]+')
        GEO_ASN=$(echo    "$geo2" | grep -oP '"as"\s*:\s*"\K[^"]+')
        GEO_ASNAME=$(echo "$geo2" | grep -oP '"asname"\s*:\s*"\K[^"]+')
        GEO_MOBILE=$(echo "$geo2" | grep -oP '"mobile"\s*:\s*\K(true|false)')
        GEO_PROXY=$(echo  "$geo2" | grep -oP '"proxy"\s*:\s*\K(true|false)')
        GEO_HOSTING=$(echo "$geo2" | grep -oP '"hosting"\s*:\s*\K(true|false)')
        GEO_CONT=$(echo   "$geo2" | grep -oP '"continent"\s*:\s*"\K[^"]+')
        GEO_LAT=$(echo    "$geo2" | grep -oP '"lat"\s*:\s*\K[0-9.\-]+')
        GEO_LON=$(echo    "$geo2" | grep -oP '"lon"\s*:\s*\K[0-9.\-]+')
        GEO_CURR=$(echo   "$geo2" | grep -oP '"currency"\s*:\s*"\K[^"]+')
        GEO_DIST=$(echo   "$geo2" | grep -oP '"district"\s*:\s*"\K[^"]+')

        kv "ISP"                "${GEO_ISP:-N/A}"
        kv "ASN organization"   "${GEO_ASN:-N/A}"
        kv "AS Name"            "${GEO_ASNAME:-N/A}"
        kv "Continent"          "${GEO_CONT:-N/A}"
        kv "Latitude"           "${GEO_LAT:-N/A}"
        kv "Longitude"          "${GEO_LON:-N/A}"
        [[ -n "$GEO_DIST" ]]   && kv "District" "$GEO_DIST"
        [[ -n "$GEO_CURR" ]]   && kv "Local currency" "$GEO_CURR"

        echo ""
        if [[ "$GEO_PROXY" == "true" ]]; then
            kv_r "⚠ Proxy/VPN/Tor" "DETECTED"
        else
            ok "No proxy/VPN detected"
        fi
        if [[ "$GEO_HOSTING" == "true" ]]; then
            kv_y "⚠ Datacenter/Hosting" "YES (server IP)"
        else
            ok "Residential/business IP"
        fi
        if [[ "$GEO_MOBILE" == "true" ]]; then
            kv_y "Mobile connection" "YES"
        else
            kv "Mobile connection" "No"
        fi
    else
        fail "Could not reach ip-api.com"
    fi

    # Shodan (no API key — basic info)
    section "Shodan — Public info"
    local shodan
    shodan=$(curl -s --max-time 8 "https://internetdb.shodan.io/${IP}" 2>/dev/null)
    if [[ -n "$shodan" && "$shodan" != *"No information"* && "$shodan" != *"error"* ]]; then
        local ports vulns hostnames
        ports=$(echo "$shodan" | grep -oP '"ports":\[\K[^\]]+')
        vulns=$(echo "$shodan" | grep -oP '"vulns":\[\K[^\]]+' | tr -d '"')
        hostnames=$(echo "$shodan" | grep -oP '"hostnames":\[\K[^\]]+' | tr -d '"')
        [[ -n "$ports" ]]     && kv "Ports (Shodan)" "$ports"
        [[ -n "$hostnames" ]] && kv "Hostnames" "${hostnames:0:80}"
        if [[ -n "$vulns" ]]; then
            kv_r "⚠ CVEs detected" "$vulns"
        else
            ok "No public CVEs on Shodan"
        fi
    else
        info "No public data in Shodan InternetDB"
    fi
}

# ════════════════════════════════════════════════════════════════════
# MODULE: WHOIS
# ════════════════════════════════════════════════════════════════════
