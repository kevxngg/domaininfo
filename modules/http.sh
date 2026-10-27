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

module_http() {
    is_ip "$TARGET" && { info "Objetivo es IP — omitiendo análisis HTTP de dominio"; return; }
    header "4 ▸ HTTP/HTTPS — CABECERAS Y TECNOLOGÍA"

    local headers status_code server powered content_type
    local hsts csp cors cdn redir cookie_h

    section "Análisis de cabeceras"
    local working_proto=""
    for PROTO in https http; do
        local h
        h=$(curl -sI --max-time 10 --location --max-redirs 5 \
            -A "Mozilla/5.0 (compatible; domaininfo/2.0)" \
            "${PROTO}://${DOMAIN}" 2>/dev/null)
        if [[ -n "$h" ]]; then
            working_proto="$PROTO"
            status_code=$(echo "$h" | head -1 | awk '{print $2}')
            server=$(echo "$h"       | grep -i "^Server:"         | head -1 | sed 's/.*: *//' | xargs)
            powered=$(echo "$h"      | grep -i "^X-Powered-By:"   | head -1 | sed 's/.*: *//' | xargs)
            content_type=$(echo "$h" | grep -i "^Content-Type:"   | head -1 | sed 's/.*: *//' | xargs)
            hsts=$(echo "$h"         | grep -i "Strict-Transport" | head -1)
            csp=$(echo "$h"          | grep -i "Content-Security" | head -1)
            cors=$(echo "$h"         | grep -i "Access-Control"   | head -1)
            redir=$(echo "$h"        | grep -i "^Location:"       | head -1 | sed 's/.*: *//' | xargs)
            cdn=$(echo "$h"          | grep -iE "^(CF-Ray|X-Cache|Via|X-Amz|X-Azure|X-Vercel|Fly-Request|X-Served-By):" | head -5)
            cookie_h=$(echo "$h"     | grep -i "^Set-Cookie:"     | head -3)
            break
        fi
    done

    if [[ -z "$working_proto" ]]; then
        fail "No se pudo conectar al servidor web"
        return
    fi

    kv "Protocolo"       "${working_proto^^}"
    kv "HTTP Status"     "${status_code:-?}"
    kv "Servidor"        "${server:-N/A}"
    kv "X-Powered-By"   "${powered:-N/A}"
    kv "Content-Type"   "${content_type:-N/A}"
    [[ -n "$redir" ]] && kv_y "Redirección" "$redir"

    echo ""
    section "Headers de Seguridad"
    [[ -n "$hsts" ]] && ok "HSTS: $hsts" || kv_r "HSTS" "No configurado"
    [[ -n "$csp"  ]] && ok "CSP presente" || kv_r "CSP" "No configurada (XSS posible)"
    [[ -n "$cors" ]] && kv_y "CORS" "$(echo "$cors" | head -c 80)"

    local xframe xcto xss
    xframe=$(curl -sI --max-time 8 "${working_proto}://${DOMAIN}" 2>/dev/null | grep -i "X-Frame-Options" | head -1)
    xcto=$(curl -sI --max-time 8 "${working_proto}://${DOMAIN}" 2>/dev/null | grep -i "X-Content-Type-Options" | head -1)
    xss=$(curl -sI --max-time 8 "${working_proto}://${DOMAIN}" 2>/dev/null | grep -i "X-XSS-Protection" | head -1)

    [[ -n "$xframe" ]] && ok "X-Frame-Options presente" || kv_r "X-Frame-Options" "Ausente (clickjacking posible)"
    [[ -n "$xcto"   ]] && ok "X-Content-Type-Options presente" || kv_r "X-Content-Type-Options" "Ausente"
    [[ -n "$xss"    ]] && ok "X-XSS-Protection presente" || info "X-XSS-Protection no reportado"

    section "CDN / Infraestructura detectada"
    if [[ -n "$cdn" ]]; then
        while IFS= read -r l; do
            [[ -n "$l" ]] && kv_y "CDN/Cloud" "$l"
        done <<< "$cdn"
        echo "$cdn" | grep -qi "cf-ray"           && ok "Cloudflare CDN confirmado"
        echo "$cdn" | grep -qi "x-amz\|amazon"   && ok "AWS / Amazon CloudFront detectado"
        echo "$cdn" | grep -qi "x-azure"          && ok "Microsoft Azure detectado"
        echo "$cdn" | grep -qi "x-vercel"         && ok "Vercel detectado"
    else
        info "No se detectó CDN conocido"
    fi

    section "Cookies"
    if [[ -n "$cookie_h" ]]; then
        while IFS= read -r l; do
            [[ -n "$l" ]] && echo -e "  ${DIM}$l${NC}"
            echo "$l" | grep -qi "secure"   && ok "  → Cookie con flag Secure"
            echo "$l" | grep -qi "httponly" && ok "  → Cookie con flag HttpOnly"
            echo "$l" | grep -qi "samesite" || kv_r "  → Cookie sin SameSite" "posible CSRF"
        done <<< "$cookie_h"
    else
        info "Sin cookies en respuesta inicial"
    fi

    # ── SSL/TLS
    section "Certificado SSL/TLS"
    if command -v openssl &>/dev/null; then
        local ssl_raw
        ssl_raw=$(echo | timeout 8 openssl s_client \
            -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null </dev/null)
        local ssl_info
        ssl_info=$(echo "$ssl_raw" | openssl x509 -noout -text 2>/dev/null)

        if [[ -n "$ssl_info" ]]; then
            local issuer subject not_before not_after sans sig_alg tls_ver
            issuer=$(echo "$ssl_info"     | grep "Issuer:"          | head -1 | sed 's/.*Issuer: //')
            subject=$(echo "$ssl_info"    | grep "Subject:"         | head -1 | sed 's/.*Subject: //')
            not_before=$(echo "$ssl_info" | grep "Not Before"       | head -1 | sed 's/.*Not Before: //')
            not_after=$(echo "$ssl_info"  | grep "Not After"        | head -1 | sed 's/.*Not After : //')
            sans=$(echo "$ssl_info"       | grep -A2 "Subject Alt"  | tail -1 | sed 's/DNS://g;s/, /\n  /g' | head -c 200)
            sig_alg=$(echo "$ssl_info"    | grep "Signature Algorithm" | head -1 | awk '{print $NF}')
            tls_ver=$(echo "$ssl_raw"     | grep "Protocol  :"      | head -1 | awk '{print $NF}')

            kv "Subject (CN)"    "${subject:-N/A}"
            kv "Emisor (CA)"     "${issuer:-N/A}"
            kv "Válido desde"    "${not_before:-N/A}"
            kv "Válido hasta"    "${not_after:-N/A}"
            kv "Algoritmo firma" "${sig_alg:-N/A}"
            kv "TLS versión"     "${tls_ver:-N/A}"
            if [[ -n "$sans" ]]; then
                echo -e "  ${C}SANs (dominios cubiertos):${NC}"
                echo "$sans" | while IFS= read -r s; do
                    [[ -n "$s" ]] && echo -e "    ${DIM}$s${NC}"
                done
            fi

            # Días de validez restante
            local exp_epoch now_epoch days_ssl
            exp_epoch=$(date -d "${not_after}" +%s 2>/dev/null)
            now_epoch=$(date +%s)
            if [[ -n "$exp_epoch" ]]; then
                days_ssl=$(( (exp_epoch - now_epoch) / 86400 ))
                if [[ $days_ssl -lt 14 ]]; then
                    kv_r "⚠ Cert expira en" "${days_ssl} días"
                elif [[ $days_ssl -lt 30 ]]; then
                    kv_y "Cert expira en" "${days_ssl} días"
                else
                    ok "Cert válido por ${days_ssl} días más"
                fi
            fi
        else
            kv_r "SSL/TLS" "No se pudo obtener certificado"
        fi
    else
        warn "openssl no disponible"
    fi

    # ── Tecnologías detectadas en HTML
    section "Detección de tecnologías (HTML)"
    local body
    body=$(curl -sL --max-time 12 -A "Mozilla/5.0" "${working_proto}://${DOMAIN}" 2>/dev/null | head -c 20000)
    if [[ -n "$body" ]]; then
        echo "$body" | grep -qi "wp-content\|wordpress" && kv_y "CMS" "WordPress"
        echo "$body" | grep -qi "Shopify"               && kv_y "Plataforma" "Shopify"
        echo "$body" | grep -qi "drupal"                && kv_y "CMS" "Drupal"
        echo "$body" | grep -qi "joomla"                && kv_y "CMS" "Joomla"
        echo "$body" | grep -qi "wix.com"               && kv_y "Plataforma" "Wix"
        echo "$body" | grep -qi "squarespace"           && kv_y "Plataforma" "Squarespace"
        echo "$body" | grep -qi "webflow"               && kv_y "Plataforma" "Webflow"
        echo "$body" | grep -qi "react\|__react"        && kv_y "JS Framework" "React"
        echo "$body" | grep -qi "ng-version\|angular"  && kv_y "JS Framework" "Angular"
        echo "$body" | grep -qi "vue.js\|__vue"        && kv_y "JS Framework" "Vue.js"
        echo "$body" | grep -qi "next.js\|__next"      && kv_y "JS Framework" "Next.js"
        echo "$body" | grep -qi "gtag\|google-analytics\|ga.js" && kv "Analytics" "Google Analytics"
        echo "$body" | grep -qi "fbq\|connect.facebook" && kv "Pixel" "Facebook Pixel"
        echo "$body" | grep -qi "hotjar"                && kv "Heatmap" "Hotjar"
        echo "$body" | grep -qi "jquery"                && kv "Librería" "jQuery"
        echo "$body" | grep -qi "bootstrap"             && kv "CSS" "Bootstrap"
        echo "$body" | grep -qi "tailwind"              && kv "CSS" "TailwindCSS"
        echo "$body" | grep -qi "recaptcha"             && ok "reCAPTCHA presente"
        # Title
        local title
        title=$(echo "$body" | grep -oP '(?i)(?<=<title>)[^<]+' | head -1 | xargs)
        [[ -n "$title" ]] && kv "Título página" "$title"
        # Generator
        local gen
        gen=$(echo "$body" | grep -oP '(?i)content="[^"]*generator[^"]*"\s+name="generator"|name="generator"\s+content="\K[^"]+' | head -1)
        [[ -n "$gen" ]] && kv "Generator meta" "$gen"
    fi
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO: PUERTOS
# ════════════════════════════════════════════════════════════════════
