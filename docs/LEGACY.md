# 🌐 DomainInfo v3.2.0 — OSINT & Security Audit Suite

> **Autor:** [@kevxngg](https://github.com/kevxngg) (Kevin)  
> **Versión:** 3.2.0  
> **Plataformas:** Linux · Kali · Parrot · macOS · Termux · Kali NetHunter

Suite completa de inteligencia OSINT y auditoría de seguridad. Cubre dominios, IPs públicas, empresas ISP/telecomunicaciones, aplicaciones web y redes locales WiFi.

---

## 🚀 Instalación

```bash
git clone https://github.com/kevxngg/domaininfo.git
cd domaininfo && bash install.sh
```

### Termux / Kali NetHunter (Android)
```bash
pkg update && pkg install git
git clone https://github.com/kevxngg/domaininfo.git
cd domaininfo && bash install.sh
```

---

## 📖 Uso

```bash
# Menú interactivo (recomendado — vuelve al menú al terminar)
bash domaininfo.sh
domaininfo

# CLI directo
domaininfo google.com
domaininfo -m quick 8.8.8.8
domaininfo -m full -j -t 20 example.com
domaininfo -f targets.txt -q

# Módulos especializados directos
bash modules/isp_audit.sh  181.78.19.203   # Auditoría ISP
bash modules/localnet.sh                    # Red local WiFi
bash modules/webapp.sh     example.com      # Web app OWASP
```

### Flags CLI

| Flag | Descripción |
|------|-------------|
| `-m <modo>` | `full` \| `quick` \| `ports` \| `web` |
| `-t <n>` | Hilos para subdomain scan (default: 15) |
| `-f <archivo>` | Batch: un objetivo por línea |
| `-s <módulo>` | Saltar módulo (ej: `-s traceroute`) |
| `-j` | Exportar resultados a JSON |
| `-q` | Modo silencioso (solo resultados) |
| `-v` | Verbose (debug de módulos) |
| `-h` | Ayuda |

---

## 🗂️ Módulos — Menú Principal

| Opción | Módulo | Descripción |
|--------|--------|-------------|
| **1** | Análisis rápido | DNS + Geo + WHOIS |
| **2** | Análisis de puertos | DNS + Geo + Nmap detallado |
| **3** | Análisis web | HTTP + WAF + SSL/TLS + Tech Stack |
| **4** | Análisis completo | Todos los módulos (12 en total) |
| **5** | Auditoría web OWASP | XSS, SQLi, Auth, Headers, Info Leak |
| **6** | Auditoría ISP/Empresa | Empresa, equipo, CVEs, puertos, riesgo |
| **7** | Red local / WiFi | Hosts, gateway, IoT, vectores WiFi |
| **8** | Batch | Múltiples objetivos desde archivo |

---

## 🔍 Módulos — domaininfo.sh (análisis de dominio/IP)

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | DNS Completo | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, DMARC, DNSSEC |
| 2 | Geolocalización | País, ciudad, ISP, ASN, proxy/VPN/datacenter |
| 3 | WHOIS | Registrar, fechas, organización, emails de abuso |
| 4 | HTTP/HTTPS | Status, servidor, cookies, CMS detection |
| 5 | Puertos | Nmap top 100 + versiones + scripts NSE |
| 6 | Blacklists | 12 DNSBL (Spamhaus, SpamCop, SORBS…) |
| 7 | Subdominios | Brute-force paralelo (250+ entradas, configurable hilos) |
| 8 | Traceroute | Ruta de red 15 saltos, fallback Python |
| 9 | Web Recon | robots.txt, sitemap.xml, 90+ rutas sensibles |
| 10 | WAF Detection | Cloudflare/Akamai/Imperva/AWS + score de security headers |
| 11 | SSL/TLS Vulns | TLS 1.0/1.1, POODLE/BEAST, cert expiry |
| 12 | Tech Stack | CMS, framework, versiones expuestas, CORS |

---

## 🌐 Módulo ISP/Network Audit (`modules/isp_audit.sh`)

Para auditar la IP pública de cualquier empresa de internet (ISP, operador de telefonía, WiFi corporativo).

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | Identificación | Empresa, ISP, ASN, país, ciudad, coordenadas + Shodan InternetDB |
| 2 | Detección de equipo | Banner grabbing HTTP/SSH/Telnet/SNMP → Fabricante + modelo |
| 3 | Puertos + acceso | 30 puertos críticos con nivel de riesgo y test de acceso |
| 4 | Firewall | Inferencia de tipo de firewall + WAF + TTL-based OS detection |
| 5 | CVEs y vulns | TR-069, DNS recursivo, proxy abierto, SNMP, WebFig sin auth |
| 6 | Mitigaciones | Tabla de comandos RouterOS y recomendaciones técnicas |
| 7 | Puntuación | Risk score 0-100 con barra visual + hallazgos clasificados |

**Equipos que detecta:** MikroTik RouterOS, Huawei, Cisco IOS, Juniper JunOS, Ubiquiti, TP-Link, Tenda, ZyXEL, routers con Dropbear SSH.

**CVEs cubiertos:**
- `CVE-2018-14847` — Winbox credential leak (MikroTik, CVSS 9.1)
- `CVE-2017-14462` — TR-069 RCE masivo en CPEs/módems
- `CVE-2019-3978/3979` — DNS cache poisoning MikroTik

---

## 📶 Módulo Red Local / WiFi (`modules/localnet.sh`)

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | Info de red | Interfaz, IP local, gateway, SSID, BSSID, calidad señal |
| 2 | Descubrimiento | Ping sweep paralelo o nmap -sn → hosts online con MAC y vendor |
| 3 | Auditoría gateway | Puertos, fingerprinting, UPnP check, panel admin |
| 4 | Análisis IoT | Por cada host: puertos, dispositivo detectado, credenciales default |
| 5 | Vulns WiFi | KRACK, PMKID, Deauth, Evil Twin, WPS brute force, ARP spoofing |
| 6 | Mitigaciones | Tabla completa de acciones con prioridad |
| 7 | Puntuación | Risk score 0-100 con hallazgos |

---

## 🕸️ Módulo Web App Audit (`modules/webapp.sh`)

Basado en OWASP Top 10.

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | Reconocimiento | Stack tech, CMS, server, cookies, versiones expuestas |
| 2 | Security Headers | HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy, CORS |
| 3 | SQLi | Indicadores de inyección SQL en parámetros GET y formularios |
| 4 | XSS | Detección de reflexión de parámetros sin sanitizar |
| 5 | Archivos sensibles | 90+ rutas: `.git/`, `.env`, `phpinfo.php`, `backup.sql`… |
| 6 | Autenticación | CSRF tokens, HTTP Basic Auth, acceso a rutas protegidas |
| 7 | Info Leak | IPs privadas, stack traces, debug info, versiones en headers |
| 8 | WordPress | REST API users, xmlrpc.php, readme.html, debug.log |

---

## 📁 Estructura del proyecto

```
domaininfo/
├── domaininfo.sh          # Script principal — menú + 12 módulos
├── install.sh             # Instalador automático
├── report.py              # Generador de reportes HTML
├── traceroute.py          # Fallback Python traceroute
├── README.md
├── LICENSE
├── .gitignore
├── modules/
│   ├── dns.sh             # DNS completo
│   ├── geo.sh             # Geolocalización
│   ├── whois.sh           # WHOIS
│   ├── http.sh            # HTTP/HTTPS analysis
│   ├── ports.sh           # Port scanning
│   ├── blacklist.sh       # DNSBL checks
│   ├── subdomains.sh      # Subdomain bruteforce
│   ├── traceroute.sh      # Network route
│   ├── extra.sh           # Web recon extra
│   ├── waf.sh             # WAF detection + headers
│   ├── ssl.sh             # SSL/TLS vulnerabilities
│   ├── tech.sh            # Tech stack detection
│   ├── summary.sh         # Executive summary
│   ├── isp_audit.sh       # ISP/Network device auditor ★
│   ├── localnet.sh        # Local network/WiFi scanner ★
│   └── webapp.sh          # Web app OWASP auditor ★
├── wordlists/
│   ├── subdomains.txt     # 250+ subdominios
│   └── paths.txt          # 90+ rutas sensibles
└── logs/
    └── .gitkeep
```

---

## 📋 Reportes generados

- **`.txt`** — Log plano en `logs/` al finalizar cada escaneo
- **`.json`** — Datos estructurados (con flag `-j`)
- **`.html`** — Reporte visual (si `python3` disponible)

---

## ⚠️ Disclaimer legal

Usar **solo** en sistemas con **autorización explícita por escrito**.  
El uso no autorizado viola la **Ley 1273/2009** (Colombia) y leyes equivalentes.  
El autor no se responsabiliza por mal uso.

---

<div align="center">

**Hecho con ❤️ por [@kevxngg](https://github.com/kevxngg) · Kevin**

</div>
