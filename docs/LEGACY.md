# 🌐 DomainInfo v3.2.0 — OSINT & Security Audit Suite

> **Author:** [@kevxngg](https://github.com/kevxngg) (Kevin)  
> **Version:** 3.2.0  
> **Platforms:** Linux · Kali · Parrot · macOS · Termux · Kali NetHunter

A complete OSINT intelligence and security audit suite. It covers domains, public IPs, ISP/telecom companies, web applications and local WiFi networks.

---

## 🚀 Installation

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

## 📖 Usage

```bash
# Interactive menu (recommended — returns to the menu when done)
bash domaininfo.sh
domaininfo

# Direct CLI
domaininfo google.com
domaininfo -m quick 8.8.8.8
domaininfo -m full -j -t 20 example.com
domaininfo -f targets.txt -q

# Specialized modules, run directly
bash modules/isp_audit.sh  181.78.19.203   # ISP audit
bash modules/localnet.sh                    # Local WiFi network
bash modules/webapp.sh     example.com      # OWASP web app
```

### CLI flags

| Flag | Description |
|------|-------------|
| `-m <mode>` | `full` \| `quick` \| `ports` \| `web` |
| `-t <n>` | Threads for the subdomain scan (default: 15) |
| `-f <file>` | Batch: one target per line |
| `-s <module>` | Skip a module (e.g. `-s traceroute`) |
| `-j` | Export results to JSON |
| `-q` | Quiet mode (results only) |
| `-v` | Verbose (module debugging) |
| `-h` | Help |

---

## 🗂️ Modules — Main menu

| Option | Module | Description |
|--------|--------|-------------|
| **1** | Quick analysis | DNS + Geo + WHOIS |
| **2** | Port analysis | DNS + Geo + detailed Nmap |
| **3** | Web analysis | HTTP + WAF + SSL/TLS + Tech Stack |
| **4** | Full analysis | All modules (12 in total) |
| **5** | OWASP web audit | XSS, SQLi, Auth, Headers, Info Leak |
| **6** | ISP/Company audit | Company, equipment, CVEs, ports, risk |
| **7** | Local network / WiFi | Hosts, gateway, IoT, WiFi vectors |
| **8** | Batch | Multiple targets from a file |

---

## 🔍 Modules — domaininfo.sh (domain/IP analysis)

| # | Module | Description |
|---|--------|-------------|
| 1 | Full DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, DMARC, DNSSEC |
| 2 | Geolocation | Country, city, ISP, ASN, proxy/VPN/datacenter |
| 3 | WHOIS | Registrar, dates, organization, abuse emails |
| 4 | HTTP/HTTPS | Status, server, cookies, CMS detection |
| 5 | Ports | Nmap top 100 + versions + NSE scripts |
| 6 | Blacklists | 12 DNSBLs (Spamhaus, SpamCop, SORBS…) |
| 7 | Subdomains | Parallel brute force (250+ entries, configurable threads) |
| 8 | Traceroute | 15-hop network path, Python fallback |
| 9 | Web Recon | robots.txt, sitemap.xml, 90+ sensitive paths |
| 10 | WAF Detection | Cloudflare/Akamai/Imperva/AWS + security header score |
| 11 | SSL/TLS Vulns | TLS 1.0/1.1, POODLE/BEAST, cert expiry |
| 12 | Tech Stack | CMS, framework, exposed versions, CORS |

---

## 🌐 ISP/Network Audit module (`modules/isp_audit.sh`)

Audits the public IP of any Internet company (ISP, telephone carrier, corporate WiFi).

| # | Module | Description |
|---|--------|-------------|
| 1 | Identification | Company, ISP, ASN, country, city, coordinates + Shodan InternetDB |
| 2 | Equipment detection | HTTP/SSH/Telnet/SNMP banner grabbing → vendor + model |
| 3 | Ports + access | 30 critical ports with risk level and access test |
| 4 | Firewall | Firewall type inference + WAF + TTL-based OS detection |
| 5 | CVEs and vulns | TR-069, recursive DNS, open proxy, SNMP, WebFig without auth |
| 6 | Mitigations | Table of RouterOS commands and technical recommendations |
| 7 | Score | Risk score 0-100 with a visual bar + classified findings |

**Detected equipment:** MikroTik RouterOS, Huawei, Cisco IOS, Juniper JunOS, Ubiquiti, TP-Link, Tenda, ZyXEL, routers with Dropbear SSH.

**CVEs covered:**
- `CVE-2018-14847` — Winbox credential leak (MikroTik, CVSS 9.1)
- `CVE-2017-14462` — mass TR-069 RCE on CPEs/modems
- `CVE-2019-3978/3979` — MikroTik DNS cache poisoning

---

## 📶 Local Network / WiFi module (`modules/localnet.sh`)

| # | Module | Description |
|---|--------|-------------|
| 1 | Network info | Interface, local IP, gateway, SSID, BSSID, signal quality |
| 2 | Discovery | Parallel ping sweep or nmap -sn → online hosts with MAC and vendor |
| 3 | Gateway audit | Ports, fingerprinting, UPnP check, admin panel |
| 4 | IoT analysis | For each host: ports, detected device, default credentials |
| 5 | WiFi vulns | KRACK, PMKID, Deauth, Evil Twin, WPS brute force, ARP spoofing |
| 6 | Mitigations | Full table of actions with priority |
| 7 | Score | Risk score 0-100 with findings |

---

## 🕸️ Web App Audit module (`modules/webapp.sh`)

Based on the OWASP Top 10.

| # | Module | Description |
|---|--------|-------------|
| 1 | Reconnaissance | Tech stack, CMS, server, cookies, exposed versions |
| 2 | Security Headers | HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy, CORS |
| 3 | SQLi | SQL injection indicators in GET parameters and forms |
| 4 | XSS | Detection of unsanitized parameter reflection |
| 5 | Sensitive files | 90+ paths: `.git/`, `.env`, `phpinfo.php`, `backup.sql`… |
| 6 | Authentication | CSRF tokens, HTTP Basic Auth, access to protected paths |
| 7 | Info Leak | Private IPs, stack traces, debug info, versions in headers |
| 8 | WordPress | REST API users, xmlrpc.php, readme.html, debug.log |

---

## 📁 Project structure

```
domaininfo/
├── domaininfo.sh          # Main script — menu + 12 modules
├── install.sh             # Automatic installer
├── report.py              # HTML report generator
├── traceroute.py          # Python traceroute fallback
├── README.md
├── LICENSE
├── .gitignore
├── modules/
│   ├── dns.sh             # Full DNS
│   ├── geo.sh             # Geolocation
│   ├── whois.sh           # WHOIS
│   ├── http.sh            # HTTP/HTTPS analysis
│   ├── ports.sh           # Port scanning
│   ├── blacklist.sh       # DNSBL checks
│   ├── subdomains.sh      # Subdomain bruteforce
│   ├── traceroute.sh      # Network route
│   ├── extra.sh           # Extra web recon
│   ├── waf.sh             # WAF detection + headers
│   ├── ssl.sh             # SSL/TLS vulnerabilities
│   ├── tech.sh            # Tech stack detection
│   ├── summary.sh         # Executive summary
│   ├── isp_audit.sh       # ISP/Network device auditor ★
│   ├── localnet.sh        # Local network/WiFi scanner ★
│   └── webapp.sh          # Web app OWASP auditor ★
├── wordlists/
│   ├── subdomains.txt     # 250+ subdomains
│   └── paths.txt          # 90+ sensitive paths
└── logs/
    └── .gitkeep
```

---

## 📋 Generated reports

- **`.txt`** — Plain log in `logs/` at the end of each scan
- **`.json`** — Structured data (with the `-j` flag)
- **`.html`** — Visual report (if `python3` is available)

---

## ⚠️ Legal disclaimer

Use **only** on systems with **explicit written authorization**.  
Unauthorized use violates **Law 1273/2009** (Colombia) and equivalent laws.  
The author is not responsible for misuse.

---

<div align="center">

**Made with ❤️ by [@kevxngg](https://github.com/kevxngg) · Kevin**

</div>
