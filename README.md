# DomainInfo 6.0 — Security Suite

Security auditing for **domains, infrastructure and web applications** on **Termux, Kali/Linux, macOS and Windows**, by [@kevxngg](https://github.com/kevxngg).

The portable core needs only **Python 3.10+ and its standard library**: no pip, root, Bash, Nmap or compilers. Everything else — external scanners, the browser engine, the web dashboard — is optional and the tool keeps working without it. The classic Bash modules from version 3 are still included.

| Area | What you get |
|---|---|
| OSINT and infrastructure | DNS (own resolver, DoH fallback), RDAP, ASN, TLS in depth, subdomains from Certificate Transparency and takeover checks, domain history, lookalike domains, mail security (SPF, DMARC, DKIM, MTA-STS) |
| Web application security | Passive review of a **full URL** (path and query kept): forms, CSRF, cookies, CSP, clickjacking, CORS, redirects, technical errors and exposed secrets |
| Sessions and APIs | Authenticated session audit with authorized test accounts, OpenAPI/Swagger analysis, OWASP ZAP passive alerts, pages rendered with Playwright |
| External tools | Safe runners for Nmap, Nuclei, Subfinder, Amass, dnsx, httpx, WhatWeb, SSLyze, testssl.sh, Semgrep, Bandit, pip-audit, Trivy and Gitleaks |
| Vulnerability intelligence | OSV, NVD and CISA KEV correlation with cache and rate limits; a name-only match is never "confirmed" |
| Reporting | JSON, TXT, Markdown, HTML, CSV, executive and technical PDF; Security / Coverage / Confidence scores; evidence for every finding |
| Security Center | Local web dashboard (projects, scope, history, comparisons, remediation status, exports) |

> Use DomainInfo only on systems you own or are authorized to assess. Active tools and authenticated tests are disabled unless you enable them explicitly.

## Interactive menu

Own ASCII logo, cyan/blue colors, audit and tool panels, and an adaptive layout: two columns on desktop and stacked panels on narrow terminals.

![DomainInfo menu on a desktop terminal](docs/assets/menu-desktop.png)

Compact view: [menu on a narrow terminal](docs/assets/menu-mobile.png). The images were rendered from the menu output; the final colors and font depend on your terminal.

```bash
domaininfo
# Or from the project folder:
python3 domaininfo.py
bash domaininfo.sh
```

On Windows: `python domaininfo.py` or `.\domaininfo.cmd`. You can also open it explicitly with `python3 domaininfo.py --interactive`.

In a real terminal just **press the option's key**, no ENTER needed (`DOMAININFO_ENTER=1` brings back number + ENTER, also used in lists of more than nine items); **0 goes back**. CTRL+C cancels the current action. Colors are disabled with `NO_COLOR`, a basic terminal or redirected output. The menu includes every audit mode, several targets from a file, recent reports, preferences (timeouts, connections, formats and **language**), computer diagnostics, the **optional tools assistant** (`t`), the **Security Center** (`x`) and the classic Bash audits.

### Language

DomainInfo speaks **English** by default. Spanish is built in: `--lang es`, `DOMAININFO_LANG=es` or *Preferences → Language* in the menu. JSON keys and enumerated values (severities, statuses…) are always English, so scripts work the same in both languages ([docs/I18N.md](docs/I18N.md)).

## Installation and first steps

You only need **Python 3.10 or newer** and **Git**. Pick your system and follow the steps in order. Every system ends the same way: `--doctor` to check, the menu, a first audit, Spanish if you want it, and the optional Security Center.

| | Windows 10/11 | macOS | Linux / Kali | Termux (Android) |
|---|---|---|---|---|
| Terminal | PowerShell | Terminal (zsh) | Terminal (bash) | Termux |
| Run it as | `python domaininfo.py` or `.\domaininfo.cmd` | `domaininfo` (after `install.sh`) | `domaininfo` (after `install.sh`) | `domaininfo` (after `install.sh`) |
| Language | `setx DOMAININFO_LANG es` | `~/.zshrc` | `~/.bashrc` | `~/.bashrc` |

### Windows 10/11 (PowerShell)

1. **Install Python and Git** (skip what you already have). Either with winget:

   ```powershell
   winget install Python.Python.3.13
   winget install Git.Git
   ```

   or from [python.org](https://www.python.org/downloads/) (tick **"Add python.exe to PATH"**) and [git-scm.com](https://git-scm.com/download/win). Then **close PowerShell and open a new window**.
2. **Check Python**: `python --version` must print 3.10 or newer. If it opens the Microsoft Store instead, use `py` in place of `python` in every command below (or turn off *Settings → Apps → Advanced app settings → App execution aliases → python.exe*).
3. **Download DomainInfo** into your user folder:

   ```powershell
   cd $HOME
   git clone https://github.com/kevxngg/domaininfo.git
   cd domaininfo
   ```

4. **Check that everything works** (no network scan): `python domaininfo.py --doctor`
5. **Open the menu**: `python domaininfo.py` — press the key of an option (no ENTER); `0` goes back or exits.
6. **Run audits directly**:

   ```powershell
   python domaininfo.py example.com                              # quick analysis
   python domaininfo.py -m web example.com --open                # website + TLS, opens the HTML report
   python domaininfo.py -m webapp --url https://example.com/login
   python domaininfo.py --tools                                  # optional external tools
   ```

   Reports are saved in the `logs` folder inside `domaininfo`. `.\domaininfo.cmd` works the same as `python domaininfo.py`.
7. **Spanish**: add `--lang es` to any command, or make it permanent with `setx DOMAININFO_LANG es` and open a new PowerShell window.
8. **Security Center (optional)**:

   ```powershell
   python -m pip install fastapi uvicorn
   python domaininfo.py --serve
   ```

   Your browser opens `http://127.0.0.1:8765` with a private token. Keep that PowerShell window open while you use it and press **CTRL+C** to stop it. Save CLI audits into it with `--store "My project"`.
9. **Update**: `cd $HOME\domaininfo` and then `python domaininfo.py --update` (it runs `git pull`).

You do not need `install.ps1` (it only checks Python) and you never need to change the PowerShell execution policy.

### macOS

1. **Install the tools**: open *Terminal* and run `xcode-select --install` (Git) and, if you use [Homebrew](https://brew.sh), `brew install python`. Otherwise install Python from [python.org](https://www.python.org/downloads/macos/). Check with `python3 --version` (3.10 or newer).
2. **Download and install**:

   ```bash
   cd ~
   git clone https://github.com/kevxngg/domaininfo.git
   cd domaininfo
   bash install.sh
   ```

   The installer creates the `domaininfo` command in `~/.local/bin`. If `domaininfo` is "not found", run once:
   `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc`
3. **Check**: `domaininfo --doctor`
4. **Use it**: `domaininfo` (menu), `domaininfo example.com`, `domaininfo -m web example.com --open`. Reports go to `logs` in the folder where you run it.
5. **Spanish**: `--lang es`, or permanently `echo 'export DOMAININFO_LANG=es' >> ~/.zshrc && source ~/.zshrc`.
6. **Security Center (optional)**: Homebrew's Python does not allow global `pip install`, so use a virtual environment inside the folder:

   ```bash
   cd ~/domaininfo
   python3 -m venv .venv
   .venv/bin/pip install fastapi uvicorn
   .venv/bin/python domaininfo.py --serve
   ```

7. **Update**: `domaininfo --update`.

The portable core does not need the system's old Bash 3.2 or GNU tools.

### Linux (Kali, Ubuntu, Debian, Fedora, Arch…)

1. **Install the tools** if they are missing:
   - Debian/Ubuntu/Kali: `sudo apt update && sudo apt install -y git python3 python3-venv`
   - Fedora: `sudo dnf install -y git python3`
   - Arch: `sudo pacman -S --needed git python`
2. **Download and install** (as your normal user, **not** with sudo):

   ```bash
   cd ~
   git clone https://github.com/kevxngg/domaininfo.git
   cd domaininfo
   bash install.sh
   ```

   The command is created in `~/.local/bin`. If `domaininfo` is "not found":
   `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
3. **Check**: `domaininfo --doctor`
4. **Use it**: `domaininfo` (menu), `domaininfo example.com`, `domaininfo -m full example.com`.
5. **Spanish**: `--lang es`, or permanently `echo 'export DOMAININFO_LANG=es' >> ~/.bashrc && source ~/.bashrc`.
6. **Security Center (optional)**: recent distributions block global `pip install` ("externally-managed-environment"), so use a virtual environment:

   ```bash
   cd ~/domaininfo
   python3 -m venv .venv
   .venv/bin/pip install fastapi uvicorn
   .venv/bin/python domaininfo.py --serve
   ```

7. **Classic Bash modules (optional)**: `bash install.sh --legacy` installs curl, dig, whois, Nmap, OpenSSL… with your package manager (it asks for sudo for that step only). Then `bash domaininfo.sh --legacy`.
8. **Update**: `domaininfo --update`.

### Termux (Android)

1. Install **Termux** (the F-Droid or GitHub builds are the recommended ones), open it and run:

   ```bash
   pkg update
   pkg install git python
   ```

   If `pkg` fails, choose another mirror with `termux-change-repo`.
2. **Download and install** inside your Termux home (not in Android shared storage):

   ```bash
   cd "$HOME"
   git clone https://github.com/kevxngg/domaininfo.git
   cd domaininfo
   bash install.sh
   ```

   The command goes to `$PREFIX/bin`; no root or sudo is used.
3. **Check**: `domaininfo --doctor`
4. **Use it**: `domaininfo` (the menu adapts to the narrow screen), `domaininfo example.com`.
5. **Spanish**: `--lang es`, or permanently `echo 'export DOMAININFO_LANG=es' >> ~/.bashrc` and reopen Termux.
6. **Classic Bash modules (optional)**: `bash install.sh --legacy` installs their packages with `pkg`.
7. **Update**: `domaininfo --update`.

The Security Center needs FastAPI, whose dependencies have to be compiled on Android; it is not tested on Termux. Everything else works with Termux's Python alone.

### Other ways to install

- **As a global command with pipx** (any system): `pipx install git+https://github.com/kevxngg/domaininfo`, or with the Security Center: `pipx install "domaininfo[server] @ git+https://github.com/kevxngg/domaininfo"`. Then just `domaininfo --serve`. Update with `pipx upgrade domaininfo`.
- **Single file**: download `domaininfo.pyz` from the [latest release](https://github.com/kevxngg/domaininfo/releases/latest) and run `python domaininfo.pyz example.com` (Windows) or `python3 domaininfo.pyz example.com`.

### Optional extras

| Extra | Install | Used by |
|---|---|---|
| Security Center | `pip install fastapi uvicorn` (or `domaininfo[server]`) | `--serve`, menu key `x` |
| Browser rendering | `pip install playwright` then `python -m playwright install chromium` | `-m browser` |
| External tools | see `--tools` (Nmap, Nuclei, Semgrep, Trivy…) | `--tool`, `-m code` |
| OWASP ZAP | [zaproxy.org](https://www.zaproxy.org/download/), started by you in daemon mode | `-m zap` |

### Common mistakes

| You see | Fix |
|---|---|
| `unrecognized arguments: --server` | The option is `--serve` |
| `domaininfo: command not found` | Run it as `python3 domaininfo.py` from the folder, or add `~/.local/bin` to PATH (steps above) |
| `python` opens the Microsoft Store | Use `py`, or disable the *App execution aliases* for Python |
| `externally-managed-environment` when using pip | Use the virtual environment (`python3 -m venv .venv`) or pipx |
| `The Security Center needs the optional web extra` | Install FastAPI and Uvicorn in the same Python you run DomainInfo with |
| Output in English | Add `--lang es` or set `DOMAININFO_LANG=es` |

## Audit modes

| Mode | Menu key | What it does |
|---|---|---|
| `quick` (default) | 1 | Addresses, DNS records (MX, NS, TXT, SOA, CAA, CNAME), DNSSEC and RDAP registration |
| `web` | 2 | DNS, HTTP, TLS in depth and technology fingerprint with a security-header grade |
| `ports` | 3 | DNS and concurrent TCP connections, no raw sockets |
| `full` | 4 | Everything general: DNS, RDAP, ASN, web, TLS, technologies, mail, subdomains, history, ports and traceroute |
| `mikrotik` | 5 | RouterOS 6/7: management services, version and recent security advisories |
| `mail` | e | SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI, with a grade and whether the domain can be spoofed |
| `recon` | s | OSINT: subdomains (Certificate Transparency), takeover candidates, network, technologies and history |
| `brand` | p | Registered lookalike domains (typos, homoglyphs, other TLDs) and whether they receive mail |
| `webapp` | w | Passive security review of one full URL |
| `session` | u | Authenticated session audit with an authorization file |
| `apispec` | i | OpenAPI/Swagger analysis |
| `zap` | z | Passive alerts from the OWASP ZAP you run locally |
| `browser` | b | The page rendered with JavaScript in headless Chromium (Playwright) |
| `code` | c | Semgrep, Bandit, pip-audit, Trivy and Gitleaks on a local project folder |

```bash
python3 domaininfo.py example.com
python3 domaininfo.py -m web example.com
python3 domaininfo.py -m ports --ports 22,80,443 --timeout 2 -t 8 127.0.0.1
python3 domaininfo.py -m full -s ports -s traceroute example.com
python3 domaininfo.py -m mail example.com            # can the domain be spoofed?
python3 domaininfo.py -m recon --brute example.com
python3 domaininfo.py -m brand mybrand.com           # domains imitating your brand
python3 domaininfo.py -f domains.txt -m full         # reports + infrastructure map + inventory + CSV
python3 domaininfo.py --help
```

On Windows replace `python3` with `python` or `py -3`.

## Web application security

`-m webapp` audits **exactly the URL you give**: scheme, host, port, path and parameters are kept (`/login` is not replaced by `/`). Only GET requests are made; forms and credentials are never submitted.

```bash
python3 domaininfo.py -m webapp --url https://example.com/login
python3 domaininfo.py -m webapp https://app.example.com:8443/admin?tab=1
python3 domaininfo.py -m webapp --url https://app.example.com/ --scope auth.example.com,*.cdn.example.com
python3 domaininfo.py -m webapp --url http://127.0.0.1:8000/login   # your app in development
```

- **Forms**: method and action, user and password fields, passwords sent by GET or over HTTP.
- **CSRF**: a visible token (direct evidence), a token in `<meta>` or SameSite cookies (alternative protection), or **pending verification** when there is no evidence either way. A form without a token is never declared vulnerable.
- **Cookies**: `Secure`, `HttpOnly`, `SameSite` (values are never stored).
- **Headers**: HSTS, CSP analysis (`unsafe-inline`, `unsafe-eval`, wildcards, `object-src`, `base-uri`), clickjacking, `Referrer-Policy`, `Permissions-Policy`, `nosniff`, version disclosure.
- **CORS**: one request with a made-up `Origin` to see whether it is reflected and allows credentials.
- **Redirects** are followed only inside the scope (max. 5); HTTPS → HTTP downgrades are flagged.
- **Technical errors** (Python, Java, PHP, .NET, Node, SQL traces) and **exposed secrets** (private keys, cloud keys, tokens), always redacted.
- **Comparison with the site root**, which proves the requested page is the one that was audited.

Add `-m browser` to see the page after JavaScript runs (dynamic forms, cookies set by scripts, mixed content) and `-m zap` to import the passive alerts of a ZAP daemon you run on this computer (`--zap-url http://127.0.0.1:8080`, key in `ZAP_API_KEY`; never an active scan).

## Sessions and APIs

**Authenticated session audit** (`-m session --auth-file scope.json`) — only for systems you are authorized to test, with **test accounts**. The JSON authorization file lists the authorized targets, who authorized the test, a time window, request and login-attempt limits, the roles and the **names of the environment variables** that hold each account's credentials (credentials are never written in the file, the report or the logs). It checks the login flow, session cookies before and after login (fixation), cookie flags and expiry, logout and token invalidation, access between test roles, user-enumeration messages, MFA presence and a capped lockout check (3 attempts by default, never more than 5, stopping at the first lockout signal). No brute force, no wordlists, no evasion. Format and examples: [docs/AUTHENTICATED_AUDIT.md](docs/AUTHENTICATED_AUDIT.md).

**API analysis** (`-m apispec --url https://api.example.com/`) reads the OpenAPI/Swagger document (given URL or the usual locations) and reports documented endpoints, `http://` servers, missing security schemes, unauthenticated operations, API keys in query strings and other risky parameters. The documented operations are never called.

## External tools and vulnerability intelligence

```bash
python3 domaininfo.py --tools                                   # what is installed and how to install the rest
python3 domaininfo.py -m web --tool whatweb,subfinder example.com
python3 domaininfo.py -m web --tool nmap,nuclei --active --scope example.com example.com
python3 domaininfo.py -m code ./my-project                      # Semgrep, Bandit, pip-audit, Trivy, Gitleaks
python3 domaininfo.py -m web --tool nmap --active --scope example.com --intel example.com
```

- Tools are detected with their version and compatibility; a missing tool is reported as not evaluated with an install hint. **Nothing is downloaded or installed automatically.**
- Arguments are built only from validated values and passed as a list, never through a shell. Every run has a timeout, an output cap and cancellation that kills the whole process tree.
- Tools that send probes (Nmap, Nuclei, SSLyze, testssl.sh, httpx probing, dnsx brute force) run only with `--active` **and** the target listed in `--scope`. Nuclei excludes intrusive, DoS, fuzzing and brute-force templates.
- `--intel` correlates the software versions found with **OSV, NVD and CISA KEV** (cache under the user cache folder, NVD rate limits, `NVD_API_KEY` optional). An exact version match backed by direct evidence can be *confirmed*; a version from a banner is at most *likely*; a name-only match stays *pending*.

Details and safety limits: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Findings, scores and reports

Every finding has an id (stable across languages and audits), target and path, category, severity, **status** (confirmed, likely, informational, pending verification, not applicable, not evaluated, check error), confidence, redacted evidence, the tool that found it, impact, safe verification steps, remediation and references (CWE, OWASP).

Each report has three scores in `assessment`: **Security** (risk of what was checked), **Coverage** (share actually checked) and **Confidence** (share backed by direct evidence). Only comparable audits (same checks, similar coverage) should be compared. The classic A–F grade (`score`) is still there.

Reports are saved to `logs/` as JSON, TXT and HTML (`--format md` adds Markdown). Several targets (`-f`) also produce an infrastructure map, an **attack-surface inventory** (domains, subdomains, IPs, ASN, DNS servers, certificates, ports, services, technologies, APIs, components and findings, de-duplicated with their sources) and a CSV summary.

## Security Center

```bash
pip install "domaininfo[server]"         # or: pip install fastapi uvicorn
domaininfo --serve                        # http://127.0.0.1:8765 with a private access token
domaininfo -m web example.com --store "My company"      # save CLI results into a project
domaininfo --export pdf --project "My company"           # executive PDF (technical-pdf, csv)
domaininfo --compare 12 15                               # new / fixed / unchanged findings
```

A local dashboard with an overview, projects and their authorized scope, targets, passive audit launch, web security, sessions, infrastructure and ports, certificates and TLS, mail and DNS, vulnerabilities and evidence, audit history, comparisons, tool configuration and exports. Findings can be marked fixed, accepted risk or false positive, with history. Dark and light themes.

It listens on **127.0.0.1 only** unless you pass `--allow-remote`, requires a random per-run token, checks the `Host` header against DNS rebinding, sends a strict CSP and no CORS headers, and launches only passive audits for targets in the project's scope. Data lives in a SQLite file in your user data folder. More in [docs/SECURITY_CENTER.md](docs/SECURITY_CENTER.md).

## Using it in the terminal

**Readable output or JSON.** At a terminal `domaininfo example.com` shows a colored summary. If the output goes to another program or a file, or you use `--json` or `-q`, the JSON is printed (one document per target), so scripts keep working.

```bash
domaininfo example.com --json          # one-line JSON
domaininfo example.com --pretty        # indented JSON
domaininfo example.com | jq .          # JSON automatically in a pipe
domaininfo -m web example.com --open   # open the HTML report when finished
```

**Watch mode.** `--watch SECONDS` repeats the review (minimum 5 s) and reports only changes: addresses, HTTP status, headers, renewed certificates, ports, RouterOS version, web findings or a module that starts failing. CTRL+C stops it.

**TAB completion.** `install.sh` installs the Bash completion. You can also load it by hand: `eval "$(domaininfo --completion bash)"` (or `zsh`). In PowerShell add `domaininfo --completion powershell | Out-String | Invoke-Expression` to your `$PROFILE`.

**Update.** `domaininfo --update` shows the installed and latest versions; in a clone it runs `git pull --ff-only`.

Exit codes: `0` success, `1` invalid targets, failed modules or a save error, `2` invalid arguments, `130` interrupted.

### MikroTik / RouterOS audit

```bash
python3 domaininfo.py -m mikrotik 192.168.88.1
python3 domaininfo.py -m mikrotik --routeros-version 7.25 192.168.88.1
python3 domaininfo.py -m mikrotik --offline --routeros-version 7.24.2
```

It does not try passwords, run exploits or change the configuration. `potentially_affected` refers to the reported version and does not confirm exploitation. Details, sources and limits in [docs/MIKROTIK.md](docs/MIKROTIK.md).

### Limits of the results

- A missing header or an open port is an observation; it does not prove a vulnerability or a CVE by itself.
- `webapp` is passive: it does not run JavaScript (use `-m browser`), submit forms or verify CSRF protection on the server, so a form without a token stays *pending verification*.
- RDAP sends the target to `rdap.org`; `--intel` sends software names and versions to OSV/NVD. Skip them with `-s rdap` or by not using `--intel`.
- Certificates are verified with Python's trust store; an invalid certificate stops the web module unless you pass `--insecure-tls`, which is noted in the report.
- Traceroute uses `tracert`/`traceroute`/`tracepath`; Android may restrict it.

## Classic Bash modules

```bash
bash install.sh --legacy
bash domaininfo.sh --legacy                   # classic menu
bash domaininfo.sh -m full -j -t 15 example.com
bash domaininfo.sh --mikrotik --offline --routeros-version 7.25
```

They need **Bash 4+**, curl, dig and the tools of each module (WHOIS, Nmap, OpenSSL, coreutils `timeout`). Windows uses the Python core; the classic modules need WSL/Linux. They are legacy code: some results are heuristic. Historical documentation: [docs/LEGACY.md](docs/LEGACY.md).

## Development

```bash
python3 -m unittest discover -s tests -v
pip install "domaininfo[dev]"    # Hypothesis, Ruff, Bandit, Pyright, pip-audit
```

The tests use local servers and mocks; no public service is scanned. GitHub Actions runs them on Ubuntu, macOS and Windows with Python 3.10, 3.12 and 3.14, plus Ruff, Bandit, Pyright, the Bash checks and the packaging workflow (web UI, wheel and zipapp). Termux needs a manual check on an Android device. Design and roadmap: [docs/V6_DESIGN.md](docs/V6_DESIGN.md); past fixes: [docs/FIXES.md](docs/FIXES.md).

MIT License. Author: [@kevxngg](https://github.com/kevxngg).
