# External integrations (DomainInfo 6.0, Phase 3)

DomainInfo's core uses only the Python standard library. Every tool below is **optional**: when it is
missing, `runners.run()` returns `status: "skipped"`, `reason: "unavailable"` and the install hint from
`tools.CATALOG`, and the rest of the audit keeps working. DomainInfo **never downloads or installs
binaries**. It runs only what `tools.detect()` finds on `PATH` (never from the current directory).

## How tools are run

- `subprocess.Popen` with a list of arguments and no shell. Arguments come only from validated values:
  strict hostnames/IPs, `safety.normalize_url` URLs, existing absolute local paths, bounded integers and
  whitelisted tokens. Targets such as `-oN /tmp/x`, `example.com;rm` or `a b` are rejected before any
  process starts.
- Each run has a timeout (default 600 s, 5–3600 s) and an optional `threading.Event` for cancellation.
  Both kill the **whole process tree** (`taskkill /T` on Windows, process group on POSIX).
- stdout is capped at 16 MB and stderr at 256 KB. Output files are read up to 16 MB and marked as truncated
  beyond that.
- Output files live in a private temporary directory (`mkdtemp`, mode 0700) that is deleted afterwards.
- Tool versions below the catalog minimum are skipped (`reason: "incompatible"`).
- Results are normalized into `findings` (same keys as `evidence.Finding.to_dict()`), `assets`,
  `components` (for `vulnintel.correlate`), explicit `errors` and a `coverage` indicator
  (`complete`, `partial`, `none`).

## Active scanners need authorization

Active tools send traffic to the target. They run only when the caller passes `allow_active=True`
**and** the target host is in the explicit `scope` list. A scope entry can be an exact host
(`www.example.com`), a wildcard that covers subdomains but not the apex (`*.example.com`), an IP, or a CIDR
(`192.0.2.0/24`). No DNS resolution is done for the scope check, so a hostname never matches a CIDR entry.

| Tool | Mode | What DomainInfo runs | Safety limits |
|---|---|---|---|
| nmap | **active** | `-sT -sV -Pn -T3 --max-retries 2 --max-rate 50 --host-timeout <t>s -oX <tmp> (-p <ports> \| --top-ports 100) <host>` | TCP connect only (no raw packets or root). No NSE scripts. XML is parsed locally and entity declarations are refused. |
| nuclei | **active** | `-u <url> -jsonl -o <tmp> -silent -nc -disable-update-check -no-interactsh -rl 10 -c 5 -bs 5 -timeout 10 -retries 1 -etags intrusive,dos,fuzz,fuzzing,bruteforce,brute-force,headless,oast [-tags …]` | Never runs intrusive, DoS, fuzzing, brute-force, headless or out-of-band templates. Rate limit 1–50 req/s. Matches are reported as `likely`, never `confirmed`. |
| httpx (ProjectDiscovery) | **active** | `-u <target> -json -status-code -title -web-server -tech-detect -ip -rl 10 -t 5 -timeout 10 -retries 1` | Probes the target over HTTP. The Python `httpx` CLI is told apart by its version and skipped. |
| sslyze | **active** | `--json_out=<tmp> --quiet <host>:<port>` | TLS handshakes only. Findings: deprecated protocols, Heartbleed, CCS injection, ROBOT. |
| testssl.sh | **active** | `--jsonfile <tmp> --quiet --color 0 --warnings off --sneaky <host>:<port>` | Needs bash. LOW and above are reported as `likely`. |
| dnsx | passive / **active** | resolution: `-l <names> -json -a -aaaa -cname -resp -rl 50`; brute force: `-d <domain> -w <wordlist>` | Resolving known names is passive. A `wordlist` option makes it active. Extra names must belong to the target domain. |
| subfinder | passive | `-d <domain> -silent -nc -oJ -o <tmp> -timeout 30 -max-time <min> -disable-update-check` | Public sources only. Names outside the domain are dropped. |
| amass | passive | `enum -passive -nocolor -d <domain> -timeout <min> -o <tmp>` | Passive only. Names outside the domain are dropped. |
| whatweb | passive | `--aggression 1 --color=never --no-errors --max-threads 2 --log-json=<tmp> <url>` | Aggression level 1 is one request, like the built-in `tech` module. |
| semgrep | local | `scan --config p/default --json --metrics off --quiet --timeout 30 --disable-version-check <dir>` | Only `p/…` / `r/…` registry rulesets or a local rules file. Metrics are disabled. Results are `likely`. |
| bandit | local | `-r <path> -f json -o <tmp> -q` | Results are `likely`. |
| pip-audit | local | `-r <requirements> --disable-pip --no-deps -f json -o <tmp> --progress-spinner off` | Does not create a virtualenv or run setup code. Queries PyPI/OSV advisories. |
| trivy | local | `fs --format json --quiet --no-progress --scanners vuln,secret,misconfig <path>` | Trivy may update its own vulnerability database. Secret matches are never copied into the evidence. |
| gitleaks | local | `detect --source <path> --report-format json --redact --no-banner --exit-code 0 [--no-git]` | `--redact` is always on, and neither `Secret` nor `Match` reaches the report. Git history is scanned only with `git_history: true`. |

`zap` and `playwright` are detected by `tools.py` but have no runner in this phase.

### Install

The install hints come from `tools.CATALOG` (for example `apt install nmap`,
`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`, `pip install sslyze semgrep bandit
pip-audit`). Install the tools yourself. DomainInfo only detects them.

## Python API

```python
import runners, vulnintel, inventory

result = runners.run("nmap", "www.example.com", {"ports": "22,80,443"},
                     allow_active=True, scope=["*.example.com"], cancel=None)
intel = vulnintel.correlate(result["components"], target="www.example.com")
assets = inventory.build([report_with_runners], scope=["*.example.com"])
```

Per-tool options: nmap `ports` / `top_ports`, nuclei `tags` / `rate`, httpx and dnsx `rate`, sslyze and
testssl.sh `port`, dnsx `names` / `wordlist`, semgrep `config`, gitleaks `git_history`, and `timeout`
for every tool.

## Vulnerability intelligence (`vulnintel.py`)

| Source | Endpoint | Use |
|---|---|---|
| OSV | `POST https://api.osv.dev/v1/query` | package + ecosystem + version → affected advisories |
| NVD CVE API 2.0 | `GET https://services.nvd.nist.gov/rest/json/cves/2.0` | `cpeName` (with range check) or `keywordSearch`. Optional `NVD_API_KEY`. Rate limit 5 requests / 30 s without a key and 50 with one. |
| CISA KEV | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | KEV flag on matches |

- Only these fixed HTTPS endpoints are contacted, with response caps (5/16/24 MB) and timeouts.
- Responses are cached on disk with `fetched_at` timestamps. The cache lives in
  `%LOCALAPPDATA%\DomainInfo\cache\vulnintel` on Windows, and in `$XDG_CACHE_HOME/domaininfo/vulnintel` or
  `~/.cache/domaininfo/vulnintel` elsewhere. TTL is 24 h for OSV/NVD and 12 h for KEV. `offline=True` uses
  the cache only.
- Match types and statuses:
  - `exact`: OSV lists the package+version, or an NVD CPE range contains the version. The status is
    `confirmed` only when the component's version came from direct evidence (banner, lockfile, pinned
    manifest). Otherwise it is `likely`.
  - `name_only` (the NVD CPE query returned the CVE but no range proves the version) and `keyword` are
    always `pending`.
- Each match carries CVSS (score from NVD, or computed from the OSV v3 vector), CWE, the KEV flag and date,
  references, `updated_at` and `published`. Severity comes from CVSS (≥ 7 high, ≥ 4 medium). A KEV entry
  always makes it high.

## Inventory (`inventory.py`)

`inventory.build(reports, scope=None)` merges one or many reports: the modules dns, asn, tls, ports, tech,
subdomains, webapp, history and openapi/apis, plus runner results from `report["runners"]`. It returns
deduplicated domains, subdomains, IPv4/IPv6, ASNs, DNS servers, certificates, ports, services,
technologies, paths, APIs, components and findings. Each entry has the `sources` that saw it. An open port
is an asset, not a vulnerability. Paths outside the audited domains, their subdomains or `scope` are
dropped and counted in `summary.out_of_scope_paths`.

## Known limitations

- Parsers follow the current JSON formats of each tool. Older or newer output formats may give partial
  results, which are reported as parse errors and never as silent success.
- `testssl.sh` needs bash, so it does not run natively on Windows.
- nuclei may fetch its template set on first use. That is the tool's own data, not a binary.
- Version comparison for NVD ranges is a generic numeric/text ordering. Distribution backports (for example
  `8.9p1 Ubuntu 3ubuntu0.1`) can be patched while still matching. That is why nmap marks banners that
  carry a distribution suffix as heuristic evidence, so their matches are at most `likely`. Review even a
  plain banner match before you act on it.
