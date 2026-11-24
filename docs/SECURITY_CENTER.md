# DomainInfo Security Center (6.0, Phase 4)

A local web dashboard for the audits DomainInfo already runs: projects, authorized scope, audit
history, findings with a review workflow, comparisons between audits and CSV/PDF exports.

The Python core stays standard-library only. The dashboard is an optional extra:

| Part | Dependencies |
|---|---|
| `auditstore.py` (SQLite store) | stdlib (`sqlite3`) |
| `exporters.py` (CSV, PDF) | stdlib (built-in PDF writer, Helvetica, WinAnsi) |
| `server.py` (HTTP API + UI) | `fastapi`, `uvicorn` (optional extra) |
| `webui/` (React + TypeScript) | Node only to rebuild; the built `webui/dist` is committed |

## Run

```bash
pip install fastapi uvicorn          # or: pip install "domaininfo[server]"
python server.py                     # http://127.0.0.1:8765, opens the browser
python server.py --port 9000 --no-browser --db ./center.db
```

The terminal prints an access link such as `http://127.0.0.1:8765/#token=…`. Open that exact link:
the token is new on every start. If the server restarts, open the new link.

From Python:

```python
from server import serve
serve(host="127.0.0.1", port=8765, open_browser=True)   # allow_remote=False by default
```

Data lives in `%LOCALAPPDATA%\DomainInfo\securitycenter.db` on Windows and
`$XDG_DATA_HOME/domaininfo/securitycenter.db` (default `~/.local/share/domaininfo/`) elsewhere,
created with 0600 permissions (folder 0700) where the platform supports it.

### Rebuilding the web UI

```bash
cd webui
npm ci
npm run build          # type-checks and writes webui/dist (commit it)
```

### Single-file build

```bash
python scripts/build_zipapp.py       # dist/domaininfo.pyz, runs with any Python 3.10+
```

## Workflow

1. **Projects**: create one per client, estate or application.
2. **Domains & targets**: register the domains, IPs or full URLs you are authorized to review. This
   list is the scope: the dashboard refuses to audit or import anything else.
3. **Available audits**: launch a passive mode (`quick`, `web`, `mail`, `recon`, `webapp`, `brand`)
   on a registered target, or import a JSON report produced by the CLI. Active modes (`ports`,
   `full`, `mikrotik`) stay in the command line.
4. **Findings** sections (web, authentication, infrastructure, TLS, mail & DNS, vulnerabilities):
   review each finding and mark it `open`, `fixed`, `accepted_risk` or `false_positive` (the last two
   need a note). Decisions carry over to later audits of the same host; a finding marked fixed that
   reappears is reopened, and open findings that disappear from a *comparable* later audit are marked
   fixed automatically. Every change is kept in the history.
5. **Compare results**: new / fixed / unchanged findings between two audits. Two audits are only
   *comparable* when they ran the same checks and their coverage differs by 10 points or less;
   otherwise the dashboard says so, because the difference may come from a different scope.
6. **Reports & export**: CSV of findings, executive PDF (grades, Security/Coverage/Confidence, top
   risks, counts, trend) and technical PDF (every finding, remediation plan prioritized by
   severity × status × exposure, false positives, change history).

## Security model

| Threat | Measure |
|---|---|
| Exposure on the network | Binds to `127.0.0.1` by default. Any non-loopback address raises an error unless `allow_remote=True` (`--allow-remote`), which also prints a warning: the traffic is plain HTTP. |
| Other local users / web pages calling the API | Random 256-bit token per run (`secrets.token_urlsafe(32)`), required in the `X-DomainInfo-Token` header of every `/api/` call and compared in constant time. Query-string tokens are not accepted. |
| Token leakage | The browser gets the token once in the URL fragment, which is never sent to the server, logged or included in `Referer` (`Referrer-Policy: no-referrer`). The UI removes it from the address bar and keeps it in `sessionStorage` for that tab only. |
| DNS rebinding | The `Host` header must be `127.0.0.1`, `localhost` or `[::1]` (with the port); anything else gets 421. |
| CSRF / cross-origin | No CORS headers at all; requests with `Sec-Fetch-Site: cross-site` or a foreign `Origin` are refused; the custom header forces a preflight that never succeeds. |
| XSS / clickjacking | CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` with no inline code, plus `nosniff`, `X-Frame-Options: DENY`, COOP/CORP and `Permissions-Policy`. React escapes all report text. |
| Resource abuse | Request bodies limited to 256 KiB (10 MiB for report import), `Content-Length` required for chunked bodies, uvicorn concurrency limit, at most 2 audits running and 8 queued, cancel at module boundaries. |
| Unauthorized scanning | Only passive modes can be launched, only on targets registered in the project scope, with `--allow-private`, `--insecure-tls` and subdomain brute force forced off. |
| SQL injection | Every statement is parameterized; the schema is versioned (`meta.schema_version`). |
| Secrets in exports | Reports are already redacted by the core; the store and every export pass the data through a second redaction (cookies, `Authorization`, bearer tokens, JWTs, cloud keys, private keys, `name=value` secrets) and CSV cells are protected against formula injection. |
| Path traversal | Static files are served from an in-memory map built at start-up; URL paths are dictionary keys, never file paths. |

## HTTP API

Every `/api/` call needs `X-DomainInfo-Token`. Bodies are JSON. Errors are `{"error": "…"}`.

| Method and path | Purpose |
|---|---|
| `GET /api/session` | version, language, passive modes and their modules |
| `GET /api/i18n` | UI translations for the active language |
| `GET /api/overview?project_id=` | counts by severity/area/review status, latest audit per target, trend |
| `GET, POST /api/projects` · `DELETE /api/projects/{id}` | projects (`{"name", "description"}`) |
| `GET, POST /api/projects/{id}/targets` · `DELETE /api/targets/{id}` | scope (`{"value", "note"}`) |
| `GET /api/projects/{id}/audits?target=` | audit list |
| `GET /api/audits/{id}` · `GET /api/audits/{id}/report` · `DELETE /api/audits/{id}` | one audit, its full report |
| `POST /api/projects/{id}/import` | store a CLI JSON report (target must be in scope) |
| `GET /api/projects/{id}/targets/{tid}/history` | audits of one target, oldest first |
| `GET /api/projects/{id}/findings?section=&status=&severity=&audit_id=` | findings |
| `GET /api/projects/{id}/sections/{web,auth,infra,tls,maildns,vulns}` | findings plus facts per target |
| `PATCH /api/findings/{id}` · `GET /api/findings/{id}/history` | review status (`{"status", "note"}`) |
| `GET /api/projects/{id}/history` | every review change |
| `GET /api/compare?base=&head=` | new / fixed / unchanged and comparability |
| `POST /api/projects/{id}/jobs` · `GET /api/jobs` · `GET /api/jobs/{id}` · `POST /api/jobs/{id}/cancel` | passive audits (`{"target_id" or "target", "mode"}`) |
| `GET /api/tools?refresh=true` | `tools.detect_all()` (cached 5 minutes) |
| `GET /api/projects/{id}/export/findings.csv`, `…/export/executive.pdf`, `…/export/technical.pdf` (`?audit_id=`) | downloads |

## Limitations

- Plain HTTP on loopback; for remote use put it behind an HTTPS tunnel you control.
- Finding identity across audits uses the finding id from the report (or a hash of host, category and
  title). Titles are written in the active language, so legacy findings audited once in English and
  once in Spanish are seen as different findings.
- Cancelling takes effect between modules; a module already running finishes first.
- PDFs use the built-in Helvetica fonts: characters outside Windows-1252 are replaced with `?`.
