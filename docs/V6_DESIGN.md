# DomainInfo 6.0 Security Suite — design and roadmap

Status: **all four phases are being implemented in 6.0** on the `feature/v6-fase1-webapp` branch. Phase 1 is implemented; phases 2–4 are in progress.

## 1. Starting point (DomainInfo 5.0)

- Python core using only the standard library: `domaininfo.py` (CLI, `scan()`, `RUNNERS`, `MODES`),
  its own menu (`terminal_ui.py`), one module per file (`dnsclient`, `mailsec`, `webtech`, `tlsdeep`,
  `recon`, `history`, `lookalike`, `netinfo`, `score`, `infra`, `render`, `routeros`).
- Classic Bash modules in `modules/` (including `webapp.sh`), launched from the menu (key `a`).
- 108 `unittest` tests without network access; CI on Windows/Linux/macOS × Python 3.10/3.12/3.14.

Technical debt found:

| Problem | Consequence | Phase 1 |
|---|---|---|
| `normalize_target()` reduces any URL to its host | `/login` is audited as `/` | `safety.normalize_url()` keeps the path and query |
| `urllib` follows redirects without checking the destination | SSRF/out-of-scope redirects | Own HTTP client with scope and manual redirects |
| DNS resolved again on every connection | DNS rebinding between requests | IP pinned per host for the whole audit |
| `score.py` mixes risk with missing data | Grades are not comparable | `assessment` with Security / Coverage / Confidence |
| Findings without evidence or status | Heuristics look like vulnerabilities | `evidence.Finding` model with status and confidence |
| Headers evaluated in two places (`http_info`, `webtech`) | Duplication | `webapp` reuses `webtech.grade_headers` and adds deep CSP analysis |

## 2. Architecture

```
domaininfo.py ── RUNNERS ──► dns, http, tls, tech, … (5.0, unchanged)
                         └─► webapp ──► webapp.py ──► safety.py (URL, scope, pinned IP, HTTP client)
                                                  └─► evidence.py (Finding, redaction, scores)
score.py ──► classic grade (no schema changes) + confirmed/likely webapp findings
evidence.assess() ──► report["assessment"] (new field)
tools.py ──► external tool detection (--doctor → "integrations")
```

Principles: stdlib core; external tool adapters only detect, check the version and turn themselves
off when missing; active modules will be added disabled by default.

### Security of the tool itself (Phase 1)

- **URL**: only `http`/`https`, no credentials, no control characters, port 1–65535, no fragment.
- **Scope**: the URL's host and those given with `--scope` (accepts `*.domain`). A redirect out of scope
  is not followed: it is recorded as blocked.
- **SSRF / rebinding**: each host is resolved once and the connection goes to that IP (Host and SNI carry the name).
  Link-local (including `169.254.169.254`), multicast, unspecified and reserved addresses are always blocked.
  Non-public addresses (private, loopback, CGNAT…) are only allowed if the initial target
  already was one (the user typed it) or with `--allow-private`.
- **Resources**: per-connection timeout, at most 5 redirects, 1 MiB per response, GET only,
  no forwarded cookies, a form is never submitted.
- **Secrets**: cookie values, CSRF tokens and key fragments are redacted before they enter
  the report (`evidence.redact`); sensitive URL parameters (`code`, `token`, `sid`, `key`…)
  are hidden (`evidence.redact_url`) and control characters are stripped from remote content.

### Independent security review (Phase 1)

A review without access to the author's conclusions found the following, and they were fixed with regression tests
(`tests/test_webapp.py::HostileServerTests`):

| Problem | Fix |
|---|---|
| ReDoS in the Node.js stack trace signature with 1 MB of line breaks | Bounded pattern and signatures limited to 256 KiB |
| No overall deadline (server sending byte by byte) | Per-audit deadline and chunked reads |
| Secret parameters in URLs, redirects and `action` not hidden; quoted JSON | `redact_url`, extended names, quotes accepted |
| `charset=undefined` and a huge `max-age` aborted the module | They are caught and `max-age` is bounded |
| `shutil.which` on Windows (< 3.12) would run a binary planted in the current folder | Paths in the current folder are ignored |
| ANSI sequences from the target in the terminal/TXT | Control characters are stripped |
| NAT64 / 6to4 towards `169.254.169.254` | The embedded IPv4 is classified |
| An origin with both a public and a private IP enabled the internal network | Only if all of its IPs are internal |
| Markdown links injected through remote titles | Markdown escaping |

Manual verification against `python -m http.server` also found that `http.client` drops the socket
after `getresponse()` when there is a `Content-Length`; the test server now sends `Content-Length`.

## 3. Finding model

`id, target, path, category, title, severity, status, confidence, evidence, tool, impact,
verification, recommendation, references`.

Statuses: `confirmed`, `likely`, `informational`, `pending`, `not_applicable`, `not_evaluated`, `error`.
Only `confirmed` (direct evidence in the response) and `likely` lower the Security Score;
`pending` means "there is no evidence either way", e.g. a form without a visible CSRF token
and without SameSite cookies: it is **not** declared vulnerable.

Scores (`report["assessment"]`):
- **security**: 100 − penalties (likely counts half).
- **coverage**: checks run / applicable checks.
- **confidence**: checks with direct evidence / checks run.
- `evidence.comparable(a, b)`: two audits are only compared if they cover the same checks and their
  coverage differs by ≤ 10 points.

`report["score"]` (the 5.0 A–F grade) keeps the same schema.

## 4. Roadmap

| Phase | Content | Status |
|---|---|---|
| 1 — Solid foundation | Full URL, passive `webapp`, forms/CSRF, cookies, CSP, CORS, errors, exposed secrets, evidence model, new scoring, scope policy, tool detection | **Done** |
| 2 — Advanced security | Sessions with test accounts (authorization file + limits), passive ZAP, optional Playwright, OpenAPI analysis, service inventory | In progress (6.0) |
| 3 — Integrations | Runners for Nmap, Nuclei, SSLyze, testssl.sh, Subfinder, httpx…; OSV/NVD/KEV with cache; version-based CVE correlation; history and comparisons | In progress (6.0) |
| 4 — Security Center | Optional FastAPI on 127.0.0.1 with a token, SQLite, React+TS dashboard, PDF/CSV, packaging | In progress (6.0) |

### Decisions for the following phases

- External tool runs will use `subprocess.run([...], shell=False, timeout=…)`
  with arguments built from validated objects (`safety.normalize_url`), never strings.
- Authenticated auditing will require an authorization file (`scope.toml`) with targets, test
  accounts referenced through environment variables, a time window and a request limit.
- The dashboard will listen on loopback only and require a random per-session token.

## 5. Phase 1 implementation plan (TDD)

1. `safety` tests: URL with path/query/port, rejection of credentials and schemes, wildcard scope,
   IP classification and rebinding with a simulated resolver.
2. `evidence` tests: redaction, valid statuses, stable ids, scores and comparability.
3. `webapp` tests against a local HTTP server (thread): root versus `/login`, forms, direct /
   alternative / pending CSRF, cookies, in-scope and out-of-scope redirects, technical errors, secrets, CORS.
4. CLI tests: `-m webapp --url …/login` keeps the path and the public JSON stays the same.
5. Minimal implementation to pass each block; integration into the menu, reports and `--doctor`.
6. Security review, ruff/bandit/pyright and the full suite.
