# Authenticated audit, API analysis, ZAP and browser rendering (DomainInfo 6.0, Phase 2)

These modules go beyond the passive `webapp` check. Use them **only on systems you are authorized
to test**, with **test accounts** created for that purpose. They never brute-force, never use
wordlists, never try to evade defenses and never touch real user accounts.

| Module | What it needs | Requests it makes |
|---|---|---|
| `session_audit` | An authorization file + test credentials in environment variables | GET/POST to the authorized targets, inside a request budget |
| `apispec` | The URL of an OpenAPI/Swagger JSON document (or the origin) | GET of the document only; documented operations are never called |
| `zapclient` | An OWASP ZAP daemon the user already runs on `127.0.0.1` | ZAP fetches the target and reports passive alerts; never an active scan |
| `browser` | Optional `playwright` + Chromium | Renders one URL; out-of-scope requests are blocked; nothing is submitted |

The core stays standard-library only. Playwright and ZAP are optional: without them the modules
return a check with state `not_evaluated` and an install hint.

## 1. The authorization file

`session_audit` refuses to run without a valid JSON authorization file. Every key is validated;
unknown keys, duplicate keys, wrong types, URLs outside the targets, an expired or not-yet-started
window and missing environment variables are all errors (`authscope.AuthorizationError`).

```json
{
  "version": 1,
  "authorized_by": "Jane Doe, CISO of Example Ltd",
  "authorization_note": "Ticket SEC-1234: authenticated test of the staging portal, 2026-11-24 09:00-18:00 CET",
  "targets": ["https://staging.example.com/"],
  "scope_hosts": [],
  "allow_private": false,
  "login": {
    "url": "https://staging.example.com/login",
    "username_field": "username",
    "password_field": "password"
  },
  "logout": {"url": "https://staging.example.com/logout", "method": "GET"},
  "accounts": [
    {"id": "user1", "role": "user", "username_env": "DI_TEST_USER1", "password_env": "DI_TEST_PASS1"},
    {"id": "admin1", "role": "admin", "username_env": "DI_TEST_ADMIN1", "password_env": "DI_TEST_ADMINPASS1"}
  ],
  "roles": {
    "user": {"protected_urls": ["https://staging.example.com/account"]},
    "admin": {"protected_urls": ["https://staging.example.com/admin", "https://staging.example.com/account"]}
  },
  "limits": {"max_requests": 150, "max_login_attempts": 3, "lockout_check": true, "lockout_account": "user1"},
  "window": {"not_before": "2026-11-24T09:00:00+01:00", "not_after": "2026-11-24T18:00:00+01:00"}
}
```

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | Always `1`. |
| `authorized_by`, `authorization_note` | yes | Who authorized the test and the reference (ticket, contract, scope). Shown in the report. |
| `targets` | yes | 1–20 URL prefixes (scheme, host, port and path). Every request — login, logout, protected URLs and the login form's `action` — must start with one of them. |
| `scope_hosts` | no | Extra host names (`*.example.com` accepted) that redirects may reach. |
| `allow_private` | no | Allow internal addresses when the target is public (default `false`; a target that is itself internal is always allowed, as in `webapp`). |
| `login.url` | yes | Page with the login form. `username_field`/`password_field` are optional; without them the password field and a user/e-mail field are detected from the form. Hidden fields (CSRF tokens) are sent back automatically. |
| `logout.url`, `logout.method` | no | Logout action (`GET` or `POST`). Without it the logout and token checks are `not_evaluated`. |
| `accounts` | yes | 1–10 test accounts: an `id`, a `role` and the **names** of the environment variables that hold the username and the password. Values never go in the file (a `password` key is rejected). |
| `roles` | yes | 1–10 roles, each with up to 20 `protected_urls` the role is allowed to open. List *every* URL a role may open: role A requesting a URL that only role B lists is treated as an access-control test. |
| `limits.max_requests` | no | Hard request budget for the run, redirect hops included (10–1000, default 150). |
| `limits.max_login_attempts` | no | Maximum **failed** password attempts per test account in the run (1–5, default 3, hard cap 5). |
| `limits.lockout_check`, `limits.lockout_account` | no | Enables the lockout/rate-limit check against that one test account (default off). |
| `window.not_before`, `window.not_after` | yes | ISO 8601 date-times with a time zone; at most 90 days. Checked before every request. |

Set the credentials only in the environment of the process, for example:

```sh
export DI_TEST_USER1='...' DI_TEST_PASS1='...'   # never in the file, the shell history of a shared host, or the report
```

## 2. What each session check does — and does not do

The checks run in this order; once the budget, the window or the login fails, the remaining
checks are reported as `not_evaluated` with a note.

| Check id | What it does | What it does not do |
|---|---|---|
| `anonymous_access` | GETs each protected URL without a session and compares it with what the owner role sees. Identical content → `confirmed`; a different 2xx page → `pending`. | It does not crawl or guess URLs. |
| `login` | GETs the login form and POSTs the credentials of each test account once. | No credential guessing; a login form that posts outside the targets stops the audit. A form with `method="get"` is never submitted. |
| `mfa` | Detects a verification-code step after the password (OTP fields, `autocomplete="one-time-code"`, wording). If found, the session checks stop: MFA is not automated. A login without a second factor is a `pending` low finding (test accounts are often exempt). | It never bypasses or answers an MFA step. |
| `session_fixation` | Compares the session cookie before and after the login (hash comparison in memory). Same value → `confirmed` high. | No cookie is ever planted in a victim's browser. |
| `cookie_flags`, `session_expiry` | Secure / HttpOnly / SameSite of the session cookie, HTTP transport and lifetime (> 30 days → `likely` low). | Server-side idle and absolute timeouts are not measured (it would require waiting). |
| `access_control` | Each logged-in account requests the protected URLs of the *other* roles that its own role does not list. Same content as the owner → `confirmed`/`likely` high; another 2xx page → `pending`. | No IDs are enumerated or modified; only the configured URLs are requested, with GET. |
| `logout` | Copies the session cookie, calls the logout URL, then replays the old cookie on a protected URL. Still valid → `confirmed` high. Also notes if the browser cookie is not cleared. | — |
| `token_invalidation` | Logs in again and checks that a new session token was issued. | — |
| `user_enumeration` | One wrong password for the first test account and one attempt with a random, non-existent username (`di_<random>`). Different status, redirect or visible message → `likely` medium. | Response times are not compared; no list of usernames is ever tried. |
| `lockout` | Only with `lockout_check: true`: wrong passwords for the configured TEST account, up to `max_login_attempts` failed attempts in total (enumeration included), stopping at the first 429/423, `Retry-After` or lockout/CAPTCHA message. No signal → `pending` low (the test is capped by design). | Never more than 5 attempts, never against other accounts, no delays or IP rotation to evade the limit. The test account may end up locked: it runs last. |

## 3. Secrets

- Usernames, passwords, session cookies, CSRF tokens and every value posted are collected in memory
  and removed from the whole result, from the notes and from exception messages
  (`[hidden]`). Values shorter than 3 characters are not scrubbed: use realistic test credentials.
- `safety.CookieJar` lives only in memory; its `repr` shows names only, and comparisons use SHA-256
  digests. Nothing is written to disk.
- `zapclient` sends the API key only in the `X-ZAP-API-Key` header to the loopback ZAP API and
  removes it from errors. `browser` reports cookie flags, never values.
- The tests (`tests/test_phase2.py`) serialize every result and check that no password, username,
  session id or CSRF token issued by the fake application appears, including in tracebacks.

## 4. Safety limits

- Every request goes through `safety`: validated URL, scope, IP pinned per host (no DNS rebinding),
  link-local/metadata/multicast always blocked, per-connection timeout and an overall deadline,
  1 MiB per response, at most 5 redirects.
- `safety.http_request` supports only GET, HEAD and POST with a form-encoded body of at most 64 KiB.
  A 301/302/303 after a POST continues as a GET without body; a 307/308 keeps the POST only within
  the same origin (scheme, host and port) and is blocked otherwise. Caller-supplied `Cookie`, `Host`
  and `Content-Length` headers are ignored.
- Request budget (`max_requests`), failed-attempt cap (`max_login_attempts` ≤ 5) and the time window
  are enforced in code, not only documented.

## 5. API analysis (`apispec`)

Given a document URL it fetches that document; given an origin (path `/`) it tries
`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/swagger/v1/swagger.json` and `/api-docs` and
stops at the first JSON OpenAPI 3 / Swagger 2 document (≤ 4 MiB). It reports: the endpoint
inventory, servers on `http://`, no security schemes, operations without a security requirement
(`pending`: the server may still enforce it), API keys in query parameters, HTTP Basic with
`http://` servers, sensitive-looking query parameters and deprecated operations. Only local
`$ref`s are followed. YAML documents are reported as `not_evaluated` (no dependency-free parser).
It never calls a documented operation.

## 6. OWASP ZAP (`zapclient`)

Start ZAP yourself, bound to loopback, with an API key:

```sh
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key="$ZAP_API_KEY"
```

DomainInfo refuses any ZAP API URL that is not `127.0.0.1`, `::1` or `localhost`. It checks the
version, asks ZAP to fetch the target (`core/action/accessUrl`), optionally runs the traditional
spider limited to the URL's subtree **only when explicitly enabled**, waits for the passive queue
(`pscan/view/recordsToScan`, with a timeout) and reads the alerts of in-scope URLs. Only an
allow-list of API endpoints can be called; `ascan/*` (active scan) is not on it. Alerts map to
findings: risk → severity; confidence High/Confirmed → `confirmed`, Medium → `likely`, Low →
`pending`; False Positive alerts are dropped; CWE/WASC/reference URLs are kept.

## 7. Browser rendering (`browser`)

Install with `pip install playwright && playwright install chromium`. The page is rendered in
headless Chromium with a navigation timeout. Each request is checked against `safety.ScopePolicy`
(route interception): out-of-scope hosts, blocked and (unless allowed) internal networks and
non-HTTP schemes are aborted and listed. Known in-scope host names are pinned to the IP that
`safety` resolved with `--host-resolver-rules`; other names do not resolve, so hosts reached only
through a `*.domain` scope entry are blocked in the browser. Service workers and downloads are
disabled. The rendered DOM's forms are analysed with `webapp`'s form/CSRF checks; cookies are
reported with their flags only and marked when JavaScript created them; console errors and mixed
content are reported. Nothing is clicked or submitted.

## 8. Python API

```python
import session_audit, apispec, zapclient, browser
session_audit.audit("authorization.json", args)   # args: timeout, insecure_tls
apispec.audit("https://api.example.com/", args)  # args: timeout, scope, allow_private, insecure_tls
zapclient.audit("https://app.example.com/", args) # + zap_url, zap_api_key, zap_spider, zap_spider_max, zap_wait
browser.audit("https://app.example.com/", args)   # + browser_timeout
```

Each returns a module `data` dict with `findings` (evidence model, English enums), `checks` and
`assessment` (security / coverage / confidence), like `webapp`.
