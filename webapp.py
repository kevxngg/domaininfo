"""Web application security (passive): analyzes a full URL without submitting forms or
credentials.

Checks transport and HSTS, Content-Security-Policy, clickjacking, Referrer-Policy,
Permissions-Policy, nosniff, cookies (Secure, HttpOnly, SameSite), forms (user and password
fields, visible CSRF tokens and alternative protections), redirects, CORS, technical errors
and sensitive data in the response. Compares the page with the site root to prove that the
requested path was the one audited.

Every request is a GET, goes through ``safety`` (scope, pinned IP, limits) and every finding
says where it comes from (``evidence.Finding``). Categories, check ids, states, severities,
statuses and confidence values are English in the JSON; titles and texts follow the active
language.
"""

import hashlib
import html
from html.parser import HTMLParser
import http.client
import re
import time
from urllib import parse

import evidence
from i18n import tr
import safety

TOOL = "domaininfo.webapp"
CORS_PROBE = "https://domaininfo-cors-probe.invalid"
CSRF_NAME = re.compile(r"csrf|xsrf|authenticity_token|requestverificationtoken|^_token$|^token$|nonce|"
                       r"csrfmiddlewaretoken|anti.?forgery|form_key|__viewstategenerator", re.I)
# Matches field names of remote pages, so the Spanish words stay ("correo", "usuario", "cuenta").
USER_NAME = re.compile(r"user|login|e-?mail|correo|usuario|account|cuenta|identif|^uid$|^name$", re.I)
SESSION_NAME = re.compile(r"sess|sid|auth|token|jwt|login|remember|identity", re.I)
VERSION = re.compile(r"\d+\.\d+")

# (title, pattern); titles are English and translated when the finding is added
ERROR_SIGNATURES = (
    ("Python error traceback", r"Traceback \(most recent call last\)"),
    ("Django debug page", r"You're seeing this error because you have <code>DEBUG = True|DEBUG = True"),
    ("Java exception trace", r"\bat (?:java|javax|org\.springframework|org\.apache)\.[\w.$]+\(|Exception in thread \""),
    ("PHP error with a server path", r"(?:Fatal error|Warning|Parse error|Notice)</b>?:? .{0,200}? on line <b>?\d+"),
    ("ASP.NET error page", r"Server Error in '/' Application|<b>Stack Trace:</b>"),
    ("Database error message", r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|"
                               r"PG::\w+Error|Microsoft OLE DB Provider|SQLite3::|psycopg2\.\w+Error"),
    ("Laravel/Symfony exception page", r"Whoops, looks like something went wrong|Symfony\\Component\\"),
    ("Rails exception page", r"Action Controller: Exception caught"),
    ("Node.js exception trace", r"\n[ \t]{1,16}at [\w.<>]{1,200} \((?:/|[A-Z]:\\)[^)\n]{1,500}\.js:\d+:\d+\)"),
)
# (title, pattern, severity, status, reference)
SECRET_SIGNATURES = (
    ("Private key in the response", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "high", "confirmed", "CWE-321"),
    ("AWS access key in the response", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high", "likely", "CWE-798"),
    ("GitHub token in the response", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high", "likely", "CWE-798"),
    ("Slack token in the response", r"\bxox[abprs]-[\w-]{10,}", "high", "likely", "CWE-798"),
    ("Google API key in the response", r"\bAIza[\w-]{35}\b", "low", "informational", "CWE-798"),
    ("JWT embedded in the page", r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}", "medium", "pending", "CWE-200"),
    ("Internal IP address in the response",
     r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "low", "informational", "CWE-200"),
)
OWASP_HEADERS = "OWASP Secure Headers Project"
SCAN_LIMIT = 256 * 1024  # error and secret signatures only scan this prefix of the response
URL_KEYS = {"url", "final_url", "from", "location", "action", "target"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _scrub(value, key=None):
    """Strip control characters from everything that comes from the target and hide secrets in URLs."""
    if isinstance(value, dict):
        return {k: _scrub(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        return evidence.redact_url(value) if key in URL_KEYS and "://" in value else evidence.clean(value)
    return value


class _PageParser(HTMLParser):
    """Title, forms with their fields, and CSRF token meta tags."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.forms, self._form = [], None
        self.meta_csrf = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title" and not self.title:
            self._in_title = True
        elif tag == "meta" and CSRF_NAME.search(attrs.get("name", "")):
            self.meta_csrf.append(attrs.get("name"))
        elif tag == "form":
            self._form = {"method": (attrs.get("method") or "get").upper(), "action": attrs.get("action", ""),
                          "id": attrs.get("id") or attrs.get("name") or "", "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            kind = (attrs.get("type") or ("text" if tag == "input" else tag)).lower()
            if tag == "button" or kind in ("submit", "button", "image", "reset"):
                return
            self._form["fields"].append({"name": attrs.get("name") or attrs.get("id") or "", "type": kind,
                                         "autocomplete": attrs.get("autocomplete"), "has_value": bool(attrs.get("value"))})

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse_page(text):
    parser = _PageParser()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):  # broken HTML: keep what was read
        pass
    parser.title = html.unescape(re.sub(r"\s+", " ", parser.title)).strip()
    return parser


def parse_cookie(raw):
    """Attributes of a Set-Cookie header without keeping its value."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    samesite = attrs.get("samesite")
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": samesite.capitalize() if samesite else None,
            "domain": attrs.get("domain") or None, "path": attrs.get("path") or None,
            "persistent": "expires" in attrs or "max-age" in attrs,
            "session_like": bool(SESSION_NAME.search(name))}


def parse_csp(value):
    directives = {}
    for chunk in (value or "").split(";"):
        tokens = chunk.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def csp_issues(directives):
    """Concrete weaknesses of a CSP (without inventing the ones that cannot be seen)."""
    issues = []
    script = directives.get("script-src", directives.get("default-src"))
    name = "script-src" if "script-src" in directives else "default-src"
    if script is None:
        issues.append(tr("no script-src or default-src: scripts are not restricted"))
    else:
        strict = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                     for t in script)
        if "'unsafe-inline'" in script and not strict:
            issues.append(tr("'unsafe-inline' in {directive}", directive=name))
        if "'unsafe-eval'" in script:
            issues.append(tr("'unsafe-eval' in {directive}", directive=name))
        if "*" in script or "https:" in script or "http:" in script:
            issues.append(tr("wildcard source in {directive}", directive=name))
        if "data:" in script:
            issues.append(tr("data: in {directive}", directive=name))
    if "object-src" not in directives and directives.get("default-src") != ["'none'"]:
        issues.append(tr("missing object-src 'none'"))
    if "base-uri" not in directives:
        issues.append(tr("missing base-uri"))
    return issues


def _fingerprint(response, page):
    return {"status": response.status, "title": page.title or None,
            "sha256": hashlib.sha256(response.body).hexdigest()[:16], "forms": len(page.forms),
            "length": len(response.body)}


class _Audit:
    def __init__(self, url, args):
        self.url = safety.normalize_url(url)
        self.args = args
        self.timeout = getattr(args, "timeout", 5.0)
        self.insecure = bool(getattr(args, "insecure_tls", False))
        self.policy = safety.ScopePolicy(self.url, extra_hosts=list(getattr(args, "scope", None) or []),
                                         allow_private=bool(getattr(args, "allow_private", False)))
        self.findings, self.checks = [], {}
        # Total deadline for the three requests (page, CORS and root) including their redirects
        self.deadline = time.monotonic() + min(180.0, max(30.0, self.timeout * 12))

    # -- helpers ------------------------------------------------------------------------------
    def get(self, url, headers=None):
        try:
            return safety.http_get(url, self.policy, self.timeout, headers=headers, insecure_tls=self.insecure,
                                   deadline=self.deadline)
        except http.client.HTTPException as exc:
            raise OSError(tr("Invalid HTTP response: {error}", error=exc)) from exc

    def check(self, cid, state, evidence_kind="direct", detail=None):
        entry = {"id": cid, "state": state, "evidence": evidence_kind}
        if detail:
            entry["detail"] = detail
        self.checks[cid] = entry

    def add(self, category, title, severity, status, proof, recommendation, impact="", verification="",
            references=(), confidence="high"):
        self.findings.append(evidence.Finding(
            target=evidence.redact_url(self.url), path=parse.urlsplit(self.final).path or "/", category=category, title=title,
            severity=severity, status=status, confidence=confidence, evidence=proof, tool=TOOL, impact=impact,
            verification=verification, recommendation=recommendation, references=list(references)).to_dict())

    # -- audit --------------------------------------------------------------------------------
    def run(self):
        response = self.get(self.url)
        self.final = response.url
        self.https = parse.urlsplit(self.final).scheme == "https"
        self.headers = {k.lower(): v for k, v in response.headers}
        text = response.body.decode(_charset(self.headers.get("content-type")), "replace")
        page = parse_page(text)
        result = {"url": self.url, "final_url": self.final, "status": response.status, "title": page.title or None,
                  "address": response.address, "tls_verified": response.tls_verified,
                  "truncated": response.truncated, "redirects": response.redirects}
        self.transport()
        self.redirects(response.redirects)
        result["headers"] = self.security_headers()
        result["cookies"] = self.cookies(response.header_all("set-cookie"))
        result["forms"] = self.forms(page, result["cookies"])
        result["cors"] = self.cors()
        self.errors(text[:SCAN_LIMIT], response.status)
        self.exposure(text[:SCAN_LIMIT])
        result["root_comparison"] = self.root(response, page)
        self.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["category"]))
        checks = list(self.checks.values())
        result.update({"findings": self.findings, "checks": checks,
                       "assessment": evidence.scores(self.findings, checks),
                       "note": tr("Passive analysis: GET requests only; no forms or credentials are sent")})
        return _scrub(result)

    def transport(self):
        if self.https:
            self.check("https", "ok")
            if self.insecure:
                self.add("transport", tr("TLS certificate not verified (audited with --insecure-tls)"), "medium",
                         "informational", tr("The connection was accepted without validating the certificate"),
                         tr("Install a valid certificate; check the TLS module"), confidence="medium")
        else:
            self.check("https", "finding")
            self.add("transport", tr("The page is served over unencrypted HTTP"), "medium", "confirmed",
                     tr("Final URL: {url}", url=self.final), tr("Serve the site over HTTPS only and redirect HTTP to HTTPS"),
                     impact=tr("Anyone on the network can read or alter the page and the data sent"),
                     verification=tr("Open the URL with http:// and check that it does not redirect to https://"),
                     references=["CWE-319", "OWASP ASVS V9.1"])

    def redirects(self, chain):
        state = "ok"
        for hop in chain:
            if hop.get("downgrade"):
                state = "finding"
                self.add("redirects", tr("Redirect from HTTPS to HTTP"), "medium", "confirmed",
                         f"{hop['status']} {hop['from']} → {hop['location']}",
                         tr("Make every redirect point to HTTPS"), references=["CWE-319"])
            if hop.get("blocked"):
                state = "finding"
                self.add("redirects", tr("Redirect not followed: outside the authorized scope"), "info", "informational",
                         f"{hop['status']} → {hop.get('location')} ({hop['blocked']})",
                         tr("If the destination is also authorized, add it with --scope"),
                         verification=tr("Check where the page redirects and whether that destination is yours"))
        self.check("redirects", state)

    def security_headers(self):
        h = self.headers
        out = {}
        # HSTS
        hsts = h.get("strict-transport-security")
        age = re.search(r"max-age=\"?(\d{1,12})\b", hsts or "")
        out["hsts"] = {"present": bool(hsts), "max_age": int(age.group(1)) if age else None,
                       "include_subdomains": "includesubdomains" in (hsts or "").lower(),
                       "preload": "preload" in (hsts or "").lower()}
        if not self.https:
            self.check("hsts", "not_applicable")
        elif not hsts:
            self.check("hsts", "finding")
            self.add("hsts", tr("No HSTS (Strict-Transport-Security)"), "medium", "confirmed", tr("Header missing"),
                     tr("Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
                     impact=tr("An attacker on the network can force the first visit over HTTP"),
                     references=["CWE-319", OWASP_HEADERS])
        elif not age or int(age.group(1)) < 15552000:
            self.check("hsts", "finding")
            self.add("hsts", tr("HSTS lasts less than 6 months"), "low", "confirmed",
                     "Strict-Transport-Security: " + hsts, tr("Use a max-age of at least 15552000 (6 months)"),
                     references=[OWASP_HEADERS])
        else:
            self.check("hsts", "ok")
        # CSP
        csp_value = h.get("content-security-policy")
        report_only = h.get("content-security-policy-report-only")
        directives = parse_csp(csp_value)
        issues = csp_issues(directives) if csp_value else []
        out["csp"] = {"present": bool(csp_value), "report_only": bool(report_only) and not csp_value,
                      "directives": sorted(directives), "issues": issues}
        if not csp_value:
            self.check("csp", "finding")
            self.add("csp", tr("No Content-Security-Policy (report-only mode only)") if report_only
                     else tr("No Content-Security-Policy"),
                     "medium", "confirmed", tr("Report-Only only") if report_only else tr("Header missing"),
                     tr("Define a CSP with a restricted script-src (nonces or hashes), object-src 'none' and "
                        "base-uri 'self'"),
                     impact=tr("An XSS flaw would face fewer barriers"), references=["CWE-1021", "CWE-79", OWASP_HEADERS])
        elif issues:
            self.check("csp", "finding")
            self.add("csp", tr("Weak CSP: {issues}", issues="; ".join(issues)), "low", "confirmed",
                     "Content-Security-Policy: " + csp_value,
                     tr("Remove 'unsafe-inline'/'unsafe-eval' and wildcards; add object-src 'none' and base-uri"),
                     references=["CWE-79", OWASP_HEADERS])
        else:
            self.check("csp", "ok")
        # Clickjacking
        xfo = (h.get("x-frame-options") or "").upper()
        ancestors = directives.get("frame-ancestors")
        protected = xfo in ("DENY", "SAMEORIGIN") or (ancestors is not None and "*" not in ancestors)
        out["clickjacking"] = {"protected": protected, "x_frame_options": xfo or None,
                               "frame_ancestors": " ".join(ancestors) if ancestors is not None else None}
        if protected:
            self.check("clickjacking", "ok")
        else:
            self.check("clickjacking", "finding")
            self.add("clickjacking", tr("No clickjacking protection"), "medium", "confirmed",
                     tr("Neither a valid X-Frame-Options nor CSP frame-ancestors"),
                     tr("Add CSP frame-ancestors 'self' (or X-Frame-Options: DENY)"),
                     impact=tr("The page can be embedded in another one to trick the user"),
                     verification=tr("Load the URL in an <iframe> from another origin"), references=["CWE-1021"])
        # nosniff
        nosniff = (h.get("x-content-type-options") or "").lower() == "nosniff"
        out["x_content_type_options"] = nosniff
        self.check("nosniff", "ok" if nosniff else "finding")
        if not nosniff:
            self.add("headers", tr("No X-Content-Type-Options: nosniff"), "low", "confirmed", tr("Header missing"),
                     tr("Add X-Content-Type-Options: nosniff"), references=["CWE-693", OWASP_HEADERS])
        # Referrer-Policy
        referrer = (h.get("referrer-policy") or "").lower()
        out["referrer_policy"] = referrer or None
        # With several policies, the browser applies the last one it understands
        effective = referrer.split(",")[-1].strip() if referrer else ""
        if effective in ("unsafe-url", "no-referrer-when-downgrade"):
            self.check("referrer", "finding")
            self.add("headers", tr("Permissive Referrer-Policy: {policy}", policy=referrer), "low", "confirmed",
                     "Referrer-Policy: " + referrer, tr("Use strict-origin-when-cross-origin or no-referrer"),
                     impact=tr("Full URLs (with parameters) are sent to other sites"), references=["CWE-200"])
        elif not referrer:
            self.check("referrer", "finding")
            self.add("headers", tr("No Referrer-Policy (the browser default applies)"), "info", "informational",
                     tr("Header missing"), tr("Set Referrer-Policy: strict-origin-when-cross-origin"),
                     references=[OWASP_HEADERS])
        else:
            self.check("referrer", "ok")
        # Permissions-Policy
        permissions = h.get("permissions-policy")
        out["permissions_policy"] = permissions
        self.check("permissions", "ok" if permissions else "finding")
        if not permissions:
            self.add("headers", tr("No Permissions-Policy"), "info", "informational", tr("Header missing"),
                     tr("Disable what you do not use: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
                     references=[OWASP_HEADERS])
        # Exposed versions
        leaks = [f"{n}: {h[n]}" for n in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                                          "x-generator") if n in h and VERSION.search(h[n])]
        out["version_leaks"] = leaks
        for leak in leaks:
            self.add("exposure", tr("The header reveals the software version"), "low", "confirmed", leak,
                     tr("Hide the version in the server configuration"), references=["CWE-200"])
        return out

    def cookies(self, raw_cookies):
        rows = [parse_cookie(raw) for raw in raw_cookies]
        if not rows:
            self.check("cookies", "not_applicable", detail=tr("The response sets no cookies"))
            return rows
        state = "ok"
        for row in rows:
            name = row["name"]
            proof = f"Set-Cookie: {name}=…" + "".join(
                f"; {k}" for k, v in (("Secure", row["secure"]), ("HttpOnly", row["httponly"])) if v) \
                + (f"; SameSite={row['samesite']}" if row["samesite"] else "")
            if self.https and not row["secure"]:
                state = "finding"
                self.add("cookies", tr("Cookie {name} without Secure", name=name),
                         "medium" if row["session_like"] else "low",
                         "confirmed", proof, tr("Mark the cookie with Secure"),
                         impact=tr("It can travel over unencrypted HTTP"), references=["CWE-614"])
            if not row["httponly"]:
                state = "finding"
                self.add("cookies", tr("Cookie {name} without HttpOnly", name=name),
                         "medium" if row["session_like"] else "low",
                         "confirmed" if row["session_like"] else "informational", proof,
                         tr("Mark cookies that JavaScript does not need with HttpOnly"),
                         impact=tr("An XSS could read it"), references=["CWE-1004"],
                         confidence="high" if row["session_like"] else "medium")
            if not row["samesite"]:
                state = "finding"
                self.add("cookies", tr("Cookie {name} without an explicit SameSite", name=name), "low",
                         "informational", proof,
                         tr("Set SameSite=Lax or Strict (None only with Secure, and only if essential)"),
                         impact=tr("It depends on each browser's default"), references=["CWE-1275"])
            elif row["samesite"] == "None" and not row["secure"]:
                state = "finding"
                self.add("cookies", tr("Cookie {name} with SameSite=None but no Secure", name=name), "medium",
                         "confirmed", proof,
                         tr("SameSite=None requires Secure; browsers will reject the cookie or send it on "
                            "third-party requests"), references=["CWE-1275"])
        self.check("cookies", state)
        return rows

    def forms(self, page, cookies):
        rows = []
        samesite = [c["name"] for c in cookies if c["samesite"] in ("Lax", "Strict")]
        csrf_state = "not_applicable"
        for index, form in enumerate(page.forms, 1):
            action = parse.urljoin(self.final, html.unescape(form["action"])) if form["action"] else self.final
            fields = form["fields"]
            passwords = [f["name"] for f in fields if f["type"] == "password"]
            users = [f["name"] for f in fields if f["type"] in ("text", "email", "tel")
                     and USER_NAME.search(f["name"])]
            tokens = [f["name"] for f in fields if f["type"] == "hidden" and CSRF_NAME.search(f["name"])
                      and f["has_value"]]
            label = tr("Form {index} ({id})", index=index, id=form["id"]) if form["id"] \
                else tr("Form {index}", index=index)
            row = {"index": index, "id": form["id"] or None, "method": form["method"], "action": action,
                   "fields": [{"name": f["name"], "type": f["type"]} for f in fields],
                   "login": bool(passwords), "password_fields": passwords, "user_fields": users}
            if form["method"] in ("POST", "PUT", "PATCH", "DELETE"):
                if tokens:
                    csrf = {"state": "token_visible", "fields": tokens, "evidence": "direct"}
                    csrf_state = _worst(csrf_state, "ok")
                elif page.meta_csrf:
                    csrf = {"state": "token_in_meta", "fields": page.meta_csrf, "evidence": "heuristic"}
                    csrf_state = _worst(csrf_state, "ok")
                    self.add("csrf", tr("{form}: CSRF token in <meta>, not in the form", form=label), "info",
                             "informational", f"<meta name='{page.meta_csrf[0]}'>",
                             tr("Check that the JavaScript sends it in a header on every request"),
                             verification=tr("Check the request header in the browser developer tools"),
                             confidence="medium")
                elif samesite:
                    csrf = {"state": "alternative_protection", "fields": [], "cookies_samesite": samesite,
                            "evidence": "heuristic"}
                    csrf_state = _worst(csrf_state, "finding")
                    self.add("csrf", tr("{form}: no visible CSRF token; relies on SameSite cookies", form=label), "info",
                             "informational", tr("Cookies with SameSite: {names}", names=", ".join(samesite)),
                             tr("Add a per-session CSRF token on top of SameSite"),
                             verification=tr("In an authorized environment, submit the form from another origin "
                                             "and check that the server rejects it"), references=["CWE-352"],
                             confidence="medium")
                else:
                    csrf = {"state": "unknown", "fields": [], "evidence": "heuristic"}
                    csrf_state = _worst(csrf_state, "finding")
                    self.add("csrf", tr("{form}: no CSRF protection visible (pending verification)", form=label),
                             "medium", "pending",
                             tr("{method} {action} without a hidden token field or SameSite cookies",
                                method=form["method"], action=action),
                             tr("Use a per-session CSRF token or check Origin/Referer on the server"),
                             impact=tr("Without another defense, another site could submit the form on the user's behalf"),
                             verification=tr("The protection may live in headers or on the server: check it with a "
                                             "test account in an authorized environment"),
                             references=["CWE-352", "OWASP ASVS V4.2.2"], confidence="low")
            else:
                csrf = {"state": "not_applicable", "fields": [], "evidence": "direct"}
            row["csrf"] = csrf
            if passwords:
                if form["method"] == "GET":
                    self.add("forms", tr("{form}: the password is sent by GET (it ends up in the URL)", form=label),
                             "high", "confirmed",
                             tr("<form method='GET' action='{action}'> with a password field", action=action),
                             tr("Use method='post' on forms with a password"),
                             impact=tr("The password ends up in histories, server logs and the Referer"),
                             references=["CWE-598"])
                if parse.urlsplit(action).scheme == "http" or not self.https:
                    self.add("forms", tr("{form}: the password travels over unencrypted HTTP", form=label), "high",
                             "confirmed", tr("Page {page} · destination {action}", page=self.final, action=action),
                             tr("Serve the page and the destination over HTTPS"),
                             impact=tr("Anyone on the network can read the password"), references=["CWE-319"])
            if parse.urlsplit(action).netloc != parse.urlsplit(self.final).netloc:
                self.add("forms", tr("{form}: sends data to another origin", form=label), "info", "informational",
                         tr("destination {action}", action=action),
                         tr("Check that the destination is yours and trusted"), confidence="medium")
            rows.append(row)
        self.check("forms", "ok" if page.forms else "not_applicable")
        self.check("csrf", csrf_state, "direct" if csrf_state == "ok" else "heuristic")
        return rows

    def cors(self):
        try:
            response = self.get(self.final, headers={"Origin": CORS_PROBE})
        except (OSError, ValueError) as exc:
            self.check("cors", "error", detail=str(exc))
            return {"error": str(exc)}
        allow = response.header("access-control-allow-origin")
        credentials = (response.header("access-control-allow-credentials") or "").lower() == "true"
        result = {"allow_origin": allow, "credentials": credentials, "reflects_origin": allow == CORS_PROBE}
        proof = f"Origin: {CORS_PROBE} → Access-Control-Allow-Origin: {allow}" + \
            ("; Access-Control-Allow-Credentials: true" if credentials else "")
        if allow == CORS_PROBE:
            self.check("cors", "finding")
            self.add("cors", tr("CORS accepts any origin with credentials") if credentials
                     else tr("CORS accepts any origin"),
                     "high" if credentials else "low", "confirmed" if credentials else "likely", proof,
                     tr("Use a closed list of allowed origins"),
                     impact=tr("Another site could read the user's authenticated responses") if credentials
                     else tr("Another site could read responses"),
                     verification=tr("Repeat the request with another Origin header and compare the response"),
                     references=["CWE-942", "OWASP ASVS V14.5.3"])
        elif allow == "null":
            self.check("cors", "finding")
            self.add("cors", tr("CORS allows the null origin"), "medium", "confirmed", proof,
                     tr("Do not include 'null' among the allowed origins"), references=["CWE-942"])
        elif allow == "*":
            self.check("cors", "ok")
            self.add("cors", tr("Public CORS (*): any site can read this response without credentials"), "info",
                     "informational", proof,
                     tr("Fine for public content; review it if the response is private"))
        else:
            self.check("cors", "ok")
        return result

    def errors(self, text, status):
        found = []
        for name, pattern in ERROR_SIGNATURES:
            match = re.search(pattern, text, re.I)
            if match:
                found.append(name)
                start = max(0, match.start() - 40)
                self.add("errors", tr(name), "medium", "confirmed", text[start:match.end() + 120],
                         tr("Disable debug mode and show generic error pages"),
                         impact=tr("Reveals internal paths, versions or queries that make an attack easier"),
                         references=["CWE-209", "OWASP ASVS V7.4.1"])
        self.check("errors", "finding" if found else "ok", "heuristic",
                   detail=None if status < 500 or found
                   else tr("HTTP {status} without visible technical details", status=status))

    def exposure(self, text):
        state = "ok"
        for name, pattern, severity, status, cwe in SECRET_SIGNATURES:
            matches = re.findall(pattern, text)
            if matches:
                state = "finding"
                self.add("exposure", tr(name), severity, status,
                         tr("{count} match(es): {first}", count=len(matches), first=matches[0]),
                         tr("Remove the data from the response and, if it is a credential, revoke it and issue "
                            "a new one"),
                         verification=tr("Look for the value in the source code and check with its owner "
                                         "whether it is still valid"), references=[cwe],
                         confidence="high" if status == "confirmed" else "medium")
        self.check("exposure", state, "heuristic")

    def root(self, response, page):
        parts = parse.urlsplit(self.final)
        root_url = parse.urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        mine = _fingerprint(response, page)
        if self.final == root_url:
            self.check("root", "not_applicable")
            return {"url": root_url, "same_as_target": True}
        try:
            other = self.get(root_url)
        except (OSError, ValueError) as exc:
            self.check("root", "error", detail=str(exc))
            return {"url": root_url, "error": str(exc)}
        other_page = parse_page(other.body.decode(_charset(other.header("content-type")), "replace"))
        theirs = _fingerprint(other, other_page)
        self.check("root", "ok")
        return {"url": root_url, "final_url": other.url, **theirs,
                "differs": (mine["status"], mine["title"], mine["sha256"]) !=
                           (theirs["status"], theirs["title"], theirs["sha256"])}


def _worst(current, new):
    rank = {"not_applicable": 0, "ok": 1, "finding": 2}
    return new if rank[new] > rank[current] else current


def _charset(content_type):
    match = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    name = match.group(1) if match else "utf-8"
    try:
        "".encode(name)
        return name
    except (LookupError, ValueError):  # unknown or unusable codec (e.g. "undefined")
        return "utf-8"


def audit(url, args):
    """Passive audit of a full URL. ``args`` provides timeout, scope, allow_private and insecure_tls."""
    return _Audit(url, args).run()
