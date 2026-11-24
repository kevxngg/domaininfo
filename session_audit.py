"""Authenticated session audit for AUTHORIZED systems only (DomainInfo 6.0, Phase 2).

Requires an authorization file (``authscope``) and test accounts whose credentials come from
environment variables. What it does, in this order, inside a request budget and the file's time
window:

1. Anonymous baseline of the protected URLs.
2. Login flow of each test account (GET the form, POST the credentials once). Detects an MFA step.
3. Session fixation (does the session cookie change at login?), session cookie flags and lifetime.
4. Access control between roles (account A requests role B's protected URLs).
5. Logout: the old session cookie must not open a protected URL any more; a new login must
   issue a new token (token invalidation).
6. User enumeration: wrong password for the test account vs. a random non-existent user.
7. Optional controlled lockout/rate-limit check, against the configured TEST account only, with
   at most ``max_login_attempts`` failed attempts (hard cap 5) and stopping at the first signal.

No brute force, no wordlists, no evasion. Passwords, usernames, session cookies, CSRF tokens and
other secrets never appear in the result or in exception messages: everything leaving this
module goes through ``_Secrets.scrub``.

Public API: ``audit(config_path, args=None, now=None, environ=None) -> dict`` (a DomainInfo
module ``data`` dict: findings, checks, assessment...). Raises ``authscope.AuthorizationError``
when the authorization file is missing, invalid, expired or does not cover a URL.
"""

import hashlib
import html
import http.client
import re
import secrets
import time
from typing import Any
from urllib import parse

import authscope
import evidence
from i18n import tr
import safety
import webapp

TOOL = "domaininfo.session"
SESSION_NAME = webapp.SESSION_NAME
LOCKOUT_TEXT = re.compile(r"too many|locked|lockout|temporarily (?:disabled|blocked|unavailable)|try again (?:later|in)|"
                          r"captcha|rate.?limit|demasiados intentos|bloquead|int[eé]ntalo m[aá]s tarde", re.I)
MFA_FIELD = re.compile(r"otp|totp|mfa|2fa|two.?factor|one.?time|verification.?code|auth.?code|^code$|security.?code",
                       re.I)
MFA_TEXT = re.compile(r"two.?factor|2.?step|verification code|authenticator app|one.?time (?:code|password)|"
                      r"security code|c[oó]digo de verificaci[oó]n|segundo factor", re.I)
DENIED = (401, 403, 404, 405)
LONG_SESSION = 30 * 86400


class _Stop(Exception):
    """Internal: the remaining checks cannot run (budget, window or login failure)."""


class _Secrets:
    """Every secret value seen during the run, to be removed from anything we output."""

    def __init__(self):
        self.values = set()

    def add(self, *values):
        for value in values:
            if value and len(str(value)) >= 3:
                self.values.add(str(value))
                self.values.add(parse.quote_plus(str(value)))
                self.values.add(parse.quote(str(value), safe=""))

    def scrub(self, value) -> Any:
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.values, key=len, reverse=True):
                if secret in value:
                    value = value.replace(secret, tr("[hidden]"))
            return value
        return value


class _FormPage(webapp._PageParser):
    """webapp's page parser plus hidden field values (kept in memory only) and visible text."""

    def __init__(self):
        super().__init__()
        self.values = []  # per form: {name: value} of hidden fields
        self.text = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        before = len(self.forms)
        super().handle_starttag(tag, attrs)
        if len(self.forms) > before:
            self.values.append({})
        named = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "template"):
            self._skip += 1
        elif tag == "input" and self._form is not None and (named.get("type") or "").lower() == "hidden":
            name = named.get("name")
            if name:
                self.values[-1][name] = named.get("value", "")

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        if tag in ("script", "style", "template") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        super().handle_data(data)
        if not self._skip and data.strip():
            self.text.append(re.sub(r"\s+", " ", data).strip())


def _parse(response):
    content_type = response.header("content-type") or ""
    charset = "utf-8"
    match = re.search(r"charset=([\w-]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        text = response.body.decode(charset, "replace")
    except LookupError:
        text = response.body.decode("utf-8", "replace")
    page = _FormPage()
    try:
        page.feed(text)
        page.close()
    except (AssertionError, ValueError):
        pass
    page.title = html.unescape(re.sub(r"\s+", " ", page.title)).strip()
    return page


def _login_form(page):
    for index, form in enumerate(page.forms):
        if any(f["type"] == "password" for f in form["fields"]):
            return index, form
    return None, None


def _mfa_form(page):
    for form in page.forms:
        for f in form["fields"]:
            if f["type"] == "password":
                continue
            if f.get("autocomplete") == "one-time-code" or (f["type"] in ("text", "number", "tel")
                                                           and MFA_FIELD.search(f["name"] or "")):
                return True
    return bool(page.forms) and bool(MFA_TEXT.search(" ".join(page.text)[:20000]))


class _View:
    """Comparable signature of a response (no body or secret is kept)."""

    def __init__(self, response, page, removed=()):
        text = " ".join(page.text)
        for value in removed:
            if value:
                text = text.replace(value, "")
        self.status = response.status
        self.path = parse.urlsplit(response.url).path or "/"
        self.url = response.url
        self.title = page.title
        self.length = len(text)
        self.digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        self.login_form = _login_form(page)[1] is not None
        self.lines = page.text[:400]
        self.retry_after = response.header("retry-after") is not None

    def ok(self):
        return 200 <= self.status < 300 and not self.login_form

    def similar(self, other):
        if self.digest == other.digest:
            return True
        longest = max(self.length, other.length, 1)
        return self.title == other.title and abs(self.length - other.length) / longest <= 0.15

    def describe(self):
        return tr("status {status}, path {path}, title '{title}', {length} characters of text",
                  status=self.status, path=self.path, title=self.title[:60], length=self.length)


class _SessionAudit:
    def __init__(self, scope, args, environ, now=None):
        self.scope = scope
        self.args = args
        self.environ = environ
        self.timeout = float(getattr(args, "timeout", 5.0) or 5.0)
        self.insecure = bool(getattr(args, "insecure_tls", False))
        self.policy = scope.policy()
        self.budget = safety.RequestBudget(scope.max_requests)
        run_limit = min(900.0, max(60.0, self.timeout * scope.max_requests))
        self.deadline = time.monotonic() + run_limit
        self.secrets = _Secrets()
        self.findings, self.checks = [], {}
        self.failed_attempts = {a.id: 0 for a in scope.accounts}
        self.credentials = {}
        for account in scope.accounts:
            user, password = account.credentials(environ)
            self.credentials[account.id] = (user, password)
            self.secrets.add(user, password)
        self.jars = []
        self.accounts = {}
        self.notes = []
        self.session_cookie_rows = []
        self.lockout_seen = 0
        self.now = now

    # -- plumbing -------------------------------------------------------------------------------
    def jar(self):
        jar = safety.CookieJar()
        self.jars.append(jar)
        return jar

    def request(self, method, url, jar, data=None):
        self.scope.check_window(self.now)
        url = self.scope.require(url)
        if data:
            for value in data.values():
                self.secrets.add(value)
        try:
            response = safety.http_request(method, url, self.policy, self.timeout, data=data, jar=jar,
                                           insecure_tls=self.insecure, deadline=self.deadline, budget=self.budget,
                                           allow=self.scope.in_targets)
        except http.client.HTTPException as exc:
            raise OSError(tr("Invalid HTTP response: {error}", error=type(exc).__name__)) from None
        finally:
            if jar is not None:
                self.secrets.add(*jar.secret_values())
        return response

    def check(self, cid, state, evidence_kind="direct", detail=None):
        entry = {"id": cid, "state": state, "evidence": evidence_kind}
        if detail:
            entry["detail"] = detail
        self.checks[cid] = entry

    def add(self, category, title, severity, status, proof, recommendation, path="/", impact="", verification="",
            references=(), confidence="high"):
        self.findings.append(evidence.Finding(
            target=evidence.redact_url(self.scope.targets[0]), path=path, category=category, title=title,
            severity=severity, status=status, confidence=confidence, evidence=self.secrets.scrub(proof), tool=TOOL,
            impact=impact, verification=verification, recommendation=recommendation,
            references=list(references)).to_dict())

    def view(self, method, url, jar, data=None, removed=()):
        response = self.request(method, url, jar, data)
        page = _parse(response)
        return response, page, _View(response, page, removed)

    # -- login ----------------------------------------------------------------------------------
    def login(self, account_id, password=None, username=None, jar=None):
        """One login attempt. Returns a dict with outcome ('form_missing', 'mfa', 'success',
        'failed'), the jar, cookie digests before/after and the response view."""
        jar = jar if jar is not None else self.jar()
        real_user, real_password = self.credentials.get(account_id, (None, None))
        username = real_user if username is None else username
        password = real_password if password is None else password
        self.secrets.add(username, password)
        response = self.request("GET", self.scope.login_url, jar)
        page = _parse(response)
        index, form = _login_form(page)
        if form is None or index is None:
            return {"outcome": "form_missing", "jar": jar, "view": _View(response, page)}
        action = parse.urljoin(response.url, html.unescape(form["action"])) if form["action"] else response.url
        action = safety.normalize_url(action)
        if not self.scope.in_targets(action):
            raise authscope.AuthorizationError(tr("The login form posts to a URL outside the authorized targets"))
        if form["method"] != "POST":
            return {"outcome": "form_get", "jar": jar, "view": _View(response, page)}
        hidden = page.values[index]
        self.secrets.add(*hidden.values())
        names = [f["name"] for f in form["fields"] if f["name"]]
        password_field = self.scope.password_field or next(f["name"] for f in form["fields"] if f["type"] == "password")
        username_field = self.scope.username_field or next(
            (f["name"] for f in form["fields"] if f["type"] in ("text", "email", "tel") and webapp.USER_NAME.search(f["name"])),
            next((f["name"] for f in form["fields"] if f["type"] in ("text", "email")), None))
        if not username_field or username_field not in names and not self.scope.username_field:
            return {"outcome": "form_missing", "jar": jar, "view": _View(response, page)}
        data = dict(hidden)
        data[username_field] = username
        data[password_field] = password
        before = {name: jar.digest(name) for name in jar.names()}
        response = self.request("POST", action, jar, data)
        page = _parse(response)
        after = {name: jar.digest(name) for name in jar.names()}
        view = _View(response, page, removed=(username,))
        if _mfa_form(page) and not view.login_form:
            outcome = "mfa"
        elif view.login_form or response.status >= 400:
            outcome = "failed"
        else:
            outcome = "success"
        return {"outcome": outcome, "jar": jar, "before": before, "after": after, "view": view,
                "attributes": {name: jar.attributes(name) for name in jar.names()}}

    def failed_attempt(self, account_id, username=None):
        """A deliberately wrong password for a TEST account, never beyond the configured cap."""
        if self.failed_attempts[account_id] >= self.scope.max_login_attempts:
            raise _Stop(tr("Login attempt limit reached ({limit})", limit=self.scope.max_login_attempts))
        self.failed_attempts[account_id] += 1
        return self.login(account_id, password="Wrong-" + secrets.token_urlsafe(12), username=username)

    # -- run ------------------------------------------------------------------------------------
    def run(self):
        scope = self.scope
        result = {"target": evidence.redact_url(scope.login_url), "authorization": scope.summary()}
        anonymous = {}
        try:
            self.anonymous_baseline(anonymous)
            primary = scope.accounts[0]
            first = self.session_checks(primary)
            for account in scope.accounts[1:]:
                self.login_account(account)
            self.anonymous_access(anonymous)
            self.access_control(anonymous)
            self.logout_checks(primary, first)
            self.enumeration(primary)
            self.lockout()
        except safety.BudgetExceeded as exc:
            self.notes.append(str(exc))
        except _Stop as exc:
            self.notes.append(str(exc))
        except (OSError, ValueError) as exc:
            if isinstance(exc, authscope.AuthorizationError):
                raise
            self.notes.append(tr("Audit stopped: {error}", error=str(exc)[:300]))
        for cid in ("login", "mfa", "session_fixation", "cookie_flags", "session_expiry", "anonymous_access",
                    "access_control", "logout", "token_invalidation", "user_enumeration", "lockout"):
            if cid not in self.checks:
                self.check(cid, "not_evaluated", detail=tr("Not run (see the notes)") if self.notes else None)
        if not scope.lockout_check:
            self.check("lockout", "not_evaluated", detail=tr("Disabled in the authorization file (lockout_check)"))
        checks = list(self.checks.values())
        self.findings.sort(key=lambda f: (webapp.SEVERITY_ORDER[f["severity"]], f["category"]))
        result.update({
            "accounts": [{"id": a.id, "role": a.role, "login": self.accounts.get(a.id, {}).get("outcome", "not_evaluated")}
                         for a in scope.accounts],
            "session_cookies": self.session_cookie_rows,
            "requests": {"used": self.budget.used, "limit": self.budget.limit},
            "login_attempts": {"failed": dict(self.failed_attempts), "limit": scope.max_login_attempts},
            "findings": self.findings, "checks": checks, "assessment": evidence.scores(self.findings, checks),
            "notes": self.notes,
            "note": tr("Authenticated audit of an authorized system with test accounts; no brute force, no "
                       "wordlists; secrets are never stored or shown")})
        for jar in self.jars:
            self.secrets.add(*jar.secret_values())
        return self.secrets.scrub(result)

    def anonymous_baseline(self, anonymous):
        for url in self.protected_urls():
            _, _, anonymous[url] = self.view("GET", url, self.jar())

    def login_account(self, account):
        result = self.login(account.id)
        self.accounts[account.id] = result
        if result["outcome"] == "success":
            urls = self.scope.roles.get(account.role) or []
            if urls:
                _, _, view = self.view("GET", urls[0], result["jar"])
                if not view.ok():
                    result["outcome"] = "failed"
        result.setdefault("views", {})
        if result["outcome"] == "success":
            for url in self.scope.roles.get(account.role) or []:
                _, _, result["views"][url] = self.view("GET", url, result["jar"])
        return result

    def session_names(self, before, after):
        """Cookies examined by the fixation and flag checks: every session-named cookie (changed or
        not, so an unchanged session id is never skipped) plus every cookie the login set or changed."""
        changed = [n for n in after if before.get(n) != after[n]]
        named = [n for n in after if SESSION_NAME.search(n)]
        return named + [n for n in changed if n not in named]

    def session_checks(self, account):
        result = self.login_account(account)
        outcome = result["outcome"]
        login_path = parse.urlsplit(self.scope.login_url).path or "/"
        if outcome in ("form_missing", "form_get"):
            self.check("login", "error", detail=tr("No usable POST login form at the login URL"))
            raise _Stop(tr("No usable POST login form at the login URL"))
        if outcome == "mfa":
            self.check("login", "ok")
            self.check("mfa", "ok")
            self.add("mfa", tr("A second authentication step (MFA) follows the password"), "info", "informational",
                     tr("After the password the application asks for a verification code"),
                     tr("Keep MFA enforced for every account"), path=login_path,
                     verification=tr("Log in with the test account and check the second step"))
            raise _Stop(tr("The MFA step cannot be automated: session checks were not run"))
        if outcome != "success":
            self.check("login", "error", detail=tr("Login with test account {account} failed", account=account.id))
            raise _Stop(tr("Login with test account {account} failed: check the credentials and the field names",
                           account=account.id))
        self.check("login", "ok")
        self.check("mfa", "finding", "heuristic")
        self.add("mfa", tr("No second factor was requested for test account {account}", account=account.id), "low",
                 "pending", tr("The password alone opened a session"),
                 tr("Require MFA for privileged and, if possible, all accounts"), path=login_path,
                 verification=tr("Test accounts are often exempt: check the MFA policy for real accounts"),
                 references=["OWASP ASVS V2.8", "CWE-308"], confidence="low")
        names = self.session_names(result["before"], result["after"])
        result["session_names"] = names
        rows = [result["attributes"][n] for n in names if result["attributes"].get(n)]
        self.session_cookie_rows = rows
        self.fixation(result, names, login_path)
        self.cookie_flags(rows, login_path)
        return result

    def fixation(self, result, names, path):
        if not names:
            self.check("session_fixation", "not_evaluated",
                       detail=tr("No session cookie observed (token-based authentication?)"))
            return
        fixed = [n for n in names if result["before"].get(n) and result["before"][n] == result["after"].get(n)]
        if fixed:
            # If the login also set another cookie, that one may be the real session token
            renewed = [n for n in names if n not in fixed and result["after"].get(n)]
            self.check("session_fixation", "finding", "heuristic" if renewed else "direct")
            self.add("session", tr("Session identifier not renewed at login (session fixation)"), "high",
                     "likely" if renewed else "confirmed",
                     tr("Cookie {name} kept the same value before and after the login", name=fixed[0]),
                     tr("Issue a new session identifier on every successful login and discard the old one"),
                     path=path, impact=tr("An attacker who plants a session id can take over the session after "
                                          "the victim logs in"),
                     verification=tr("Note the session cookie before logging in and compare it after logging in"),
                     references=["CWE-384", "OWASP ASVS V3.2.1"], confidence="medium" if renewed else "high")
        else:
            self.check("session_fixation", "ok")

    def cookie_flags(self, rows, path):
        if not rows:
            self.check("cookie_flags", "not_evaluated", detail=tr("No session cookie observed"))
            self.check("session_expiry", "not_evaluated", detail=tr("No session cookie observed"))
            return
        https = parse.urlsplit(self.scope.login_url).scheme == "https"
        state, expiry = "ok", "ok"
        for row in rows:
            name = row["name"]
            proof = tr("Flags of session cookie {name} are Secure={secure}, HttpOnly={httponly}, SameSite={samesite}",
                       name=name, secure=row["secure"], httponly=row["httponly"], samesite=row["samesite"] or "-")
            if not https:
                state = "finding"
                self.add("transport", tr("Session cookie {name} travels over unencrypted HTTP", name=name), "high",
                         "confirmed", proof, tr("Serve the application over HTTPS only and mark the cookie Secure"),
                         path=path, impact=tr("Anyone on the network can steal the session"),
                         references=["CWE-319", "CWE-614"])
            elif not row["secure"]:
                state = "finding"
                self.add("cookies", tr("Session cookie {name} without Secure", name=name), "medium", "confirmed",
                         proof, tr("Mark the session cookie with Secure"), path=path, references=["CWE-614"])
            if not row["httponly"]:
                state = "finding"
                self.add("cookies", tr("Session cookie {name} without HttpOnly", name=name), "medium", "confirmed",
                         proof, tr("Mark the session cookie with HttpOnly"), path=path,
                         impact=tr("An XSS could read it"), references=["CWE-1004"])
            if not row["samesite"]:
                state = "finding"
                self.add("cookies", tr("Session cookie {name} without an explicit SameSite", name=name), "low",
                         "informational", proof, tr("Set SameSite=Lax or Strict on the session cookie"), path=path,
                         references=["CWE-1275"], confidence="medium")
            if row["lifetime"] is not None and row["lifetime"] > LONG_SESSION:
                expiry = "finding"
                self.add("session", tr("Session cookie {name} lives {days} days", name=name,
                                       days=round(row["lifetime"] / 86400)), "low", "likely",
                         tr("Max-Age/Expires of {name}: about {days} days", name=name, days=round(row["lifetime"] / 86400)),
                         tr("Use short-lived sessions with an idle timeout on the server"), path=path,
                         verification=tr("The server-side idle and absolute timeouts must be checked by hand"),
                         references=["OWASP ASVS V3.3", "CWE-613"], confidence="medium")
        self.check("cookie_flags", state)
        self.check("session_expiry", expiry, "heuristic" if expiry == "ok" else "direct",
                   detail=tr("Only the cookie lifetime is visible; server-side timeouts are not tested"))

    def anonymous_access(self, anonymous):
        if not anonymous:
            self.check("anonymous_access", "not_applicable", detail=tr("No protected URLs configured"))
            return
        state = "ok"
        for url in self.protected_urls():
            anon = anonymous.get(url)
            owner = self.owner_view(url)
            if anon is None or not anon.ok():
                continue
            path = parse.urlsplit(url).path or "/"
            if owner is not None and anon.similar(owner):
                state = "finding"
                # Same visible text is still a heuristic: an SPA shell is identical for everyone
                self.add("access_control", tr("Protected URL accessible without authentication"), "high", "likely",
                         tr("Anonymous: {anonymous} · authenticated: {authenticated}", anonymous=anon.describe(),
                            authenticated=owner.describe()),
                         tr("Require an authenticated session on every protected URL"), path=path,
                         impact=tr("Anyone can read the protected content"),
                         verification=tr("Open the URL in a private window without logging in"),
                         references=["CWE-306", "OWASP ASVS V4.1"])
            elif anon.ok():
                state = "finding"
                self.add("access_control", tr("Protected URL answers 2xx without authentication"), "medium",
                         "pending", tr("Anonymous: {anonymous}", anonymous=anon.describe()),
                         tr("Check that the URL is meant to be public; otherwise require a session"), path=path,
                         verification=tr("Compare the anonymous and the authenticated page by hand"),
                         references=["CWE-306"], confidence="low")
        self.check("anonymous_access", state, "heuristic" if state == "finding" else "direct")

    def protected_urls(self):
        seen = []
        for urls in self.scope.roles.values():
            seen += [u for u in urls if u not in seen]
        return seen

    def owner_view(self, url):
        for account in self.scope.accounts:
            data = self.accounts.get(account.id)
            if data and data.get("outcome") == "success" and url in data.get("views", {}):
                return data["views"][url]
        return None

    def access_control(self, anonymous):
        logged = [a for a in self.scope.accounts if self.accounts.get(a.id, {}).get("outcome") == "success"]
        if len({a.role for a in logged}) < 2:
            self.check("access_control", "not_applicable" if len(self.scope.roles) < 2 else "not_evaluated",
                       detail=tr("Needs logged-in test accounts with at least two different roles"))
            return
        state = "ok"
        for account in logged:
            own = set(self.scope.roles.get(account.role) or [])
            jar = self.accounts[account.id]["jar"]
            for role, urls in self.scope.roles.items():
                if role == account.role:
                    continue
                owner = next((a for a in logged if a.role == role), None)
                for url in urls:
                    if url in own or owner is None:
                        continue
                    reference = self.accounts[owner.id]["views"].get(url)
                    anon = anonymous.get(url)
                    _, _, view = self.view("GET", url, jar)
                    if reference is None or not view.ok() or not reference.ok():
                        continue
                    if anon is not None and anon.ok() and anon.similar(reference):
                        continue  # already reported as anonymous access
                    path = parse.urlsplit(url).path or "/"
                    proof = tr("{account} ({role}) → {own}; {owner} ({owner_role}) → {reference}", account=account.id,
                               role=account.role, own=view.describe(), owner=owner.id, owner_role=role,
                               reference=reference.describe())
                    state = "finding"
                    if view.similar(reference):
                        self.add("access_control", tr("Role {role} can open a URL reserved for role {other}",
                                                      role=account.role, other=role), "high",
                                 "likely", proof,
                                 tr("Enforce the role check on the server for every request"), path=path,
                                 impact=tr("Users can reach functions or data of another role"),
                                 verification=tr("Log in as {account} and open the URL", account=account.id),
                                 references=["CWE-285", "OWASP ASVS V4.1", "OWASP A01:2021"])
                    else:
                        self.add("access_control", tr("Role {role} gets a 2xx answer on a URL reserved for role {other}",
                                                      role=account.role, other=role), "medium", "pending", proof,
                                 tr("Check that the page shows no data or function of the other role"), path=path,
                                 verification=tr("Log in as {account}, open the URL and compare it with role {other}",
                                                 account=account.id, other=role),
                                 references=["CWE-285"], confidence="low")
        self.check("access_control", state, "heuristic" if state == "finding" else "direct")

    def logout_checks(self, account, first):
        urls = self.scope.roles.get(account.role) or []
        if not self.scope.logout_url:
            self.check("logout", "not_evaluated", detail=tr("No logout URL in the authorization file"))
            self.check("token_invalidation", "not_evaluated", detail=tr("No logout URL in the authorization file"))
            return
        if not urls or not first.get("session_names"):
            reason = tr("Needs a protected URL for the role and a session cookie")
            self.check("logout", "not_evaluated", detail=reason)
            self.check("token_invalidation", "not_evaluated", detail=reason)
            return
        url = urls[0]
        jar = first["jar"]
        reference = first["views"].get(url)
        old = jar.copy()
        self.jars.append(old)
        self.request(self.scope.logout_method, self.scope.logout_url,
                     jar, {} if self.scope.logout_method == "POST" else None)
        logout_path = parse.urlsplit(self.scope.logout_url).path or "/"
        names = first["session_names"]
        still = [n for n in names if jar.digest(n) and jar.digest(n) == old.digest(n)]
        _, _, after = self.view("GET", url, jar)
        if after.ok() and reference is not None and after.similar(reference) and still:
            self.check("logout", "finding", "heuristic")
            self.check("token_invalidation", "not_evaluated", detail=tr("The logout could not be verified"))
            self.add("logout", tr("Logout neither removed the session cookie nor ended the session"), "high",
                     "pending", tr("After calling the logout URL, {path} still opens with the same cookie: {view}",
                                   path=parse.urlsplit(url).path or "/", view=after.describe()),
                     tr("Invalidate the session on the server and expire the cookie at logout"), path=logout_path,
                     verification=tr("Check that logout.url is the real logout action, then log out in a browser "
                                     "and reuse the old cookie"), references=["CWE-613"], confidence="low")
            return
        replay = old.copy()
        self.jars.append(replay)
        _, _, view = self.view("GET", url, replay)
        path = parse.urlsplit(url).path or "/"
        if view.ok() and reference is not None and view.similar(reference):
            self.check("logout", "finding", "heuristic")
            self.add("logout", tr("The session stays valid on the server after logout"), "high",
                     "likely",
                     tr("The session cookie captured before logout still opens {path}: {view}", path=path,
                        view=view.describe()),
                     tr("Invalidate the session on the server at logout, not only in the browser"), path=logout_path,
                     impact=tr("A stolen session cookie keeps working after the user logs out"),
                     verification=tr("Copy the session cookie, log out, send the copy and open a protected URL"),
                     references=["CWE-613", "OWASP ASVS V3.3.1"])
        else:
            self.check("logout", "ok")
        if still:
            self.add("logout", tr("Logout does not remove the session cookie from the browser"), "low",
                     "informational", tr("After logout the browser keeps cookie {name}", name=still[0]),
                     tr("Expire the session cookie in the logout response"), path=logout_path,
                     references=["CWE-613"], confidence="medium")
        again = self.login(account.id)
        if again["outcome"] != "success":
            self.check("token_invalidation", "not_evaluated", detail=tr("The second login did not succeed"))
            return
        reused = [n for n in names if old.digest(n) and old.digest(n) == again["jar"].digest(n)]
        if reused:
            self.check("token_invalidation", "finding")
            self.add("session", tr("A new login reuses the previous session token"), "medium", "confirmed",
                     tr("Cookie {name} has the same value in two separate logins", name=reused[0]),
                     tr("Generate a new random session token on every login"), path=logout_path,
                     references=["CWE-384", "CWE-613"])
        else:
            self.check("token_invalidation", "ok")
        self.accounts[account.id]["jar"] = again["jar"]

    def enumeration(self, account):
        username = self.credentials[account.id][0]
        login_path = parse.urlsplit(self.scope.login_url).path or "/"
        if self.failed_attempts[account.id] >= self.scope.max_login_attempts:
            self.check("user_enumeration", "not_evaluated", detail=tr("No login attempts left"))
            return
        wrong = self.failed_attempt(account.id)
        if wrong["outcome"] == "success":
            self.check("user_enumeration", "error", detail=tr("A wrong password was accepted"))
            self.add("authentication", tr("The login accepted a wrong password"), "high", "confirmed",
                     tr("A random password opened a session for the test account"),
                     tr("Check the password verification on the server"), path=login_path,
                     references=["CWE-287"])
            return
        fake = ("di-" + secrets.token_hex(6) + "@example.invalid") if "@" in username else \
            "di_" + secrets.token_hex(6)
        unknown = self.login(account.id, password="Wrong-" + secrets.token_urlsafe(12), username=fake)
        self.lockout_signal(wrong, 1)
        a, b = wrong.get("view"), unknown.get("view")
        if a is None or b is None or "before" not in wrong or "before" not in unknown:
            self.check("user_enumeration", "not_evaluated", detail=tr("No usable POST login form at the login URL"))
            return
        lines_a = [line.replace(username, "") for line in a.lines]
        lines_b = [line.replace(fake, "") for line in b.lines]
        diff_a = [line for line in lines_a if line not in lines_b]
        diff_b = [line for line in lines_b if line not in lines_a]
        if a.status != b.status or a.path != b.path or diff_a or diff_b:
            self.check("user_enumeration", "finding", "heuristic")
            message_a = (diff_a or [""])[0][:120]
            message_b = (diff_b or [""])[0][:120]
            self.add("user_enumeration", tr("Login responses reveal whether an account exists"), "medium", "likely",
                     tr("With a wrong password the answer is status {status_a}, '{message_a}'; with an unknown user it is "
                        "status {status_b}, '{message_b}'", status_a=a.status, message_a=message_a, status_b=b.status,
                        message_b=message_b),
                     tr("Return the same message, status and redirect for a wrong password and an unknown user"),
                     path=login_path, impact=tr("An attacker can find out which accounts exist"),
                     verification=tr("Log in once with a wrong password and once with a made-up user and compare"),
                     references=["CWE-204", "OWASP ASVS V2.2"], confidence="medium")
        else:
            self.check("user_enumeration", "ok", "heuristic",
                       detail=tr("Same status, path and text; response times are not compared"))

    def lockout_signal(self, attempt, number):
        view = attempt.get("view")
        if view is None:
            return False
        if view.status in (423, 429) or view.retry_after or LOCKOUT_TEXT.search(" ".join(view.lines)[:20000]):
            self.lockout_seen = number
            return True
        return False

    def lockout(self):
        if not self.scope.lockout_check:
            return
        account_id = self.scope.lockout_account
        login_path = parse.urlsplit(self.scope.login_url).path or "/"
        cap = self.scope.max_login_attempts
        if not self.lockout_seen:
            while self.failed_attempts[account_id] < cap:
                attempt = self.failed_attempt(account_id)
                if self.lockout_signal(attempt, self.failed_attempts[account_id]):
                    break
        if self.lockout_seen:
            self.check("lockout", "ok")
            self.add("rate_limit", tr("Lockout or rate limiting after {count} failed attempts",
                                      count=self.failed_attempts[account_id]), "info", "informational",
                     tr("The application signalled a lockout or rate limit (429/423, Retry-After or a message)"),
                     tr("Keep the limit; make sure a locked account can be recovered safely"), path=login_path,
                     verification=tr("The test account {account} may now be locked", account=account_id),
                     references=["OWASP ASVS V2.2.1"])
            self.notes.append(tr("The test account {account} may now be locked", account=account_id))
        else:
            self.check("lockout", "finding", "heuristic")
            self.add("rate_limit", tr("No lockout or rate limit after {count} failed attempts",
                                      count=self.failed_attempts[account_id]), "low", "pending",
                     tr("{count} wrong passwords for the test account got no 429/423, Retry-After or lockout message",
                        count=self.failed_attempts[account_id]),
                     tr("Limit failed logins per account and per source (lockout, delays or CAPTCHA)"), path=login_path,
                     verification=tr("The check stops at {cap} attempts by design; confirm the policy with the "
                                     "application owner", cap=cap),
                     references=["CWE-307", "OWASP ASVS V2.2.1"], confidence="low")


def audit(config_path, args=None, now=None, environ=None):
    """Authenticated session audit described by the authorization file ``config_path``.

    ``args`` may provide ``timeout`` and ``insecure_tls``. ``environ`` (default ``os.environ``)
    holds the test credentials. Raises ``authscope.AuthorizationError`` when the file is
    missing/invalid/expired; other errors are reported as checks and notes. The returned dict
    never contains passwords, usernames, cookies or tokens.
    """
    scope = authscope.load(config_path, now=now, environ=environ)
    runner = _SessionAudit(scope, args, environ, now)
    try:
        return runner.run()
    except authscope.AuthorizationError as exc:
        raise authscope.AuthorizationError(runner.secrets.scrub(str(exc))) from None
    except Exception as exc:  # never let a secret escape in an unexpected exception message
        raise RuntimeError(runner.secrets.scrub(tr("Session audit failed: {error}", error=f"{type(exc).__name__}: {exc}"))) \
            from None
