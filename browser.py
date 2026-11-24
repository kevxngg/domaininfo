"""Optional headless-browser rendering with Playwright (DomainInfo 6.0, Phase 2).

Playwright is NOT a dependency: it is imported only when ``audit`` runs, and without it the
module returns a ``not_evaluated`` result with the install hint.

What it does for one authorized URL: launches headless Chromium, blocks every request whose
host is out of scope or on a blocked/internal network (``safety.ScopePolicy`` through route
interception), pins the known hosts to the IPs that ``safety`` resolved (``--host-resolver-rules``,
other names do not resolve), loads the page with a navigation timeout, and collects the DOM after
JavaScript, its forms (analysed with webapp's form checks), cookies (flags only, never values,
marking those set by JavaScript), console errors and mixed content. It submits nothing.

Public API: ``available() -> dict`` and ``audit(url, args) -> dict``.
"""

import importlib
import importlib.metadata
from typing import Any, cast
from urllib import parse

import evidence
from i18n import tr
import safety
import webapp

TOOL = "domaininfo.browser"
INSTALL_HINT = "pip install playwright && playwright install chromium"
MAX_EVENTS = 50
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _load():
    try:
        return importlib.import_module("playwright.sync_api")
    except ImportError:
        return None


def available():
    module = _load()
    if module is None:
        return {"available": False, "version": None, "install": INSTALL_HINT}
    try:
        version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        version = None
    return {"available": True, "version": version, "install": INSTALL_HINT}


def route_decision(url, policy):
    """('allow', None) or ('block', reason) for a request the page wants to make."""
    parts = parse.urlsplit(url)
    if parts.scheme in ("data", "blob", "about"):
        return "allow", None
    if parts.scheme not in ("http", "https"):
        return "block", tr("scheme {scheme} not allowed", scheme=parts.scheme[:10])
    try:
        policy.connect_address(parts.hostname or "")
    except (safety.ScopeError, ValueError) as exc:
        return "block", str(exc)
    return "allow", None


def websocket_decision(url, policy):
    """Same rules as ``route_decision`` for ws:// and wss:// (mapped to http:// and https://)."""
    parts = parse.urlsplit(url)
    if parts.scheme not in ("ws", "wss"):
        return "block", tr("scheme {scheme} not allowed", scheme=parts.scheme[:10])
    return route_decision(("https" if parts.scheme == "wss" else "http") + url[len(parts.scheme):], policy)


# Fallback when Playwright cannot route WebSockets: the page cannot open any socket at all.
DISABLE_WEBSOCKETS = ("(() => { const blocked = function () { throw new Error('WebSocket disabled by DomainInfo'); };"
                      " Object.defineProperty(window, 'WebSocket', {value: blocked, writable: false}); })();")


def resolver_rules(policy):
    """Chromium ``--host-resolver-rules`` mapping each known in-scope name to its pinned IP; every
    other name fails to resolve (so DNS rebinding cannot redirect the browser)."""
    rules = []
    names = [policy.origin_host] + [p for p in policy.patterns if not p.startswith("*.")]
    for host in names:
        if safety._is_ip(host):
            continue
        address = policy.connect_address(host)
        rules.append(f"MAP {host} {'[' + address + ']' if ':' in address else address}")
    rules.append("MAP * ~NOTFOUND")
    return ",".join(rules)


def _not_evaluated(url, detail):
    checks = [{"id": "browser", "state": "not_evaluated", "evidence": "direct", "detail": detail}]
    return {"url": evidence.redact_url(url), "available": False, "install": INSTALL_HINT, "findings": [],
            "checks": checks, "assessment": evidence.scores([], checks)}


def _cookie_row(cookie, header_names):
    samesite = cookie.get("sameSite")
    return {"name": evidence.clean(cookie.get("name", ""))[:100], "domain": cookie.get("domain"),
            "path": cookie.get("path"), "secure": bool(cookie.get("secure")), "httponly": bool(cookie.get("httpOnly")),
            "samesite": samesite if samesite in ("Lax", "Strict", "None") else None,
            "persistent": (cookie.get("expires") or -1) > 0,
            "set_by_js": cookie.get("name") not in header_names,
            "session_like": bool(webapp.SESSION_NAME.search(cookie.get("name", "")))}


def audit(url, args):
    """Render ``url`` in headless Chromium. ``args``: timeout, scope, allow_private, insecure_tls,
    browser_timeout (navigation seconds, default 20)."""
    url = safety.normalize_url(url)
    module = _load()
    if module is None:
        return _not_evaluated(url, tr("Playwright is not installed (optional). Install: {install}",
                                      install=INSTALL_HINT))
    policy = safety.ScopePolicy(url, extra_hosts=list(getattr(args, "scope", None) or []),
                                allow_private=bool(getattr(args, "allow_private", False)))
    rules = resolver_rules(policy)  # raises ScopeError when the target itself is not allowed
    nav_ms = int(max(3.0, min(float(getattr(args, "browser_timeout", 20) or 20), 120.0)) * 1000)
    blocked, console, mixed, header_cookies = [], [], [], set()
    https = parse.urlsplit(url).scheme == "https"

    def on_route(route):
        decision, reason = route_decision(route.request.url, policy)
        if decision == "allow":
            route.continue_()
        else:
            if len(blocked) < MAX_EVENTS:
                blocked.append({"url": evidence.redact_url(route.request.url)[:300], "reason": reason})
            route.abort("blockedbyclient")

    def on_console(message):
        if message.type == "error" and len(console) < MAX_EVENTS:
            console.append(evidence.redact(message.text, 300))

    def on_page_error(error):
        if len(console) < MAX_EVENTS:
            console.append(evidence.redact(str(error), 300))

    def on_request(request):
        if https and request.url.startswith("http://") and len(mixed) < MAX_EVENTS:
            mixed.append({"url": evidence.redact_url(request.url)[:300], "type": request.resource_type})

    def on_response(response):
        try:
            for header in response.headers_array():
                if header["name"].lower() == "set-cookie":
                    for line in header["value"].split("\n"):
                        header_cookies.add(line.split("=", 1)[0].strip())
        # A response without readable headers only loses the JS/HTTP cookie distinction
        except Exception:  # noqa: S110  # nosec B110
            pass

    websocket_guard = {"active": False}

    def on_websocket(ws):
        # context.route() does not see WebSockets; apply the same scope rules to ws:// and wss://
        decision, reason = websocket_decision(ws.url, policy)
        if decision == "allow":
            ws.connect_to_server()
        else:
            if len(blocked) < MAX_EVENTS:
                blocked.append({"url": evidence.redact_url(ws.url.replace("ws", "http", 1))[:300], "reason": reason,
                                "type": "websocket"})
            ws.close()

    try:
        with module.sync_playwright() as play:
            chromium = play.chromium.launch(headless=True, args=[f"--host-resolver-rules={rules}"])
            try:
                context = chromium.new_context(ignore_https_errors=bool(getattr(args, "insecure_tls", False)),
                                               service_workers="block", accept_downloads=False)
                context.route("**/*", on_route)
                if hasattr(context, "route_web_socket"):  # Playwright 1.48+
                    context.route_web_socket("**/*", on_websocket)
                    websocket_guard["active"] = True
                else:
                    context.add_init_script(DISABLE_WEBSOCKETS)
                page = context.new_page()
                page.on("console", on_console)
                page.on("pageerror", on_page_error)
                page.on("request", on_request)
                page.on("response", on_response)
                response = page.goto(url, timeout=nav_ms, wait_until="load")
                final = page.url
                dom = page.content()
                cookies = [_cookie_row(c, header_cookies) for c in context.cookies()]
                status = response.status if response is not None else None
            finally:
                chromium.close()
    except Exception as exc:  # Playwright raises its own error types (timeouts, missing browser…)
        checks = [{"id": "browser", "state": "error", "evidence": "direct",
                   "detail": evidence.redact(f"{type(exc).__name__}: {exc}", 300)}]
        return {"url": evidence.redact_url(url), "available": True, "findings": [], "checks": checks,
                "assessment": evidence.scores([], checks), "blocked_requests": blocked}

    # Reuse webapp's form and cookie analysis on the rendered DOM
    analysis = webapp._Audit(final if final.startswith(("http://", "https://")) else url, args)
    analysis.final = analysis.url
    analysis.https = parse.urlsplit(analysis.final).scheme == "https"
    parsed = webapp.parse_page(dom[:webapp.SCAN_LIMIT * 4])
    forms = analysis.forms(parsed, cookies)
    analysis.findings = [f for f in analysis.findings if f["category"] in ("forms", "csrf")]
    findings = [dict(f, tool=TOOL) for f in analysis.findings]
    target = evidence.redact_url(url)
    path = parse.urlsplit(final).path or "/"
    for cookie in cookies:
        if cookie["set_by_js"] and cookie["session_like"]:
            findings.append(evidence.Finding(
                target=target, path=path, category="cookies",
                title=tr("Session-like cookie {name} is set by JavaScript", name=cookie["name"]), severity="medium",
                status="likely", confidence="medium",
                evidence=tr("Cookie {name} appears after rendering without a Set-Cookie header (HttpOnly={httponly})",
                            name=cookie["name"], httponly=cookie["httponly"]),
                tool=TOOL, recommendation=tr("Set session cookies from the server with HttpOnly"),
                impact=tr("Cookies written by JavaScript cannot be HttpOnly: an XSS could read them"),
                references=["CWE-1004"]).to_dict())
    if mixed:
        findings.append(evidence.Finding(
            target=target, path=path, category="transport", title=tr("Mixed content: the HTTPS page loads HTTP resources"),
            severity="medium", status="confirmed", confidence="high",
            evidence=", ".join(m["url"] for m in mixed[:5]), tool=TOOL,
            recommendation=tr("Load every resource over HTTPS"), references=["CWE-319"]).to_dict())
    if console:
        findings.append(evidence.Finding(
            target=target, path=path, category="errors",
            title=tr("{count} JavaScript errors in the console", count=len(console)), severity="info",
            status="informational", confidence="high", evidence=console[0], tool=TOOL,
            recommendation=tr("Review the console errors; they may reveal internal details")).to_dict())
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["category"]))
    checks = [{"id": "browser", "state": "ok", "evidence": "direct"},
              {"id": "mixed_content", "state": "finding" if mixed else ("ok" if https else "not_applicable"),
               "evidence": "direct"},
              analysis.checks.get("forms", {"id": "forms", "state": "not_applicable", "evidence": "direct"}),
              analysis.checks.get("csrf", {"id": "csrf", "state": "not_applicable", "evidence": "direct"}),
              {"id": "websocket_guard", "state": "ok" if websocket_guard["active"] else "not_evaluated",
               "evidence": "direct"}]
    note = tr("Rendered in headless Chromium; out-of-scope requests are blocked and nothing is submitted")
    if not websocket_guard["active"]:
        note += " · " + tr("This Playwright version cannot filter WebSockets (needs 1.48 or newer), so the page "
                           "could not open any WebSocket; update Playwright")
    return cast(dict[str, Any], webapp._scrub({
        "url": target, "final_url": final, "status": status, "available": True, "title": parsed.title or None,
        "dom_length": len(dom), "forms": forms, "cookies": cookies, "console_errors": console,
        "mixed_content": mixed, "blocked_requests": blocked, "findings": findings, "checks": checks,
        "websocket_filter": websocket_guard["active"], "assessment": evidence.scores(findings, checks),
        "note": note}))
