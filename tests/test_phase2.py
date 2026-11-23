"""DomainInfo 6.0 Phase 2 tests: authorization file, authenticated session audit, OpenAPI
analysis, passive ZAP client, optional Playwright and the method-generic safety client.

Every request goes to local HTTP servers running in threads (a fake web application with login,
roles, logout and lockout; a fake ZAP API); the Internet is never touched.
"""

import argparse
import ast
import json
import secrets
import sys
import tempfile
import threading
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib import parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import apispec  # noqa: E402
import authscope  # noqa: E402
import browser  # noqa: E402
import i18n  # noqa: E402
import safety  # noqa: E402
import session_audit  # noqa: E402
import zapclient  # noqa: E402

USERS = {"alice.tester": ("Al1ce-Pass-DoNotLeak-7731", "user"),
         "admin.tester": ("R00t-Pass-DoNotLeak-9921", "admin")}
ENV = {"DI_USER_A": "alice.tester", "DI_PASS_A": USERS["alice.tester"][0],
       "DI_USER_B": "admin.tester", "DI_PASS_B": USERS["admin.tester"][0]}
SECRET_VALUES = [v for pair in USERS.items() for v in (pair[0], pair[1][0])]

SPEC = {
    "openapi": "3.0.3", "info": {"title": "Shop API", "version": "1"},
    "servers": [{"url": "http://api.example.test/v1"}, {"url": "/v2"}],
    "components": {"securitySchemes": {
        "keyQuery": {"type": "apiKey", "in": "query", "name": "api_key"},
        "basicAuth": {"type": "http", "scheme": "basic"}},
        "parameters": {"tok": {"name": "access_token", "in": "query"}}},
    "paths": {
        "/orders": {"get": {"operationId": "listOrders", "security": [{"basicAuth": []}],
                            "parameters": [{"$ref": "#/components/parameters/tok"}]},
                    "delete": {"operationId": "dropOrders", "deprecated": True}},
        "/health": {"get": {"security": []}},
        "/login": {"post": {"parameters": [{"name": "password", "in": "query"}]}},
    },
}


# -- fake web application ------------------------------------------------------------------------

class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    @property
    def app(self):
        return self.server.app

    def cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid":
                return value
        return None

    def send(self, status, body="", headers=(), content_type="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def session(self):
        sid = self.cookie()
        return sid, self.app.sessions.get(sid) if sid else None

    def new_sid(self):
        sid = "S" + secrets.token_hex(16)
        self.app.issued.append(sid)
        return sid

    def cookie_header(self, sid):
        flags = "; HttpOnly; SameSite=Lax" if self.app.cfg["flags"] else ""
        extra = "; Max-Age=7776000" if self.app.cfg.get("long_session") else ""
        return ("Set-Cookie", f"sid={sid}; Path=/{flags}{extra}")

    def login_page(self, sid, message="", status=200, headers=()):
        state = self.app.sessions.setdefault(sid, {"user": None})
        state["csrf"] = "C" + secrets.token_hex(12)
        self.app.issued.append(state["csrf"])
        action = self.app.cfg.get("action", "/login")
        body = (f"<html><head><title>Sign in</title></head><body><p>{message}</p>"
                f"<form method='post' action='{action}'><input type='hidden' name='csrf' value='{state['csrf']}'>"
                "<input type='text' name='username'><input type='password' name='password'>"
                "<button>Go</button></form></body></html>")
        self.send(status, body, headers)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        self.app.seen.append(("GET", path))
        sid, state = self.session()
        user = state.get("user") if state else None
        if path in self.app.static:
            status, body, ctype = self.app.static[path]
            self.send(status, body, content_type=ctype)
        elif path == "/login":
            headers = []
            if not state:
                sid = self.new_sid()
                headers.append(self.cookie_header(sid))
            self.login_page(sid, headers=headers)
        elif path == "/home":
            if user:
                self.send(200, f"<title>Home</title><p>Hello {user}</p><p>Your dashboard</p>")
            else:
                self.send(302, "", [("Location", "/login")])
        elif path == "/admin":
            if user and (USERS[user][1] == "admin" or self.app.cfg["idor"]):
                self.send(200, "<title>Admin</title><p>Admin console</p>")
            elif user:
                self.send(403, "<title>Forbidden</title>")
            else:
                self.send(302, "", [("Location", "/login")])
        elif path == "/logout":
            if self.app.cfg["logout_server"] and sid:
                self.app.sessions.pop(sid, None)
            headers = [("Location", "/login")]
            if self.app.cfg["logout_clears"]:
                headers.append(("Set-Cookie", "sid=; Path=/; Max-Age=0"))
            self.send(302, "", headers)
        else:
            self.send(404, "<title>Not found</title>")

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        form = dict(parse.parse_qsl(self.rfile.read(length).decode()))
        self.app.seen.append(("POST", path))
        if path == "/echo":
            self.send(200, json.dumps({"method": "POST", "form": form, "cookie": self.headers.get("Cookie")}),
                      content_type="application/json")
            return
        if path == "/redirect303":
            self.send(303, "", [("Location", "/echo-get")])
            return
        if path == "/redirect307-other":
            self.send(307, "", [("Location", self.app.cfg["other_origin"] + "/echo")])
            return
        if path != "/login":
            self.send(404, "")
            return
        sid, state = self.session()
        username, password = form.get("username", ""), form.get("password", "")
        self.app.attempts.append((username, password == USERS.get(username, ("",))[0]))
        if not state or form.get("csrf") != state.get("csrf"):
            self.send(400, "<title>Bad request</title><p>CSRF check failed</p>")
            return
        leak = self.app.cfg["leak"]
        if username not in USERS:
            self.login_page(sid, "Unknown user" if leak else "Invalid credentials")
            return
        limit = self.app.cfg["lockout_after"]
        failures = self.app.failures.get(username, 0)
        if limit and failures >= limit:
            self.send(429, "<title>Slow down</title><p>Too many attempts, try again later</p>",
                      [("Retry-After", "60")])
            return
        if password != USERS[username][0]:
            self.app.failures[username] = failures + 1
            self.login_page(sid, "Wrong password" if leak else "Invalid credentials")
            return
        if self.app.cfg["mfa"]:
            self.send(200, "<title>Verify</title><p>Enter the verification code</p><form method='post' "
                           "action='/mfa'><input type='text' name='otp' autocomplete='one-time-code'></form>")
            return
        headers = [("Location", "/home")]
        if self.app.cfg["fixation"]:
            state["user"] = username
        else:
            self.app.sessions.pop(sid, None)
            sid = self.new_sid()
            self.app.sessions[sid] = {"user": username}
            headers.append(self.cookie_header(sid))
        self.send(302, "", headers)


class App:
    DEFAULTS = {"flags": True, "fixation": False, "idor": False, "logout_server": True, "logout_clears": True,
                "leak": False, "lockout_after": None, "mfa": False, "long_session": False}

    def __init__(self, **cfg):
        self.cfg = dict(self.DEFAULTS, **cfg)
        self.sessions, self.failures, self.seen, self.attempts, self.issued = {}, {}, [], [], []
        self.static = {}

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), AppHandler)
        self.server.app = self
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def wrong_attempts(self, username):
        return sum(1 for user, ok in self.attempts if user == username and not ok)


def config(base, **overrides):
    now = datetime.now(timezone.utc)
    data = {
        "version": 1, "authorized_by": "QA lead (test)", "authorization_note": "Unit test of a local fake app",
        "targets": [base + "/"],
        "login": {"url": base + "/login"},
        "logout": {"url": base + "/logout"},
        "accounts": [{"id": "alice", "role": "user", "username_env": "DI_USER_A", "password_env": "DI_PASS_A"},
                     {"id": "root", "role": "admin", "username_env": "DI_USER_B", "password_env": "DI_PASS_B"}],
        "roles": {"user": {"protected_urls": [base + "/home"]},
                  "admin": {"protected_urls": [base + "/admin", base + "/home"]}},
        "limits": {"max_requests": 120, "max_login_attempts": 3, "lockout_check": True, "lockout_account": "alice"},
        "window": {"not_before": (now - timedelta(hours=1)).isoformat(),
                   "not_after": (now + timedelta(hours=1)).isoformat()},
    }
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


class ConfigFile:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = str(Path(self.dir.name) / "authorization.json")
        Path(self.path).write_text(json.dumps(self.data) if not isinstance(self.data, str) else self.data,
                                   encoding="utf-8")
        return self.path

    def __exit__(self, *exc):
        self.dir.cleanup()


def opts(**extra):
    values = {"timeout": 3.0, "scope": [], "allow_private": False}
    values.update(extra)
    return argparse.Namespace(**values)


def run_session(app, **overrides):
    with ConfigFile(config(app.base, **overrides)) as path:
        return session_audit.audit(path, opts(), environ=ENV)


def titles(result, category=None):
    return [f["title"] for f in result["findings"] if category is None or f["category"] == category]


def states(result):
    return {c["id"]: c["state"] for c in result["checks"]}


# -- authorization file ------------------------------------------------------------------------------

class AuthScopeTests(unittest.TestCase):
    base = "http://127.0.0.1:8000"

    def load(self, data, **kw):
        with ConfigFile(data) as path:
            return authscope.load(path, environ=ENV, **kw)

    def test_valid_file(self):
        scope = self.load(config(self.base))
        self.assertEqual(scope.login_url, self.base + "/login")
        self.assertEqual([a.id for a in scope.accounts], ["alice", "root"])
        self.assertTrue(scope.in_targets(self.base + "/admin?x=1"))
        self.assertFalse(scope.in_targets("http://127.0.0.1:8001/admin"))
        summary = json.dumps(scope.summary())
        self.assertNotIn("DI_PASS_A", summary)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, summary)

    def test_missing_file_refused(self):
        with self.assertRaises(authscope.AuthorizationError):
            authscope.load(None)
        with self.assertRaises(authscope.AuthorizationError):
            authscope.load(str(ROOT / "does-not-exist.json"))
        with self.assertRaises(authscope.AuthorizationError):
            session_audit.audit(str(ROOT / "does-not-exist.json"), opts(), environ=ENV)

    def test_strict_validation(self):
        base = config(self.base)
        bad = [
            dict(base, authorized_by=""),
            {k: v for k, v in base.items() if k != "authorization_note"},
            dict(base, password="hunter2"),  # noqa: S106  # nosec B106
            dict(base, accounts=[{"id": "a", "role": "user", "username_env": "alice", "password_env": "P"}]),
            dict(base, accounts=[{"id": "a", "role": "user", "username_env": "U", "password_env": "P",
                                  "password": "x"}]),
            dict(base, accounts=[{"id": "a", "role": "ghost", "username_env": "U", "password_env": "P"}]),
            dict(base, login={"url": "http://evil.example/login"}),  # out of the authorized targets
            dict(base, logout={"url": "http://127.0.0.1:9999/logout"}),
            dict(base, roles={"user": {"protected_urls": ["http://other.example/home"]}}),
            dict(base, limits={"max_login_attempts": 6}),
            dict(base, limits={"max_requests": 100000}),
            dict(base, limits={"lockout_check": True}),
            dict(base, limits={"lockout_check": True, "lockout_account": "nobody"}),
            dict(base, window={"not_before": "2026-01-01T00:00:00", "not_after": "2026-01-02T00:00:00"}),
            dict(base, window={"not_before": "2026-01-02T00:00:00Z", "not_after": "2026-01-01T00:00:00Z"}),
            dict(base, window={"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"}),
            dict(base, version=2),
            dict(base, targets=["ftp://example.com/"]),
            dict(base, targets=["https://user:pw@example.com/"]),
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(authscope.AuthorizationError):
                self.load(data)

    def test_duplicate_keys_and_bad_json(self):
        with self.assertRaises(authscope.AuthorizationError):
            self.load('{"version": 1, "version": 1}')
        with self.assertRaises(authscope.AuthorizationError):
            self.load("{not json")

    def test_window_enforced(self):
        past = config(self.base, window={"not_before": "2020-01-01T00:00:00Z", "not_after": "2020-01-02T00:00:00Z"})
        with self.assertRaises(authscope.AuthorizationError):
            self.load(past)

    def test_missing_environment_names_variable_not_value(self):
        env = dict(ENV)
        del env["DI_PASS_B"]
        with ConfigFile(config(self.base)) as path, self.assertRaises(authscope.AuthorizationError) as ctx:
            authscope.load(path, environ=env)
        self.assertIn("DI_PASS_B", str(ctx.exception))
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, str(ctx.exception))

    def test_prefix_boundaries(self):
        scope = self.load(config(self.base, targets=[self.base + "/app"], login={"url": self.base + "/app/login"},
                                 logout=None, roles={"user": {"protected_urls": []}, "admin": {}}))
        self.assertTrue(scope.in_targets(self.base + "/app"))
        self.assertTrue(scope.in_targets(self.base + "/app/x"))
        self.assertFalse(scope.in_targets(self.base + "/application"))
        self.assertFalse(scope.in_targets("https://127.0.0.1:8000/app/x"))


# -- safety: method-generic client and cookie jar -----------------------------------------------------

class SafetyRequestTests(unittest.TestCase):
    def test_post_and_cookie_jar(self):
        with App() as app:
            policy = safety.ScopePolicy(app.base)
            jar = safety.CookieJar()
            safety.http_request("GET", app.base + "/login", policy, 3, jar=jar)
            self.assertEqual(jar.names(), {"sid"})
            response = safety.http_request("POST", app.base + "/echo", policy, 3, data={"a": "1 2"}, jar=jar)
            body = json.loads(response.body)
            self.assertEqual(body["form"], {"a": "1 2"})
            self.assertTrue(body["cookie"].startswith("sid=S"))
            self.assertNotIn(body["cookie"][4:], repr(jar))
            head = safety.http_request("HEAD", app.base + "/login", policy, 3, jar=jar)
            self.assertEqual(head.body, b"")

    def test_post_redirect_becomes_get_and_cross_origin_307_blocked(self):
        with App() as app, App() as other:
            app.cfg["other_origin"] = other.base
            policy = safety.ScopePolicy(app.base)
            response = safety.http_request("POST", app.base + "/redirect303", policy, 3, data={"x": "1"})
            self.assertEqual(response.method, "GET")
            self.assertEqual(app.seen[-1], ("GET", "/echo-get"))
            response = safety.http_request("POST", app.base + "/redirect307-other", policy, 3, data={"x": "1"})
            self.assertEqual(response.status, 307)
            self.assertIn("blocked", response.redirects[-1])
            self.assertEqual(other.seen, [])

    def test_budget_and_limits(self):
        with App() as app:
            policy = safety.ScopePolicy(app.base)
            budget = safety.RequestBudget(2)
            safety.http_request("GET", app.base + "/home", policy, 3, budget=budget)  # 302 + login page
            with self.assertRaises(safety.BudgetExceeded):
                safety.http_request("GET", app.base + "/login", policy, 3, budget=budget)
        with self.assertRaises(ValueError):
            safety.http_request("PUT", "http://127.0.0.1/", safety.ScopePolicy("http://127.0.0.1/"), 3)
        with self.assertRaises(ValueError):
            safety.http_request("GET", "http://127.0.0.1/", safety.ScopePolicy("http://127.0.0.1/"), 3, data={"a": 1})
        with self.assertRaises(ValueError):
            safety.encode_form({"a": "x" * (safety.MAX_REQUEST_BODY + 1)})

    def test_cookie_rules(self):
        jar = safety.CookieJar()
        jar.store("http://app.example.com/a/b", ["s=1; Secure", "d=2; Domain=other.example", "p=3; Domain=example.com; Path=/",
                                                 "gone=4; Max-Age=0", "h=5; Path=/a"])
        self.assertEqual(jar.names(), {"p", "h"})  # Secure over http and foreign domains refused
        self.assertEqual(jar.header_for("http://x.example.com/"), "p=3")
        self.assertIn("h=5", jar.header_for("http://app.example.com/a/z"))
        self.assertNotIn("h=5", jar.header_for("http://app.example.com/ab") or "")
        jar.store("http://app.example.com/", ["h=; Path=/a; Max-Age=0"])
        self.assertNotIn("h", jar.names())
        secure = safety.CookieJar()
        secure.store("https://app.example.com/", ["s=1; Secure; HttpOnly"])
        self.assertIsNone(secure.header_for("http://app.example.com/"))
        self.assertEqual(secure.attributes("s")["httponly"], True)
        self.assertNotIn("value", secure.attributes("s"))


# -- authenticated session audit ---------------------------------------------------------------------

class SessionAuditTests(unittest.TestCase):
    def assert_no_secrets(self, result, app):
        dumped = json.dumps(result)
        for secret in SECRET_VALUES + app.issued:
            self.assertNotIn(secret, dumped)

    def test_secure_app(self):
        with App(lockout_after=2) as app:
            result = run_session(app)
        s = states(result)
        self.assertEqual(s["login"], "ok")
        self.assertEqual(s["session_fixation"], "ok")
        self.assertEqual(s["cookie_flags"], "finding")  # plain HTTP: session cookie travels unencrypted
        self.assertEqual(s["logout"], "ok")
        self.assertEqual(s["token_invalidation"], "ok")
        self.assertEqual(s["access_control"], "ok")
        self.assertEqual(s["anonymous_access"], "ok")
        self.assertEqual(s["user_enumeration"], "ok")
        self.assertEqual(s["lockout"], "ok")
        self.assertEqual([a["login"] for a in result["accounts"]], ["success", "success"])
        self.assertIn("Session cookie sid travels over unencrypted HTTP", titles(result))
        self.assertLessEqual(app.wrong_attempts("alice.tester"), 3)
        for finding in result["findings"]:
            self.assertIn(finding["status"], ("confirmed", "likely", "informational", "pending"))
        self.assert_no_secrets(result, app)

    def test_vulnerable_app(self):
        with App(fixation=True, idor=True, logout_server=False, leak=True, flags=False, long_session=True) as app:
            result = run_session(app)
            self.assert_no_secrets(result, app)
        found = titles(result)
        self.assertIn("Session identifier not renewed at login (session fixation)", found)
        self.assertIn("Role user can open a URL reserved for role admin", found)
        self.assertIn("The session stays valid on the server after logout", found)
        self.assertIn("Login responses reveal whether an account exists", found)
        self.assertIn("Session cookie sid without HttpOnly", found)
        self.assertIn("No lockout or rate limit after 3 failed attempts", found)
        self.assertTrue(any("lives 90 days" in t for t in found))
        by_title = {f["title"]: f for f in result["findings"]}
        self.assertEqual(by_title["Role user can open a URL reserved for role admin"]["status"], "confirmed")
        self.assertEqual(by_title["Login responses reveal whether an account exists"]["status"], "likely")
        self.assertEqual(app.wrong_attempts("alice.tester"), 3)  # never more than the cap
        self.assertEqual(app.wrong_attempts("admin.tester"), 0)  # only the configured test account

    def test_attempts_never_exceed_cap(self):
        for cap in (1, 2, 5):
            with self.subTest(cap=cap), App() as app:
                limits = {"max_requests": 200, "max_login_attempts": cap, "lockout_check": True,
                          "lockout_account": "alice"}
                result = run_session(app, limits=limits)
                self.assertEqual(app.wrong_attempts("alice.tester"), cap)
                self.assertEqual(result["login_attempts"]["failed"]["alice"], cap)

    def test_lockout_stops_at_first_signal(self):
        with App(lockout_after=1) as app:
            result = run_session(app, limits={"max_login_attempts": 5, "lockout_check": True,
                                              "lockout_account": "alice"})
        self.assertEqual(states(result)["lockout"], "ok")
        # attempt 1 (enumeration) is a wrong password, attempt 2 gets 429 and the check stops
        self.assertEqual(len([a for a in app.attempts if a[0] == "alice.tester" and not a[1]]), 2)

    def test_lockout_disabled_by_default(self):
        with App() as app:
            result = run_session(app, limits={"max_login_attempts": 3})
        self.assertEqual(states(result)["lockout"], "not_evaluated")
        self.assertEqual(app.wrong_attempts("alice.tester"), 1)  # only the enumeration comparison

    def test_mfa_detected_and_stops(self):
        with App(mfa=True) as app:
            result = run_session(app)
        s = states(result)
        self.assertEqual(s["mfa"], "ok")
        self.assertEqual(s["session_fixation"], "not_evaluated")
        self.assertTrue(result["notes"])

    def test_wrong_credentials_reported_without_secrets(self):
        env = dict(ENV, DI_PASS_A="Not-The-Password-123")  # noqa: S106  # nosec B106
        with App() as app, ConfigFile(config(app.base)) as path:
            result = session_audit.audit(path, opts(), environ=env)
            self.assertEqual(states(result)["login"], "error")
            self.assertNotIn("Not-The-Password-123", json.dumps(result))

    def test_request_budget(self):
        with App() as app:
            result = run_session(app, limits={"max_requests": 10})
        self.assertLessEqual(len(app.seen), 10)
        self.assertEqual(result["requests"]["used"], 10)
        self.assertTrue(any("Request limit reached" in n for n in result["notes"]))

    def test_login_form_posting_out_of_scope_refused(self):
        with App(action="http://evil.invalid/steal") as app:
            with self.assertRaises(authscope.AuthorizationError):
                run_session(app)
            self.assertFalse(any(method == "POST" for method, _ in app.seen))

    def test_no_secret_in_exceptions(self):
        password = ENV["DI_PASS_A"]

        def boom(*args, **kwargs):
            raise KeyError("leaking " + password)

        with App() as app, ConfigFile(config(app.base)) as path, patch("session_audit._parse", side_effect=boom):
            with self.assertRaises(RuntimeError) as ctx:
                session_audit.audit(path, opts(), environ=ENV)
        text = "".join(traceback.format_exception(ctx.exception))
        self.assertNotIn(password, str(ctx.exception))
        self.assertNotIn(password, text)

        def oserror(*args, **kwargs):
            raise OSError("socket said " + password)

        with App() as app, ConfigFile(config(app.base)) as path, patch("safety.http_request", side_effect=oserror):
            result = session_audit.audit(path, opts(), environ=ENV)
        self.assertNotIn(password, json.dumps(result))


# -- OpenAPI ---------------------------------------------------------------------------------------

class ApiSpecTests(unittest.TestCase):
    def test_discovery_and_findings(self):
        with App() as app:
            app.static["/v3/api-docs"] = (200, json.dumps(SPEC), "application/json")
            result = apispec.audit(app.base + "/", opts())
            paths = [p for _, p in app.seen]
        self.assertEqual(paths, list(apispec.COMMON_PATHS[:3]))  # stops at the first document; no operation called
        found = titles(result)
        self.assertIn("API server declared over unencrypted HTTP", found)
        self.assertIn("API key sent in the URL query string", found)
        self.assertIn("HTTP Basic authentication over unencrypted HTTP", found)
        self.assertIn("Sensitive-looking parameters in the query string", found)
        self.assertIn("1 deprecated operations are still published", found)
        self.assertIn("3 documented operations declare no security requirement", found)
        self.assertEqual(result["operations"], 4)
        self.assertEqual({(i["method"], i["path"]) for i in result["inventory"]},
                         {("GET", "/orders"), ("DELETE", "/orders"), ("GET", "/health"), ("POST", "/login")})
        self.assertEqual(states(result)["spec_fetch"], "ok")

    def test_swagger2_and_missing_schemes(self):
        doc = {"swagger": "2.0", "host": "api.example.test", "schemes": ["https"], "basePath": "/",
               "paths": {"/a": {"get": {}}}}
        result = apispec.analyze(doc, "https://api.example.test/swagger.json")
        self.assertIn("The API description declares no security schemes", titles(result))
        self.assertEqual(states(result)["servers"], "ok")

    def test_yaml_not_evaluated(self):
        with App() as app:
            app.static["/spec.yaml"] = (200, "openapi: 3.0.0\ninfo:\n  title: x\n", "application/yaml")
            result = apispec.audit(app.base + "/spec.yaml", opts())
        self.assertEqual(result["checks"][0]["state"], "not_evaluated")
        self.assertIn("YAML", result["checks"][0]["detail"])

    def test_nothing_found(self):
        with App() as app:
            result = apispec.audit(app.base, opts())
        self.assertEqual(states(result)["spec_fetch"], "not_evaluated")
        self.assertEqual(len(result["tried"]), len(apispec.COMMON_PATHS))

    def test_out_of_scope_refused(self):
        with self.assertRaises(ValueError):
            apispec.audit("http://169.254.169.254/openapi.json", opts())


# -- ZAP ----------------------------------------------------------------------------------------------

ZAP_KEY = "zap-key-DoNotLeak-4411"


class ZapHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        parts = parse.urlsplit(self.path)
        self.server.seen.append(parts.path)
        if self.headers.get("X-ZAP-API-Key") != ZAP_KEY:
            return self.reply(403, {"code": "bad_api_key", "message": "Missing or wrong API key"})
        target = self.server.target
        if parts.path == "/JSON/core/view/version/":
            return self.reply(200, {"version": "2.15.0"})
        if parts.path == "/JSON/core/action/accessUrl/":
            return self.reply(200, {"Result": "OK"})
        if parts.path == "/JSON/spider/action/scan/":
            return self.reply(200, {"scan": "1"})
        if parts.path == "/JSON/spider/view/status/":
            return self.reply(200, {"status": "100"})
        if parts.path == "/JSON/pscan/view/recordsToScan/":
            return self.reply(200, {"recordsToScan": "0"})
        if parts.path == "/JSON/alert/view/alerts/":
            alerts = [
                {"alert": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
                 "cweid": "693", "wascid": "15", "url": target + "/", "pluginId": "10038",
                 "reference": "https://developer.mozilla.org/csp", "solution": "Set a CSP"},
                {"alert": "Cookie No HttpOnly Flag", "risk": "Low", "confidence": "Medium", "cweid": "1004",
                 "url": target + "/login", "pluginId": "10010", "evidence": "Set-Cookie: sid=SECRETCOOKIEVALUE123"},
                {"alert": "Timestamp Disclosure", "risk": "Low", "confidence": "Low", "url": target + "/x",
                 "pluginId": "10096"},
                {"alert": "Fake", "risk": "High", "confidence": "False Positive", "url": target + "/",
                 "pluginId": "1"},
                {"alert": "Other site", "risk": "High", "confidence": "High", "url": "https://other.example/",
                 "pluginId": "2"},
            ]
            return self.reply(200, {"alerts": alerts})
        return self.reply(404, {"code": "bad_view", "message": "No such view"})

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeZap:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ZapHandler)
        self.server.seen = []
        self.server.target = "http://127.0.0.1:65000"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class ZapTests(unittest.TestCase):
    def test_passive_audit(self):
        with FakeZap() as zap:
            result = zapclient.audit(zap.server.target + "/", opts(zap_url=zap.url, zap_api_key=ZAP_KEY))
            seen = list(zap.server.seen)
        self.assertEqual(result["zap_version"], "2.15.0")
        by_title = {f["title"]: f for f in result["findings"]}
        self.assertEqual(set(by_title), {"Content Security Policy (CSP) Header Not Set", "Cookie No HttpOnly Flag",
                                         "Timestamp Disclosure"})
        self.assertEqual(by_title["Content Security Policy (CSP) Header Not Set"]["status"], "confirmed")
        self.assertIn("CWE-693", by_title["Content Security Policy (CSP) Header Not Set"]["references"])
        self.assertIn("WASC-15", by_title["Content Security Policy (CSP) Header Not Set"]["references"])
        self.assertEqual(by_title["Cookie No HttpOnly Flag"]["status"], "likely")
        self.assertEqual(by_title["Timestamp Disclosure"]["status"], "pending")
        dumped = json.dumps(result)
        self.assertNotIn(ZAP_KEY, dumped)
        self.assertNotIn("SECRETCOOKIEVALUE123", dumped)
        self.assertFalse(any("ascan" in p or "spider" in p for p in seen))

    def test_spider_only_when_enabled(self):
        with FakeZap() as zap:
            zapclient.audit(zap.server.target + "/", opts(zap_url=zap.url, zap_api_key=ZAP_KEY, zap_spider=True))
            self.assertIn("/JSON/spider/action/scan/", zap.server.seen)
            self.assertFalse(any("ascan" in p for p in zap.server.seen))

    def test_only_loopback_and_allowlisted_endpoints(self):
        for url in ("http://10.0.0.5:8080", "http://zap.example.com:8080", "http://169.254.169.254/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                zapclient.ZapClient(url, ZAP_KEY)
        client = zapclient.ZapClient("http://localhost:8080", ZAP_KEY)
        self.assertEqual(client.base, "http://127.0.0.1:8080")
        self.assertNotIn(ZAP_KEY, repr(client))
        with self.assertRaises(ValueError):
            client.call("ascan/action/scan", url="http://x/")

    def test_absent_and_wrong_key(self):
        with FakeZap() as zap:
            port = zap.server.server_address[1]
        result = zapclient.audit("http://127.0.0.1:65000/", opts(zap_url=f"http://127.0.0.1:{port}", zap_api_key="k"))
        self.assertEqual(result["checks"][0]["state"], "not_evaluated")
        self.assertFalse(result["available"])
        with FakeZap() as zap:
            status = zapclient.available(zap.url, "wrong-key-value")
        self.assertFalse(status["available"])
        self.assertNotIn("wrong-key-value", status["reason"])


# -- Playwright (optional) ------------------------------------------------------------------------

HAS_PLAYWRIGHT = browser.available()["available"]


class BrowserTests(unittest.TestCase):
    def test_degrades_without_playwright(self):
        with patch("browser._load", return_value=None):
            result = browser.audit("http://127.0.0.1:65000/", opts())
            self.assertFalse(browser.available()["available"])
        self.assertEqual(result["checks"][0]["state"], "not_evaluated")
        self.assertIn("playwright", result["install"])

    def test_route_decision_uses_scope_policy(self):
        def resolver(host):
            return {"app.example.com": ["93.184.216.34"], "cdn.example.com": ["93.184.216.35"],
                    "meta.example.com": ["169.254.169.254"], "intranet.example.com": ["10.0.0.8"]}[host]

        policy = safety.ScopePolicy("https://app.example.com/", extra_hosts=["*.example.com"], resolver=resolver)
        self.assertEqual(browser.route_decision("https://app.example.com/a.js", policy)[0], "allow")
        self.assertEqual(browser.route_decision("https://cdn.example.com/a.js", policy)[0], "allow")
        self.assertEqual(browser.route_decision("data:image/png;base64,AA==", policy)[0], "allow")
        for url in ("https://evil.example.org/x", "https://meta.example.com/", "https://intranet.example.com/",
                    "ws://app.example.com/socket", "file:///etc/passwd"):
            with self.subTest(url=url):
                self.assertEqual(browser.route_decision(url, policy)[0], "block")
        rules = browser.resolver_rules(policy)
        self.assertEqual(rules, "MAP app.example.com 93.184.216.34,MAP * ~NOTFOUND")

    @unittest.skipUnless(HAS_PLAYWRIGHT, "Playwright is not installed")
    def test_render_local_page(self):  # pragma: no cover - needs Playwright and Chromium
        with App() as app:
            app.static["/page"] = (200, "<title>P</title><script>document.cookie='sessionid=js1';"
                                        "fetch('http://evil.invalid/x');</script><form method='post'>"
                                        "<input name='user'><input type='password' name='pw'></form>",
                                   "text/html")
            result = browser.audit(app.base + "/page", opts())
        self.assertEqual(result["checks"][0]["state"], "ok")
        self.assertTrue(result["forms"])
        self.assertTrue(any(c["set_by_js"] for c in result["cookies"]))
        self.assertNotIn("js1", json.dumps(result["cookies"]))


# -- translations -------------------------------------------------------------------------------------

class Phase2CatalogTests(unittest.TestCase):
    FILES = ("authscope.py", "session_audit.py", "apispec.py", "zapclient.py", "browser.py")

    def test_every_string_translated(self):
        import i18n_es_phase2
        catalog = dict(i18n_es_phase2.STRINGS)
        for module in ("i18n_es_modules",):
            try:
                catalog.update(__import__(module).STRINGS)
            except ImportError:
                pass
        missing = []
        for name in self.FILES:
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "tr" and node.args \
                        and isinstance(node.args[0], ast.Constant) and node.args[0].value not in catalog:
                    missing.append(f"{name}: {node.args[0].value}")
        self.assertEqual(missing, [])

    def test_placeholders_match(self):
        self.assertEqual(i18n.catalog_problems("es"), [])


if __name__ == "__main__":
    unittest.main()
