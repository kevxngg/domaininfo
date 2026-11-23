"""Pruebas de la Fase 1 de DomainInfo 6.0: URL completa, alcance, evidencias y módulo webapp.

Todas las peticiones van a un servidor HTTP local en un hilo; no se toca Internet.
"""

import argparse
import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import domaininfo as app  # noqa: E402
import evidence  # noqa: E402
import safety  # noqa: E402
import score  # noqa: E402
import tools  # noqa: E402
import webapp  # noqa: E402

TOKEN = "s3cr3tCsrfTokenValue123456"
COOKIE = "S3SSIONVALUEDONOTLEAK999"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

PAGES = {
    "/": (200, {}, "<html><head><title>Inicio</title></head><body><h1>Bienvenido</h1></body></html>"),
    "/login": (200, {
        "Set-Cookie": f"sessionid={COOKIE}; Path=/",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "X-Frame-Options": "DENY",
    }, "<html><head><title>Acceso</title></head><body>"
       "<form method='post' action='/session'>"
       "<input type='text' name='username' autocomplete='username'>"
       "<input type='password' name='password'>"
       f"<input type='hidden' name='csrf_token' value='{TOKEN}'>"
       "<button>Entrar</button></form></body></html>"),
    "/login-samesite": (200, {"Set-Cookie": "sid=abc; Path=/; HttpOnly; SameSite=Lax"},
                        "<title>B</title><form method='post'><input name='user'>"
                        "<input type='password' name='pass'></form>"),
    "/login-bare": (200, {}, "<title>C</title><form method='post' action='/s'><input name='email' type='email'>"
                             "<input type='password' name='pw'></form>"),
    "/login-get": (200, {}, "<title>D</title><form method='get' action='/s'><input name='u'>"
                            "<input type='password' name='p'></form>"),
    "/search": (200, {}, "<title>E</title><form method='get' action='/buscar'><input name='q'></form>"),
    "/error": (500, {}, "<pre>Traceback (most recent call last):\n  File \"/srv/app.py\", line 3\n"
                        "ZeroDivisionError: division by zero</pre>"),
    "/leak": (200, {}, f"<title>L</title><script>var k='{AWS_KEY}';</script>"
                       "<!-- -----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA -->"),
    "/redir": (302, {"Location": "/login"}, ""),
    "/redir-out": (302, {"Location": "http://evil.invalid/steal"}, ""),
    "/loop": (302, {"Location": "/loop"}, ""),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (nombre exigido por http.server)
        path = self.path.split("?", 1)[0]
        self.server.seen.append(self.path)
        if path == "/cors":
            self.send_response(200)
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"<title>CORS</title>")
            return
        status, headers, body = PAGES.get(path, (404, {}, "<title>No</title>"))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if not any(key.lower() == "content-type" for key in headers):
            self.send_header("Content-Type", "text/html; charset=utf-8")
        data = body.encode()
        # Como los servidores reales: con Content-Length (http.client suelta antes el socket)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class LocalServer:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.seen = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def opts(**extra):
    values = {"timeout": 3.0, "scope": [], "allow_private": False}
    values.update(extra)
    return argparse.Namespace(**values)


def audit(url, **extra):
    return webapp.audit(url, opts(**extra))


def finding(result, category):
    return [f for f in result["findings"] if f["category"] == category]


class NormalizeUrlTests(unittest.TestCase):
    def test_keeps_path_query_and_port(self):
        self.assertEqual(safety.normalize_url("https://Example.COM:8443/login?next=/a#frag"),
                         "https://example.com:8443/login?next=/a")

    def test_defaults(self):
        self.assertEqual(safety.normalize_url("example.com/login"), "https://example.com/login")
        self.assertEqual(safety.normalize_url("http://example.com"), "http://example.com/")
        self.assertEqual(safety.normalize_url("https://example.com:443/x"), "https://example.com/x")
        self.assertEqual(safety.normalize_url("http://[2001:db8::1]:8080/a"), "http://[2001:db8::1]:8080/a")

    def test_rejects_unsafe(self):
        for bad in ("ftp://example.com/", "file:///etc/passwd", "https://user:pw@example.com/",
                    "https://exa mple.com/", "https://example.com:0/", "https://example.com:70000/",
                    "javascript:alert(1)", "", "https://example.com/\x00"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                safety.normalize_url(bad)

    def test_idna(self):
        self.assertEqual(safety.normalize_url("https://bücher.example/"), "https://xn--bcher-kva.example/")


class ScopeTests(unittest.TestCase):
    def resolver(self, table):
        return lambda host: table[host]

    def test_host_scope(self):
        policy = safety.ScopePolicy("https://app.example.com/login", extra_hosts=["*.cdn.example.com", "auth.example.org"])
        self.assertTrue(policy.in_scope("app.example.com"))
        self.assertTrue(policy.in_scope("img.cdn.example.com"))
        self.assertTrue(policy.in_scope("auth.example.org"))
        self.assertFalse(policy.in_scope("cdn.example.com.evil.test"))
        self.assertFalse(policy.in_scope("example.com"))

    def test_metadata_always_blocked(self):
        policy = safety.ScopePolicy("http://169.254.169.254/latest", allow_private=True,
                                    resolver=self.resolver({"169.254.169.254": ["169.254.169.254"]}))
        with self.assertRaises(safety.ScopeError):
            policy.connect_address("169.254.169.254")

    def test_rebinding_public_to_private_blocked(self):
        table = {"public.example": ["8.8.8.8"], "rebind.example": ["127.0.0.1"]}
        policy = safety.ScopePolicy("https://public.example/", extra_hosts=["rebind.example"],
                                    resolver=self.resolver(table))
        self.assertEqual(policy.connect_address("public.example"), "8.8.8.8")
        with self.assertRaises(safety.ScopeError):
            policy.connect_address("rebind.example")

    def test_address_pinned_per_host(self):
        calls = []

        def resolver(host):
            calls.append(host)
            return ["8.8.8.8"] if len(calls) == 1 else ["127.0.0.1"]
        policy = safety.ScopePolicy("https://public.example/", resolver=resolver)
        self.assertEqual(policy.connect_address("public.example"), "8.8.8.8")
        self.assertEqual(policy.connect_address("public.example"), "8.8.8.8")
        self.assertEqual(len(calls), 1)

    def test_private_target_typed_by_user_allowed(self):
        policy = safety.ScopePolicy("http://10.0.0.5/", resolver=self.resolver({"10.0.0.5": ["10.0.0.5"]}))
        self.assertEqual(policy.connect_address("10.0.0.5"), "10.0.0.5")

    def test_out_of_scope_host(self):
        policy = safety.ScopePolicy("https://a.example/")
        with self.assertRaises(safety.ScopeError):
            policy.connect_address("b.example")

    def test_ipv4_mapped_ipv6_metadata(self):
        self.assertEqual(safety.classify_ip("::ffff:169.254.169.254"), "blocked")
        self.assertEqual(safety.classify_ip("10.1.2.3"), "private")
        self.assertEqual(safety.classify_ip("1.1.1.1"), "public")


class EvidenceTests(unittest.TestCase):
    def test_redact(self):
        text = evidence.redact(f"sessionid={COOKIE}; key {AWS_KEY}")
        self.assertNotIn(COOKIE, text)
        self.assertNotIn(AWS_KEY, text)
        self.assertIn("sessionid=", text)
        self.assertEqual(evidence.mask("abcdef123456"), "abcd…[oculto]")

    def test_finding_validation_and_id(self):
        item = evidence.Finding(target="https://a.example/login", path="/login", category="cookies",
                                title="Cookie sin Secure", severity="media", status="confirmado",
                                confidence="alta", evidence="Set-Cookie: sid=…", tool="webapp",
                                impact="i", verification="v", recommendation="r", references=["CWE-614"])
        data = item.to_dict()
        for key in ("id", "target", "path", "category", "severity", "status", "confidence", "evidence",
                    "tool", "impact", "verification", "recommendation", "references"):
            self.assertIn(key, data)
        self.assertTrue(data["id"].startswith("DI-"))
        self.assertEqual(data["id"], evidence.Finding(**{**item.__dict__}).to_dict()["id"])
        with self.assertRaises(ValueError):
            evidence.Finding(target="t", path="/", category="c", title="t", severity="grave", status="confirmado")
        with self.assertRaises(ValueError):
            evidence.Finding(target="t", path="/", category="c", title="t", severity="alta", status="vulnerable")

    def test_scores(self):
        checks = [{"id": "a", "state": "ok", "evidence": "directa"},
                  {"id": "b", "state": "ok", "evidence": "heuristica"},
                  {"id": "c", "state": "no_evaluado"},
                  {"id": "d", "state": "no_aplicable"}]
        findings = [{"severity": "alta", "status": "confirmado"}, {"severity": "alta", "status": "probable"},
                    {"severity": "alta", "status": "pendiente"}]
        result = evidence.scores(findings, checks)
        self.assertEqual(result["security"], 100 - 20 - 10)
        self.assertEqual(result["coverage"], 67)  # 2 de 3 aplicables
        self.assertEqual(result["confidence"], 50)

    def test_comparable(self):
        a = {"coverage": 90, "checks": ["x", "y"]}
        self.assertTrue(evidence.comparable(a, {"coverage": 85, "checks": ["y", "x"]}))
        self.assertFalse(evidence.comparable(a, {"coverage": 60, "checks": ["x", "y"]}))
        self.assertFalse(evidence.comparable(a, {"coverage": 90, "checks": ["x"]}))


class WebappAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.local = LocalServer().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.local.__exit__(None, None, None)

    def test_login_path_preserved_and_distinct_from_root(self):
        result = audit(self.local.base + "/login")
        self.assertEqual(result["url"], self.local.base + "/login")
        self.assertEqual(result["final_url"], self.local.base + "/login")
        self.assertEqual(result["title"], "Acceso")
        self.assertIn("/login", self.local.server.seen)
        root = result["root_comparison"]
        self.assertEqual(root["title"], "Inicio")
        self.assertTrue(root["differs"])
        self.assertEqual(root["forms"], 0)
        self.assertEqual(len(result["forms"]), 1)

    def test_login_form_analysis(self):
        result = audit(self.local.base + "/login")
        form = result["forms"][0]
        self.assertEqual(form["method"], "POST")
        self.assertEqual(form["action"], self.local.base + "/session")
        self.assertTrue(form["login"])
        self.assertEqual(form["password_fields"], ["password"])
        self.assertEqual(form["user_fields"], ["username"])
        self.assertEqual(form["csrf"]["state"], "token_visible")
        self.assertEqual(form["csrf"]["fields"], ["csrf_token"])

    def test_secrets_never_in_report(self):
        result = audit(self.local.base + "/login")
        text = json.dumps(result)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(COOKIE, text)

    def test_cookie_flags(self):
        result = audit(self.local.base + "/login")
        cookie = result["cookies"][0]
        self.assertEqual(cookie["name"], "sessionid")
        self.assertFalse(cookie["httponly"])
        self.assertIsNone(cookie["samesite"])
        titles = " ".join(f["title"] for f in finding(result, "cookies"))
        self.assertIn("HttpOnly", titles)
        self.assertIn("SameSite", titles)
        # Por HTTP no se exige Secure: no aplica
        self.assertNotIn("Secure", titles)

    def test_csp_and_clickjacking(self):
        result = audit(self.local.base + "/login")
        csp = result["headers"]["csp"]
        self.assertTrue(csp["present"])
        self.assertIn("'unsafe-inline' en script-src", csp["issues"])
        self.assertTrue(result["headers"]["clickjacking"]["protected"])
        self.assertFalse(finding(result, "clickjacking"))

    def test_csrf_alternative_protection(self):
        result = audit(self.local.base + "/login-samesite")
        csrf = result["forms"][0]["csrf"]
        self.assertEqual(csrf["state"], "proteccion_alternativa")
        statuses = {f["status"] for f in finding(result, "csrf")}
        self.assertNotIn("confirmado", statuses)

    def test_csrf_unknown_is_pending_not_vulnerable(self):
        result = audit(self.local.base + "/login-bare")
        self.assertEqual(result["forms"][0]["csrf"]["state"], "desconocido")
        self.assertEqual(result["forms"][0]["user_fields"], ["email"])
        items = finding(result, "csrf")
        self.assertTrue(items)
        self.assertTrue(all(f["status"] == "pendiente" for f in items))

    def test_password_over_get_and_http(self):
        result = audit(self.local.base + "/login-get")
        titles = " ".join(f["title"] for f in finding(result, "formularios"))
        self.assertIn("GET", titles)
        self.assertIn("HTTP", titles)

    def test_search_form_not_login(self):
        result = audit(self.local.base + "/search")
        self.assertFalse(result["forms"][0]["login"])
        self.assertEqual(result["forms"][0]["csrf"]["state"], "no_aplicable")
        self.assertFalse(finding(result, "csrf"))

    def test_redirect_inside_scope(self):
        result = audit(self.local.base + "/redir")
        self.assertEqual(result["final_url"], self.local.base + "/login")
        self.assertEqual(result["redirects"][0]["status"], 302)
        self.assertFalse(result["redirects"][0].get("blocked"))

    def test_redirect_out_of_scope_blocked(self):
        result = audit(self.local.base + "/redir-out")
        self.assertEqual(result["final_url"], self.local.base + "/redir-out")
        self.assertTrue(result["redirects"][0]["blocked"])
        self.assertIn("evil.invalid", result["redirects"][0]["location"])
        self.assertTrue(finding(result, "redirecciones"))

    def test_redirect_loop_limited(self):
        result = audit(self.local.base + "/loop")
        self.assertLessEqual(len(result["redirects"]), safety.MAX_REDIRECTS + 1)
        self.assertTrue(any(r.get("blocked") for r in result["redirects"]))

    def test_error_exposure(self):
        result = audit(self.local.base + "/error")
        self.assertEqual(result["status"], 500)
        items = finding(result, "errores")
        self.assertTrue(items)
        self.assertEqual(items[0]["status"], "confirmado")
        self.assertIn("Python", items[0]["title"])

    def test_sensitive_data_redacted(self):
        result = audit(self.local.base + "/leak")
        items = finding(result, "exposicion")
        kinds = " ".join(f["title"] for f in items)
        self.assertIn("AWS", kinds)
        self.assertIn("privada", kinds)
        self.assertNotIn(AWS_KEY, json.dumps(result))

    def test_cors_reflection(self):
        result = audit(self.local.base + "/cors")
        self.assertTrue(result["cors"]["reflects_origin"])
        self.assertTrue(result["cors"]["credentials"])
        items = finding(result, "cors")
        self.assertEqual(items[0]["status"], "confirmado")
        self.assertEqual(items[0]["severity"], "alta")

    def test_hsts_not_applicable_over_http(self):
        result = audit(self.local.base + "/")
        check = next(c for c in result["checks"] if c["id"] == "hsts")
        self.assertEqual(check["state"], "no_aplicable")

    def test_every_finding_has_origin(self):
        result = audit(self.local.base + "/login-get")
        for item in result["findings"]:
            self.assertEqual(item["tool"], "domaininfo.webapp")
            self.assertTrue(item["evidence"])
            self.assertTrue(item["recommendation"])
            self.assertIn(item["status"], evidence.STATUSES)

    def test_scores_present(self):
        result = audit(self.local.base + "/login")
        for key in ("security", "coverage", "confidence"):
            self.assertTrue(0 <= result["assessment"][key] <= 100)

    def test_private_redirect_blocked_for_public_origin(self):
        # Origen "público" simulado que redirige a loopback: debe bloquearse (SSRF).
        policy = safety.ScopePolicy("https://public.example/", extra_hosts=["127.0.0.1"],
                                    resolver=lambda host: ["8.8.8.8"] if host == "public.example" else ["127.0.0.1"])
        with self.assertRaises(safety.ScopeError):
            safety.http_get(self.local.base + "/", policy, timeout=2)


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            code = app.main(argv + ["-q", "-o", folder, "--format", "json"])
        return code, json.loads(out.getvalue())

    def test_webapp_url_keeps_path(self):
        with LocalServer() as local:
            code, report = self.run_cli(["-m", "webapp", "--url", local.base + "/login"])
        self.assertEqual(code, 0)
        self.assertEqual(report["meta"]["target"], local.base + "/login")
        self.assertEqual(report["modules"]["webapp"]["data"]["title"], "Acceso")
        self.assertIn("assessment", report)
        self.assertIn("score", report)

    def test_positional_url_in_webapp_mode(self):
        with LocalServer() as local:
            code, report = self.run_cli(["-m", "webapp", local.base + "/login?x=1"])
        self.assertEqual(code, 0)
        self.assertEqual(report["modules"]["webapp"]["data"]["url"], local.base + "/login?x=1")

    def test_url_requires_webapp(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            app.main(["--url", "https://example.com/login", "-q"])

    def test_classic_modes_unchanged(self):
        self.assertEqual(app.normalize_target("https://example.com/login"), "example.com")
        self.assertEqual(app.MODES["web"], ("dns", "http", "tls", "tech"))
        self.assertIn("webapp", app.MODES)
        self.assertIn("webapp", app.MODULES)

    def test_legacy_score_schema_and_webapp_findings(self):
        report = {"modules": {"webapp": {"status": "ok", "data": {"findings": [
            {"severity": "alta", "status": "confirmado", "category": "cors", "title": "CORS refleja",
             "recommendation": "r"},
            {"severity": "alta", "status": "pendiente", "category": "csrf", "title": "sin token",
             "recommendation": "r"}], "checks": []}}}}
        result = score.assess(report)
        self.assertEqual(set(result) >= {"score", "grade", "findings", "note"}, True)
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("CORS refleja", titles)
        self.assertNotIn("sin token", titles)


HOSTILE = {
    "/redos": (200, {}, "\n" * 900_000 + "x"),
    "/badcharset": (200, {"Content-Type": "text/html; charset=undefined"}, "<title>Rara</title>"),
    "/hsts": (200, {"Strict-Transport-Security": "max-age=" + "9" * 5000}, "<title>H</title>"),
    "/ansi": (200, {"Server": "nginx/1.2\x1b[2J"}, "<title>Hola\x1b[31m</title>"),
    "/to-callback": (302, {"Location": "/cb?code=abcdef123456789&sid=zzzzyyyyxxxx1234&page=2"}, ""),
    "/cb": (200, {}, "<title>cb</title>"),
    "/debug": (500, {}, "Traceback (most recent call last):\n {'SECRET_KEY': 'k3yV4lu3D0NotLeak', "
                        "\"token\":\"t0k3nV4lu3D0NotLeak\"}"),
}


class HostileServerTests(unittest.TestCase):
    """Fallos encontrados en la revisión de seguridad: un objetivo hostil no debe colgar, romper
    ni ensuciar la auditoría."""

    @classmethod
    def setUpClass(cls):
        cls.patch = patch.dict(PAGES, HOSTILE)
        cls.patch.start()
        cls.local = LocalServer().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.local.__exit__(None, None, None)
        cls.patch.stop()

    def test_no_catastrophic_regex(self):
        import time
        start = time.monotonic()
        audit(self.local.base + "/redos")
        self.assertLess(time.monotonic() - start, 5)

    def test_bad_charset_and_huge_max_age_do_not_abort(self):
        self.assertEqual(audit(self.local.base + "/badcharset")["title"], "Rara")
        with patch.object(webapp._Audit, "run", webapp._Audit.run):
            result = audit(self.local.base + "/hsts")
        self.assertEqual(result["status"], 200)

    def test_control_characters_removed(self):
        text = json.dumps(audit(self.local.base + "/ansi"))
        self.assertNotIn("\\u001b", text)

    def test_secrets_in_urls_masked(self):
        text = json.dumps(audit(self.local.base + "/to-callback"))
        self.assertNotIn("abcdef123456789", text)
        self.assertNotIn("zzzzyyyyxxxx1234", text)
        self.assertIn("page=2", text)

    def test_quoted_secrets_in_error_dump_masked(self):
        text = json.dumps(audit(self.local.base + "/debug"))
        self.assertNotIn("k3yV4lu3D0NotLeak", text)
        self.assertNotIn("t0k3nV4lu3D0NotLeak", text)

    def test_total_deadline(self):
        with self.assertRaises(OSError):
            safety.http_get(self.local.base + "/", safety.ScopePolicy(self.local.base + "/"), timeout=2,
                            deadline=0)

    def test_embedded_ipv4_classification(self):
        self.assertEqual(safety.classify_ip("64:ff9b::a9fe:a9fe"), "blocked")
        self.assertEqual(safety.classify_ip("2002:a9fe:a9fe::"), "blocked")
        self.assertEqual(safety.classify_ip("64:ff9b::0a00:0001"), "private")

    def test_mixed_origin_is_not_private(self):
        policy = safety.ScopePolicy("https://mixed.example/", resolver=lambda h: ["8.8.8.8", "10.0.0.1"])
        with self.assertRaises(safety.ScopeError):
            policy.connect_address("mixed.example")

    def test_markdown_escapes_titles(self):
        import render
        report = {"meta": {}, "modules": {"webapp": {"status": "ok", "data": {"findings": [
            {"id": "DI-1", "title": "x](javascript:alert(1))", "severity": "baja", "status": "confirmado",
             "category": "c", "confidence": "alta", "evidence": "e", "references": []}]}}}}
        self.assertNotIn("](javascript:", render.to_markdown(app, report))


class MenuAndReportTests(unittest.TestCase):
    def test_menu_webapp_keeps_path_and_explains(self):
        from terminal_ui import MODE_KEYS, InteractiveApp
        self.assertEqual(MODE_KEYS["w"], "webapp")
        with LocalServer() as local, tempfile.TemporaryDirectory() as folder:
            answers = iter(["w", local.base + "/login", "1", "0", "0"])
            out = io.StringIO()
            ui = InteractiveApp(app, app.parser().parse_args(["-o", folder]), input_fn=lambda: next(answers),
                                output=out)
            self.assertEqual(ui.run(), 0)
            data = ui.history[0]["report"]["modules"]["webapp"]["data"]
            self.assertEqual(data["final_url"], local.base + "/login")
            text = out.getvalue()
            self.assertIn("Acceso", text)
            self.assertIn("Raíz del sitio", text)
            self.assertIn("CSRF: token visible", text)
            self.assertNotIn(TOKEN, text)

    def test_reports_explain_origin(self):
        import render
        with LocalServer() as local:
            args = app.parser().parse_args(["-m", "webapp", "-q", local.base + "/login"])
            report = app.scan(local.base + "/login", args)
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(COOKIE, serialized)
        for content in (render.to_text(app, report), render.to_markdown(app, report),
                        render.to_html(app, report, serialized)):
            self.assertIn("domaininfo.webapp", content)
            self.assertIn("CWE-", content)
            self.assertIn("Cobertura", content)
            self.assertNotIn(COOKIE, content)
            self.assertNotIn(TOKEN, content)

    def test_batch_file_keeps_urls(self):
        with LocalServer() as local, tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "urls.txt"
            path.write_text(f"{local.base}/login\n{local.base}/\n# x\n{local.base}/login\n", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = app.main(["-m", "webapp", "-f", str(path), "-q", "-o", folder, "--format", "json"])
        self.assertEqual(code, 0)
        targets = [json.loads(line)["meta"]["target"] for line in out.getvalue().splitlines() if line.strip()]
        self.assertEqual(targets, [local.base + "/login", local.base + "/"])


class ToolsTests(unittest.TestCase):
    def test_missing_tool_disabled(self):
        with patch("shutil.which", return_value=None):
            info = tools.detect("nmap")
        self.assertFalse(info["available"])
        self.assertIn("install", info)

    def test_version_parsed_without_shell(self):
        completed = argparse.Namespace(stdout="Nmap version 7.95 ( https://nmap.org )", stderr="", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
                patch("subprocess.run", return_value=completed) as run:
            info = tools.detect("nmap")
        self.assertTrue(info["available"])
        self.assertEqual(info["version"], "7.95")
        self.assertTrue(info["compatible"])
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list)
        self.assertNotIn("shell", kwargs)
        self.assertIn("timeout", kwargs)

    def test_binary_in_current_directory_ignored(self):
        import os
        planted = os.path.join(os.getcwd(), "nmap.exe")
        with patch("shutil.which", return_value=planted), patch("subprocess.run") as run:
            info = tools.detect("nmap")
        self.assertFalse(info["available"])
        run.assert_not_called()

    def test_catalog_covers_requested_tools(self):
        for name in ("nmap", "subfinder", "amass", "dnsx", "httpx", "whatweb", "zap", "nuclei", "sslyze",
                     "testssl.sh", "semgrep", "bandit", "pip-audit", "trivy", "gitleaks", "playwright"):
            self.assertIn(name, tools.CATALOG)


try:
    from hypothesis import given, settings, strategies as st
except ImportError:  # dependencia de desarrollo opcional
    given = None


@unittest.skipIf(given is None, "hypothesis no instalado (pip install hypothesis)")
class PropertyTests(unittest.TestCase):
    if given is not None:
        @settings(max_examples=300, deadline=None)
        @given(st.text(max_size=80))
        def test_normalize_url_is_safe_and_idempotent(self, raw):
            try:
                url = safety.normalize_url(raw)
            except ValueError:
                return
            self.assertTrue(url.startswith(("http://", "https://")))
            self.assertNotIn("@", url.split("/")[2])
            self.assertFalse(any(ord(c) < 33 for c in url))
            self.assertEqual(safety.normalize_url(url), url)

        @settings(max_examples=300, deadline=None)
        @given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=12, max_size=40))
        def test_redact_hides_cookie_values(self, value):
            value = value.replace(";", "").replace(",", "").replace("&", "").replace("<", "").replace(">", "") \
                .replace('"', "").replace("'", "")
            if len(value) < 12:
                return
            self.assertNotIn(value, evidence.redact(f"Set-Cookie: sessionid={value}; Path=/"))


if __name__ == "__main__":
    unittest.main()
