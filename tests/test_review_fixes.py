"""Regression tests for the security review fixes (runners, apispec, browser, zapclient, auditstore,
vulnintel, server). No network: DNS, subprocess, HTTP and Playwright are mocked."""

import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import apispec  # noqa: E402
import auditstore  # noqa: E402
import browser  # noqa: E402
import runners  # noqa: E402
import safety  # noqa: E402
import vulnintel  # noqa: E402
import zapclient  # noqa: E402

AVAILABLE = {"available": True, "path": "/opt/tools/fake", "version": "9.9", "compatible": True, "minimum": "1.0",
             "install": "hint"}
PUBLIC = "93.184.216.34"


def opts(**values):
    base = {"timeout": 3.0, "scope": [], "allow_private": False}
    base.update(values)
    return types.SimpleNamespace(**base)


def fake_execute(payload=b"[]"):
    calls = []

    def run(argv, timeout=0, cancel=None, cwd=None, **_):
        calls.append(list(argv))
        out = next((a.split("=", 1)[-1] for a in argv if cwd and cwd in a), None)
        if out:
            with open(out, "wb") as handle:
                handle.write(payload)
        return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False, "cancelled": False,
                "truncated": False, "duration": 0.01}
    run.calls = calls
    return run


def resolver(table):
    def resolve(host):
        if host in table:
            return table[host]
        try:
            return [str(__import__("ipaddress").ip_address(host))]
        except ValueError:
            raise OSError("no such host") from None
    return resolve


# -- 1 and 2: runners -------------------------------------------------------------------------------
class RunnerNetworkGuardTests(unittest.TestCase):
    def setUp(self):
        patch("tools.detect", return_value=AVAILABLE).start()
        patch.object(safety, "resolve_host", resolver({
            "www.example.com": [PUBLIC], "intranet.example.com": ["10.0.0.5"],
            "meta.example.com": ["169.254.169.254"], "mixed.example.com": [PUBLIC, "192.168.1.1"]})).start()
        self.addCleanup(patch.stopall)

    def test_whatweb_never_follows_redirects(self):
        fake = fake_execute()
        with patch.object(runners, "execute", fake):
            result = runners.run("whatweb", "https://www.example.com/")
        self.assertEqual(result["status"], "ok", result["errors"])
        argv = fake.calls[0]
        self.assertIn("--follow-redirect=never", argv)
        self.assertIn("--max-redirects=0", argv)

    def test_passive_network_tool_refuses_internal_targets(self):
        for url in ("http://intranet.example.com/", "http://10.0.0.5/", "http://mixed.example.com/",
                    "http://meta.example.com/", "http://169.254.169.254/latest/"):
            with self.subTest(url=url), patch.object(runners, "execute") as execute:
                result = runners.run("whatweb", url)
                self.assertEqual(result["status"], "skipped")
                self.assertIn(result["reason"], ("private_address", "blocked_address"))
                execute.assert_not_called()

    def test_allow_private_opens_internal_but_never_metadata(self):
        fake = fake_execute()
        with patch.object(runners, "execute", fake):
            self.assertEqual(runners.run("whatweb", "http://intranet.example.com/", allow_private=True)["status"], "ok")
            blocked = runners.run("whatweb", "http://meta.example.com/", allow_private=True)
        self.assertEqual(blocked["reason"], "blocked_address")
        self.assertEqual(len(fake.calls), 1)

    def test_active_tool_on_private_ip_needs_allow_private(self):
        with patch.object(runners, "execute", fake_execute(b"")) as fake:
            result = runners.run("nmap", "10.0.0.5", allow_active=True, scope=["10.0.0.0/8"])
            self.assertEqual(result["reason"], "private_address")
            self.assertEqual(fake.calls, [])

    def test_unresolvable_target_is_skipped(self):
        with patch.object(runners, "execute") as execute:
            result = runners.run("whatweb", "https://nowhere.example.com/")
        self.assertEqual((result["status"], result["reason"]), ("skipped", "unresolved"))
        execute.assert_not_called()

    def test_domain_only_tools_do_not_resolve_the_target(self):
        with patch.object(safety, "resolve_host", side_effect=AssertionError("no lookup")), \
                patch.object(runners, "execute", fake_execute(b"")):
            result = runners.run("subfinder", "example.com")
        self.assertNotIn(result["reason"], ("unresolved", "private_address", "blocked_address"))

    def test_script_shims_are_never_executed(self):
        for path in (r"C:\tools\whatweb.bat", r"C:\tools\whatweb.CMD", r"C:\tools\whatweb.ps1"):
            with self.subTest(path=path), patch("tools.detect", return_value=dict(AVAILABLE, path=path)), \
                    patch.object(runners, "execute") as execute:
                result = runners.run("whatweb", "https://www.example.com/")
                self.assertEqual((result["status"], result["reason"]), ("skipped", "unsafe_executable"))
                execute.assert_not_called()


# -- 3: apispec ---------------------------------------------------------------------------------------
WRONG = (5, 1.5, True, None, "text", [], {}, [5, "x", None], {"a": 5}, [[1]], {"a": {"b": [5]}})
TOP_KEYS = ("openapi", "swagger", "info", "servers", "host", "basePath", "schemes", "paths", "components",
            "securityDefinitions", "security", "tags", "consumes", "produces", "definitions", "x-extra")


class ApiSpecFuzzTests(unittest.TestCase):
    def bases(self):
        yield {"openapi": "3.0.0", "paths": {"/a": {"get": {"responses": {}}}}}
        yield {"swagger": "2.0", "host": "api.example.com", "paths": {"/a": {"get": {}}}}

    def test_wrong_types_at_every_top_level_key(self):
        for base in self.bases():
            for key in TOP_KEYS:
                for value in WRONG:
                    with self.subTest(base=next(iter(base)), key=key, value=value):
                        result = apispec.analyze(dict(base, **{key: value}), "https://api.example.com/openapi.json")
                        self.assertIsInstance(result["findings"], list)

    def test_wrong_types_inside_paths_operations_and_components(self):
        nested = []
        for value in WRONG:
            nested += [
                {"paths": {"/a": value}},
                {"paths": {"/a": {"get": value}}},
                {"paths": {"/a": {"parameters": value, "get": {"parameters": value}}}},
                {"paths": {"/a": {"get": {"parameters": [value], "tags": value, "security": value,
                                          "operationId": value, "deprecated": value}}}},
                {"paths": {"/a": {"$ref": value}}},
                {"paths": {"/a": {"get": {"parameters": [{"in": value, "name": value}]}}}},
                {"components": {"securitySchemes": value}},
                {"components": {"securitySchemes": {"k": value}}},
                {"components": {"securitySchemes": {"k": {"type": value, "in": value, "scheme": value}}}},
                {"securityDefinitions": {"k": {"type": value, "in": value}}},
                {"servers": [{"url": value}]},
                {"servers": [{"url": "http://[::1"}]},
                {"info": {"title": value}},
            ]
        for base in self.bases():
            for extra in nested:
                with self.subTest(base=next(iter(base)), extra=extra):
                    result = apispec.analyze(dict(base, **extra), "https://api.example.com/openapi.json")
                    self.assertIsInstance(result["checks"], list)
        for bad in (None, 5, "x", [], {"swagger": "2.0", "host": "a[b", "schemes": ["http"]}):
            with self.subTest(document=bad):
                self.assertIsInstance(apispec.analyze(bad, "https://api.example.com/openapi.json")["findings"], list)

    def test_audit_with_malformed_spec_never_raises(self):
        body = json.dumps({"openapi": "3.0.0", "servers": 5, "paths": {"/a": {"get": {"tags": 5}}}, "tags": 5})
        fake = MagicMock(status=200, truncated=False, body=body.encode(), url="https://api.example.com/openapi.json")
        with patch.object(safety, "http_get", return_value=fake):
            result = apispec.audit("https://api.example.com/openapi.json", opts())
        self.assertEqual(result["checks"][0]["state"], "ok")


# -- 4: browser WebSockets ---------------------------------------------------------------------------
class FakeWebSocketRoute:
    def __init__(self, url):
        self.url, self.closed, self.connected = url, False, False

    def close(self, **_):
        self.closed = True

    def connect_to_server(self):
        self.connected = True


class FakeContext:
    def __init__(self, with_ws_api, sockets):
        self.sockets, self.ws_handlers, self.init_scripts = sockets, [], []
        if with_ws_api:
            self.route_web_socket = lambda pattern, handler: self.ws_handlers.append(handler)

    def route(self, pattern, handler):
        pass

    def add_init_script(self, script=None, **_):
        self.init_scripts.append(script)

    def new_page(self):
        context = self

        class Page:
            url = f"http://{PUBLIC}/"

            def on(self, *_):
                pass

            def goto(self, url, **_):
                for handler in context.ws_handlers:
                    for ws in context.sockets:
                        handler(ws)
                return MagicMock(status=200)

            def content(self):
                return "<html><title>T</title></html>"
        return Page()

    def cookies(self):
        return []


def fake_playwright(context):
    chromium = MagicMock()
    chromium.new_context.return_value = context
    play = MagicMock()
    play.chromium.launch.return_value = chromium
    manager = MagicMock()
    manager.__enter__.return_value = play
    manager.__exit__.return_value = False
    return types.SimpleNamespace(sync_playwright=lambda: manager)


class BrowserWebSocketTests(unittest.TestCase):
    def test_websocket_decision(self):
        policy = safety.ScopePolicy(f"http://{PUBLIC}/", resolver=resolver({}))
        self.assertEqual(browser.websocket_decision(f"ws://{PUBLIC}/s", policy)[0], "allow")
        self.assertEqual(browser.websocket_decision(f"wss://{PUBLIC}/s", policy)[0], "allow")
        for url in ("ws://10.0.0.5/s", "ws://169.254.169.254/", "ws://127.0.0.1:9222/devtools", "ftp://x/"):
            with self.subTest(url=url):
                self.assertEqual(browser.websocket_decision(url, policy)[0], "block")

    def test_sockets_to_internal_addresses_are_closed(self):
        good, bad, meta = (FakeWebSocketRoute(f"ws://{PUBLIC}/live"), FakeWebSocketRoute("ws://10.0.0.5/x"),
                           FakeWebSocketRoute("ws://169.254.169.254/"))
        context = FakeContext(True, [good, bad, meta])
        with patch.object(browser, "_load", return_value=fake_playwright(context)):
            result = browser.audit(f"http://{PUBLIC}/", opts())
        self.assertTrue(good.connected and not good.closed)
        self.assertTrue(bad.closed and not bad.connected)
        self.assertTrue(meta.closed and not meta.connected)
        states = {c["id"]: c["state"] for c in result["checks"]}
        self.assertEqual(states["websocket_guard"], "ok")
        self.assertTrue(any("10.0.0.5" in b["url"] for b in result["blocked_requests"]))

    def test_workers_are_disabled_in_every_mode(self):
        # Sockets and requests from Web Workers might escape the page-level filters: no workers at all
        for with_api in (True, False):
            context = FakeContext(with_api, [])
            with patch.object(browser, "_load", return_value=fake_playwright(context)):
                browser.audit(f"http://{PUBLIC}/", opts())
            with self.subTest(with_api=with_api):
                self.assertTrue(any("SharedWorker" in s and "'Worker'" in s for s in context.init_scripts))

    def test_without_route_web_socket_guard_is_not_evaluated(self):
        context = FakeContext(False, [])
        with patch.object(browser, "_load", return_value=fake_playwright(context)):
            result = browser.audit(f"http://{PUBLIC}/", opts())
        states = {c["id"]: c["state"] for c in result["checks"]}
        self.assertEqual(states["websocket_guard"], "not_evaluated")
        self.assertTrue(context.init_scripts and "WebSocket" in context.init_scripts[0])
        self.assertIn("WebSocket", result["note"])


# -- 5: ZAP ------------------------------------------------------------------------------------------
class ZapReviewTests(unittest.TestCase):
    def test_high_confidence_is_likely(self):
        finding = zapclient.normalize_alert({"alert": "X", "risk": "Medium", "confidence": "High",
                                             "url": "https://example.com/"}, "https://example.com/")
        self.assertEqual(finding["status"], "likely")
        finding = zapclient.normalize_alert({"alert": "X", "risk": "Medium", "confidence": "Confirmed",
                                             "url": "https://example.com/"}, "https://example.com/")
        self.assertEqual(finding["status"], "confirmed")

    def test_hostname_resolving_internal_is_refused(self):
        table = resolver({"rebind.example.com": [PUBLIC, "10.1.1.1"], "inside.example.com": ["192.168.0.10"]})
        with patch.object(safety, "resolve_host", table), patch.object(zapclient, "ZapClient") as client:
            for url in ("http://rebind.example.com/", "http://inside.example.com/"):
                with self.subTest(url=url), self.assertRaises(safety.ScopeError):
                    zapclient.audit(url, opts(zap_url="http://127.0.0.1:1"))
            client.assert_not_called()

    def test_note_documents_dns_gap(self):
        self.assertIn("rebinding", zapclient.__doc__ or "")


# -- 6: auditstore -----------------------------------------------------------------------------------
class AuditStorePermissionTests(unittest.TestCase):
    def test_existing_parent_directory_is_not_chmodded(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "x.db"
            with patch.object(auditstore.os, "chmod", wraps=os.chmod) as chmod:
                auditstore._secure_file(target)
            touched = [Path(call.args[0]) for call in chmod.call_args_list]
            self.assertNotIn(Path(folder), touched)
            self.assertIn(target, touched)

    def test_created_directory_is_private(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "new" / "deeper" / "x.db"
            with patch.object(auditstore.os, "chmod", wraps=os.chmod) as chmod:
                auditstore._secure_file(target)
            touched = [Path(call.args[0]) for call in chmod.call_args_list]
            self.assertIn(target.parent, touched)
            self.assertNotIn(Path(folder), touched)
            self.assertTrue(target.exists())


# -- 7: vulnintel ------------------------------------------------------------------------------------
class VulnIntelHttpTests(unittest.TestCase):
    def test_incomplete_read_becomes_source_error(self):
        response = MagicMock()
        response.__enter__.return_value.read.side_effect = http.client.IncompleteRead(b"{", 10)
        with patch.object(vulnintel.request, "urlopen", return_value=response), \
                self.assertRaises(vulnintel.SourceError):
            vulnintel._http(vulnintel.OSV_URL, {"x": 1})

    def test_remote_disconnect_becomes_source_error(self):
        with patch.object(vulnintel.request, "urlopen", side_effect=http.client.BadStatusLine("x")), \
                self.assertRaises(vulnintel.SourceError):
            vulnintel._http(vulnintel.OSV_URL, {"x": 1})


# -- 8: server ---------------------------------------------------------------------------------------
try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "FastAPI extra not installed")
class ServerBodyTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8765"

    def setUp(self):
        import server
        self.server = server
        self.store = auditstore.AuditStore(":memory:")
        self.token = "t" * 43
        self.folder = tempfile.TemporaryDirectory()
        Path(self.folder.name, "index.html").write_text("<!doctype html><title>UI</title>", encoding="utf-8")
        self.app = server.create_app(self.store, self.token, server.allowed_hosts("127.0.0.1", 8765),
                                     webui_dir=self.folder.name, scanner=lambda *a: {},
                                     tools_detect=lambda: {})
        self.client = TestClient(self.app, base_url=self.BASE)

    def tearDown(self):
        self.app.state.jobs.shutdown()
        self.client.close()
        self.store.close()
        self.folder.cleanup()

    def post(self, content, headers):
        return self.client.post("/api/projects", content=content,
                                headers={"X-DomainInfo-Token": self.token, "Content-Type": "application/json",
                                         **headers})

    def test_content_length_with_transfer_encoding_rejected(self):
        response = self.post(b'{"name": "A"}', {"Content-Length": "13", "Transfer-Encoding": "chunked"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.store.list_projects(), [])

    def test_chunked_body_refused(self):
        def chunks():
            yield b'{"name": "'
            yield b"A" * (self.server.MAX_BODY + 10)
            yield b'"}'
        response = self.post(chunks(), {})
        self.assertIn(response.status_code, (411, 413))
        self.assertEqual(self.store.list_projects(), [])

    def test_body_limit_enforced_on_bytes_actually_read(self):
        payload = b'{"name": "' + b"A" * (self.server.MAX_BODY + 10) + b'"}'
        response = self.post(payload, {"Content-Length": "20"})
        self.assertIn(response.status_code, (400, 413))
        self.assertEqual(self.store.list_projects(), [])


if __name__ == "__main__":
    unittest.main()
