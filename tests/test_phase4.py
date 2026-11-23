"""Phase 4 (Security Center): audit store, CSV/PDF exports and the local web server. No network."""

import csv
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auditstore  # noqa: E402
import exporters  # noqa: E402
import server  # noqa: E402

COOKIE = "SESSIONVALUEDONOTLEAK999"
TOKEN = "CsrfTokenDoNotLeak123456"  # noqa: S105 - fake value
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:  # the extra is optional: the server tests are skipped
    HAVE_FASTAPI = False


def make_report(target="example.com", day=1, findings=("cookie", "csp"), checks=("webapp.csp", "webapp.cookies"),
                coverage=80):
    catalog = {
        "cookie": {"id": "DI-COOKIE0001", "target": "https://example.com/login", "path": "/login",
                   "category": "cookies", "title": "Session cookie without HttpOnly", "severity": "medium",
                   "status": "confirmed", "confidence": "high",
                   "evidence": f"Set-Cookie: sid={COOKIE}; Path=/", "tool": "domaininfo.webapp",
                   "impact": "Script can read the session", "verification": "Inspect the Set-Cookie header",
                   "recommendation": "Add HttpOnly", "references": ["CWE-1004"]},
        "csp": {"id": "DI-CSP0000001", "target": "https://example.com/login", "path": "/login", "category": "csp",
                "title": "No Content-Security-Policy", "severity": "low", "status": "likely", "confidence": "medium",
                "evidence": f"csrf_token={TOKEN} key {AWS_KEY}", "tool": "domaininfo.webapp"},
        "legacy": {"id": "DI-OLDSPANISH", "category": "transporte", "title": "HTTP sin cifrar", "severity": "alta",
                   "status": "confirmado", "confidence": "alta"},
    }
    return {"meta": {"tool": "DomainInfo", "version": "6.0.0", "target": target,
                     "date": f"2026-11-{day:02d}T10:00:00+00:00", "mode": "webapp"},
            "modules": {"webapp": {"status": "ok", "data": {"findings": [catalog[f] for f in findings],
                                                            "cookies": [{"name": "sid", "secure": True}]}},
                        "ports": {"status": "ok", "data": {"results": [{"port": 3389, "state": "open"}]}}},
            "score": {"score": 72, "grade": "C",
                      "findings": [{"severity": "alta", "area": "Puertos", "title": "RDP reachable on port 3389",
                                    "fix": "Close it"}]},
            "assessment": {"security": 70, "coverage": coverage, "confidence": 60, "checks": list(checks)}}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = auditstore.AuditStore(":memory:")
        self.project = self.store.create_project("Acme", "Main site")
        self.target = self.store.add_target(self.project["id"], "Example.COM")

    def tearDown(self):
        self.store.close()

    def test_projects_and_scope(self):
        self.assertEqual(self.store.schema_version(), auditstore.SCHEMA_VERSION)
        self.assertEqual(self.target["value"], "example.com")
        self.assertEqual(self.target["kind"], "domain")
        url = self.store.add_target(self.project["id"], "https://App.example.com/login?x=1")
        self.assertEqual(url["kind"], "url")
        with self.assertRaises(ValueError):
            self.store.create_project("Acme")
        with self.assertRaises(ValueError):
            self.store.add_target(self.project["id"], "example.com")
        for bad in ("ftp://example.com", "https://user:pw@example.com/", "bad host", "-x-.com", ""):
            with self.assertRaises(ValueError, msg=bad):
                self.store.add_target(self.project["id"], bad)
        self.assertIsNotNone(self.store.in_scope(self.project["id"], "EXAMPLE.com."))
        self.assertIsNone(self.store.in_scope(self.project["id"], "evil.example.net"))
        self.assertEqual(self.store.list_projects()[0]["target_count"], 2)
        self.assertTrue(self.store.remove_target(url["id"]))
        self.assertTrue(self.store.delete_project(self.project["id"]))
        self.assertEqual(self.store.list_projects(), [])

    def test_sql_is_parameterized(self):
        name = "x'); DROP TABLE projects; --"
        project = self.store.create_project(name)
        self.assertEqual(self.store.get_project(project["id"])["name"], name)
        self.assertEqual(len(self.store.list_projects()), 2)

    def test_audit_and_normalized_findings(self):
        audit = self.store.save_audit(self.project["id"], make_report(findings=("cookie", "csp", "legacy")))
        self.assertEqual(audit["target_id"], self.target["id"])
        self.assertEqual((audit["grade"], audit["security"], audit["coverage"]), ("C", 70, 80))
        findings = self.store.list_findings(audit_id=audit["id"])
        by_title = {f["title"]: f for f in findings}
        self.assertEqual(len(findings), 4)
        legacy = by_title["HTTP sin cifrar"]
        self.assertEqual((legacy["severity"], legacy["evidence_status"], legacy["category"], legacy["section"]),
                         ("high", "confirmed", "transport", "tls"))
        rdp = by_title["RDP reachable on port 3389"]
        self.assertEqual((rdp["severity"], rdp["category"], rdp["section"]), ("high", "ports", "infra"))
        self.assertEqual(by_title["Session cookie without HttpOnly"]["section"], "auth")
        stored = json.dumps(self.store.get_audit(audit["id"], include_report=True)) + json.dumps(findings)
        for secret in (COOKIE, TOKEN, AWS_KEY):
            self.assertNotIn(secret, stored)
        self.assertEqual(self.store.severity_counts(audit_id=audit["id"]),
                         {"high": 2, "medium": 1, "low": 1, "info": 0})
        with self.assertRaises(ValueError):
            self.store.save_audit(self.project["id"], {"meta": "x"})

    def test_status_history_and_carry_over(self):
        first = self.store.save_audit(self.project["id"], make_report(day=1))
        cookie = next(f for f in self.store.list_findings(audit_id=first["id"]) if f["category"] == "cookies")
        with self.assertRaises(ValueError):
            self.store.set_finding_status(cookie["id"], "accepted_risk")  # a note is required
        with self.assertRaises(ValueError):
            self.store.set_finding_status(cookie["id"], "bogus", "x")
        updated = self.store.set_finding_status(cookie["id"], "accepted_risk", "Legacy app, retired in Q1")
        self.assertEqual(updated["review_status"], "accepted_risk")
        second = self.store.save_audit(self.project["id"], make_report(day=2))
        again = next(f for f in self.store.list_findings(audit_id=second["id"]) if f["category"] == "cookies")
        self.assertEqual(again["review_status"], "accepted_risk")
        history = self.store.finding_history(again["id"])
        self.assertEqual([h["new_status"] for h in history], ["open", "accepted_risk"])
        self.assertEqual(history[1]["note"], "Legacy app, retired in Q1")
        self.assertEqual(len(self.store.target_history(self.project["id"], "example.com")), 2)

    def test_comparison_marks_fixed_only_when_comparable(self):
        first = self.store.save_audit(self.project["id"], make_report(day=1))
        second = self.store.save_audit(self.project["id"], make_report(day=2, findings=("cookie",)))
        result = self.store.compare(first["id"], second["id"])
        self.assertTrue(result["comparable"])
        self.assertEqual([f["title"] for f in result["fixed"]], ["No Content-Security-Policy"])
        self.assertEqual(len(result["unchanged"]), 2)
        self.assertEqual(result["new"], [])
        fixed = next(f for f in self.store.list_findings(audit_id=first["id"]) if f["category"] == "csp")
        self.assertEqual(fixed["review_status"], "fixed")
        # Reappears: reopened with a note in the history
        third = self.store.save_audit(self.project["id"], make_report(day=3))
        csp = next(f for f in self.store.list_findings(audit_id=third["id"]) if f["category"] == "csp")
        self.assertEqual(csp["review_status"], "open")
        self.assertIn("again", self.store.finding_history(csp["id"])[-1]["note"])
        # Different coverage: not comparable, nothing is marked fixed
        fourth = self.store.save_audit(self.project["id"], make_report(day=4, findings=(), coverage=50))
        result = self.store.compare(third["id"], fourth["id"])
        self.assertFalse(result["comparable"])
        self.assertIn("30", result["reason"])
        self.assertTrue(all(f["review_status"] == "open" for f in self.store.list_findings(audit_id=third["id"])
                            if f["category"] == "csp"))
        other_checks = self.store.save_audit(self.project["id"], make_report(day=5, checks=("dns",)))
        self.assertFalse(self.store.compare(fourth["id"], other_checks["id"])["comparable"])
        self.assertEqual(len(self.store.list_comparisons(self.project["id"])) >= 3, True)

    def test_comparable_rule(self):
        self.assertTrue(auditstore.comparable({"checks": ["a"], "coverage": 80}, {"checks": ["a"], "coverage": 90})[0])
        self.assertFalse(auditstore.comparable({"checks": ["a"], "coverage": 80}, {"checks": ["a"], "coverage": 91})[0])
        self.assertFalse(auditstore.comparable({"checks": ["a"]}, {"checks": ["b"]})[0])
        self.assertFalse(auditstore.comparable({}, {"checks": ["a"]})[0])

    def test_file_database_and_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sub" / "center.db"
            with auditstore.AuditStore(path) as store:
                store.create_project("Disk")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with auditstore.AuditStore(path) as store:
                self.assertEqual(store.list_projects()[0]["name"], "Disk")

    def test_default_path_is_user_data_dir(self):
        path = str(auditstore.default_path())
        self.assertIn("DomainInfo" if sys.platform == "win32" else "domaininfo", path)
        self.assertTrue(path.endswith("securitycenter.db"))


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.store = auditstore.AuditStore(":memory:")
        project = self.store.create_project("Acme")
        self.store.add_target(project["id"], "example.com")
        self.store.save_audit(project["id"], make_report(day=1))
        second = self.store.save_audit(project["id"], make_report(day=2, findings=("cookie",)))
        rdp = next(f for f in self.store.list_findings(audit_id=second["id"]) if f["category"] == "ports")
        self.store.set_finding_status(rdp["id"], "false_positive", "Port belongs to the lab VPN gateway")
        self.bundle = self.store.report_bundle(project["id"])

    def tearDown(self):
        self.store.close()

    def test_redaction(self):
        text = exporters.redact_text(f"Cookie: sid={COOKIE}\nAuthorization: Bearer abcdefghijklmnop {AWS_KEY}")
        for secret in (COOKIE, "abcdefghijklmnop", AWS_KEY):
            self.assertNotIn(secret, text)
        data = exporters.scrub({"session_token": "abcdefghijkl", "note": f"x token={TOKEN} and more text"})
        self.assertNotIn("abcdefghijkl", json.dumps(data))
        self.assertNotIn(TOKEN, json.dumps(data))

    def test_csv(self):
        findings = self.bundle["findings"] + [dict(self.bundle["findings"][0], title="=HYPERLINK(\"http://x\")")]
        rows = list(csv.reader(io.StringIO(exporters.findings_csv(findings))))
        self.assertEqual(tuple(rows[0]), exporters.CSV_COLUMNS)
        self.assertEqual(len(rows), len(findings) + 1)
        self.assertTrue(rows[-1][exporters.CSV_COLUMNS.index("title")].startswith("'="))
        self.assertNotIn(COOKIE, exporters.findings_csv(findings))

    def _check_pdf(self, data):
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        startxref = int(re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data).group(1))
        self.assertTrue(data[startxref:].startswith(b"xref"))
        count = int(re.search(rb"xref\s+0 (\d+)", data).group(1))
        offsets = re.findall(rb"(\d{10}) 00000 n ", data)
        self.assertEqual(len(offsets), count - 1)
        for number, offset in enumerate(offsets, 1):
            self.assertTrue(data[int(offset):].startswith(b"%d 0 obj" % number))
        self.assertIn(b"/Root 1 0 R", data)
        pages = len(re.findall(rb"/Type /Page ", data))
        self.assertEqual(int(re.search(rb"/Count (\d+)", data).group(1)), pages)
        for secret in (COOKIE, TOKEN, AWS_KEY):
            self.assertNotIn(secret.encode(), data)
        return pages

    def test_executive_pdf(self):
        data = exporters.executive_pdf(self.bundle)
        self.assertGreaterEqual(self._check_pdf(data), 1)
        self.assertIn(b"Top risks", data)

    def test_technical_pdf_and_page_breaks(self):
        data = exporters.technical_pdf(self.bundle)
        self._check_pdf(data)
        self.assertIn(b"False positives", data)
        self.assertIn(b"Port belongs to the lab VPN gateway", data)
        big = dict(self.bundle, findings=[dict(self.bundle["findings"][0], id=i, title=f"Finding {i} " + "x" * 90)
                                          for i in range(60)])
        self.assertGreater(self._check_pdf(exporters.technical_pdf(big)), 3)

    def test_pdf_text_escaping_and_winansi(self):
        doc = exporters.PDFDocument("T")
        doc.paragraph("Paréntesis (abiertos) y barra \\ · ñ → 中")
        data = doc.render()
        self.assertIn(b"Par\xe9ntesis \\(abiertos\\) y barra \\\\", data)
        self.assertEqual(self._check_pdf(data), 1)

    def test_priority(self):
        high = {"severity": "high", "evidence_status": "confirmed", "review_status": "open", "section": "infra"}
        self.assertGreater(exporters.priority(high), exporters.priority(dict(high, section="maildns")))
        self.assertEqual(exporters.priority(dict(high, review_status="fixed")), 0)


class ServerHelpersTests(unittest.TestCase):
    def test_loopback_and_hosts(self):
        self.assertTrue(server.is_loopback("127.0.0.1"))
        self.assertTrue(server.is_loopback("::1"))
        self.assertTrue(server.is_loopback("localhost"))
        self.assertFalse(server.is_loopback("0.0.0.0"))  # noqa: S104
        self.assertFalse(server.is_loopback("192.168.1.10"))
        hosts = server.allowed_hosts("127.0.0.1", 8765)
        self.assertIn("127.0.0.1:8765", hosts)
        self.assertIn("localhost:8765", hosts)
        self.assertNotIn("evil.example:8765", hosts)

    def test_serve_refuses_remote_by_default(self):
        if not HAVE_FASTAPI:
            with self.assertRaises(server.MissingExtra):
                server.serve("0.0.0.0", open_browser=False)  # noqa: S104
            return
        with self.assertRaises(ValueError):
            server.serve("0.0.0.0", open_browser=False)  # noqa: S104
        with self.assertRaises(ValueError):
            server.serve("192.168.1.10", open_browser=False)

    def test_only_passive_modes(self):
        with self.assertRaises(ValueError):
            server.build_args("ports", "example.com")
        with self.assertRaises(ValueError):
            server.build_args("full", "example.com")
        args, target = server.build_args("web", "example.com")
        self.assertEqual((args.mode, target, args.brute), ("web", "example.com", False))

    def test_section_facts(self):
        facts = server.section_facts(make_report(), "infra")
        self.assertEqual(facts[0]["value"], "3389")


@unittest.skipUnless(HAVE_FASTAPI, "FastAPI extra not installed")
class ServerTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8765"

    def setUp(self):
        self.store = auditstore.AuditStore(":memory:")
        self.token = "t" * 43
        self.scanned = []
        self.release = threading.Event()
        self.release.set()

        def scanner(target, args, progress):
            self.scanned.append((target, args.mode))
            progress("webapp", "running", 1, 1)
            self.release.wait(5)
            progress("webapp", "ok", 1, 1)
            return make_report(target=target)

        self.folder = tempfile.TemporaryDirectory()
        Path(self.folder.name, "index.html").write_text("<!doctype html><title>UI</title>", encoding="utf-8")
        Path(self.folder.name, "assets").mkdir()
        Path(self.folder.name, "assets", "app.js").write_text("console.log(1)", encoding="utf-8")
        self.app = server.create_app(self.store, self.token, server.allowed_hosts("127.0.0.1", 8765),
                                     webui_dir=self.folder.name, scanner=scanner,
                                     tools_detect=lambda: {"nmap": {"name": "nmap", "available": False}})
        self.client = TestClient(self.app, base_url=self.BASE)
        self.auth = {"X-DomainInfo-Token": self.token}

    def tearDown(self):
        self.release.set()
        self.app.state.jobs.shutdown()
        self.client.close()
        self.store.close()
        self.folder.cleanup()

    def api(self, method, path, **kwargs):
        headers = dict(self.auth, **kwargs.pop("headers", {}))
        return self.client.request(method, path, headers=headers, **kwargs)

    def project(self):
        project = self.api("POST", "/api/projects", json={"name": "Acme"}).json()
        target = self.api("POST", f"/api/projects/{project['id']}/targets", json={"value": "example.com"}).json()
        return project, target

    def test_token_required(self):
        self.assertEqual(self.client.get("/api/projects").status_code, 401)
        self.assertEqual(self.client.get("/api/projects", headers={"X-DomainInfo-Token": "wrong"}).status_code, 401)
        self.assertEqual(self.client.get("/api/projects?token=" + self.token).status_code, 401)
        response = self.api("GET", "/api/projects")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_static_ui_without_token_and_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("UI", response.text)
        self.assertEqual(self.client.get("/assets/app.js").status_code, 200)
        self.assertEqual(self.client.get("/assets/../../secret.txt").status_code, 404)
        csp = response.headers["content-security-policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe", csp)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_host_header_allow_list(self):
        self.assertEqual(self.client.get("/api/projects", headers=dict(self.auth, host="evil.example")).status_code,
                         421)
        self.assertEqual(self.client.get("/", headers={"host": "rebind.attacker.test:8765"}).status_code, 421)
        self.assertEqual(self.api("GET", "/api/projects", headers={"host": "localhost:8765"}).status_code, 200)

    def test_cross_site_and_cors(self):
        response = self.api("GET", "/api/projects", headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)
        response = self.client.options("/api/projects", headers={"Origin": "https://evil.example",
                                                                 "Access-Control-Request-Method": "GET"})
        self.assertNotIn("access-control-allow-origin", response.headers)
        self.assertEqual(self.api("GET", "/api/projects", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        self.assertEqual(self.api("GET", "/api/projects", headers={"Origin": self.BASE}).status_code, 200)

    def test_request_size_limit(self):
        response = self.api("POST", "/api/projects", content=b"{" + b" " * (server.MAX_BODY + 10) + b"}",
                            headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)

    def test_project_scope_findings_and_exports(self):
        project, target = self.project()
        pid = project["id"]
        self.assertEqual(self.api("POST", f"/api/projects/{pid}/targets", json={"value": "ftp://x"}).status_code, 400)
        imported = self.api("POST", f"/api/projects/{pid}/import", json=make_report())
        self.assertEqual(imported.status_code, 201, imported.text)
        outside = self.api("POST", f"/api/projects/{pid}/import", json=make_report(target="evil.example.net"))
        self.assertEqual(outside.status_code, 403)
        findings = self.api("GET", f"/api/projects/{pid}/findings").json()
        self.assertEqual(len(findings), 3)
        cookie = next(f for f in findings if f["category"] == "cookies")
        self.assertEqual(self.api("PATCH", f"/api/findings/{cookie['id']}",
                                  json={"status": "false_positive"}).status_code, 400)
        changed = self.api("PATCH", f"/api/findings/{cookie['id']}",
                           json={"status": "false_positive", "note": "Test cookie"}).json()
        self.assertEqual(changed["review_status"], "false_positive")
        self.assertEqual(len(self.api("GET", f"/api/findings/{cookie['id']}/history").json()), 2)
        section = self.api("GET", f"/api/projects/{pid}/sections/infra").json()
        self.assertEqual(section["facts"][0]["facts"][0]["value"], "3389")
        self.assertEqual(self.api("GET", f"/api/projects/{pid}/sections/nope").status_code, 404)
        overview = self.api("GET", "/api/overview").json()
        self.assertEqual(overview["audits"], 1)
        csv_response = self.api("GET", f"/api/projects/{pid}/export/findings.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("attachment", csv_response.headers["content-disposition"])
        for kind in ("executive", "technical"):
            pdf = self.api("GET", f"/api/projects/{pid}/export/{kind}.pdf")
            self.assertEqual(pdf.status_code, 200)
            self.assertTrue(pdf.content.startswith(b"%PDF-"))
            self.assertNotIn(COOKIE.encode(), pdf.content)
        self.assertEqual(self.client.get(f"/api/projects/{pid}/export/technical.pdf").status_code, 401)
        second = self.api("POST", f"/api/projects/{pid}/import", json=make_report(day=2, findings=()))
        compare = self.api("GET", f"/api/compare?base={imported.json()['id']}&head={second.json()['id']}").json()
        self.assertTrue(compare["comparable"])
        self.assertEqual(len(compare["fixed"]), 2)
        self.assertEqual(len(self.api("GET", f"/api/projects/{pid}/targets/{target['id']}/history").json()), 2)

    def wait_job(self, job_id):
        for _ in range(200):
            job = self.api("GET", f"/api/jobs/{job_id}").json()
            if job["state"] in ("done", "error", "cancelled"):
                return job
            time.sleep(0.02)
        self.fail("job did not finish")

    def test_launch_passive_audit_in_scope(self):
        project, target = self.project()
        pid = project["id"]
        response = self.api("POST", f"/api/projects/{pid}/jobs", json={"target_id": target["id"], "mode": "quick"})
        self.assertEqual(response.status_code, 202, response.text)
        job = self.wait_job(response.json()["id"])
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(self.scanned, [("example.com", "quick")])
        self.assertEqual(len(self.api("GET", f"/api/projects/{pid}/audits").json()), 1)

    def test_active_modes_and_out_of_scope_refused(self):
        project, target = self.project()
        pid = project["id"]
        for mode in ("ports", "full", "mikrotik"):
            response = self.api("POST", f"/api/projects/{pid}/jobs", json={"target_id": target["id"], "mode": mode})
            self.assertEqual(response.status_code, 403, mode)
        response = self.api("POST", f"/api/projects/{pid}/jobs", json={"target": "evil.example.net", "mode": "web"})
        self.assertEqual(response.status_code, 403)
        other = self.api("POST", "/api/projects", json={"name": "Other"}).json()
        response = self.api("POST", f"/api/projects/{other['id']}/jobs", json={"target_id": target["id"],
                                                                               "mode": "web"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.scanned, [])

    def test_cancel_running_job(self):
        project, target = self.project()
        self.release.clear()
        job = self.api("POST", f"/api/projects/{project['id']}/jobs",
                       json={"target": "example.com", "mode": "webapp"}).json()
        duplicate = self.api("POST", f"/api/projects/{project['id']}/jobs",
                             json={"target": "example.com", "mode": "webapp"})
        self.assertEqual(duplicate.status_code, 409)
        for _ in range(100):
            if self.api("GET", f"/api/jobs/{job['id']}").json()["state"] == "running":
                break
            time.sleep(0.02)
        self.assertIn(self.api("POST", f"/api/jobs/{job['id']}/cancel").json()["state"], ("cancelling", "cancelled"))
        self.release.set()
        self.assertEqual(self.wait_job(job["id"])["state"], "cancelled")
        self.assertEqual(self.api("GET", f"/api/projects/{project['id']}/audits").json(), [])

    def test_tools_status(self):
        data = self.api("GET", "/api/tools").json()
        self.assertFalse(data["tools"]["nmap"]["available"])

    def test_unknown_api_route(self):
        self.assertEqual(self.api("GET", "/api/nope").status_code, 404)
        self.assertEqual(self.client.get("/api/nope").status_code, 401)


if __name__ == "__main__":
    unittest.main()
