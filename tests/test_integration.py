"""CLI wiring of the 6.0 phases: code mode, external tools, intel, Security Center store and exports.

No network and no real external tools: runners and vulnintel are mocked.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import domaininfo as app  # noqa: E402
import i18n  # noqa: E402


def fake_run(tool, target, options=None, allow_active=False, scope=None, cancel=None, timeout=None,
             allow_private=False):
    if tool == "bandit":
        return {"tool": tool, "target": target, "status": "ok", "reason": "", "active": False, "available": True,
                "version": "1.9", "install": "", "duration": 0.1, "coverage": {"state": "complete"},
                "findings": [{"id": "DI-1", "target": target, "path": "app.py:2", "category": "code",
                              "title": "Bandit B602", "severity": "high", "status": "likely", "confidence": "high",
                              "evidence": "shell=True", "tool": "bandit", "impact": "", "verification": "",
                              "recommendation": "Avoid shell=True", "references": []}],
                "components": [], "assets": [], "errors": []}
    if tool == "nmap":
        return {"tool": tool, "target": target, "status": "skipped" if not allow_active else "ok",
                "reason": "" if allow_active else "not_authorized", "active": True, "available": True,
                "findings": [], "errors": [], "assets": [],
                "components": [{"name": "openssh", "version": "9.6", "evidence": "direct", "source": "nmap"}]}
    return {"tool": tool, "target": target, "status": "skipped", "reason": "unavailable", "available": False,
            "install": "pip install " + tool, "findings": [], "components": [], "assets": [], "errors": []}


class CliIntegrationTests(unittest.TestCase):
    def setUp(self):
        i18n.set_language("en")
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.dir = Path(self.folder.name)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = app.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_code_mode_runs_code_tools_with_real_coverage(self):
        project = self.dir / "project"
        project.mkdir()
        with patch("runners.run", side_effect=fake_run) as run:
            code, out, _ = self.run_cli(["-m", "code", str(project), "-q", "-o", str(self.dir), "--format", "json"])
        self.assertEqual(code, 0)
        report = json.loads(out)
        tools = report["modules"]["tools"]["data"]
        self.assertEqual({row["tool"] for row in tools["results"]}, set(app.CODE_TOOLS))
        pip = next(row for row in tools["results"] if row["tool"] == "pip-audit")
        self.assertEqual(pip["reason"], "not_applicable")  # no requirements.txt
        self.assertNotIn("pip-audit", [call.args[0] for call in run.call_args_list])
        self.assertEqual(report["assessment"]["coverage"], 25)  # 1 of 4 applicable tools ran
        self.assertIn("Bandit B602", [f["title"] for f in report["score"]["findings"]])

    def test_code_mode_rejects_missing_folder(self):
        code, _, err = self.run_cli(["-m", "code", str(self.dir / "nope"), "-q", "-o", str(self.dir)])
        self.assertEqual(code, 2)
        self.assertIn("Not an existing folder", err)

    def test_active_tools_need_explicit_flags(self):
        code, _, err = self.run_cli(["--active", "-q", "example.com"])
        self.assertEqual(code, 2)
        self.assertIn("--active only applies together with --tool", err)
        args = app.parser().parse_args(["--tool", "nmap", "-q", "example.com"])
        with patch("runners.run", side_effect=fake_run) as run, \
                patch.dict(app.RUNNERS, {"dns": lambda t, a: {"addresses": []}, "rdap": lambda t, a: {}}):
            report = app.scan("example.com", args)
        self.assertFalse(run.call_args.kwargs["allow_active"])
        self.assertEqual(report["modules"]["tools"]["data"]["results"][0]["reason"], "not_authorized")

    def test_unexpected_module_error_does_not_abort_the_scan(self):
        def broken(target, args):
            raise TypeError("'int' object is not iterable")
        args = app.parser().parse_args(["-q", "example.com"])
        with patch.dict(app.RUNNERS, {"dns": broken, "rdap": lambda t, a: {"handle": "X"}}):
            report = app.scan("example.com", args)
        self.assertEqual(report["modules"]["dns"]["status"], "error")
        self.assertIn("TypeError", report["modules"]["dns"]["error"])
        self.assertEqual(report["modules"]["rdap"]["status"], "ok")

    def test_unknown_tool_is_rejected(self):
        code, _, err = self.run_cli(["--tool", "metasploit", "-q", "example.com"])
        self.assertEqual(code, 2)
        self.assertIn("Unknown tool", err)

    def test_intel_uses_components_and_marks_banners_heuristic(self):
        args = app.parser().parse_args(["--tool", "nmap", "--active", "--scope", "example.com", "--intel", "-q",
                                        "example.com"])
        seen = {}

        def correlate(components, target=None, **kwargs):
            seen["components"] = components
            return {"matches": [], "findings": [], "errors": [], "sources": {"osv": "ok"}, "skipped": []}
        with patch("runners.run", side_effect=fake_run), patch("vulnintel.correlate", side_effect=correlate), \
                patch.dict(app.RUNNERS, {"dns": lambda t, a: {"addresses": []},
                                         "rdap": lambda t, a: {}}):
            report = app.scan("example.com", args)
        self.assertEqual(seen["components"][0]["name"], "openssh")
        self.assertEqual(report["modules"]["intel"]["status"], "ok")
        banner = app.report_components({"modules": {"tech": {"status": "ok", "data": {
            "headers_grade": {"version_leaks": ["server: Apache/2.4.58"]}}}}})
        self.assertEqual(banner[0]["evidence"], "heuristic")

    def test_intel_without_versions_is_not_applicable(self):
        result = app.intel_info("example.com", None, {"modules": {}})
        self.assertEqual(result["checks"][0]["state"], "not_applicable")

    def test_session_mode_requires_authorization_file(self):
        code, _, err = self.run_cli(["-m", "session", "-q"])
        self.assertEqual(code, 2)
        self.assertIn("--auth-file", err)

    def test_store_history_compare_and_exports(self):
        db = str(self.dir / "center.db")
        project = self.dir / "project"
        project.mkdir()
        with patch("runners.run", side_effect=fake_run):
            for _ in range(2):
                code, _, _ = self.run_cli(["-m", "code", str(project), "-q", "-o", str(self.dir), "--format", "json",
                                           "--store", "Demo", "--db", db])
                self.assertEqual(code, 0)
        code, out, _ = self.run_cli(["--compare", "1", "2", "--db", db])
        self.assertEqual(code, 0)
        self.assertIn("unchanged", json.loads(out))
        for fmt, suffix in (("csv", ".csv"), ("pdf", "_executive.pdf"), ("technical-pdf", "_technical.pdf")):
            code, out, _ = self.run_cli(["--export", fmt, "--project", "demo", "--db", db, "-o", str(self.dir)])
            self.assertEqual(code, 0, fmt)
            path = Path(out.strip())
            self.assertTrue(path.name.endswith(suffix))
            data = path.read_bytes()
            if suffix.endswith(".pdf"):
                self.assertTrue(data.startswith(b"%PDF-"))
        code, _, err = self.run_cli(["--export", "csv", "--project", "missing", "--db", db, "-o", str(self.dir)])
        self.assertEqual(code, 1)
        self.assertIn("Unknown project", err)

    def test_tools_listing_is_json_when_piped(self):
        code, out, _ = self.run_cli(["--tools"])
        self.assertEqual(code, 0)
        self.assertIn("nmap", json.loads(out))

    def test_batch_files_have_english_names(self):
        report = {"meta": {"target": "a.test"}, "modules": {}}
        _, paths = app.save_batch([report, {"meta": {"target": "b.test"}, "modules": {}}], self.dir)
        names = " ".join(Path(p).name for p in paths)
        self.assertIn("_batch_", names)
        self.assertIn("_map.json", names)
        self.assertIn("_inventory.json", names)

    def test_spanish_catalog_covers_new_cli_strings(self):
        i18n.set_language("es")
        self.assertIn("herramientas externas", app.parser().format_help())


if __name__ == "__main__":
    unittest.main()
