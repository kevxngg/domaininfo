"""Terminal usability: readable output, help, completion, watch, update and single-key menus."""
import contextlib
import io
import json
import tempfile
import unittest
from unittest.mock import patch

import completions
import domaininfo as app
from terminal_ui import Back, InteractiveApp, service_label


class TTY(io.StringIO):
    def isatty(self):
        return True


def fake_report(target="example.com", ports=(22,), expires="2027-01-01", days=200, status=200):
    return {"meta": {"tool": "DomainInfo", "version": app.VERSION, "target": target, "mode": "full"},
            "modules": {
                "dns": {"status": "ok", "data": {"addresses": ["192.0.2.10"]}},
                "http": {"status": "ok", "data": {"status": status, "title": "Inicio", "missing_headers": []}},
                "tls": {"status": "ok", "data": {"protocol": "TLSv1.3", "expires": expires, "days_remaining": days,
                                                 "certificate": {"serialNumber": "01"}}},
                "ports": {"status": "ok", "data": {"results": [{"port": port, "state": "open"} for port in ports]
                                                   + [{"port": 23, "state": "closed_or_filtered"}]}}}}


class OutputTests(unittest.TestCase):
    def run_main(self, argv, stdout):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app.sys, "stdout", stdout), contextlib.redirect_stderr(io.StringIO()):
            return app.main(argv + ["-o", directory])

    def test_readable_summary_at_a_terminal(self):
        out = TTY()
        self.assertEqual(self.run_main(["localhost", "-s", "rdap"], out), 0)
        text = out.getvalue()
        self.assertIn("Direcciones:", text)
        self.assertIn("--json", text)
        self.assertNotIn('"modules":', text)

    def test_json_flag_and_pretty_keep_machine_output(self):
        for flags, indented in ((["--json"], False), (["--pretty"], True), (["-j"], False)):
            out = TTY()
            self.run_main(["localhost", "-s", "rdap"] + flags, out)
            self.assertEqual(json.loads(out.getvalue())["meta"]["target"], "localhost")
            self.assertEqual("\n  " in out.getvalue(), indented, flags)

    def test_pipes_still_get_one_json_line(self):
        out = io.StringIO()
        self.run_main(["localhost", "-s", "rdap"], out)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        json.loads(out.getvalue())

    def test_open_launches_the_html_report(self):
        with patch("webbrowser.open") as browser:
            self.run_main(["localhost", "-s", "rdap", "-q", "--open"], io.StringIO())
        self.assertTrue(browser.call_args[0][0].endswith(".html"))


class HelpAndCompletionTests(unittest.TestCase):
    def test_help_is_spanish_with_examples(self):
        text = app.parser().format_help()
        for expected in ("uso: domaininfo", "ejemplos:", "--watch", "--completion", "por defecto: quick"):
            self.assertIn(expected, text)
        self.assertNotIn("show this help", text)
        self.assertNotIn("-j ", text)

    def test_completion_scripts_list_options_and_values(self):
        cli = app.parser()
        for shell in ("bash", "zsh", "powershell"):
            script = completions.script(shell, cli)
            for expected in ("--mode", "quick", "mikrotik", "--watch"):
                self.assertIn(expected, script, shell)
        self.assertIn("complete -o default -F _domaininfo domaininfo", completions.script("bash", cli))
        self.assertIn("bashcompinit", completions.script("zsh", cli))
        self.assertIn("Register-ArgumentCompleter", completions.script("powershell", cli))

    def test_completion_flag_prints_script(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(app.main(["--completion", "bash"]), 0)
        self.assertIn("_domaininfo()", out.getvalue())


class CertificateTests(unittest.TestCase):
    def summary(self, report):
        out = io.StringIO()
        InteractiveApp(app, app.parser().parse_args([]), input_fn=lambda: "", output=out).summary(report)
        return out.getvalue()

    def test_expiry_warning_levels(self):
        self.assertEqual(app.expiry_warning(-1), "expired")
        self.assertEqual(app.expiry_warning(app.CERT_WARN_DAYS), "soon")
        self.assertIsNone(app.expiry_warning(app.CERT_WARN_DAYS + 1))
        self.assertIsNone(app.expiry_warning(None))

    def test_summary_flags_expired_and_soon_certificates(self):
        self.assertIn("CADUCADO hace 3 días", self.summary(fake_report(days=-3)))
        self.assertIn("caduca en 12 días", self.summary(fake_report(days=12)))
        self.assertIn("caduca el 2027-01-01 (200 días)", self.summary(fake_report()))

    def test_expired_certificate_error_is_explained(self):
        self.assertIn("caducado", InteractiveApp.explain_error(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired"))

    def test_missing_local_root_is_not_blamed_on_the_site(self):
        text = InteractiveApp.explain_error("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                            "unable to get local issuer certificate (_ssl.c:1082)")
        self.assertIn("almacén del sistema", text)

    def test_ports_show_usual_service_and_closed_count(self):
        text = self.summary(fake_report(ports=(22, 443)))
        self.assertIn("Puertos TCP accesibles: 22 (ssh), 443 (https)", text)
        self.assertIn("Sin respuesta: 1 de 3", text)
        self.assertEqual(service_label(40000), "40000")


class WatchTests(unittest.TestCase):
    def test_watch_reports_only_changes(self):
        reports = iter([fake_report(), fake_report(), fake_report(ports=(22, 80))])
        sleeps = iter([None, None, KeyboardInterrupt()])

        def sleep(_):
            value = next(sleeps)
            if value:
                raise value

        out = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, "scan", side_effect=lambda *a, **k: next(reports)), \
                patch.object(app.time, "sleep", side_effect=sleep), \
                patch.object(app.sys, "stdout", out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(app.main(["example.com", "-q", "--watch", "5", "-o", directory]), 0)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(lines), 2)  # first full report + one change event
        self.assertEqual(lines[1]["event"], "change")
        self.assertIn("Puertos abiertos: 22 → 22, 80", lines[1]["changes"])

    def test_volatile_values_are_not_changes(self):
        before, after = app.fingerprint(fake_report(days=200)), app.fingerprint(fake_report(days=199))
        self.assertEqual(app.describe_changes(before, after), [])

    def test_watch_interval_is_bounded(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            app.parser().parse_args(["example.com", "--watch", "1"])


class UpdateTests(unittest.TestCase):
    def test_update_uses_git_in_a_clone(self):
        with patch.object(app, "latest_release", return_value="v4.3"), \
                patch.object(app.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as out:
            run.return_value.returncode = 0
            self.assertEqual(app.main(["--update"]), 0)
        self.assertEqual(run.call_args[0][0][-2:], ["pull", "--ff-only"])
        self.assertIn("última publicada: v4.3", out.getvalue())

    def test_update_without_git_explains_pipx(self):
        with patch.object(app, "latest_release", return_value=None), \
                patch.object(app.shutil, "which", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(app.self_update(), 0)
        self.assertIn("pipx upgrade domaininfo", out.getvalue())


class SingleKeyMenuTests(unittest.TestCase):
    def app(self, keys):
        out = io.StringIO()
        ui = InteractiveApp(app, app.parser().parse_args([]), input_fn=lambda: "", output=out)
        ui.instant = True
        sequence = iter(keys)
        ui.read_key = lambda: next(sequence)
        return ui, out

    def test_valid_key_without_enter(self):
        ui, out = self.app(["x", "2"])
        self.assertEqual(ui.choose({"1", "2"}), "2")
        self.assertIn("Opción no válida", out.getvalue())

    def test_enter_takes_default_and_zero_goes_back(self):
        ui, _ = self.app(["\r"])
        self.assertEqual(ui.choose({"1", "2"}, default="1"), "1")
        ui, _ = self.app(["0"])
        with self.assertRaises(Back):
            ui.choose({"1", "2"})

    def test_multi_digit_menus_keep_enter(self):
        ui, _ = self.app([])
        ui.read = lambda: "12"
        self.assertEqual(ui.choose({str(n) for n in range(1, 13)}), "12")

    def test_enter_mode_when_not_a_terminal(self):
        ui = InteractiveApp(app, app.parser().parse_args([]), input_fn=lambda: "1", output=io.StringIO())
        self.assertFalse(ui.instant)


if __name__ == "__main__":
    unittest.main()
