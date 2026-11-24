"""Phase 3: external tool runners, vulnerability intelligence and attack-surface inventory.

No network and no real external tools: subprocess and HTTP are mocked. The only real processes are
short Python children used to check timeouts, cancellation, output caps and process-tree killing.
"""

import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import i18n  # noqa: E402
import inventory  # noqa: E402
import runners  # noqa: E402
import vulnintel  # noqa: E402

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV">
<host><status state="up"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<hostnames><hostname name="www.example.com" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.1" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.18.0" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe>
</service></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/></port>
</ports></host>
<runstats><finished exit="success"/></runstats>
</nmaprun>"""

NUCLEI_JSONL = b"\n".join(json.dumps(row).encode() for row in (
    {"template-id": "CVE-2021-41773", "host": "https://www.example.com", "matched-at": "https://www.example.com/cgi-bin/",
     "matcher-name": "status",
     "info": {"name": "Apache 2.4.49 Path Traversal", "severity": "critical", "reference": ["https://httpd.apache.org/"],
              "classification": {"cve-id": ["cve-2021-41773"], "cwe-id": ["cwe-22"], "cvss-score": 7.5}}},
    {"template-id": "tech-detect", "host": "https://www.example.com", "matched-at": "https://www.example.com/",
     "info": {"name": "Wappalyzer Technology Detection", "severity": "info"}},
)) + b"\nnot json\n"

OSV_RESPONSE = {"vulns": [{
    "id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2023-0001"], "summary": "Request smuggling",
    "modified": "2024-01-02T00:00:00Z", "published": "2023-05-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"cwe_ids": ["CWE-444"], "severity": "CRITICAL"},
    "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"}]}]}


def _nvd_item(cve_id, criteria, kev=False, **ranges):
    return {"cve": {
        "id": cve_id, "lastModified": "2024-03-01T00:00:00.000", "published": "2022-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3, "vectorString": "CVSS:3.1/AV:N/..."}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-20"}]}],
        "references": [{"url": f"https://example.org/{cve_id}"}],
        **({"cisaExploitAdd": "2023-01-01"} if kev else {}),
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria, **ranges}]}]}]}}


NVD_RESPONSE = {"vulnerabilities": [
    _nvd_item("CVE-2021-0001", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.3"),
    _nvd_item("CVE-2021-0002", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="8.0"),
]}
KEV_RESPONSE = {"vulnerabilities": [{"cveID": "CVE-2021-0001", "dateAdded": "2024-02-02"},
                                    {"cveID": "CVE-2023-0001", "dateAdded": "2024-02-03"}]}

AVAILABLE = {"available": True, "path": "/opt/tools/fake", "version": "9.9", "compatible": True, "minimum": "1.0",
             "install": "hint"}


def fake_execute(payload, returncode=0, **flags):
    """Stand-in for runners.execute that writes ``payload`` into the tool's output file."""
    calls = []

    def run(argv, timeout=0, cancel=None, cwd=None, **_):
        calls.append(list(argv))
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        target = next((a.split("=", 1)[-1] for a in argv if cwd and cwd in a and "names.txt" not in a), None)
        if target and payload is not None:
            with open(target, "wb") as handle:
                handle.write(payload)
        return {"returncode": returncode, "stdout": "", "stderr": "", "timed_out": False, "cancelled": False,
                "truncated": False, "duration": 0.01, **flags}
    run.calls = calls
    return run


def _alive(pid):
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:  # a zombie still answers to signal 0
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().split()[2] != "Z"
    except OSError:
        return True


class ValidationTests(unittest.TestCase):
    def test_injection_targets_are_rejected(self):
        for bad in ("-oN /tmp/x", "example.com;rm", "example.com;rm -rf /", "$(id).example.com", "`id`",
                    "--script=vuln", "a b.com", "example.com\n-p1", "", "exa mple.com", "example.com|nc"):
            with self.subTest(bad=bad), self.assertRaises(runners.TargetError):
                runners.validate_host(bad)

    def test_valid_hosts(self):
        self.assertEqual(runners.validate_host("WWW.Example.COM."), "www.example.com")
        self.assertEqual(runners.validate_host("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(runners.validate_host("192.0.2.1"), "192.0.2.1")

    def test_run_never_executes_invalid_targets(self):
        with patch.object(runners, "execute") as execute, patch("tools.detect", return_value=AVAILABLE):
            for tool, bad in (("nmap", "-oN /tmp/x"), ("nuclei", "example.com;rm"), ("subfinder", "-d x"),
                              ("whatweb", "javascript:alert(1)"), ("bandit", "/no/such/path/xyz"),
                              ("sslyze", "example.com --help")):
                result = runners.run(tool, bad, allow_active=True, scope=["example.com"])
                self.assertEqual(result["status"], "error", tool)
                self.assertEqual(result["reason"], "invalid_input", tool)
            execute.assert_not_called()

    def test_option_injection_is_rejected(self):
        with patch.object(runners, "execute") as execute, patch("tools.detect", return_value=AVAILABLE):
            bad = runners.run("nmap", "example.com", {"ports": "80 -oN /tmp/x"}, True, ["example.com"])
            self.assertEqual(bad["reason"], "invalid_input")
            bad = runners.run("nmap", "example.com", {"ports": "70000"}, True, ["example.com"])
            self.assertEqual(bad["reason"], "invalid_input")
            for tag in ("dos", "intrusive", "fuzz", "-itags x"):
                bad = runners.run("nuclei", "https://example.com", {"tags": [tag]}, True, ["example.com"])
                self.assertEqual(bad["reason"], "invalid_input", tag)
            bad = runners.run("dnsx", "example.com", {"names": ["evil.org"]})
            self.assertEqual(bad["reason"], "invalid_input")
            bad = runners.run("semgrep", os.getcwd(), {"config": "--dangerous"})
            self.assertEqual(bad["reason"], "invalid_input")
            execute.assert_not_called()

    def test_unknown_tool(self):
        self.assertEqual(runners.run("rm", "example.com")["reason"], "unknown_tool")


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.execute = patch.object(runners, "execute", side_effect=AssertionError("must not run")).start()
        patch("tools.detect", return_value=AVAILABLE).start()
        self.addCleanup(patch.stopall)

    def test_active_tools_refused_without_authorization(self):
        for tool, target in (("nmap", "example.com"), ("nuclei", "https://example.com/"), ("sslyze", "example.com"),
                             ("testssl.sh", "example.com"), ("httpx", "example.com")):
            result = runners.run(tool, target, scope=["example.com"])
            self.assertEqual((result["status"], result["reason"]), ("skipped", "not_authorized"), tool)
            self.assertTrue(result["active"])

    def test_active_tools_refused_out_of_scope(self):
        cases = (("example.com", None), ("example.com", []), ("example.com", ["*.example.com"]),
                 ("evil.com", ["example.com"]), ("example.com.evil.com", ["example.com"]),
                 ("www.example.com", ["192.0.2.0/24"]), ("198.51.100.7", ["192.0.2.0/24"]))
        for target, scope in cases:
            result = runners.run("nmap", target, allow_active=True, scope=scope)
            self.assertEqual(result["reason"], "out_of_scope", (target, scope))

    def test_dnsx_bruteforce_is_active(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("www\n")
        self.addCleanup(os.unlink, handle.name)
        self.assertTrue(runners.is_active("dnsx", {"wordlist": handle.name}))
        self.assertFalse(runners.is_active("dnsx", {}))
        result = runners.run("dnsx", "example.com", {"wordlist": handle.name})
        self.assertEqual(result["reason"], "not_authorized")

    def test_scope_matching(self):
        self.assertTrue(runners.in_scope("www.example.com", ["*.example.com"]))
        self.assertTrue(runners.in_scope("192.0.2.10", ["192.0.2.0/24"]))
        self.assertTrue(runners.in_scope("2001:db8::5", ["2001:db8::/64"]))
        self.assertFalse(runners.in_scope("example.com", ["*.example.com"]))
        with self.assertRaises(runners.TargetError):
            runners.in_scope("example.com", ["exa mple.com"])

    def test_cancel_before_start(self):
        cancel = threading.Event()
        cancel.set()
        result = runners.run("subfinder", "example.com", cancel=cancel)
        self.assertEqual(result["reason"], "cancelled")

    def test_missing_tool_gives_install_hint(self):
        with patch("tools.detect", return_value={"available": False, "install": "go install x", "minimum": "2.6"}):
            result = runners.run("subfinder", "example.com")
        self.assertEqual((result["status"], result["reason"]), ("skipped", "unavailable"))
        self.assertIn("go install x", result["errors"][0]["message"])
        self.assertEqual(result["install"], "go install x")

    def test_incompatible_version_skipped(self):
        with patch("tools.detect", return_value={**AVAILABLE, "version": "0.1", "compatible": False}):
            self.assertEqual(runners.run("subfinder", "example.com")["reason"], "incompatible")


class RunnerFlowTests(unittest.TestCase):
    def setUp(self):
        patch("tools.detect", return_value=AVAILABLE).start()
        self.addCleanup(patch.stopall)

    def test_nmap_authorized_flow(self):
        fake = fake_execute(NMAP_XML)
        with patch.object(runners, "execute", fake):
            result = runners.run("nmap", "www.example.com", {"ports": "22,80,8080,25"}, True, ["*.example.com"])
        self.assertEqual(result["status"], "ok", result["errors"])
        argv = fake.calls[0]
        self.assertEqual(argv[-1], "www.example.com")
        self.assertIn("-sT", argv)
        self.assertIn("-sV", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "22,80,8080,25")
        self.assertEqual(result["findings"], [], "an open port is not a vulnerability")
        ports = sorted(a["port"] for a in result["assets"] if a["type"] == "port")
        self.assertEqual(ports, [22, 80, 8080])
        ssh = next(c for c in result["components"] if c["name"] == "OpenSSH")
        self.assertEqual(ssh["version"], "8.9p1")
        self.assertEqual(ssh["cpe"], "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
        self.assertEqual(ssh["evidence"], "heuristic", "distro banners may carry backported fixes")
        nginx = next(c for c in result["components"] if c["name"] == "nginx")
        self.assertEqual(nginx["cpe"], "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*")
        self.assertEqual(nginx["evidence"], "direct")
        self.assertEqual(result["coverage"]["state"], "complete")
        self.assertTrue(all("<tmp>" in a or "domaininfo-" not in a for a in result["command"]))

    def test_nmap_rejects_entities(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
        with self.assertRaises(ValueError):
            runners.parse_nmap_xml(evil, "example.com")

    def test_nuclei_flow_and_safe_flags(self):
        fake = fake_execute(NUCLEI_JSONL)
        with patch.object(runners, "execute", fake):
            result = runners.run("nuclei", "https://www.example.com/", {"tags": "cve,misconfig", "rate": 5}, True,
                                 ["www.example.com"])
        argv = fake.calls[0]
        self.assertEqual(argv[argv.index("-rl") + 1], "5")
        banned = argv[argv.index("-etags") + 1].split(",")
        for tag in ("intrusive", "dos", "fuzz"):
            self.assertIn(tag, banned)
        self.assertIn("-no-interactsh", argv)
        self.assertEqual(argv[argv.index("-tags") + 1], "cve,misconfig")
        high = next(f for f in result["findings"] if f["severity"] == "high")
        self.assertEqual(high["status"], "likely")
        self.assertIn("CVE-2021-41773", high["evidence"])
        self.assertTrue(high["id"].startswith("DI-") and len(high["id"]) == 13)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-41773", high["references"])
        info = next(f for f in result["findings"] if f["severity"] == "info")
        self.assertEqual(info["status"], "informational")
        self.assertEqual(result["coverage"]["state"], "partial")  # one malformed line

    def test_timeout_reported_as_error(self):
        fake = fake_execute(None, returncode=None, timed_out=True)
        with patch.object(runners, "execute", fake):
            result = runners.run("subfinder", "example.com", {"timeout": 5})
        self.assertEqual((result["status"], result["reason"]), ("error", "timeout"))

    def test_partial_output_after_timeout_is_kept(self):
        rows = b'{"host":"a.example.com","source":"crtsh"}\n{"host":"evil.org"}\n'
        with patch.object(runners, "execute", fake_execute(rows, timed_out=True)):
            result = runners.run("subfinder", "example.com", {"timeout": 5})
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual([a["value"] for a in result["assets"]], ["a.example.com"])
        self.assertEqual(result["coverage"]["state"], "partial")

    def test_exec_failure_is_explicit(self):
        with patch.object(runners, "execute", side_effect=FileNotFoundError("missing")):
            result = runners.run("subfinder", "example.com")
        self.assertEqual(result["reason"], "exec_failed")

    def test_temp_dir_removed(self):
        seen = []

        def spy(argv, cwd=None, **_):
            seen.append(cwd)
            return fake_execute(b"[]")(argv, cwd=cwd)
        with tempfile.TemporaryDirectory() as folder, patch.object(runners, "execute", spy):
            runners.run("gitleaks", folder)
        self.assertFalse(os.path.exists(seen[0]))

    def test_dnsx_names_file(self):
        fake = fake_execute(b'{"host":"www.example.com","a":["192.0.2.1"],"cname":["x.cdn.net"]}\n')
        with patch.object(runners, "execute", fake):
            result = runners.run("dnsx", "example.com", {"names": ["www.example.com"]})
        self.assertEqual(result["status"], "ok")
        self.assertIn("-l", fake.calls[0])
        self.assertIn({"type": "ip", "value": "192.0.2.1", "host": "www.example.com"}, result["assets"])


class ParserTests(unittest.TestCase):
    def test_sslyze(self):
        doc = {"server_scan_results": [{"server_location": {"hostname": "example.com", "port": 443},
                                        "scan_result": {
                                            "tls_1_0_cipher_suites": {"result": {"accepted_cipher_suites": [{}, {}]}},
                                            "tls_1_2_cipher_suites": {"result": {"accepted_cipher_suites": [{}]}},
                                            "heartbleed": {"result": {"is_vulnerable_to_heartbleed": False}},
                                            "robot": {"result": {"robot_result": "VULNERABLE_STRONG_ORACLE"}}}}]}
        findings = runners.parse_sslyze(json.dumps(doc).encode(), "example.com")[0]
        titles = [f["title"] for f in findings]
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("TLS 1.0" in t for t in titles))
        self.assertTrue(any("ROBOT" in t for t in titles))

    def test_testssl(self):
        rows = [{"id": "SSLv3", "ip": "example.com/93.184.216.34", "port": "443", "severity": "HIGH",
                 "finding": "offered", "cve": "CVE-2014-3566"},
                {"id": "TLS1_3", "severity": "OK", "finding": "offered"}]
        findings = runners.parse_testssl(json.dumps(rows).encode(), "example.com")[0]
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]["severity"], findings[0]["status"]), ("high", "likely"))

    def test_gitleaks_never_copies_secret(self):
        rows = [{"RuleID": "aws-access-key", "File": "app/settings.py", "StartLine": 3,
                 "Secret": "AKIAABCDEFGHIJKLMNOP", "Match": "key=AKIAABCDEFGHIJKLMNOP", "Commit": "abc"}]
        finding = runners.parse_gitleaks(json.dumps(rows).encode(), "/repo")[0][0]
        self.assertNotIn("AKIA", json.dumps(finding))
        self.assertEqual(finding["path"], "app/settings.py:3")

    def test_trivy_and_pip_audit(self):
        trivy = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-0001", "PkgName": "requests", "InstalledVersion": "2.0.0",
             "FixedVersion": "2.31.0", "Severity": "CRITICAL", "PrimaryURL": "https://avd.aquasec.com/x"}],
            "Secrets": [{"RuleID": "github-pat", "StartLine": 9, "Severity": "HIGH", "Match": "ghp_secret"}]}]}
        findings, _, components, _ = runners.parse_trivy(json.dumps(trivy).encode(), "/repo")
        self.assertEqual(components[0]["evidence"], "direct")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertNotIn("ghp_secret", json.dumps(findings))
        audit = {"dependencies": [{"name": "jinja2", "version": "2.10", "vulns": [
            {"id": "PYSEC-2019-1", "aliases": ["CVE-2019-10906"], "fix_versions": ["2.10.1"]}]},
            {"name": "local-pkg", "skip_reason": "not on PyPI"}]}
        findings, _, components, _ = runners.parse_pip_audit(json.dumps(audit).encode(), "req.txt")
        self.assertEqual(findings[0]["status"], "confirmed")
        self.assertEqual(components[0]["ecosystem"], "PyPI")

    def test_semgrep_and_bandit(self):
        semgrep = {"results": [{"check_id": "python.lang.security.eval", "path": "a.py", "start": {"line": 4},
                                "extra": {"severity": "ERROR", "message": "eval use",
                                          "metadata": {"confidence": "HIGH", "cwe": ["CWE-95"]}}}]}
        finding = runners.parse_semgrep(json.dumps(semgrep).encode(), "/src")[0][0]
        self.assertEqual((finding["severity"], finding["confidence"], finding["status"]), ("high", "high", "likely"))
        bandit = {"results": [{"filename": "a.py", "line_number": 2, "test_id": "B602", "test_name": "shell_true",
                               "issue_text": "shell=True", "issue_severity": "HIGH", "issue_confidence": "MEDIUM",
                               "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"}}]}
        finding = runners.parse_bandit(json.dumps(bandit).encode(), "/src")[0][0]
        self.assertIn("CWE-78", finding["evidence"])

    def test_whatweb_and_httpx(self):
        whatweb = [{"target": "https://example.com/", "http_status": 200,
                    "plugins": {"nginx": {"version": ["1.18.0"]}, "HTML5": {}}}]
        _, assets, components, _ = runners.parse_whatweb(json.dumps(whatweb).encode(), "https://example.com/")
        self.assertEqual(components, [{"name": "nginx", "version": "1.18.0", "evidence": "direct",
                                       "source": "whatweb", "location": "https://example.com/"}])
        httpx = b'{"url":"https://example.com","input":"example.com","status_code":200,"host":"192.0.2.1",' \
                b'"tech":["Nginx:1.18.0","HSTS"]}\n'
        _, assets, components, _ = runners.parse_httpx(httpx, "example.com")
        self.assertEqual(components[0]["evidence"], "heuristic")
        self.assertIn({"type": "ip", "value": "192.0.2.1", "host": "example.com"}, assets)

    def test_cpe_conversion(self):
        self.assertIsNone(runners.cpe23("cpe:/a:vendor:product"))
        self.assertIsNone(runners.cpe23("cpe:/a:ven dor:product:1.0"))
        self.assertEqual(runners.cpe23("cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"), "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*")


class ExecuteTests(unittest.TestCase):
    def test_timeout_kills_process(self):
        start = time.monotonic()
        result = runners.execute([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)
        self.assertTrue(result["timed_out"])
        self.assertLess(time.monotonic() - start, 20)

    def test_cancellation(self):
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        result = runners.execute([sys.executable, "-c", "import time; time.sleep(60)"], timeout=60, cancel=cancel)
        self.assertTrue(result["cancelled"])
        self.assertFalse(result["timed_out"])

    def test_output_cap(self):
        code = "import sys; sys.stdout.write('x' * 200000)"
        result = runners.execute([sys.executable, "-c", code], timeout=30, max_output=1000)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), 1000)
        self.assertEqual(result["returncode"], 0)

    def test_kills_process_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = os.path.join(folder, "pid")
            child = ("import subprocess, sys, time\n"
                     "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                     f"open({pidfile!r}, 'w').write(str(p.pid))\n"
                     "time.sleep(60)\n")
            result = runners.execute([sys.executable, "-c", child], timeout=3)
            self.assertTrue(result["timed_out"])
            with open(pidfile) as handle:
                grandchild = int(handle.read())
            deadline = time.monotonic() + 5
            while _alive(grandchild) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertFalse(_alive(grandchild))

    def test_argv_must_be_a_list(self):
        with self.assertRaises(TypeError):
            runners.execute("nmap example.com")  # type: ignore[arg-type]
        with patch("subprocess.Popen", side_effect=AssertionError) as popen:
            with self.assertRaises(TypeError):
                runners.execute([sys.executable, 3])  # type: ignore[list-item]
            popen.assert_not_called()

    def test_no_shell(self):
        with patch("subprocess.Popen", side_effect=OSError("stop")) as popen:
            with self.assertRaises(OSError):
                runners.execute(["tool", "a;b"])
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertEqual(popen.call_args.args[0], ["tool", "a;b"])


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class VulnIntelTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.clock = FakeClock()
        self.cache = vulnintel.Cache(self.folder.name, clock=self.clock)
        self.requests = []

    def fetch(self, url, body, headers, timeout, limit):
        self.requests.append((url, body, headers))
        if url == vulnintel.OSV_URL:
            return OSV_RESPONSE if body["version"] == "2.0.0" else {}
        if url.startswith(vulnintel.NVD_URL):
            return NVD_RESPONSE if "cpeName" in url else {"vulnerabilities": [
                _nvd_item("CVE-2020-9999", "cpe:2.3:a:x:widget:*:*:*:*:*:*:*:*")]}
        if url == vulnintel.KEV_URL:
            return KEV_RESPONSE
        raise AssertionError(url)

    def client(self, **kwargs):
        limiter = vulnintel.RateLimiter(5, 30, clock=self.clock, sleep=self.clock.sleep)
        return vulnintel.Client(cache=self.cache, fetch=self.fetch, api_key="", limiter=limiter, **kwargs)

    def test_cache_ttl(self):
        entry = self.cache.put("osv", "k", {"a": 1})
        self.assertIn("fetched_at", entry)
        self.assertEqual(self.cache.get("osv", "k", 60)["data"], {"a": 1})
        self.clock.now += 61
        self.assertIsNone(self.cache.get("osv", "k", 60))

    def test_client_uses_cache(self):
        client = self.client()
        client.osv("requests", "PyPI", "2.0.0")
        data, fetched_at = client.osv("requests", "PyPI", "2.0.0")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(data, OSV_RESPONSE)
        self.assertTrue(fetched_at.endswith("+00:00"))
        self.assertEqual(client.sources["osv"]["cached"], 1)
        self.clock.now += vulnintel.TTL["osv"] + 1
        client.osv("requests", "PyPI", "2.0.0")
        self.assertEqual(len(self.requests), 2)

    def test_offline_without_cache(self):
        client = self.client(offline=True)
        with self.assertRaises(vulnintel.SourceError):
            client.osv("requests", "PyPI", "2.0.0")
        self.assertEqual(self.requests, [])

    def test_rate_limiter(self):
        limiter = vulnintel.RateLimiter(5, 30, clock=self.clock, sleep=self.clock.sleep)
        start = self.clock.now
        for _ in range(5):
            limiter.acquire()
        self.assertEqual(self.clock.now, start)
        limiter.acquire()
        self.assertGreaterEqual(self.clock.now - start, 30)
        self.assertEqual(vulnintel.NVD_CALLS, {False: 5, True: 50})

    def test_nvd_rate_limit_applies_to_requests(self):
        client = self.client()
        start = self.clock.now
        for index in range(6):
            client.nvd_keyword(f"widget {index}")
        self.assertGreaterEqual(self.clock.now - start, 30)

    def test_api_key_header(self):
        client = vulnintel.Client(cache=self.cache, fetch=self.fetch, api_key="k" * 8,
                                  limiter=vulnintel.RateLimiter(50, 30, clock=self.clock, sleep=self.clock.sleep))
        client.nvd_cpe("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
        self.assertEqual(self.requests[0][2], {"apiKey": "k" * 8})

    def test_endpoint_allowlist(self):
        with self.assertRaises(vulnintel.SourceError):
            vulnintel._http("https://evil.example/v1/query")

    def test_cvss(self):
        self.assertEqual(vulnintel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(vulnintel.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(vulnintel.cvss3_score("garbage"))

    def test_version_ranges(self):
        self.assertTrue(vulnintel.version_in_range("8.9p1", end_excl="9.3"))
        self.assertFalse(vulnintel.version_in_range("8.9p1", end_excl="8.0"))
        self.assertTrue(vulnintel.version_in_range("1.10", start_incl="1.9", end_incl="1.10"))
        self.assertFalse(vulnintel.version_in_range("1.0", exact="*"))

    def test_correlation_statuses(self):
        components = [
            {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI", "evidence": "direct"},
            {"name": "OpenSSH", "version": "8.9p1", "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
             "evidence": "heuristic"},
            {"name": "widget", "version": "3.1"},
            {"name": "", "version": "1"},
            {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI", "evidence": "direct"},
        ]
        result = vulnintel.correlate(components, client=self.client(), target="example.com")
        by_id = {m["vuln_id"]: m for m in result["matches"]}
        osv = by_id["CVE-2023-0001"]
        self.assertEqual((osv["match_type"], osv["status"]), ("exact", "confirmed"))
        self.assertIn("GHSA-xxxx-yyyy-zzzz", osv["aliases"])
        self.assertEqual(osv["cvss"]["score"], 9.8)
        self.assertTrue(osv["kev"])
        self.assertEqual(osv["cwe"], ["CWE-444"])
        self.assertEqual(osv["updated_at"], "2024-01-02T00:00:00Z")
        ssh = by_id["CVE-2021-0001"]
        self.assertEqual((ssh["match_type"], ssh["status"]), ("exact", "likely"))
        self.assertTrue(ssh["kev"])
        self.assertEqual(ssh["severity"], "high")
        self.assertEqual(by_id["CVE-2021-0002"]["match_type"], "name_only")
        self.assertEqual(by_id["CVE-2021-0002"]["status"], "pending")
        self.assertEqual(by_id["CVE-2021-0002"]["severity"], "medium")
        keyword = by_id["CVE-2020-9999"]
        self.assertEqual((keyword["match_type"], keyword["status"]), ("keyword", "pending"))
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(sum(1 for r in self.requests if r[0] == vulnintel.OSV_URL), 1)
        statuses = {f["title"]: f["status"] for f in result["findings"]}
        self.assertNotIn("confirmed", [statuses[t] for t in statuses if "widget" in t])
        self.assertTrue(all(f["category"] == "vulnerable_component" for f in result["findings"]))
        self.assertIn("kev", result["sources"])

    def test_heuristic_osv_version_is_only_likely(self):
        result = vulnintel.correlate([{"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"}],
                                     client=self.client(), use_kev=False)
        self.assertEqual(result["matches"][0]["status"], "likely")

    def test_source_errors_do_not_raise(self):
        def broken(*_):
            raise vulnintel.SourceError("down")
        client = vulnintel.Client(cache=self.cache, fetch=broken, api_key="",
                                  limiter=vulnintel.RateLimiter(5, 30, clock=self.clock, sleep=self.clock.sleep))
        result = vulnintel.correlate([{"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"}], client=client)
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["errors"][0]["source"], "osv")

    def test_cache_dir(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "C:\\x", "XDG_CACHE_HOME": "xdg-cache"}):
            path = vulnintel.cache_dir()
        self.assertEqual(path.name, "vulnintel")


def _report(target, **modules):
    return {"meta": {"target": target}, "modules": {k: {"status": "ok", "data": v} for k, v in modules.items()}}


class InventoryTests(unittest.TestCase):
    def test_dedup_and_sources(self):
        finding = runners.make_finding("https://example.com/", "headers", "Missing CSP", "low", "confirmed")
        first = _report(
            "example.com",
            dns={"addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
                 "records": {"NS": ["a.iana-servers.net."], "MX": ["10 mail.example.com."]}},
            asn={"networks": [{"ip": "93.184.216.34", "asn": "15133", "as_name": "EDGECAST", "prefix": "93.184.216.0/24"}]},
            tls={"subject": "www.example.org", "issuer": "DigiCert", "serial": "0A", "san": ["example.com",
                                                                                         "www.example.com", "*.example.com"]},
            ports={"protocol": "tcp", "results": [{"port": 443, "state": "open", "address": "93.184.216.34"},
                                                   {"port": 22, "state": "closed_or_filtered"}]},
            tech={"url": "https://example.com/", "technologies": [{"name": "nginx", "category": "server"}],
                  "generator": "WordPress 6.4.2", "headers_grade": {"version_leaks": ["server: nginx/1.18.0"]}},
            subdomains={"alive": [{"name": "www.example.com", "addresses": ["93.184.216.34"], "cname": None}],
                        "unresolved": ["old.example.com"]},
            webapp={"url": "https://example.com/login", "final_url": "https://example.com/login",
                    "forms": [{"action": "/session"}, {"action": "https://evil.org/steal"}], "findings": [finding],
                    "apis": [{"url": "/openapi.json", "title": "API"}]},
            history={"registrar": "RESERVED-IANA"})
        first["runners"] = [{"tool": "nmap", "assets": [
            {"type": "port", "host": "example.com", "address": "93.184.216.34", "port": 443, "protocol": "tcp",
             "service": "https", "product": "nginx", "version": "1.18.0"}],
            "components": [{"name": "nginx", "version": "1.18.0", "evidence": "direct", "location": "example.com:443"}],
            "findings": []}]
        second = _report("example.com", dns={"addresses": ["93.184.216.34"]},
                         webapp={"url": "https://example.com/login", "findings": [finding]})
        inv = inventory.build([first, second], scope=["api.partner.net"])
        ipv4 = {e["value"]: e for e in inv["ipv4"]}
        self.assertEqual(sorted(ipv4["93.184.216.34"]["sources"]), ["asn", "dns", "nmap", "ports", "subdomains"])
        self.assertEqual(len(inv["ipv6"]), 1)
        self.assertEqual(len(inv["ports"]), 1, "closed ports are not assets; same port from two sources is one")
        self.assertEqual(sorted(inv["ports"][0]["sources"]), ["nmap", "ports"])
        self.assertEqual(inv["services"][0]["product"], "nginx")
        self.assertEqual(len(inv["findings"]), 1, "the same finding id from two reports is one finding")
        self.assertEqual(inv["findings"][0]["sources"], ["webapp"])
        nginx = [c for c in inv["components"] if c["name"] == "nginx"]
        self.assertEqual(len(nginx), 1)
        self.assertEqual(sorted(nginx[0]["sources"]), ["nmap", "tech"])
        self.assertIn("WordPress", [c["name"] for c in inv["components"]])
        subs = {e["value"] for e in inv["subdomains"]}
        self.assertEqual(subs, {"www.example.com", "old.example.com", "mail.example.com"})
        self.assertEqual([e["value"] for e in inv["dns_servers"]], ["a.iana-servers.net"])
        self.assertEqual(inv["asns"][0]["asn"], "15133")
        self.assertEqual(len(inv["certificates"]), 1)
        paths = {e["url"] for e in inv["paths"]}
        self.assertIn("https://example.com/session", paths)
        self.assertNotIn("https://evil.org/steal", paths)
        self.assertEqual(inv["summary"]["out_of_scope_paths"], 1)
        self.assertEqual(inv["apis"][0]["url"], "https://example.com/openapi.json")
        self.assertEqual(inv["domains"][0]["registrar"], "RESERVED-IANA")
        self.assertEqual(inv["summary"]["targets"], 2)
        self.assertFalse(any(f.get("category") == "ports" for f in inv["findings"]))

    def test_single_report_and_failed_modules(self):
        report = {"meta": {"target": "192.0.2.5"}, "modules": {"dns": {"status": "error", "error": "x"}}}
        inv = inventory.build(report)
        self.assertEqual([e["value"] for e in inv["ipv4"]], ["192.0.2.5"])
        self.assertEqual(inv["findings"], [])


class I18nPhase3Tests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en")

    def test_spanish_messages(self):
        i18n.set_language("es")
        result = runners.run("nmap", "example.com")
        self.assertIn("autorizaci", result["errors"][0]["message"])
        self.assertEqual(i18n.catalog_problems("es"), [])


if __name__ == "__main__":
    unittest.main()
