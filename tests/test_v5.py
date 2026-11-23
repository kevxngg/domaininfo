"""Offline tests for the version 5 functions."""

import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dnsclient  # noqa: E402
import domaininfo as app  # noqa: E402
import history  # noqa: E402
import i18n  # noqa: E402
import infra  # noqa: E402
import lookalike  # noqa: E402
import mailsec  # noqa: E402
import recon  # noqa: E402
import render  # noqa: E402
import score  # noqa: E402
import webtech  # noqa: E402


def response(qid, answers):
    """DNS response with one question for example.com and records that compress the name."""
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, len(answers), 0, 0)
    question = dnsclient.encode_name("example.com") + struct.pack(">HH", 15, 1)
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + body


class DNSClientTests(unittest.TestCase):
    def test_query_has_question_and_edns(self):
        qid, packet = dnsclient.build_query("example.com", "MX", qid=7)
        self.assertEqual(qid, 7)
        self.assertEqual(struct.unpack(">H", packet[:2])[0], 7)
        self.assertIn(b"\x07example\x03com\x00", packet)
        self.assertEqual(struct.unpack(">H", packet[10:12])[0], 1)  # OPT

    def test_parse_mx_txt_with_compression(self):
        mx = struct.pack(">H", 10) + b"\x04mail\xc0\x0c"
        txt = b"\x07v=spf1 " + b"\x04-all"
        parsed = dnsclient.parse_response(response(9, [(15, mx), (16, txt)]), 9)
        self.assertEqual(parsed["rcode"], "NOERROR")
        self.assertEqual(parsed["answers"][0]["value"], {"priority": 10, "host": "mail.example.com"})
        self.assertEqual(parsed["answers"][1]["value"], "v=spf1 -all")

    def test_wrong_id_rejected(self):
        with self.assertRaises(dnsclient.DNSError):
            dnsclient.parse_response(response(1, []), 2)

    def test_pointer_loop_detected(self):
        msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(dnsclient.DNSError):
            dnsclient.parse_response(msg, 1)

    def test_resolver_env(self):
        with patch.dict("os.environ", {"DOMAININFO_RESOLVER": "9.9.9.9, 1.1.1.1"}):
            self.assertEqual(dnsclient.system_resolvers(), ["9.9.9.9", "1.1.1.1"])


class MailTests(unittest.TestCase):
    def test_spf_strict(self):
        spf = mailsec.analyze_spf(["v=spf1 include:_spf.google.com -all"])
        self.assertEqual(spf["all"], "fail")
        self.assertEqual(spf["issues"], [])

    def test_spf_problems(self):
        self.assertFalse(mailsec.analyze_spf(["google-site-verification=x"])["present"])
        self.assertIn("'+all'", " ".join(mailsec.analyze_spf(["v=spf1 +all"])["issues"]))
        many = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all"
        self.assertIn("maximum 10", " ".join(mailsec.analyze_spf([many])["issues"]))

    def test_dmarc(self):
        dmarc = mailsec.analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
        self.assertEqual(dmarc["policy"], "reject")
        self.assertEqual(dmarc["issues"], [])
        self.assertIn("p=none", " ".join(mailsec.analyze_dmarc(["v=DMARC1; p=none"])["issues"]))

    def test_grade_and_spoofable(self):
        strict = mailsec.analyze_spf(["v=spf1 -all"])
        reject = mailsec.analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.c"])
        none = mailsec.analyze_dmarc(["v=DMARC1; p=none"])
        self.assertEqual(mailsec.grade(strict, reject, True, {"mode": "enforce"}, True), ("A", False))
        self.assertEqual(mailsec.grade(strict, none, True, {}, True), ("C", True))
        self.assertEqual(mailsec.grade({"present": False}, {"present": False}, False, {}, True), ("F", True))


class WebTests(unittest.TestCase):
    def test_murmur3_vectors(self):
        self.assertEqual(webtech.murmur3_32(b"foo"), -156908512)
        self.assertEqual(webtech.murmur3_32(b"hello"), 613153351)
        self.assertEqual(webtech.murmur3_32(b""), 0)

    def test_headers_grade(self):
        good = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()"}
        self.assertEqual(webtech.grade_headers(good, True)["grade"], "A")
        bad = webtech.grade_headers({"server": "Apache/2.4.1"}, True)
        self.assertEqual(bad["grade"], "F")
        self.assertTrue(bad["version_leaks"])
        states = {check["id"]: check["state"] for check in bad["checks"]}
        self.assertEqual(states["hsts"], "missing")
        self.assertEqual(states["version"], "warning")

    def test_detect(self):
        found, generator = webtech.detect({"server": "nginx", "cf-ray": "1"},
                                          '<meta name="generator" content="WordPress 6.5"><link href="/wp-content/x.css">')
        names = {item["name"] for item in found}
        self.assertTrue({"Nginx", "Cloudflare", "WordPress"} <= names)
        self.assertEqual(generator, "WordPress 6.5")

    def test_cookies(self):
        rows = webtech.analyze_cookies(["sid=1; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"], True)
        self.assertEqual(rows[0]["issues"], ["no Secure", "no HttpOnly", "no SameSite"])
        self.assertEqual(rows[1]["issues"], [])


class ReconTests(unittest.TestCase):
    def test_takeover_matching(self):
        self.assertEqual(recon.takeover_service("user.github.io.")[0], "GitHub Pages")
        self.assertEqual(recon.takeover_service("b.s3-website-us-east-1.amazonaws.com")[0], "Amazon S3")
        self.assertIsNone(recon.takeover_service("notgithub.io")[0])

    def test_clean_names(self):
        names = recon.clean(["*.example.com\nwww.example.com", "evil.com", "a.b.example.com", "example.com"], "example.com")
        self.assertEqual(names, ["a.b.example.com", "www.example.com"])

    def test_lookalike_generation(self):
        variants = dict(lookalike.generate("python.org"))
        self.assertNotIn("python.org", variants)
        self.assertEqual(variants.get("pyhton.org"), "transposition")
        self.assertEqual(variants.get("pyth0n.org"), "homoglyph")
        self.assertEqual(variants.get("python.com"), "other TLD")
        self.assertEqual(variants.get("pyton.org"), "omission")
        self.assertEqual(variants.get("py-thon.org"), "hyphenation")
        self.assertEqual(lookalike.split("tienda.com.co"), ("tienda", "com.co"))

    def test_history_from_rdap(self):
        rdap = {"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                           {"eventAction": "expiration", "eventDate": "2099-01-01T00:00:00Z"}],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}]}
        result = history.from_rdap(rdap)
        self.assertEqual(result["registered"], "2000-01-01")
        self.assertEqual(result["registrar"], "Example Registrar")
        self.assertFalse(result["new_domain"])


def sample_report(target="example.com", ip="203.0.113.5"):
    return {"meta": {"target": target, "mode": "full", "version": app.VERSION, "date": "today"},
            "modules": {
                "dns": {"status": "ok", "data": {"addresses": [ip], "dnssec": False,
                                                 "records": {"NS": ["ns1.dns.test"], "MX": [], "CAA": []}}},
                "tls": {"status": "ok", "data": {"verified": True, "days_remaining": 10, "serial": "AB",
                                                 "issuer": "CA", "versions": {"TLSv1.0": True, "TLSv1.3": True}}},
                "mail": {"status": "ok", "data": {"grade": "F", "spoofable": True, "accepts_mail": False,
                                                  "spf": {"present": False, "issues": []},
                                                  "dmarc": {"present": False, "issues": []}, "dkim": {}, "mta_sts": {}}},
                "ports": {"status": "ok", "data": {"results": [{"port": 3389, "state": "open"}]}},
            }}


class ScoreAndReportTests(unittest.TestCase):
    def test_assess(self):
        result = score.assess(sample_report())
        titles = " ".join(f["title"] for f in result["findings"])
        self.assertIn("Forged mail", titles)
        self.assertIn("RDP", titles)
        self.assertIn("TLSv1.0", titles)
        self.assertEqual(result["findings"][0]["severity"], "high")
        self.assertTrue({"Mail", "Ports", "TLS", "DNS"} <= {f["area"] for f in result["findings"]})
        self.assertIn(result["grade"], ("D", "F"))

    def test_assess_does_not_depend_on_language(self):
        """Mail issues are classified from the data, not by matching translated text."""
        report = sample_report()
        report["modules"]["mail"]["data"].update(
            spf=mailsec.analyze_spf(["v=spf1 +all"]), dmarc=mailsec.analyze_dmarc([]))
        english = score.assess(report)
        i18n.set_language("es")
        try:
            spanish = score.assess(report)
        finally:
            i18n.set_language("en")
        keys = [(f["severity"], f["area"]) for f in english["findings"]]
        self.assertEqual(keys, [(f["severity"], f["area"]) for f in spanish["findings"]])
        self.assertEqual(english["score"], spanish["score"])
        mail = [f["title"] for f in english["findings"] if f["area"] == "Mail"]
        self.assertEqual(sum("DMARC" in title and "receivers" in title for title in mail), 0)
        self.assertTrue(any("'+all'" in title for title in mail))

    def test_assess_nothing(self):
        self.assertIsNone(score.assess({"modules": {"rdap": {"status": "ok", "data": {}}}}))

    def test_infra_correlation_and_csv(self):
        a, b = sample_report("a.test"), sample_report("b.test")
        result = infra.correlate([a, b])
        kinds = {(g["kind"], g["value"]) for g in result["groups"]}
        self.assertIn(("IP", "203.0.113.5"), kinds)
        self.assertIn(("DNS server", "ns1.dns.test"), kinds)
        csv_text = infra.to_csv([a, b])
        self.assertTrue(csv_text.startswith("target,grade"))
        self.assertIn("a.test", csv_text)

    def test_renderers(self):
        report = sample_report()
        report["score"] = score.assess(report)
        text = render.to_text(app, report)
        self.assertIn("SECURITY GRADE:", text)
        md = render.to_markdown(app, report)
        self.assertIn("| Level | Area |", md)
        page = render.to_html(app, report, '{"x": "<script>"}')
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)

    def test_not_applicable_is_skipped(self):
        args = app.parser().parse_args(["-m", "mail", "-q", "203.0.113.5"])
        with patch.dict(app.RUNNERS, {"dns": lambda target, a: {"addresses": [target]}}):
            report = app.scan("203.0.113.5", args)
        self.assertEqual(report["modules"]["mail"]["status"], "skipped")
        self.assertIn("domain", report["modules"]["mail"]["reason"])

    def test_cli_options(self):
        args = app.parser().parse_args(["-m", "recon", "--brute", "--format", "md", "example.com"])
        self.assertTrue(args.brute)
        self.assertEqual(args.format, "md")
        self.assertTrue({"mail", "recon", "brand"} <= set(app.MODES))
        self.assertTrue(set(app.MODULES) >= {m for mode in app.MODES.values() for m in mode})


if __name__ == "__main__":
    unittest.main()
