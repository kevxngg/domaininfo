"""Optional OWASP ZAP integration, PASSIVE by default (DomainInfo 6.0, Phase 2).

Talks to a ZAP daemon that the USER already runs on this machine (``zap.sh -daemon``): the API
URL must be loopback (127.0.0.1, ::1 or localhost); anything else is refused. The API key comes
from ``args.zap_api_key`` or the ``ZAP_API_KEY`` environment variable and is sent only in the
``X-ZAP-API-Key`` header to that loopback address; it never appears in results or errors.

What it does: checks ZAP's version, asks ZAP to fetch the target URL (so ZAP's *passive* scanner
sees it), optionally runs the traditional spider limited to the URL's subtree when explicitly
enabled (``args.zap_spider``), waits for the passive scan queue to drain (with a timeout) and
reads the alerts for in-scope URLs. It never starts an active scan: only the API endpoints in
``ALLOWED_ENDPOINTS`` can be called.

Alerts become ``evidence`` findings: status ``confirmed`` only for ZAP confidence High or
Confirmed, ``likely`` for Medium and ``pending`` for Low; False Positive alerts are dropped.

Public API: ``available(zap_url=None, api_key=None, timeout=5) -> dict`` and ``audit(url, args) -> dict``.
"""

import http.client
import ipaddress
import json
import os
import time
from urllib import parse

import evidence
from i18n import tr
import safety

TOOL = "owasp-zap"
DEFAULT_ZAP_URL = "http://127.0.0.1:8080"
ALLOWED_ENDPOINTS = frozenset({
    "core/view/version", "core/action/accessUrl", "pscan/view/recordsToScan", "alert/view/alerts",
    "core/view/alerts", "spider/action/scan", "spider/view/status",
})
RISK = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}
CONFIDENCE = {"confirmed": ("confirmed", "high"), "high": ("confirmed", "high"), "medium": ("likely", "medium"),
              "low": ("pending", "low")}
MAX_ALERTS = 500
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
INSTALL_HINT = "https://www.zaproxy.org/download/ · zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=…"


class ZapError(RuntimeError):
    """ZAP is absent, unreachable or answered with an error."""


def zap_base(value=None):
    """Validated loopback ZAP API base URL; raises ValueError for any other host."""
    url = safety.normalize_url(value or os.environ.get("ZAP_API_URL") or DEFAULT_ZAP_URL)
    parts = parse.urlsplit(url)
    host = parts.hostname or ""
    loopback = host == "localhost"
    if not loopback:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
    if not loopback:
        raise ValueError(tr("The ZAP API must run on this machine (127.0.0.1, ::1 or localhost)"))
    netloc = parts.netloc.replace("localhost", "127.0.0.1", 1) if host == "localhost" else parts.netloc
    return parse.urlunsplit((parts.scheme, netloc, "", "", ""))


class ZapClient:
    def __init__(self, base, api_key=None, timeout=5.0):
        self.base = zap_base(base)
        self._key = api_key if api_key is not None else os.environ.get("ZAP_API_KEY")
        self.timeout = timeout
        self.policy = safety.ScopePolicy(self.base, allow_private=True)

    def __repr__(self):
        return f"ZapClient(base={self.base!r})"

    def _scrub(self, text):
        text = str(text)
        return text.replace(self._key, tr("[hidden]")) if self._key else text

    def call(self, endpoint, **params):
        if endpoint not in ALLOWED_ENDPOINTS:
            raise ValueError(tr("ZAP endpoint not allowed: {endpoint}", endpoint=endpoint))
        query = parse.urlencode({k: str(v) for k, v in params.items()})
        url = f"{self.base}/JSON/{endpoint}/" + (f"?{query}" if query else "")
        headers = {"Accept": "application/json"}
        if self._key:
            headers["X-ZAP-API-Key"] = self._key
        try:
            response = safety.http_get(url, self.policy, self.timeout, headers=headers, max_redirects=0,
                                       limit=8 * 1024 * 1024, deadline=time.monotonic() + max(10.0, self.timeout * 2))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ZapError(tr("ZAP is not reachable at {url}: {error}", url=self.base,
                              error=self._scrub(exc)[:200])) from None
        try:
            data = json.loads(response.body.decode("utf-8", "replace"))
        except ValueError:
            data = None
        if response.status != 200 or not isinstance(data, dict):
            message = data.get("message") if isinstance(data, dict) else None
            raise ZapError(tr("ZAP API error on {endpoint} (HTTP {status}): {message}", endpoint=endpoint,
                              status=response.status, message=self._scrub(message or "-")[:200]))
        return data

    def version(self):
        return str(self.call("core/view/version").get("version", ""))[:40]


def available(zap_url=None, api_key=None, timeout=5.0):
    """{'available': bool, 'version': str|None, 'url': str, 'reason': str|None}."""
    try:
        client = ZapClient(zap_url, api_key, timeout)
    except ValueError as exc:
        return {"available": False, "version": None, "url": None, "reason": str(exc)}
    try:
        return {"available": True, "version": client.version(), "url": client.base, "reason": None}
    except ZapError as exc:
        return {"available": False, "version": None, "url": client.base, "reason": str(exc)}


def normalize_alert(alert, target):
    """ZAP alert -> evidence finding dict (None for False Positive)."""
    confidence_raw = str(alert.get("confidence", "")).strip().lower()
    if confidence_raw.startswith("false"):
        return None
    status, confidence = CONFIDENCE.get(confidence_raw, ("pending", "low"))
    severity = RISK.get(str(alert.get("risk", "")).strip().lower(), "info")
    if severity == "info" and status != "confirmed":
        status = "informational"
    url = str(alert.get("url") or target)
    references = []
    cwe = str(alert.get("cweid") or "").strip()
    if cwe.isdigit() and cwe != "0" and cwe != "-1":
        references.append(f"CWE-{cwe}")
    wasc = str(alert.get("wascid") or "").strip()
    if wasc.isdigit() and wasc != "0" and wasc != "-1":
        references.append(f"WASC-{wasc}")
    for ref in str(alert.get("reference") or "").split()[:3]:
        if ref.startswith(("http://", "https://")):
            references.append(evidence.clean(ref)[:200])
    proof = " · ".join(p for p in (
        tr("URL: {url}", url=evidence.redact_url(url)),
        tr("parameter: {param}", param=evidence.clean(alert["param"])[:80]) if alert.get("param") else "",
        tr("evidence: {value}", value=str(alert["evidence"])[:200]) if alert.get("evidence") else "") if p)
    return evidence.Finding(
        target=evidence.redact_url(target), path=parse.urlsplit(url).path or "/", category="zap",
        title=evidence.clean(alert.get("alert") or alert.get("name") or "ZAP alert")[:160], severity=severity,
        status=status, confidence=confidence, evidence=proof, tool=TOOL,
        impact=evidence.redact(alert.get("description") or "", 300),
        verification=tr("Reported by ZAP's passive scanner (plugin {plugin}, confidence {confidence}); check it by hand",
                        plugin=evidence.clean(alert.get("pluginId") or "-")[:20],
                        confidence=evidence.clean(alert.get("confidence") or "-")[:20]),
        recommendation=evidence.redact(alert.get("solution") or "", 400), references=references).to_dict()


def _not_evaluated(url, detail, extra=None):
    checks = [{"id": "zap", "state": "not_evaluated", "evidence": "direct", "detail": detail}]
    result = {"url": evidence.redact_url(url), "available": False, "findings": [], "checks": checks,
              "assessment": evidence.scores([], checks), "install": INSTALL_HINT}
    result.update(extra or {})
    return result


def audit(url, args):
    """Passive ZAP audit of ``url``. ``args``: zap_url, zap_api_key, zap_spider (bool),
    zap_wait (seconds for the passive queue), zap_spider_max (children), timeout, scope, allow_private."""
    url = safety.normalize_url(url)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    policy = safety.ScopePolicy(url, extra_hosts=list(getattr(args, "scope", None) or []),
                                allow_private=bool(getattr(args, "allow_private", False)))
    # Same network rules as the rest of DomainInfo before asking ZAP to visit the target
    policy.connect_address(parse.urlsplit(url).hostname)
    client = ZapClient(getattr(args, "zap_url", None), getattr(args, "zap_api_key", None), timeout)
    try:
        version = client.version()
    except ZapError as exc:
        return _not_evaluated(url, tr("OWASP ZAP is not available: {reason}", reason=str(exc)))
    notes = []
    wait = max(5.0, min(float(getattr(args, "zap_wait", 120) or 120), 900.0))
    try:
        client.call("core/action/accessUrl", url=url, followRedirects="false")
        if getattr(args, "zap_spider", False):
            maximum = max(1, min(int(getattr(args, "zap_spider_max", 50) or 50), 500))
            scan = client.call("spider/action/scan", url=url, maxChildren=maximum, recurse="true",
                               subtreeOnly="true").get("scan")
            end = time.monotonic() + wait
            while time.monotonic() < end:
                if str(client.call("spider/view/status", scanId=scan).get("status")) == "100":
                    break
                time.sleep(1.0)
            else:
                notes.append(tr("The spider did not finish within {seconds} s", seconds=round(wait)))
        end = time.monotonic() + wait
        pending = None
        while time.monotonic() < end:
            pending = str(client.call("pscan/view/recordsToScan").get("recordsToScan", "0"))
            if pending == "0":
                break
            time.sleep(1.0)
        else:
            notes.append(tr("ZAP's passive scan still had {count} records after {seconds} s",
                            count=pending, seconds=round(wait)))
        origin = parse.urlunsplit((*parse.urlsplit(url)[:2], "", "", ""))
        try:
            alerts = client.call("alert/view/alerts", baseurl=origin, start=0, count=MAX_ALERTS).get("alerts", [])
        except ZapError:
            alerts = client.call("core/view/alerts", baseurl=origin, start=0, count=MAX_ALERTS).get("alerts", [])
    except ZapError as exc:
        checks = [{"id": "zap", "state": "error", "evidence": "direct", "detail": str(exc)}]
        return {"url": evidence.redact_url(url), "available": True, "zap_version": version, "findings": [],
                "checks": checks, "assessment": evidence.scores([], checks), "notes": notes}
    findings, seen = [], set()
    for alert in alerts if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        alert_url = str(alert.get("url") or "")
        try:
            host = parse.urlsplit(safety.normalize_url(alert_url)).hostname or ""
            if not policy.in_scope(host):
                continue
        except ValueError:
            continue
        key = (alert.get("pluginId"), alert.get("alert") or alert.get("name"), parse.urlsplit(alert_url).path)
        if key in seen:
            continue
        seen.add(key)
        finding = normalize_alert(alert, url)
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["title"]))
    checks = [{"id": "zap", "state": "finding" if any(f["status"] in ("confirmed", "likely") for f in findings)
               else "ok", "evidence": "direct"}]
    return {"url": evidence.redact_url(url), "available": True, "zap_version": version,
            "spider": bool(getattr(args, "zap_spider", False)), "alerts": len(findings), "findings": findings,
            "checks": checks, "assessment": evidence.scores(findings, checks), "notes": notes,
            "note": tr("ZAP passive mode: the target is fetched through ZAP and its passive scanner reports; no "
                       "active scan is ever started")}
