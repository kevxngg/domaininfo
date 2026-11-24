"""Safe executors for the optional external tools listed in ``tools.CATALOG`` (DomainInfo 6.0, Phase 3).

Public API::

    runners.run(tool, target, options=None, allow_active=False, scope=None, cancel=None,
                allow_private=False) -> dict
    runners.describe() -> dict          # static metadata of every supported tool
    runners.is_active(tool, options=None) -> bool
    runners.in_scope(host, scope) -> bool
    runners.make_finding(...) -> dict   # finding dict with the evidence.Finding.to_dict() keys

Rules enforced here:

* Tools are optional. A missing tool returns ``status="skipped"`` with an install hint; nothing is ever
  downloaded or installed.
* Arguments are built only from validated values (strict hostnames / IPs, ``safety.normalize_url`` URLs,
  existing local paths, bounded integers and whitelisted tokens). ``subprocess.Popen`` gets a list and
  never a shell, so a target such as ``example.com;rm`` or ``-oN /tmp/x`` is rejected before any process
  starts.
* ACTIVE tools (they send traffic to the target: nmap, nuclei, testssl.sh, sslyze, httpx probing and dnsx
  brute force) only run when the caller passes ``allow_active=True`` AND the target host is in the explicit
  ``scope`` list (exact host, ``*.domain`` wildcard, IP or CIDR).
* Every tool that connects to the target (host, URL) refuses it when its name resolves to a
  link-local / metadata / multicast / reserved address, and to a private address unless
  ``allow_private=True`` (``safety.classify_ip``). The external tool resolves the name again by itself, so
  DNS rebinding between this check and the tool's own lookup is a residual gap. Domain-only tools
  (subfinder, amass, dnsx) query DNS and public sources, not the target, and are not resolved here.
* Windows script shims (``.bat``, ``.cmd``, ``.ps1``) are never executed: their arguments would pass through
  ``cmd.exe``, which interprets ``& | " ^ %``.
* Every run has a timeout and an optional ``threading.Event`` for cancellation; both kill the whole
  process tree. Output is capped and temporary files live in a private directory removed afterwards.

The result dict always has: ``tool, target, status (ok|error|skipped), reason, active, available,
version, install, command, returncode, duration, findings, assets, components, errors, coverage``.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess  # nosec B404
import tempfile
import threading
import time

from i18n import tr

MAX_OUTPUT = 16 * 1024 * 1024        # bytes kept from stdout / an output file
MAX_STDERR = 256 * 1024
DEFAULT_TIMEOUT = 600                # seconds
MIN_TIMEOUT, MAX_TIMEOUT = 5, 3600
NUCLEI_BANNED_TAGS = ("intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force", "headless", "oast")
SEVERITIES = ("high", "medium", "low", "info")
STATUSES = ("confirmed", "likely", "informational", "pending", "not_applicable", "not_evaluated", "error")
CONFIDENCES = ("high", "medium", "low")

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(r"(?=.{1,253}\Z)(?:" + _LABEL + r"\.)*" + _LABEL + r"\Z")
_TAG = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}\Z")
_PORTS = re.compile(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?){0,99}\Z")
_SEMGREP_CONFIG = re.compile(r"(?:p|r)/[A-Za-z0-9._-]{1,80}(?:/[A-Za-z0-9._-]{1,80}){0,3}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DISTRO = re.compile(r"(?i)ubuntu|debian|deb\d|el\d|rhel|centos|fedora|suse|alpine|freebsd")
_CPE_PART = re.compile(r"(?:\*|[A-Za-z0-9._~%+-]+)\Z")


class TargetError(ValueError):
    """The target or an option failed validation; nothing was executed."""


# --------------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------------
def clean(text, limit=300):
    """Evidence text without control characters (ANSI sequences), collapsed and truncated."""
    text = _CONTROL.sub("", re.sub(r"\s+", " ", str(text or ""))).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def make_finding(target, category, title, severity, status, confidence="medium", evidence="", tool="",
                 path="", impact="", verification="", recommendation="", references=()):
    """Finding dict with the same keys and id rule as ``evidence.Finding.to_dict()``."""
    if severity not in SEVERITIES or status not in STATUSES or confidence not in CONFIDENCES:
        raise ValueError(f"invalid finding enum: {severity}/{status}/{confidence}")
    import evidence as evidence_model
    finding_id = evidence_model.finding_id(target, category, title)  # language-independent id
    target, category, title = str(target), str(category), clean(title, 200)
    refs = [clean(ref, 300) for ref in references if isinstance(ref, str) and ref.startswith(("http://", "https://"))]
    return {"id": finding_id, "target": target, "path": clean(path, 300), "category": category,
            "title": title, "severity": severity, "status": status, "confidence": confidence,
            "evidence": evidence_model.redact(clean(evidence)), "tool": tool, "impact": impact,
            "verification": verification,
            "recommendation": recommendation, "references": refs[:10]}


# --------------------------------------------------------------------------------------------
# Validation and scope
# --------------------------------------------------------------------------------------------
def _reject_raw(value):
    if not isinstance(value, str) or not value.strip():
        raise TargetError(tr("Empty or invalid target"))
    value = value.strip()
    if value.startswith("-") or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise TargetError(tr("Target contains spaces, control characters or starts with '-': {target}",
                             target=clean(value, 80)))
    return value


def validate_host(value):
    """Lower-case ASCII hostname or canonical IP address; anything else raises TargetError."""
    value = _reject_raw(value).strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    import safety
    try:
        host = safety.normalize_host(value)
    except ValueError as exc:
        raise TargetError(tr("Invalid hostname: {target}", target=clean(value, 80))) from exc
    if not _HOST.match(host):
        raise TargetError(tr("Invalid hostname: {target}", target=clean(value, 80)))
    return host


def validate_domain(value):
    host = validate_host(value)
    if _is_ip(host) or "." not in host:
        raise TargetError(tr("A domain name is required: {target}", target=host))
    return host


def validate_url(value):
    _reject_raw(value)
    import safety
    try:
        return safety.normalize_url(value)
    except ValueError as exc:
        raise TargetError(tr("Invalid URL: {target}", target=clean(value, 80))) from exc


def validate_path(value, kind="any"):
    """Absolute, existing local path (file or directory)."""
    if not isinstance(value, (str, os.PathLike)) or not str(value).strip():
        raise TargetError(tr("Empty or invalid target"))
    if _CONTROL.search(str(value)):
        raise TargetError(tr("Invalid local path: {target}", target=clean(value, 80)))
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise TargetError(tr("Local path not found: {target}", target=clean(value, 120))) from exc
    if kind == "file" and not path.is_file():
        raise TargetError(tr("A file is required: {target}", target=str(path)))
    if kind == "dir" and not path.is_dir():
        raise TargetError(tr("A directory is required: {target}", target=str(path)))
    return str(path)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host_of(target):
    from urllib import parse
    return parse.urlsplit(target).hostname if "://" in target else target


def _scope_entry(entry):
    if not isinstance(entry, str) or not entry.strip():
        raise TargetError(tr("Invalid scope entry: {entry}", entry=clean(entry, 80)))
    entry = entry.strip().lower()
    if "/" in entry:
        try:
            return ("net", ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise TargetError(tr("Invalid scope entry: {entry}", entry=clean(entry, 80))) from exc
    if entry.startswith("*."):
        return ("wild", validate_domain(entry[2:]))
    return ("host", validate_host(entry))


def in_scope(host, scope):
    """True when ``host`` (hostname or IP) matches an explicit scope entry. No DNS resolution is done,
    so a hostname never matches a CIDR entry."""
    if not scope:
        return False
    host = validate_host(host)
    ip = ipaddress.ip_address(host) if _is_ip(host) else None
    for kind, value in map(_scope_entry, scope):
        if isinstance(value, str):
            if (kind == "host" and value == host) or (kind == "wild" and ip is None and host.endswith("." + value)):
                return True
        elif ip is not None and ip.version == value.version and ip in value:
            return True
    return False


def _bounded(options, key, default, low, high):
    value = options.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise TargetError(tr("Option {option} must be an integer between {low} and {high}",
                             option=key, low=low, high=high))
    return value


def _port(options):
    return _bounded(options, "port", 443, 1, 65535)


def _hostport(host, port):
    return (f"[{host}]" if ":" in host else host) + f":{port}"


# --------------------------------------------------------------------------------------------
# Process execution
# --------------------------------------------------------------------------------------------
class _Capture(threading.Thread):
    """Drains a pipe, keeping at most ``limit`` bytes (the rest is read and discarded)."""

    def __init__(self, stream, limit):
        super().__init__(daemon=True)
        self.stream, self.limit, self.chunks, self.size, self.truncated = stream, limit, [], 0, False

    def run(self):
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                room = self.limit - self.size
                if room > 0:
                    self.chunks.append(chunk[:room])
                    self.size += min(room, len(chunk))
                if len(chunk) > room:
                    self.truncated = True
        except (OSError, ValueError):
            pass

    def text(self):
        return b"".join(self.chunks).decode("utf-8", "replace")


def _kill_tree(proc):
    """Kill the process and all of its children."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
            # Fixed system binary and a numeric PID: no user input reaches this command.
            subprocess.run([taskkill, "/F", "/T", "/PID", str(proc.pid)],  # noqa: S603  # nosec B603
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
        else:
            killpg = getattr(os, "killpg", None)
            if killpg is not None:
                killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def execute(argv, timeout=DEFAULT_TIMEOUT, cancel=None, cwd=None, max_output=MAX_OUTPUT, poll=0.1):
    """Run ``argv`` (a list, no shell) with a deadline and cancellation; kills the process tree on stop.

    Returns ``{returncode, stdout, stderr, timed_out, cancelled, truncated, duration}``.
    Raises OSError when the executable cannot be started.
    """
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a non-empty list of strings")
    start = time.monotonic()
    # List arguments built from validated values; shell=False. The executable comes from tools.detect().
    proc = subprocess.Popen(  # noqa: S603  # nosec B603
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd,
        shell=False, creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
        start_new_session=os.name != "nt")
    out, err = _Capture(proc.stdout, max_output), _Capture(proc.stderr, MAX_STDERR)
    out.start()
    err.start()
    timed_out = cancelled = False
    while True:
        try:
            proc.wait(timeout=poll)
            break
        except subprocess.TimeoutExpired:
            pass
        if cancel is not None and cancel.is_set():
            cancelled = True
        elif time.monotonic() - start > timeout:
            timed_out = True
        if cancelled or timed_out:
            _kill_tree(proc)
            break
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    out.join(3)
    err.join(3)
    for stream in (proc.stdout, proc.stderr):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass
    return {"returncode": proc.returncode, "stdout": out.text(), "stderr": err.text(),
            "timed_out": timed_out, "cancelled": cancelled, "truncated": out.truncated,
            "duration": round(time.monotonic() - start, 3)}


def _read_output(path, limit=MAX_OUTPUT):
    """Bytes of a tool output file (at most ``limit``) and whether it was truncated; None if missing."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            return handle.read(limit), size > limit
    except OSError:
        return None, False


def _jsonl(data):
    rows, bad = [], 0
    for line in (data or b"").decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows, bad


def _json(data):
    try:
        return json.loads((data or b"").decode("utf-8", "replace") or "null")
    except ValueError as exc:
        raise ValueError(tr("Tool output is not valid JSON: {error}", error=clean(exc, 120))) from exc


def _dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# --------------------------------------------------------------------------------------------
# Parsers (also used by the tests with fixtures)
# --------------------------------------------------------------------------------------------
def cpe23(cpe, version=None):
    """CPE 2.2 URI (``cpe:/a:vendor:product:version``) or 2.3 string -> CPE 2.3 with a version, or None."""
    if not isinstance(cpe, str):
        return None
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")[2:]
    elif cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
    else:
        return None
    parts = (parts + ["*"] * 11)[:11]
    if parts[3] in ("", "*", "-") and version:
        parts[3] = str(version).split()[0]
    if parts[0] not in ("a", "o", "h") or parts[3] in ("", "*", "-"):
        return None
    parts = [part or "*" for part in parts]
    if not all(_CPE_PART.match(part) for part in parts):
        return None
    return "cpe:2.3:" + ":".join(parts)


def parse_nmap_xml(data, target):
    """Open ports, services and versioned components from ``nmap -oX`` output (a local file)."""
    import xml.etree.ElementTree as ET  # nosec B405
    if not data:
        raise ValueError(tr("Empty nmap output"))
    if b"<!ENTITY" in data.upper():
        raise ValueError(tr("Unexpected XML entities in nmap output"))
    # Local output written by nmap in our private temp dir; entity declarations are refused above.
    root = ET.fromstring(data)  # noqa: S314  # nosec B314
    assets, components = [], []
    for host in root.iter("host"):
        addresses = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")]
        names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
        address = addresses[0] if addresses else None
        hostname = target if not _is_ip(target) else (names[0] if names else target)
        assets.extend({"type": "ip", "value": a, "host": hostname} for a in addresses if a)
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                number = int(port.get("portid") or "")
            except ValueError:
                continue
            asset = {"type": "port", "host": hostname, "address": address, "port": number,
                     "protocol": port.get("protocol") or "tcp", "state": "open"}
            service = port.find("service")
            if service is not None:
                cpes = [c.text for c in service.findall("cpe") if c.text]
                asset.update(service=service.get("name"), product=service.get("product"),
                             version=service.get("version"), extrainfo=service.get("extrainfo"),
                             method=service.get("method"), cpe=cpes)
                product, version = service.get("product"), service.get("version")
                if product and version:
                    components.append({
                        "name": product, "version": version.split()[0],
                        "cpe": cpe23(cpes[0], version) if cpes else None,
                        # 'probed' = read from the banner; 'table' = guessed from the port number. A distro
                        # suffix ("8.9p1 Ubuntu 3ubuntu0.1") means backported fixes: not direct evidence.
                        "evidence": "direct" if service.get("method") == "probed" and len(version.split()) == 1
                                    and not _DISTRO.search(service.get("extrainfo") or "") else "heuristic",
                        "source": "nmap", "location": f"{hostname}:{number}/{asset['protocol']}"})
            assets.append(asset)
    finished = root.find("runstats/finished")
    complete = finished is not None and finished.get("exit", "success") == "success"
    return [], assets, components, complete


_NUCLEI_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


def parse_nuclei(data, target):
    rows, bad = _jsonl(data)
    findings, assets = [], []
    for row in rows:
        info = _dict(row.get("info"))
        classification = _dict(info.get("classification"))
        severity = _NUCLEI_SEVERITY.get(str(info.get("severity", "")).lower(), "info")
        template = clean(row.get("template-id") or row.get("templateID") or "unknown", 80)
        matched = clean(row.get("matched-at") or row.get("matched") or row.get("host") or target, 300)
        cves = [c for c in _as_list(classification.get("cve-id")) if isinstance(c, str)]
        cwes = [c for c in _as_list(classification.get("cwe-id")) if isinstance(c, str)]
        refs = [r for r in _as_list(info.get("reference")) if isinstance(r, str)]
        refs += [f"https://nvd.nist.gov/vuln/detail/{c.upper()}" for c in cves]
        detail = [f"template={template}", f"matched-at={matched}"]
        if row.get("matcher-name"):
            detail.append(f"matcher={clean(row['matcher-name'], 60)}")
        if cves:
            detail.append("cve=" + ",".join(c.upper() for c in cves))
        if cwes:
            detail.append("cwe=" + ",".join(c.upper() for c in cwes))
        if classification.get("cvss-score") is not None:
            detail.append(f"cvss={classification.get('cvss-score')}")
        findings.append(make_finding(
            target, "nuclei", tr("Nuclei: {name}", name=clean(info.get("name") or template, 150)), severity,
            "informational" if severity == "info" else "likely", "medium", "; ".join(detail), "nuclei",
            path=matched, verification=tr("Template match by nuclei; reproduce the request manually before "
                                          "treating it as confirmed."),
            recommendation=clean(info.get("remediation") or "", 300), references=refs))
    return findings, assets, [], bad == 0


def parse_subfinder(data, target):
    rows, bad = _jsonl(data)
    assets, seen = [], set()
    for row in rows:
        try:
            name = validate_host(str(row.get("host", "")))
        except TargetError:
            continue
        if name not in seen and (name == target or name.endswith("." + target)):
            seen.add(name)
            assets.append({"type": "subdomain", "value": name, "source_detail": clean(row.get("source", ""), 40)})
    return [], assets, [], bad == 0


_NAME_TOKEN = re.compile(r"[A-Za-z0-9._-]+")


def parse_amass(data, target):
    assets, seen = [], set()
    for token in _NAME_TOKEN.findall((data or b"").decode("utf-8", "replace").lower()):
        token = token.rstrip(".")
        if (token == target or token.endswith("." + target)) and token not in seen:
            try:
                assets.append({"type": "subdomain", "value": validate_host(token)})
                seen.add(token)
            except TargetError:
                continue
    return [], assets, [], True


def parse_dnsx(data, target):
    rows, bad = _jsonl(data)
    assets = []
    for row in rows:
        name = clean(row.get("host", ""), 253).lower()
        assets.append({"type": "subdomain" if name != target else "domain", "value": name})
        for key in ("a", "aaaa"):
            assets.extend({"type": "ip", "value": ip, "host": name}
                          for ip in _as_list(row.get(key)) if isinstance(ip, str) and _is_ip(ip))
        assets.extend({"type": "cname", "value": clean(c, 253).lower(), "host": name}
                      for c in _as_list(row.get("cname")) if isinstance(c, str))
    return [], assets, [], bad == 0


def _tech_component(text, source, location, evidence):
    name, _, version = str(text).partition(":")
    version = version.strip()
    return {"name": clean(name, 100), "version": clean(version, 50) or None, "evidence": evidence,
            "source": source, "location": location}


def parse_httpx(data, target):
    rows, bad = _jsonl(data)
    assets, components = [], []
    for row in rows:
        url = clean(row.get("url", ""), 300)
        asset = {"type": "url", "value": url, "host": clean(row.get("input") or target, 253),
                 "status_code": row.get("status_code", row.get("status-code")), "title": clean(row.get("title", ""), 120),
                 "webserver": clean(row.get("webserver", ""), 80), "port": row.get("port")}
        if isinstance(row.get("host"), str) and _is_ip(row["host"]):
            asset["address"] = row["host"]
            assets.append({"type": "ip", "value": row["host"], "host": asset["host"]})
        assets.append(asset)
        for tech in _as_list(row.get("tech")):
            component = _tech_component(tech, "httpx", url, "heuristic")
            assets.append({"type": "technology", "name": component["name"], "version": component["version"]})
            if component["version"]:
                components.append(component)
    return [], assets, components, bad == 0


def parse_whatweb(data, target):
    rows = _json(data) or []
    assets, components = [], []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        url = clean(row.get("target", ""), 300)
        assets.append({"type": "url", "value": url, "status_code": row.get("http_status")})
        plugins = _dict(row.get("plugins"))
        for name, detail in plugins.items():
            versions = [v for v in _as_list((detail or {}).get("version")) if isinstance(v, str)]
            assets.append({"type": "technology", "name": clean(name, 80), "version": versions[0] if versions else None})
            if versions:
                components.append({"name": clean(name, 80), "version": clean(versions[0], 50), "evidence": "direct",
                                   "source": "whatweb", "location": url})
    return [], assets, components, True


_DEPRECATED_TLS = {"ssl_2_0_cipher_suites": ("SSL 2.0", "high"), "ssl_3_0_cipher_suites": ("SSL 3.0", "high"),
                   "tls_1_0_cipher_suites": ("TLS 1.0", "medium"), "tls_1_1_cipher_suites": ("TLS 1.1", "medium")}


def _sslyze_result(scan, key):
    entry = scan.get(key) if isinstance(scan, dict) else None
    if not isinstance(entry, dict):
        return None
    return entry.get("result") if isinstance(entry.get("result"), dict) else None


def parse_sslyze(data, target):
    doc = _json(data) or {}
    findings, complete = [], True
    for server in _as_list(doc.get("server_scan_results") if isinstance(doc, dict) else None):
        if not isinstance(server, dict):
            continue
        location = server.get("server_location") or {}
        where = _hostport(location.get("hostname", target), location.get("port", 443))
        scan = server.get("scan_result")
        if not isinstance(scan, dict):
            complete = False
            continue
        for key, (protocol, severity) in _DEPRECATED_TLS.items():
            result = _sslyze_result(scan, key)
            if result and result.get("accepted_cipher_suites"):
                findings.append(make_finding(
                    target, "tls", tr("Deprecated protocol {protocol} accepted", protocol=protocol), severity,
                    "confirmed", "high", tr("{count} cipher suites accepted on {where}",
                                            count=len(result["accepted_cipher_suites"]), where=where), "sslyze",
                    path=where, recommendation=tr("Disable {protocol} and keep TLS 1.2 and 1.3 only.", protocol=protocol)))
        checks = (("heartbleed", "is_vulnerable_to_heartbleed", "Heartbleed (CVE-2014-0160)"),
                  ("openssl_ccs_injection", "is_vulnerable_to_ccs_injection", "OpenSSL CCS injection (CVE-2014-0224)"))
        for key, field, name in checks:
            result = _sslyze_result(scan, key)
            if result and result.get(field) is True:
                findings.append(make_finding(target, "tls", tr("Vulnerable to {name}", name=name), "high", "confirmed",
                                             "high", f"{key}={field}", "sslyze", path=where))
        robot = _sslyze_result(scan, "robot")
        if robot and str(robot.get("robot_result", "")).startswith("VULNERABLE"):
            findings.append(make_finding(target, "tls", tr("Vulnerable to {name}", name="ROBOT"), "high", "confirmed",
                                         "medium", str(robot.get("robot_result")), "sslyze", path=where))
    return findings, [], [], complete


_TESTSSL_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


def parse_testssl(data, target):
    rows = _json(data) or []
    if isinstance(rows, dict):
        rows = rows.get("scanResult", [])
    findings, complete = [], True
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        level = str(row.get("severity", "")).lower()
        if level == "fatal":
            complete = False
        severity = _TESTSSL_SEVERITY.get(level)
        if not severity:
            continue
        check = clean(row.get("id", "check"), 60)
        where = _hostport(clean(row.get("ip", target), 100).split("/")[0], row.get("port", 443))
        cves = [c for c in str(row.get("cve", "")).split() if c.upper().startswith("CVE-")]
        findings.append(make_finding(
            target, "tls", tr("testssl.sh: {check}", check=check), severity, "likely", "medium",
            clean(row.get("finding", ""), 300), "testssl.sh", path=where,
            verification=tr("Reported by testssl.sh; confirm the server configuration before acting."),
            references=[f"https://nvd.nist.gov/vuln/detail/{c.upper()}" for c in cves]))
    return findings, [], [], complete


_SEMGREP_SEVERITY = {"error": "high", "warning": "medium", "info": "low"}
_CONFIDENCE = {"high": "high", "medium": "medium", "low": "low"}


def parse_semgrep(data, target):
    doc = _json(data) or {}
    findings = []
    for row in _as_list(doc.get("results") if isinstance(doc, dict) else None):
        if not isinstance(row, dict):
            continue
        extra = _dict(row.get("extra"))
        meta = _dict(extra.get("metadata"))
        line = (row.get("start") or {}).get("line")
        where = f"{clean(row.get('path', ''), 200)}:{line}"
        rule = clean(row.get("check_id", "rule"), 120)
        refs = [r for r in _as_list(meta.get("references")) if isinstance(r, str)]
        cwe = ", ".join(clean(c, 80) for c in _as_list(meta.get("cwe")) if isinstance(c, str))
        findings.append(make_finding(
            target, "code", tr("Semgrep: {rule} at {where}", rule=rule, where=where),
            _SEMGREP_SEVERITY.get(str(extra.get("severity", "")).lower(), "low"), "likely",
            _CONFIDENCE.get(str(meta.get("confidence", "")).lower(), "low"),
            clean(extra.get("message", ""), 250) + (f" ({cwe})" if cwe else ""), "semgrep", path=where,
            verification=tr("Static analysis result: review the code path before treating it as confirmed."),
            references=refs))
    return findings, [], [], True


def parse_bandit(data, target):
    doc = _json(data) or {}
    findings = []
    for row in _as_list(doc.get("results") if isinstance(doc, dict) else None):
        if not isinstance(row, dict):
            continue
        where = f"{clean(row.get('filename', ''), 200)}:{row.get('line_number')}"
        cwe = _dict(row.get("issue_cwe"))
        evidence = clean(row.get("issue_text", ""), 250) + (f" (CWE-{cwe.get('id')})" if cwe.get("id") else "")
        findings.append(make_finding(
            target, "code", tr("Bandit {test_id}: {name} at {where}", test_id=clean(row.get("test_id", ""), 10),
                               name=clean(row.get("test_name", ""), 80), where=where),
            _CONFIDENCE.get(str(row.get("issue_severity", "")).lower(), "low"), "likely",
            _CONFIDENCE.get(str(row.get("issue_confidence", "")).lower(), "low"), evidence, "bandit", path=where,
            verification=tr("Static analysis result: review the code path before treating it as confirmed."),
            references=[r for r in (row.get("more_info"), cwe.get("link")) if isinstance(r, str)]))
    return findings, [], [], True


def parse_pip_audit(data, target):
    doc = _json(data) or {}
    rows = doc.get("dependencies", []) if isinstance(doc, dict) else doc
    findings, components = [], []
    for dep in rows if isinstance(rows, list) else []:
        if not isinstance(dep, dict) or not dep.get("name"):
            continue
        name, version = clean(dep["name"], 100), clean(dep.get("version") or "", 50)
        if version:
            components.append({"name": name, "version": version, "ecosystem": "PyPI", "evidence": "direct",
                               "source": "pip-audit", "location": target})
        for vuln in _as_list(dep.get("vulns")):
            if not isinstance(vuln, dict):
                continue
            vid = clean(vuln.get("id", ""), 40)
            aliases = [clean(a, 40) for a in _as_list(vuln.get("aliases")) if isinstance(a, str)]
            fixes = ", ".join(clean(f, 30) for f in _as_list(vuln.get("fix_versions")) if isinstance(f, str))
            findings.append(make_finding(
                target, "vulnerable_component", tr("{component} {version} is affected by {vuln_id}",
                                                   component=name, version=version, vuln_id=vid),
                "medium", "confirmed", "high", clean(", ".join(aliases) + " " + str(vuln.get("description", "")), 250),
                "pip-audit", path=target,
                recommendation=tr("Upgrade to a fixed version: {versions}", versions=fixes) if fixes else "",
                references=[f"https://osv.dev/vulnerability/{vid}"] if vid else []))
    return findings, [], components, True


_TRIVY_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


def parse_trivy(data, target):
    doc = _json(data) or {}
    findings, components = [], []
    for result in _as_list(doc.get("Results") if isinstance(doc, dict) else None):
        if not isinstance(result, dict):
            continue
        where = clean(result.get("Target", ""), 200)
        for vuln in _as_list(result.get("Vulnerabilities")):
            if not isinstance(vuln, dict):
                continue
            name, version = clean(vuln.get("PkgName", ""), 100), clean(vuln.get("InstalledVersion", ""), 50)
            vid = clean(vuln.get("VulnerabilityID", ""), 40)
            components.append({"name": name, "version": version, "evidence": "direct", "source": "trivy",
                               "location": where})
            refs = [vuln.get("PrimaryURL")] + _as_list(vuln.get("References"))[:5]
            findings.append(make_finding(
                target, "vulnerable_component", tr("{component} {version} is affected by {vuln_id}",
                                                   component=name, version=version, vuln_id=vid),
                _TRIVY_SEVERITY.get(str(vuln.get("Severity", "")).lower(), "info"), "confirmed", "high",
                clean(vuln.get("Title", ""), 250), "trivy", path=where,
                recommendation=tr("Upgrade to a fixed version: {versions}", versions=clean(vuln["FixedVersion"], 60))
                if vuln.get("FixedVersion") else "", references=[r for r in refs if isinstance(r, str)]))
        for secret in _as_list(result.get("Secrets")):
            if isinstance(secret, dict):
                line = f"{where}:{secret.get('StartLine')}"
                # The matched text is never copied: it may contain the secret itself.
                findings.append(make_finding(
                    target, "secrets", tr("Possible secret ({rule}) at {where}",
                                          rule=clean(secret.get("RuleID", ""), 60), where=line),
                    _TRIVY_SEVERITY.get(str(secret.get("Severity", "")).lower(), "high"), "likely", "medium",
                    clean(secret.get("Title", ""), 120), "trivy", path=line,
                    recommendation=tr("Revoke and rotate the secret, then remove it from the code and history.")))
        for misconf in _as_list(result.get("Misconfigurations")):
            if isinstance(misconf, dict) and str(misconf.get("Status", "FAIL")).upper() == "FAIL":
                findings.append(make_finding(
                    target, "configuration", tr("Misconfiguration {check_id}: {title}",
                                                check_id=clean(misconf.get("ID", ""), 30),
                                                title=clean(misconf.get("Title", ""), 120)),
                    _TRIVY_SEVERITY.get(str(misconf.get("Severity", "")).lower(), "low"), "likely", "medium",
                    clean(misconf.get("Message", ""), 250), "trivy", path=where,
                    recommendation=clean(misconf.get("Resolution", ""), 250),
                    references=[r for r in (misconf.get("PrimaryURL"),) if isinstance(r, str)]))
    return findings, [], components, True


def parse_gitleaks(data, target):
    rows = _json(data) or []
    findings = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        where = f"{clean(row.get('File', ''), 200)}:{row.get('StartLine')}"
        commit = clean(row.get("Commit", ""), 12)
        # Neither 'Secret' nor 'Match' is copied into the evidence.
        findings.append(make_finding(
            target, "secrets", tr("Possible secret ({rule}) at {where}", rule=clean(row.get("RuleID", ""), 60),
                                  where=where), "high", "likely", "medium",
            clean(row.get("Description", ""), 150) + (f" commit={commit}" if commit else ""), "gitleaks", path=where,
            recommendation=tr("Revoke and rotate the secret, then remove it from the code and history.")))
    return findings, [], [], True


# --------------------------------------------------------------------------------------------
# Command builders
# --------------------------------------------------------------------------------------------
def _minutes(timeout):
    return str(max(1, timeout // 60))


def _build_nmap(ctx):
    options, argv = ctx.options, [ctx.exe, "-sT", "-sV", "-Pn", "-T3", "--max-retries", "2", "--max-rate", "50",
                                  "--host-timeout", f"{ctx.timeout}s", "-oX", ctx.out]
    if ":" in ctx.target:
        argv.append("-6")
    ports = options.get("ports")
    if ports is not None:
        if not isinstance(ports, str) or not _PORTS.match(ports) or \
                any(not 1 <= int(p) <= 65535 for p in re.split(r"[,-]", ports)):
            raise TargetError(tr("Invalid port list: {ports}", ports=clean(ports, 60)))
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", str(_bounded(options, "top_ports", 100, 1, 1000))]
    return argv + [ctx.target]


def _build_nuclei(ctx):
    options = ctx.options
    tags = options.get("tags") or []
    if isinstance(tags, str):
        tags = tags.split(",")
    tags = [str(t).strip().lower() for t in tags if str(t).strip()]
    for tag in tags:
        if not _TAG.match(tag) or tag in NUCLEI_BANNED_TAGS:
            raise TargetError(tr("Nuclei tag not allowed: {tag}", tag=clean(tag, 40)))
    argv = [ctx.exe, "-u", ctx.target, "-jsonl", "-o", ctx.out, "-silent", "-nc", "-disable-update-check",
            "-no-interactsh", "-rl", str(_bounded(options, "rate", 10, 1, 50)), "-c", "5", "-bs", "5",
            "-timeout", "10", "-retries", "1", "-etags", ",".join(NUCLEI_BANNED_TAGS)]
    if tags:
        argv += ["-tags", ",".join(tags)]
    return argv


def _build_httpx(ctx):
    return [ctx.exe, "-u", ctx.target, "-json", "-o", ctx.out, "-silent", "-nc", "-status-code", "-title",
            "-web-server", "-tech-detect", "-ip", "-rl", str(_bounded(ctx.options, "rate", 10, 1, 50)), "-t", "5",
            "-timeout", "10", "-retries", "1", "-disable-update-check"]


def _build_whatweb(ctx):
    # Never follow redirects: a redirect could point WhatWeb at an internal or out-of-scope address.
    return [ctx.exe, "--aggression", "1", "--color=never", "--no-errors", "--max-threads", "2",
            "--follow-redirect=never", "--max-redirects=0",
            "--open-timeout", "10", "--read-timeout", "20", f"--log-json={ctx.out}", ctx.target]


def _build_sslyze(ctx):
    return [ctx.exe, f"--json_out={ctx.out}", "--quiet", _hostport(ctx.target, _port(ctx.options))]


def _build_testssl(ctx):
    return [ctx.exe, "--jsonfile", ctx.out, "--quiet", "--color", "0", "--warnings", "off", "--sneaky",
            _hostport(ctx.target, _port(ctx.options))]


def _build_subfinder(ctx):
    return [ctx.exe, "-d", ctx.target, "-silent", "-nc", "-oJ", "-o", ctx.out, "-timeout", "30",
            "-max-time", _minutes(ctx.timeout), "-disable-update-check"]


def _build_amass(ctx):
    return [ctx.exe, "enum", "-passive", "-nocolor", "-d", ctx.target, "-timeout", _minutes(ctx.timeout),
            "-o", ctx.out]


def _build_dnsx(ctx):
    argv = [ctx.exe, "-json", "-o", ctx.out, "-silent", "-nc", "-a", "-aaaa", "-cname", "-resp",
            "-rl", str(_bounded(ctx.options, "rate", 50, 1, 200)), "-retry", "2", "-disable-update-check"]
    wordlist = ctx.options.get("wordlist")
    if wordlist:
        return argv + ["-d", ctx.target, "-w", validate_path(wordlist, "file")]
    names = [ctx.target]
    for name in _as_list(ctx.options.get("names"))[:10000]:
        host = validate_host(name)
        if host != ctx.target and not host.endswith("." + ctx.target):
            raise TargetError(tr("Name outside the target domain: {name}", name=host))
        names.append(host)
    listing = os.path.join(ctx.tmp, "names.txt")
    with open(listing, "w", encoding="ascii") as handle:
        handle.write("\n".join(dict.fromkeys(names)) + "\n")
    return argv + ["-l", listing]


def _build_semgrep(ctx):
    config = ctx.options.get("config", "p/default")
    if not (isinstance(config, str) and _SEMGREP_CONFIG.match(config)):
        config = validate_path(config, "file")
    return [ctx.exe, "scan", "--config", config, "--json", "--output", ctx.out, "--metrics", "off", "--quiet",
            "--timeout", "30", "--disable-version-check", ctx.target]


def _build_bandit(ctx):
    return [ctx.exe, "-r", ctx.target, "-f", "json", "-o", ctx.out, "-q"]


def _build_pip_audit(ctx):
    # --disable-pip + --no-deps: audits the pinned requirements without creating a venv or running setup code.
    return [ctx.exe, "-r", ctx.target, "--disable-pip", "--no-deps", "-f", "json", "-o", ctx.out,
            "--progress-spinner", "off"]


def _build_trivy(ctx):
    return [ctx.exe, "fs", "--format", "json", "--output", ctx.out, "--quiet", "--no-progress",
            "--scanners", "vuln,secret,misconfig", ctx.target]


def _build_gitleaks(ctx):
    argv = [ctx.exe, "detect", "--source", ctx.target, "--report-format", "json", "--report-path", ctx.out,
            "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"]
    return argv if ctx.options.get("git_history") is True else argv + ["--no-git"]


# name: target kind, active rule (bool or callable on options), builder, parser, output file, description
SPECS = {
    "nmap": ("host", True, _build_nmap, parse_nmap_xml, "nmap.xml",
             "TCP connect scan with service/version detection (-sT -sV), XML output"),
    "subfinder": ("domain", False, _build_subfinder, parse_subfinder, "subfinder.jsonl",
                  "Passive subdomain enumeration from public sources"),
    "amass": ("domain", False, _build_amass, parse_amass, "amass.txt", "Passive subdomain enumeration (enum -passive)"),
    "dnsx": ("domain", lambda options: bool(options.get("wordlist")), _build_dnsx, parse_dnsx, "dnsx.jsonl",
             "DNS resolution of known names; brute force with a wordlist is active"),
    "httpx": ("url_or_host", True, _build_httpx, parse_httpx, "httpx.jsonl", "HTTP probing: status, title, server, tech"),
    "whatweb": ("url", False, _build_whatweb, parse_whatweb, "whatweb.json",
                "Technology fingerprint at aggression level 1 (one request, like the tech module)"),
    "nuclei": ("url", True, _build_nuclei, parse_nuclei, "nuclei.jsonl",
               "Template scan without intrusive/dos/fuzz tags, rate limited, no interactsh"),
    "sslyze": ("host", True, _build_sslyze, parse_sslyze, "sslyze.json", "TLS configuration scan"),
    "testssl.sh": ("host", True, _build_testssl, parse_testssl, "testssl.json", "TLS configuration scan"),
    "semgrep": ("dir", False, _build_semgrep, parse_semgrep, "semgrep.json", "Static analysis of local source code"),
    "bandit": ("path", False, _build_bandit, parse_bandit, "bandit.json", "Python static analysis of local code"),
    "pip-audit": ("file", False, _build_pip_audit, parse_pip_audit, "pip-audit.json",
                  "Known vulnerabilities in a pinned requirements file"),
    "trivy": ("path", False, _build_trivy, parse_trivy, "trivy.json",
              "Local filesystem scan: vulnerable dependencies, secrets, misconfigurations"),
    "gitleaks": ("path", False, _build_gitleaks, parse_gitleaks, "gitleaks.json", "Secret scan of local files (redacted)"),
}


class _Context:
    def __init__(self, tool, target, options, exe, tmp, out, timeout):
        self.tool, self.target, self.options, self.exe = tool, target, options, exe
        self.tmp, self.out, self.timeout = tmp, out, timeout


def is_active(tool, options=None):
    """Whether ``tool`` with these options sends traffic to the target (needs authorization)."""
    rule = SPECS[tool][1]
    return bool(rule(options or {})) if callable(rule) else bool(rule)


def describe():
    """Static metadata of every supported tool (no detection, no execution)."""
    return {name: {"target": spec[0], "active": spec[1] if isinstance(spec[1], bool) else "conditional",
                   "description": spec[5]} for name, spec in SPECS.items()}


def _validate_target(kind, target):
    if kind == "host":
        return validate_host(target)
    if kind == "domain":
        return validate_domain(target)
    if kind == "url":
        return validate_url(target)
    if kind == "url_or_host":
        return validate_url(target) if "://" in str(target) else validate_host(target)
    return validate_path(target, {"dir": "dir", "file": "file"}.get(kind, "any"))


NETWORK_KINDS = ("host", "url", "url_or_host")
UNSAFE_SUFFIXES = (".bat", ".cmd", ".ps1")


def check_address(host, allow_private=False):
    """None when ``host`` may be contacted, else ``(reason_code, message)``. Every address the name
    resolves to must be public (or private with ``allow_private``); blocked addresses are never allowed."""
    import safety
    try:
        addresses = safety.resolve_host(host)
    except (OSError, UnicodeError, ValueError) as exc:
        return "unresolved", tr("Could not resolve {host}: {error}", host=host, error=clean(exc, 120))
    if not addresses:
        return "unresolved", tr("{host} has no addresses", host=host)
    kinds = set()
    for address in addresses:
        try:
            kinds.add(safety.classify_ip(address))
        except ValueError:
            kinds.add("blocked")
    if "blocked" in kinds:
        return "blocked_address", tr("{host} resolves to a blocked address (link-local, multicast or reserved)",
                                     host=host)
    if "private" in kinds and not allow_private:
        return "private_address", tr("{host} resolves to an internal network; use --allow-private if authorized",
                                     host=host)
    return None


def _error(result, code, message, status="error"):
    result["status"], result["reason"] = status, code
    result["errors"].append({"code": code, "message": message})
    result["coverage"] = {"state": "none", "note": message}
    return result


def _command_view(argv, tmp):
    return [os.path.basename(arg) if i == 0 else arg.replace(tmp, "<tmp>") for i, arg in enumerate(argv)]


def run(tool, target, options=None, allow_active=False, scope=None, cancel=None, timeout=None,
        allow_private=False):
    """Run one optional tool safely and return a normalized result dict (never raises for tool problems).

    ``options`` per tool: nmap ``ports`` ("22,80,443" / "1-1024") or ``top_ports``; nuclei ``tags`` and
    ``rate``; httpx/dnsx ``rate``; sslyze/testssl.sh ``port``; dnsx ``names`` (list) or ``wordlist`` (active);
    semgrep ``config`` (``p/<ruleset>`` or a local rules file); gitleaks ``git_history``; all ``timeout``.
    ``allow_private`` lets network tools reach private (RFC 1918, loopback...) addresses; link-local and
    cloud-metadata addresses are always refused.
    """
    options = dict(options or {})
    result = {"tool": tool, "target": clean(target, 300), "status": "ok", "reason": None, "active": False,
              "available": None, "version": None, "install": None, "command": [], "returncode": None,
              "duration": 0.0, "findings": [], "assets": [], "components": [], "errors": [],
              "coverage": {"state": "none", "note": ""}}
    if tool not in SPECS:
        return _error(result, "unknown_tool", tr("Unknown tool: {tool}", tool=clean(tool, 40)))
    kind, _, build, parse, outname, _ = SPECS[tool]
    try:
        target = _validate_target(kind, target)
        result["target"] = target
        result["active"] = active = is_active(tool, options)
        wait = timeout if timeout is not None else options.get("timeout", DEFAULT_TIMEOUT)
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not MIN_TIMEOUT <= wait <= MAX_TIMEOUT:
            raise TargetError(tr("Option {option} must be an integer between {low} and {high}",
                                 option="timeout", low=MIN_TIMEOUT, high=MAX_TIMEOUT))
        if active:
            if not allow_active:
                return _error(result, "not_authorized", tr("{tool} is an active scanner: it needs explicit "
                                                           "authorization (allow_active) and a scope list",
                                                           tool=tool), "skipped")
            if not in_scope(_host_of(target), scope):
                return _error(result, "out_of_scope", tr("{target} is not in the authorized scope", target=target),
                              "skipped")
    except TargetError as exc:
        return _error(result, "invalid_input", str(exc))
    if kind in NETWORK_KINDS:
        refused = check_address(_host_of(target) or "", allow_private)
        if refused:
            return _error(result, refused[0], refused[1], "skipped")
    if cancel is not None and cancel.is_set():
        return _error(result, "cancelled", tr("Cancelled before start"), "skipped")

    import tools
    try:
        info = tools.detect(tool, timeout=5)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        return _error(result, "detect_failed", tr("Could not detect {tool}: {error}", tool=tool, error=clean(exc, 120)))
    result.update(available=bool(info.get("available")), version=info.get("version"), install=info.get("install"))
    if not info.get("available"):
        return _error(result, "unavailable", tr("{tool} is not installed (optional). Install: {install}",
                                                tool=tool, install=info.get("install")), "skipped")
    if info.get("compatible") is False:
        return _error(result, "incompatible", tr("{tool} {version} is older than the supported minimum {minimum}",
                                                 tool=tool, version=info.get("version"),
                                                 minimum=info.get("minimum")), "skipped")
    if str(info.get("path") or "").lower().endswith(UNSAFE_SUFFIXES):
        return _error(result, "unsafe_executable", tr("{tool} is installed as a script shim ({path}); it is not run "
                                                      "because cmd.exe would interpret its arguments. Install the "
                                                      "native executable", tool=tool,
                                                      path=os.path.basename(str(info.get("path")))), "skipped")

    tmp = tempfile.mkdtemp(prefix="domaininfo-")  # private (0700) directory
    try:
        ctx = _Context(tool, target, options, info["path"], tmp, os.path.join(tmp, outname), int(wait))
        try:
            argv = build(ctx)
        except TargetError as exc:
            return _error(result, "invalid_input", str(exc))
        result["command"] = _command_view(argv, tmp)
        try:
            proc = execute(argv, timeout=int(wait), cancel=cancel, cwd=tmp)
        except OSError as exc:
            return _error(result, "exec_failed", tr("Could not start {tool}: {error}", tool=tool, error=clean(exc, 120)))
        result.update(returncode=proc["returncode"], duration=proc["duration"])
        data, truncated = _read_output(ctx.out)
        if data is None and tool == "amass":
            data, truncated = proc["stdout"].encode(), proc["truncated"]
        if proc["cancelled"]:
            _error(result, "cancelled", tr("Cancelled by the user; the process tree was stopped"), "skipped")
        elif proc["timed_out"]:
            _error(result, "timeout", tr("{tool} exceeded the {seconds} s time limit; the process tree was killed",
                                         tool=tool, seconds=int(wait)))
        if data is None:
            if not result["errors"]:
                _error(result, "no_output", tr("{tool} produced no output (exit code {code}): {stderr}", tool=tool,
                                               code=proc["returncode"], stderr=clean(proc["stderr"], 200)))
            return result
        try:
            findings, assets, components, complete = parse(data, target)
        except (ValueError, TypeError, AttributeError, SyntaxError) as exc:
            if not result["errors"]:
                _error(result, "parse_error", tr("Could not read the {tool} output: {error}", tool=tool,
                                                 error=clean(exc, 150)))
            return result
        result.update(findings=findings, assets=assets, components=components)
        if truncated:
            result["errors"].append({"code": "truncated", "message": tr("Output larger than {size} MB was truncated",
                                                                        size=MAX_OUTPUT // (1024 * 1024))})
        partial = truncated or not complete or bool(result["errors"])
        if not result["errors"] or result["reason"] is None:
            result["coverage"] = {"state": "partial" if partial else "complete",
                                  "note": tr("Partial results") if partial else tr("Completed")}
        else:
            result["coverage"] = {"state": "partial", "note": result["errors"][0]["message"]}
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
