"""Vulnerability intelligence for DomainInfo 6.0 (Phase 3): OSV, NVD CVE API 2.0 and CISA KEV.

Public API::

    vulnintel.correlate(components, client=None, use_osv=True, use_nvd=True, use_kev=True,
                        keyword_search=True, cancel=None) -> dict
    vulnintel.Client(cache=None, api_key=None, timeout=20, offline=False, fetch=None)
        .osv(name, ecosystem, version) / .nvd_cpe(cpe) / .nvd_keyword(text) / .kev()
    vulnintel.Cache(directory=None, clock=time.time)          # on-disk JSON cache with TTL
    vulnintel.RateLimiter(calls, period, clock=..., sleep=...) # sliding-window limiter (NVD)
    vulnintel.cache_dir() -> Path
    vulnintel.cvss3_score(vector) -> float | None

A component is ``{"name", "version", "cpe"?, "ecosystem"?, "evidence"?}``. ``evidence == "direct"``
means the version was read from the asset itself (banner, lockfile, pinned manifest).

Match types and statuses:

* ``exact`` - OSV says that package+version is affected, or an NVD CPE range contains the version.
  Status ``confirmed`` only when the component version came from direct evidence, otherwise ``likely``.
* ``name_only`` - NVD returned the CVE for the CPE but no range in its configurations proves the version.
* ``keyword`` - NVD keyword search by name/version. Both are ``pending`` and are never confirmed.

Only fixed HTTPS endpoints are contacted; responses have size caps and timeouts.
"""

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime, timezone
from urllib import error, parse, request

from i18n import tr

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_ALLOWED = (OSV_URL, NVD_URL, KEV_URL)
TTL = {"osv": 24 * 3600, "nvd": 24 * 3600, "kev": 12 * 3600}
LIMITS = {"osv": 5 * 1024 * 1024, "nvd": 16 * 1024 * 1024, "kev": 24 * 1024 * 1024}
NVD_WINDOW = 30.0
NVD_CALLS = {False: 5, True: 50}          # requests per 30 s without / with an API key
MAX_COMPONENTS = 500
MAX_RESULTS_PER_QUERY = 50
USER_AGENT = "DomainInfo-vulnintel"
_SAFE = re.compile(r"[\w .:+~@/-]{1,200}\Z")
_CPE23 = re.compile(r"cpe:2\.3:[aoh](?::[^:\s]+){10}\Z")


class SourceError(Exception):
    """A vulnerability source failed (network, HTTP status, size or format)."""


def cache_dir():
    """Per-user cache directory: %LOCALAPPDATA%\\DomainInfo\\cache on Windows, XDG_CACHE_HOME or ~/.cache."""
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"]) / "DomainInfo" / "cache"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "domaininfo"
    return base / "vulnintel"


def _now_iso(clock=time.time):
    return datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds")


class Cache:
    """JSON files keyed by sha256; each entry stores ``fetched_at`` (ISO) and ``ts`` (epoch)."""

    def __init__(self, directory=None, clock=time.time):
        self.directory = Path(directory) if directory else cache_dir()
        self.clock = clock

    def _path(self, source, key):
        return self.directory / f"{source}-{hashlib.sha256(key.encode()).hexdigest()[:40]}.json"

    def get(self, source, key, ttl):
        """Cached entry ``{"fetched_at", "ts", "data"}`` younger than ``ttl`` seconds, else None."""
        try:
            with open(self._path(source, key), encoding="utf-8") as handle:
                entry = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict) or not isinstance(entry.get("ts"), (int, float)):
            return None
        return entry if 0 <= self.clock() - entry["ts"] < ttl else None

    def put(self, source, key, data):
        entry = {"fetched_at": _now_iso(self.clock), "ts": self.clock(), "key": key[:300], "data": data}
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self._path(source, key)
            tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(entry, handle)
            os.replace(tmp, path)
        except OSError:
            pass  # a read-only cache never breaks the audit
        return entry


class RateLimiter:
    """At most ``calls`` acquisitions per ``period`` seconds (sliding window, thread safe)."""

    def __init__(self, calls, period, clock=time.monotonic, sleep=time.sleep):
        self.calls, self.period, self.clock, self.sleep = calls, period, clock, sleep
        self.stamps, self.lock = [], threading.Lock()

    def acquire(self, cancel=None):
        while True:
            with self.lock:
                now = self.clock()
                self.stamps = [t for t in self.stamps if now - t < self.period]
                if len(self.stamps) < self.calls:
                    self.stamps.append(now)
                    return
                wait = self.period - (now - self.stamps[0])
            if cancel is not None and cancel.is_set():
                raise SourceError(tr("Cancelled"))
            self.sleep(max(wait, 0.01))


_LIMITERS = {}
_LIMITERS_LOCK = threading.Lock()


def nvd_limiter(has_key):
    with _LIMITERS_LOCK:
        if has_key not in _LIMITERS:
            _LIMITERS[has_key] = RateLimiter(NVD_CALLS[has_key], NVD_WINDOW)
        return _LIMITERS[has_key]


def _http(url, body=None, headers=None, timeout=20, limit=1024 * 1024):
    """GET/POST to one of the fixed HTTPS endpoints; returns parsed JSON."""
    base = url.split("?", 1)[0]
    if base not in _ALLOWED:
        raise SourceError(tr("Endpoint not allowed: {url}", url=base))
    data = json.dumps(body).encode() if body is not None else None
    req = request.Request(url, data=data, method="POST" if data is not None else "GET",  # noqa: S310
                          headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                   **({"Content-Type": "application/json"} if data is not None else {}),
                                   **(headers or {})})
    try:
        # Fixed https:// endpoints from _ALLOWED only (checked above).
        with request.urlopen(req, timeout=timeout) as response:  # noqa: S310  # nosec B310
            raw = response.read(limit + 1)
    except error.HTTPError as exc:
        raise SourceError(tr("HTTP {status} from {url}", status=exc.code, url=base)) from exc
    except (error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        # HTTPException (e.g. IncompleteRead) is not an OSError and must not escape the scan
        raise SourceError(tr("Request to {url} failed: {error}", url=base, error=str(exc)[:150])) from exc
    if len(raw) > limit:
        raise SourceError(tr("Response from {url} exceeds {size} bytes", url=base, size=limit))
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise SourceError(tr("Invalid JSON from {url}", url=base)) from exc


class Client:
    """Cached access to OSV, NVD and KEV. ``fetch(url, body, headers, timeout, limit)`` can be injected."""

    def __init__(self, cache=None, api_key=None, timeout=20, offline=False, fetch=None, limiter=None):
        self.cache = cache if cache is not None else Cache()
        self.api_key = api_key if api_key is not None else (os.environ.get("NVD_API_KEY") or None)
        self.timeout, self.offline, self.fetch = timeout, offline, fetch or _http
        self.limiter = limiter or nvd_limiter(bool(self.api_key))
        self.sources = {}

    def _cached(self, source, key, call):
        entry = self.cache.get(source, key, TTL[source])
        if entry is None:
            if self.offline:
                raise SourceError(tr("Offline mode and no fresh cache for {source}", source=source))
            entry = self.cache.put(source, key, call())
            cached = False
        else:
            cached = True
        info = self.sources.setdefault(source, {"requests": 0, "cached": 0, "fetched_at": entry["fetched_at"]})
        info["cached" if cached else "requests"] += 1
        info["fetched_at"] = min(info["fetched_at"], entry["fetched_at"])
        return entry["data"], entry["fetched_at"]

    def osv(self, name, ecosystem, version):
        body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        return self._cached("osv", json.dumps(body, sort_keys=True), lambda: self.fetch(
            OSV_URL, body, None, self.timeout, LIMITS["osv"]))

    def _nvd(self, params, cancel=None):
        query = parse.urlencode({**params, "resultsPerPage": MAX_RESULTS_PER_QUERY})

        def call():
            self.limiter.acquire(cancel)
            headers = {"apiKey": self.api_key} if self.api_key else None
            return self.fetch(NVD_URL + "?" + query, None, headers, self.timeout, LIMITS["nvd"])
        return self._cached("nvd", query, call)

    def nvd_cpe(self, cpe, cancel=None):
        return self._nvd({"cpeName": cpe}, cancel)

    def nvd_keyword(self, text, cancel=None):
        return self._nvd({"keywordSearch": text}, cancel)

    def kev(self):
        """Mapping CVE id -> KEV entry (vendor, product, dateAdded, dueDate, knownRansomwareCampaignUse)."""
        data, fetched_at = self._cached("kev", "catalog", lambda: self.fetch(
            KEV_URL, None, None, self.timeout, LIMITS["kev"]))
        rows = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        return {str(r.get("cveID", "")).upper(): r for r in rows if isinstance(r, dict) and r.get("cveID")}, fetched_at


# --------------------------------------------------------------------------------------------
# Versions and CVSS
# --------------------------------------------------------------------------------------------
def _vkey(version):
    """Comparable key: numeric parts as numbers, text parts after numbers (1.2 < 1.2.1 < 1.10)."""
    parts = re.findall(r"\d+|[a-z]+", str(version).lower())
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts)


def version_in_range(version, exact=None, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    key = _vkey(version)
    if exact not in (None, "*", "-", ""):
        return key == _vkey(exact)
    if not any((start_incl, start_excl, end_incl, end_excl)):
        return False  # "any version" is not proof that this version is affected
    return ((start_incl is None or key >= _vkey(start_incl)) and (start_excl is None or key > _vkey(start_excl))
            and (end_incl is None or key <= _vkey(end_incl)) and (end_excl is None or key < _vkey(end_excl)))


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value):
    integer = round(value * 100000)
    return integer / 100000.0 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Base score of a CVSS v3.x vector string, or None if it cannot be parsed."""
    try:
        metrics = dict(part.split(":", 1) for part in str(vector).split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10) if scope_changed else min(impact + exploit, 10))


def _severity(score, kev=False):
    if kev or (score is not None and score >= 7.0):
        return "high"
    if score is None:
        return "medium"
    return "medium" if score >= 4.0 else ("low" if score > 0 else "info")


# --------------------------------------------------------------------------------------------
# Normalization of source records
# --------------------------------------------------------------------------------------------
def _osv_record(vuln):
    aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
    cvss = None
    for item in vuln.get("severity", []) or []:
        if isinstance(item, dict) and str(item.get("type", "")).startswith("CVSS_V3"):
            cvss = {"version": "3", "vector": item.get("score"), "score": cvss3_score(item.get("score"))}
            break
    specific = vuln.get("database_specific") if isinstance(vuln.get("database_specific"), dict) else {}
    return {"vuln_id": vuln.get("id"), "aliases": aliases, "summary": (vuln.get("summary") or vuln.get("details") or "")[:300],
            "cvss": cvss, "cwe": [c for c in specific.get("cwe_ids", []) if isinstance(c, str)],
            "references": [r.get("url") for r in vuln.get("references", []) if isinstance(r, dict) and r.get("url")][:10],
            "updated_at": vuln.get("modified"), "published": vuln.get("published"), "source": "osv"}


def _nvd_cvss(metrics):
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        for metric in metrics.get(key, []) or []:
            data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
            if data.get("baseScore") is not None:
                return {"version": version, "vector": data.get("vectorString"), "score": data.get("baseScore")}
    return None


def _nvd_record(item):
    cve = item.get("cve", {}) if isinstance(item, dict) else {}
    description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if str(d.get("value", "")).startswith("CWE-")})
    return {"vuln_id": cve.get("id"), "aliases": [], "summary": description[:300],
            "cvss": _nvd_cvss(cve.get("metrics", {}) or {}), "cwe": cwes,
            "references": [r.get("url") for r in cve.get("references", []) if r.get("url")][:10],
            "updated_at": cve.get("lastModified"), "published": cve.get("published"), "source": "nvd",
            "nvd_kev": bool(cve.get("cisaExploitAdd")), "_configurations": cve.get("configurations", [])}


def _nvd_proves(record, cpe, version):
    """True when a vulnerable cpeMatch for the same vendor:product contains ``version``."""
    wanted = cpe.split(":")[3:5]
    for config in record.get("_configurations") or []:
        for node in config.get("nodes", []) if isinstance(config, dict) else []:
            for match in node.get("cpeMatch", []) if isinstance(node, dict) else []:
                criteria = str(match.get("criteria", "")).split(":")
                if not match.get("vulnerable") or criteria[3:5] != wanted or len(criteria) < 6:
                    continue
                if version_in_range(version, criteria[5], match.get("versionStartIncluding"),
                                    match.get("versionStartExcluding"), match.get("versionEndIncluding"),
                                    match.get("versionEndExcluding")):
                    return True
    return False


def _cve_ids(record):
    ids = [record["vuln_id"]] + record["aliases"]
    return sorted({str(i).upper() for i in ids if str(i).upper().startswith("CVE-")})


def _component(raw):
    if not isinstance(raw, dict):
        return None
    name, version = str(raw.get("name") or "").strip(), str(raw.get("version") or "").strip()
    if not (_SAFE.match(name) and _SAFE.match(version)) or len(version) > 100:
        return None
    cpe = raw.get("cpe")
    ecosystem = raw.get("ecosystem")
    evidence = raw.get("evidence")
    if isinstance(evidence, dict):
        evidence = evidence.get("type")
    return {"name": name, "version": version, "cpe": cpe if isinstance(cpe, str) and _CPE23.match(cpe) else None,
            "ecosystem": ecosystem if isinstance(ecosystem, str) and _SAFE.match(ecosystem) else None,
            "direct": evidence == "direct", "evidence": evidence if isinstance(evidence, str) else None,
            "location": str(raw.get("location") or raw.get("source") or "")[:300]}


def _finding(match, target):
    import runners
    cvss = match["cvss"] or {}
    detail = [f"{match['source'].upper()} {match['vuln_id']}", f"match={match['match_type']}",
              f"version_evidence={match['version_evidence'] or 'unknown'}"]
    if cvss.get("score") is not None:
        detail.append(f"CVSS {cvss.get('version')}={cvss['score']}")
    if match["cwe"]:
        detail.append(",".join(match["cwe"][:3]))
    if match["kev"]:
        detail.append("CISA KEV")
    verification = {
        "confirmed": tr("Version read directly from the asset and listed as affected by the advisory."),
        "likely": tr("The advisory covers this version, but the version was not read directly; confirm it."),
        "pending": tr("Name or keyword match only: check that the product and version really match."),
    }[match["status"]]
    return runners.make_finding(
        target or match["location"] or match["component"], "vulnerable_component",
        tr("{component} {version} is affected by {vuln_id}", component=match["component"], version=match["version"],
           vuln_id=match["vuln_id"]),
        match["severity"], match["status"], {"confirmed": "high", "likely": "medium"}.get(match["status"], "low"),
        "; ".join(detail), "vulnintel." + match["source"], path=match["location"],
        impact=match["summary"][:300], verification=verification,
        recommendation=tr("Upgrade {component} to a version that fixes {vuln_id}.", component=match["component"],
                          vuln_id=match["vuln_id"]), references=match["references"])


def _status(match_type, direct):
    if match_type != "exact":
        return "pending"
    return "confirmed" if direct else "likely"


def correlate(components, client=None, use_osv=True, use_nvd=True, use_kev=True, keyword_search=True,
              cancel=None, target=None):
    """Match components against OSV/NVD and flag CISA KEV entries.

    Returns ``{"matches": [...], "findings": [...], "errors": [...], "sources": {...}, "skipped": [...]}``.
    Source failures are recorded in ``errors`` and never raise.
    """
    client = client or Client()
    result = {"matches": [], "findings": [], "errors": [], "sources": {}, "skipped": []}
    merged = {}
    seen = set()
    for raw in list(components or [])[:MAX_COMPONENTS]:
        if cancel is not None and cancel.is_set():
            result["errors"].append({"source": "vulnintel", "message": tr("Cancelled")})
            break
        comp = _component(raw)
        if comp is None:
            result["skipped"].append({"component": str((raw or {}).get("name", ""))[:100] if isinstance(raw, dict)
                                      else "", "reason": tr("Missing or invalid name/version")})
            continue
        key = (comp["name"].lower(), comp["version"], comp["cpe"], comp["ecosystem"])
        if key in seen:
            continue
        seen.add(key)
        records = []  # (record, match_type)
        if use_osv and comp["ecosystem"]:
            try:
                data, _ = client.osv(comp["name"], comp["ecosystem"], comp["version"])
                records += [(_osv_record(v), "exact") for v in (data or {}).get("vulns", []) if isinstance(v, dict)]
            except SourceError as exc:
                result["errors"].append({"source": "osv", "component": comp["name"], "message": str(exc)})
        if use_nvd and comp["cpe"]:
            try:
                data, _ = client.nvd_cpe(comp["cpe"], cancel)
                for item in (data or {}).get("vulnerabilities", [])[:MAX_RESULTS_PER_QUERY]:
                    record = _nvd_record(item)
                    records.append((record, "exact" if _nvd_proves(record, comp["cpe"], comp["version"])
                                    else "name_only"))
            except SourceError as exc:
                result["errors"].append({"source": "nvd", "component": comp["name"], "message": str(exc)})
        elif use_nvd and keyword_search and not comp["ecosystem"]:
            try:
                data, _ = client.nvd_keyword(f"{comp['name']} {comp['version']}", cancel)
                records += [(_nvd_record(item), "keyword")
                            for item in (data or {}).get("vulnerabilities", [])[:MAX_RESULTS_PER_QUERY]]
            except SourceError as exc:
                result["errors"].append({"source": "nvd", "component": comp["name"], "message": str(exc)})
        rank = {"exact": 0, "name_only": 1, "keyword": 2}
        for record, match_type in records:
            if not record.get("vuln_id"):
                continue
            ids = _cve_ids(record)
            canonical = ids[0] if ids else str(record["vuln_id"])
            mkey = (comp["name"].lower(), comp["version"], canonical)
            match = merged.get(mkey)
            if match is None:
                match = merged[mkey] = {
                    "component": comp["name"], "version": comp["version"], "cpe": comp["cpe"],
                    "ecosystem": comp["ecosystem"], "version_evidence": comp["evidence"], "location": comp["location"],
                    "vuln_id": canonical, "aliases": [], "source": record["source"], "sources": [],
                    "match_type": match_type, "summary": record["summary"], "cvss": record["cvss"],
                    "cwe": [], "references": [], "updated_at": record["updated_at"], "published": record["published"],
                    "kev": bool(record.get("nvd_kev")), "_direct": comp["direct"]}
            if rank[match_type] < rank[match["match_type"]]:
                match["match_type"] = match_type
            match["sources"] = sorted(set(match["sources"]) | {record["source"]})
            match["aliases"] = sorted(set(match["aliases"]) | set(ids + [str(record["vuln_id"])]) - {canonical})
            match["cwe"] = sorted(set(match["cwe"]) | set(record["cwe"]))
            match["references"] = list(dict.fromkeys(match["references"] + record["references"]))[:10]
            match["kev"] = match["kev"] or bool(record.get("nvd_kev"))
            match["cvss"] = match["cvss"] or record["cvss"]
            match["summary"] = match["summary"] or record["summary"]
            if record["updated_at"] and (not match["updated_at"] or record["updated_at"] > match["updated_at"]):
                match["updated_at"] = record["updated_at"]
    kev = {}
    if use_kev and merged:
        try:
            kev, _ = client.kev()
        except SourceError as exc:
            result["errors"].append({"source": "kev", "message": str(exc)})
    for match in merged.values():
        ids = {match["vuln_id"]} | set(match["aliases"])
        hit = next((kev[i] for i in ids if i in kev), None)
        if hit:
            match["kev"] = True
            match["kev_date_added"] = hit.get("dateAdded")
        direct = match.pop("_direct")
        match["status"] = _status(match["match_type"], direct)
        score = (match["cvss"] or {}).get("score")
        match["severity"] = _severity(score if isinstance(score, (int, float)) else None, match["kev"])
        result["matches"].append(match)
        result["findings"].append(_finding(match, target))
    result["matches"].sort(key=lambda m: ({"confirmed": 0, "likely": 1, "pending": 2}[m["status"]],
                                          {"high": 0, "medium": 1, "low": 2, "info": 3}[m["severity"]], m["vuln_id"]))
    result["sources"] = client.sources
    return result
