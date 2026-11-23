"""Local audit store for the DomainInfo Security Center (standard library only: sqlite3).

Keeps projects, the authorized scope of each project (targets), audits with their full report,
normalized findings with a review workflow (open, fixed, accepted_risk, false_positive) and its
history, and comparisons between audits. A comparison only counts as *comparable* when both audits
ran the same checks and their coverage differs by at most 10 points (same rule as
``evidence.comparable``).

    store = AuditStore()                       # default file in the user data directory
    project = store.create_project("Acme")
    store.add_target(project["id"], "example.com")
    audit = store.save_audit(project["id"], report)   # report = domaininfo.scan(...)

Every SQL statement is parameterized. The database file is created with 0600 permissions where the
platform supports them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from urllib import parse

from i18n import tr

SCHEMA_VERSION = 1
REVIEW_STATUSES = ("open", "fixed", "accepted_risk", "false_positive")
SEVERITIES = ("high", "medium", "low", "info")
SECTIONS = ("web", "auth", "infra", "tls", "maildns", "vulns")
COVERAGE_TOLERANCE = 10
MAX_NOTE = 2000
MAX_NAME = 120

# 5.x / Phase-1 Spanish enum values -> 6.0 English values (docs/I18N.md)
_SEVERITY = {"alta": "high", "media": "medium", "baja": "low", "info": "info",
             "high": "high", "medium": "medium", "low": "low", "critical": "high"}
_STATUS = {"confirmado": "confirmed", "probable": "likely", "informativo": "informational",
           "pendiente": "pending", "no_aplicable": "not_applicable", "no_evaluado": "not_evaluated"}
_CONFIDENCE = {"alta": "high", "media": "medium", "baja": "low"}
_CATEGORY = {"transporte": "transport", "redirecciones": "redirects", "cabeceras": "headers",
             "formularios": "forms", "errores": "errors", "exposicion": "exposure",
             "correo": "mail", "puertos": "ports", "subdominios": "subdomains", "registro": "registration",
             "marca": "brand", "web app": "web app"}
_SECTION_OF = {
    "web": "web", "web app": "web", "headers": "web", "csp": "web", "clickjacking": "web", "redirects": "web",
    "errors": "web", "cors": "web",
    "cookies": "auth", "forms": "auth", "csrf": "auth", "session": "auth", "sessions": "auth", "auth": "auth",
    "authentication": "auth",
    "ports": "infra", "asn": "infra", "infrastructure": "infra", "services": "infra", "mikrotik": "infra",
    "network": "infra",
    "tls": "tls", "transport": "tls", "hsts": "tls", "certificate": "tls", "certificates": "tls",
    "mail": "maildns", "dns": "maildns", "subdomains": "maildns", "registration": "maildns", "brand": "maildns",
}
EXPOSURE = {"infra": 3, "vulns": 3, "tls": 2, "web": 2, "auth": 2, "maildns": 1}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_path():
    """``%LOCALAPPDATA%\\DomainInfo\\securitycenter.db`` on Windows, XDG data dir elsewhere."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "DomainInfo"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "domaininfo"
    return base / "securitycenter.db"


def _secure_file(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def english(value, table):
    value = str(value or "").strip()
    return table.get(value.lower(), value)


def section_for(category):
    return _SECTION_OF.get(str(category or "").lower(), "vulns")


def comparable(a, b, tolerance=COVERAGE_TOLERANCE):
    """Same checks and coverage within ``tolerance`` points; missing assessments are never comparable."""
    if not isinstance(a, dict) or not isinstance(b, dict) or not a.get("checks") or not b.get("checks"):
        return False, tr("One of the audits has no coverage data")
    if set(a["checks"]) != set(b["checks"]):
        return False, tr("The audits did not run the same checks")
    gap = abs((a.get("coverage") or 0) - (b.get("coverage") or 0))
    if gap > tolerance:
        return False, tr("Coverage differs by {gap} points (maximum {max})", gap=gap, max=tolerance)
    return True, ""


def normalize_target(value):
    """Scope entries: a hostname/IP (lower case, IDNA) or a full http(s) URL kept as written."""
    value = str(value or "").strip()
    if not value or len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError(tr("Empty target or target with spaces/control characters"))
    if "://" in value:
        parts = parse.urlsplit(value)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise ValueError(tr("Only HTTP/HTTPS URLs are accepted"))
        if parts.username is not None or parts.password is not None:
            raise ValueError(tr("Credentials are not accepted in the target"))
        return parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    host = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in host.split(".")):
        raise ValueError(tr("Invalid domain"))
    return host


def host_of(value):
    value = str(value or "")
    if "://" in value:
        return (parse.urlsplit(value).hostname or "").lower()
    return value.strip("[]").lower()


def findings_from_report(report):
    """Normalized findings of a report: every module ``findings`` list plus the 5.x score findings."""
    from exporters import redact_text
    target = str((report.get("meta") or {}).get("target") or "")
    found, seen = [], set()
    for name, module in (report.get("modules") or {}).items():
        data: dict = module["data"] if isinstance(module, dict) and isinstance(module.get("data"), dict) else {}
        for item in data.get("findings") or []:
            if not isinstance(item, dict) or not item.get("title"):
                continue
            category = english(item.get("category") or name, _CATEGORY)
            found.append({
                "ext_id": str(item.get("id") or ""), "target": str(item.get("target") or target),
                "path": str(item.get("path") or ""), "category": category, "title": str(item["title"]),
                "severity": english(item.get("severity"), _SEVERITY),
                "evidence_status": english(item.get("status") or "likely", _STATUS),
                "confidence": english(item.get("confidence") or "medium", _CONFIDENCE),
                "evidence": redact_text(item.get("evidence") or "", 1000),
                "tool": str(item.get("tool") or "domaininfo." + name), "impact": str(item.get("impact") or ""),
                "verification": str(item.get("verification") or ""),
                "recommendation": str(item.get("recommendation") or ""),
                "references": [str(r) for r in item.get("references") or []][:20]})
            seen.add(str(item["title"]))
    legacy = report.get("score") if isinstance(report.get("score"), dict) else {}
    for item in legacy.get("findings") or []:
        if not isinstance(item, dict) or item.get("source") == "webapp" or item.get("title") in seen:
            continue
        area = english(item.get("area") or "", _CATEGORY)
        found.append({
            "ext_id": str(item.get("id") or ""), "target": target, "path": "", "category": area or "general",
            "title": str(item.get("title")),
            "severity": english(item.get("severity"), _SEVERITY), "evidence_status": "likely",
            "confidence": "medium", "evidence": "", "tool": "domaininfo.score", "impact": "", "verification": "",
            "recommendation": str(item.get("fix") or ""), "references": []})
    for item in found:
        if item["severity"] not in SEVERITIES:
            item["severity"] = "info"
        item["section"] = section_for(item["category"])
        host = host_of(item["target"]) or host_of(target)
        digest = "|".join((host, item["category"].lower(), item["title"]))
        # Stable identity across audits of the same host (used for review carry-over and history)
        item["key"] = host + ":" + (item["ext_id"] or "K-" + hashlib.sha256(digest.encode()).hexdigest()[:16].upper())
    return found


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    value TEXT NOT NULL, kind TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
    UNIQUE (project_id, value));
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL, target TEXT NOT NULL, mode TEXT,
    tool_version TEXT, report_date TEXT, created_at TEXT NOT NULL, grade TEXT, score INTEGER,
    security INTEGER, coverage INTEGER, confidence INTEGER, checks TEXT NOT NULL DEFAULT '[]',
    report TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audits_target ON audits (project_id, target, id);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL, key TEXT NOT NULL, ext_id TEXT, target TEXT NOT NULL, path TEXT,
    category TEXT, section TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
    evidence_status TEXT, confidence TEXT, evidence TEXT, tool TEXT, impact TEXT, verification TEXT,
    recommendation TEXT, refs TEXT NOT NULL DEFAULT '[]', review_status TEXT NOT NULL DEFAULT 'open',
    updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_audit ON findings (audit_id);
CREATE INDEX IF NOT EXISTS findings_key ON findings (project_id, key);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    project_id INTEGER NOT NULL, key TEXT NOT NULL, audit_id INTEGER, old_status TEXT, new_status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '', author TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS history_key ON finding_history (project_id, key);
CREATE TABLE IF NOT EXISTS comparisons (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    base_audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    head_audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    comparable INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', new_count INTEGER NOT NULL,
    fixed_count INTEGER NOT NULL, unchanged_count INTEGER NOT NULL, created_at TEXT NOT NULL,
    UNIQUE (base_audit_id, head_audit_id));
"""


class AuditStore:
    """Thread-safe wrapper around one SQLite file (``":memory:"`` for tests)."""

    def __init__(self, path=None):
        self.path = ":memory:" if path == ":memory:" else Path(path) if path else default_path()
        if self.path != ":memory:":
            _secure_file(self.path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock, self._db:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._migrate()

    # -- infrastructure ----------------------------------------------------------------------
    def _migrate(self):
        self._db.executescript(_SCHEMA)
        row = self._db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        version = int(row["value"]) if row else 0
        if version > SCHEMA_VERSION:
            raise RuntimeError(tr("The database was created by a newer DomainInfo (schema {version})",
                                  version=version))
        # Future migrations: ``if version < 2: ...`` before updating the stored version.
        self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                         (str(SCHEMA_VERSION),))

    def schema_version(self):
        with self._lock:
            return int(self._db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0])

    def close(self):
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _all(self, sql, params=()):
        with self._lock:
            return [dict(row) for row in self._db.execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        with self._lock:
            row = self._db.execute(sql, params).fetchone()
            return dict(row) if row else None

    # -- projects ----------------------------------------------------------------------------
    def create_project(self, name, description=""):
        name = " ".join(str(name or "").split())[:MAX_NAME]
        if not name:
            raise ValueError(tr("The project needs a name"))
        with self._lock, self._db:
            try:
                cursor = self._db.execute("INSERT INTO projects (name, description, created_at) VALUES (?, ?, ?)",
                                          (name, str(description or "")[:MAX_NOTE], _now()))
            except sqlite3.IntegrityError as exc:
                raise ValueError(tr("A project with that name already exists")) from exc
        return self.get_project(cursor.lastrowid)

    def get_project(self, project_id):
        return self._one("SELECT * FROM projects WHERE id = ?", (project_id,))

    def list_projects(self):
        return self._all(
            "SELECT p.*, (SELECT COUNT(*) FROM targets t WHERE t.project_id = p.id) AS target_count,"
            " (SELECT COUNT(*) FROM audits a WHERE a.project_id = p.id) AS audit_count,"
            " (SELECT MAX(created_at) FROM audits a WHERE a.project_id = p.id) AS last_audit"
            " FROM projects p ORDER BY p.name COLLATE NOCASE")

    def delete_project(self, project_id):
        with self._lock, self._db:
            self._db.execute("DELETE FROM finding_history WHERE project_id = ?", (project_id,))
            self._db.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
            return self._db.execute("DELETE FROM projects WHERE id = ?", (project_id,)).rowcount > 0

    # -- scope -------------------------------------------------------------------------------
    def add_target(self, project_id, value, note=""):
        if not self.get_project(project_id):
            raise KeyError(tr("Unknown project"))
        value = normalize_target(value)
        kind = "url" if "://" in value else "ip" if _is_ip(value) else "domain"
        with self._lock, self._db:
            try:
                cursor = self._db.execute(
                    "INSERT INTO targets (project_id, value, kind, note, created_at) VALUES (?, ?, ?, ?, ?)",
                    (project_id, value, kind, str(note or "")[:MAX_NOTE], _now()))
            except sqlite3.IntegrityError as exc:
                raise ValueError(tr("That target is already in the project scope")) from exc
        return self.get_target(cursor.lastrowid)

    def get_target(self, target_id):
        return self._one("SELECT * FROM targets WHERE id = ?", (target_id,))

    def list_targets(self, project_id):
        return self._all(
            "SELECT t.*, (SELECT COUNT(*) FROM audits a WHERE a.target_id = t.id) AS audit_count,"
            " (SELECT MAX(created_at) FROM audits a WHERE a.target_id = t.id) AS last_audit"
            " FROM targets t WHERE t.project_id = ? ORDER BY t.value", (project_id,))

    def remove_target(self, target_id):
        with self._lock, self._db:
            return self._db.execute("DELETE FROM targets WHERE id = ?", (target_id,)).rowcount > 0

    def in_scope(self, project_id, value):
        """The registered scope entry for ``value`` (exact match after normalization) or None."""
        try:
            value = normalize_target(value)
        except (ValueError, UnicodeError):
            return None
        return self._one("SELECT * FROM targets WHERE project_id = ? AND value = ?", (project_id, value))

    # -- audits ------------------------------------------------------------------------------
    def save_audit(self, project_id, report, target_id=None):
        """Store a report (dict from ``domaininfo.scan``) and its findings; returns the audit row.

        Review decisions carry over from the previous audit of the same target (accepted risk and false
        positives stay; a finding marked fixed that shows up again is reopened). When the previous audit
        is comparable, its open findings that disappeared are marked fixed."""
        if not isinstance(report, dict) or not isinstance(report.get("meta"), dict) \
                or not isinstance(report.get("modules"), dict):
            raise ValueError(tr("This is not a DomainInfo report"))
        if not self.get_project(project_id):
            raise KeyError(tr("Unknown project"))
        from exporters import scrub
        report = scrub(report)
        meta = report["meta"]
        target = str(meta.get("target") or "")[:2048]
        if not target:
            raise ValueError(tr("The report has no target"))
        if target_id is None:
            entry = self.in_scope(project_id, target)
            target_id = entry["id"] if entry else None
        score = report.get("score") if isinstance(report.get("score"), dict) else {}
        assessment = report.get("assessment") if isinstance(report.get("assessment"), dict) else {}
        findings = findings_from_report(report)
        now = _now()
        with self._lock, self._db:
            previous = self._db.execute(
                "SELECT id FROM audits WHERE project_id = ? AND target = ? ORDER BY id DESC LIMIT 1",
                (project_id, target)).fetchone()
            cursor = self._db.execute(
                "INSERT INTO audits (project_id, target_id, target, mode, tool_version, report_date, created_at,"
                " grade, score, security, coverage, confidence, checks, report)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project_id, target_id, target, str(meta.get("mode") or ""), str(meta.get("version") or ""),
                 str(meta.get("date") or ""), now, score.get("grade"), _int(score.get("score")),
                 _int(assessment.get("security")), _int(assessment.get("coverage")),
                 _int(assessment.get("confidence")), json.dumps(sorted(assessment.get("checks") or [])),
                 json.dumps(report, ensure_ascii=False)))
            audit_id = cursor.lastrowid
            for item in findings:
                status, note = "open", ""
                # Latest review decision for this finding in the project (any earlier audit of the target)
                last = self._db.execute(
                    "SELECT new_status FROM finding_history WHERE project_id = ? AND key = ? ORDER BY id DESC LIMIT 1",
                    (project_id, item["key"])).fetchone()
                before = {"review_status": last["new_status"]} if last else None
                if before and before["review_status"] in ("accepted_risk", "false_positive"):
                    status = before["review_status"]
                elif before and before["review_status"] == "fixed":
                    note = tr("Detected again after being marked fixed")
                cursor = self._db.execute(
                    "INSERT INTO findings (audit_id, project_id, key, ext_id, target, path, category, section, title,"
                    " severity, evidence_status, confidence, evidence, tool, impact, verification, recommendation,"
                    " refs, review_status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                    " ?, ?)",
                    (audit_id, project_id, item["key"], item["ext_id"], item["target"], item["path"],
                     item["category"], item["section"], item["title"], item["severity"], item["evidence_status"],
                     item["confidence"], item["evidence"], item["tool"], item["impact"], item["verification"],
                     item["recommendation"], json.dumps(item["references"]), status, now))
                if not before or note:
                    self._history(cursor.lastrowid, project_id, item["key"], audit_id,
                                  before["review_status"] if before else None, status,
                                  note or tr("First detected"), "domaininfo")
        audit = self.get_audit(audit_id)
        if previous:
            result = self.compare(previous["id"], audit_id)
            if result["comparable"]:
                for item in result["fixed"]:
                    if item["review_status"] == "open":
                        self.set_finding_status(item["id"], "fixed",
                                                tr("Not detected in audit #{audit}", audit=audit_id), "domaininfo")
        return audit

    def get_audit(self, audit_id, include_report=False):
        columns = "*" if include_report else ", ".join(
            ("id", "project_id", "target_id", "target", "mode", "tool_version", "report_date", "created_at", "grade",
             "score", "security", "coverage", "confidence", "checks"))
        row = self._one(f"SELECT {columns} FROM audits WHERE id = ?", (audit_id,))  # noqa: S608  # nosec B608
        if not row:
            return None
        row["checks"] = json.loads(row["checks"] or "[]")
        if include_report:
            row["report"] = json.loads(row["report"])
        row["counts"] = self.severity_counts(audit_id=audit_id)
        return row

    def list_audits(self, project_id=None, target=None, limit=200):
        sql = ("SELECT id, project_id, target_id, target, mode, tool_version, report_date, created_at, grade, score,"
               " security, coverage, confidence FROM audits WHERE 1 = 1")
        params: list = []
        if project_id is not None:
            sql += " AND project_id = ?"
            params.append(project_id)
        if target is not None:
            sql += " AND target = ?"
            params.append(target)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        rows = self._all(sql, params)
        for row in rows:
            row["counts"] = self.severity_counts(audit_id=row["id"])
        return rows

    def target_history(self, project_id, target):
        """Audits of one target, oldest first, with score trend."""
        return list(reversed(self.list_audits(project_id, target)))

    def latest_audits(self, project_id):
        """The newest audit of each target of the project."""
        return self._all(
            "SELECT a.id, a.project_id, a.target_id, a.target, a.mode, a.report_date, a.created_at, a.grade,"
            " a.score, a.security, a.coverage, a.confidence FROM audits a JOIN (SELECT MAX(id) AS id FROM audits"
            " WHERE project_id = ? GROUP BY target) newest ON newest.id = a.id ORDER BY a.target", (project_id,))

    def previous_audit(self, audit_id):
        audit = self._one("SELECT project_id, target FROM audits WHERE id = ?", (audit_id,))
        if not audit:
            return None
        return self._one("SELECT id FROM audits WHERE project_id = ? AND target = ? AND id < ? ORDER BY id DESC"
                         " LIMIT 1", (audit["project_id"], audit["target"], audit_id))

    def delete_audit(self, audit_id):
        with self._lock, self._db:
            return self._db.execute("DELETE FROM audits WHERE id = ?", (audit_id,)).rowcount > 0

    # -- findings ----------------------------------------------------------------------------
    def list_findings(self, audit_id=None, project_id=None, section=None, review_status=None, severity=None,
                      latest_only=True):
        """Findings of one audit, or of the newest audit of each target of a project."""
        sql = "SELECT * FROM findings WHERE 1 = 1"
        params: list = []
        if audit_id is not None:
            sql += " AND audit_id = ?"
            params.append(audit_id)
        elif project_id is not None:
            sql += " AND project_id = ?"
            params.append(project_id)
            if latest_only:
                sql += " AND audit_id IN (SELECT MAX(id) FROM audits WHERE project_id = ? GROUP BY target)"
                params.append(project_id)
        for column, value in (("section", section), ("review_status", review_status), ("severity", severity)):
            if value:
                sql += f" AND {column} = ?"
                params.append(value)
        sql += (" ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,"
                " target, title")
        return [_finding(row) for row in self._all(sql, params)]

    def get_finding(self, finding_id):
        row = self._one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return _finding(row) if row else None

    def set_finding_status(self, finding_id, status, note="", author="user"):
        if status not in REVIEW_STATUSES:
            raise ValueError(tr("Unknown status: {status}", status=status))
        note = str(note or "")[:MAX_NOTE]
        if status in ("accepted_risk", "false_positive") and not note.strip():
            raise ValueError(tr("Explain why with a note"))
        row = self._one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not row:
            raise KeyError(tr("Unknown finding"))
        with self._lock, self._db:
            self._db.execute("UPDATE findings SET review_status = ?, updated_at = ? WHERE id = ?",
                             (status, _now(), finding_id))
            self._history(finding_id, row["project_id"], row["key"], row["audit_id"], row["review_status"], status,
                          note, str(author or "")[:MAX_NAME])
        return self.get_finding(finding_id)

    def _history(self, finding_id, project_id, key, audit_id, old, new, note, author):
        self._db.execute(
            "INSERT INTO finding_history (finding_id, project_id, key, audit_id, old_status, new_status, note, author,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, project_id, key, audit_id, old, new, note, author, _now()))

    def finding_history(self, finding_id):
        """Every status change of this finding across all audits of the same target (same key)."""
        row = self._one("SELECT project_id, key FROM findings WHERE id = ?", (finding_id,))
        if not row:
            return []
        return self._all("SELECT * FROM finding_history WHERE project_id = ? AND key = ? ORDER BY id",
                         (row["project_id"], row["key"]))

    def project_history(self, project_id, limit=500):
        return self._all(
            "SELECT h.*, f.title, f.target, f.severity FROM finding_history h LEFT JOIN findings f"
            " ON f.id = h.finding_id WHERE h.project_id = ? ORDER BY h.id DESC LIMIT ?",
            (project_id, max(1, min(int(limit), 5000))))

    def severity_counts(self, audit_id=None, project_id=None, open_only=True):
        counts = {s: 0 for s in SEVERITIES}
        for item in self.list_findings(audit_id=audit_id, project_id=project_id):
            if not open_only or item["review_status"] == "open":
                counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        return counts

    # -- comparisons -------------------------------------------------------------------------
    def compare(self, base_id, head_id):
        """New / fixed / unchanged findings between two audits, plus whether they are comparable."""
        base = self._one("SELECT * FROM audits WHERE id = ?", (base_id,))
        head = self._one("SELECT * FROM audits WHERE id = ?", (head_id,))
        if not base or not head:
            raise KeyError(tr("Unknown audit"))
        if base["project_id"] != head["project_id"]:
            raise ValueError(tr("Both audits must belong to the same project"))
        ok, reason = comparable(_assessment(base), _assessment(head))
        if ok and host_of(base["target"]) != host_of(head["target"]):
            ok, reason = False, tr("The audits are for different targets")
        old = {f["key"]: f for f in self.list_findings(audit_id=base_id)}
        new = {f["key"]: f for f in self.list_findings(audit_id=head_id)}
        result = {"base": self.get_audit(base_id), "head": self.get_audit(head_id), "comparable": ok,
                  "reason": reason,
                  "new": [new[k] for k in new if k not in old],
                  "fixed": [old[k] for k in old if k not in new],
                  "unchanged": [new[k] for k in new if k in old],
                  "score_delta": _delta(head["score"], base["score"]),
                  "security_delta": _delta(head["security"], base["security"])}
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO comparisons (project_id, base_audit_id, head_audit_id, comparable, reason,"
                " new_count, fixed_count, unchanged_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (base["project_id"], base_id, head_id, int(ok), reason, len(result["new"]), len(result["fixed"]),
                 len(result["unchanged"]), _now()))
        return result

    def list_comparisons(self, project_id):
        return self._all("SELECT * FROM comparisons WHERE project_id = ? ORDER BY id DESC", (project_id,))

    # -- dashboards and exports ----------------------------------------------------------------
    def overview(self, project_id=None):
        projects = [self.get_project(project_id)] if project_id else self.list_projects()
        projects = [p for p in projects if p]
        latest = [a for p in projects for a in self.latest_audits(p["id"])]
        counts = {s: 0 for s in SEVERITIES}
        sections = {s: 0 for s in SECTIONS}
        reviews = {s: 0 for s in REVIEW_STATUSES}
        for project in projects:
            for item in self.list_findings(project_id=project["id"]):
                reviews[item["review_status"]] += 1
                if item["review_status"] == "open":
                    counts[item["severity"]] += 1
                    sections[item["section"]] += 1
        trend = []
        for audit in latest:
            previous = self.previous_audit(audit["id"])
            trend.append({"target": audit["target"], "audit_id": audit["id"],
                          "previous_id": previous["id"] if previous else None,
                          "history": [{"id": a["id"], "date": a["created_at"], "score": a["score"],
                                       "security": a["security"]}
                                      for a in self.target_history(audit["project_id"], audit["target"])[-12:]]})
        return {"projects": len(projects), "targets": sum(len(self.list_targets(p["id"])) for p in projects),
                "audits": sum(len(self.list_audits(p["id"])) for p in projects), "latest": latest,
                "open_by_severity": counts, "open_by_section": sections, "by_review_status": reviews,
                "trend": trend}

    def report_bundle(self, project_id, audit_id=None):
        """Everything the exporters need for a project (or one audit), already redacted."""
        project = self.get_project(project_id)
        if not project:
            raise KeyError(tr("Unknown project"))
        if audit_id is not None:
            audit = self.get_audit(audit_id)
            if not audit or audit["project_id"] != project_id:
                raise KeyError(tr("Unknown audit"))
            audits = [audit]
            findings = self.list_findings(audit_id=audit_id)
        else:
            audits = [row for row in (self.get_audit(a["id"]) for a in self.latest_audits(project_id)) if row]
            findings = self.list_findings(project_id=project_id)
        comparisons = []
        for audit in audits:
            previous = self.previous_audit(audit["id"])
            if previous:
                result = self.compare(previous["id"], audit["id"])
                comparisons.append({"target": audit["target"], "base": previous["id"], "head": audit["id"],
                                    "comparable": result["comparable"], "reason": result["reason"],
                                    "new": len(result["new"]), "fixed": len(result["fixed"]),
                                    "unchanged": len(result["unchanged"]), "score_delta": result["score_delta"]})
        return {"project": project, "audits": audits, "findings": findings, "comparisons": comparisons,
                "history": self.project_history(project_id), "generated": _now()}


def _assessment(audit_row):
    return {"checks": json.loads(audit_row["checks"] or "[]"), "coverage": audit_row["coverage"] or 0}


def _finding(row):
    row = dict(row)
    row["references"] = json.loads(row.pop("refs") or "[]")
    from exporters import priority
    row["priority"] = priority(row)
    return row


def _int(value):
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _delta(a, b):
    return a - b if isinstance(a, int) and isinstance(b, int) else None


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
