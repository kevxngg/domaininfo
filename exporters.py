"""Exports of the DomainInfo Security Center: CSV of findings and PDF reports (standard library only).

The PDF writer is deliberately small: the 14 built-in fonts (Helvetica and Helvetica-Bold) with
WinAnsi (cp1252) text, so no font is embedded and no third-party library is needed. It supports
headings, wrapped paragraphs, tables with automatic page breaks and coloured severity badges.

Everything that goes into an export passes through :func:`redact_text` / :func:`scrub` first. Reports
are already redacted when they are created, but an export is the place where data leaves the machine,
so cookies, tokens, keys and similar values are stripped again here.

    data = store.report_bundle(project_id)
    Path("exec.pdf").write_bytes(executive_pdf(data))
    Path("tech.pdf").write_bytes(technical_pdf(data))
    Path("findings.csv").write_text(findings_csv(data["findings"]), encoding="utf-8")
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from i18n import tr

# ---------------------------------------------------------------------------------------------
# Redaction (local copy of the evidence-style rules so this module never depends on evidence.py)
# ---------------------------------------------------------------------------------------------
_WORDS = (r"(?:sess|sid|token|csrf|xsrf|auth|jwt|secret|passw|pwd|apikey|api_key|cookie|key|"  # noqa: S105
          r"code|sig|signature|ticket|nonce)")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     lambda m: "-----BEGIN PRIVATE KEY-----[redacted]"),
    (re.compile(r"(?i)\b(set-cookie|cookie|authorization|x-api-key|x-auth-token)([ \t]*:[ \t]*)[^\r\n]{1,4000}"),
     lambda m: m.group(1) + m.group(2) + "[redacted]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: mask(m.group(0))),
    (re.compile(r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}"), lambda m: mask(m.group(0))),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[\w-]{10,}|AIza[\w-]{35}|sk_live_[\w]{16,})"),
     lambda m: mask(m.group(0))),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), lambda m: m.group(1) + " [redacted]"),
    (re.compile(r"(?i)(?<![\w.-])(?=[\w.-]{0,64}?" + _WORDS + r")([\w.-]{1,64})"
                r"([\"']?[ \t]*[=:][ \t]*[\"']?)([^\s;,\"'&<>]{4,})"),
     lambda m: m.group(1) + m.group(2) + mask(m.group(3))),
)
_SECRET_KEY = re.compile(r"(?i)(?:^|[_.-])(?:session|sess|sid|token|csrf_token|xsrf|jwt|secret|password|passwd|"
                         r"pwd|apikey|api_key|cookie|set-cookie|authorization|private_key|access_key)(?:$|[_.-])")
REDACT_INPUT_LIMIT = 8000


def mask(value):
    value = str(value)
    if "[redacted]" in value or "[oculto]" in value:
        return value
    return value[:4] + "...[redacted]" if len(value) > 8 else "[redacted]"


def redact_text(text, limit=600):
    """Remove recognizable secrets and control characters, collapse whitespace, cut to ``limit``."""
    text = str(text or "")[:REDACT_INPUT_LIMIT]
    for pattern, replace in _PATTERNS:
        text = pattern.sub(replace, text)
    text = _CONTROL.sub("", re.sub(r"[ \t\r\n]+", " ", text)).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def scrub(value, key="") -> Any:
    """Recursive copy of a report with secret-named string fields masked and text fields redacted."""
    if isinstance(value, dict):
        return {k: scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, key) for v in value]
    if isinstance(value, str):
        if key and _SECRET_KEY.search(key) and value:
            return mask(value)
        if len(value) > 24:
            # long text may embed a header or a key=value pair; short ones (dates, enums) are left alone
            for pattern, replace in _PATTERNS:
                value = pattern.sub(replace, value)
        return _CONTROL.sub("", value)
    return value


# ---------------------------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------------------------
SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}
EVIDENCE_WEIGHT = {"confirmed": 1.0, "likely": 0.7, "pending": 0.4, "informational": 0.2}
REVIEW_WEIGHT = {"open": 1.0, "accepted_risk": 0.3, "fixed": 0.0, "false_positive": 0.0}
EXPOSURE = {"infra": 3, "vulns": 3, "tls": 2, "web": 2, "auth": 2, "maildns": 1}


def priority(finding):
    """Remediation priority 0-27: severity x status (evidence and review) x exposure."""
    severity = SEVERITY_WEIGHT.get(finding.get("severity"), 0)
    status = EVIDENCE_WEIGHT.get(finding.get("evidence_status"), 0.3) * \
        REVIEW_WEIGHT.get(finding.get("review_status", "open"), 1.0)
    exposure = EXPOSURE.get(finding.get("section"), 2)
    return round(severity * 3 * status * exposure, 1)


def remediation_plan(findings):
    return sorted((f for f in findings if f.get("review_status", "open") == "open" and priority(f) > 0),
                  key=lambda f: (-priority(f), f.get("target", ""), f.get("title", "")))


# ---------------------------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------------------------
CSV_COLUMNS = ("id", "key", "target", "path", "category", "section", "title", "severity", "evidence_status",
               "confidence", "review_status", "priority", "evidence", "tool", "impact", "verification",
               "recommendation", "references", "audit_id")


def _cell(value):
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(v) for v in value)
    text = redact_text(value, 4000) if value is not None else ""
    # Spreadsheet formula injection: neutralize cells that a spreadsheet would evaluate
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def findings_csv(findings):
    """CSV (RFC 4180, UTF-8 text) with one row per finding."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for item in findings:
        row = dict(item, priority=priority(item))
        writer.writerow([_cell(row.get(column)) for column in CSV_COLUMNS])
    return out.getvalue()


# ---------------------------------------------------------------------------------------------
# Minimal PDF writer
# ---------------------------------------------------------------------------------------------
_HELVETICA = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
    556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
    556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722,
    500, 500, 500, 334, 260, 334, 584)
_HELVETICA_BOLD = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722,
    611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556,
    611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778,
    556, 556, 500, 389, 280, 389, 584)
PAGE_W, PAGE_H, MARGIN = 595.28, 841.89, 48.0
INK = (0.09, 0.13, 0.20)
MUTED = (0.38, 0.43, 0.50)
RULE = (0.80, 0.83, 0.87)
BADGE = {"high": (0.70, 0.14, 0.09), "medium": (0.71, 0.33, 0.03), "low": (0.20, 0.42, 0.67),
         "info": (0.40, 0.44, 0.52)}


def text_width(text, size, bold=False):
    table = _HELVETICA_BOLD if bold else _HELVETICA
    total = 0
    for char in text:
        code = ord(char)
        total += table[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000.0


def wrap(text, width, size, bold=False):
    """Greedy word wrap with hard breaks for words longer than a line."""
    lines = []
    for paragraph in str(text).split("\n"):
        line = ""
        for word in paragraph.split(" "):
            candidate = (line + " " + word) if line else word
            if text_width(candidate, size, bold) <= width:
                line = candidate
                continue
            if line:
                lines.append(line)
            while text_width(word, size, bold) > width and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines or [""]


def _pdf_string(text):
    data = str(text).encode("cp1252", "replace")
    out = bytearray(b"(")
    for byte in data:
        if byte in (0x28, 0x29, 0x5C):
            out += b"\\" + bytes([byte])
        elif byte < 32 or byte == 127:
            out += b"\\%03o" % byte
        else:
            out.append(byte)
    return bytes(out + b")")


def _color(rgb, stroke=False):
    return ("%.3f %.3f %.3f " % rgb + ("RG" if stroke else "rg")).encode()


class PDFDocument:
    """A4 pages with a moving cursor; call :meth:`render` to get the PDF bytes."""

    def __init__(self, title, subtitle=""):
        self.title, self.subtitle = title, subtitle
        self.pages: list[list[bytes]] = []
        self.y = 0.0
        self.new_page()

    # -- primitives ---------------------------------------------------------------------------
    @property
    def ops(self):
        return self.pages[-1]

    def new_page(self):
        self.pages.append([])
        self.y = PAGE_H - MARGIN - 18

    def ensure(self, height):
        if self.y - height < MARGIN + 24:
            self.new_page()

    def text(self, x, y, value, size=10.0, bold=False, color=INK):
        self.ops.append(b"BT " + _color(color) + b" /" + (b"F2" if bold else b"F1") + b" %.1f Tf %.2f %.2f Td "
                        % (size, x, y) + _pdf_string(value) + b" Tj ET")

    def rect(self, x, y, w, h, color):
        self.ops.append(_color(color) + b" %.2f %.2f %.2f %.2f re f" % (x, y, w, h))

    def line(self, x1, y1, x2, y2, color=RULE, width=0.6):
        self.ops.append(_color(color, True) + b" %.2f w %.2f %.2f m %.2f %.2f l S" % (width, x1, y1, x2, y2))

    # -- blocks -------------------------------------------------------------------------------
    def heading(self, value, level=1):
        size = {1: 18, 2: 13, 3: 11}[level]
        self.ensure(size * 2.6)
        self.y -= size * (1.1 if level == 1 else 1.4)
        self.text(MARGIN, self.y, value, size, True)
        self.y -= size * 0.6
        if level <= 2:
            self.line(MARGIN, self.y, PAGE_W - MARGIN, self.y, RULE if level == 2 else INK, 0.6 if level == 2 else 1)
            self.y -= 6

    def paragraph(self, value, size=9.5, bold=False, color=INK, indent=0.0):
        leading = size * 1.35
        for line in wrap(redact_text(value, 6000), PAGE_W - 2 * MARGIN - indent, size, bold):
            self.ensure(leading)
            self.y -= leading
            self.text(MARGIN + indent, self.y, line, size, bold, color)
        self.y -= size * 0.4

    def badge(self, x, y, severity, size=7.5):
        label = severity_label(severity)
        width = text_width(label, size, True) + 8
        self.rect(x, y - 2.5, width, size + 4, BADGE.get(severity, MUTED))
        self.text(x + 4, y, label, size, True, (1, 1, 1))
        return width

    def table(self, columns, rows, size=8.5):
        """``columns`` = [(header, relative width)]; a cell may be ("badge", severity)."""
        total = sum(w for _, w in columns)
        usable = PAGE_W - 2 * MARGIN
        widths = [usable * w / total for _, w in columns]
        leading = size * 1.3

        def header():
            self.ensure(leading + 6)
            self.y -= leading + 2
            self.rect(MARGIN, self.y - 4, usable, leading + 4, (0.93, 0.94, 0.96))
            x = MARGIN
            for (name, _), width in zip(columns, widths, strict=True):
                self.text(x + 3, self.y, name, size, True, MUTED)
                x += width
            self.y -= 6
        header()
        for row in rows:
            cells = []
            for cell, width in zip(row, widths, strict=True):
                if isinstance(cell, tuple) and cell and cell[0] == "badge":
                    cells.append(cell)
                else:
                    cells.append(wrap(redact_text(cell, 1500), width - 6, size)[:40])
            height = max(1 if isinstance(c, tuple) else len(c) for c in cells) * leading + 4
            if self.y - height < MARGIN + 24:
                self.new_page()
                header()
            top = self.y
            x = MARGIN
            for cell, width in zip(cells, widths, strict=True):
                if isinstance(cell, tuple):
                    self.badge(x + 3, top - leading, cell[1], size - 1)
                else:
                    for index, line in enumerate(cell):
                        self.text(x + 3, top - leading * (index + 1), line, size)
                x += width
            self.y = top - height
            self.line(MARGIN, self.y + 1, PAGE_W - MARGIN, self.y + 1, RULE, 0.4)
        self.y -= 6

    def field(self, label, value):
        if value in (None, "", []):
            return
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        self.ensure(24)
        self.y -= 11
        self.text(MARGIN + 8, self.y, label, 8, True, MUTED)
        self.paragraph(value, 9, indent=8)

    # -- output -------------------------------------------------------------------------------
    def render(self):
        count = len(self.pages)
        for number, ops in enumerate(self.pages, 1):
            top = PAGE_H - MARGIN + 6
            ops.insert(0, b"BT " + _color(MUTED) + b" /F1 8 Tf %.2f %.2f Td " % (MARGIN, top)
                       + _pdf_string(self.title + (" - " + self.subtitle if self.subtitle else "")) + b" Tj ET")
            footer = tr("Page {page} of {pages}", page=number, pages=count)
            ops.append(b"BT " + _color(MUTED) + b" /F1 8 Tf %.2f %.2f Td " % (
                PAGE_W - MARGIN - text_width(footer, 8), MARGIN - 20) + _pdf_string(footer) + b" Tj ET")
            ops.append(b"BT " + _color(MUTED) + b" /F1 8 Tf %.2f %.2f Td " % (MARGIN, MARGIN - 20)
                       + _pdf_string(tr("DomainInfo Security Center - confidential")) + b" Tj ET")
        objects: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"",  # pages, filled below
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
            b"<< /Producer " + _pdf_string("DomainInfo Security Center") + b" /Title " + _pdf_string(self.title)
            + b" >>",
        ]
        kids = []
        for ops in self.pages:
            stream = b"\n".join(ops)
            objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
            content = len(objects)
            objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R"
                           b" /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>" % (PAGE_W, PAGE_H, content))
            kids.append(b"%d 0 R" % len(objects))
        objects[1] = b"<< /Type /Pages /Kids [" + b" ".join(kids) + b"] /Count %d >>" % count
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
        for offset in offsets:
            out += b"%010d 00000 n \n" % offset
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
        return bytes(out)


# ---------------------------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------------------------
def severity_label(value):
    return {"high": tr("High"), "medium": tr("Medium"), "low": tr("Low"), "info": tr("Info")}.get(value, str(value))


def review_label(value):
    return {"open": tr("Open"), "fixed": tr("Fixed"), "accepted_risk": tr("Accepted risk"),
            "false_positive": tr("False positive")}.get(value, str(value or ""))


def evidence_label(value):
    return {"confirmed": tr("Confirmed"), "likely": tr("Likely"), "informational": tr("Informational"),
            "pending": tr("Pending verification"), "not_applicable": tr("Not applicable"),
            "not_evaluated": tr("Not evaluated"), "error": tr("Check error")}.get(value, str(value or ""))


def _num(value):
    return "-" if value is None else str(value)


def _subtitle(data):
    return str((data.get("project") or {}).get("name") or "")


def _counts(findings):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        if item.get("review_status", "open") == "open" and item.get("severity") in counts:
            counts[item["severity"]] += 1
    return counts


def _cover(doc, data, title):
    doc.y -= 10
    doc.text(MARGIN, doc.y, title, 22, True)
    doc.y -= 20
    doc.text(MARGIN, doc.y, tr("Project: {name}", name=_subtitle(data)), 11)
    doc.y -= 14
    doc.text(MARGIN, doc.y, tr("Generated: {date} (UTC)", date=str(data.get("generated", ""))[:19]), 9, False, MUTED)
    doc.y -= 10


# ---------------------------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------------------------
def executive_pdf(data):
    """Executive summary: grades, Security/Coverage/Confidence, counts, top risks, trend."""
    data = scrub(data)
    findings = data.get("findings") or []
    doc = PDFDocument(tr("Executive security report"), _subtitle(data))
    _cover(doc, data, tr("Executive security report"))

    doc.heading(tr("Open findings by severity"), 2)
    counts = _counts(findings)
    doc.ensure(30)
    doc.y -= 18
    x = MARGIN
    for severity, number in counts.items():
        x += doc.badge(x, doc.y, severity, 9) + 6
        doc.text(x, doc.y, str(number), 14, True)
        x += text_width(str(number), 14, True) + 22
    doc.y -= 12

    doc.heading(tr("Scores by target"), 2)
    doc.paragraph(tr("Security measures the risk of what was checked; Coverage, how much could be checked; "
                     "Confidence, how much rests on direct evidence. Grade is the classic A-F score."), 8.5,
                  color=MUTED)
    doc.table([(tr("Target"), 4), (tr("Date"), 2), (tr("Grade"), 1), (tr("Score"), 1), (tr("Security"), 1.3),
               (tr("Coverage"), 1.3), (tr("Confidence"), 1.4)],
              [[a.get("target"), str(a.get("created_at", ""))[:10], a.get("grade") or "-", _num(a.get("score")),
                _num(a.get("security")), _num(a.get("coverage")), _num(a.get("confidence"))]
               for a in data.get("audits") or []] or [[tr("No audits yet"), "", "", "", "", "", ""]])

    doc.heading(tr("Top risks"), 2)
    top = remediation_plan(findings)[:10]
    if top:
        doc.table([(tr("Severity"), 1.2), (tr("Finding"), 5), (tr("Target"), 3), (tr("Status"), 1.6)],
                  [[("badge", f.get("severity")), f.get("title"), f.get("target"),
                    evidence_label(f.get("evidence_status"))] for f in top])
    else:
        doc.paragraph(tr("No open findings with risk."))

    doc.heading(tr("Trend against the previous audit"), 2)
    rows = []
    for item in data.get("comparisons") or []:
        rows.append([item.get("target"), tr("Yes") if item.get("comparable") else tr("No") + ": " +
                     str(item.get("reason") or ""), str(item.get("new")), str(item.get("fixed")),
                     str(item.get("unchanged")), _num(item.get("score_delta"))])
    if rows:
        doc.table([(tr("Target"), 3), (tr("Comparable"), 3), (tr("New"), 1), (tr("Fixed"), 1),
                   (tr("Unchanged"), 1.4), (tr("Score change"), 1.4)], rows)
    else:
        doc.paragraph(tr("There is no previous audit to compare with."))
    doc.paragraph(tr("Only audits with the same checks and coverage within 10 points are comparable; "
                     "otherwise new and fixed counts may reflect a different scope, not a real change."),
                  8.5, color=MUTED)
    return doc.render()


def technical_pdf(data):
    """Technical report: every finding with its evidence, the remediation plan and the change history."""
    data = scrub(data)
    findings = data.get("findings") or []
    doc = PDFDocument(tr("Technical security report"), _subtitle(data))
    _cover(doc, data, tr("Technical security report"))

    doc.heading(tr("Remediation plan"), 2)
    doc.paragraph(tr("Ordered by priority = severity x status (evidence and review) x exposure."), 8.5, color=MUTED)
    plan = remediation_plan(findings)
    if plan:
        doc.table([(tr("Priority"), 1), (tr("Severity"), 1.2), (tr("Finding"), 4), (tr("Target"), 2.5),
                   (tr("Remediation"), 4)],
                  [[str(priority(f)), ("badge", f.get("severity")), f.get("title"), f.get("target"),
                    f.get("recommendation") or "-"] for f in plan])
    else:
        doc.paragraph(tr("No open findings with risk."))

    doc.heading(tr("Findings"), 2)
    active = [f for f in findings if f.get("review_status") != "false_positive"]
    if not active:
        doc.paragraph(tr("No findings."))
    for item in active:
        doc.ensure(60)
        doc.y -= 16
        width = doc.badge(MARGIN, doc.y, item.get("severity"), 8)
        title = wrap(redact_text(item.get("title"), 400), PAGE_W - 2 * MARGIN - width - 8, 10.5, True)
        doc.text(MARGIN + width + 6, doc.y, title[0], 10.5, True)
        for extra in title[1:]:
            doc.y -= 13
            doc.text(MARGIN + width + 6, doc.y, extra, 10.5, True)
        doc.y -= 4
        doc.field(tr("ID"), "%s (%s)" % (item.get("ext_id") or item.get("key"), item.get("id")))
        doc.field(tr("Target and path"), str(item.get("target") or "") + (
            "  " + str(item["path"]) if item.get("path") else ""))
        doc.field(tr("Category"), item.get("category"))
        doc.field(tr("Status"), tr("{evidence} - review: {review}", evidence=evidence_label(item.get(
            "evidence_status")), review=review_label(item.get("review_status"))))
        doc.field(tr("Confidence"), item.get("confidence"))
        doc.field(tr("Evidence"), item.get("evidence"))
        doc.field(tr("Tool"), item.get("tool"))
        doc.field(tr("Impact"), item.get("impact"))
        doc.field(tr("Safe verification"), item.get("verification"))
        doc.field(tr("Remediation"), item.get("recommendation"))
        doc.field(tr("References"), item.get("references"))
        doc.y -= 4
        doc.line(MARGIN, doc.y, PAGE_W - MARGIN, doc.y)

    doc.heading(tr("False positives"), 2)
    false = [f for f in findings if f.get("review_status") == "false_positive"]
    if false:
        notes = {}
        for event in data.get("history") or []:
            if event.get("new_status") == "false_positive":
                notes.setdefault(event.get("key"), event.get("note"))
        doc.table([(tr("Severity"), 1.2), (tr("Finding"), 4), (tr("Target"), 2.5), (tr("Reason"), 4)],
                  [[("badge", f.get("severity")), f.get("title"), f.get("target"), notes.get(f.get("key"), "")]
                   for f in false])
    else:
        doc.paragraph(tr("No findings marked as false positives."))

    doc.heading(tr("Change history"), 2)
    history = data.get("history") or []
    if history:
        doc.table([(tr("Date"), 2), (tr("Finding"), 4), (tr("Change"), 2.6), (tr("Note"), 3.5), (tr("By"), 1.2)],
                  [[str(h.get("created_at", ""))[:16].replace("T", " "), h.get("title") or h.get("key"),
                    (review_label(h.get("old_status")) + " > " if h.get("old_status") else "")
                    + review_label(h.get("new_status")), h.get("note"), h.get("author")] for h in history[:400]])
    else:
        doc.paragraph(tr("No changes recorded."))
    return doc.render()
