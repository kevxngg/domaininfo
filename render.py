"""Readable reports: plain text, Markdown and HTML with the grade, findings and details.

Reuses the menu summaries (terminal_ui) so the terminal and the files say the same thing.
The full JSON is kept inside the HTML. Text follows the active language (``i18n``).
"""

import argparse
import html
import io
import re

import i18n
from i18n import tr

SEVERITY = {"high": ("HIGH", "#ef4444"), "medium": ("MEDIUM", "#f59e0b"),
            "low": ("LOW", "#38bdf8"), "info": ("INFO", "#94a3b8")}
GRADE_COLORS = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}


def _severity(level):
    """(translated label, color) of a severity; unknown values are shown as they are."""
    label, color = SEVERITY.get(level, (str(level).upper(), "#94a3b8"))
    return tr(label), color


def _app(core, buffer):
    from terminal_ui import InteractiveApp
    return InteractiveApp(core, argparse.Namespace(), output=buffer)


def module_lines(core, name, module):
    buffer = io.StringIO()
    try:
        _app(core, buffer).module_summary(name, module)
    except (TypeError, KeyError, AttributeError, ValueError):
        return [tr("(summary not available; see the JSON)")]
    return [line[2:] if line.startswith("  ") else line for line in buffer.getvalue().splitlines()]


def _labels():
    from terminal_ui import MODULE_LABELS, MODULE_HELP
    return ({name: tr(text) for name, text in MODULE_LABELS.items()},
            {name: tr(text) for name, text in MODULE_HELP.items()})


def _md(value):
    """Escape remote text so it cannot form links, images or HTML in Markdown."""
    return re.sub(r"([\\`*_{}\[\]()<>#|!])", r"\\\1", str(value))


def evidence_findings(report):
    """Findings with the evidence model from every module that produces them (webapp, auth, api, zap,
    browser, tools, intel). They are already redacted."""
    found = []
    for module in (report.get("modules") or {}).values():
        data = module.get("data") if isinstance(module, dict) else None
        if module.get("status") == "ok" and isinstance(data, dict) and isinstance(data.get("findings"), list):
            found += [f for f in data["findings"] if isinstance(f, dict) and f.get("status") and f.get("id")]
    return found


def assessment_line(report):
    a = report.get("assessment")
    if not isinstance(a, dict):
        return None
    return tr("Security {security}/100 · Coverage {coverage}% · Confidence {confidence}%",
              security=a.get("security"), coverage=a.get("coverage"), confidence=a.get("confidence"))


def _finding_fields(f):
    import evidence
    status = evidence.STATUS_LABELS.get(f["status"], f["status"])
    confidence = f.get("confidence")
    if confidence in ("high", "medium", "low"):
        confidence = tr(confidence)
    fields = [(tr("Path"), f.get("path")), (tr("Tool"), f.get("tool")), (tr("Evidence"), f.get("evidence")),
              (tr("Impact"), f.get("impact")), (tr("Safe verification"), f.get("verification")),
              (tr("Fix"), f.get("recommendation")), (tr("References"), ", ".join(f.get("references") or []))]
    badge = tr("{severity} · {status} · confidence {confidence}", severity=_severity(f["severity"])[0],
               status=tr(status), confidence=confidence)
    return fields, badge


def to_text(core, report, serialized=None):
    labels, _ = _labels()
    meta = report.get("meta", {})
    out = [f"DomainInfo {meta.get('version', '')} · {meta.get('target', '')}",
           tr("Date: {date} · mode: {mode}", date=meta.get("date", ""), mode=meta.get("mode", "")), ""]
    line = assessment_line(report)
    if line:
        out += [tr("ASSESSMENT: {line}", line=line), ""]
    findings = evidence_findings(report)
    if findings:
        out.append(tr("FINDINGS WITH EVIDENCE"))
        for f in findings:
            fields, badge = _finding_fields(f)
            out.append(f"  {f['id']} [{badge}] {f['category']}: {f['title']}")
            out += [f"      {name}: {value}" for name, value in fields if value]
        out.append("")
    score = report.get("score")
    if isinstance(score, dict) and score.get("grade"):
        out.append(tr("SECURITY GRADE: {grade} ({score}/100)", grade=score["grade"], score=score["score"]))
        for finding in score.get("findings", []):
            out.append(f"  [{_severity(finding['severity'])[0]}] {tr(finding['area'])}: {finding['title']}")
            out.append("      " + tr("How to fix: {fix}", fix=finding["fix"]))
        out.append("")
    for name, module in (report.get("modules") or {}).items():
        out.append(labels.get(name, name).upper())
        out.extend("  " + line for line in module_lines(core, name, module))
        out.append("")
    if not report.get("modules"):
        out.append(serialized or "")
    return "\n".join(out).rstrip() + "\n"


def to_markdown(core, report, serialized=None):
    labels, helps = _labels()
    meta = report.get("meta", {})
    out = [f"# DomainInfo · {meta.get('target', '')}", "",
           "*" + tr("{date} · mode `{mode}` · DomainInfo {version}", date=meta.get("date", ""),
                    mode=meta.get("mode", ""), version=meta.get("version", "")) + "*", ""]
    score = report.get("score")
    if isinstance(score, dict) and score.get("grade"):
        out += ["## " + tr("Security grade: **{grade}** ({score}/100)", grade=score["grade"], score=score["score"]), ""]
        if score.get("findings"):
            out += [tr("| Level | Area | Finding | How to fix |"), "|---|---|---|---|"]
            for f in score["findings"]:
                cells = [_severity(f["severity"])[0], tr(f["area"]), f["title"], f["fix"]]
                out.append("| " + " | ".join(_md(c) for c in cells) + " |")
            out.append("")
        out += [f"> {score.get('note', '')}", ""]
    line = assessment_line(report)
    if line:
        out += [tr("**Assessment:** {line}", line=line), ""]
    findings = evidence_findings(report)
    if findings:
        out += ["## " + tr("Findings with evidence"), ""]
        for f in findings:
            fields, badge = _finding_fields(f)
            out += [f"### {_md(f['id'])} · {_md(f['title'])}", "", f"*{_md(badge)} · {_md(f['category'])}*", ""]
            out += ["- **" + name + ":** " + _md(value) for name, value in fields if value]
            out.append("")
    for name, module in (report.get("modules") or {}).items():
        out += [f"## {labels.get(name, name)}", "", f"_{helps.get(name, '')}_", ""]
        out += [f"- {_md(line.strip())}" for line in module_lines(core, name, module) if line.strip()]
        out.append("")
    if not report.get("modules"):
        out += ["```json", serialized or "", "```"]
    return "\n".join(out).rstrip() + "\n"


CSS = """
:root{color-scheme:dark;--bg:#0b1120;--card:#111a2e;--line:#1e2a44;--text:#e5e7eb;--muted:#94a3b8;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;gap:20px;align-items:center;flex-wrap:wrap;margin-bottom:20px}
.grade{width:96px;height:96px;border-radius:24px;display:grid;place-items:center;font-size:52px;font-weight:800;color:#0b1120}
h1{margin:0;font-size:26px;overflow-wrap:anywhere}h2{margin:0 0 4px;font-size:18px}
.muted{color:var(--muted);font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;margin:14px 0}
.finding{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:10px 0;border-top:1px solid var(--line)}
.finding:first-of-type{border-top:0}.badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:999px;color:#0b1120;height:fit-content}
.fix{grid-column:2;color:var(--muted);font-size:14px}
.status{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);margin-left:8px}
ul{margin:8px 0 0;padding-left:20px}li{overflow-wrap:anywhere}
details{margin-top:18px}summary{cursor:pointer;color:var(--accent)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#0a0f1c;border:1px solid var(--line);border-radius:12px;padding:12px}
footer{margin-top:28px;color:var(--muted);font-size:13px}
"""


def to_html(core, report, serialized):
    labels, helps = _labels()
    meta = report.get("meta", {})
    esc = html.escape
    parts = [f"<!doctype html><html lang='{i18n.language()}'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             f"<title>DomainInfo · {esc(str(meta.get('target', '')))}</title><style>{CSS}</style></head><body><main>"]
    score = report.get("score") if isinstance(report.get("score"), dict) else None
    grade = score.get("grade") if score else None
    parts.append("<header>")
    if grade:
        parts.append(f"<div class='grade' style='background:{GRADE_COLORS.get(grade, '#94a3b8')}'>{esc(grade)}</div>")
    subtitle = tr("{date} · mode {mode} · DomainInfo {version}", date=meta.get("date", ""),
                  mode=meta.get("mode", ""), version=meta.get("version", ""))
    if grade:
        subtitle += " · " + tr("grade {grade} ({score}/100)", grade=grade, score=score["score"])
    parts.append(f"<div><h1>{esc(str(meta.get('target', '')))}</h1><div class='muted'>"
                 f"{esc(subtitle)}</div></div></header>")
    if score and score.get("findings"):
        parts.append(f"<section class='card'><h2>{esc(tr('Findings'))}</h2>")
        for f in score["findings"]:
            label, color = _severity(f["severity"])
            fix = tr("How to fix: {fix}", fix=f["fix"])
            parts.append(f"<div class='finding'><span class='badge' style='background:{color}'>{esc(label)}</span>"
                         f"<div><b>{esc(tr(f['area']))}</b> · {esc(f['title'])}</div>"
                         f"<div class='fix'>{esc(fix)}</div></div>")
        parts.append(f"<p class='muted'>{esc(score.get('note', ''))}</p></section>")
    line = assessment_line(report)
    findings = evidence_findings(report)
    if line or findings:
        parts.append(f"<section class='card'><h2>{esc(tr('Findings with evidence'))}</h2>")
        if line:
            parts.append(f"<p class='muted'>{esc(line)}</p>")
        for f in findings:
            fields, badge = _finding_fields(f)
            label, color = _severity(f["severity"])
            parts.append(f"<div class='finding'><span class='badge' style='background:{color}'>"
                         f"{esc(label)}</span><div><b>{esc(f['id'])}</b> · "
                         f"{esc(f['title'])}<div class='muted'>{esc(badge)} · {esc(f['category'])}</div></div>")
            parts += [f"<div class='fix'><b>{esc(name)}:</b> {esc(str(value))}</div>" for name, value in fields if value]
            parts.append("</div>")
        parts.append("</section>")
    for name, module in (report.get("modules") or {}).items():
        states = {"ok": "done", "error": "error", "skipped": "skipped"}
        status = tr(states[module.get("status")]) if module.get("status") in states else module.get("status")
        parts.append(f"<section class='card'><h2>{esc(labels.get(name, name))}<span class='status'>{esc(str(status))}</span></h2>"
                     f"<div class='muted'>{esc(helps.get(name, ''))}</div><ul>")
        parts += [f"<li>{esc(line.strip())}</li>" for line in module_lines(core, name, module) if line.strip()]
        parts.append("</ul></section>")
    parts.append(f"<details><summary>{esc(tr('Full technical data (JSON)'))}</summary><pre>"
                 + esc(serialized) + "</pre></details>")
    parts.append("<footer>" + esc(tr("Generated with DomainInfo by @kevxngg. Findings are indicative and based on "
                                     "public information; only review targets you are authorized to audit."))
                 + "</footer>")
    parts.append("</main></body></html>")
    return "".join(parts)
