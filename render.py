"""Reportes legibles: texto plano, Markdown y HTML con nota, hallazgos y detalle.

Reutiliza los resúmenes del menú (terminal_ui) para que la terminal y los archivos
digan lo mismo. El JSON completo se conserva dentro del HTML.
"""

import argparse
import html
import io
import re

SEVERITY = {"alta": ("ALTA", "#ef4444"), "media": ("MEDIA", "#f59e0b"),
            "baja": ("BAJA", "#38bdf8"), "info": ("INFO", "#94a3b8")}
GRADE_COLORS = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}


def _app(core, buffer):
    from terminal_ui import InteractiveApp
    return InteractiveApp(core, argparse.Namespace(), output=buffer)


def module_lines(core, name, module):
    buffer = io.StringIO()
    try:
        _app(core, buffer).module_summary(name, module)
    except (TypeError, KeyError, AttributeError, ValueError):
        return ["(resumen no disponible; consulta el JSON)"]
    return [line[2:] if line.startswith("  ") else line for line in buffer.getvalue().splitlines()]


def _labels():
    from terminal_ui import MODULE_LABELS, MODULE_HELP
    return MODULE_LABELS, MODULE_HELP


def _md(value):
    """Escapa el texto remoto para que no forme enlaces, imágenes ni HTML en Markdown."""
    return re.sub(r"([\\`*_{}\[\]()<>#|!])", r"\\\1", str(value))


def evidence_findings(report):
    """Hallazgos con el modelo de evidencias (Fase 1: módulo webapp). Ya vienen redactados."""
    module = (report.get("modules") or {}).get("webapp") or {}
    data = module.get("data")
    if module.get("status") != "ok" or not isinstance(data, dict):
        return []
    return data.get("findings", [])


def assessment_line(report):
    a = report.get("assessment")
    if not isinstance(a, dict):
        return None
    return (f"Seguridad {a.get('security')}/100 · Cobertura {a.get('coverage')}% · "
            f"Confianza {a.get('confidence')}%")


def _finding_fields(f):
    import evidence
    return [("Ruta", f.get("path")), ("Herramienta", f.get("tool")), ("Evidencia", f.get("evidence")),
            ("Impacto", f.get("impact")), ("Verificación segura", f.get("verification")),
            ("Corrección", f.get("recommendation")), ("Referencias", ", ".join(f.get("references") or []))], \
        f"{SEVERITY[f['severity']][0]} · {evidence.STATUS_LABELS.get(f['status'], f['status'])} · confianza {f.get('confidence')}"


def to_text(core, report, serialized=None):
    labels, _ = _labels()
    meta = report.get("meta", {})
    out = [f"DomainInfo {meta.get('version', '')} · {meta.get('target', '')}",
           f"Fecha: {meta.get('date', '')} · modo: {meta.get('mode', '')}", ""]
    line = assessment_line(report)
    if line:
        out += ["EVALUACIÓN: " + line, ""]
    findings = evidence_findings(report)
    if findings:
        out.append("HALLAZGOS CON EVIDENCIA")
        for f in findings:
            fields, badge = _finding_fields(f)
            out.append(f"  {f['id']} [{badge}] {f['category']}: {f['title']}")
            out += [f"      {name}: {value}" for name, value in fields if value]
        out.append("")
    score = report.get("score")
    if isinstance(score, dict) and score.get("grade"):
        out.append(f"NOTA DE SEGURIDAD: {score['grade']} ({score['score']}/100)")
        for finding in score.get("findings", []):
            out.append(f"  [{SEVERITY[finding['severity']][0]}] {finding['area']}: {finding['title']}")
            out.append(f"      Cómo arreglarlo: {finding['fix']}")
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
           f"*{meta.get('date', '')} · modo `{meta.get('mode', '')}` · DomainInfo {meta.get('version', '')}*", ""]
    score = report.get("score")
    if isinstance(score, dict) and score.get("grade"):
        out += [f"## Nota de seguridad: **{score['grade']}** ({score['score']}/100)", ""]
        if score.get("findings"):
            out += ["| Nivel | Área | Hallazgo | Cómo arreglarlo |", "|---|---|---|---|"]
            for f in score["findings"]:
                cells = [SEVERITY[f["severity"]][0], f["area"], f["title"], f["fix"]]
                out.append("| " + " | ".join(_md(c) for c in cells) + " |")
            out.append("")
        out += [f"> {score.get('note', '')}", ""]
    line = assessment_line(report)
    if line:
        out += [f"**Evaluación:** {line}", ""]
    findings = evidence_findings(report)
    if findings:
        out += ["## Hallazgos con evidencia", ""]
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
    parts = ["<!doctype html><html lang='es'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             f"<title>DomainInfo · {esc(str(meta.get('target', '')))}</title><style>{CSS}</style></head><body><main>"]
    score = report.get("score") if isinstance(report.get("score"), dict) else None
    grade = score.get("grade") if score else None
    parts.append("<header>")
    if grade:
        parts.append(f"<div class='grade' style='background:{GRADE_COLORS.get(grade, '#94a3b8')}'>{esc(grade)}</div>")
    parts.append(f"<div><h1>{esc(str(meta.get('target', '')))}</h1><div class='muted'>"
                 f"{esc(str(meta.get('date', '')))} · modo {esc(str(meta.get('mode', '')))} · "
                 f"DomainInfo {esc(str(meta.get('version', '')))}"
                 + (f" · nota {esc(grade)} ({score['score']}/100)" if grade else "") + "</div></div></header>")
    if score and score.get("findings"):
        parts.append("<section class='card'><h2>Hallazgos</h2>")
        for f in score["findings"]:
            label, color = SEVERITY[f["severity"]]
            parts.append(f"<div class='finding'><span class='badge' style='background:{color}'>{label}</span>"
                         f"<div><b>{esc(f['area'])}</b> · {esc(f['title'])}</div>"
                         f"<div class='fix'>Cómo arreglarlo: {esc(f['fix'])}</div></div>")
        parts.append(f"<p class='muted'>{esc(score.get('note', ''))}</p></section>")
    line = assessment_line(report)
    findings = evidence_findings(report)
    if line or findings:
        parts.append("<section class='card'><h2>Hallazgos con evidencia</h2>")
        if line:
            parts.append(f"<p class='muted'>{esc(line)}</p>")
        for f in findings:
            fields, badge = _finding_fields(f)
            color = SEVERITY[f["severity"]][1]
            parts.append(f"<div class='finding'><span class='badge' style='background:{color}'>"
                         f"{esc(SEVERITY[f['severity']][0])}</span><div><b>{esc(f['id'])}</b> · "
                         f"{esc(f['title'])}<div class='muted'>{esc(badge)} · {esc(f['category'])}</div></div>")
            parts += [f"<div class='fix'><b>{esc(name)}:</b> {esc(str(value))}</div>" for name, value in fields if value]
            parts.append("</div>")
        parts.append("</section>")
    for name, module in (report.get("modules") or {}).items():
        status = {"ok": "listo", "error": "error", "skipped": "omitido"}.get(module.get("status"), module.get("status"))
        parts.append(f"<section class='card'><h2>{esc(labels.get(name, name))}<span class='status'>{esc(str(status))}</span></h2>"
                     f"<div class='muted'>{esc(helps.get(name, ''))}</div><ul>")
        parts += [f"<li>{esc(line.strip())}</li>" for line in module_lines(core, name, module) if line.strip()]
        parts.append("</ul></section>")
    parts.append("<details><summary>Datos técnicos completos (JSON)</summary><pre>"
                 + esc(serialized) + "</pre></details>")
    parts.append("<footer>Generado con DomainInfo por @kevxngg. Los hallazgos son orientativos y se basan en "
                 "información pública; revisa solo objetivos que tengas autorización para auditar.</footer>")
    parts.append("</main></body></html>")
    return "".join(parts)
