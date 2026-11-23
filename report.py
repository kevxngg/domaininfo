#!/usr/bin/env python3
"""
report.py — HTML Report Generator for DomainInfo v3.2.0
Author: @kevxngg (Kevin)
Usage: python3 report.py <log_file.txt> [output.html]
"""

import sys
import os
import re
import html
from datetime import datetime

import i18n
from i18n import tr

VERSION = "4.3.0"

TEMPLATE = """<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DomainInfo Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --dim: #8b949e;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
    --blue: #58a6ff; --purple: #bc8cff; --cyan: #39d353;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
  header {{ background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%); border: 1px solid var(--border); border-radius: 12px; padding: 30px; margin-bottom: 24px; }}
  header h1 {{ font-size: 1.8rem; color: var(--blue); margin-bottom: 8px; }}
  header .meta {{ color: var(--dim); font-size: 0.9rem; display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.78rem; font-weight: 600; }}
  .badge-blue {{ background: rgba(88,166,255,0.2); color: var(--blue); border: 1px solid rgba(88,166,255,0.4); }}
  .badge-green {{ background: rgba(63,185,80,0.2); color: var(--green); border: 1px solid rgba(63,185,80,0.4); }}
  .badge-red {{ background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid rgba(248,81,73,0.4); }}
  .section {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
  .section h2 {{ font-size: 1rem; color: var(--blue); margin-bottom: 16px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
  .kv-table {{ width: 100%; border-collapse: collapse; }}
  .kv-table td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); font-size: 0.88rem; }}
  .kv-table td:first-child {{ color: var(--dim); width: 35%; }}
  .kv-table td:last-child {{ color: var(--text); font-family: monospace; word-break: break-all; }}
  .finding {{ display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px; border-radius: 8px; margin-bottom: 8px; font-size: 0.88rem; }}
  .finding-critical {{ background: rgba(248,81,73,0.1); border-left: 3px solid var(--red); }}
  .finding-high {{ background: rgba(210,153,34,0.1); border-left: 3px solid var(--yellow); }}
  .finding-medium {{ background: rgba(88,166,255,0.1); border-left: 3px solid var(--blue); }}
  .finding-low {{ background: rgba(63,185,80,0.1); border-left: 3px solid var(--green); }}
  pre {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 14px;
         font-size: 0.82rem; overflow-x: auto; color: var(--cyan); line-height: 1.5; white-space: pre-wrap; word-break: break-word; }}
  footer {{ text-align: center; color: var(--dim); font-size: 0.82rem; padding: 24px; }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🔍 DomainInfo Security Report</h1>
  <div style="margin-top:10px;">
    <span style="font-size:1.3rem; font-weight:700; color: var(--text);">{target}</span>
    <span style="margin-left:12px;" class="badge badge-blue">v{version}</span>
  </div>
  <div class="meta">
    <span>📅 {date}</span>
    <span>👤 @kevxngg (Kevin)</span>
    <span>🔒 {authorized}</span>
  </div>
</header>

{content}

<footer>
  <p>{generated}</p>
  <p style="margin-top:4px;">{confidential}</p>
</footer>
</div>
</body>
</html>"""


# ── ANSI stripping ────────────────────────────────────────────────
# Covers: CSI sequences (\x1b[...m), OSC hyperlinks (\x1b]8;;...\x1b\\),
# and stray escape characters.
_ANSI_RE = re.compile(
    r'\x1b'
    r'(?:'
    r'\[[0-9;:<=>?]*[ -/]*[@-~]'   # CSI sequences (colors, cursor, etc.)
    r'|'
    r'\][^\x07\x1b]*(?:\x07|\x1b\\)'  # OSC sequences (hyperlinks, title)
    r'|'
    r'[@-_][0-?]*[ -/]*[@-~]?'     # Other 2-character sequences
    r')'
)


def strip_ansi(text: str) -> str:
    """Remove every ANSI/VT100 escape sequence from a string."""
    return _ANSI_RE.sub('', text)


def parse_log(log_path: str) -> dict:
    """
    Parse a DomainInfo log file.
    Reads the structured header block ('Key : Value' lines)
    and keeps the rest as the raw log to show in full.
    """
    data = {
        "target":     "Unknown",
        "date":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "fields":     {},
        "raw_lines":  [],
        "findings":   [],
    }

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(tr("Error reading the log: {error}", error=e))
        return data

    # Keep clean lines (without ANSI)
    data["raw_lines"] = [strip_ansi(l.rstrip()) for l in lines]

    # ── Parse the structured header fields ────────────────────────
    # save_log in domaininfo.sh writes lines such as:
    #   "Domain     : value"  (older versions: "Dominio    : valor")
    #   "IP         : value"
    header_field_re = re.compile(
        r'^([A-ZÁÉÍÓÚÑa-záéíóúñ][A-ZÁÉÍÓÚÑa-záéíóúñ0-9 _/()]*?)\s*:\s*(.+)$'
    )

    in_header = False
    for line in data["raw_lines"]:
        stripped = line.strip()

        # Detect the start/end of the header block
        if "===" in stripped and "DomainInfo" in stripped:
            in_header = True
            continue
        if "===" in stripped and in_header:
            in_header = False

        # Extract "Report: TARGET" (or the Spanish "Reporte:") for the report title
        m = re.search(r'(?:Report|Reporte):\s*(.+)', stripped)
        if m:
            data["target"] = m.group(1).strip()

        # Extract "Date:" (or "Fecha:") from the header
        m = re.search(r'^(?:Date|Fecha)\s+:\s+([^|]+)', stripped)
        if m:
            data["date"] = m.group(1).strip()

        # Parse key-value fields of the structured header
        m = header_field_re.match(stripped)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            # Skip separator lines and 1-character keys
            if len(key) > 1 and val not in ("", "==="):
                data["fields"][key] = val

        # Detect findings (lines with security markers); Spanish markers come from older logs
        low = stripped.lower()
        if any(k in stripped for k in ["EXPOSED", "LISTED", "CRITICAL", "EXPUESTO", "LISTADO", "CRITICO", "⚠", " VULN "]):
            data["findings"].append(("critical", stripped))
        elif any(k in low for k in ["high:", "high ", "alto:", "alto ", "vulnerable", "exposed", "expuesto"]):
            data["findings"].append(("high", stripped))
        elif any(k in low for k in ["[!]", "warn", "medium:", "medio:"]):
            data["findings"].append(("medium", stripped))

    return data


def generate_html(log_path: str, output_path: str) -> None:
    """Build the HTML report from a DomainInfo log."""
    data = parse_log(log_path)
    html_sections = []
    summary_title, log_title = tr("Executive summary"), tr("Full log")

    # ── Section: executive summary ────────────────────────────────
    if data["fields"]:
        rows = ""
        for k, v in list(data["fields"].items())[:20]:
            # Escape HTML to avoid XSS in keys and values
            k_safe = html.escape(k)
            v_safe = html.escape(v)

            # Color by content
            if any(w in v.lower() for w in ["critical", "high", "vulnerable", "exposed", "listed", "crítico", "alto", "expuesto", "listado", "n/a"]):
                v_html = f'<span style="color:var(--red);">{v_safe}</span>'
            elif any(w in v.lower() for w in ["clean", "ok", "secure", "limpio", "seguro", "0 "]):
                v_html = f'<span style="color:var(--green);">{v_safe}</span>'
            else:
                v_html = v_safe

            rows += f"    <tr><td>{k_safe}</td><td>{v_html}</td></tr>\n"

        html_sections.append(f"""
<div class="section">
  <h2>📋 {html.escape(summary_title)}</h2>
  <table class="kv-table">
{rows}  </table>
</div>""")

    # ── Section: findings ─────────────────────────────────────────
    if data["findings"]:
        findings_html = ""
        findings_title = tr("Security findings ({count})", count=len(data["findings"]))
        seen = set()
        for severity, finding in data["findings"][:30]:
            clean = html.escape(finding.strip())
            if clean in seen:
                continue
            seen.add(clean)
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            findings_html += f'  <div class="finding finding-{severity}">{icon} {clean}</div>\n'

        html_sections.append(f"""
<div class="section">
  <h2>⚠️ {html.escape(findings_title)}</h2>
{findings_html}</div>""")

    # ── Section: full log (escaped) ───────────────────────────────
    raw_text = html.escape("\n".join(data["raw_lines"]))
    html_sections.append(f"""
<div class="section">
  <h2>📄 {html.escape(log_title)}</h2>
  <pre>{raw_text}</pre>
</div>""")

    # ── Final render ──────────────────────────────────────────────
    page = TEMPLATE.format(
        target=html.escape(data["target"]),
        date=html.escape(data["date"]),
        version=html.escape(VERSION),
        content="\n".join(html_sections),
        lang=i18n.language(),
        authorized=html.escape(tr("Authorized use only")),
        generated=html.escape(tr("Generated by DomainInfo v{version} — @kevxngg (Kevin)", version=VERSION)),
        confidential=html.escape(tr("This report is confidential. For authorized audits only.")),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)

    print("✓ " + tr("HTML report generated: {path}", path=output_path))


def main() -> None:
    if len(sys.argv) < 2:
        print(tr("Usage: python3 {script} <log_file.txt> [output.html]", script=sys.argv[0]))
        print(tr("Example: python3 report.py logs/domaininfo_google.com_20260411.txt"))
        sys.exit(1)

    log_path = sys.argv[1]
    if not os.path.isfile(log_path):
        print(tr("Error: file not found: {path}", path=log_path))
        sys.exit(1)

    base = os.path.splitext(log_path)[0]
    output_path = sys.argv[2] if len(sys.argv) > 2 else f"{base}_report.html"

    generate_html(log_path, output_path)


if __name__ == "__main__":
    main()
