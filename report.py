#!/usr/bin/env python3
"""
report.py — HTML Report Generator for DomainInfo v3.2.0
Autor: @kevxngg (Kevin)
Uso: python3 report.py <log_file.txt> [output.html]
"""

import sys
import os
import re
import html
from datetime import datetime

VERSION = "4.2.0"

TEMPLATE = """<!DOCTYPE html>
<html lang="es">
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
    <span>🔒 Uso autorizado únicamente</span>
  </div>
</header>

{content}

<footer>
  <p>Generado por DomainInfo v{version} — @kevxngg (Kevin)</p>
  <p style="margin-top:4px;">Este reporte es confidencial. Uso exclusivo para auditorías autorizadas.</p>
</footer>
</div>
</body>
</html>"""


# ── ANSI stripping ────────────────────────────────────────────────
# Cubre: CSI sequences (\x1b[...m), OSC hyperlinks (\x1b]8;;...\x1b\\),
# y caracteres de escape sueltos.
_ANSI_RE = re.compile(
    r'\x1b'
    r'(?:'
    r'\[[0-9;:<=>?]*[ -/]*[@-~]'   # CSI sequences (colores, cursores, etc.)
    r'|'
    r'\][^\x07\x1b]*(?:\x07|\x1b\\)'  # OSC sequences (hyperlinks, title)
    r'|'
    r'[@-_][0-?]*[ -/]*[@-~]?'     # Otras secuencias de 2 caracteres
    r')'
)


def strip_ansi(text: str) -> str:
    """Elimina todas las secuencias de escape ANSI/VT100 de un string."""
    return _ANSI_RE.sub('', text)


def parse_log(log_path: str) -> dict:
    """
    Parsea el archivo de log de DomainInfo.
    Lee el bloque de cabecera estructurado (líneas 'Clave : Valor')
    y el resto como raw log para mostrar completo.
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
        print(f"Error leyendo log: {e}")
        return data

    # Guardar líneas limpias (sin ANSI)
    data["raw_lines"] = [strip_ansi(l.rstrip()) for l in lines]

    # ── Parsear campos estructurados del encabezado ───────────────
    # El save_log de domaininfo.sh escribe líneas como:
    #   "Dominio    : valor"
    #   "IP         : valor"
    header_field_re = re.compile(
        r'^([A-ZÁÉÍÓÚÑa-záéíóúñ][A-ZÁÉÍÓÚÑa-záéíóúñ0-9 _/()]*?)\s*:\s*(.+)$'
    )

    in_header = False
    for line in data["raw_lines"]:
        stripped = line.strip()

        # Detectar inicio/fin del bloque de cabecera
        if "===" in stripped and "DomainInfo" in stripped:
            in_header = True
            continue
        if "===" in stripped and in_header:
            in_header = False

        # Extraer "Reporte: TARGET" para el título del reporte
        m = re.search(r'Reporte:\s*(.+)', stripped)
        if m:
            data["target"] = m.group(1).strip()

        # Extraer "Fecha:" del encabezado
        m = re.search(r'^Fecha\s+:\s+([^|]+)', stripped)
        if m:
            data["date"] = m.group(1).strip()

        # Parsear campos clave-valor del encabezado estructurado
        m = header_field_re.match(stripped)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            # Excluir líneas de separador y claves de 1 carácter
            if len(key) > 1 and val not in ("", "==="):
                data["fields"][key] = val

        # Detectar findings (líneas con indicadores de seguridad)
        low = stripped.lower()
        if any(k in stripped for k in ["EXPUESTO", "LISTADO", "CRITICO", "⚠", " VULN "]):
            data["findings"].append(("critical", stripped))
        elif any(k in low for k in ["alto:", "alto ", "vulnerable", "expuesto"]):
            data["findings"].append(("high", stripped))
        elif any(k in low for k in ["[!]", "warn", "medio:"]):
            data["findings"].append(("medium", stripped))

    return data


def generate_html(log_path: str, output_path: str) -> None:
    """Genera el reporte HTML a partir del log de DomainInfo."""
    data = parse_log(log_path)
    html_sections = []

    # ── Sección: Resumen ejecutivo ────────────────────────────────
    if data["fields"]:
        rows = ""
        for k, v in list(data["fields"].items())[:20]:
            # Escapar HTML para evitar XSS en claves y valores
            k_safe = html.escape(k)
            v_safe = html.escape(v)

            # Colorear según contenido
            if any(w in v.lower() for w in ["crítico", "alto", "vulnerable", "expuesto", "listado", "n/a"]):
                v_html = f'<span style="color:var(--red);">{v_safe}</span>'
            elif any(w in v.lower() for w in ["limpio", "clean", "ok", "seguro", "0 "]):
                v_html = f'<span style="color:var(--green);">{v_safe}</span>'
            else:
                v_html = v_safe

            rows += f"    <tr><td>{k_safe}</td><td>{v_html}</td></tr>\n"

        html_sections.append(f"""
<div class="section">
  <h2>📋 Resumen Ejecutivo</h2>
  <table class="kv-table">
{rows}  </table>
</div>""")

    # ── Sección: Hallazgos ────────────────────────────────────────
    if data["findings"]:
        findings_html = ""
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
  <h2>⚠️ Hallazgos de Seguridad ({len(data['findings'])})</h2>
{findings_html}</div>""")

    # ── Sección: Log completo (escapado) ──────────────────────────
    raw_text = html.escape("\n".join(data["raw_lines"]))
    html_sections.append(f"""
<div class="section">
  <h2>📄 Log Completo</h2>
  <pre>{raw_text}</pre>
</div>""")

    # ── Render final ──────────────────────────────────────────────
    page = TEMPLATE.format(
        target=html.escape(data["target"]),
        date=html.escape(data["date"]),
        version=html.escape(VERSION),
        content="\n".join(html_sections),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)

    print(f"✓ Reporte HTML generado: {output_path}")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Uso: python3 {sys.argv[0]} <log_file.txt> [output.html]")
        print(f"Ejemplo: python3 report.py logs/domaininfo_google.com_20260411.txt")
        sys.exit(1)

    log_path = sys.argv[1]
    if not os.path.isfile(log_path):
        print(f"Error: archivo no encontrado: {log_path}")
        sys.exit(1)

    base = os.path.splitext(log_path)[0]
    output_path = sys.argv[2] if len(sys.argv) > 2 else f"{base}_report.html"

    generate_html(log_path, output_path)


if __name__ == "__main__":
    main()
