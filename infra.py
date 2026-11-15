"""Mapa de infraestructura entre varios objetivos y exportación CSV/Markdown.

Agrupa qué objetivos comparten IP, red (ASN), servidores DNS, servidores de correo,
certificado o favicon: útil para descubrir activos relacionados.
"""

import csv
import io


def _data(report, name):
    module = report.get("modules", {}).get(name, {})
    return module.get("data") if module.get("status") == "ok" and isinstance(module.get("data"), dict) else {}


def facts(report):
    dns, asn, mail, tls, tech = (_data(report, n) for n in ("dns", "asn", "mail", "tls", "tech"))
    records = dns.get("records") or {}
    return {
        "IP": set(dns.get("addresses", [])),
        "Red (ASN)": {f"AS{r['asn']} {r.get('as_name') or ''}".strip() for r in asn.get("networks", []) if r.get("asn")},
        "Servidor DNS": set(records.get("NS", [])),
        "Servidor de correo": {r["host"] for r in records.get("MX", []) if isinstance(r, dict)}
        | {r["host"] for r in mail.get("mx", []) if isinstance(r, dict)},
        "Certificado": {f"{tls.get('issuer')} #{tls.get('serial')}"} if tls.get("serial") else set(),
        "Favicon": {str(tech["favicon"]["mmh3"])} if tech.get("favicon") else set(),
    }


def correlate(reports):
    """{"groups": [{"kind", "value", "targets"}]} solo con valores compartidos por 2+ objetivos."""
    index = {}
    for report in reports:
        target = report.get("meta", {}).get("target")
        for kind, values in facts(report).items():
            for value in values:
                index.setdefault((kind, value), set()).add(target)
    groups = [{"kind": kind, "value": value, "targets": sorted(targets)}
              for (kind, value), targets in index.items() if len(targets) > 1]
    groups.sort(key=lambda g: (-len(g["targets"]), g["kind"], g["value"]))
    return {"targets": [r.get("meta", {}).get("target") for r in reports], "groups": groups}


def summary_row(report):
    dns, tls, mail, ports, subs, http, tech = (_data(report, n) for n in
                                               ("dns", "tls", "mail", "ports", "subdomains", "http", "tech"))
    score = report.get("score") or {}
    return {"objetivo": report.get("meta", {}).get("target"), "nota": score.get("grade", ""),
            "puntos": score.get("score", ""), "ips": " ".join(dns.get("addresses", [])),
            "http": tech.get("status") or http.get("status") or "",
            "tls_valido": "" if not tls else ("sí" if tls.get("verified") else "no"),
            "tls_caduca": tls.get("expires", ""), "correo": mail.get("grade", ""),
            "suplantable": "" if not mail else ("sí" if mail.get("spoofable") else "no"),
            "puertos_abiertos": " ".join(str(r["port"]) for r in ports.get("results", []) if r.get("state") == "open"),
            "subdominios": subs.get("total", ""), "takeover": len(subs.get("takeover", [])) if subs else ""}


def to_csv(reports):
    rows = [summary_row(r) for r in reports]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]) if rows else ["objetivo"])
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def map_markdown(result):
    lines = ["# Mapa de infraestructura", "", "Objetivos: " + ", ".join(result["targets"]), ""]
    if not result["groups"]:
        lines.append("No se encontraron elementos compartidos entre los objetivos.")
    for group in result["groups"]:
        lines.append(f"- **{group['kind']}** `{group['value']}` → " + ", ".join(group["targets"]))
    return "\n".join(lines) + "\n"
