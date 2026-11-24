"""Infrastructure map across several targets and CSV/Markdown export.

Groups the targets that share an IP, network (ASN), DNS servers, mail servers,
certificate or favicon: useful to discover related assets.

Group ``kind`` values are English (IP, Network (ASN), DNS server, Mail server, Certificate,
Favicon); the Markdown map translates them.
"""

import csv
import io

from i18n import tr


def _data(report, name):
    module = report.get("modules", {}).get(name, {})
    return module.get("data") if module.get("status") == "ok" and isinstance(module.get("data"), dict) else {}


def facts(report):
    dns, asn, mail, tls, tech = (_data(report, n) for n in ("dns", "asn", "mail", "tls", "tech"))
    records = dns.get("records") or {}
    return {
        "IP": set(dns.get("addresses", [])),
        "Network (ASN)": {f"AS{r['asn']} {r.get('as_name') or ''}".strip() for r in asn.get("networks", []) if r.get("asn")},
        "DNS server": set(records.get("NS", [])),
        "Mail server": {r["host"] for r in records.get("MX", []) if isinstance(r, dict)}
        | {r["host"] for r in mail.get("mx", []) if isinstance(r, dict)},
        "Certificate": {f"{tls.get('issuer')} #{tls.get('serial')}"} if tls.get("serial") else set(),
        "Favicon": {str(tech["favicon"]["mmh3"])} if tech.get("favicon") else set(),
    }


def correlate(reports):
    """{"groups": [{"kind", "value", "targets"}]} only with values shared by 2+ targets."""
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
    return {"target": report.get("meta", {}).get("target"), "grade": score.get("grade", ""),
            "points": score.get("score", ""), "ips": " ".join(dns.get("addresses", [])),
            "http": tech.get("status") or http.get("status") or "",
            "tls_valid": "" if not tls else ("yes" if tls.get("verified") else "no"),
            "tls_expires": tls.get("expires", ""), "mail": mail.get("grade", ""),
            "spoofable": "" if not mail else ("yes" if mail.get("spoofable") else "no"),
            "open_ports": " ".join(str(r["port"]) for r in ports.get("results", []) if r.get("state") == "open"),
            "subdomains": subs.get("total", ""), "takeover": len(subs.get("takeover", [])) if subs else ""}


def to_csv(reports):
    rows = [summary_row(r) for r in reports]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]) if rows else ["target"])
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def map_markdown(result):
    lines = [tr("# Infrastructure map"), "", tr("Targets: {targets}", targets=", ".join(result["targets"])), ""]
    if not result["groups"]:
        lines.append(tr("No shared elements were found between the targets."))
    for group in result["groups"]:
        lines.append(f"- **{tr(group['kind'])}** `{group['value']}` → " + ", ".join(group["targets"]))
    return "\n".join(lines) + "\n"
