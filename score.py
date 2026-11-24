"""Overall security grade (0–100, A–F) from the modules that ran.

Each finding explains what is wrong and how to fix it. It is guidance: it does not replace
an audit or prove that anything is exploitable.

Severities (``high``, ``medium``, ``low``, ``info``) and areas (``Web``, ``TLS``, ``Mail``, ``DNS``,
``Ports``, ``Subdomains``, ``Registration``, ``Brand``, ``Web app``) are English in every language;
titles and fixes follow the active language.
"""

from i18n import tr

PENALTY = {"high": 20, "medium": 8, "low": 3, "info": 0}
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "Remote Desktop (RDP)", 3306: "MySQL",
               5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
               5900: "VNC", 2375: "Docker without TLS"}
# Header checks of the tech module whose absence weighs more (see webtech.grade_headers ids)
TRANSPORT_CHECKS = {"hsts", "https"}


# Legacy grade area for findings copied from evidence-model modules
EVIDENCE_AREAS = {"webapp": "Web app", "session": "Sessions", "apispec": "API", "zap": "Web app", "browser": "Web app",
                  "tools": "Tools", "intel": "Vulnerabilities"}


def _data(report, name):
    module = report.get("modules", {}).get(name, {})
    return module.get("data") if module.get("status") == "ok" and isinstance(module.get("data"), dict) else None


def assess(report):
    findings = []

    import evidence
    target = str((report.get("meta") or {}).get("target") or "")

    def add(severity, area, title, fix):
        # id is computed from the English title, so it is stable across languages and audits
        findings.append({"id": evidence.finding_id(target, "score." + str(area), title), "severity": severity,
                         "area": area, "title": title, "fix": fix})

    tls = _data(report, "tls")
    if tls:
        if not tls.get("verified"):
            add("high", "TLS", tr("Invalid certificate: {reason}",
                                  reason=tls.get("verify_error") or tr("not verified")),
                tr("Install a certificate from a recognized authority that covers the site name"))
        days = tls.get("days_remaining")
        if days is not None and days < 0:
            add("high", "TLS", tr("Certificate expired {days} days ago", days=-days), tr("Renew the certificate"))
        elif days is not None and days <= 30:
            add("medium", "TLS", tr("The certificate expires in {days} days", days=days),
                tr("Renew it or automate renewal"))
        versions = tls.get("versions") or {}
        old = [v for v in ("TLSv1.0", "TLSv1.1") if versions.get(v)]
        if old:
            add("medium", "TLS", tr("Accepts old versions: {versions}", versions=", ".join(old)),
                tr("Disable TLS 1.0 and 1.1; keep only 1.2 and 1.3"))
        if versions and versions.get("TLSv1.3") is False:
            add("low", "TLS", tr("Does not support TLS 1.3"), tr("Enable TLS 1.3 on the server"))
    tech = _data(report, "tech")
    if tech:
        for check in tech.get("headers_grade", {}).get("checks", []):
            if check["state"] == "missing":
                severity = "medium" if check.get("id") in TRANSPORT_CHECKS else "low"
                add(severity, "Web", check["text"], tr("Add the header on the server or the CDN"))
            elif check["state"] == "warning":
                add("low", "Web", check["text"], tr("Adjust the header or hide the software version"))
        weak = [c["name"] for c in tech.get("cookies", []) if c.get("issues")]
        if weak:
            add("low", "Web", tr("Cookies without Secure/HttpOnly/SameSite: {names}", names=", ".join(weak[:5])),
                tr("Mark cookies with Secure, HttpOnly and SameSite"))
    else:
        http = _data(report, "http")
        for header in (http or {}).get("missing_headers", []):
            add("medium" if header == "strict-transport-security" else "low", "Web",
                tr("Missing header {header}", header=header), tr("Add the header on the server or the CDN"))
    mail = _data(report, "mail")
    if mail:
        spf, dmarc = mail.get("spf", {}), mail.get("dmarc", {})
        if mail.get("spoofable"):
            add("high", "Mail", tr("Forged mail can be sent in the domain's name (DMARC does not block it)"),
                tr("Publish DMARC with p=quarantine or p=reject after reviewing the reports"))
        if not spf.get("present"):
            add("medium", "Mail", tr("No SPF record"), tr("Publish a TXT 'v=spf1 ... -all' listing your servers"))
        # A missing record already has its own finding; its only issue would repeat it.
        details = (spf.get("issues", []) if spf.get("present") else []) + \
            (dmarc.get("issues", []) if dmarc.get("present") else [])
        for issue in details:
            add("low", "Mail", issue, tr("Fix the matching DNS record"))
        if not dmarc.get("present"):
            add("medium", "Mail", tr("No DMARC"), tr("Publish _dmarc with at least p=none and rua= to start"))
        if mail.get("accepts_mail") and not mail.get("dkim", {}).get("selectors_found"):
            add("info", "Mail", tr("No DKIM found on common selectors"), tr("Check that your provider signs with DKIM"))
        if mail.get("accepts_mail") and mail.get("mta_sts", {}).get("mode") != "enforce":
            add("info", "Mail", tr("No MTA-STS in enforce mode"), tr("Publish MTA-STS to enforce TLS on inbound mail"))
    dns = _data(report, "dns")
    if dns and dns.get("records") is not None:
        if dns.get("dnssec") is False:
            add("low", "DNS", tr("No DNSSEC"), tr("Enable DNSSEC at your DNS provider and registrar"))
        if not dns["records"].get("CAA"):
            add("low", "DNS", tr("No CAA record"), tr("Publish CAA to limit which authorities may issue certificates"))
    ports = _data(report, "ports")
    if ports:
        for row in ports.get("results", []):
            if row.get("state") == "open" and row.get("port") in RISKY_PORTS:
                add("high", "Ports", tr("{service} reachable on port {port}", service=tr(RISKY_PORTS[row["port"]]),
                                        port=row["port"]),
                    tr("Close it to the public or restrict it with a firewall/VPN"))
    subs = _data(report, "subdomains")
    if subs:
        for row in subs.get("takeover", []):
            risk = row["takeover"]["risk"]
            add("high" if risk == "high" else "medium", "Subdomains",
                tr("{name}: possible subdomain takeover ({service})", name=row["name"],
                   service=row["takeover"].get("service") or tr("external service")),
                tr("Remove the CNAME or recreate the resource on the service"))
    history = _data(report, "history")
    if history and history.get("new_domain"):
        add("info", "Registration", tr("Domain registered {days} days ago", days=history.get("age_days")),
            tr("Newly created domains are common in phishing; verify its legitimacy"))
    if history and history.get("expires_in_days") is not None and 0 <= history["expires_in_days"] <= 30:
        add("medium", "Registration", tr("The domain expires in {days} days", days=history["expires_in_days"]),
            tr("Renew the domain"))
    look = _data(report, "lookalike")
    if look and look.get("with_mail"):
        add("medium", "Brand", tr("{count} registered lookalike domains can receive mail", count=look["with_mail"]),
            tr("Monitor those domains and consider registering or reporting them"))
    evidence_modules = []
    for name in (report.get("modules") or {}):
        data = _data(report, name)
        if not data or not isinstance(data.get("findings"), list) or name in ("tech",):
            continue
        evidence_modules.append(name)
        for item in data["findings"]:
            # Only findings with evidence: 'pending' or 'informational' ones do not lower the classic grade.
            if isinstance(item, dict) and item.get("status") in ("confirmed", "likely") \
                    and item.get("severity") in PENALTY:
                findings.append({"id": item.get("id"), "severity": item["severity"],
                                 "area": EVIDENCE_AREAS.get(name, name), "title": item["title"],
                                 "fix": item.get("recommendation", ""), "source": name})
    if not findings and not any(_data(report, n) for n in ("tls", "tech", "http", "mail", "dns", "ports",
                                                           *evidence_modules)):
        return None
    points = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    letter = "A" if points >= 90 else "B" if points >= 80 else "C" if points >= 65 else "D" if points >= 50 else "F"
    findings.sort(key=lambda f: ORDER[f["severity"]])
    return {"score": points, "grade": letter, "findings": findings,
            "note": tr("Indicative: summarizes the modules that ran; it does not prove anything is exploitable")}
