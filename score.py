"""Nota global de seguridad (0–100, A–F) a partir de los módulos ejecutados.

Cada hallazgo explica qué pasa y cómo arreglarlo. Es una orientación: no sustituye
una auditoría ni prueba que algo sea explotable.
"""

PENALTY = {"alta": 20, "media": 8, "baja": 3, "info": 0}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "Escritorio remoto (RDP)", 3306: "MySQL",
               5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
               5900: "VNC", 2375: "Docker sin TLS"}


def _data(report, name):
    module = report.get("modules", {}).get(name, {})
    return module.get("data") if module.get("status") == "ok" and isinstance(module.get("data"), dict) else None


def assess(report):
    findings = []

    def add(severity, area, title, fix):
        findings.append({"severity": severity, "area": area, "title": title, "fix": fix})

    tls = _data(report, "tls")
    if tls:
        if not tls.get("verified"):
            add("alta", "TLS", "Certificado no válido: " + str(tls.get("verify_error") or "no verificado"),
                "Instala un certificado de una autoridad reconocida que cubra el nombre del sitio")
        days = tls.get("days_remaining")
        if days is not None and days < 0:
            add("alta", "TLS", f"Certificado caducado hace {-days} días", "Renueva el certificado")
        elif days is not None and days <= 30:
            add("media", "TLS", f"El certificado caduca en {days} días", "Renueva o automatiza la renovación")
        versions = tls.get("versions") or {}
        old = [v for v in ("TLSv1.0", "TLSv1.1") if versions.get(v)]
        if old:
            add("media", "TLS", "Acepta versiones antiguas: " + ", ".join(old),
                "Desactiva TLS 1.0 y 1.1; deja solo 1.2 y 1.3")
        if versions and versions.get("TLSv1.3") is False:
            add("baja", "TLS", "No admite TLS 1.3", "Activa TLS 1.3 en el servidor")
    tech = _data(report, "tech")
    if tech:
        for check in tech.get("headers_grade", {}).get("checks", []):
            if check["state"] == "falta":
                severity = "media" if "HSTS" in check["text"] or "HTTPS" in check["text"] else "baja"
                add(severity, "Web", check["text"], "Añade la cabecera en el servidor o el CDN")
            elif check["state"] == "aviso":
                add("baja", "Web", check["text"], "Ajusta la cabecera u oculta la versión del software")
        weak = [c["name"] for c in tech.get("cookies", []) if c.get("issues")]
        if weak:
            add("baja", "Web", "Cookies sin Secure/HttpOnly/SameSite: " + ", ".join(weak[:5]),
                "Marca las cookies con Secure, HttpOnly y SameSite")
    else:
        http = _data(report, "http")
        for header in (http or {}).get("missing_headers", []):
            add("media" if header == "strict-transport-security" else "baja", "Web",
                f"Falta la cabecera {header}", "Añade la cabecera en el servidor o el CDN")
    mail = _data(report, "mail")
    if mail:
        if mail.get("spoofable"):
            add("alta", "Correo", "Se pueden enviar correos falsos en nombre del dominio (DMARC no los bloquea)",
                "Publica DMARC con p=quarantine o p=reject tras revisar los informes")
        if not mail.get("spf", {}).get("present"):
            add("media", "Correo", "Sin registro SPF", "Publica un TXT 'v=spf1 ... -all' con tus servidores")
        for issue in mail.get("spf", {}).get("issues", []) + mail.get("dmarc", {}).get("issues", []):
            if "Sin registro SPF" not in issue and "Sin DMARC" not in issue:
                add("baja", "Correo", issue, "Corrige el registro DNS correspondiente")
        if not mail.get("dmarc", {}).get("present"):
            add("media", "Correo", "Sin DMARC", "Publica _dmarc con al menos p=none y rua= para empezar")
        if mail.get("accepts_mail") and not mail.get("dkim", {}).get("selectors_found"):
            add("info", "Correo", "No se encontró DKIM en selectores comunes", "Verifica que tu proveedor firme con DKIM")
        if mail.get("accepts_mail") and mail.get("mta_sts", {}).get("mode") != "enforce":
            add("info", "Correo", "Sin MTA-STS en modo enforce", "Publica MTA-STS para forzar TLS en el correo entrante")
    dns = _data(report, "dns")
    if dns and dns.get("records") is not None:
        if dns.get("dnssec") is False:
            add("baja", "DNS", "Sin DNSSEC", "Activa DNSSEC en tu proveedor DNS y registrador")
        if not dns["records"].get("CAA"):
            add("baja", "DNS", "Sin registro CAA", "Publica CAA para limitar qué autoridades pueden emitir certificados")
    ports = _data(report, "ports")
    if ports:
        for row in ports.get("results", []):
            if row.get("state") == "open" and row.get("port") in RISKY_PORTS:
                add("alta", "Puertos", f"{RISKY_PORTS[row['port']]} accesible en el puerto {row['port']}",
                    "Ciérralo al público o limítalo con cortafuegos/VPN")
    subs = _data(report, "subdomains")
    if subs:
        for row in subs.get("takeover", []):
            risk = row["takeover"]["risk"]
            add("alta" if risk == "alto" else "media", "Subdominios",
                f"{row['name']}: posible toma del subdominio ({row['takeover'].get('service') or 'servicio externo'})",
                "Elimina el CNAME o vuelve a crear el recurso en el servicio")
    history = _data(report, "history")
    if history and history.get("new_domain"):
        add("info", "Registro", f"Dominio registrado hace {history.get('age_days')} días",
            "Los dominios recién creados son habituales en phishing; verifica su legitimidad")
    if history and history.get("expires_in_days") is not None and 0 <= history["expires_in_days"] <= 30:
        add("media", "Registro", f"El dominio caduca en {history['expires_in_days']} días", "Renueva el dominio")
    look = _data(report, "lookalike")
    if look and look.get("with_mail"):
        add("media", "Marca", f"{look['with_mail']} dominios parecidos registrados pueden recibir correo",
            "Vigila esos dominios y valora registrarlos o denunciarlos")
    webapp = _data(report, "webapp")
    for item in (webapp or {}).get("findings", []):
        # Solo lo que tiene evidencia: lo 'pendiente' o 'informativo' no resta en la nota clásica.
        if item.get("status") in ("confirmado", "probable") and item.get("severity") in PENALTY:
            findings.append({"severity": item["severity"], "area": "Web app", "title": item["title"],
                             "fix": item.get("recommendation", ""), "source": "webapp"})
    if not findings and not any(_data(report, n) for n in ("tls", "tech", "http", "mail", "dns", "ports", "webapp")):
        return None
    points = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    letter = "A" if points >= 90 else "B" if points >= 80 else "C" if points >= 65 else "D" if points >= 50 else "F"
    order = {"alta": 0, "media": 1, "baja": 2, "info": 3}
    findings.sort(key=lambda f: order[f["severity"]])
    return {"score": points, "grade": letter, "findings": findings,
            "note": "Orientativa: resume los módulos ejecutados; no prueba que algo sea explotable"}
