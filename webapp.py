"""Seguridad de aplicaciones web (pasivo): analiza una URL completa sin enviar formularios
ni credenciales.

Comprueba transporte y HSTS, Content-Security-Policy, clickjacking, Referrer-Policy,
Permissions-Policy, nosniff, cookies (Secure, HttpOnly, SameSite), formularios (campos de usuario
y contraseña, tokens CSRF visibles y protecciones alternativas), redirecciones, CORS, errores
técnicos y datos sensibles en la respuesta. Compara la página con la raíz del sitio para
demostrar que se ha auditado la ruta pedida.

Todas las peticiones son GET, pasan por ``safety`` (alcance, IP fijada, límites) y cada
hallazgo dice de dónde sale (``evidence.Finding``).
"""

import hashlib
import html
from html.parser import HTMLParser
import http.client
import re
import time
from urllib import parse

import evidence
import safety

TOOL = "domaininfo.webapp"
CORS_PROBE = "https://domaininfo-cors-probe.invalid"
CSRF_NAME = re.compile(r"csrf|xsrf|authenticity_token|requestverificationtoken|^_token$|^token$|nonce|"
                       r"csrfmiddlewaretoken|anti.?forgery|form_key|__viewstategenerator", re.I)
USER_NAME = re.compile(r"user|login|e-?mail|correo|usuario|account|cuenta|identif|^uid$|^name$", re.I)
SESSION_NAME = re.compile(r"sess|sid|auth|token|jwt|login|remember|identity", re.I)
VERSION = re.compile(r"\d+\.\d+")

ERROR_SIGNATURES = (
    ("Traza de error de Python", r"Traceback \(most recent call last\)"),
    ("Página de depuración de Django", r"You're seeing this error because you have <code>DEBUG = True|DEBUG = True"),
    ("Traza de excepción Java", r"\bat (?:java|javax|org\.springframework|org\.apache)\.[\w.$]+\(|Exception in thread \""),
    ("Error de PHP con ruta del servidor", r"(?:Fatal error|Warning|Parse error|Notice)</b>?:? .{0,200}? on line <b>?\d+"),
    ("Página de error de ASP.NET", r"Server Error in '/' Application|<b>Stack Trace:</b>"),
    ("Mensaje de error de base de datos", r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|"
                                          r"PG::\w+Error|Microsoft OLE DB Provider|SQLite3::|psycopg2\.\w+Error"),
    ("Página de excepción de Laravel/Symfony", r"Whoops, looks like something went wrong|Symfony\\Component\\"),
    ("Página de excepción de Rails", r"Action Controller: Exception caught"),
    ("Traza de excepción de Node.js", r"\n[ \t]{1,16}at [\w.<>]{1,200} \((?:/|[A-Z]:\\)[^)\n]{1,500}\.js:\d+:\d+\)"),
)
SECRET_SIGNATURES = (
    ("Clave privada en la respuesta", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "alta", "confirmado", "CWE-321"),
    ("Clave de acceso de AWS en la respuesta", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "alta", "probable", "CWE-798"),
    ("Token de GitHub en la respuesta", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "alta", "probable", "CWE-798"),
    ("Token de Slack en la respuesta", r"\bxox[abprs]-[\w-]{10,}", "alta", "probable", "CWE-798"),
    ("Clave de API de Google en la respuesta", r"\bAIza[\w-]{35}\b", "baja", "informativo", "CWE-798"),
    ("JWT incrustado en la página", r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}", "media", "pendiente", "CWE-200"),
    ("Dirección IP interna en la respuesta",
     r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "baja", "informativo", "CWE-200"),
)
OWASP_HEADERS = "OWASP Secure Headers Project"
SCAN_LIMIT = 256 * 1024  # las firmas de errores y secretos solo recorren este prefijo de la respuesta
URL_KEYS = {"url", "final_url", "from", "location", "action", "target"}


def _scrub(value, key=None):
    """Quita caracteres de control de todo lo que viene del objetivo y oculta secretos en las URL."""
    if isinstance(value, dict):
        return {k: _scrub(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        return evidence.redact_url(value) if key in URL_KEYS and "://" in value else evidence.clean(value)
    return value


class _PageParser(HTMLParser):
    """Título, formularios con sus campos y metaetiquetas de token CSRF."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.forms, self._form = [], None
        self.meta_csrf = []

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title" and not self.title:
            self._in_title = True
        elif tag == "meta" and CSRF_NAME.search(attrs.get("name", "")):
            self.meta_csrf.append(attrs.get("name"))
        elif tag == "form":
            self._form = {"method": (attrs.get("method") or "get").upper(), "action": attrs.get("action", ""),
                          "id": attrs.get("id") or attrs.get("name") or "", "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            kind = (attrs.get("type") or ("text" if tag == "input" else tag)).lower()
            if tag == "button" or kind in ("submit", "button", "image", "reset"):
                return
            self._form["fields"].append({"name": attrs.get("name") or attrs.get("id") or "", "type": kind,
                                         "autocomplete": attrs.get("autocomplete"), "has_value": bool(attrs.get("value"))})

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse_page(text):
    parser = _PageParser()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):  # HTML roto: nos quedamos con lo leído
        pass
    parser.title = html.unescape(re.sub(r"\s+", " ", parser.title)).strip()
    return parser


def parse_cookie(raw):
    """Atributos de un Set-Cookie sin guardar su valor."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    samesite = attrs.get("samesite")
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": samesite.capitalize() if samesite else None,
            "domain": attrs.get("domain") or None, "path": attrs.get("path") or None,
            "persistent": "expires" in attrs or "max-age" in attrs,
            "session_like": bool(SESSION_NAME.search(name))}


def parse_csp(value):
    directives = {}
    for chunk in (value or "").split(";"):
        tokens = chunk.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def csp_issues(directives):
    """Debilidades concretas de una CSP (sin inventar las que no se pueden ver)."""
    issues = []
    script = directives.get("script-src", directives.get("default-src"))
    name = "script-src" if "script-src" in directives else "default-src"
    if script is None:
        issues.append("sin script-src ni default-src: no limita los scripts")
    else:
        strict = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                     for t in script)
        if "'unsafe-inline'" in script and not strict:
            issues.append(f"'unsafe-inline' en {name}")
        if "'unsafe-eval'" in script:
            issues.append(f"'unsafe-eval' en {name}")
        if "*" in script or "https:" in script or "http:" in script:
            issues.append(f"origen comodín en {name}")
        if "data:" in script:
            issues.append(f"data: en {name}")
    if "object-src" not in directives and directives.get("default-src") != ["'none'"]:
        issues.append("falta object-src 'none'")
    if "base-uri" not in directives:
        issues.append("falta base-uri")
    return issues


def _fingerprint(response, page):
    return {"status": response.status, "title": page.title or None,
            "sha256": hashlib.sha256(response.body).hexdigest()[:16], "forms": len(page.forms),
            "length": len(response.body)}


class _Audit:
    def __init__(self, url, args):
        self.url = safety.normalize_url(url)
        self.args = args
        self.timeout = getattr(args, "timeout", 5.0)
        self.insecure = bool(getattr(args, "insecure_tls", False))
        self.policy = safety.ScopePolicy(self.url, extra_hosts=list(getattr(args, "scope", None) or []),
                                         allow_private=bool(getattr(args, "allow_private", False)))
        self.findings, self.checks = [], {}
        # Plazo total para las tres peticiones (página, CORS y raíz) con sus redirecciones
        self.deadline = time.monotonic() + min(180.0, max(30.0, self.timeout * 12))

    # -- utilidades ---------------------------------------------------------------------------
    def get(self, url, headers=None):
        try:
            return safety.http_get(url, self.policy, self.timeout, headers=headers, insecure_tls=self.insecure,
                                   deadline=self.deadline)
        except http.client.HTTPException as exc:
            raise OSError(f"Respuesta HTTP no válida: {exc}") from exc

    def check(self, cid, state, evidence_kind="directa", detail=None):
        entry = {"id": cid, "state": state, "evidence": evidence_kind}
        if detail:
            entry["detail"] = detail
        self.checks[cid] = entry

    def add(self, category, title, severity, status, proof, recommendation, impact="", verification="",
            references=(), confidence="alta"):
        self.findings.append(evidence.Finding(
            target=evidence.redact_url(self.url), path=parse.urlsplit(self.final).path or "/", category=category, title=title,
            severity=severity, status=status, confidence=confidence, evidence=proof, tool=TOOL, impact=impact,
            verification=verification, recommendation=recommendation, references=list(references)).to_dict())

    # -- auditoría ----------------------------------------------------------------------------
    def run(self):
        response = self.get(self.url)
        self.final = response.url
        self.https = parse.urlsplit(self.final).scheme == "https"
        self.headers = {k.lower(): v for k, v in response.headers}
        text = response.body.decode(_charset(self.headers.get("content-type")), "replace")
        page = parse_page(text)
        result = {"url": self.url, "final_url": self.final, "status": response.status, "title": page.title or None,
                  "address": response.address, "tls_verified": response.tls_verified,
                  "truncated": response.truncated, "redirects": response.redirects}
        self.transport()
        self.redirects(response.redirects)
        result["headers"] = self.security_headers()
        result["cookies"] = self.cookies(response.header_all("set-cookie"))
        result["forms"] = self.forms(page, result["cookies"])
        result["cors"] = self.cors()
        self.errors(text[:SCAN_LIMIT], response.status)
        self.exposure(text[:SCAN_LIMIT])
        result["root_comparison"] = self.root(response, page)
        order = {"alta": 0, "media": 1, "baja": 2, "info": 3}
        self.findings.sort(key=lambda f: (order[f["severity"]], f["category"]))
        checks = list(self.checks.values())
        result.update({"findings": self.findings, "checks": checks,
                       "assessment": evidence.scores(self.findings, checks),
                       "note": "Análisis pasivo: solo peticiones GET; no se envían formularios ni credenciales"})
        return _scrub(result)

    def transport(self):
        if self.https:
            self.check("https", "ok")
            if self.insecure:
                self.add("transporte", "Certificado TLS no verificado (auditado con --insecure-tls)", "media",
                         "informativo", "La conexión se aceptó sin validar el certificado",
                         "Instala un certificado válido; revisa el módulo TLS", confidence="media")
        else:
            self.check("https", "hallazgo")
            self.add("transporte", "La página se sirve por HTTP sin cifrar", "media", "confirmado",
                     f"URL final: {self.final}", "Sirve el sitio solo por HTTPS y redirige HTTP a HTTPS",
                     impact="Cualquiera en la red puede leer o alterar la página y los datos enviados",
                     verification="Abre la URL con http:// y comprueba que no redirige a https://",
                     references=["CWE-319", "OWASP ASVS V9.1"])

    def redirects(self, chain):
        state = "ok"
        for hop in chain:
            if hop.get("downgrade"):
                state = "hallazgo"
                self.add("redirecciones", "Redirección de HTTPS a HTTP", "media", "confirmado",
                         f"{hop['status']} {hop['from']} → {hop['location']}",
                         "Haz que todas las redirecciones apunten a HTTPS", references=["CWE-319"])
            if hop.get("blocked"):
                state = "hallazgo"
                self.add("redirecciones", "Redirección no seguida: fuera del alcance autorizado", "info", "informativo",
                         f"{hop['status']} → {hop.get('location')} ({hop['blocked']})",
                         "Si el destino también está autorizado, añádelo con --scope",
                         verification="Revisa a dónde redirige la página y si ese destino es tuyo")
        self.check("redirecciones", state)

    def security_headers(self):
        h = self.headers
        out = {}
        # HSTS
        hsts = h.get("strict-transport-security")
        age = re.search(r"max-age=\"?(\d{1,12})\b", hsts or "")
        out["hsts"] = {"present": bool(hsts), "max_age": int(age.group(1)) if age else None,
                       "include_subdomains": "includesubdomains" in (hsts or "").lower(),
                       "preload": "preload" in (hsts or "").lower()}
        if not self.https:
            self.check("hsts", "no_aplicable")
        elif not hsts:
            self.check("hsts", "hallazgo")
            self.add("hsts", "Sin HSTS (Strict-Transport-Security)", "media", "confirmado", "Cabecera ausente",
                     "Añade Strict-Transport-Security: max-age=31536000; includeSubDomains",
                     impact="Un atacante en la red puede forzar la primera visita por HTTP",
                     references=["CWE-319", OWASP_HEADERS])
        elif not age or int(age.group(1)) < 15552000:
            self.check("hsts", "hallazgo")
            self.add("hsts", "HSTS con duración menor de 6 meses", "baja", "confirmado",
                     "Strict-Transport-Security: " + hsts, "Usa max-age de al menos 15552000 (6 meses)",
                     references=[OWASP_HEADERS])
        else:
            self.check("hsts", "ok")
        # CSP
        csp_value = h.get("content-security-policy")
        report_only = h.get("content-security-policy-report-only")
        directives = parse_csp(csp_value)
        issues = csp_issues(directives) if csp_value else []
        out["csp"] = {"present": bool(csp_value), "report_only": bool(report_only) and not csp_value,
                      "directives": sorted(directives), "issues": issues}
        if not csp_value:
            self.check("csp", "hallazgo")
            self.add("csp", "Sin Content-Security-Policy" + (" (solo en modo informe)" if report_only else ""),
                     "media", "confirmado", "Cabecera ausente" if not report_only else "Solo Report-Only",
                     "Define una CSP con script-src limitado (nonces o hashes), object-src 'none' y base-uri 'self'",
                     impact="Un fallo de XSS tendría menos barreras", references=["CWE-1021", "CWE-79", OWASP_HEADERS])
        elif issues:
            self.check("csp", "hallazgo")
            self.add("csp", "CSP débil: " + "; ".join(issues), "baja", "confirmado",
                     "Content-Security-Policy: " + csp_value,
                     "Elimina 'unsafe-inline'/'unsafe-eval' y comodines; añade object-src 'none' y base-uri",
                     references=["CWE-79", OWASP_HEADERS])
        else:
            self.check("csp", "ok")
        # Clickjacking
        xfo = (h.get("x-frame-options") or "").upper()
        ancestors = directives.get("frame-ancestors")
        protected = xfo in ("DENY", "SAMEORIGIN") or (ancestors is not None and "*" not in ancestors)
        out["clickjacking"] = {"protected": protected, "x_frame_options": xfo or None,
                               "frame_ancestors": " ".join(ancestors) if ancestors is not None else None}
        if protected:
            self.check("clickjacking", "ok")
        else:
            self.check("clickjacking", "hallazgo")
            self.add("clickjacking", "Sin protección contra clickjacking", "media", "confirmado",
                     "Ni X-Frame-Options válida ni CSP frame-ancestors",
                     "Añade CSP frame-ancestors 'self' (o X-Frame-Options: DENY)",
                     impact="La página se puede incrustar en otra para engañar al usuario",
                     verification="Carga la URL en un <iframe> desde otro origen", references=["CWE-1021"])
        # nosniff
        nosniff = (h.get("x-content-type-options") or "").lower() == "nosniff"
        out["x_content_type_options"] = nosniff
        self.check("nosniff", "ok" if nosniff else "hallazgo")
        if not nosniff:
            self.add("cabeceras", "Sin X-Content-Type-Options: nosniff", "baja", "confirmado", "Cabecera ausente",
                     "Añade X-Content-Type-Options: nosniff", references=["CWE-693", OWASP_HEADERS])
        # Referrer-Policy
        referrer = (h.get("referrer-policy") or "").lower()
        out["referrer_policy"] = referrer or None
        # Con varias políticas, el navegador aplica la última que entiende
        effective = referrer.split(",")[-1].strip() if referrer else ""
        if effective in ("unsafe-url", "no-referrer-when-downgrade"):
            self.check("referrer", "hallazgo")
            self.add("cabeceras", "Referrer-Policy permisiva: " + referrer, "baja", "confirmado",
                     "Referrer-Policy: " + referrer, "Usa strict-origin-when-cross-origin o no-referrer",
                     impact="Las URL completas (con parámetros) se envían a otros sitios", references=["CWE-200"])
        elif not referrer:
            self.check("referrer", "hallazgo")
            self.add("cabeceras", "Sin Referrer-Policy (se aplica la del navegador)", "info", "informativo",
                     "Cabecera ausente", "Define Referrer-Policy: strict-origin-when-cross-origin",
                     references=[OWASP_HEADERS])
        else:
            self.check("referrer", "ok")
        # Permissions-Policy
        permissions = h.get("permissions-policy")
        out["permissions_policy"] = permissions
        self.check("permissions", "ok" if permissions else "hallazgo")
        if not permissions:
            self.add("cabeceras", "Sin Permissions-Policy", "info", "informativo", "Cabecera ausente",
                     "Desactiva lo que no uses: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                     references=[OWASP_HEADERS])
        # Versiones expuestas
        leaks = [f"{n}: {h[n]}" for n in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                                          "x-generator") if n in h and VERSION.search(h[n])]
        out["version_leaks"] = leaks
        for leak in leaks:
            self.add("exposicion", "La cabecera revela la versión del software", "baja", "confirmado", leak,
                     "Oculta la versión en la configuración del servidor", references=["CWE-200"])
        return out

    def cookies(self, raw_cookies):
        rows = [parse_cookie(raw) for raw in raw_cookies]
        if not rows:
            self.check("cookies", "no_aplicable", detail="La respuesta no crea cookies")
            return rows
        state = "ok"
        for row in rows:
            name = row["name"]
            proof = f"Set-Cookie: {name}=…" + "".join(
                f"; {k}" for k, v in (("Secure", row["secure"]), ("HttpOnly", row["httponly"])) if v) \
                + (f"; SameSite={row['samesite']}" if row["samesite"] else "")
            if self.https and not row["secure"]:
                state = "hallazgo"
                self.add("cookies", f"Cookie {name} sin Secure", "media" if row["session_like"] else "baja",
                         "confirmado", proof, "Marca la cookie con Secure",
                         impact="Puede viajar por HTTP sin cifrar", references=["CWE-614"])
            if not row["httponly"]:
                state = "hallazgo"
                self.add("cookies", f"Cookie {name} sin HttpOnly", "media" if row["session_like"] else "baja",
                         "confirmado" if row["session_like"] else "informativo", proof,
                         "Marca con HttpOnly las cookies que no necesite JavaScript",
                         impact="Un XSS podría leerla", references=["CWE-1004"],
                         confidence="alta" if row["session_like"] else "media")
            if not row["samesite"]:
                state = "hallazgo"
                self.add("cookies", f"Cookie {name} sin SameSite explícito", "baja", "informativo", proof,
                         "Define SameSite=Lax o Strict (None solo con Secure si es imprescindible)",
                         impact="Depende del valor por defecto de cada navegador", references=["CWE-1275"])
            elif row["samesite"] == "None" and not row["secure"]:
                state = "hallazgo"
                self.add("cookies", f"Cookie {name} con SameSite=None sin Secure", "media", "confirmado", proof,
                         "SameSite=None exige Secure; los navegadores la rechazarán o se enviará en peticiones "
                         "de terceros", references=["CWE-1275"])
        self.check("cookies", state)
        return rows

    def forms(self, page, cookies):
        rows = []
        samesite = [c["name"] for c in cookies if c["samesite"] in ("Lax", "Strict")]
        csrf_state = "no_aplicable"
        for index, form in enumerate(page.forms, 1):
            action = parse.urljoin(self.final, html.unescape(form["action"])) if form["action"] else self.final
            fields = form["fields"]
            passwords = [f["name"] for f in fields if f["type"] == "password"]
            users = [f["name"] for f in fields if f["type"] in ("text", "email", "tel")
                     and USER_NAME.search(f["name"])]
            tokens = [f["name"] for f in fields if f["type"] == "hidden" and CSRF_NAME.search(f["name"])
                      and f["has_value"]]
            label = f"Formulario {index}" + (f" ({form['id']})" if form["id"] else "")
            row = {"index": index, "id": form["id"] or None, "method": form["method"], "action": action,
                   "fields": [{"name": f["name"], "type": f["type"]} for f in fields],
                   "login": bool(passwords), "password_fields": passwords, "user_fields": users}
            if form["method"] in ("POST", "PUT", "PATCH", "DELETE"):
                if tokens:
                    csrf = {"state": "token_visible", "fields": tokens, "evidence": "directa"}
                    csrf_state = _worst(csrf_state, "ok")
                elif page.meta_csrf:
                    csrf = {"state": "token_en_meta", "fields": page.meta_csrf, "evidence": "heuristica"}
                    csrf_state = _worst(csrf_state, "ok")
                    self.add("csrf", f"{label}: token CSRF en <meta>, no en el formulario", "info", "informativo",
                             f"<meta name='{page.meta_csrf[0]}'>",
                             "Comprueba que el JavaScript lo envía en una cabecera en cada petición",
                             verification="Revisa en las herramientas del navegador la cabecera de la petición",
                             confidence="media")
                elif samesite:
                    csrf = {"state": "proteccion_alternativa", "fields": [], "cookies_samesite": samesite,
                            "evidence": "heuristica"}
                    csrf_state = _worst(csrf_state, "hallazgo")
                    self.add("csrf", f"{label}: sin token CSRF visible; depende de cookies SameSite", "info",
                             "informativo", "Cookies con SameSite: " + ", ".join(samesite),
                             "Añade un token CSRF por sesión además de SameSite",
                             verification="En un entorno autorizado, envía el formulario desde otro origen "
                                          "y comprueba que el servidor lo rechaza", references=["CWE-352"],
                             confidence="media")
                else:
                    csrf = {"state": "desconocido", "fields": [], "evidence": "heuristica"}
                    csrf_state = _worst(csrf_state, "hallazgo")
                    self.add("csrf", f"{label}: no se ve protección CSRF (pendiente de verificar)", "media",
                             "pendiente", f"{form['method']} {action} sin campo oculto de token ni cookies SameSite",
                             "Usa un token CSRF por sesión o comprueba Origin/Referer en el servidor",
                             impact="Si no hay otra defensa, otro sitio podría enviar el formulario en nombre del usuario",
                             verification="La protección puede estar en cabeceras o en el servidor: compruébalo "
                                          "con una cuenta de prueba en un entorno autorizado",
                             references=["CWE-352", "OWASP ASVS V4.2.2"], confidence="baja")
            else:
                csrf = {"state": "no_aplicable", "fields": [], "evidence": "directa"}
            row["csrf"] = csrf
            if passwords:
                if form["method"] == "GET":
                    self.add("formularios", f"{label}: la contraseña se envía por GET (queda en la URL)", "alta",
                             "confirmado", f"<form method='GET' action='{action}'> con campo password",
                             "Usa method='post' en formularios con contraseña",
                             impact="La contraseña queda en historiales, registros del servidor y Referer",
                             references=["CWE-598"])
                if parse.urlsplit(action).scheme == "http" or not self.https:
                    self.add("formularios", f"{label}: la contraseña viaja por HTTP sin cifrar", "alta", "confirmado",
                             f"Página {self.final} · destino {action}", "Sirve la página y el destino por HTTPS",
                             impact="Cualquiera en la red puede leer la contraseña", references=["CWE-319"])
            if parse.urlsplit(action).netloc != parse.urlsplit(self.final).netloc:
                self.add("formularios", f"{label}: envía datos a otro origen", "info", "informativo",
                         f"destino {action}", "Comprueba que el destino es tuyo y de confianza", confidence="media")
            rows.append(row)
        self.check("formularios", "ok" if page.forms else "no_aplicable")
        self.check("csrf", csrf_state, "directa" if csrf_state == "ok" else "heuristica")
        return rows

    def cors(self):
        try:
            response = self.get(self.final, headers={"Origin": CORS_PROBE})
        except (OSError, ValueError) as exc:
            self.check("cors", "error", detail=str(exc))
            return {"error": str(exc)}
        allow = response.header("access-control-allow-origin")
        credentials = (response.header("access-control-allow-credentials") or "").lower() == "true"
        result = {"allow_origin": allow, "credentials": credentials, "reflects_origin": allow == CORS_PROBE}
        proof = f"Origin: {CORS_PROBE} → Access-Control-Allow-Origin: {allow}" + \
            ("; Access-Control-Allow-Credentials: true" if credentials else "")
        if allow == CORS_PROBE:
            self.check("cors", "hallazgo")
            self.add("cors", "CORS acepta cualquier origen" + (" con credenciales" if credentials else ""),
                     "alta" if credentials else "baja", "confirmado" if credentials else "probable", proof,
                     "Usa una lista cerrada de orígenes permitidos",
                     impact="Otro sitio podría leer respuestas" + (" autenticadas del usuario" if credentials else ""),
                     verification="Repite la petición con otra cabecera Origin y compara la respuesta",
                     references=["CWE-942", "OWASP ASVS V14.5.3"])
        elif allow == "null":
            self.check("cors", "hallazgo")
            self.add("cors", "CORS permite el origen null", "media", "confirmado", proof,
                     "No incluyas 'null' entre los orígenes permitidos", references=["CWE-942"])
        elif allow == "*":
            self.check("cors", "ok")
            self.add("cors", "CORS público (*): cualquier sitio puede leer esta respuesta sin credenciales", "info",
                     "informativo", proof, "Correcto para contenido público; revísalo si la respuesta es privada")
        else:
            self.check("cors", "ok")
        return result

    def errors(self, text, status):
        found = []
        for name, pattern in ERROR_SIGNATURES:
            match = re.search(pattern, text, re.I)
            if match:
                found.append(name)
                start = max(0, match.start() - 40)
                self.add("errores", name, "media", "confirmado", text[start:match.end() + 120],
                         "Desactiva el modo depuración y muestra páginas de error genéricas",
                         impact="Revela rutas, versiones o consultas internas que facilitan un ataque",
                         references=["CWE-209", "OWASP ASVS V7.4.1"])
        self.check("errores", "hallazgo" if found else "ok", "heuristica",
                   detail=None if status < 500 or found else f"HTTP {status} sin detalles técnicos visibles")

    def exposure(self, text):
        state = "ok"
        for name, pattern, severity, status, cwe in SECRET_SIGNATURES:
            matches = re.findall(pattern, text)
            if matches:
                state = "hallazgo"
                self.add("exposicion", name, severity, status, f"{len(matches)} coincidencia(s): {matches[0]}",
                         "Retira el dato de la respuesta y, si es una credencial, revócala y genera otra",
                         verification="Busca el valor en el código fuente y comprueba si sigue siendo válido "
                                      "con su propietario", references=[cwe],
                         confidence="alta" if status == "confirmado" else "media")
        self.check("exposicion", state, "heuristica")

    def root(self, response, page):
        parts = parse.urlsplit(self.final)
        root_url = parse.urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        mine = _fingerprint(response, page)
        if self.final == root_url:
            self.check("raiz", "no_aplicable")
            return {"url": root_url, "same_as_target": True}
        try:
            other = self.get(root_url)
        except (OSError, ValueError) as exc:
            self.check("raiz", "error", detail=str(exc))
            return {"url": root_url, "error": str(exc)}
        other_page = parse_page(other.body.decode(_charset(other.header("content-type")), "replace"))
        theirs = _fingerprint(other, other_page)
        self.check("raiz", "ok")
        return {"url": root_url, "final_url": other.url, **theirs,
                "differs": (mine["status"], mine["title"], mine["sha256"]) !=
                           (theirs["status"], theirs["title"], theirs["sha256"])}


def _worst(current, new):
    rank = {"no_aplicable": 0, "ok": 1, "hallazgo": 2}
    return new if rank[new] > rank[current] else current


def _charset(content_type):
    match = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    name = match.group(1) if match else "utf-8"
    try:
        "".encode(name)
        return name
    except (LookupError, ValueError):  # códec desconocido o no utilizable (p. ej. "undefined")
        return "utf-8"


def audit(url, args):
    """Auditoría pasiva de una URL completa. ``args`` aporta timeout, scope, allow_private e insecure_tls."""
    return _Audit(url, args).run()
