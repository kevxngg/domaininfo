"""DomainInfo Security Center: local web dashboard (optional extra: FastAPI + uvicorn).

    from server import serve
    serve()                      # http://127.0.0.1:8765, opens the browser with a one-time token

Security model (docs/SECURITY_CENTER.md):

- Listens on loopback only. Any other address needs ``allow_remote=True`` explicitly.
- A random token is created on every run. The browser receives it once in the URL fragment (never sent
  to the server or written to logs) and must send it in the ``X-DomainInfo-Token`` header of every API
  call. Static files carry no data and need no token.
- The ``Host`` header must be one of the expected loopback names (DNS-rebinding defence), cross-site
  requests (``Sec-Fetch-Site``/``Origin``) are refused and there is no CORS.
- Strict CSP and security headers on every response; request bodies are size-limited.
- New audits only run passive modes, only against targets registered in the project scope, in a
  bounded background pool that can be cancelled.

The Python core stays standard-library only: this module imports FastAPI lazily and explains how
to install the extra when it is missing.
"""

import argparse
import hmac
import importlib
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from i18n import language, tr

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
TOKEN_HEADER = "x-domaininfo-token"  # noqa: S105 - a header name, not a secret
PASSIVE_MODES = ("quick", "web", "mail", "recon", "webapp", "brand")
MAX_BODY = 256 * 1024
MAX_IMPORT = 10 * 1024 * 1024
MAX_WORKERS = 2
MAX_PENDING = 8
TOOLS_CACHE_SECONDS = 300
INSTALL_HINT = "pip install \"domaininfo[server]\"  (or: pip install fastapi uvicorn)"

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


class MissingExtra(RuntimeError):
    """FastAPI/uvicorn are not installed."""


def require_extra():
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError as exc:
        raise MissingExtra(tr("The Security Center needs the optional web extra. Install it with: {hint}",
                              hint=INSTALL_HINT)) from exc


def is_loopback(host):
    if str(host).lower() in ("localhost", "localhost.", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(str(host).strip("[]")).is_loopback
    except ValueError:
        return False


def allowed_hosts(host, port):
    """Host header values the server accepts (with and without the port)."""
    names = {"127.0.0.1", "localhost", "[::1]"}
    host = str(host)
    if host not in ("0.0.0.0", "::"):  # noqa: S104  # nosec B104 - only compared, never bound here
        names.add("[" + host + "]" if ":" in host and not host.startswith("[") else host)
    return {n.lower() for n in names} | {f"{n}:{port}".lower() for n in names}


# ---------------------------------------------------------------------------------------------
# Static web UI
# ---------------------------------------------------------------------------------------------
def _webui_candidates():
    env = os.environ.get("DOMAININFO_WEBUI")
    if env:
        yield Path(env)
    here = Path(__file__).resolve().parent
    yield here / "webui" / "dist"
    yield Path(sys.prefix) / "share" / "domaininfo" / "webui"


def load_webui(directory=None):
    """Map of URL path -> (bytes, content type) for the built UI, from a folder or from the zipapp."""
    files = {}
    folders = [Path(directory)] if directory else list(_webui_candidates())
    for folder in folders:
        if folder.is_dir() and (folder / "index.html").is_file():
            for path in folder.rglob("*"):
                if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
                    files[path.relative_to(folder).as_posix()] = path.read_bytes()
            break
    if not files and directory is None:
        archive = Path(__file__).resolve().parent  # inside a .pyz the parent is the archive itself
        if archive.is_file() and zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as bundle:
                for name in bundle.namelist():
                    if name.startswith("webui/dist/") and not name.endswith("/"):
                        files[name[len("webui/dist/"):]] = bundle.read(name)
    return {name: (body, _content_type(name)) for name, body in files.items()}


def _content_type(name):
    special = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
               ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json",
               ".woff2": "font/woff2", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json"}
    suffix = os.path.splitext(name)[1].lower()
    return special.get(suffix) or mimetypes.guess_type(name)[0] or "application/octet-stream"


_FALLBACK_PAGE = ("<!doctype html><html lang=en><meta charset=utf-8><title>DomainInfo Security Center</title>"
                  "<body><h1>DomainInfo Security Center</h1><p>{message}</p></body></html>")


# ---------------------------------------------------------------------------------------------
# Audit jobs
# ---------------------------------------------------------------------------------------------
class JobCancelled(Exception):
    pass


def _default_scanner(target, args, on_progress):
    import domaininfo
    return domaininfo.scan(target, args, on_progress=on_progress)


def build_args(mode, target):
    """Parsed CLI arguments for a passive audit (quiet, no brute force, no private redirects)."""
    import domaininfo
    if mode not in PASSIVE_MODES:
        raise ValueError(tr("Only passive modes can be launched from the Security Center"))
    args = domaininfo.parser().parse_args(["-m", mode, "-q", "--timeout", "5", "--", target])
    args.brute = False
    args.allow_private = False
    args.insecure_tls = False
    return args, domaininfo.normalize_for_mode(target, mode)


class JobManager:
    """Bounded pool of background audits with progress and cancellation."""

    def __init__(self, store, scanner=None, max_workers=MAX_WORKERS, max_pending=MAX_PENDING):
        self.store = store
        self.scanner = scanner or _default_scanner
        self.max_pending = max_pending
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="domaininfo-audit")
        self.jobs: dict[int, dict] = {}
        self.futures: dict = {}
        self.cancel_flags: dict[int, threading.Event] = {}
        self.lock = threading.Lock()
        self.counter = 0

    def submit(self, project_id, target_row, mode):
        if mode not in PASSIVE_MODES:
            raise PermissionError(tr("Only passive modes can be launched from the Security Center"))
        with self.lock:
            active = [j for j in self.jobs.values() if j["state"] in ("queued", "running")]
            if len(active) >= self.max_pending:
                raise OverflowError(tr("Too many audits in progress; wait or cancel one"))
            if any(j["target_id"] == target_row["id"] and j["mode"] == mode for j in active):
                raise FileExistsError(tr("This audit is already queued or running"))
            self.counter += 1
            job = {"id": self.counter, "project_id": project_id, "target_id": target_row["id"],
                   "target": target_row["value"], "mode": mode, "state": "queued", "module": None,
                   "progress": 0, "total": 0, "audit_id": None, "error": None,
                   "created_at": time.time(), "finished_at": None}
            self.jobs[job["id"]] = job
            self.cancel_flags[job["id"]] = threading.Event()
            self.futures[job["id"]] = self.pool.submit(self._run, job["id"])
            return dict(job)

    def _run(self, job_id):
        job, flag = self.jobs[job_id], self.cancel_flags[job_id]
        if flag.is_set():
            return

        def progress(module, state, index, total):
            if flag.is_set():
                raise JobCancelled()
            job.update(module=module, progress=index - (1 if state == "running" else 0), total=total)

        job["state"] = "running"
        try:
            args, target = build_args(job["mode"], job["target"])
            report = self.scanner(target, args, progress)
            if flag.is_set():
                raise JobCancelled()
            audit = self.store.save_audit(job["project_id"], report, job["target_id"])
            job.update(state="done", audit_id=audit["id"], progress=job["total"])
        except JobCancelled:
            job["state"] = "cancelled"
        except Exception as exc:  # noqa: BLE001 - a failed audit is reported in the job, never crashes the pool
            job.update(state="error", error=str(exc)[:500])
        finally:
            job["finished_at"] = time.time()

    def cancel(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(tr("Unknown job"))
            if job["state"] in ("queued", "running"):
                self.cancel_flags[job_id].set()
                if self.futures[job_id].cancel():
                    job.update(state="cancelled", finished_at=time.time())
                elif job["state"] == "running":
                    job["state"] = "cancelling"
            return dict(job)

    def list(self):
        with self.lock:
            return sorted((dict(j) for j in self.jobs.values()), key=lambda j: -j["id"])[:100]

    def get(self, job_id):
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(tr("Unknown job"))
        return dict(job)

    def shutdown(self):
        for flag in self.cancel_flags.values():
            flag.set()
        self.pool.shutdown(wait=False, cancel_futures=True)


# ---------------------------------------------------------------------------------------------
# Section facts (latest report of each target, summarized for the dashboard)
# ---------------------------------------------------------------------------------------------
def _module(report, name):
    module = (report.get("modules") or {}).get(name) or {}
    return module.get("data") if module.get("status") == "ok" and isinstance(module.get("data"), dict) else None


def _join(values, limit=12):
    out = []
    for value in list(values or [])[:limit]:
        if isinstance(value, dict):
            value = " ".join(str(v) for v in value.values() if v not in (None, ""))
        out.append(str(value))
    return ", ".join(out)


def section_facts(report, section):
    """Short label/value pairs describing what the latest report says about one dashboard section."""
    facts = []

    def add(label, value, tone="neutral"):
        if value not in (None, "", [], {}):
            facts.append({"label": label, "value": str(value)[:400], "tone": tone})

    webapp = _module(report, "webapp") or {}
    if section == "web":
        http = _module(report, "http") or {}
        tech = _module(report, "tech") or {}
        add(tr("HTTP status"), webapp.get("status") or http.get("status") or tech.get("status"))
        add(tr("Final URL"), webapp.get("final_url") or tech.get("url") or http.get("url"))
        add(tr("Page title"), webapp.get("title") or http.get("title"))
        grade = (tech.get("headers_grade") or {}).get("grade")
        add(tr("Security headers grade"), grade, "good" if grade in ("A", "B") else "bad" if grade else "neutral")
        add(tr("Missing headers"), _join(http.get("missing_headers")), "bad")
        add(tr("Technologies"), _join(t.get("name") for t in tech.get("technologies") or [] if isinstance(t, dict)))
        checks = webapp.get("checks") or []
        if checks:
            add(tr("Web checks run"), len(checks))
    elif section == "auth":
        cookies = webapp.get("cookies") or (_module(report, "tech") or {}).get("cookies") or []
        for cookie in cookies[:12]:
            if isinstance(cookie, dict):
                flags = [name for name in ("secure", "httponly") if cookie.get(name)]
                if cookie.get("samesite"):
                    flags.append("SameSite=" + str(cookie["samesite"]))
                issues = cookie.get("issues")
                add(tr("Cookie {name}", name=cookie.get("name", "?")),
                    ", ".join(flags) or tr("no protection flags"), "bad" if issues or not flags else "good")
        forms = webapp.get("forms") or {}
        items = forms.get("forms") if isinstance(forms, dict) else forms
        if isinstance(items, list):
            add(tr("Forms found"), len(items))
            for form in items[:6]:
                if isinstance(form, dict):
                    csrf = form.get("csrf")
                    add(tr("Form {method} {action}", method=str(form.get("method") or "GET").upper(),
                           action=form.get("action") or "/"),
                        (csrf.get("state") if isinstance(csrf, dict) else csrf) or "-")
    elif section == "infra":
        dns = _module(report, "dns") or {}
        add(tr("Addresses"), _join(dns.get("addresses")))
        ports = _module(report, "ports") or {}
        open_ports = [str(r.get("port")) for r in ports.get("results") or [] if r.get("state") == "open"]
        if ports:
            add(tr("Open TCP ports"), ", ".join(open_ports) or tr("no open ports"), "bad" if open_ports else "good")
        asn = _module(report, "asn") or {}
        add(tr("Networks"), _join(asn.get("networks"), 4))
    elif section == "tls":
        tls = _module(report, "tls") or {}
        if tls:
            add(tr("Certificate valid"), tr("Yes") if tls.get("verified") else tls.get("verify_error") or tr("No"),
                "good" if tls.get("verified") else "bad")
            add(tr("Subject"), tls.get("subject"))
            add(tr("Issuer"), tls.get("issuer"))
            days = tls.get("days_remaining")
            add(tr("Expires"), "%s (%s)" % (tls.get("expires"), tr("{days} days", days=days)) if days is not None
                else tls.get("expires"), "bad" if isinstance(days, int) and days <= 30 else "good")
            add(tr("Protocol"), tls.get("protocol"))
            versions = tls.get("versions") or {}
            if isinstance(versions, dict) and versions:
                accepted = [v for v, ok in versions.items() if ok]
                add(tr("Accepted versions"), ", ".join(accepted),
                    "bad" if {"TLSv1.0", "TLSv1.1"} & set(accepted) else "good")
        add(tr("TLS verified for the URL"), webapp.get("tls_verified"))
    elif section == "maildns":
        mail = _module(report, "mail") or {}
        if mail:
            add(tr("Mail grade"), mail.get("grade"), "good" if mail.get("grade") in ("A", "B") else "bad")
            add(tr("Spoofable"), tr("Yes") if mail.get("spoofable") else tr("No"),
                "bad" if mail.get("spoofable") else "good")
            add(tr("MX"), _join(mail.get("mx"), 6))
            add(tr("SPF"), (mail.get("spf") or {}).get("record") or (
                tr("present") if (mail.get("spf") or {}).get("present") else tr("missing")))
            add(tr("DMARC policy"), (mail.get("dmarc") or {}).get("policy") or tr("missing"))
            add(tr("DKIM selectors"), _join((mail.get("dkim") or {}).get("selectors_found")) or tr("none found"))
        dns = _module(report, "dns") or {}
        records = dns.get("records") or {}
        if dns:
            add(tr("DNSSEC"), tr("Yes") if dns.get("dnssec") else tr("No"), "good" if dns.get("dnssec") else "bad")
            add(tr("Name servers"), _join(records.get("NS")))
            add(tr("CAA"), _join(records.get("CAA")) or tr("missing"))
        subs = _module(report, "subdomains") or {}
        add(tr("Live subdomains"), len(subs.get("alive") or []) if subs else None)
    else:  # vulns
        assessment = report.get("assessment") or {}
        add(tr("Findings by evidence status"), _join(f"{k}: {v}" for k, v in (assessment.get("status_counts")
                                                                             or {}).items()))
        errors = [name for name, m in (report.get("modules") or {}).items()
                  if isinstance(m, dict) and m.get("status") == "error"]
        add(tr("Modules with errors"), ", ".join(errors), "bad")
    return facts


# ---------------------------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------------------------
def create_app(store, token, hosts, webui_dir=None, scanner=None, tools_detect=None):
    """FastAPI application. ``hosts`` is the Host allow-list; ``scanner``/``tools_detect`` are injectable."""
    require_extra()
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response

    import exporters

    app = FastAPI(title="DomainInfo Security Center", docs_url=None, redoc_url=None, openapi_url=None)
    jobs = JobManager(store, scanner)
    webui = load_webui(webui_dir)
    hosts = {h.lower() for h in hosts}
    origins = {"http://" + h for h in hosts}
    tools_cache: dict = {"at": 0.0, "data": None}
    tools_lock = threading.Lock()
    app.state.jobs = jobs
    app.state.store = store

    def error(status, message):
        return JSONResponse({"error": message}, status_code=status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").lower()
        path = request.url.path
        if host not in hosts:
            response = error(421, tr("Unexpected Host header"))
        elif request.method not in ("GET", "HEAD", "POST", "PATCH", "DELETE"):
            response = error(405, tr("Method not allowed"))
        elif request.headers.get("sec-fetch-site") == "cross-site" or (
                request.headers.get("origin") and request.headers["origin"].lower() not in origins):
            response = error(403, tr("Cross-site requests are not allowed"))
        elif path.startswith("/api/") and not hmac.compare_digest(
                (request.headers.get(TOKEN_HEADER) or "").encode(), token.encode()):
            response = error(401, tr("Missing or invalid access token"))
        else:
            response = None
            if request.method in ("POST", "PATCH", "DELETE"):
                limit = MAX_IMPORT if path.endswith("/import") else MAX_BODY
                length = request.headers.get("content-length")
                if length is None and request.headers.get("transfer-encoding"):
                    response = error(411, tr("Content-Length is required"))
                elif length is not None and (not length.isdigit() or int(length) > limit):
                    response = error(413, tr("Request body too large"))
            if response is None:
                response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        if path.startswith("/api/") or path == "/" or path.endswith(".html"):
            response.headers["Cache-Control"] = "no-store"
        return response

    async def body(request, required=()):
        try:
            data = json.loads((await request.body()) or b"{}")
        except (ValueError, UnicodeDecodeError):
            data = None
        if not isinstance(data, dict):
            raise ValueError(tr("The request body must be a JSON object"))
        for name in required:
            if name not in data:
                raise ValueError(tr("Missing field: {name}", name=name))
        return data

    def handle(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError as exc:
            return error(403, str(exc))
        except FileExistsError as exc:
            return error(409, str(exc))
        except OverflowError as exc:
            return error(429, str(exc))
        except KeyError as exc:
            return error(404, str(exc.args[0]) if exc.args else tr("Not found"))
        except (ValueError, UnicodeError) as exc:
            return error(400, str(exc))

    def project_or_404(project_id):
        project = store.get_project(project_id)
        if not project:
            raise KeyError(tr("Unknown project"))
        return project

    def own_audit(audit_id):
        audit = store.get_audit(audit_id)
        if not audit:
            raise KeyError(tr("Unknown audit"))
        return audit

    # -- session ----------------------------------------------------------------------------
    @app.get("/api/session")
    def session():
        import domaininfo
        return {"version": domaininfo.VERSION, "language": language(), "passive_modes": list(PASSIVE_MODES),
                "modes": {m: list(domaininfo.MODES[m]) for m in PASSIVE_MODES},
                "review_statuses": ["open", "fixed", "accepted_risk", "false_positive"],
                "database": str(store.path)}

    @app.get("/api/i18n")
    def i18n_strings():
        strings = {}
        if language() == "es":
            try:
                strings = dict(importlib.import_module("i18n_es_phase4").STRINGS)
            except ImportError:
                strings = {}
        return {"language": language(), "strings": strings}

    @app.get("/api/overview")
    def overview(project_id: int | None = None):
        return handle(store.overview, project_id)

    # -- projects and scope -----------------------------------------------------------------
    @app.get("/api/projects")
    def projects():
        return store.list_projects()

    @app.post("/api/projects", status_code=201)
    async def create_project(request: Request):
        try:
            data = await body(request, ("name",))
        except ValueError as exc:
            return error(400, str(exc))
        return handle(store.create_project, data["name"], data.get("description", ""))

    @app.delete("/api/projects/{project_id}")
    def delete_project(project_id: int):
        return {"deleted": store.delete_project(project_id)}

    @app.get("/api/projects/{project_id}/targets")
    def targets(project_id: int):
        return handle(lambda: (project_or_404(project_id), store.list_targets(project_id))[1])

    @app.post("/api/projects/{project_id}/targets", status_code=201)
    async def add_target(project_id: int, request: Request):
        try:
            data = await body(request, ("value",))
        except ValueError as exc:
            return error(400, str(exc))
        return handle(store.add_target, project_id, str(data["value"]), data.get("note", ""))

    @app.delete("/api/targets/{target_id}")
    def remove_target(target_id: int):
        return {"deleted": store.remove_target(target_id)}

    # -- audits ------------------------------------------------------------------------------
    @app.get("/api/projects/{project_id}/audits")
    def audits(project_id: int, target: str | None = None):
        return handle(lambda: (project_or_404(project_id), store.list_audits(project_id, target))[1])

    @app.get("/api/audits/{audit_id}")
    def audit(audit_id: int):
        def run():
            row = own_audit(audit_id)
            previous = store.previous_audit(audit_id)
            row["previous_id"] = previous["id"] if previous else None
            return row
        return handle(run)

    @app.get("/api/audits/{audit_id}/report")
    def audit_report(audit_id: int):
        def run():
            row = store.get_audit(audit_id, include_report=True)
            if not row:
                raise KeyError(tr("Unknown audit"))
            return row["report"]
        return handle(run)

    @app.delete("/api/audits/{audit_id}")
    def delete_audit(audit_id: int):
        return {"deleted": store.delete_audit(audit_id)}

    @app.post("/api/projects/{project_id}/import", status_code=201)
    async def import_report(project_id: int, request: Request):
        try:
            data = await body(request)
            project_or_404(project_id)
            target = str((data.get("meta") or {}).get("target") or "")
            entry = store.in_scope(project_id, target)
            if not entry:
                return error(403, tr("The report target is not in the project scope: {target}", target=target[:200]))
        except KeyError as exc:
            return error(404, str(exc.args[0]))
        except ValueError as exc:
            return error(400, str(exc))
        return handle(store.save_audit, project_id, data, entry["id"])

    @app.get("/api/projects/{project_id}/targets/{target_id}/history")
    def target_history(project_id: int, target_id: int):
        def run():
            entry = store.get_target(target_id)
            if not entry or entry["project_id"] != project_id:
                raise KeyError(tr("Unknown target"))
            rows = store.list_audits(project_id)
            return [r for r in reversed(rows) if r["target_id"] == target_id]
        return handle(run)

    # -- findings ----------------------------------------------------------------------------
    @app.get("/api/projects/{project_id}/findings")
    def findings(project_id: int, section: str | None = None, status: str | None = None,
                 severity: str | None = None, audit_id: int | None = None):
        def run():
            project_or_404(project_id)
            if audit_id is not None and own_audit(audit_id)["project_id"] != project_id:
                raise KeyError(tr("Unknown audit"))
            return store.list_findings(audit_id=audit_id, project_id=project_id, section=section,
                                       review_status=status, severity=severity)
        return handle(run)

    @app.get("/api/projects/{project_id}/sections/{section}")
    def section(project_id: int, section: str):
        def run():
            project_or_404(project_id)
            if section not in ("web", "auth", "infra", "tls", "maildns", "vulns"):
                raise KeyError(tr("Unknown section"))
            facts = []
            for latest in store.latest_audits(project_id):
                report = store.get_audit(latest["id"], include_report=True)["report"]
                facts.append({"target": latest["target"], "audit_id": latest["id"], "date": latest["created_at"],
                              "mode": latest["mode"], "facts": section_facts(report, section)})
            return {"section": section, "facts": facts,
                    "findings": store.list_findings(project_id=project_id, section=section)}
        return handle(run)

    @app.patch("/api/findings/{finding_id}")
    async def update_finding(finding_id: int, request: Request):
        try:
            data = await body(request, ("status",))
        except ValueError as exc:
            return error(400, str(exc))
        return handle(store.set_finding_status, finding_id, str(data["status"]), str(data.get("note") or ""),
                      "user")

    @app.get("/api/findings/{finding_id}/history")
    def finding_history(finding_id: int):
        if not store.get_finding(finding_id):
            return error(404, tr("Unknown finding"))
        return store.finding_history(finding_id)

    @app.get("/api/projects/{project_id}/history")
    def project_history(project_id: int):
        return handle(lambda: (project_or_404(project_id), store.project_history(project_id))[1])

    @app.get("/api/compare")
    def compare(base: int, head: int):
        return handle(store.compare, base, head)

    # -- audits launched from the dashboard -------------------------------------------------
    @app.post("/api/projects/{project_id}/jobs", status_code=202)
    async def launch(project_id: int, request: Request):
        try:
            data = await body(request, ("mode",))
            project_or_404(project_id)
        except KeyError as exc:
            return error(404, str(exc.args[0]))
        except ValueError as exc:
            return error(400, str(exc))
        mode = str(data["mode"])
        if mode not in PASSIVE_MODES:
            return error(403, tr("Only passive modes can be launched from the Security Center"))
        entry = None
        if data.get("target_id") is not None:
            entry = store.get_target(data["target_id"]) if isinstance(data["target_id"], int) else None
            if entry and entry["project_id"] != project_id:
                entry = None
        elif data.get("target"):
            entry = store.in_scope(project_id, str(data["target"]))
        if not entry:
            return error(403, tr("The target is not registered in this project's scope"))
        return handle(jobs.submit, project_id, entry, mode)

    @app.get("/api/jobs")
    def list_jobs():
        return jobs.list()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: int):
        return handle(jobs.get, job_id)

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: int):
        return handle(jobs.cancel, job_id)

    # -- tools ------------------------------------------------------------------------------
    @app.get("/api/tools")
    def tool_status(refresh: bool = False):
        with tools_lock:
            if refresh or tools_cache["data"] is None or time.time() - tools_cache["at"] > TOOLS_CACHE_SECONDS:
                if tools_detect:
                    tools_cache["data"] = tools_detect()
                else:
                    import tools
                    tools_cache["data"] = tools.detect_all()
                tools_cache["at"] = time.time()
            return {"checked_at": tools_cache["at"], "tools": tools_cache["data"]}

    # -- exports ----------------------------------------------------------------------------
    def bundle(project_id, audit_id):
        return store.report_bundle(project_id, audit_id)

    def download(content, media, filename):
        return Response(content, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/projects/{project_id}/export/findings.csv")
    def export_csv(project_id: int, audit_id: int | None = None):
        def run():
            data = bundle(project_id, audit_id)
            return download(exporters.findings_csv(data["findings"]).encode("utf-8-sig"), "text/csv; charset=utf-8",
                            f"domaininfo-findings-{project_id}.csv")
        return handle(run)

    @app.get("/api/projects/{project_id}/export/{kind}.pdf")
    def export_pdf(project_id: int, kind: str, audit_id: int | None = None):
        def run():
            if kind not in ("executive", "technical"):
                raise KeyError(tr("Unknown report"))
            data = bundle(project_id, audit_id)
            content = exporters.executive_pdf(data) if kind == "executive" else exporters.technical_pdf(data)
            return download(content, "application/pdf", f"domaininfo-{kind}-{project_id}.pdf")
        return handle(run)

    # -- static UI --------------------------------------------------------------------------
    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PATCH", "DELETE"])
    def api_not_found(rest: str):
        return error(404, tr("Not found"))

    @app.get("/{path:path}")
    def static(path: str):
        name = path or "index.html"
        if name in webui:
            content, media = webui[name]
            return Response(content, media_type=media)
        if "index.html" in webui and "." not in name.rsplit("/", 1)[-1]:
            content, media = webui["index.html"]
            return Response(content, media_type=media)
        if not webui and name == "index.html":
            return Response(_FALLBACK_PAGE.format(message=tr("The web interface is not built. Run npm run build "
                                                             "in the webui folder.")), media_type="text/html")
        return error(404, tr("Not found"))

    return app


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, open_browser=True, allow_remote=False, db_path=None):
    """Run the Security Center until CTRL+C. Refuses non-loopback addresses unless ``allow_remote``."""
    require_extra()
    import uvicorn

    from auditstore import AuditStore
    if not is_loopback(host) and not allow_remote:
        raise ValueError(tr("Refusing to listen on {host}: the Security Center only listens on loopback "
                            "unless remote access is explicitly allowed", host=host))
    if not 1 <= int(port) <= 65535:
        raise ValueError(tr("Port out of range"))
    token = secrets.token_urlsafe(32)
    store = AuditStore(db_path)
    app = create_app(store, token, allowed_hosts(host, port))
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else ("[" + host + "]" if ":" in host else host)  # noqa: S104  # nosec B104
    url = f"http://{shown}:{port}/#token={token}"
    if not is_loopback(host):
        print(tr("WARNING: remote access enabled on {host}. Traffic is not encrypted; use it only on a trusted "
                 "network or behind an HTTPS tunnel.", host=host), file=sys.stderr)
    print(tr("DomainInfo Security Center at {url}", url=url), file=sys.stderr)
    print(tr("Database: {path}. Press CTRL+C to stop.", path=store.path), file=sys.stderr)
    config = uvicorn.Config(app, host=host, port=int(port), log_level="warning", server_header=False,
                            date_header=False, proxy_headers=False, forwarded_allow_ips="",
                            limit_concurrency=64, timeout_keep_alive=5, h11_max_incomplete_event_size=64 * 1024)
    server = uvicorn.Server(config)
    if open_browser:
        import webbrowser
        timer = threading.Timer(1.0, webbrowser.open, (url,))
        timer.daemon = True
        timer.start()
    try:
        server.run()
    finally:
        app.state.jobs.shutdown()
        store.close()
    return 0


def main(argv=None):
    cli = argparse.ArgumentParser(prog="domaininfo-server", description=tr("DomainInfo Security Center"))
    cli.add_argument("--host", default=DEFAULT_HOST, help=tr("address to listen on (default: loopback)"))
    cli.add_argument("--port", type=int, default=DEFAULT_PORT, help=tr("TCP port (default: %(default)s)"))
    cli.add_argument("--no-browser", action="store_true", help=tr("do not open the browser"))
    cli.add_argument("--allow-remote", action="store_true",
                     help=tr("allow a non-loopback address (unencrypted; trusted networks only)"))
    cli.add_argument("--db", type=Path, help=tr("database file (default: user data folder)"))
    args = cli.parse_args(argv)
    try:
        return serve(args.host, args.port, not args.no_browser, args.allow_remote, args.db)
    except (MissingExtra, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
