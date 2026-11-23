"""Passive OpenAPI/Swagger analysis (DomainInfo 6.0, Phase 2).

Fetches the API description from the given URL, or from the usual documented locations under the
authorized origin (``COMMON_PATHS``), through ``safety`` (scope, pinned IP, limits). Then it
analyses the document only: it never calls a documented operation.

Reports: endpoint inventory, servers on plain http://, missing security schemes, operations
without security, API keys in query parameters, HTTP Basic over http://, sensitive-looking query
parameters and deprecated operations still published. JSON documents only; a YAML document is
reported as ``not_evaluated`` (no third-party parser in the core).

Public API: ``audit(url, args) -> dict`` and ``analyze(document, source_url) -> dict``.
"""

import http.client
import json
import re
import time
from urllib import parse

import evidence
from i18n import tr
import safety

TOOL = "domaininfo.apispec"
COMMON_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/swagger/v1/swagger.json", "/api-docs")
MAX_SPEC = 4 * 1024 * 1024
MAX_INVENTORY = 500
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
SENSITIVE_PARAM = re.compile(r"passw|pwd|secret|token|api.?key|apikey|access.?key|session|sid$|auth|credential|"
                             r"ssn|credit.?card|card.?number|cvv|iban|private", re.I)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _is_spec(data):
    return isinstance(data, dict) and (isinstance(data.get("openapi"), str) or isinstance(data.get("swagger"), str)) \
        and isinstance(data.get("paths", {}), dict)


def _looks_yaml(text):
    return bool(re.search(r"^(?:openapi|swagger)\s*:", text[:4096], re.M))


def _resolve(document, item, depth=0):
    """Follow a local ``$ref`` (``#/...``) a few levels; remote references are not fetched."""
    while isinstance(item, dict) and isinstance(item.get("$ref"), str) and depth < 5:
        ref = item["$ref"]
        if not ref.startswith("#/"):
            return {}
        node = document
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            node = node.get(part) if isinstance(node, dict) else None
        item, depth = node if isinstance(node, dict) else {}, depth + 1
    return item if isinstance(item, dict) else {}


def _servers(document, source_url):
    """Absolute server URLs declared by the document (relative ones resolved against the source)."""
    urls = []
    if isinstance(document.get("swagger"), str):
        host = document.get("host")
        base = document.get("basePath") or "/"
        schemes = [s for s in document.get("schemes") or [] if isinstance(s, str)]
        if host and isinstance(host, str):
            for scheme in schemes or [parse.urlsplit(source_url).scheme]:
                urls.append(f"{scheme}://{host}{base}")
        return urls
    for server in document.get("servers") or []:
        if isinstance(server, dict) and isinstance(server.get("url"), str):
            urls.append(parse.urljoin(source_url, server["url"]))
    return urls


def _schemes(document):
    if isinstance(document.get("swagger"), str):
        defs = document.get("securityDefinitions")
    else:
        defs = (document.get("components") or {}).get("securitySchemes") if isinstance(document.get("components"), dict) \
            else None
    return {k: _resolve(document, v) for k, v in defs.items()} if isinstance(defs, dict) else {}


def _operations(document):
    for path, item in (document.get("paths") or {}).items():
        item = _resolve(document, item)
        shared = item.get("parameters")
        shared = list(shared) if isinstance(shared, list) else []
        for method in HTTP_METHODS:
            op = item.get(method)
            if isinstance(op, dict):
                own = op.get("parameters")
                own = list(own) if isinstance(own, list) else []
                params = [_resolve(document, p) for p in shared + own if isinstance(p, dict)]
                yield str(path), method.upper(), op, params


def analyze(document, source_url):
    """Findings, checks and inventory for an already decoded OpenAPI/Swagger document."""
    findings, checks = [], {}
    target = evidence.redact_url(source_url)
    spec_path = parse.urlsplit(source_url).path or "/"

    def add(category, title, severity, status, proof, recommendation, path=spec_path, impact="", verification="",
            references=(), confidence="high"):
        findings.append(evidence.Finding(
            target=target, path=path, category=category, title=title, severity=severity, status=status,
            confidence=confidence, evidence=proof, tool=TOOL, impact=impact, verification=verification,
            recommendation=recommendation, references=list(references)).to_dict())

    def check(cid, state, kind="direct", detail=None):
        checks[cid] = {"id": cid, "state": state, "evidence": kind, **({"detail": detail} if detail else {})}

    version = document.get("openapi") or document.get("swagger")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    servers = _servers(document, source_url)
    schemes = _schemes(document)
    global_security = document.get("security")
    operations = list(_operations(document))

    add("api", tr("API description published ({count} operations)", count=len(operations)), "info", "informational",
        tr("{kind} {version} at {url}", kind="Swagger" if document.get("swagger") else "OpenAPI",
           version=str(version)[:20], url=target),
        tr("Publish the API description only if it is meant to be public"), confidence="high")

    # Servers over plain HTTP
    insecure = [s for s in servers if parse.urlsplit(s).scheme == "http"]
    if insecure:
        check("servers", "finding")
        add("transport", tr("API server declared over unencrypted HTTP"), "medium", "confirmed",
            tr("servers: {servers}", servers=", ".join(evidence.redact_url(s) for s in insecure[:5])),
            tr("Declare and serve the API over HTTPS only"), impact=tr("Requests and tokens can be read on the network"),
            references=["CWE-319"])
    else:
        check("servers", "ok" if servers else "not_applicable")

    # Security schemes
    if not schemes:
        check("security_schemes", "finding", "heuristic")
        add("authentication", tr("The API description declares no security schemes"), "medium", "pending",
            tr("No components.securitySchemes / securityDefinitions"),
            tr("Document the authentication of the API (and require it on the server)"),
            verification=tr("Call a non-destructive operation without credentials in an authorized environment"),
            references=["OWASP API2:2023"], confidence="low")
    else:
        check("security_schemes", "ok")

    # Operations without security (an explicit empty list, or no global/operation requirement)
    unsecured, deprecated, inventory = [], [], []
    query_secrets = []
    for path, method, op, params in operations:
        security = op.get("security", global_security)
        secured = bool(security) if isinstance(security, list) else None
        if not security:
            unsecured.append(f"{method} {path}")
        if op.get("deprecated") is True:
            deprecated.append(f"{method} {path}")
        for param in params:
            name = str(param.get("name") or "")
            if param.get("in") == "query" and SENSITIVE_PARAM.search(name):
                query_secrets.append(f"{method} {path} ?{name}")
        if len(inventory) < MAX_INVENTORY:
            inventory.append({"method": method, "path": path[:300],
                              "operation_id": str(op.get("operationId") or "")[:120] or None,
                              "deprecated": op.get("deprecated") is True, "secured": secured,
                              "tags": [str(t)[:60] for t in op.get("tags") or [] if isinstance(t, str)][:5]})
    if not operations:
        check("operation_security", "not_applicable")
    elif unsecured:
        check("operation_security", "finding", "heuristic")
        add("authentication", tr("{count} documented operations declare no security requirement",
                                 count=len(unsecured)), "medium", "pending", ", ".join(unsecured[:15]),
            tr("Declare a security requirement on every operation that is not deliberately public"),
            impact=tr("Undocumented or missing authentication on API operations"),
            verification=tr("Check each listed operation on the server with a test account; this module never "
                            "calls them"), references=["OWASP API2:2023", "CWE-306"], confidence="low")
    else:
        check("operation_security", "ok")

    # API keys in the query string and Basic over HTTP
    query_keys = [n for n, s in schemes.items() if s.get("type") == "apiKey" and s.get("in") == "query"]
    if query_keys:
        check("api_keys", "finding")
        add("authentication", tr("API key sent in the URL query string"), "medium", "confirmed",
            tr("securitySchemes: {names} (in: query)", names=", ".join(query_keys[:5])),
            tr("Send API keys in a header (e.g. Authorization or X-API-Key)"),
            impact=tr("Keys end up in server logs, proxies and browser history"), references=["CWE-598"])
    else:
        check("api_keys", "ok" if schemes else "not_applicable")
    basic = [n for n, s in schemes.items() if s.get("type") == "basic" or
             (s.get("type") == "http" and str(s.get("scheme", "")).lower() == "basic")]
    if basic and insecure:
        check("basic_auth", "finding")
        add("authentication", tr("HTTP Basic authentication over unencrypted HTTP"), "high", "confirmed",
            tr("Basic schemes {names} with servers {servers}", names=", ".join(basic[:5]),
               servers=", ".join(evidence.redact_url(s) for s in insecure[:3])),
            tr("Serve the API over HTTPS only; prefer token-based authentication"),
            impact=tr("Passwords travel in clear text (Base64) on every request"), references=["CWE-319", "CWE-523"])
    else:
        check("basic_auth", "ok" if basic else "not_applicable")

    if query_secrets:
        check("query_secrets", "finding", "heuristic")
        add("exposure", tr("Sensitive-looking parameters in the query string"), "medium", "likely",
            ", ".join(query_secrets[:15]), tr("Move secrets and personal data to headers or the request body"),
            impact=tr("Query strings are stored in logs, proxies and the Referer header"), references=["CWE-598"],
            confidence="medium")
    else:
        check("query_secrets", "ok" if operations else "not_applicable", "heuristic")

    if deprecated:
        check("deprecated", "finding")
        add("api", tr("{count} deprecated operations are still published", count=len(deprecated)), "low",
            "informational", ", ".join(deprecated[:15]),
            tr("Remove deprecated operations from the server and the description when no longer needed"),
            verification=tr("Check whether the deprecated operations still answer on the server"),
            references=["OWASP API9:2023"], confidence="high")
    else:
        check("deprecated", "ok" if operations else "not_applicable")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["category"]))
    check_list = list(checks.values())
    return {"spec_url": target, "format": "swagger" if document.get("swagger") else "openapi",
            "version": evidence.clean(str(version))[:20], "title": evidence.clean(str(info.get("title") or ""))[:120] or None,
            "servers": [evidence.redact_url(s) for s in servers[:20]], "security_schemes":
                [{"name": evidence.clean(n)[:60], "type": str(s.get("type"))[:20], "in": s.get("in")}
                 for n, s in list(schemes.items())[:20]],
            "operations": len(operations), "inventory": inventory, "findings": findings, "checks": check_list,
            "assessment": evidence.scores(findings, check_list)}


def _not_evaluated(url, detail, tried=()):
    checks = [{"id": "spec_fetch", "state": "not_evaluated", "evidence": "direct", "detail": detail}]
    return {"spec_url": evidence.redact_url(url), "tried": [evidence.redact_url(t) for t in tried], "findings": [],
            "checks": checks, "assessment": evidence.scores([], checks), "inventory": [],
            "note": tr("Passive analysis of the API description; documented operations are never called")}


def audit(url, args):
    """Fetch and analyse an OpenAPI/Swagger document. ``url`` is the document itself or, when its
    path is ``/``, the origin whose ``COMMON_PATHS`` are tried. ``args`` provides timeout, scope,
    allow_private and insecure_tls like webapp."""
    url = safety.normalize_url(url)
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    policy = safety.ScopePolicy(url, extra_hosts=list(getattr(args, "scope", None) or []),
                                allow_private=bool(getattr(args, "allow_private", False)))
    deadline = time.monotonic() + min(180.0, max(30.0, timeout * 12))
    insecure = bool(getattr(args, "insecure_tls", False))
    parts = parse.urlsplit(url)
    candidates = [url] if parts.path not in ("", "/") or parts.query else \
        [parse.urlunsplit((parts.scheme, parts.netloc, p, "", "")) for p in COMMON_PATHS]
    tried, yaml_seen, errors = [], None, []
    for candidate in candidates:
        tried.append(candidate)
        try:
            response = safety.http_get(candidate, policy, timeout, limit=MAX_SPEC, insecure_tls=insecure,
                                       deadline=deadline, headers={"Accept": "application/json, */*;q=0.5"})
        except safety.ScopeError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            errors.append(str(exc)[:200])
            continue
        if response.status != 200 or response.truncated:
            if response.truncated:
                errors.append(tr("Document larger than {limit} bytes", limit=MAX_SPEC))
            continue
        text = response.body.decode("utf-8", "replace")
        try:
            document = json.loads(text)
        except ValueError:
            if _looks_yaml(text):
                yaml_seen = response.url
            continue
        if _is_spec(document):
            result = analyze(document, response.url)
            result.update({"tried": [evidence.redact_url(t) for t in tried], "fetch_status": response.status,
                           "note": tr("Passive analysis of the API description; documented operations are never "
                                      "called")})
            checks = [{"id": "spec_fetch", "state": "ok", "evidence": "direct"}] + result["checks"]
            result["checks"] = checks
            result["assessment"] = evidence.scores(result["findings"], checks)
            return result
    if yaml_seen:
        return _not_evaluated(yaml_seen, tr("The API description is YAML; only JSON is parsed without "
                                            "dependencies (export it as JSON)"), tried)
    detail = tr("No OpenAPI/Swagger JSON document found")
    if errors:
        detail += " · " + evidence.clean(errors[-1])
    return _not_evaluated(url, detail, tried)
