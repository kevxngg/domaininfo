"""RouterOS version-based assessment. Author: Kevin (@kevxngg).

No exploit payloads, login attempts or configuration changes are performed.
Ranges follow the disclosing CERT; the vendor bulletin provides remediation.
"""

from dataclasses import dataclass
import re
import socket
from urllib import error, request

REVIEWED = "2026-10-26"
VENDOR = "https://mikrotik.com/supportsec/september-2026-vulnerability/"
CERT = "https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/"
RELEASES_URL = "https://mikrotik.com/download/changelogs"
RELEASES = {"stable": "7.25", "long-term": "7.23.8", "legacy-6": "6.49.23"}
PORTS = (21, 22, 23, 80, 443, 2000, 8080, 8291, 8443, 8728, 8729)

# Half-open intervals: introduced <= installed < fixed.
# No inference is made for beta/rc builds: their backports require manual review.
COMMON = (("6.0", "6.49.21"), ("7.0", "7.23.4"), ("7.24", "7.24.2"))
ADVISORIES = (
    {"id": "CVE-2026-67276", "component": "SSH", "ports": (22,),
     "ranges": (("7.9", "7.23.4"), ("7.24", "7.24.2")),
     "summary": "Validación de claves RSA en autenticación SSH"},
    {"id": "CVE-2026-67277", "component": "bandwidth-test", "ports": (2000,),
     "ranges": COMMON, "summary": "Control de sesiones del servicio bandwidth-test"},
    {"id": "CVE-2026-67278", "component": "TLS/SSH client", "ports": (),
     "ranges": (("7.0", "7.23.6"), ("7.24", "7.24.3")),
     "summary": "Verificación de firmas en certificados y claves de host"},
    {"id": "CVE-2026-67279", "component": "SSH", "ports": (22,),
     "ranges": COMMON, "summary": "Control de acceso a canales de comandos SSH"},
    {"id": "CVE-2026-67281", "component": "WebFig", "ports": (80, 443, 8080, 8443),
     "ranges": (("7.20", "7.23.4"), ("7.24", "7.24.2")),
     "summary": "Acceso a archivos mediante la interfaz web"},
    {"id": "CVE-2026-86060", "component": "SSH", "ports": (22,),
     "ranges": COMMON, "summary": "Tratamiento de nombres de usuario en SSH"},
)


@dataclass(frozen=True)
class Version:
    numbers: tuple
    stage: str = ""
    build: int = 0

    @property
    def text(self):
        major, minor, patch = self.numbers
        base = f"{major}.{minor}" + (f".{patch}" if patch else "")
        return base + (f"{self.stage}{self.build}" if self.stage else "")


def parse_version(value):
    match = re.fullmatch(
        r"\s*(?:RouterOS\s+)?v?(\d{1,3})\.(\d{1,3})(?:\.(\d{1,3}))?"
        r"(?:(beta|rc)(\d{1,3}))?(?:\s*\((?:stable|long-term|testing|development)\))?\s*",
        value, re.I,
    )
    if not match:
        raise ValueError("Versión RouterOS inválida; usa 7.25, 7.23.8 o 7.26beta3")
    major, minor, patch = (int(match.group(i) or 0) for i in (1, 2, 3))
    return Version((major, minor, patch), (match.group(4) or "").lower(),
                   int(match.group(5) or 0))


def extract_versions(text):
    """Require a RouterOS marker: an SSH protocol/version is not an OS version."""
    pattern = (r"\bRouterOS\s*(?:version\s*[:=]?\s*)?v?"
               r"(\d{1,3}\.\d{1,3}(?:\.\d{1,3})?(?:(?:beta|rc)\d{1,3})?)"
               r"(?![\w.])")
    return sorted({parse_version(m).text for m in re.findall(pattern, text, re.I)})


def assess(version_text=None, open_ports=(), provenance="unknown"):
    version = parse_version(version_text) if version_text else None
    applicable = version and not version.stage and version.numbers[0] in (6, 7)
    findings = []
    for entry in ADVISORIES:
        status = "unknown_version"
        if version and not applicable:
            status = "manual_review"
        elif applicable:
            affected = any(parse_version(low).numbers <= version.numbers < parse_version(high).numbers
                           for low, high in entry["ranges"])
            status = "potentially_affected" if affected else "not_in_affected_range"
        reachable = sorted(set(open_ports).intersection(entry["ports"]))
        findings.append({
            "id": entry["id"], "component": entry["component"], "summary": entry["summary"],
            "status": status, "confirmed": False,
            "affected_ranges": [{"introduced": low, "fixed": high}
                                for low, high in entry["ranges"]],
            "observed_default_ports": reachable,
            "exposure": "default_port_reachable" if reachable else "not_established",
            "sources": [CERT, VENDOR],
        })
    comparisons = {}
    if applicable:
        for channel, release in RELEASES.items():
            baseline = parse_version(release).numbers
            if baseline[0] != version.numbers[0]:
                continue
            comparisons[channel] = ("older_than_snapshot" if version.numbers < baseline else
                                    "matches_snapshot" if version.numbers == baseline else
                                    "newer_than_snapshot")
    return {
        "version": version.text if version else None, "version_source": provenance,
        "catalog_reviewed": REVIEWED, "catalog_sources": [VENDOR, CERT],
        "release_snapshot": {"reviewed": REVIEWED, "versions": RELEASES,
                             "source": RELEASES_URL, "comparison": comparisons},
        "advisories": findings,
        "scope": "Solo los seis avisos de septiembre de 2026; no es una certificación de seguridad",
        "limitations": [
            "Versión declarada o banner no verificado contra un inventario autenticado",
            "Un puerto abierto no demuestra un CVE; uno cerrado no descarta el aviso",
            "Puertos personalizados, ACL y configuración interna requieren revisión adicional",
            "Beta/rc y ramas diferentes de 6/7 requieren revisión manual",
            "Catálogo y versiones son una instantánea fechada, no una consulta en tiempo real",
        ],
        "recommendations": [
            "Revisar los avisos y actualizar dentro de una rama compatible con el equipo",
            "Restringir SSH, WebFig, Winbox y API a la red de gestión o una VPN",
            "Deshabilitar Telnet, FTP, API sin TLS y bandwidth-test si no se utilizan",
            "Revisar usuarios, scripts, configuración y estado Flagged desde una sesión autorizada",
        ],
    }


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_web(target, port, timeout, scheme=None):
    """Fetch only a bounded public landing page; never follow off-target redirects."""
    scheme = scheme or ("https" if port in (443, 8443) else "http")
    host = f"[{target}]" if ":" in target else target
    url = f"{scheme}://{host}:{port}/"
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    req = request.Request(url, headers={"User-Agent": "DomainInfo-RouterOS/1"})
    try:
        response = opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    with response:
        text = str(response.headers) + "\n" + response.read(65536).decode("utf-8", "replace")
        return {"port": port, "protocol": scheme, "status": response.status,
                "versions": extract_versions(text),
                "routeros_marker": bool(re.search(r"mikrotik|routeros|webfig", text, re.I))}


def audit(target, args, probe_ports):
    if args.offline:
        result = assess(args.routeros_version, provenance="user_supplied")
        result.update({"offline": True, "port_checks": [], "evidence": []})
        return result
    # Copy arguments so default RouterOS ports do not change the other scan modes.
    from argparse import Namespace
    probe_args = Namespace(**vars(args))
    probe_args.ports = args.ports or sorted(set(PORTS).union(
        (args.web_port,) if args.web_port else ()).union((args.ssh_port,)))
    checks = probe_ports(target, probe_args)["results"]
    open_ports = {item["port"] for item in checks if item["state"] == "open"}
    evidence = []
    detected = set()
    web_ports = {80, 443, 8080, 8443}
    if args.web_port:
        web_ports.add(args.web_port)
    for port in sorted(open_ports.intersection(web_ports)):
        try:
            item = fetch_web(target, port, args.timeout,
                             args.scheme if port == args.web_port else None)
            detected.update(item["versions"])
            evidence.append(item)
        except (OSError, ValueError) as exc:
            evidence.append({"port": port, "error": str(exc)})
    if args.ssh_port in open_ports:
        try:
            with socket.create_connection((target, args.ssh_port), timeout=args.timeout) as conn:
                conn.settimeout(args.timeout)
                banner = conn.recv(1024).decode("utf-8", "replace")
            versions = extract_versions(banner)
            detected.update(versions)
            evidence.append({"port": args.ssh_port, "versions": versions,
                             "routeros_marker": bool(re.search(r"routeros|rosssh|mikrotik", banner, re.I))})
        except OSError as exc:
            evidence.append({"port": args.ssh_port, "error": str(exc)})
    declared = args.routeros_version
    selected = declared or (next(iter(detected)) if len(detected) == 1 else None)
    source = "user_supplied" if declared else "public_banner" if selected else "unknown"
    result = assess(selected, open_ports, source)
    result.update({"offline": False, "port_checks": checks, "evidence": evidence,
                   "detected_versions": sorted(detected),
                   "version_conflict": (len(detected) > 1 or bool(
                       declared and detected and detected != {parse_version(declared).text})),
                   "identity": "user_declared" if declared else
                       "routeros_indicators" if any(item.get("routeros_marker") for item in evidence)
                       else "unconfirmed"})
    if result["version_conflict"]:
        for entry in result["advisories"]:
            entry["status"] = "manual_review"
        result["limitations"].append("Versiones contradictorias: validar el inventario antes de concluir")
    return result
