#!/usr/bin/env python3
"""DomainInfo: portable domain diagnostics, requiring only Python 3.10+."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import functools
from datetime import datetime, timezone
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib import error, parse, request
import uuid

import i18n
from i18n import tr

VERSION = "6.0.0a1"
REPO = "kevxngg/domaininfo"
CERT_WARN_DAYS = 30
MODULES = ("dns", "rdap", "asn", "http", "tls", "tech", "mail", "subdomains", "history",
           "ports", "traceroute", "lookalike", "mikrotik", "webapp")
MODES = {
    "quick": ("dns", "rdap"),
    "web": ("dns", "http", "tls", "tech"),
    "ports": ("dns", "ports"),
    "full": ("dns", "rdap", "asn", "http", "tls", "tech", "mail", "subdomains", "history", "ports", "traceroute"),
    "mikrotik": ("mikrotik",),
    "mail": ("dns", "mail"),
    "recon": ("dns", "rdap", "asn", "tech", "subdomains", "history"),
    "brand": ("dns", "lookalike"),
    "webapp": ("webapp",),
}
# Modes and modules that only make sense for a domain (not for an IP address)
DOMAIN_ONLY = {"mail", "subdomains", "history", "lookalike"}
# Modes whose target is a full URL (scheme, host, port, path and query)
URL_MODES = {"webapp"}


class NotApplicable(Exception):
    """The module does not apply to this target (for example, mail checks for an IP address)."""
DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443)


def normalize_target(value):
    """Accept a hostname, IP or HTTP URL without shell interpolation."""
    value = value.strip()
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError(tr("Empty target or target with spaces/control characters"))
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    url = parse.urlsplit(value if "://" in value else "//" + value)
    if url.scheme and url.scheme.lower() not in ("http", "https"):
        raise ValueError(tr("Only HTTP/HTTPS URLs are accepted"))
    if url.username is not None or url.password is not None:
        raise ValueError(tr("Credentials are not accepted in the target"))
    host = url.hostname
    # Access port to reject malformed port numbers even though scans use --web-port.
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError(tr("Port out of range"))
    if not host:
        raise ValueError(tr("The target name is missing"))
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError(tr("Invalid domain"))
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError(tr("Invalid IPv4 address"))
    return host


def normalize_for_mode(value, mode):
    """URL modes keep the full URL; every other mode keeps only the host, as always."""
    if mode in URL_MODES:
        import safety
        return safety.normalize_url(value)
    return normalize_target(value)


def resolve(target):
    addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    return sorted({entry[4][0] for entry in addresses})


def fetch(url, timeout, limit=1024 * 1024):
    req = request.Request(url, headers={"User-Agent": "DomainInfo/" + VERSION,
                                        "Accept": "application/json, */*"})
    try:
        response = request.urlopen(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc  # HTTP errors still carry useful headers and status.
    with response:
        body = response.read(limit + 1)
        return {"url": response.geturl(), "status": response.status,
                "headers": dict(response.headers.items()),
                "truncated": len(body) > limit}, body[:limit]


def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def require_domain(target):
    if is_ip(target) or "." not in target:
        raise NotApplicable(tr("domains only"))


def dns_info(target, args):
    """System A/AAAA and, for domains, MX, NS, TXT, SOA, CAA, CNAME and DNSSEC with the built-in client."""
    import dnsclient
    result = {"addresses": resolve(target), "resolver": "system"}
    timeout = min(args.timeout, 5)
    if is_ip(target):
        try:
            result["ptr"] = dnsclient.values(dnsclient.reverse_name(target), "PTR", timeout)
        except dnsclient.DNSError:
            result["ptr"] = []
        return result
    if dnsclient.is_single_label(target):
        result["note"] = tr("Local name: system addresses only")
        return result
    records, errors = {}, []

    def one(kind):
        try:
            return kind, dnsclient.values(target, kind, timeout)
        except dnsclient.DNSError as exc:
            errors.append(f"{kind}: {exc}")
            return kind, []
    with ThreadPoolExecutor(max_workers=7) as pool:
        for kind, values in pool.map(one, ("NS", "MX", "TXT", "SOA", "CAA", "CNAME", "DS")):
            records[kind] = values
    result["dnssec"] = bool(records.pop("DS", []))
    result["records"] = records
    result["dns_server"] = ", ".join(dnsclient.system_resolvers())
    if errors:
        result["errors"] = errors
    return result


@functools.lru_cache(maxsize=32)
def _rdap(target, timeout):
    kind = "ip" if is_ip(target) else "domain"
    meta, body = fetch("https://rdap.org/" + kind + "/" + parse.quote(target, safe=""), timeout)
    if meta["status"] != 200:
        raise ValueError(tr("RDAP answered HTTP {status}", status=meta["status"]))
    if meta["truncated"]:
        raise ValueError(tr("RDAP response too large"))
    return body


def rdap_info(target, args):
    return json.loads(_rdap(target, args.timeout))


def asn_info(target, args):
    import netinfo
    addresses = [target] if is_ip(target) else resolve(target)
    with ThreadPoolExecutor(max_workers=4) as pool:
        networks = list(pool.map(lambda ip: netinfo.lookup(ip, min(args.timeout, 5)), addresses[:8]))
    return {"networks": networks, "source": "Team Cymru (DNS)"}


def mail_info(target, args):
    require_domain(target)
    import mailsec
    return mailsec.audit(target, None, min(args.timeout, 5), fetch)


def web_url(target, args):
    port = args.web_port or (443 if args.scheme == "https" else 80)
    default = (args.scheme == "https" and port == 443) or (args.scheme == "http" and port == 80)
    return f"{args.scheme}://{web_host(target)}" + ("" if default else f":{port}") + "/"


def tech_info(target, args):
    import webtech
    return webtech.audit(web_url(target, args), args.timeout, "Mozilla/5.0 (compatible; DomainInfo/" + VERSION + ")")


def subdomains_info(target, args):
    require_domain(target)
    import recon
    return recon.audit(target, args.threads, min(args.timeout, 5), brute=getattr(args, "brute", False))


def history_info(target, args):
    require_domain(target)
    import history
    result = {}
    try:
        result.update(history.from_rdap(json.loads(_rdap(target, args.timeout))))
    except (OSError, ValueError) as exc:
        result["rdap_error"] = str(exc)
    try:
        result["wayback"] = history.wayback(target, max(args.timeout, 10))
    except (OSError, ValueError) as exc:
        result["wayback"] = {"error": str(exc)}
    if "rdap_error" in result and "error" in result["wayback"]:
        raise ValueError(tr("No registration data and no Wayback Machine data"))
    return result


def lookalike_info(target, args):
    require_domain(target)
    import lookalike
    return lookalike.audit(target, args.threads, min(args.timeout, 3))


def web_host(target):
    return "[" + target + "]" if ":" in target else target


def http_info(target, args):
    port = args.web_port or (443 if args.scheme == "https" else 80)
    url = f"{args.scheme}://{web_host(target)}:{port}/"
    meta, body = fetch(url, args.timeout)
    headers = {k.lower(): v for k, v in meta["headers"].items()}
    expected = ["content-security-policy", "x-content-type-options", "referrer-policy"]
    if parse.urlsplit(meta["url"]).scheme == "https":
        expected.append("strict-transport-security")
    meta["missing_headers"] = [key for key in expected if key not in headers]
    title = re.search(r"<title[^>]*>(.*?)</title>", body.decode("utf-8", "replace"),
                      re.I | re.S)
    meta["title"] = html.unescape(title.group(1).strip()) if title else None
    meta["note"] = tr("Missing headers are observations; they do not prove a vulnerability")
    return meta


def tls_info(target, args):
    """Certificate (verified or, if not, the reason) and accepted TLS versions."""
    import tlsdeep
    port = args.web_port or 443
    result = tlsdeep.inspect(target, port, args.timeout)
    result["expiry_warning"] = expiry_warning(result.get("days_remaining"))
    if not getattr(args, "no_tls_versions", False):
        result["versions"] = tlsdeep.versions(target, port, min(args.timeout, 5))
    return result


def expiry_warning(days):
    """'expired', 'soon' (30 days or less) or None; shared by the CLI and the menu."""
    if days is None:
        return None
    if days < 0:
        return "expired"
    return "soon" if days <= CERT_WARN_DAYS else None


def ports_info(target, args):
    # Resolve once so per-port connection deadlines do not repeat DNS resolution.
    addresses = resolve(target)

    def check(port):
        attempts = []
        for address in addresses:
            try:
                with socket.create_connection((address, port), timeout=args.timeout):
                    return {"port": port, "state": "open", "address": address}
            except OSError as exc:
                attempts.append({"address": address, "error": str(exc)})
        return {"port": port, "state": "closed_or_filtered", "attempts": attempts}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        return {"protocol": "tcp", "results": list(pool.map(check, args.ports or DEFAULT_PORTS))}


def trace_info(target, args):
    if platform.system() == "Windows":
        executable = shutil.which("tracert")
        command = [executable, "-d", "-h", "15", "-w", "1000", target]
    else:
        executable = shutil.which("traceroute")
        command = [executable, "-n", "-m", "15", "-w", "1", "-q", "1", target]
        if not executable:
            executable = shutil.which("tracepath")
            command = [executable, "-n", "-m", "15", target]
    if not executable:
        return {"status": "unavailable",
                "reason": tr("Install traceroute/tracepath; TCP hops are not simulated")}
    result = subprocess.run(command, capture_output=True, text=True, errors="replace",
                            timeout=50, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or tr("Traceroute finished with an error"))
    return {"output": result.stdout, "returncode": result.returncode}


def mikrotik_info(target, args):
    import routeros
    return routeros.audit(target, args, ports_info)


def webapp_info(target, args):
    """Passive web security review of a full URL (no forms or credentials are ever submitted)."""
    import webapp
    return webapp.audit(target if "://" in target else web_url(target, args), args)


RUNNERS = {"dns": dns_info, "rdap": rdap_info, "asn": asn_info, "http": http_info,
           "tls": tls_info, "tech": tech_info, "mail": mail_info, "subdomains": subdomains_info,
           "history": history_info, "ports": ports_info, "traceroute": trace_info,
           "lookalike": lookalike_info, "mikrotik": mikrotik_info, "webapp": webapp_info}


def scan(target, args, on_progress=None):
    report = {"meta": {"tool": "DomainInfo", "version": VERSION, "target": target,
                       "date": datetime.now(timezone.utc).isoformat(), "mode": args.mode,
                       "platform": platform.system()}, "modules": {}}
    for index, name in enumerate(MODES[args.mode], 1):
        if name in args.skip:
            report["modules"][name] = {"status": "skipped"}
            if on_progress:
                on_progress(name, "skipped", index, len(MODES[args.mode]))
            continue
        if on_progress:
            on_progress(name, "running", index, len(MODES[args.mode]))
        try:
            data = RUNNERS[name](target, args)
            report["modules"][name] = {"status": "ok", "data": data}
        except NotApplicable as exc:
            report["modules"][name] = {"status": "skipped", "reason": str(exc)}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            report["modules"][name] = {"status": "error", "error": str(exc)}
        if on_progress:
            on_progress(name, report["modules"][name]["status"], index, len(MODES[args.mode]))
        # The readable output draws its own progress; JSON mode keeps the classic stderr lines.
        if not args.quiet and not getattr(args, "human", False):
            print(f"[{name}] {report['modules'][name]['status']}", file=sys.stderr)
    import score
    assessment = score.assess(report)
    if assessment:
        report["score"] = assessment
    import evidence
    detail = evidence.assess(report)
    if detail:
        report["assessment"] = detail
    return report


def atomic_write(path, content):
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, delete=False) as stream:
            temp_name = stream.name
            stream.write(content)
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def save_report(report, directory, formats):
    directory.mkdir(parents=True, exist_ok=True)
    target = re.sub(r"[^a-zA-Z0-9._-]", "_", report["meta"]["target"])
    stem = f"domaininfo_{target}_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:8]}"
    serialized = json.dumps(report, ensure_ascii=False, indent=2)
    paths = []
    for fmt in formats:
        path = directory / (stem + "." + fmt)
        if fmt in ("html", "txt", "md"):
            import render
            content = {"html": render.to_html, "txt": render.to_text, "md": render.to_markdown}[fmt](
                sys.modules[__name__], report, serialized)
        else:
            content = serialized + "\n"
        atomic_write(path, content)
        paths.append(str(path))
    return paths


def save_batch(reports, directory):
    """Infrastructure map (JSON/MD) and CSV summary of several targets."""
    import infra
    directory.mkdir(parents=True, exist_ok=True)
    # File names stay stable across languages so scripts can find them.
    stem = f"domaininfo_lote_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}"
    result = infra.correlate(reports)
    paths = []
    for suffix, content in ((".csv", infra.to_csv(reports)), ("_mapa.md", infra.map_markdown(result)),
                            ("_mapa.json", json.dumps(result, ensure_ascii=False, indent=2) + "\n")):
        path = directory / (stem + suffix)
        atomic_write(path, content)
        paths.append(str(path))
    return result, paths


def bounded_int(low, high):
    def convert(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(tr("Must be an integer")) from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(tr("Must be between {low} and {high}", low=low, high=high))
        return number
    return convert


def timeout_value(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(tr("Invalid timeout")) from exc
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError(tr("Timeout must be between 0.1 and 60 seconds"))
    return number


def port_list(value):
    try:
        return sorted({bounded_int(1, 65535)(item.strip()) for item in value.split(",")})
    except argparse.ArgumentTypeError as exc:
        raise argparse.ArgumentTypeError(tr("Invalid ports: use 22,80,443 (1-65535)")) from exc


def doctor():
    import tools
    return {"python": platform.python_version(), "platform": platform.platform(),
            "openssl": ssl.OPENSSL_VERSION, "core": tr("stdlib; no root or pip needed"),
            "optional": {name: shutil.which(name) for name in
                         ("traceroute", "tracepath", "tracert", "bash", "nmap", "dig", "whois")},
            "integrations": tools.detect_all()}


def host_list(value):
    """--scope: comma-separated hosts; accepts *.domain."""
    import safety
    hosts = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            wildcard = item.startswith("*.")
            hosts.append(("*." if wildcard else "") + safety.normalize_host(item[2:] if wildcard else item))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(tr("Invalid host in --scope: {host}", host=item)) from exc
    return hosts


EXAMPLES = """\
examples:
  domaininfo                                    guided menu
  domaininfo example.com                        quick analysis (DNS + registration)
  domaininfo -m web example.com                 website, headers and TLS certificate
  domaininfo -m ports --ports 22,80,443 10.0.0.5
  domaininfo -m full -s traceroute example.com  everything except the network route
  domaininfo -f targets.txt -m web --format html
  domaininfo -m mikrotik 192.168.88.1
  domaininfo -m mikrotik --offline --routeros-version 7.24.2
  domaininfo -m web --watch 300 example.com     watch and report changes
  domaininfo -m webapp --url https://example.com/login
                                                passive web security review of one URL
  domaininfo -m webapp --url https://app.example.com/ --scope auth.example.com
                                                allows following redirects to another authorized host
  domaininfo example.com --json --pretty        indented JSON
  domaininfo example.com | jq .                 in a pipe the output is JSON automatically
  domaininfo --lang es example.com              output in Spanish (or set DOMAININFO_LANG=es)

output:
  At a terminal you get a readable, colored summary. If the output goes to another
  program or a file, or you use --json/-q, the usual JSON is printed (one per target).
  NO_COLOR disables colors. Exit codes: 0 success, 1 errors in modules or
  targets, 2 invalid arguments, 130 interrupted.

Use the network modes only on systems you are authorized to review."""


class LocalizedHelp(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, tr("usage: ") if prefix is None else prefix)


def default_language():
    """Language from DOMAININFO_LANG, else English (``--lang`` overrides it)."""
    value = (os.environ.get("DOMAININFO_LANG") or "").strip().lower()[:2]
    return value if value in i18n.SUPPORTED else "en"


def parser():
    cli = argparse.ArgumentParser(prog="domaininfo", add_help=False, formatter_class=LocalizedHelp,
                                  description=tr("DomainInfo: portable diagnostics for domains and IPs"),
                                  epilog=tr(EXAMPLES))
    cli._positionals.title = tr("arguments")
    cli._optionals.title = tr("general")
    cli.add_argument("target", nargs="?", help=tr("domain, IPv4, IPv6 or HTTP/HTTPS URL"))
    cli.add_argument("-h", "--help", action="help", help=tr("show this help and exit"))
    cli.add_argument("--version", action="version", version=VERSION, help=tr("show the version and exit"))
    cli.add_argument("--interactive", action="store_true", help=tr("open the guided menu"))
    cli.add_argument("--doctor", action="store_true", help=tr("local diagnostics of this computer, no scans"))
    cli.add_argument("--update", action="store_true", help=tr("update DomainInfo to the latest version"))
    cli.add_argument("--completion", choices=("bash", "zsh", "powershell"),
                     help=tr("print the autocompletion script for your shell"))
    cli.add_argument("--lang", choices=i18n.SUPPORTED, default=default_language(),
                     help=tr("output language (default: DOMAININFO_LANG, else en)"))

    audit = cli.add_argument_group(tr("audit"))
    audit.add_argument("-m", "--mode", choices=MODES, default="quick",
                       help=tr("quick: DNS and registration · web: HTTP, headers and TLS · ports: TCP ports · "
                               "full: everything · mikrotik: RouterOS · webapp: one specific URL "
                               "(default: %(default)s)"))
    audit.add_argument("--url", metavar="URL",
                       help=tr("webapp: full URL to audit; port, path and parameters are kept"))
    audit.add_argument("-f", "--file", type=Path, metavar=tr("FILE"),
                       help=tr("UTF-8 file with one target per line (# for comments)"))
    audit.add_argument("-s", "--skip", choices=MODULES, action="append", default=[], metavar=tr("MODULE"),
                       help=tr("skip a module; can be repeated: {modules}", modules=", ".join(MODULES)))
    audit.add_argument("--brute", action="store_true",
                       help=tr("subdomains: besides certificates, also try the word list"))
    audit.add_argument("--no-tls-versions", action="store_true",
                       help=tr("TLS: do not check which versions the server accepts (faster)"))
    audit.add_argument("--watch", type=bounded_int(5, 86400), metavar=tr("SECONDS"),
                       help=tr("repeat the review every N seconds and report only changes (CTRL+C to quit)"))

    network = cli.add_argument_group(tr("network"))
    network.add_argument("-t", "--threads", type=bounded_int(1, 64), default=15, metavar="N",
                         help=tr("simultaneous TCP connections, 1-64 (default: %(default)s)"))
    network.add_argument("--resolver", metavar="IP",
                         help=tr("DNS server for MX/TXT/NS (default: the system's; if it does not answer, DNS over HTTPS)"))
    network.add_argument("--timeout", type=timeout_value, default=5.0, metavar=tr("SEC"),
                         help=tr("maximum wait per connection, 0.1-60 s (default: %(default)s)"))
    network.add_argument("--ports", type=port_list, metavar=tr("LIST"),
                         help=tr("comma-separated TCP ports, e.g. 22,80,443 (default depends on the mode)"))
    network.add_argument("--scheme", choices=("http", "https"), default="https",
                         help=tr("protocol for the web mode (default: %(default)s)"))
    network.add_argument("--web-port", type=bounded_int(1, 65535), metavar=tr("PORT"),
                         help=tr("web server port (default 443 or 80)"))

    scope = cli.add_argument_group(tr("scope and safety (webapp)"))
    scope.add_argument("--scope", type=host_list, action="extend", default=[], metavar="HOSTS",
                       help=tr("extra hosts authorized for following redirects, e.g. auth.example.com,*.cdn.example.com"))
    scope.add_argument("--allow-private", action="store_true",
                       help=tr("allow a public target to redirect or resolve to internal networks (only if authorized)"))
    scope.add_argument("--insecure-tls", action="store_true",
                       help=tr("read the page even if its certificate is not valid (noted in the report)"))

    router = cli.add_argument_group("mikrotik")
    router.add_argument("--routeros-version", metavar=tr("VERSION"),
                        help=tr("declared RouterOS version, for example 7.25"))
    router.add_argument("--ssh-port", type=bounded_int(1, 65535), default=22, metavar=tr("PORT"),
                        help=tr("SSH port to read the banner, without authentication (default: %(default)s)"))
    router.add_argument("--offline", action="store_true",
                        help=tr("evaluate the version without connecting to any device"))

    output = cli.add_argument_group(tr("output"))
    output.add_argument("--json", action="store_true",
                        help=tr("print JSON even at a terminal"))
    output.add_argument("--pretty", action="store_true", help=tr("indented JSON, easier to read"))
    output.add_argument("-q", "--quiet", action="store_true",
                        help=tr("JSON only on stdout, no progress"))
    output.add_argument("-o", "--output", type=Path, default=Path("logs"), metavar=tr("FOLDER"),
                        help=tr("reports folder (default: %(default)s)"))
    output.add_argument("--format", choices=("json", "txt", "html", "md", "all"), default="all",
                        help=tr("report formats to save (default: %(default)s)"))
    output.add_argument("--open", action="store_true", help=tr("open the HTML report when finished"))
    output.add_argument("-v", "--verbose", action="store_true",
                        help=tr("show report paths on stderr"))
    output.add_argument("-j", action="store_true", help=argparse.SUPPRESS)  # old flag: same as --json
    return cli


def latest_release(timeout=5):
    """Latest published tag on GitHub, or None without network."""
    try:
        meta, body = fetch(f"https://api.github.com/repos/{REPO}/releases/latest", timeout, 256 * 1024)
        return json.loads(body).get("tag_name") if meta["status"] == 200 else None
    except (OSError, ValueError):
        return None


def self_update():
    here = Path(__file__).resolve().parent
    latest = latest_release()
    if latest:
        print(tr("Installed: v{version} · latest published: {latest}", version=VERSION, latest=latest))
    else:
        print(tr("Installed: v{version}", version=VERSION))
    if (here / ".git").exists() and shutil.which("git"):
        result = subprocess.run(["git", "-C", str(here), "pull", "--ff-only"], check=False)
        if result.returncode:
            print(tr("Could not update with git. Check whether you have local changes in {path}", path=here),
                  file=sys.stderr)
        return result.returncode
    print(tr("This copy is not a git repository. Update with the method you used to install it:"))
    print("  pipx upgrade domaininfo")
    print(f"  pip install --upgrade git+https://github.com/{REPO}")
    return 0


def open_html(paths):
    import webbrowser
    for path in paths:
        if path.endswith(".html"):
            try:
                webbrowser.open(Path(path).resolve().as_uri())
            except (OSError, webbrowser.Error):
                print(tr("Could not open the browser: {path}", path=path), file=sys.stderr)
            return


def fingerprint(report):
    """Facts that matter for --watch; volatile values (dates, days left) stay out."""
    facts = {}
    for name, module in report["modules"].items():
        facts[name + ".status"] = module["status"]
        data = module.get("data") if isinstance(module.get("data"), dict) else {}
        if name == "dns":
            facts["dns.addresses"] = ", ".join(data.get("addresses", []))
        elif name == "http":
            facts["http.status"] = data.get("status")
            facts["http.missing_headers"] = ", ".join(data.get("missing_headers", []))
        elif name == "tls":
            cert = data.get("certificate") or {}
            facts["tls.expires"] = data.get("expires")
            facts["tls.serial"] = cert.get("serialNumber")
            facts["tls.protocol"] = data.get("protocol")
        elif name == "ports":
            facts["ports.open"] = ", ".join(str(row["port"]) for row in data.get("results", [])
                                            if row.get("state") == "open")
        elif name == "mikrotik":
            facts["mikrotik.version"] = data.get("version")
        elif name == "mail":
            facts["mail.grade"] = data.get("grade")
            facts["mail.dmarc"] = (data.get("dmarc") or {}).get("policy")
        elif name == "subdomains":
            facts["subdomains.alive"] = len(data.get("alive", []))
            facts["subdomains.takeover"] = ", ".join(r["name"] for r in data.get("takeover", []))
        elif name == "tech":
            facts["tech.list"] = ", ".join(t["name"] for t in data.get("technologies", []))
        elif name == "lookalike":
            facts["lookalike.registered"] = ", ".join(r["domain"] for r in data.get("registered", []))
        elif name == "webapp":
            facts["webapp.status"] = data.get("status")
            facts["webapp.findings"] = ", ".join(sorted({f["title"] for f in data.get("findings", [])
                                                         if f.get("status") in ("confirmed", "likely")}))
    if isinstance(report.get("score"), dict):
        facts["score.grade"] = report["score"].get("grade")
    return facts


FACT_LABELS = {"dns.addresses": "Addresses", "http.status": "HTTP status",
               "http.missing_headers": "Missing headers", "tls.expires": "Certificate expiry",
               "tls.serial": "Certificate serial number", "tls.protocol": "TLS protocol",
               "ports.open": "Open ports", "mikrotik.version": "RouterOS version",
               "mail.grade": "Mail grade", "mail.dmarc": "DMARC policy",
               "subdomains.alive": "Active subdomains", "subdomains.takeover": "Subdomains open to takeover",
               "tech.list": "Technologies", "lookalike.registered": "Registered lookalike domains",
               "score.grade": "Security grade", "webapp.status": "HTTP status of the URL",
               "webapp.findings": "Confirmed or likely web findings"}


def describe_changes(before, after):
    changes = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            label = tr(FACT_LABELS[key]) if key in FACT_LABELS else tr("Module {name}", name=key.split(".")[0])
            changes.append(f"{label}: {before.get(key) or '—'} → {after.get(key) or '—'}")
    return changes


def emit_json(report, args):
    print(json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None), flush=True)


def run_targets(targets, args, view):
    """One pass over every target; returns (failed, reports)."""
    failed, reports = False, []
    formats = ("json", "txt", "html") if args.format == "all" else (args.format,)
    for target in targets:
        report = scan(target, args, on_progress=view.progress if view else None)
        try:
            paths = save_report(report, args.output, formats)
        except OSError as exc:
            print(tr("Could not save the report: {error}", error=exc), file=sys.stderr)
            failed = True
            paths = []
        if args.verbose:
            print(tr("Reports: {paths}", paths=", ".join(paths)), file=sys.stderr)
        if view:
            view.report(report, paths)
        else:
            emit_json(report, args)
        if args.open:
            open_html(paths)
        failed |= any(module["status"] == "error" for module in report["modules"].values())
        reports.append(report)
    if len(reports) > 1:
        try:
            result, paths = save_batch(reports, args.output)
            message = tr("Batch: {count} items shared between targets · {paths}",
                         count=len(result["groups"]), paths=", ".join(paths))
            if view:
                view.note(message)
            elif args.verbose:
                print(message, file=sys.stderr)
        except OSError as exc:
            print(tr("Could not save the batch summary: {error}", error=exc), file=sys.stderr)
    return failed, reports


def watch(targets, args, view):
    """Repeat the audit and report only what changed, until CTRL+C."""
    _, reports = run_targets(targets, args, view)
    known = {report["meta"]["target"]: fingerprint(report) for report in reports}
    if view:
        view.note(tr("Watching {count} target(s) every {seconds} s. CTRL+C to quit.",
                     count=len(targets), seconds=args.watch))
    saved_open, args.open = args.open, False
    try:
        while True:
            time.sleep(args.watch)
            for target in targets:
                report = scan(target, args, on_progress=view.progress if view else None)
                facts = fingerprint(report)
                changes = describe_changes(known.get(target, {}), facts)
                known[target] = facts
                stamp = datetime.now().strftime("%H:%M:%S")
                if not changes:
                    if view:
                        view.quiet_tick(tr("[{time}] {target}: no changes", time=stamp, target=target))
                    continue
                formats = ("json", "txt", "html") if args.format == "all" else (args.format,)
                try:
                    save_report(report, args.output, formats)
                except OSError as exc:
                    print(tr("Could not save the report: {error}", error=exc), file=sys.stderr)
                if view:
                    view.changes(stamp, target, changes)
                else:
                    print(json.dumps({"event": "change", "time": datetime.now(timezone.utc).isoformat(),
                                      "target": target, "changes": changes, "report": report},
                                     ensure_ascii=False, indent=2 if args.pretty else None), flush=True)
    except KeyboardInterrupt:
        if view:
            view.note(tr("Watch stopped."))
        return 0
    finally:
        args.open = saved_open


def requested_language(argv):
    """``--lang`` value from the raw arguments, read before the parser so --help is translated too."""
    for index, item in enumerate(argv):
        if item == "--lang" and index + 1 < len(argv):
            return argv[index + 1]
        if item.startswith("--lang="):
            return item.split("=", 1)[1]
    return None


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:] if argv is None else list(argv)
    i18n.set_language(requested_language(argv) or default_language())
    cli = parser()
    args = cli.parse_args(argv)
    i18n.set_language(args.lang)
    if args.resolver:
        try:
            os.environ["DOMAININFO_RESOLVER"] = ",".join(str(ipaddress.ip_address(item.strip()))
                                                         for item in args.resolver.split(","))
        except ValueError:
            cli.error(tr("--resolver must be one or more comma-separated IP addresses"))
    if args.completion:
        from completions import script
        print(script(args.completion, cli))
        return 0
    if args.update:
        return self_update()
    if args.doctor:
        print(json.dumps(doctor(), ensure_ascii=False, indent=2))
        return 0
    if args.routeros_version or args.offline:
        if args.mode != "mikrotik":
            cli.error(tr("--routeros-version and --offline require -m mikrotik"))
        if args.offline and (not args.routeros_version or args.target or args.file):
            cli.error(tr("--offline requires --routeros-version and does not accept targets/files"))
        if args.routeros_version:
            import routeros
            try:
                args.routeros_version = routeros.parse_version(args.routeros_version).text
            except ValueError as exc:
                cli.error(str(exc))
    if args.url:
        if args.mode not in URL_MODES:
            cli.error(tr("--url requires -m webapp"))
        if args.target or args.file:
            cli.error(tr("Use --url, a target or --file, not several at once"))
        args.target = args.url
    if args.target and args.file:
        cli.error(tr("Use a target or --file, not both"))
    if args.interactive and (args.target or args.file or args.offline):
        cli.error(tr("--interactive does not accept a target, --file or --offline; choose inside the menu"))
    if args.interactive or (not args.target and not args.file and not args.offline and sys.stdin.isatty()):
        from terminal_ui import InteractiveApp
        return InteractiveApp(sys.modules[__name__], args).run()
    raw_targets = []
    if args.offline:
        raw_targets = ["routeros-offline"]
    elif args.file:
        try:
            raw_targets = args.file.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError) as exc:
            cli.error(str(exc))
    elif args.target:
        raw_targets = [args.target]
    else:
        cli.error(tr("Give a target, --file or --doctor"))
    targets = []
    invalid = False
    for raw in raw_targets:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            target = normalize_for_mode(raw, args.mode)
            if target not in targets:
                targets.append(target)
        except (ValueError, UnicodeError) as exc:
            print(tr("Invalid target {target}: {error}", target=repr(raw), error=exc), file=sys.stderr)
            invalid = True
    if not targets:
        cli.error(tr("No valid targets"))
    # Readable view only for a person at a terminal; pipes, files, --json and -q keep JSON.
    args.human = not (args.json or args.j or args.quiet or args.pretty) and sys.stdout.isatty()
    view = None
    if args.human:
        from terminal_ui import CliView
        view = CliView(sys.modules[__name__], args)
    if args.watch:
        return watch(targets, args, view)
    failed, _ = run_targets(targets, args, view)
    return 1 if failed or invalid else 0


def entry():
    """Console entry point (pipx/pip) and direct execution."""
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print(tr("Interrupted"), file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry()
