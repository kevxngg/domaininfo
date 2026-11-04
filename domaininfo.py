#!/usr/bin/env python3
"""DomainInfo: portable domain diagnostics, requiring only Python 3.10+."""

import argparse
from concurrent.futures import ThreadPoolExecutor
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

VERSION = "4.3.0"
REPO = "kevxngg/domaininfo"
CERT_WARN_DAYS = 30
MODULES =("dns", "rdap", "http", "tls", "ports", "traceroute", "mikrotik")
MODES = {
    "quick": ("dns", "rdap"),
    "web": ("dns", "http", "tls"),
    "ports": ("dns", "ports"),
    "full": tuple(name for name in MODULES if name != "mikrotik"),
    "mikrotik": ("mikrotik",),
}
DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443)


def normalize_target(value):
    """Accept a hostname, IP or HTTP URL without shell interpolation."""
    value = value.strip()
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("Objetivo vacío o con espacios/caracteres de control")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    url = parse.urlsplit(value if "://" in value else "//" + value)
    if url.scheme and url.scheme.lower() not in ("http", "https"):
        raise ValueError("Solo se aceptan URLs HTTP/HTTPS")
    if url.username is not None or url.password is not None:
        raise ValueError("No se aceptan credenciales en el objetivo")
    host = url.hostname
    # Access port to reject malformed port numbers even though scans use --web-port.
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("Puerto fuera de rango")
    if not host:
        raise ValueError("Falta el nombre del objetivo")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Dominio inválido")
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError("Dirección IPv4 inválida")
    return host


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


def dns_info(target, args):
    # System resolver supports IPv4/IPv6 and local hosts on every platform.
    return {"addresses": resolve(target), "resolver": "system",
            "note": "A/AAAA del resolver del sistema; no incluye MX/TXT/NS"}


def rdap_info(target, args):
    try:
        ipaddress.ip_address(target)
        kind = "ip"
    except ValueError:
        kind = "domain"
    meta, body = fetch("https://rdap.org/" + kind + "/" + parse.quote(target, safe=""),
                       args.timeout)
    if meta["status"] != 200:
        raise ValueError("RDAP respondió HTTP " + str(meta["status"]))
    if meta["truncated"]:
        raise ValueError("Respuesta RDAP demasiado grande")
    return json.loads(body)


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
    meta["note"] = "Headers ausentes son observaciones; no prueban una vulnerabilidad"
    return meta


def tls_info(target, args):
    port = args.web_port or 443
    context = ssl.create_default_context()
    with socket.create_connection((target, port), timeout=args.timeout) as raw:
        with context.wrap_socket(raw, server_hostname=target) as conn:
            cert = conn.getpeercert()
            expiry = ssl.cert_time_to_seconds(cert["notAfter"])
            days = int((expiry - time.time()) // 86400)
            return {"verified": True, "protocol": conn.version(),
                    "cipher": conn.cipher(), "certificate": cert,
                    "expires": datetime.fromtimestamp(expiry, timezone.utc).date().isoformat(),
                    "days_remaining": days, "expiry_warning": expiry_warning(days)}


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
        return {"status": "unavailable", "reason": "Instala traceroute/tracepath; no se simulan saltos TCP"}
    result = subprocess.run(command, capture_output=True, text=True, errors="replace",
                            timeout=50, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Traceroute terminó con error")
    return {"output": result.stdout, "returncode": result.returncode}


def mikrotik_info(target, args):
    import routeros
    return routeros.audit(target, args, ports_info)


RUNNERS = {"dns": dns_info, "rdap": rdap_info, "http": http_info,
           "tls": tls_info, "ports": ports_info, "traceroute": trace_info,
           "mikrotik": mikrotik_info}


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
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            report["modules"][name] = {"status": "error", "error": str(exc)}
        if on_progress:
            on_progress(name, report["modules"][name]["status"], index, len(MODES[args.mode]))
        # The readable output draws its own progress; JSON mode keeps the classic stderr lines.
        if not args.quiet and not getattr(args, "human", False):
            print(f"[{name}] {report['modules'][name]['status']}", file=sys.stderr)
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
        if fmt == "html":
            content = ("<!doctype html><html lang='es'><meta charset='utf-8'>"
                       "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                       "<title>DomainInfo Report</title><style>body{font:16px system-ui;"
                       "max-width:1000px;margin:2rem auto;padding:1rem;background:#101827;color:#e5e7eb}"
                       "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>"
                       "<h1>DomainInfo: " + html.escape(report["meta"]["target"]) + "</h1><pre>"
                       + html.escape(serialized) + "</pre></html>")
        else:
            content = serialized + "\n"
        atomic_write(path, content)
        paths.append(str(path))
    return paths


def bounded_int(low, high):
    def convert(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("Debe ser un entero") from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Debe estar entre {low} y {high}")
        return number
    return convert


def timeout_value(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Timeout inválido") from exc
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError("Timeout debe estar entre 0.1 y 60 segundos")
    return number


def port_list(value):
    try:
        return sorted({bounded_int(1, 65535)(item.strip()) for item in value.split(",")})
    except argparse.ArgumentTypeError as exc:
        raise argparse.ArgumentTypeError("Puertos inválidos: usa 22,80,443 (1-65535)") from exc


def doctor():
    return {"python": platform.python_version(), "platform": platform.platform(),
            "openssl": ssl.OPENSSL_VERSION, "core": "stdlib; sin root ni pip",
            "optional": {name: shutil.which(name) for name in
                         ("traceroute", "tracepath", "tracert", "bash", "nmap", "dig", "whois")}}


EXAMPLES = """\
ejemplos:
  domaininfo                                    menú guiado
  domaininfo example.com                        análisis rápido (DNS + registro)
  domaininfo -m web example.com                 web, cabeceras y certificado TLS
  domaininfo -m ports --ports 22,80,443 10.0.0.5
  domaininfo -m full -s traceroute example.com  todo menos la ruta de red
  domaininfo -f objetivos.txt -m web --format html
  domaininfo -m mikrotik 192.168.88.1
  domaininfo -m mikrotik --offline --routeros-version 7.24.2
  domaininfo -m web --watch 300 example.com     vigilar y avisar de cambios
  domaininfo example.com --json --pretty        JSON con sangría
  domaininfo example.com | jq .                 en una tubería sale JSON automáticamente

salida:
  En una terminal se muestra un resumen legible con colores. Si la salida va a otro
  programa o archivo, o usas --json/-q, se imprime el JSON de siempre (uno por objetivo).
  NO_COLOR desactiva los colores. Códigos de salida: 0 correcto, 1 errores en módulos u
  objetivos, 2 argumentos inválidos, 130 interrumpido.

Usa los modos de red solo sobre sistemas que tengas autorización para revisar."""


class SpanishHelp(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, "uso: " if prefix is None else prefix)


def parser():
    cli = argparse.ArgumentParser(prog="domaininfo", add_help=False, formatter_class=SpanishHelp,
                                  description="DomainInfo: diagnóstico portable de dominios e IPs",
                                  epilog=EXAMPLES)
    cli._positionals.title = "argumentos"
    cli._optionals.title = "general"
    cli.add_argument("target", nargs="?", help="dominio, IPv4, IPv6 o URL HTTP/HTTPS")
    cli.add_argument("-h", "--help", action="help", help="muestra esta ayuda y sale")
    cli.add_argument("--version", action="version", version=VERSION, help="muestra la versión y sale")
    cli.add_argument("--interactive", action="store_true", help="abre el menú guiado")
    cli.add_argument("--doctor", action="store_true", help="diagnóstico local del equipo, sin escaneos")
    cli.add_argument("--update", action="store_true", help="actualiza DomainInfo a la última versión")
    cli.add_argument("--completion", choices=("bash", "zsh", "powershell"),
                     help="imprime el script de autocompletado para tu shell")

    audit = cli.add_argument_group("auditoría")
    audit.add_argument("-m", "--mode", choices=MODES, default="quick",
                       help="quick: DNS y registro · web: HTTP, cabeceras y TLS · ports: puertos TCP · "
                            "full: todo · mikrotik: RouterOS (por defecto: %(default)s)")
    audit.add_argument("-f", "--file", type=Path, metavar="ARCHIVO",
                       help="archivo UTF-8 con un objetivo por línea (# para comentarios)")
    audit.add_argument("-s", "--skip", choices=MODULES, action="append", default=[], metavar="MÓDULO",
                       help="omite un módulo; se puede repetir: " + ", ".join(MODULES))
    audit.add_argument("--watch", type=bounded_int(5, 86400), metavar="SEGUNDOS",
                       help="repite la revisión cada N segundos y avisa solo de los cambios (CTRL+C para salir)")

    network = cli.add_argument_group("red")
    network.add_argument("-t", "--threads", type=bounded_int(1, 64), default=15, metavar="N",
                         help="conexiones TCP simultáneas, 1-64 (por defecto: %(default)s)")
    network.add_argument("--timeout", type=timeout_value, default=5.0, metavar="SEG",
                         help="espera máxima por conexión, 0.1-60 s (por defecto: %(default)s)")
    network.add_argument("--ports", type=port_list, metavar="LISTA",
                         help="puertos TCP separados por comas, p. ej. 22,80,443 (por defecto según el modo)")
    network.add_argument("--scheme", choices=("http", "https"), default="https",
                         help="protocolo para el modo web (por defecto: %(default)s)")
    network.add_argument("--web-port", type=bounded_int(1, 65535), metavar="PUERTO",
                         help="puerto del servidor web (por defecto 443 o 80)")

    router = cli.add_argument_group("mikrotik")
    router.add_argument("--routeros-version", metavar="VERSIÓN",
                        help="versión RouterOS declarada, por ejemplo 7.25")
    router.add_argument("--ssh-port", type=bounded_int(1, 65535), default=22, metavar="PUERTO",
                        help="puerto SSH para leer el banner, sin autenticación (por defecto: %(default)s)")
    router.add_argument("--offline", action="store_true",
                        help="evalúa la versión sin conectar con ningún equipo")

    output = cli.add_argument_group("salida")
    output.add_argument("--json", action="store_true",
                        help="imprime JSON aunque estés en una terminal")
    output.add_argument("--pretty", action="store_true", help="JSON con sangría, más fácil de leer")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="solo JSON en stdout, sin progreso")
    output.add_argument("-o", "--output", type=Path, default=Path("logs"), metavar="CARPETA",
                        help="carpeta de reportes (por defecto: %(default)s)")
    output.add_argument("--format", choices=("json", "txt", "html", "all"), default="all",
                        help="formatos de reporte que se guardan (por defecto: %(default)s)")
    output.add_argument("--open", action="store_true", help="abre el reporte HTML al terminar")
    output.add_argument("-v", "--verbose", action="store_true",
                        help="muestra las rutas de los reportes en stderr")
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
    print(f"Instalada: v{VERSION}" + (f" · última publicada: {latest}" if latest else ""))
    if (here / ".git").exists() and shutil.which("git"):
        result = subprocess.run(["git", "-C", str(here), "pull", "--ff-only"], check=False)
        if result.returncode:
            print("No se pudo actualizar con git. Revisa si tienes cambios locales en " + str(here),
                  file=sys.stderr)
        return result.returncode
    print("Esta copia no es un repositorio git. Actualiza con el método que usaste al instalar:")
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
                print("No se pudo abrir el navegador: " + path, file=sys.stderr)
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
    return facts


FACT_LABELS = {"dns.addresses": "Direcciones", "http.status": "Estado HTTP",
               "http.missing_headers": "Cabeceras ausentes", "tls.expires": "Caducidad del certificado",
               "tls.serial": "Número de serie del certificado", "tls.protocol": "Protocolo TLS",
               "ports.open": "Puertos abiertos", "mikrotik.version": "Versión RouterOS"}


def describe_changes(before, after):
    changes = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            label = FACT_LABELS.get(key) or ("Módulo " + key.split(".")[0])
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
            print(f"No se pudo guardar reporte: {exc}", file=sys.stderr)
            failed = True
            paths = []
        if args.verbose:
            print("Reportes: " + ", ".join(paths), file=sys.stderr)
        if view:
            view.report(report, paths)
        else:
            emit_json(report, args)
        if args.open:
            open_html(paths)
        failed |= any(module["status"] == "error" for module in report["modules"].values())
        reports.append(report)
    return failed, reports


def watch(targets, args, view):
    """Repeat the audit and report only what changed, until CTRL+C."""
    _, reports = run_targets(targets, args, view)
    known = {report["meta"]["target"]: fingerprint(report) for report in reports}
    if view:
        view.note(f"Vigilando {len(targets)} objetivo(s) cada {args.watch} s. CTRL+C para salir.")
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
                        view.quiet_tick(f"[{stamp}] {target}: sin cambios")
                    continue
                formats = ("json", "txt", "html") if args.format == "all" else (args.format,)
                try:
                    save_report(report, args.output, formats)
                except OSError as exc:
                    print(f"No se pudo guardar reporte: {exc}", file=sys.stderr)
                if view:
                    view.changes(stamp, target, changes)
                else:
                    print(json.dumps({"event": "change", "time": datetime.now(timezone.utc).isoformat(),
                                      "target": target, "changes": changes, "report": report},
                                     ensure_ascii=False, indent=2 if args.pretty else None), flush=True)
    except KeyboardInterrupt:
        if view:
            view.note("Vigilancia detenida.")
        return 0
    finally:
        args.open = saved_open


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cli = parser()
    args = cli.parse_args(argv)
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
            cli.error("--routeros-version y --offline requieren -m mikrotik")
        if args.offline and (not args.routeros_version or args.target or args.file):
            cli.error("--offline requiere --routeros-version y no acepta objetivos/archivos")
        if args.routeros_version:
            import routeros
            try:
                args.routeros_version = routeros.parse_version(args.routeros_version).text
            except ValueError as exc:
                cli.error(str(exc))
    if args.target and args.file:
        cli.error("Usa un objetivo o --file, no ambos")
    if args.interactive and (args.target or args.file or args.offline):
        cli.error("--interactive no acepta objetivo, --file ni --offline; elige dentro del menú")
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
        cli.error("Indica un objetivo, --file o --doctor")
    targets = []
    invalid = False
    for raw in raw_targets:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            target = normalize_target(raw)
            if target not in targets:
                targets.append(target)
        except (ValueError, UnicodeError) as exc:
            print(f"Objetivo inválido {raw!r}: {exc}", file=sys.stderr)
            invalid = True
    if not targets:
        cli.error("No hay objetivos válidos")
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
        print("Interrumpido", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry()
