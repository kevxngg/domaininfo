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

VERSION = "4.1.0"
MODULES = ("dns", "rdap", "http", "tls", "ports", "traceroute", "mikrotik")
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
            return {"verified": True, "protocol": conn.version(),
                    "cipher": conn.cipher(), "certificate": cert,
                    "days_remaining": int((expiry - time.time()) // 86400)}


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


def scan(target, args):
    report = {"meta": {"tool": "DomainInfo", "version": VERSION, "target": target,
                       "date": datetime.now(timezone.utc).isoformat(), "mode": args.mode,
                       "platform": platform.system()}, "modules": {}}
    for name in MODES[args.mode]:
        if name in args.skip:
            report["modules"][name] = {"status": "skipped"}
            continue
        try:
            data = RUNNERS[name](target, args)
            report["modules"][name] = {"status": "ok", "data": data}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            report["modules"][name] = {"status": "error", "error": str(exc)}
        if not args.quiet:
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


def parser():
    cli = argparse.ArgumentParser(description="DomainInfo: diagnóstico portable de dominios e IPs")
    cli.add_argument("target", nargs="?", help="Dominio, IPv4, IPv6 o URL HTTP/HTTPS")
    cli.add_argument("--version", action="version", version=VERSION)
    cli.add_argument("--doctor", action="store_true", help="Diagnóstico local, sin escaneos")
    cli.add_argument("-m", "--mode", choices=MODES, default="quick")
    cli.add_argument("-f", "--file", type=Path, help="Objetivos UTF-8, uno por línea")
    cli.add_argument("-t", "--threads", type=bounded_int(1, 64), default=15)
    cli.add_argument("--timeout", type=timeout_value, default=5.0)
    cli.add_argument("--ports", type=port_list, help="Puertos TCP; por defecto según el modo")
    cli.add_argument("--routeros-version", help="Versión RouterOS declarada, por ejemplo 7.25")
    cli.add_argument("--ssh-port", type=bounded_int(1, 65535), default=22,
                     help="MikroTik: puerto SSH para leer el banner (sin autenticación)")
    cli.add_argument("--offline", action="store_true", help="MikroTik: evaluar versión sin conectar a la red")
    cli.add_argument("-s", "--skip", choices=MODULES, action="append", default=[])
    cli.add_argument("--scheme", choices=("http", "https"), default="https")
    cli.add_argument("--web-port", type=bounded_int(1, 65535))
    cli.add_argument("-o", "--output", type=Path, default=Path("logs"))
    cli.add_argument("--format", choices=("json", "txt", "html", "all"), default="all")
    cli.add_argument("-j", action="store_true", help="Compatibilidad: JSON ya incluido por defecto")
    cli.add_argument("-q", "--quiet", action="store_true", help="Solo JSON en stdout")
    cli.add_argument("-v", "--verbose", action="store_true", help="Incluye rutas de reportes en stderr")
    return cli


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cli = parser()
    args = cli.parse_args(argv)
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
    elif sys.stdin.isatty():
        print("DomainInfo " + VERSION + " | 1 Rápido  2 Web  3 Puertos  4 Completo  5 MikroTik  0 Salir")
        choice = input("Opción [1]: ").strip() or "1"
        if choice == "0":
            return 0
        if choice not in ("1", "2", "3", "4", "5"):
            cli.error("Opción inválida")
        args.mode = {"1": "quick", "2": "web", "3": "ports", "4": "full", "5": "mikrotik"}[choice]
        raw_targets = [input("Dominio o IP: ")]
        if args.mode == "mikrotik" and not args.routeros_version:
            declared = input("Versión RouterOS (ENTER para intentar detectarla): ").strip()
            if declared:
                import routeros
                try:
                    args.routeros_version = routeros.parse_version(declared).text
                except ValueError as exc:
                    cli.error(str(exc))
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
    failed = invalid
    for target in targets:
        report = scan(target, args)
        formats = ("json", "txt", "html") if args.format == "all" else (args.format,)
        try:
            paths = save_report(report, args.output, formats)
        except OSError as exc:
            print(f"No se pudo guardar reporte: {exc}", file=sys.stderr)
            failed = True
            paths = []
        if args.verbose:
            print("Reportes: " + ", ".join(paths), file=sys.stderr)
        print(json.dumps(report, ensure_ascii=False))
        failed |= any(module["status"] == "error" for module in report["modules"].values())
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("Interrumpido", file=sys.stderr)
        sys.exit(130)
