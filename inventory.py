"""Attack-surface inventory for DomainInfo 6.0 (Phase 3).

Public API::

    inventory.build(reports, scope=None) -> dict

``reports`` is one DomainInfo report dict or a list of them (``{"meta": {"target"}, "modules": {name:
{"status", "data"}}}``). Runner results from ``runners.run()`` are read from ``report["runners"]`` (list or
dict) and from any module whose data looks like a runner result (has ``tool`` and ``assets``).

Every asset lists the ``sources`` that saw it (module or tool names), so the same IP seen by ``dns``,
``asn`` and ``nmap`` is one entry with three sources. An open port is an asset, never a vulnerability:
findings only come from modules and tools that emit findings. Discovered paths are kept only when their
host belongs to the audited targets, their subdomains or the explicit ``scope``.
"""

import ipaddress
import re
from urllib import parse

from i18n import tr

KINDS = ("domains", "subdomains", "ipv4", "ipv6", "asns", "dns_servers", "certificates", "ports", "services",
         "technologies", "paths", "apis", "components", "findings")
_VERSIONED = re.compile(r"([A-Za-z][\w.+-]{0,60})/(\d[\w.+-]{0,40})")
_GENERATOR = re.compile(r"^\s*([A-Za-z][\w .+-]{0,60}?)\s+v?(\d[\w.+-]{0,40})\s*$")


def _host(value):
    value = str(value or "").strip().rstrip(".").lower()
    return value if value and len(value) <= 253 and re.fullmatch(r"[a-z0-9*_.-]+", value) else None


def _ip(value):
    try:
        return ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return None


class _Store:
    def __init__(self):
        self.items = {kind: {} for kind in KINDS}

    def add(self, kind, key, source, **fields):
        entry = self.items[kind].get(key)
        if entry is None:
            entry = self.items[kind][key] = {**fields, "sources": []}
        else:
            for name, value in fields.items():
                if entry.get(name) in (None, "", []) and value not in (None, "", []):
                    entry[name] = value
        if source and source not in entry["sources"]:
            entry["sources"].append(source)
        return entry


class _Builder:
    def __init__(self, roots, scope):
        self.store, self.roots, self.scope = _Store(), roots, scope
        self.dropped_paths = 0

    # -- classification ---------------------------------------------------------------------
    def name(self, value, source, **extra):
        host = _host(value)
        if not host or host.startswith("*"):
            return None
        if _ip(host):
            return self.ip(host, source)
        root = next((r for r in self.roots if host.endswith("." + r)), None)
        if root:
            self.store.add("subdomains", host, source, value=host, parent=root, **extra)
        else:
            self.store.add("domains", host, source, value=host, **extra)
        return host

    def ip(self, value, source, **extra):
        ip = _ip(value)
        if ip is None:
            return None
        kind = "ipv4" if ip.version == 4 else "ipv6"
        self.store.add(kind, str(ip), source, value=str(ip), **extra)
        return str(ip)

    def authorized(self, host):
        host = _host(host)
        if not host:
            return False
        if host in self.roots or any(host.endswith("." + r) for r in self.roots):
            return True
        for entry in self.scope:
            entry = str(entry).lower()
            if entry == host or (entry.startswith("*.") and host.endswith(entry[1:])):
                return True
        return False

    def path(self, url, source, kind="paths", **extra):
        if not isinstance(url, str) or not url:
            return
        parts = parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return
        if not self.authorized(parts.hostname) and not _ip(parts.hostname):
            self.dropped_paths += 1
            return
        clean = parse.urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", "", ""))
        self.store.add(kind, clean, source, url=clean, **extra)

    def port(self, host, address, port, protocol, source, service=None, product=None, version=None):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        address = self.ip(address, source) if address else None
        host = _host(host) or address
        key = f"{address or host}:{port}/{protocol}"
        self.store.add("ports", key, source, host=host, address=address, port=port, protocol=protocol, state="open")
        if service or product:
            self.store.add("services", key, source, host=host, address=address, port=port, protocol=protocol,
                           name=service, product=product, version=version)

    def technology(self, name, source, version=None, category=None):
        name = str(name or "").strip()[:80]
        if name:
            key = f"{name.lower()}|{version or ''}"
            self.store.add("technologies", key, source, name=name, version=version, category=category)

    def component(self, comp, source):
        if not isinstance(comp, dict) or not comp.get("name"):
            return
        name, version = str(comp["name"])[:100], str(comp.get("version") or "")[:50] or None
        entry = self.store.add("components", f"{name.lower()}|{version or ''}", source, name=name, version=version,
                               cpe=comp.get("cpe"), ecosystem=comp.get("ecosystem"), evidence=comp.get("evidence"),
                               locations=[])
        location = comp.get("location")
        if location and location not in entry["locations"]:
            entry["locations"].append(location)
        # direct evidence from any source wins over heuristic evidence
        if comp.get("evidence") == "direct":
            entry["evidence"] = "direct"

    def finding(self, finding, source):
        if isinstance(finding, dict) and finding.get("id"):
            entry = self.store.add("findings", finding["id"], source, **{k: v for k, v in finding.items()})
            entry.setdefault("tool", source)

    def certificate(self, cert, source):
        if not isinstance(cert, dict) or not (cert.get("serial") or cert.get("subject")):
            return
        key = f"{cert.get('issuer') or ''}|{cert.get('serial') or cert.get('subject')}"
        self.store.add("certificates", key, source, subject=cert.get("subject"), issuer=cert.get("issuer"),
                       serial=cert.get("serial"), san=list(cert.get("san") or []), not_before=cert.get("not_before"),
                       expires=cert.get("expires"), self_signed=cert.get("self_signed"),
                       verified=cert.get("verified"))
        for name in cert.get("san") or []:
            self.name(name, source)

    # -- modules ----------------------------------------------------------------------------
    def dns(self, data, target):
        for address in data.get("addresses", []):
            self.ip(address, "dns", host=target)
        records = data.get("records") or {}
        for value in records.get("NS", []):
            host = _host(value)
            if host:
                self.store.add("dns_servers", host, "dns", value=host)
        for value in records.get("CNAME", []):
            self.name(value, "dns")
        for value in records.get("MX", []):
            self.name(str(value).split()[-1] if str(value).split() else value, "dns", role="mail")

    def asn(self, data, target):
        for row in data.get("networks", []):
            if not isinstance(row, dict):
                continue
            self.ip(row.get("ip"), "asn", host=target)
            if row.get("asn"):
                self.store.add("asns", str(row["asn"]), "asn", asn=str(row["asn"]), name=row.get("as_name"),
                               prefix=row.get("prefix"), country=row.get("country"), registry=row.get("registry"))

    def tls(self, data, target):
        self.certificate(data, "tls")

    def ports(self, data, target):
        for row in data.get("results", []):
            if isinstance(row, dict) and row.get("state") == "open":
                self.port(target, row.get("address"), row.get("port"), data.get("protocol", "tcp"), "ports")

    def tech(self, data, target):
        for tech in data.get("technologies", []):
            if isinstance(tech, dict):
                self.technology(tech.get("name"), "tech", category=tech.get("category"))
        generator = data.get("generator")
        match = _GENERATOR.match(str(generator or ""))
        if match:
            self.technology(match.group(1), "tech", version=match.group(2))
            self.component({"name": match.group(1), "version": match.group(2), "evidence": "direct",
                            "location": data.get("url")}, "tech")
        for leak in (data.get("headers_grade") or {}).get("version_leaks", []):
            for name, version in _VERSIONED.findall(str(leak)):
                self.technology(name, "tech", version=version)
                self.component({"name": name, "version": version, "evidence": "direct",
                                "location": data.get("url")}, "tech")
        self.path(data.get("url"), "tech")

    def subdomains(self, data, target):
        for row in data.get("alive", []):
            if isinstance(row, dict):
                self.name(row.get("name"), "subdomains", resolved=True)
                for address in row.get("addresses", []):
                    self.ip(address, "subdomains", host=row.get("name"))
                if row.get("cname"):
                    self.name(row["cname"], "subdomains")
        for name in data.get("unresolved", []):
            self.name(name, "subdomains", resolved=False)

    def webapp(self, data, target):
        for key in ("url", "final_url"):
            self.path(data.get(key), "webapp")
        if data.get("address"):
            self.ip(data["address"], "webapp", host=target)
        base = data.get("final_url") or data.get("url") or ""
        for form in data.get("forms", []) if isinstance(data.get("forms"), list) else []:
            if isinstance(form, dict) and form.get("action"):
                self.path(parse.urljoin(base, str(form["action"])), "webapp")
        for key in ("paths", "discovered_paths", "endpoints"):
            for item in data.get(key, []) if isinstance(data.get(key), list) else []:
                url = item.get("url") if isinstance(item, dict) else item
                self.path(parse.urljoin(base, str(url or "")), "webapp")
        self.apis(data, "webapp", base)
        for finding in data.get("findings", []):
            self.finding(finding, "webapp")

    def apis(self, data, source, base=""):
        for key in ("apis", "openapi"):
            value = data.get(key)
            for item in value if isinstance(value, list) else ([value] if isinstance(value, dict) else []):
                if isinstance(item, dict):
                    url = item.get("url") or item.get("spec_url") or item.get("source")
                    if url:
                        self.path(parse.urljoin(base, str(url)), source, kind="apis", title=item.get("title"),
                                  version=item.get("version"))

    def history(self, data, target):
        if target in self.store.items["domains"]:
            entry = self.store.items["domains"][target]
            for key in ("registrar", "registered", "expires"):
                entry.setdefault(key, data.get(key))

    def runner(self, result, target):
        tool = str(result.get("tool") or "runner")
        for asset in result.get("assets", []):
            if not isinstance(asset, dict):
                continue
            kind = asset.get("type")
            if kind in ("domain", "subdomain", "cname"):
                self.name(asset.get("value"), tool)
            elif kind == "ip":
                self.ip(asset.get("value"), tool, host=asset.get("host"))
            elif kind == "port":
                self.port(asset.get("host") or target, asset.get("address"), asset.get("port"),
                          asset.get("protocol", "tcp"), tool, asset.get("service"), asset.get("product"),
                          asset.get("version"))
            elif kind == "technology":
                self.technology(asset.get("name"), tool, version=asset.get("version"))
            elif kind == "url":
                self.path(asset.get("value"), tool)
            elif kind == "certificate":
                self.certificate(asset, tool)
        for comp in result.get("components", []):
            self.component(comp, tool)
        for finding in result.get("findings", []):
            self.finding(finding, tool)


_MODULES = ("dns", "asn", "tls", "ports", "tech", "subdomains", "webapp", "history")


def _runner_results(report):
    runners = report.get("runners")
    items = list(runners.values()) if isinstance(runners, dict) else list(runners or [])
    for name, module in (report.get("modules") or {}).items():
        data = module.get("data") if isinstance(module, dict) else None
        if name not in _MODULES and isinstance(data, dict) and "tool" in data and "assets" in data:
            items.append(data)
    return [item for item in items if isinstance(item, dict)]


def build(reports, scope=None):
    """Deduplicated inventory of every asset seen in one or many reports (see module docstring)."""
    if isinstance(reports, dict):
        reports = [reports]
    reports = [r for r in reports or [] if isinstance(r, dict)]
    targets = [str((r.get("meta") or {}).get("target") or "").lower() for r in reports]
    roots = sorted({h for h in map(_host, targets) if h and not _ip(h) and "." in h}, key=len, reverse=True)
    builder = _Builder(roots, [s for s in scope or [] if isinstance(s, str)])
    for report, target in zip(reports, targets, strict=True):
        if _ip(target):
            builder.ip(target, "target")
        elif _host(target):
            builder.store.add("domains", _host(target), "target", value=_host(target))
        modules = report.get("modules") or {}
        for name in _MODULES:
            module = modules.get(name)
            if isinstance(module, dict) and module.get("status") == "ok" and isinstance(module.get("data"), dict):
                getattr(builder, name)(module["data"], target)
        for name, module in modules.items():
            data = module.get("data") if isinstance(module, dict) else None
            if name not in _MODULES and isinstance(data, dict) and name in ("openapi", "api", "apis"):
                builder.apis(data, name)
        for result in _runner_results(report):
            builder.runner(result, target)
    inventory: dict = {kind: sorted(builder.store.items[kind].values(), key=_sort_key) for kind in KINDS}
    for entry in inventory["findings"]:
        entry["sources"] = sorted(entry["sources"])
    inventory["summary"] = {kind: len(inventory[kind]) for kind in KINDS}
    inventory["summary"]["targets"] = len(reports)
    inventory["summary"]["out_of_scope_paths"] = builder.dropped_paths
    inventory["note"] = tr("Open ports and services are assets, not vulnerabilities. Paths outside the "
                           "authorized scope are not listed.")
    return inventory


def _sort_key(entry):
    for key in ("value", "url", "asn", "name", "id"):
        if entry.get(key) is not None:
            return (0, str(entry.get("address") or entry.get("host") or ""), str(entry[key]), str(entry.get("version")))
    return (1, str(entry.get("address") or entry.get("host") or ""), str(entry.get("port", "")).zfill(5), "")
