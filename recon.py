"""Subdomains from public certificate logs (Certificate Transparency) and, optionally,
from a word list; detection of abandoned subdomains that could be taken over
(subdomain takeover) from the CNAME and the HTTP response.

Takeover ``risk`` values: ``high`` (dangling CNAME to a known service), ``review`` (dangling
CNAME to an unknown service) and ``possible`` (the service says the resource does not exist).
"""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import sys
from urllib import error, parse, request

import dnsclient
from i18n import tr

# service, CNAME suffixes, text shown when the resource does not exist
TAKEOVER = (
    ("GitHub Pages", ("github.io",), "There isn't a GitHub Pages site here"),
    ("Heroku", ("herokuapp.com", "herokudns.com"), "No such app"),
    ("Amazon S3", ("s3.amazonaws.com", "s3-website"), "NoSuchBucket"),
    ("Azure", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
               "blob.core.windows.net", "azureedge.net"), None),
    ("Shopify", ("myshopify.com",), "Sorry, this shop is currently unavailable"),
    ("Fastly", ("fastly.net",), "Fastly error: unknown domain"),
    ("Netlify", ("netlify.app", "netlify.com"), "Not Found - Request ID"),
    ("Vercel", ("vercel.app", "vercel-dns.com"), "The deployment could not be found"),
    ("Zendesk", ("zendesk.com",), "Help Center Closed"),
    ("Ghost", ("ghost.io",), "Site unavailable"),
    ("Surge.sh", ("surge.sh",), "project not found"),
    ("Bitbucket", ("bitbucket.io",), "Repository not found"),
    ("WordPress.com", ("wordpress.com",), "Do you want to register"),
    ("Pantheon", ("pantheonsite.io",), "The gods are wise"),
    ("Tumblr", ("domains.tumblr.com",), "Whatever you were looking for doesn't currently exist"),
    ("Unbounce", ("unbouncepages.com",), "The requested URL was not found on this server"),
    ("Readme.io", ("readme.io",), "Project doesnt exist"),
    ("Cargo", ("cargocollective.com",), "404 Not Found"),
    ("Strikingly", ("s.strikinglydns.com",), "page not found"),
    ("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"), "The page you are looking for doesn't exist"),
)
MAX_RESOLVE = 300


def _json(url, timeout, limit=12 * 1024 * 1024):
    req = request.Request(url, headers={"User-Agent": "DomainInfo", "Accept": "application/json"})
    with request.urlopen(req, timeout=timeout) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError(tr("Response too large"))
        return json.loads(body)


def clean(names, domain):
    out = set()
    for raw in names:
        for name in str(raw).lower().split("\n"):
            name = name.strip().lstrip("*.").rstrip(".")
            if name and (name == domain or name.endswith("." + domain)) and " " not in name and "@" not in name:
                out.add(name)
    out.discard(domain)
    return sorted(out)


def from_ct(domain, timeout):
    """crt.sh and, if it fails, Cert Spotter. Returns (names, source)."""
    try:
        rows = _json(f"https://crt.sh/?q={parse.quote('%.' + domain)}&output=json", max(timeout, 25))
        return clean((row.get("name_value", "") for row in rows), domain), "crt.sh"
    except (OSError, ValueError, error.URLError):
        pass
    rows = _json("https://api.certspotter.com/v1/issuances?domain=" + parse.quote(domain)
                 + "&include_subdomains=true&expand=dns_names", max(timeout, 20))
    return clean((name for row in rows for name in row.get("dns_names", [])), domain), "certspotter"


def from_wordlist(domain, threads, timeout):
    # Next to the code in a clone; under <prefix>/share/domaininfo when installed with pip/pipx
    candidates = (Path(__file__).resolve().parent / "wordlists" / "subdomains.txt",
                  Path(sys.prefix) / "share" / "domaininfo" / "wordlists" / "subdomains.txt")
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        return []
    words = [w.strip().lower() for w in path.read_text(encoding="utf-8", errors="replace").splitlines()
             if w.strip() and not w.startswith("#")][:2000]

    def exists(word):
        name = f"{word}.{domain}"
        try:
            socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
            return name
        except OSError:
            return None
    with ThreadPoolExecutor(max_workers=threads) as pool:
        return sorted(name for name in pool.map(exists, words) if name)


def takeover_service(cname):
    cname = cname.lower().rstrip(".")
    for service, suffixes, marker in TAKEOVER:
        if any(("." + s) in ("." + cname) for s in suffixes):
            return service, marker
    return None, None


def inspect(name, timeout, http_get):
    """Addresses, CNAME and takeover risk of a subdomain."""
    row = {"name": name, "addresses": [], "cname": None}
    try:
        row["addresses"] = sorted({entry[4][0] for entry in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)})
    except OSError:
        pass
    try:
        cnames = dnsclient.values(name, "CNAME", timeout)
        row["cname"] = cnames[0] if cnames else None
    except dnsclient.DNSError:
        pass
    if not row["cname"]:
        return row
    service, marker = takeover_service(row["cname"])
    try:
        target_rcode = dnsclient.query(row["cname"], "A", timeout)["rcode"]
    except dnsclient.DNSError:
        target_rcode = None
    if target_rcode == "NXDOMAIN":
        row["takeover"] = {"risk": "high" if service else "review", "service": service,
                           "reason": tr("The CNAME points to {cname}, which no longer exists", cname=row["cname"])}
    elif service and marker:
        for scheme in ("https", "http"):
            try:
                body = http_get(f"{scheme}://{name}/", timeout)
            except (OSError, ValueError):
                continue
            if marker.lower() in body.lower():
                row["takeover"] = {"risk": "possible", "service": service,
                                   "reason": tr("{service} says the resource does not exist ('{marker}')",
                                                service=service, marker=marker)}
            break
    return row


def _http_text(url, timeout):
    req = request.Request(url, headers={"User-Agent": "DomainInfo"})
    try:
        response = request.urlopen(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    with response:
        return response.read(256 * 1024).decode("utf-8", "replace")


def audit(domain, threads, timeout, brute=False):
    sources, names, note = [], set(), None
    try:
        found, source = from_ct(domain, timeout)
        names.update(found)
        sources.append(source)
    except (OSError, ValueError) as exc:
        note = tr("Certificate logs unavailable: {error}", error=exc)
    if brute:
        names.update(from_wordlist(domain, threads, timeout))
        sources.append("wordlist")
    ordered = sorted(names)
    checked = ordered[:MAX_RESOLVE]
    with ThreadPoolExecutor(max_workers=threads) as pool:
        rows = list(pool.map(lambda n: inspect(n, timeout, _http_text), checked))
    alive = [r for r in rows if r["addresses"] or r["cname"]]
    result = {"total": len(ordered), "checked": len(checked), "sources": sources,
              "alive": alive, "takeover": [r for r in rows if r.get("takeover")],
              "unresolved": [r["name"] for r in rows if not r["addresses"] and not r["cname"]][:100]}
    if len(ordered) > MAX_RESOLVE:
        result["note"] = tr("Checked the first {checked} of {total} subdomains", checked=MAX_RESOLVE, total=len(ordered))
    if note:
        result["warning"] = note
    return result
