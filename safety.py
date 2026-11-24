"""The tool's own safeguards: validated URLs, authorized scope and an HTTP client that does
not follow redirects out of scope or let itself be steered into internal networks.

- ``normalize_url`` keeps scheme, host, port, path and query (drops the fragment).
- ``ScopePolicy`` decides which hosts may be visited and pins each host's IP the first time it
  is resolved, so DNS that changes between requests (DNS rebinding) has no effect.
- ``http_get`` only sends GET requests, follows redirects manually and limits size, time and
  number of hops. It sends no cookies or credentials.
- ``http_request`` (Phase 2, authenticated audits only) adds HEAD/POST with a capped form-encoded
  body, a per-audit in-memory ``CookieJar`` that never leaves the process and an optional
  ``RequestBudget``. Same scope, pinning, deadline and redirect rules; a redirected POST becomes
  a GET and a body is never re-sent to another origin.

Standard library only.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib import parse

from i18n import tr

DEFAULT_DEADLINE = 60  # seconds per request (redirects included) when no other deadline is given
MAX_REDIRECTS = 5
MAX_BODY = 1024 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; DomainInfo-webapp)"
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ScopeError(ValueError):
    """The destination is outside the authorized scope or on a blocked network."""


def _host(value):
    """Lowercase ASCII (IDNA) host; validates IPs and DNS labels."""
    value = value.strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(tr("Invalid host name")) from exc
    if not host or len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError(tr("Invalid host name"))
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError(tr("Invalid IPv4 address"))
    return host


normalize_host = _host
_ENCODED_DOT_OR_SLASH = re.compile(r"%2[ef]", re.I)


def remove_dot_segments(path):
    """RFC 3986 section 5.2.4: resolve "." and ".." segments of an absolute path."""
    output = []
    segments = path.split("/")[1:] if path.startswith("/") else path.split("/")
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == ".":
            if last:
                output.append("")
        elif segment == "..":
            if output:
                output.pop()
            if last:
                output.append("")
        else:
            output.append(segment)
    return "/" + "/".join(output)


def normalize_url(value):
    """Canonical HTTP/HTTPS URL that keeps the path and the query.

    Without a scheme, https is assumed. Rejects credentials, spaces, control characters,
    other schemes, ports outside 1–65535 and a percent-encoded dot or slash in the path
    (%2e, %2f); "." and ".." path segments are resolved, so a prefix check on the result
    cannot be escaped with dot-segments.
    """
    value = (value or "").strip()
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError(tr("Empty URL or URL with spaces/control characters"))
    if "://" not in value:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d)", value):
            raise ValueError(tr("Only HTTP/HTTPS URLs are accepted"))
        value = "https://" + value
    parts = parse.urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(tr("Only HTTP/HTTPS URLs are accepted"))
    if parts.username is not None or parts.password is not None:
        raise ValueError(tr("Credentials in the URL are not accepted"))
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(tr("Port out of range")) from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(tr("Port out of range"))
    if not parts.hostname:
        raise ValueError(tr("The URL has no host"))
    host = _host(parts.hostname)
    netloc = "[" + host + "]" if ":" in host else host
    if port and port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    if _ENCODED_DOT_OR_SLASH.search(parts.path):
        raise ValueError(tr("Percent-encoded dot or slash in the URL path is not accepted"))
    return parse.urlunsplit((scheme, netloc, remove_dot_segments(parts.path or "/"), parts.query, ""))


def classify_ip(address):
    """'blocked' (never visited), 'private' (not public) or 'public'."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        # Embedded IPv4: ::ffff:a.b.c.d, 6to4 (2002::/16) and NAT64 (64:ff9b::/96) reach the real IPv4
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "blocked"  # includes 169.254.169.254 (cloud metadata) and 0.0.0.0
    return "public" if ip.is_global else "private"


def resolve_host(host):
    """System addresses for a host (or the host itself if it is an IP)."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


@dataclass
class ScopePolicy:
    """Hosts authorized for an audit and the pinned IP of each one."""

    origin_url: str
    extra_hosts: list = field(default_factory=list)
    allow_private: bool = False
    resolver: Callable[[str], list] = resolve_host
    _pinned: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self.origin_host = _host(parse.urlsplit(self.origin_url).hostname or "")
        self.patterns = []
        for raw in self.extra_hosts or []:
            raw = raw.strip()
            if not raw:
                continue
            wildcard = raw.startswith("*.")
            self.patterns.append(("*." if wildcard else "") + _host(raw[2:] if wildcard else raw))

    def in_scope(self, host):
        host = _host(host)
        if host == self.origin_host:
            return True
        for pattern in self.patterns:
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
            if host == pattern:
                return True
        return False

    def _resolve(self, host):
        if host not in self._pinned:
            try:
                addresses = list(self.resolver(host))
            except OSError as exc:
                raise ScopeError(tr("Could not resolve {host}: {error}", host=host, error=exc)) from exc
            if not addresses:
                raise ScopeError(tr("{host} has no addresses", host=host))
            self._pinned[host] = addresses
        return self._pinned[host]

    def origin_is_private(self):
        """Only if ALL the origin's addresses are internal (a mixed origin does not open the internal network)."""
        return all(classify_ip(ip) == "private" for ip in self._resolve(self.origin_host))

    def connect_address(self, host):
        """Validated IP to connect to for ``host``; raises ScopeError if it is not allowed."""
        host = _host(host)
        if not self.in_scope(host):
            raise ScopeError(tr("{host} is outside the authorized scope", host=host))
        addresses = self._resolve(host)
        kinds = {ip: classify_ip(ip) for ip in addresses}
        if any(kind == "blocked" for kind in kinds.values()):
            raise ScopeError(tr("{host} resolves to a blocked address (link-local, multicast or reserved)", host=host))
        private_ok = self.allow_private or self.origin_is_private()
        if any(kind == "private" for kind in kinds.values()) and not private_ok:
            raise ScopeError(tr("{host} resolves to an internal network; use --allow-private if authorized", host=host))
        return addresses[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = self._raw_sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._sni = host
        self._tls = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        server_name = None if _is_ip(self._sni) else self._sni
        self._raw_sock = sock
        self.sock = self._raw_sock = self._tls.wrap_socket(sock, server_hostname=server_name)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class Response:
    url: str
    status: int
    headers: list
    body: bytes
    truncated: bool
    redirects: list
    address: str
    tls_verified: object = None
    method: str = "GET"

    def header(self, name, default=None):
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return default

    def header_all(self, name):
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise OSError(tr("Total audit time exhausted"))
    return left


def _read_body(response, limit, deadline):
    """Read in chunks while checking the total deadline: a server that sends byte by byte cannot
    hold the audit past the deadline (each read waits at most the per-connection timeout)."""
    chunks, size = [], 0
    while size <= limit:
        _remaining(deadline)
        chunk = response.read1(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        _remaining(deadline)
    return b"".join(chunks)


def _request_once(url, policy, timeout, limit, extra_headers, insecure_tls=False, deadline=None, method="GET",
                  body=None):
    deadline = time.monotonic() + DEFAULT_DEADLINE if deadline is None else deadline
    timeout = min(timeout, _remaining(deadline))
    parts = parse.urlsplit(url)
    host = parts.hostname
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    address = policy.connect_address(host)
    target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
               "Accept-Encoding": "identity", "Connection": "close"}
    headers.update(extra_headers or {})
    verified = None
    attempts = ((True, False) if insecure_tls else (True,)) if https else (None,)
    for verify in attempts:
        if https:
            context = ssl.create_default_context()
            if verify is False:
                # Only with --insecure-tls, set by the user: passive read of a site with an invalid
                # certificate (e.g. an internal self-signed one). No secret is sent and the result
                # is marked with tls_verified = False.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # nosec B501
            connection = _PinnedHTTPS(host, port, address, timeout, context)
        else:
            connection = _PinnedHTTP(host, port, address, timeout)
        # Watchdog: when the total deadline passes it cuts the socket, also during TLS and the headers,
        # which http.client reads without giving a chance to check the deadline.
        watchdog = threading.Timer(_remaining(deadline), _abort, (connection,))
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            body = _read_body(response, limit, deadline)
            verified = verify
            return response.status, list(response.getheaders()), body, address, verified
        except ssl.SSLCertVerificationError as exc:  # before OSError, of which it is a subclass
            if verify is True and len(attempts) > 1:
                continue
            raise OSError(tr("Invalid TLS certificate ({reason}); use --insecure-tls only if the site is "
                             "authorized and you trust the network", reason=exc.verify_message)) from exc
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= deadline:
                raise OSError(tr("Total audit time exhausted")) from exc
            raise
        finally:
            watchdog.cancel()
            connection.close()
    raise OSError(tr("Could not connect"))  # pragma: no cover


def _abort(connection):
    """Unblock any pending read on the connection (called from the timer)."""
    # _raw_sock stays valid even after http.client released connection.sock following getresponse()
    sock = getattr(connection, "_raw_sock", None) or getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _check_allowed(url, allow):
    """Raise ScopeError when the caller's ``allow(url)`` callback refuses ``url``."""
    if allow is not None and not allow(url):
        raise ScopeError(tr("The URL is outside the authorized URL prefixes"))


def http_get(url, policy, timeout, limit=MAX_BODY, headers=None, max_redirects=MAX_REDIRECTS,
             insecure_tls=False, deadline=None, allow=None):
    """GET with manual redirects inside the scope. Never raises for blocked redirects: it stops
    and marks them with ``blocked`` in the chain. It does raise ScopeError if the initial URL is
    not allowed. ``deadline`` (time.monotonic) limits the total time; OSError when it runs out.
    ``allow(url) -> bool`` (optional) is checked on every hop before connecting."""
    current = normalize_url(url)
    _check_allowed(current, allow)
    deadline = time.monotonic() + DEFAULT_DEADLINE if deadline is None else deadline
    chain = []
    seen = set()
    while True:
        status, raw_headers, body, address, verified = _request_once(current, policy, timeout, limit, headers,
                                                                     insecure_tls, deadline)
        location = next((v for k, v in raw_headers if k.lower() == "location"), None)
        if status in (301, 302, 303, 307, 308) and location:
            entry = {"status": status, "from": current}
            try:
                nxt = normalize_url(parse.urljoin(current, location))
                entry["location"] = nxt
                if len(chain) >= max_redirects or nxt in seen or nxt == current:
                    raise ScopeError(tr("Too many redirects or a redirect loop"))
                if parse.urlsplit(current).scheme == "https" and parse.urlsplit(nxt).scheme == "http":
                    entry["downgrade"] = True
                _check_allowed(nxt, allow)
                policy.connect_address(parse.urlsplit(nxt).hostname)
            except (ScopeError, ValueError) as exc:
                entry.setdefault("location", location[:300])
                entry["blocked"] = str(exc)
                chain.append(entry)
            else:
                chain.append(entry)
                seen.add(current)
                current = nxt
                continue
        return Response(url=current, status=status, headers=raw_headers, body=body[:limit],
                        truncated=len(body) > limit, redirects=chain, address=address, tls_verified=verified)


# -- Phase 2: method-generic client with an in-memory cookie jar ------------------------------------

METHODS = ("GET", "HEAD", "POST")
MAX_REQUEST_BODY = 64 * 1024
MAX_COOKIES = 64
MAX_COOKIE_SIZE = 4096


class BudgetExceeded(RuntimeError):
    """The per-run request limit of an authorized audit has been reached."""


@dataclass
class RequestBudget:
    """Counts every HTTP request (redirect hops included) against a hard limit."""

    limit: int
    used: int = 0

    def spend(self):
        if self.used >= self.limit:
            raise BudgetExceeded(tr("Request limit reached ({limit})", limit=self.limit))
        self.used += 1

    @property
    def remaining(self):
        return max(0, self.limit - self.used)


@dataclass
class _Cookie:
    name: str
    value: str = field(repr=False)
    domain: str = ""
    host_only: bool = True
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: object = None
    expires: object = None  # time.time() value or None (session cookie)
    max_age: object = None  # seconds requested by the server (for reporting), or None


def _default_path(url):
    path = parse.urlsplit(url).path or "/"
    return "/" if not path.startswith("/") or path.count("/") <= 1 else path[:path.rfind("/")]


def _path_match(request_path, cookie_path):
    if request_path == cookie_path:
        return True
    return request_path.startswith(cookie_path) and (cookie_path.endswith("/") or request_path[len(cookie_path)] == "/")


class CookieJar:
    """Per-audit cookie store that lives only in memory.

    Values never leave the process: ``repr``, ``attributes`` and ``names`` expose names and flags
    only; ``digest`` gives a hash for internal comparisons (e.g. "did the session id change?").
    Secure cookies are only sent over HTTPS and only to hosts that domain-match.
    """

    def __init__(self):
        self._cookies = {}

    def __repr__(self):
        return f"CookieJar(names={sorted(self.names())})"

    def __len__(self):
        self._expire()
        return len(self._cookies)

    def copy(self):
        other = CookieJar()
        other._cookies = {key: _Cookie(**vars(c)) for key, c in self._cookies.items()}
        return other

    def clear(self):
        self._cookies.clear()

    def _expire(self):
        now = time.time()
        for key in [k for k, c in self._cookies.items() if c.expires is not None and c.expires <= now]:
            del self._cookies[key]

    def store(self, url, set_cookie_headers):
        """Store the ``Set-Cookie`` headers of a response received from ``url``."""
        parts = parse.urlsplit(url)
        host = _host(parts.hostname or "")
        https = parts.scheme == "https"
        for raw in set_cookie_headers or []:
            if len(raw) > MAX_COOKIE_SIZE:
                continue
            pieces = [p.strip() for p in raw.split(";")]
            name, sep, value = pieces[0].partition("=")
            name, value = name.strip(), value.strip()
            if not sep or not name:
                continue
            attrs = {}
            for piece in pieces[1:]:
                key, _, val = piece.partition("=")
                attrs[key.strip().lower()] = val.strip()
            if "secure" in attrs and not https:
                continue  # a non-secure origin cannot set a Secure cookie
            domain, host_only = host, True
            if attrs.get("domain"):
                try:
                    wanted = _host(attrs["domain"].lstrip("."))
                except ValueError:
                    continue
                if wanted != host and (_is_ip(host) or not host.endswith("." + wanted)):
                    continue  # the server may not set cookies for another domain
                domain, host_only = wanted, wanted == host
            path = attrs["path"] if attrs.get("path", "").startswith("/") else _default_path(url)
            expires, max_age = None, None
            if "max-age" in attrs:
                try:
                    max_age = max(-1, min(int(attrs["max-age"]), 10 * 365 * 86400))
                    expires = time.time() + max_age
                except ValueError:
                    max_age = None
            elif attrs.get("expires"):
                try:
                    expires = parsedate_to_datetime(attrs["expires"]).timestamp()
                except (TypeError, ValueError, IndexError, OverflowError):
                    expires = None
            samesite = attrs.get("samesite")
            key = (domain, path, name)
            if expires is not None and expires <= time.time():
                self._cookies.pop(key, None)  # deletion requested by the server
                continue
            if key not in self._cookies and len(self._cookies) >= MAX_COOKIES:
                continue
            self._cookies[key] = _Cookie(name, value, domain, host_only, path, "secure" in attrs,
                                         "httponly" in attrs, samesite.capitalize() if samesite else None,
                                         expires, max_age)

    def _matching(self, url):
        self._expire()
        parts = parse.urlsplit(url)
        host = _host(parts.hostname or "")
        path = parts.path or "/"
        for cookie in self._cookies.values():
            if cookie.host_only and host != cookie.domain:
                continue
            if not cookie.host_only and host != cookie.domain and not host.endswith("." + cookie.domain):
                continue
            if cookie.secure and parts.scheme != "https":
                continue
            if _path_match(path, cookie.path):
                yield cookie

    def header_for(self, url):
        """``Cookie`` header value for a request to ``url`` (None when nothing matches)."""
        cookies = sorted(self._matching(url), key=lambda c: -len(c.path))
        return "; ".join(f"{c.name}={c.value}" for c in cookies) or None

    def names(self):
        self._expire()
        return {c.name for c in self._cookies.values()}

    def _find(self, name):
        self._expire()
        return next((c for c in self._cookies.values() if c.name == name), None)

    def attributes(self, name):
        """Flags of a cookie without its value (None when absent)."""
        cookie = self._find(name)
        if cookie is None:
            return None
        return {"name": cookie.name, "domain": cookie.domain, "host_only": cookie.host_only, "path": cookie.path,
                "secure": cookie.secure, "httponly": cookie.httponly, "samesite": cookie.samesite,
                "persistent": cookie.expires is not None, "max_age": cookie.max_age,
                "lifetime": None if cookie.expires is None else max(0, round(cookie.expires - time.time()))}

    def digest(self, name):
        """SHA-256 of a cookie's value for internal comparisons (never for output)."""
        cookie = self._find(name)
        return None if cookie is None else hashlib.sha256(cookie.value.encode("utf-8", "replace")).hexdigest()

    def secret_values(self):
        """Raw values, only so that callers can scrub them from anything they output."""
        self._expire()
        return [c.value for c in self._cookies.values() if c.value]


def _origin(url):
    parts = parse.urlsplit(url)
    return parts.scheme, parts.netloc


def encode_form(data):
    """``application/x-www-form-urlencoded`` body from a mapping or a list of pairs, size-capped."""
    pairs = list(data.items()) if isinstance(data, dict) else list(data)
    body = parse.urlencode([(str(k), str(v)) for k, v in pairs]).encode("ascii")
    if len(body) > MAX_REQUEST_BODY:
        raise ValueError(tr("Request body too large (limit {limit} bytes)", limit=MAX_REQUEST_BODY))
    return body


def http_request(method, url, policy, timeout, data=None, jar=None, limit=MAX_BODY, headers=None,
                 max_redirects=MAX_REDIRECTS, insecure_tls=False, deadline=None, budget=None, allow=None):
    """GET, HEAD or POST (form-encoded ``data``) with the rules of ``http_get``.

    ``jar`` (``CookieJar``) receives the cookies of every hop and supplies the matching ones; it
    is never written anywhere. ``budget`` (``RequestBudget``) is charged once per hop. A
    301/302/303 after a POST continues as a GET without body; a 307/308 keeps the POST only
    inside the same origin (scheme, host and port) and is blocked otherwise. Caller-supplied
    ``Cookie``, ``Host`` and ``Content-Length`` headers are ignored. ``allow(url) -> bool``
    (optional) is checked on every hop, the first one included, before connecting: a refused
    redirect is marked ``blocked`` and not followed. With a ``jar``, an HTTPS to HTTP redirect
    is refused (not only flagged) so that session cookies never travel in clear text.
    """
    method = (method or "").upper()
    if method not in METHODS:
        raise ValueError(tr("Unsupported HTTP method: {method}", method=method[:10]))
    if data is not None and method != "POST":
        raise ValueError(tr("Only POST requests carry a body"))
    body = encode_form(data or {}) if method == "POST" else None
    current = normalize_url(url)
    _check_allowed(current, allow)
    deadline = time.monotonic() + DEFAULT_DEADLINE if deadline is None else deadline
    base_headers = {k: v for k, v in (headers or {}).items()
                    if k.lower() not in ("cookie", "host", "content-length", "content-type")}
    chain, seen = [], set()
    while True:
        if budget is not None:
            budget.spend()
        hop_headers = dict(base_headers)
        if jar is not None:
            cookie = jar.header_for(current)
            if cookie:
                hop_headers["Cookie"] = cookie
        if body is not None:
            hop_headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, raw_headers, rbody, address, verified = _request_once(
            current, policy, timeout, limit, hop_headers, insecure_tls, deadline, method=method, body=body)
        if jar is not None:
            jar.store(current, [v for k, v in raw_headers if k.lower() == "set-cookie"])
        location = next((v for k, v in raw_headers if k.lower() == "location"), None)
        if status in (301, 302, 303, 307, 308) and location:
            entry = {"status": status, "from": current, "method": method}
            try:
                nxt = normalize_url(parse.urljoin(current, location))
                entry["location"] = nxt
                if len(chain) >= max_redirects or (nxt, method) in seen or (nxt == current and method != "POST"):
                    raise ScopeError(tr("Too many redirects or a redirect loop"))
                if parse.urlsplit(current).scheme == "https" and parse.urlsplit(nxt).scheme == "http":
                    entry["downgrade"] = True
                    if jar is not None:
                        raise ScopeError(tr("Redirect from HTTPS to HTTP refused while session cookies are in use"))
                _check_allowed(nxt, allow)
                if method == "POST" and status in (307, 308) and _origin(nxt) != _origin(current):
                    raise ScopeError(tr("A POST body is never re-sent to another origin"))
                policy.connect_address(parse.urlsplit(nxt).hostname)
            except (ScopeError, ValueError) as exc:
                entry.setdefault("location", location[:300])
                entry["blocked"] = str(exc)
                chain.append(entry)
            else:
                chain.append(entry)
                seen.add((current, method))
                current = nxt
                if (method == "POST" and status in (301, 302, 303)) or (status == 303 and method != "HEAD"):
                    method, body = "GET", None
                continue
        return Response(url=current, status=status, headers=raw_headers, body=rbody[:limit],
                        truncated=len(rbody) > limit, redirects=chain, address=address, tls_verified=verified,
                        method=method)
