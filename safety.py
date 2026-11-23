"""Protecciones de la propia herramienta: URL validadas, alcance autorizado y un cliente HTTP
que no sigue redirecciones fuera de alcance ni se deja llevar a redes internas.

- ``normalize_url`` conserva protocolo, host, puerto, ruta y consulta (descarta el fragmento).
- ``ScopePolicy`` decide qué hosts se pueden visitar y fija la IP de cada uno la primera vez que
  se resuelve, de modo que un DNS que cambie entre peticiones (DNS rebinding) no tenga efecto.
- ``http_get`` hace solo peticiones GET, sigue redirecciones de forma manual y limita tamaño,
  tiempo y número de saltos. No envía cookies ni credenciales.

Solo biblioteca estándar.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
import http.client
import ipaddress
import re
import socket
import ssl
import time
from urllib import parse

DEFAULT_DEADLINE = 60  # segundos por petición (con redirecciones) si no se indica otro plazo
MAX_REDIRECTS = 5
MAX_BODY = 1024 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; DomainInfo-webapp)"
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ScopeError(ValueError):
    """El destino queda fuera del alcance autorizado o en una red bloqueada."""


def _host(value):
    """Host en minúsculas y en ASCII (IDNA); valida IP y etiquetas DNS."""
    value = value.strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nombre de host inválido") from exc
    if not host or len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("Nombre de host inválido")
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError("Dirección IPv4 inválida")
    return host


normalize_host = _host


def normalize_url(value):
    """URL HTTP/HTTPS canónica que conserva la ruta y la consulta.

    Sin esquema se asume https. Rechaza credenciales, espacios, caracteres de control,
    otros esquemas y puertos fuera de 1–65535.
    """
    value = (value or "").strip()
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("URL vacía o con espacios/caracteres de control")
    if "://" not in value:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d)", value):
            raise ValueError("Solo se aceptan URLs HTTP/HTTPS")
        value = "https://" + value
    parts = parse.urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Solo se aceptan URLs HTTP/HTTPS")
    if parts.username is not None or parts.password is not None:
        raise ValueError("No se aceptan credenciales en la URL")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Puerto fuera de rango") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Puerto fuera de rango")
    if not parts.hostname:
        raise ValueError("Falta el host de la URL")
    host = _host(parts.hostname)
    netloc = "[" + host + "]" if ":" in host else host
    if port and port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return parse.urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def classify_ip(address):
    """'blocked' (nunca se visita), 'private' (no pública) o 'public'."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv4 incrustado: ::ffff:a.b.c.d, 6to4 (2002::/16) y NAT64 (64:ff9b::/96) llegan a la IPv4 real
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "blocked"  # incluye 169.254.169.254 (metadatos de nube) y 0.0.0.0
    return "public" if ip.is_global else "private"


def resolve_host(host):
    """Direcciones del sistema para un host (o el propio host si es una IP)."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


@dataclass
class ScopePolicy:
    """Hosts autorizados para una auditoría y la IP fijada de cada uno."""

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
                raise ScopeError(f"No se pudo resolver {host}: {exc}") from exc
            if not addresses:
                raise ScopeError(f"{host} no tiene direcciones")
            self._pinned[host] = addresses
        return self._pinned[host]

    def origin_is_private(self):
        """Solo si TODAS las direcciones del origen son internas (un origen mixto no abre la red interna)."""
        return all(classify_ip(ip) == "private" for ip in self._resolve(self.origin_host))

    def connect_address(self, host):
        """IP validada a la que conectar para ``host``; lanza ScopeError si no se permite."""
        host = _host(host)
        if not self.in_scope(host):
            raise ScopeError(f"{host} está fuera del alcance autorizado")
        addresses = self._resolve(host)
        kinds = {ip: classify_ip(ip) for ip in addresses}
        if any(kind == "blocked" for kind in kinds.values()):
            raise ScopeError(f"{host} resuelve a una dirección bloqueada (enlace local, multicast o reservada)")
        private_ok = self.allow_private or self.origin_is_private()
        if any(kind == "private" for kind in kinds.values()) and not private_ok:
            raise ScopeError(f"{host} resuelve a una red interna; usa --allow-private si está autorizado")
        return addresses[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._sni = host
        self._tls = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        server_name = None if _is_ip(self._sni) else self._sni
        self.sock = self._tls.wrap_socket(sock, server_hostname=server_name)


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
        raise OSError("Tiempo total de la auditoría agotado")
    return left


def _read_body(response, limit, deadline):
    """Lee por trozos comprobando el plazo total: un servidor que envía byte a byte no la retiene
    más allá del plazo (cada lectura espera como mucho el timeout por conexión)."""
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


def _request_once(url, policy, timeout, limit, extra_headers, insecure_tls=False, deadline=None):
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
                # Solo con --insecure-tls, puesto por el usuario: lectura pasiva de un sitio con
                # certificado inválido (p. ej. autofirmado interno). No se envía ningún secreto y el
                # resultado queda marcado con tls_verified = False.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # nosec B501
            connection = _PinnedHTTPS(host, port, address, timeout, context)
        else:
            connection = _PinnedHTTP(host, port, address, timeout)
        try:
            connection.request("GET", target, headers=headers)
            if connection.sock is not None:  # getresponse() puede soltar el socket: se ajusta antes
                connection.sock.settimeout(min(timeout, _remaining(deadline)))
            response = connection.getresponse()
            body = _read_body(response, limit, deadline)
            verified = verify
            return response.status, list(response.getheaders()), body, address, verified
        except ssl.SSLCertVerificationError as exc:
            if verify is True and len(attempts) > 1:
                continue
            raise OSError(f"Certificado TLS no válido ({exc.verify_message}); "
                          "usa --insecure-tls solo si el sitio está autorizado y confías en la red") from exc
        finally:
            connection.close()
    raise OSError("No se pudo conectar")  # pragma: no cover


def http_get(url, policy, timeout, limit=MAX_BODY, headers=None, max_redirects=MAX_REDIRECTS,
             insecure_tls=False, deadline=None):
    """GET con redirecciones manuales dentro del alcance. Nunca lanza por redirecciones bloqueadas:
    se detiene y las marca con ``blocked`` en la cadena. Sí lanza ScopeError si la URL inicial
    no está permitida. ``deadline`` (time.monotonic) limita el tiempo total; OSError si se agota."""
    current = normalize_url(url)
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
                    raise ScopeError("Demasiadas redirecciones o redirección en bucle")
                if parse.urlsplit(current).scheme == "https" and parse.urlsplit(nxt).scheme == "http":
                    entry["downgrade"] = True
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
