"""Cliente DNS mínimo con la biblioteca estándar: UDP, TCP y DNS sobre HTTPS.

Sin dependencias: construye y lee mensajes DNS (RFC 1035) para consultar MX, NS, TXT,
SOA, CAA, CNAME, PTR, SRV, DS y DNSKEY. Usa los servidores del sistema y, si no
responden (redes que bloquean el puerto 53, Android sin resolv.conf), DNS sobre HTTPS.
"""

import base64
import ipaddress
import os
import random
import socket
import struct
from urllib import request

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "CAA": 257}
TYPE_NAMES = {value: key for key, value in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")
FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8")


class DNSError(Exception):
    """La consulta no obtuvo una respuesta válida de ningún servidor."""


def system_resolvers():
    """Servidores DNS del sistema (DOMAININFO_RESOLVER tiene prioridad)."""
    custom = os.environ.get("DOMAININFO_RESOLVER")
    if custom:
        return [item.strip() for item in custom.split(",") if item.strip()]
    servers = []
    candidates = ["/etc/resolv.conf"]
    if os.environ.get("PREFIX"):  # Termux
        candidates.insert(0, os.path.join(os.environ["PREFIX"], "etc", "resolv.conf"))
    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        try:
                            address = ipaddress.ip_address(parts[1].split("%")[0])
                        except ValueError:
                            continue
                        # 127.0.0.53 (systemd) suele funcionar; se conserva.
                        servers.append(str(address))
        except OSError:
            continue
        if servers:
            break
    return servers or list(FALLBACK_SERVERS)


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("Etiqueta DNS demasiado larga")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype, qid=None, dnssec=False):
    """Mensaje de consulta con EDNS0 (respuestas UDP de hasta 1232 bytes)."""
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    code = TYPES[qtype] if isinstance(qtype, str) else qtype
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack(">HH", code, 1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000 if dnssec else 0, 0)
    return qid, header + question + opt


def read_name(msg, offset, depth=0):
    """Nombre en la posición dada (con punteros de compresión). Devuelve (nombre, siguiente)."""
    labels = []
    jumped = False
    end = offset
    for _ in range(128):
        if offset >= len(msg):
            raise DNSError("Nombre DNS truncado")
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise DNSError("Puntero DNS truncado")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            if pointer >= len(msg) or depth > 20:
                raise DNSError("Puntero DNS inválido")
            offset = pointer
            depth += 1
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            return ".".join(labels), end
        offset += 1
        labels.append(msg[offset:offset + length].decode("ascii", "replace"))
        offset += length
    raise DNSError("Nombre DNS demasiado largo")


def parse_rdata(msg, rtype, offset, length):
    data = msg[offset:offset + length]
    name = TYPE_NAMES.get(rtype, str(rtype))
    if name == "A" and length == 4:
        return str(ipaddress.IPv4Address(data))
    if name == "AAAA" and length == 16:
        return str(ipaddress.IPv6Address(data))
    if name in ("NS", "CNAME", "PTR"):
        return read_name(msg, offset)[0]
    if name == "MX":
        return {"priority": struct.unpack(">H", data[:2])[0], "host": read_name(msg, offset + 2)[0]}
    if name == "TXT":
        parts, pos = [], 0
        while pos < length:
            size = data[pos]
            parts.append(data[pos + 1:pos + 1 + size].decode("utf-8", "replace"))
            pos += 1 + size
        return "".join(parts)
    if name == "SOA":
        mname, pos = read_name(msg, offset)
        rname, pos = read_name(msg, pos)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[pos:pos + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    if name == "SRV":
        priority, weight, port = struct.unpack(">HHH", data[:6])
        return {"priority": priority, "weight": weight, "port": port, "target": read_name(msg, offset + 6)[0]}
    if name == "CAA":
        flags, tag_len = data[0], data[1]
        return {"flags": flags, "tag": data[2:2 + tag_len].decode("ascii", "replace"),
                "value": data[2 + tag_len:].decode("utf-8", "replace")}
    if name == "DS":
        key_tag, algorithm, digest_type = struct.unpack(">HBB", data[:4])
        return {"key_tag": key_tag, "algorithm": algorithm, "digest_type": digest_type, "digest": data[4:].hex()}
    if name == "DNSKEY":
        flags, protocol, algorithm = struct.unpack(">HBB", data[:4])
        return {"flags": flags, "protocol": protocol, "algorithm": algorithm, "sep": bool(flags & 1)}
    return data.hex()


def parse_response(msg, qid=None):
    if len(msg) < 12:
        raise DNSError("Respuesta DNS demasiado corta")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", msg[:12])
    if qid is not None and rid != qid:
        raise DNSError("Identificador de respuesta distinto")
    offset = 12
    for _ in range(qdcount):
        _, offset = read_name(msg, offset)
        offset += 4
    sections = {}
    for section, count in (("answers", ancount), ("authority", nscount), ("additional", arcount)):
        rows = []
        for _ in range(count):
            name, offset = read_name(msg, offset)
            rtype, rclass, ttl, length = struct.unpack(">HHIH", msg[offset:offset + 10])
            offset += 10
            if offset + length > len(msg):
                raise DNSError("Registro DNS truncado")
            if rtype != 41:  # OPT
                rows.append({"name": name, "type": TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl,
                             "value": parse_rdata(msg, rtype, offset, length)})
            offset += length
        sections[section] = rows
    return {"rcode": RCODES.get(flags & 0xF, str(flags & 0xF)), "truncated": bool(flags & 0x0200),
            "authenticated": bool(flags & 0x0020), **sections}


def _udp(server, packet, timeout):
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        return sock.recvfrom(4096)[0]


def _tcp(server, packet, timeout):
    with socket.create_connection((server, 53), timeout=timeout) as sock:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        size = struct.unpack(">H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, size)


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise DNSError("Conexión DNS cerrada")
        data += chunk
    return data


def _doh(packet, timeout):
    encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode("ascii")
    last = None
    for url in DOH_SERVERS:
        try:
            req = request.Request(url + "?dns=" + encoded, headers={"Accept": "application/dns-message",
                                                                     "User-Agent": "DomainInfo"})
            with request.urlopen(req, timeout=timeout) as response:
                return response.read(65535), url
        except OSError as exc:
            last = exc
    raise DNSError(f"DNS sobre HTTPS no disponible: {last}")


def query(name, qtype, timeout=3.0, servers=None, dnssec=False):
    """Consulta un tipo de registro. Devuelve rcode, respuestas y el servidor usado."""
    qid, packet = build_query(name, qtype, dnssec=dnssec)
    errors = []
    for server in servers or system_resolvers():
        try:
            raw = _udp(server, packet, timeout)
            result = parse_response(raw, qid)
            if result["truncated"]:
                result = parse_response(_tcp(server, packet, timeout), qid)
            result["server"] = server
            return result
        except (OSError, DNSError, struct.error, ValueError) as exc:
            errors.append(f"{server}: {exc}")
    try:
        raw, url = _doh(packet, timeout)
        result = parse_response(raw, qid)
        result["server"] = url
        return result
    except (OSError, DNSError, struct.error, ValueError) as exc:
        errors.append(str(exc))
    raise DNSError("; ".join(errors))


def values(name, qtype, timeout=3.0, servers=None):
    """Solo los valores del tipo pedido ([] si no existe el nombre o el registro)."""
    result = query(name, qtype, timeout, servers)
    return [row["value"] for row in result.get("answers", []) if row["type"] == qtype]


def reverse_name(address):
    return ipaddress.ip_address(address).reverse_pointer


def is_single_label(name):
    return "." not in name.strip(".")
