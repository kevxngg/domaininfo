"""Network of each address: autonomous system (ASN), prefix, country, operator and reverse DNS.

Uses Team Cymru's public DNS (TXT) service, with no keys or libraries.
"""

import ipaddress

import dnsclient
from i18n import tr


def _fields(text):
    return [part.strip() for part in text.split("|")]


def lookup(address, timeout=3.0):
    ip = ipaddress.ip_address(address)
    row = {"ip": str(ip), "ptr": None, "asn": None, "prefix": None, "country": None,
           "registry": None, "as_name": None}
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        row["note"] = tr("Private or reserved address: no public network data")
        return row
    try:
        ptr = dnsclient.values(dnsclient.reverse_name(str(ip)), "PTR", timeout)
        row["ptr"] = ptr[0] if ptr else None
    except dnsclient.DNSError:
        pass
    if ip.version == 4:
        name = ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = ip.exploded.replace(":", "")
        name = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    try:
        origin = dnsclient.values(name, "TXT", timeout)
    except dnsclient.DNSError as exc:
        row["error"] = str(exc)
        return row
    if origin:
        parts = _fields(origin[0])
        if len(parts) >= 4:
            row.update(asn=parts[0].split()[0], prefix=parts[1], country=parts[2], registry=parts[3])
    if row["asn"]:
        try:
            names = dnsclient.values(f"AS{row['asn']}.asn.cymru.com", "TXT", timeout)
            if names:
                parts = _fields(names[0])
                row["as_name"] = parts[-1] if parts else None
        except dnsclient.DNSError:
            pass
    return row
