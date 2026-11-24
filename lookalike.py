"""Lookalike domains (typosquatting): generates variants of the name and checks which ones
exist. Helps protect a brand against phishing and impersonation.

Variant ``kind`` values (JSON, always English): omission, repetition, transposition,
adjacent key, insertion, homoglyph, bit flip, hyphenation, vowel swap, added word, other TLD.
"""

from concurrent.futures import ThreadPoolExecutor
import socket

import dnsclient
from i18n import tr

KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
            "o": "ipl", "p": "ol", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv",
            "h": "gyjb", "j": "hukn", "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
            "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"}
HOMOGLYPHS = {"o": ("0",), "l": ("1", "i"), "i": ("1", "l"), "e": ("3",), "a": ("4",), "s": ("5",),
              "g": ("9", "q"), "m": ("rn", "nn"), "w": ("vv",), "d": ("cl",), "b": ("6",)}
TLDS = ("com", "net", "org", "co", "io", "info", "biz", "xyz", "online", "site", "shop", "app",
        "store", "live", "me", "us", "mx", "es", "com.co", "com.mx")
SECOND_LEVEL = ("co.uk", "com.co", "com.mx", "com.ar", "com.br", "com.pe", "com.ec", "com.ve", "gov.co",
                "edu.co", "org.co", "net.co", "com.es", "com.au", "co.jp", "com.cl", "gob.mx")


def split(domain):
    for suffix in SECOND_LEVEL:
        if domain.endswith("." + suffix):
            head = domain[:-len(suffix) - 1]
            return head.split(".")[-1], suffix
    parts = domain.split(".")
    return (parts[-2], parts[-1]) if len(parts) >= 2 else (parts[0], "")


def _valid(label):
    return 1 <= len(label) <= 63 and not label.startswith("-") and not label.endswith("-") \
        and all(c.isalnum() or c == "-" for c in label)


def generate(domain, limit=600):
    """List of (domain, kind) without duplicates or the original."""
    name, tld = split(domain)
    seen, out = {domain}, []

    def add(label, kind, suffix=tld):
        candidate = f"{label}.{suffix}"
        if _valid(label) and candidate not in seen:
            seen.add(candidate)
            out.append((candidate, kind))
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
        for near in KEYBOARD.get(name[i], ""):
            add(name[:i] + near + name[i + 1:], "adjacent key")
            add(name[:i] + near + name[i:], "insertion")
        for glyph in HOMOGLYPHS.get(name[i], ()):
            add(name[:i] + glyph + name[i + 1:], "homoglyph")
        for bit in range(8):
            flipped = chr(ord(name[i]) ^ (1 << bit))
            if flipped.isalnum() and flipped.isascii():
                add(name[:i] + flipped.lower() + name[i + 1:], "bit flip")
        if 0 < i < len(name):
            add(name[:i] + "-" + name[i:], "hyphenation")
    for vowel_from in "aeiou":
        if vowel_from in name:
            for vowel_to in "aeiou":
                if vowel_to != vowel_from:
                    add(name.replace(vowel_from, vowel_to, 1), "vowel swap")
    # Spanish words stay on purpose: phishers target Spanish-speaking brands too.
    for extra in ("login", "secure", "app", "online", "soporte", "pago", "cuenta", "verify", "my", "web"):
        add(f"{name}-{extra}", "added word")
        add(f"{extra}{name}", "added word")
    for other in TLDS:
        if other != tld:
            add(name, "other TLD", other)
    return out[:limit]


def check(candidate, timeout):
    try:
        addresses = sorted({e[4][0] for e in socket.getaddrinfo(candidate, None, type=socket.SOCK_STREAM)})
    except OSError:
        return None
    row = {"domain": candidate, "addresses": addresses[:4], "mx": False}
    try:
        row["mx"] = bool(dnsclient.values(candidate, "MX", timeout))
    except dnsclient.DNSError:
        pass
    return row


def audit(domain, threads, timeout, limit=600):
    candidates = generate(domain, limit)
    kinds = dict(candidates)
    socket.setdefaulttimeout(timeout)
    try:
        with ThreadPoolExecutor(max_workers=max(threads, 20)) as pool:
            rows = [r for r in pool.map(lambda c: check(c[0], timeout), candidates) if r]
    finally:
        socket.setdefaulttimeout(None)
    for row in rows:
        row["kind"] = kinds.get(row["domain"])
    rows.sort(key=lambda r: (not r["mx"], r["domain"]))
    return {"checked": len(candidates), "registered": rows,
            "with_mail": sum(1 for r in rows if r["mx"]),
            "note": tr("Existing does not mean malicious; review the ones that receive mail or copy your site")}
