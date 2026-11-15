"""Historia del dominio: antigüedad y caducidad del registro (RDAP), registrador y
primera y última captura en la Wayback Machine de Internet Archive.
"""

from datetime import datetime, timezone
import json
from urllib import parse, request


def _date(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def from_rdap(rdap):
    """Fechas y registrador de una respuesta RDAP ya descargada."""
    events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", []) if isinstance(e, dict)}
    now = datetime.now(timezone.utc)
    registered, expires = _date(events.get("registration")), _date(events.get("expiration"))
    result = {"registered": registered.date().isoformat() if registered else None,
              "expires": expires.date().isoformat() if expires else None,
              "last_changed": (events.get("last changed") or "")[:10] or None,
              "age_days": (now - registered).days if registered else None,
              "expires_in_days": (expires - now).days if expires else None,
              "registrar": None, "status": rdap.get("status", [])}
    for entity in rdap.get("entities", []) or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
            name = next((item[3] for item in vcard if item and item[0] == "fn"), None)
            result["registrar"] = name or entity.get("handle")
    if result["age_days"] is not None:
        result["new_domain"] = result["age_days"] < 90
    return result


def wayback(domain, timeout):
    base = "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp&url=" + parse.quote(domain)

    def one(limit):
        req = request.Request(base + f"&limit={limit}", headers={"User-Agent": "DomainInfo"})
        with request.urlopen(req, timeout=timeout) as response:
            rows = json.loads(response.read(64 * 1024) or b"[]")
        if len(rows) > 1:
            stamp = rows[1][0]
            return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}"
        return None
    return {"first_capture": one(1), "last_capture": one(-1)}
