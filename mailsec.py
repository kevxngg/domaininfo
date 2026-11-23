"""Mail security of a domain: SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI.

Public DNS queries only (plus the MTA-STS policy over HTTPS). The analysis functions
are pure so they can be tested without a network.
"""

import re

from i18n import tr

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
                  "mail", "dkim", "smtp", "mx", "email", "mandrill", "everlytickey1",
                  "zoho", "protonmail", "fm1", "mxvault", "sendgrid", "amazonses", "cm")
SPF_LOOKUP_TERMS = ("include:", "a", "a:", "mx", "mx:", "ptr", "ptr:", "exists:", "redirect=")


def analyze_spf(records):
    """records: TXT records of the domain. Returns the policy, the mechanisms and the issues.

    When ``present`` is False the only issue is the missing record itself (score.py relies on it)."""
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False,
                "issues": [tr("No SPF record: anyone can claim to send mail for this domain")]}
    result = {"present": True, "record": spf[0], "issues": []}
    if len(spf) > 1:
        result["issues"].append(tr("Several SPF records; receivers treat this as an error (permerror)"))
    terms = spf[0].split()[1:]
    result["mechanisms"] = terms
    lookups = sum(1 for t in terms if t.lstrip("+-~?").lower().startswith(SPF_LOOKUP_TERMS)
                  and t.lstrip("+-~?").lower() not in ("all",))
    result["dns_lookups"] = lookups
    if lookups > 10:
        result["issues"].append(tr("{lookups} direct DNS lookups (maximum 10): SPF may fail", lookups=lookups))
    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    qualifier = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}
    if all_term is None:
        result["all"] = None
        if not any(t.lower().startswith("redirect=") for t in terms):
            result["issues"].append(tr("Missing '-all' or '~all': SPF does not reject unauthorized senders"))
    else:
        result["all"] = qualifier.get(all_term[0], "pass")
        if result["all"] == "pass":
            result["issues"].append(tr("'+all' authorizes any server: SPF gives no protection"))
        elif result["all"] == "neutral":
            result["issues"].append(tr("'?all' tells receivers nothing"))
    if any(t.lstrip("+-~?").lower().startswith("ptr") for t in terms):
        result["issues"].append(tr("The 'ptr' mechanism is discouraged (RFC 7208)"))
    return result


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def analyze_dmarc(records):
    dmarc = [r for r in records if r.lower().replace(" ", "").startswith("v=dmarc1")]
    if not dmarc:
        return {"present": False,
                "issues": [tr("No DMARC: receivers do not know what to do with forged mail")]}
    tags = parse_tags(dmarc[0])
    policy = tags.get("p", "").lower()
    result = {"present": True, "record": dmarc[0], "policy": policy or None,
              "subdomain_policy": tags.get("sp", policy) or None,
              "pct": int(tags["pct"]) if tags.get("pct", "").isdigit() else 100,
              "reports": tags.get("rua"), "issues": []}
    if len(dmarc) > 1:
        result["issues"].append(tr("Several DMARC records: all of them are ignored"))
    if policy not in ("none", "quarantine", "reject"):
        result["issues"].append(tr("DMARC policy 'p=' missing or invalid"))
    elif policy == "none":
        result["issues"].append(tr("p=none only monitors: forged mail is still delivered"))
    if result["pct"] < 100 and policy in ("quarantine", "reject"):
        result["issues"].append(tr("Applied to only {pct}% of messages (pct)", pct=result["pct"]))
    if not result["reports"]:
        result["issues"].append(tr("No 'rua': you get no reports on who sends mail in your name"))
    return result


def analyze_mta_sts(txt_records, policy_text):
    present = any(r.lower().startswith("v=stsv1") for r in txt_records)
    result = {"present": present, "mode": None}
    if present and policy_text:
        match = re.search(r"^mode:\s*(\w+)", policy_text, re.M | re.I)
        result["mode"] = match.group(1).lower() if match else None
    return result


def grade(spf, dmarc, dkim_found, mta_sts, has_mx):
    """A–F grade and whether the domain can be spoofed."""
    strong_spf = spf.get("present") and spf.get("all") in ("fail", "softfail")
    enforcing = dmarc.get("present") and dmarc.get("policy") in ("quarantine", "reject")
    # Without a DMARC policy that rejects or quarantines, the visible sender (From) can be forged
    # even with a strict SPF: SPF only validates the envelope sender.
    spoofable = not enforcing
    if strong_spf and enforcing and dmarc.get("pct", 100) == 100 and dkim_found:
        letter = "A" if mta_sts.get("mode") == "enforce" or not has_mx else "A-"
    elif strong_spf and enforcing:
        letter = "B"
    elif spf.get("present") and dmarc.get("present"):
        letter = "C"
    elif spf.get("present") or dmarc.get("present"):
        letter = "D"
    else:
        letter = "F"
    return letter, spoofable


def audit(domain, txt, timeout, fetch=None):
    """txt(name) -> list of TXT records; MX records come from the same DNS client."""
    import dnsclient
    lookup = txt or (lambda name: dnsclient.values(name, "TXT", timeout))
    try:
        mx = dnsclient.values(domain, "MX", timeout)
    except dnsclient.DNSError:
        mx = []
    null_mx = len(mx) == 1 and mx[0]["host"] in ("", ".")
    spf = analyze_spf(lookup(domain))
    dmarc = analyze_dmarc(lookup("_dmarc." + domain))
    dkim = []
    for selector in DKIM_SELECTORS:
        try:
            records = lookup(f"{selector}._domainkey.{domain}")
        except Exception:  # noqa: BLE001 - one failing selector does not invalidate the rest
            continue
        if any("p=" in r for r in records):
            dkim.append(selector)
    sts_txt = lookup("_mta-sts." + domain)
    policy = None
    if any(r.lower().startswith("v=stsv1") for r in sts_txt) and fetch:
        try:
            meta, body = fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout)
            if meta["status"] == 200:
                policy = body.decode("utf-8", "replace")
        except (OSError, ValueError):
            policy = None
    mta_sts = analyze_mta_sts(sts_txt, policy)
    tls_rpt = any(r.lower().startswith("v=tlsrptv1") for r in lookup("_smtp._tls." + domain))
    bimi = any(r.lower().startswith("v=bimi1") for r in lookup("default._bimi." + domain))
    letter, spoofable = grade(spf, dmarc, bool(dkim), mta_sts, bool(mx) and not null_mx)
    return {"grade": letter, "spoofable": spoofable,
            "mx": [] if null_mx else sorted(mx, key=lambda r: r["priority"]),
            "accepts_mail": bool(mx) and not null_mx, "spf": spf, "dmarc": dmarc,
            "dkim": {"selectors_found": dkim, "checked": len(DKIM_SELECTORS),
                     "note": tr("Only common selectors are tried; others may exist")},
            "mta_sts": mta_sts, "tls_rpt": tls_rpt, "bimi": bimi}
