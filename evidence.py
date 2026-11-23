"""DomainInfo 6 evidence model: findings with status and confidence, secret redaction
and the three scores (security, coverage and confidence).

Ground rule: a heuristic observation is never presented as a confirmed vulnerability.
Only ``confirmed`` and ``likely`` lower the score; ``pending`` means there is no evidence
either way and it has to be verified by hand.

Every enumerated value (severity, status, confidence, check state, evidence kind) is English
in the JSON whatever the output language; ``STATUS_LABELS`` gives the translated label.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import re

from i18n import tr

STATUSES = ("confirmed", "likely", "informational", "pending", "not_applicable", "not_evaluated", "error")
SEVERITIES = ("high", "medium", "low", "info")
CONFIDENCE = ("high", "medium", "low")
PENALTY = {"high": 20, "medium": 8, "low": 3, "info": 0}
STATUS_WEIGHT = {"confirmed": 1.0, "likely": 0.5}
CHECK_STATES = ("ok", "finding", "not_applicable", "not_evaluated", "error")
EVIDENCE_KINDS = ("direct", "heuristic")


class _Labels(dict):
    """Status -> label in the active language (translated on every lookup, not at import time)."""

    def __getitem__(self, key):
        return tr(super().__getitem__(key))

    def get(self, key, default=None):
        return self[key] if key in self else default


STATUS_LABELS = _Labels({"confirmed": "Confirmed", "likely": "Likely", "informational": "Informational",
                         "pending": "Pending verification", "not_applicable": "Not applicable",
                         "not_evaluated": "Not evaluated", "error": "Check error"})

# Pattern of parameter names that usually carry secrets (used to hide them; it is not a secret)
_SECRET_WORDS = (r"(?:sess|sid|token|csrf|xsrf|auth|jwt|secret|passw|pwd|apikey|api_key|cookie|key|"  # noqa: S105
                 r"code|sig|signature|ticket|nonce)")
_SECRET_NAME = r"[\w.-]{0,64}" + _SECRET_WORDS + r"[\w.-]{0,64}"
_SECRET_PARAM = re.compile(r"(?i)" + _SECRET_NAME)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     lambda m: "-----BEGIN PRIVATE KEY-----" + tr("[hidden]")),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: mask(m.group(0))),
    (re.compile(r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}"), lambda m: mask(m.group(0))),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[\w-]{10,}|AIza[\w-]{35})"), lambda m: mask(m.group(0))),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), lambda m: m.group(1) + " " + tr("[hidden]")),
    # Bounded name (no nested quantifiers: linear time); the list of names is checked separately.
    # The lookahead (bounded to 64) requires a sensitive name: a key such as "http" never gets to
    # consume the URL that follows, and everything stays linear-time.
    (re.compile(r"(?i)(?<![\w.-])(?=[\w.-]{0,64}?" + _SECRET_WORDS + r")([\w.-]{1,64})"
                # The value is consumed whole (no limit): no long tail stays visible. Still linear
                # because the name is bounded and the input is cut to REDACT_INPUT_LIMIT.
                r"([\"']?[ \t]*[=:][ \t]*[\"']?)([^\s;,\"'&<>]{4,})"),
     lambda m: m.group(1) + m.group(2) + mask(m.group(3))),
)
REDACT_INPUT_LIMIT = 4000


def mask(value):
    """First 4 characters and the rest hidden; nothing at all if it is too short."""
    value = str(value)
    return value[:4] + "…" + tr("[hidden]") if len(value) > 8 else tr("[hidden]")


def redact(text, limit=300):
    """Remove recognizable secrets (cookies, tokens, keys) and trim the evidence."""
    text = str(text or "")[:REDACT_INPUT_LIMIT]
    for pattern, replace in _PATTERNS:
        text = pattern.sub(replace, text)
    text = clean(re.sub(r"\s+", " ", text)).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def clean(text):
    """Remove control characters (e.g. ANSI sequences that could spoof the terminal)."""
    return _CONTROL.sub("", str(text))


def redact_url(url):
    """URL with the values of sensitive parameters (code, token, sid, key…) hidden."""
    from urllib import parse
    parts = parse.urlsplit(clean(url))
    if not parts.query:
        return parts.geturl()
    pairs = parse.parse_qsl(parts.query, keep_blank_values=True)
    query = "&".join(parse.quote(k, safe="") + "=" + (mask(v) if _SECRET_PARAM.fullmatch(k) and v
                                                         else parse.quote(v, safe="/:"))
                     for k, v in pairs)
    return parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


@dataclass
class Finding:
    """Finding with a verifiable origin. ``evidence`` is redacted when serialized."""

    target: str
    path: str
    category: str
    title: str
    severity: str
    status: str
    confidence: str = "medium"
    evidence: str = ""
    tool: str = "domaininfo.webapp"
    impact: str = ""
    verification: str = ""
    recommendation: str = ""
    references: list = field(default_factory=list)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(tr("Invalid severity: {value}", value=self.severity))
        if self.status not in STATUSES:
            raise ValueError(tr("Invalid status: {value}", value=self.status))
        if self.confidence not in CONFIDENCE:
            raise ValueError(tr("Invalid confidence: {value}", value=self.confidence))

    def to_dict(self):
        data = {key: (str(value) if isinstance(value, str) else value) for key, value in asdict(self).items()}
        data["evidence"] = redact(self.evidence)
        return {"id": finding_id(self.target, self.category, self.title), **data}


def finding_id(target, category, title):
    """Stable id: computed from the English title, so it is the same in every language."""
    from i18n import source
    digest = hashlib.sha256("|".join((str(target), str(category), source(title))).encode()).hexdigest()
    return "DI-" + digest[:10].upper()


def scores(findings, checks):
    """Security (risk), Coverage (checks performed) and Confidence (direct evidence), 0–100."""
    penalty = sum(PENALTY.get(f.get("severity"), 0) * STATUS_WEIGHT.get(f.get("status"), 0) for f in findings)
    applicable = [c for c in checks if c.get("state") != "not_applicable"]
    executed = [c for c in applicable if c.get("state") in ("ok", "finding")]
    direct = [c for c in executed if c.get("evidence") == "direct"]
    return {"security": max(0, round(100 - penalty)),
            "coverage": round(100 * len(executed) / len(applicable)) if applicable else 0,
            "confidence": round(100 * len(direct) / len(executed)) if executed else 0}


def comparable(a, b, tolerance=10):
    """Two assessments are only comparable if they check the same things with similar coverage."""
    return set(a.get("checks", [])) == set(b.get("checks", [])) and \
        abs(a.get("coverage", 0) - b.get("coverage", 0)) <= tolerance


# Classic modules whose conclusion is heuristic (fingerprints, lists, name matches)
_HEURISTIC = {"tech", "subdomains", "lookalike", "history", "mikrotik"}


def assess(report):
    """Overall assessment (the report's ``assessment`` field): combines the webapp checks with
    the state of the classic modules and the 5.0 grade findings as 'likely'."""
    findings, checks = [], []
    for name, module in (report.get("modules") or {}).items():
        status = module.get("status")
        data = module.get("data") if isinstance(module.get("data"), dict) else {}
        # Modules built on the evidence model (webapp, auth, api, zap, browser, tools, intel) bring their own
        # findings and checks; classic modules count as one check each.
        if status == "ok" and (isinstance(data.get("checks"), list) or isinstance(data.get("findings"), list)):
            findings += [f for f in data.get("findings") or [] if isinstance(f, dict) and f.get("status")]
            own = [c for c in data.get("checks") or [] if isinstance(c, dict) and c.get("id")]
            checks += [{**c, "id": name + "." + str(c["id"])} for c in own] or [
                {"id": name, "state": "ok", "evidence": "heuristic" if name in _HEURISTIC else "direct"}]
            continue
        state = {"ok": "ok", "error": "error"}.get(status, "not_applicable" if module.get("reason") else "not_evaluated")
        checks.append({"id": name, "state": state,
                       "evidence": "heuristic" if name in _HEURISTIC else "direct"})
    legacy = report.get("score") if isinstance(report.get("score"), dict) else {}
    for item in legacy.get("findings", []):
        if not item.get("source"):  # findings copied from evidence modules are already counted
            findings.append({"severity": item.get("severity"), "status": "likely"})
    if not checks:
        return None
    result: dict = dict(scores(findings, checks))
    counts = {}
    for item in findings:
        counts[item.get("status")] = counts.get(item.get("status"), 0) + 1
    result.update({"version": 2, "checks": sorted(c["id"] for c in checks if c.get("state") != "not_applicable"),
                   "status_counts": counts,
                   "note": tr("security: risk of what was checked · coverage: share checked · confidence: share "
                              "with direct evidence. Compare audits only if their coverage is comparable.")})
    return result
