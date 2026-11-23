"""Modelo de evidencias de DomainInfo 6: hallazgos con estado y confianza, redacción de secretos
y las tres puntuaciones (seguridad, cobertura y confianza).

Regla básica: una observación heurística nunca se presenta como vulnerabilidad confirmada.
Solo ``confirmado`` y ``probable`` restan puntos; ``pendiente`` significa que no hay evidencia
en ningún sentido y hay que verificarlo a mano.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import re

STATUSES = ("confirmado", "probable", "informativo", "pendiente", "no_aplicable", "no_evaluado", "error")
SEVERITIES = ("alta", "media", "baja", "info")
CONFIDENCE = ("alta", "media", "baja")
PENALTY = {"alta": 20, "media": 8, "baja": 3, "info": 0}
STATUS_WEIGHT = {"confirmado": 1.0, "probable": 0.5}
CHECK_STATES = ("ok", "hallazgo", "no_aplicable", "no_evaluado", "error")
STATUS_LABELS = {"confirmado": "Confirmado", "probable": "Probable", "informativo": "Informativo",
                 "pendiente": "Pendiente de verificar", "no_aplicable": "No aplicable",
                 "no_evaluado": "No evaluado", "error": "Error de comprobación"}

# Patrón de nombres de parámetros que suelen llevar secretos (se usa para ocultarlos, no es un secreto)
_SECRET_WORDS = (r"(?:sess|sid|token|csrf|xsrf|auth|jwt|secret|passw|pwd|apikey|api_key|cookie|key|"  # noqa: S105
                 r"code|sig|signature|ticket|nonce)")
_SECRET_NAME = r"[\w.-]{0,64}" + _SECRET_WORDS + r"[\w.-]{0,64}"
_SECRET_PARAM = re.compile(r"(?i)" + _SECRET_NAME)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     lambda m: "-----BEGIN PRIVATE KEY-----[oculto]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: mask(m.group(0))),
    (re.compile(r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}"), lambda m: mask(m.group(0))),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[\w-]{10,}|AIza[\w-]{35})"), lambda m: mask(m.group(0))),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), lambda m: m.group(1) + " [oculto]"),
    # Nombre acotado (sin cuantificadores anidados: tiempo lineal); la lista de nombres se comprueba aparte
    # La búsqueda anticipada (acotada a 64) exige un nombre sensible: una clave como "http" no llega a
    # consumir la URL que sigue, y todo sigue siendo de tiempo lineal.
    (re.compile(r"(?i)(?<![\w.-])(?=[\w.-]{0,64}?" + _SECRET_WORDS + r")([\w.-]{1,64})"
                # El valor se consume entero (sin límite): ninguna cola larga queda visible. Sigue siendo
                # lineal porque el nombre está acotado y la entrada se recorta a REDACT_INPUT_LIMIT.
                r"([\"']?[ \t]*[=:][ \t]*[\"']?)([^\s;,\"'&<>]{4,})"),
     lambda m: m.group(1) + m.group(2) + mask(m.group(3))),
)
REDACT_INPUT_LIMIT = 4000


def mask(value):
    """Primeros 4 caracteres y el resto oculto; nada si es demasiado corto."""
    value = str(value)
    return value[:4] + "…[oculto]" if len(value) > 8 else "[oculto]"


def redact(text, limit=300):
    """Quita secretos reconocibles (cookies, tokens, claves) y recorta la evidencia."""
    text = str(text or "")[:REDACT_INPUT_LIMIT]
    for pattern, replace in _PATTERNS:
        text = pattern.sub(replace, text)
    text = clean(re.sub(r"\s+", " ", text)).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def clean(text):
    """Quita caracteres de control (p. ej. secuencias ANSI que podrían falsear la terminal)."""
    return _CONTROL.sub("", str(text))


def redact_url(url):
    """URL con los valores de parámetros sensibles (code, token, sid, key…) ocultos."""
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
    """Hallazgo con origen verificable. ``evidence`` se redacta al serializar."""

    target: str
    path: str
    category: str
    title: str
    severity: str
    status: str
    confidence: str = "media"
    evidence: str = ""
    tool: str = "domaininfo.webapp"
    impact: str = ""
    verification: str = ""
    recommendation: str = ""
    references: list = field(default_factory=list)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Severidad no válida: {self.severity}")
        if self.status not in STATUSES:
            raise ValueError(f"Estado no válido: {self.status}")
        if self.confidence not in CONFIDENCE:
            raise ValueError(f"Confianza no válida: {self.confidence}")

    def to_dict(self):
        data = asdict(self)
        data["evidence"] = redact(self.evidence)
        digest = hashlib.sha256("|".join((self.target, self.category, self.title)).encode()).hexdigest()
        return {"id": "DI-" + digest[:10].upper(), **data}


def scores(findings, checks):
    """Security (riesgo), Coverage (comprobaciones hechas) y Confidence (evidencia directa), 0–100."""
    penalty = sum(PENALTY.get(f.get("severity"), 0) * STATUS_WEIGHT.get(f.get("status"), 0) for f in findings)
    applicable = [c for c in checks if c.get("state") != "no_aplicable"]
    executed = [c for c in applicable if c.get("state") in ("ok", "hallazgo")]
    direct = [c for c in executed if c.get("evidence") == "directa"]
    return {"security": max(0, round(100 - penalty)),
            "coverage": round(100 * len(executed) / len(applicable)) if applicable else 0,
            "confidence": round(100 * len(direct) / len(executed)) if executed else 0}


def comparable(a, b, tolerance=10):
    """Dos evaluaciones solo se comparan si revisan lo mismo y con cobertura parecida."""
    return set(a.get("checks", [])) == set(b.get("checks", [])) and \
        abs(a.get("coverage", 0) - b.get("coverage", 0)) <= tolerance


# Módulos clásicos cuya conclusión es heurística (huellas, listas, coincidencias por nombre)
_HEURISTIC = {"tech", "subdomains", "lookalike", "history", "mikrotik"}


def assess(report):
    """Evaluación global (campo ``assessment`` del reporte): combina las comprobaciones de webapp
    con el estado de los módulos clásicos y los hallazgos de la nota 5.0 como 'probable'."""
    findings, checks = [], []
    for name, module in (report.get("modules") or {}).items():
        status = module.get("status")
        data = module.get("data") if isinstance(module.get("data"), dict) else {}
        if name == "webapp" and status == "ok":
            findings += data.get("findings", [])
            checks += [{**c, "id": "webapp." + c["id"]} for c in data.get("checks", [])]
            continue
        state = {"ok": "ok", "error": "error"}.get(status, "no_aplicable" if module.get("reason") else "no_evaluado")
        checks.append({"id": name, "state": state,
                       "evidence": "heuristica" if name in _HEURISTIC else "directa"})
    legacy = report.get("score") if isinstance(report.get("score"), dict) else {}
    for item in legacy.get("findings", []):
        if item.get("source") != "webapp":
            findings.append({"severity": item.get("severity"), "status": "probable"})
    if not checks:
        return None
    result: dict = dict(scores(findings, checks))
    counts = {}
    for item in findings:
        counts[item.get("status")] = counts.get(item.get("status"), 0) + 1
    result.update({"version": 2, "checks": sorted(c["id"] for c in checks if c.get("state") != "no_aplicable"),
                   "status_counts": counts,
                   "note": "security: riesgo de lo comprobado · coverage: parte comprobada · confidence: parte "
                           "con evidencia directa. Compara auditorías solo si su cobertura es comparable."})
    return result
