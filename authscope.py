"""Authorization file for authenticated audits (DomainInfo 6.0, Phase 2).

Every authenticated test (``session_audit``) refuses to run without a valid file. The file is
JSON (standard library) and states who authorized the test, which URL prefixes may be visited,
which test accounts exist (only the *names* of the environment variables that hold their
username and password), their roles and protected URLs, the login and logout URLs, request and
login-attempt limits and the time window in which the test is allowed. See
``docs/AUTHENTICATED_AUDIT.md`` for the format.

Credentials are never read from the file: a key such as ``password`` is an unknown key and the
file is rejected. Error messages name the environment variable, never its value.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
import re
from urllib import parse

from i18n import tr
import safety

SCHEMA_VERSION = 1
MAX_FILE_SIZE = 256 * 1024
DEFAULT_MAX_REQUESTS = 150
MAX_REQUESTS_CAP = 1000
DEFAULT_LOGIN_ATTEMPTS = 3
LOGIN_ATTEMPTS_CAP = 5
MAX_WINDOW = timedelta(days=90)
MAX_ACCOUNTS = 10
MAX_ROLES = 10
MAX_URLS_PER_ROLE = 20
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
IDENT = re.compile(r"[A-Za-z0-9_.-]{1,64}")
FIELD_NAME = re.compile(r"[\w.:\[\]-]{1,128}")

_TOP_KEYS = {"version", "authorized_by", "authorization_note", "targets", "scope_hosts", "allow_private",
             "login", "logout", "accounts", "roles", "limits", "window"}
_REQUIRED = {"version", "authorized_by", "authorization_note", "targets", "login", "accounts", "roles", "window"}


class AuthorizationError(ValueError):
    """The authorization file is missing, invalid, expired or does not cover the request."""


@dataclass(frozen=True)
class Account:
    """A test account. Only the environment variable *names* are kept here."""

    id: str
    role: str
    username_env: str
    password_env: str

    def credentials(self, environ=None):
        """(username, password) read from the environment; raises AuthorizationError if unset."""
        environ = os.environ if environ is None else environ
        values = []
        for name in (self.username_env, self.password_env):
            value = environ.get(name)
            if not value:
                raise AuthorizationError(tr("Environment variable {name} (account {account}) is not set",
                                            name=name, account=self.id))
            values.append(value)
        return values[0], values[1]


@dataclass
class AuthScope:
    path: str
    authorized_by: str
    authorization_note: str
    targets: list
    login_url: str
    accounts: list
    roles: dict
    not_before: datetime
    not_after: datetime
    scope_hosts: list = field(default_factory=list)
    allow_private: bool = False
    username_field: object = None
    password_field: object = None
    logout_url: object = None
    logout_method: str = "GET"
    max_requests: int = DEFAULT_MAX_REQUESTS
    max_login_attempts: int = DEFAULT_LOGIN_ATTEMPTS
    lockout_check: bool = False
    lockout_account: object = None

    def in_targets(self, url):
        """True when ``url`` (normalized, dot-segments resolved) lies under one of the authorized
        prefixes (scheme, host, port and path on a segment boundary)."""
        try:
            url = safety.normalize_url(url)
        except ValueError:
            return False
        return any(_prefix_match(url, prefix) for prefix in self.targets)

    def require(self, url):
        if not self.in_targets(url):
            raise AuthorizationError(tr("{url} is not covered by the authorized targets", url=_short(url)))
        return safety.normalize_url(url)

    def check_window(self, now=None):
        now = now or datetime.now(timezone.utc)
        if now < self.not_before:
            raise AuthorizationError(tr("The authorized time window has not started yet ({start})",
                                        start=self.not_before.isoformat()))
        if now > self.not_after:
            raise AuthorizationError(tr("The authorized time window ended at {end}", end=self.not_after.isoformat()))

    def account(self, account_id):
        return next(a for a in self.accounts if a.id == account_id)

    def policy(self):
        """ScopePolicy for the audit: the first target is the origin, the other targets and
        ``scope_hosts`` are extra hosts."""
        hosts = [parse.urlsplit(t).hostname or "" for t in self.targets[1:]] + list(self.scope_hosts)
        return safety.ScopePolicy(self.targets[0], extra_hosts=hosts, allow_private=self.allow_private)

    def summary(self):
        """Safe description for the report (no environment variable names or values)."""
        return {"file": os.path.basename(self.path), "authorized_by": self.authorized_by,
                "authorization_note": self.authorization_note, "targets": list(self.targets),
                "window": {"not_before": self.not_before.isoformat(), "not_after": self.not_after.isoformat()},
                "accounts": [{"id": a.id, "role": a.role} for a in self.accounts],
                "roles": sorted(self.roles), "limits": {"max_requests": self.max_requests,
                                                        "max_login_attempts": self.max_login_attempts,
                                                        "lockout_check": self.lockout_check}}


def _short(url):
    return str(url)[:200]


def _prefix_match(url, prefix):
    """``url`` lies under ``prefix``: same scheme, host and port, and the path continues the
    prefix on a segment boundary (``/app`` covers ``/app`` and ``/app/x``, never ``/application``).
    Both are normalized first, so dot-segments (``/app/../admin``) cannot escape the prefix and
    percent-encoded dots or slashes are refused."""
    try:
        url, prefix = safety.normalize_url(url), safety.normalize_url(prefix)
    except ValueError:
        return False
    a, b = parse.urlsplit(url), parse.urlsplit(prefix)
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        return False
    base = b.path or "/"
    path = a.path or "/"
    if base.endswith("/"):
        return path.startswith(base) or path + "/" == base
    return path == base or path.startswith(base + "/")


def _reject_duplicates(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise AuthorizationError(tr("Duplicate key in the authorization file: {key}", key=str(key)[:64]))
        data[key] = value
    return data


def _keys(obj, allowed, where, required=()):
    if not isinstance(obj, dict):
        raise AuthorizationError(tr("{where} must be an object", where=where))
    unknown = sorted(set(obj) - set(allowed))
    if unknown:
        raise AuthorizationError(tr("Unknown key in {where}: {key}", where=where, key=str(unknown[0])[:64]))
    missing = sorted(set(required) - set(obj))
    if missing:
        raise AuthorizationError(tr("Missing key in {where}: {key}", where=where, key=missing[0]))


def _text(value, where, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise AuthorizationError(tr("{where} must be a non-empty text of at most {limit} characters",
                                    where=where, limit=limit))
    return value.strip()


def _bool(value, where):
    if not isinstance(value, bool):
        raise AuthorizationError(tr("{where} must be true or false", where=where))
    return value


def _int(value, where, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise AuthorizationError(tr("{where} must be an integer between {low} and {high}",
                                    where=where, low=low, high=high))
    return value


def _url(value, where):
    if not isinstance(value, str):
        raise AuthorizationError(tr("{where} must be a URL", where=where))
    try:
        return safety.normalize_url(value)
    except ValueError as exc:
        raise AuthorizationError(tr("{where}: invalid URL ({error})", where=where, error=exc)) from None


def _when(value, where):
    if not isinstance(value, str):
        raise AuthorizationError(tr("{where} must be an ISO 8601 date and time with a time zone", where=where))
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AuthorizationError(tr("{where} must be an ISO 8601 date and time with a time zone",
                                    where=where)) from None
    if moment.tzinfo is None:
        raise AuthorizationError(tr("{where} must be an ISO 8601 date and time with a time zone", where=where))
    return moment


def parse_config(data, path="<memory>"):
    """Validate an already decoded authorization document and return an ``AuthScope``."""
    _keys(data, _TOP_KEYS, tr("the authorization file"), _REQUIRED)
    if data["version"] != SCHEMA_VERSION or isinstance(data["version"], bool):
        raise AuthorizationError(tr("Unsupported authorization file version (expected {version})",
                                    version=SCHEMA_VERSION))
    authorized_by = _text(data["authorized_by"], "authorized_by", 200)
    note = _text(data["authorization_note"], "authorization_note", 2000)

    targets = data["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20:
        raise AuthorizationError(tr("targets must be a list of 1 to 20 URL prefixes"))
    targets = [_url(t, "targets") for t in targets]
    for target in targets:
        if parse.urlsplit(target).query:
            raise AuthorizationError(tr("A target prefix cannot contain a query string"))

    scope_hosts = data.get("scope_hosts", [])
    if not isinstance(scope_hosts, list) or len(scope_hosts) > 20:
        raise AuthorizationError(tr("scope_hosts must be a list of at most 20 host names"))
    for host in scope_hosts:
        if not isinstance(host, str):
            raise AuthorizationError(tr("scope_hosts must be a list of at most 20 host names"))
        try:
            safety.normalize_host(host[2:] if host.startswith("*.") else host)
        except ValueError:
            raise AuthorizationError(tr("Invalid host in scope_hosts: {host}", host=host[:100])) from None
    allow_private = _bool(data.get("allow_private", False), "allow_private")

    scope = AuthScope(path=str(path), authorized_by=authorized_by, authorization_note=note, targets=targets,
                      login_url="", accounts=[], roles={}, not_before=datetime.now(timezone.utc),
                      not_after=datetime.now(timezone.utc), scope_hosts=list(scope_hosts),
                      allow_private=allow_private)

    login = data["login"]
    _keys(login, {"url", "username_field", "password_field"}, "login", {"url"})
    scope.login_url = scope.require(_url(login["url"], "login.url"))
    for key in ("username_field", "password_field"):
        if key in login:
            value = login[key]
            if not isinstance(value, str) or not FIELD_NAME.fullmatch(value):
                raise AuthorizationError(tr("login.{key} is not a valid form field name", key=key))
            setattr(scope, key, value)

    if "logout" in data:
        logout = data["logout"]
        _keys(logout, {"url", "method"}, "logout", {"url"})
        scope.logout_url = scope.require(_url(logout["url"], "logout.url"))
        method = logout.get("method", "GET")
        if method not in ("GET", "POST"):
            raise AuthorizationError(tr("logout.method must be GET or POST"))
        scope.logout_method = method

    roles = data["roles"]
    if not isinstance(roles, dict) or not 1 <= len(roles) <= MAX_ROLES:
        raise AuthorizationError(tr("roles must be an object with 1 to {limit} roles", limit=MAX_ROLES))
    for name, role in roles.items():
        if not IDENT.fullmatch(name):
            raise AuthorizationError(tr("Invalid role name: {name}", name=name[:64]))
        _keys(role, {"protected_urls"}, tr("role {name}", name=name))
        urls = role.get("protected_urls", [])
        if not isinstance(urls, list) or len(urls) > MAX_URLS_PER_ROLE:
            raise AuthorizationError(tr("protected_urls of role {name} must be a list of at most {limit} URLs",
                                        name=name, limit=MAX_URLS_PER_ROLE))
        scope.roles[name] = [scope.require(_url(u, "protected_urls")) for u in urls]

    accounts = data["accounts"]
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= MAX_ACCOUNTS:
        raise AuthorizationError(tr("accounts must be a list of 1 to {limit} test accounts", limit=MAX_ACCOUNTS))
    for raw in accounts:
        _keys(raw, {"id", "role", "username_env", "password_env"}, tr("an account"),
              {"id", "role", "username_env", "password_env"})
        if not isinstance(raw["id"], str) or not IDENT.fullmatch(raw["id"]):
            raise AuthorizationError(tr("Invalid account id"))
        if raw["role"] not in scope.roles:
            raise AuthorizationError(tr("Account {account} uses an undefined role", account=raw["id"]))
        for key in ("username_env", "password_env"):
            if not isinstance(raw[key], str) or not ENV_NAME.fullmatch(raw[key]):
                raise AuthorizationError(tr("{key} of account {account} must be an environment variable name "
                                            "(A-Z, 0-9, _), never a credential", key=key, account=raw["id"]))
        if raw["username_env"] == raw["password_env"]:
            raise AuthorizationError(tr("Account {account} uses the same variable for username and password",
                                        account=raw["id"]))
        if any(a.id == raw["id"] for a in scope.accounts):
            raise AuthorizationError(tr("Duplicate account id: {account}", account=raw["id"]))
        scope.accounts.append(Account(raw["id"], raw["role"], raw["username_env"], raw["password_env"]))

    limits = data.get("limits", {})
    _keys(limits, {"max_requests", "max_login_attempts", "lockout_check", "lockout_account"}, "limits")
    scope.max_requests = _int(limits.get("max_requests", DEFAULT_MAX_REQUESTS), "limits.max_requests",
                              10, MAX_REQUESTS_CAP)
    scope.max_login_attempts = _int(limits.get("max_login_attempts", DEFAULT_LOGIN_ATTEMPTS),
                                    "limits.max_login_attempts", 1, LOGIN_ATTEMPTS_CAP)
    scope.lockout_check = _bool(limits.get("lockout_check", False), "limits.lockout_check")
    if scope.lockout_check:
        account = limits.get("lockout_account")
        if not any(a.id == account for a in scope.accounts):
            raise AuthorizationError(tr("limits.lockout_account must name one of the test accounts"))
        scope.lockout_account = account
    elif "lockout_account" in limits:
        raise AuthorizationError(tr("limits.lockout_account requires lockout_check: true"))

    window = data["window"]
    _keys(window, {"not_before", "not_after"}, "window", {"not_before", "not_after"})
    scope.not_before = _when(window["not_before"], "window.not_before")
    scope.not_after = _when(window["not_after"], "window.not_after")
    if scope.not_after <= scope.not_before:
        raise AuthorizationError(tr("window.not_after must be later than window.not_before"))
    if scope.not_after - scope.not_before > MAX_WINDOW:
        raise AuthorizationError(tr("The authorized window cannot exceed {days} days", days=MAX_WINDOW.days))
    return scope


def load(path, now=None, environ=None, check_env=True):
    """Read, validate and check an authorization file: format, time window and (by default)
    that every account's environment variables are set. Raises ``AuthorizationError``."""
    if not path:
        raise AuthorizationError(tr("An authorization file is required for authenticated tests"))
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_SIZE + 1)
    except OSError as exc:
        raise AuthorizationError(tr("Cannot read the authorization file: {error}",
                                    error=exc.strerror or type(exc).__name__)) from None
    if len(raw) > MAX_FILE_SIZE:
        raise AuthorizationError(tr("The authorization file is too large"))
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError(tr("The authorization file is not valid JSON: {error}",
                                    error=getattr(exc, "msg", type(exc).__name__))) from None
    scope = parse_config(data, path)
    scope.check_window(now)
    if check_env:
        for account in scope.accounts:
            account.credentials(environ)
    return scope
