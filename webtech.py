"""Website fingerprint: technologies, graded security headers, cookies, redirects,
security.txt, robots.txt and the favicon hash (to look it up on Shodan).

Header checks carry a stable ``id`` and a ``state`` of ``ok``, ``missing`` or ``warning``;
``text`` is written in the active language.
"""

import base64
import html
import re
from urllib import error, parse, request

from i18n import tr

# (name, category, where to look, pattern)
RULES = (
    ("Cloudflare", "CDN", "header", r"^cf-ray:|^server: cloudflare"),
    ("Akamai", "CDN", "header", r"^x-akamai|^server: akamai"),
    ("Fastly", "CDN", "header", r"^x-fastly|^x-served-by: cache-"),
    ("Amazon CloudFront", "CDN", "header", r"^x-amz-cf-id:|^via: .*cloudfront"),
    ("Vercel", "Hosting", "header", r"^x-vercel-id:|^server: vercel"),
    ("Netlify", "Hosting", "header", r"^x-nf-request-id:|^server: netlify"),
    ("GitHub Pages", "Hosting", "header", r"^server: github\.com"),
    ("Nginx", "Web server", "header", r"^server: nginx"),
    ("Apache", "Web server", "header", r"^server: apache"),
    ("Microsoft IIS", "Web server", "header", r"^server: microsoft-iis"),
    ("LiteSpeed", "Web server", "header", r"^server: litespeed"),
    ("Caddy", "Web server", "header", r"^server: caddy"),
    ("PHP", "Language", "header", r"^x-powered-by: php|phpsessid"),
    ("ASP.NET", "Framework", "header", r"^x-aspnet-version:|^x-powered-by: asp\.net|asp\.net_sessionid"),
    ("Express", "Framework", "header", r"^x-powered-by: express"),
    ("WordPress", "CMS", "body", r"/wp-content/|/wp-includes/|<meta name=\"generator\" content=\"wordpress"),
    ("Drupal", "CMS", "body", r"drupal-settings-json|/sites/default/files/|content=\"drupal"),
    ("Joomla", "CMS", "body", r"/media/jui/|content=\"joomla"),
    ("Shopify", "E-commerce", "body", r"cdn\.shopify\.com|shopify\.theme"),
    ("WooCommerce", "E-commerce", "body", r"woocommerce"),
    ("Magento", "E-commerce", "body", r"mage/cookies|magento"),
    ("Wix", "Site builder", "body", r"static\.wixstatic\.com|x-wix-"),
    ("Squarespace", "Site builder", "body", r"squarespace\.com"),
    ("Next.js", "JS framework", "body", r"__next_data__|/_next/static/"),
    ("Nuxt", "JS framework", "body", r"__nuxt|/_nuxt/"),
    ("React", "JS library", "body", r"data-reactroot|react-dom"),
    ("Vue.js", "JS library", "body", r"data-v-[0-9a-f]{6}|vue(\.min)?\.js"),
    ("Angular", "JS framework", "body", r"ng-version=|angular(\.min)?\.js"),
    ("jQuery", "JS library", "body", r"jquery[.-]?[0-9.]*(\.min)?\.js"),
    ("Bootstrap", "CSS", "body", r"bootstrap(\.min)?\.(css|js)"),
    ("Tailwind CSS", "CSS", "body", r"tailwind"),
    ("Google Analytics", "Analytics", "body", r"googletagmanager\.com/gtag|google-analytics\.com"),
    ("Google Tag Manager", "Analytics", "body", r"googletagmanager\.com/gtm\.js"),
    ("Meta Pixel", "Analytics", "body", r"connect\.facebook\.net/.*/fbevents\.js"),
    ("Hotjar", "Analytics", "body", r"static\.hotjar\.com"),
    ("reCAPTCHA", "Security", "body", r"google\.com/recaptcha"),
    ("hCaptcha", "Security", "body", r"hcaptcha\.com"),
    ("Cloudflare Turnstile", "Security", "body", r"challenges\.cloudflare\.com/turnstile"),
)
VERSION_LEAK = re.compile(r"\d+\.\d+")


def murmur3_32(data, seed=0):
    """Signed 32-bit MurmurHash3 x86 (the one Shodan uses for http.favicon.hash)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h = seed & 0xFFFFFFFF
    rounded = length - (length % 4)
    for i in range(0, rounded, 4):
        k = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    k = 0
    tail = length & 3
    if tail == 3:
        k ^= data[rounded + 2] << 16
    if tail >= 2:
        k ^= data[rounded + 1] << 8
    if tail >= 1:
        k ^= data[rounded]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(data):
    """Same as Shodan: mmh3 of the base64 favicon with a line break every 76 characters."""
    return murmur3_32(base64.encodebytes(data))


class _Recorder(request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status": code, "location": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, timeout, limit, user_agent, recorder=None):
    handlers = [recorder] if recorder else []
    opener = request.build_opener(*handlers)
    req = request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    try:
        response = opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    with response:
        return response.status, response.geturl(), response.headers, response.read(limit)


def grade_headers(headers, https):
    """headers: lowercase dict. Returns an A–F grade, points and checks."""
    checks, points = [], 0
    hsts = headers.get("strict-transport-security", "")
    if https:
        age = re.search(r"max-age=(\d+)", hsts)
        if age and int(age.group(1)) >= 15552000:
            points += 25
            checks.append(("hsts", "ok", tr("HSTS of at least 6 months with preload") if "preload" in hsts
                           else tr("HSTS of at least 6 months")))
        elif hsts:
            points += 10
            checks.append(("hsts", "warning", tr("Short HSTS duration (less than 6 months)")))
        else:
            checks.append(("hsts", "missing", tr("No HSTS: the browser could use unencrypted HTTP")))
    else:
        checks.append(("https", "missing", tr("The site does not use HTTPS")))
    csp = headers.get("content-security-policy", "")
    if csp:
        points += 25 if "unsafe-inline" not in csp else 15
        checks.append(("csp", "ok", tr("CSP present")) if "unsafe-inline" not in csp
                      else ("csp", "warning", tr("CSP present but allows 'unsafe-inline'")))
    else:
        checks.append(("csp", "missing", tr("No Content-Security-Policy: more exposed to XSS")))
    if "x-frame-options" in headers or "frame-ancestors" in csp:
        points += 15
        checks.append(("clickjacking", "ok", tr("Clickjacking protection")))
    else:
        checks.append(("clickjacking", "missing", tr("No X-Frame-Options or frame-ancestors: clickjacking possible")))
    if headers.get("x-content-type-options", "").lower() == "nosniff":
        points += 10
        checks.append(("nosniff", "ok", "X-Content-Type-Options: nosniff"))
    else:
        checks.append(("nosniff", "missing", tr("No X-Content-Type-Options: nosniff")))
    if "referrer-policy" in headers:
        points += 10
        checks.append(("referrer", "ok", tr("Referrer-Policy set")))
    else:
        checks.append(("referrer", "missing", tr("No Referrer-Policy")))
    if "permissions-policy" in headers:
        points += 10
        checks.append(("permissions", "ok", tr("Permissions-Policy set")))
    else:
        checks.append(("permissions", "missing", tr("No Permissions-Policy")))
    if "cross-origin-opener-policy" in headers:
        points += 5
    leaks = [f"{name}: {headers[name]}" for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
             if name in headers and VERSION_LEAK.search(headers[name])]
    for leak in leaks:
        points -= 5
        checks.append(("version", "warning", tr("Reveals the software version: {header}", header=leak)))
    points = max(0, min(100, points))
    letter = "A" if points >= 85 else "B" if points >= 70 else "C" if points >= 55 else "D" if points >= 40 else "F"
    return {"grade": letter, "points": points, "checks": [{"id": i, "state": s, "text": t} for i, s, t in checks],
            "version_leaks": leaks}


def analyze_cookies(raw_cookies, https):
    rows = []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        issues = []
        if https and "secure" not in lower:
            issues.append(tr("no Secure"))
        if "httponly" not in lower:
            issues.append(tr("no HttpOnly"))
        if "samesite" not in lower:
            issues.append(tr("no SameSite"))
        rows.append({"name": name, "issues": issues})
    return rows


def detect(headers, body):
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    body_text = body.lower()
    found = []
    for name, category, where, pattern in RULES:
        text = header_text if where == "header" else body_text
        if re.search(pattern, text, re.M):
            found.append({"name": name, "category": category})
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    return found, html.unescape(generator.group(1)) if generator else None


def audit(base_url, timeout, user_agent):
    recorder = _Recorder()
    status, final, headers, body = _get(base_url, timeout, 1024 * 1024, user_agent, recorder)
    lower = {k.lower(): v for k, v in headers.items()}
    text = body.decode("utf-8", "replace")
    https = parse.urlsplit(final).scheme == "https"
    tech, generator = detect(lower, text)
    result = {"url": final, "status": status, "redirects": recorder.chain, "technologies": tech,
              "generator": generator, "headers_grade": grade_headers(lower, https),
              "cookies": analyze_cookies(headers.get_all("Set-Cookie") or [], https)}
    root = f"{parse.urlsplit(final).scheme}://{parse.urlsplit(final).netloc}"
    icon = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)', text, re.I)
    icon_url = parse.urljoin(final, html.unescape(icon.group(1))) if icon else root + "/favicon.ico"
    try:
        icon_status, _, _, icon_data = _get(icon_url, timeout, 512 * 1024, user_agent)
        if icon_status == 200 and icon_data:
            value = favicon_hash(icon_data)
            result["favicon"] = {"url": icon_url, "mmh3": value, "shodan": f"http.favicon.hash:{value}"}
    except (OSError, ValueError):
        pass
    try:
        sec_status, _, _, sec_body = _get(root + "/.well-known/security.txt", timeout, 64 * 1024, user_agent)
        sec_text = sec_body.decode("utf-8", "replace")
        result["security_txt"] = sec_status == 200 and "contact:" in sec_text.lower()
    except (OSError, ValueError):
        result["security_txt"] = None
    try:
        rob_status, _, _, rob_body = _get(root + "/robots.txt", timeout, 256 * 1024, user_agent)
        if rob_status == 200:
            rob = rob_body.decode("utf-8", "replace")
            result["robots"] = {"disallow": len(re.findall(r"^\s*disallow:\s*\S", rob, re.I | re.M)),
                                "sitemaps": re.findall(r"^\s*sitemap:\s*(\S+)", rob, re.I | re.M)[:5]}
    except (OSError, ValueError):
        pass
    return result
