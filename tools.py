"""Catalog of optional external tools: detection, version and compatibility.

Phase 1 only detects. It never downloads or installs anything, never uses a shell, and every
version check has a time limit. When a tool is missing, DomainInfo keeps working and marks it
as disabled. The runners arrive in Phase 3 (see docs/V6_DESIGN.md).
"""

from concurrent.futures import ThreadPoolExecutor
import os
import re
import shutil
import subprocess  # nosec B404

from i18n import tr

# name: (possible executables, version arguments, minimum version, category, installation)
CATALOG = {
    "nmap": (("nmap",), ("--version",), "7.80", "recon", "https://nmap.org/download · apt install nmap"),
    "subfinder": (("subfinder",), ("-version",), "2.6", "recon",
                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "amass": (("amass",), ("-version",), "4.0", "recon", "https://github.com/owasp-amass/amass"),
    "dnsx": (("dnsx",), ("-version",), "1.2", "recon",
             "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "httpx": (("httpx-pd", "httpx"), ("-version",), "1.6", "recon",
              "go install github.com/projectdiscovery/httpx/cmd/httpx@latest (not the Python httpx)"),
    "whatweb": (("whatweb",), ("--version",), "0.5", "recon", "apt install whatweb"),
    "zap": (("zap.sh", "zap.bat", "zaproxy"), ("-version",), "2.14", "web", "https://www.zaproxy.org/download/"),
    "nuclei": (("nuclei",), ("-version",), "3.0", "web",
               "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "playwright": (("playwright",), ("--version",), "1.40", "web", "pip install playwright && playwright install chromium"),
    "sslyze": (("sslyze",), ("--help",), "5.0", "web", "pip install sslyze"),
    "testssl.sh": (("testssl.sh", "testssl"), ("--version",), "3.0", "web", "https://testssl.sh/"),
    "semgrep": (("semgrep",), ("--version",), "1.0", "code", "pip install semgrep"),
    "bandit": (("bandit",), ("--version",), "1.7", "code", "pip install bandit"),
    "pip-audit": (("pip-audit",), ("--version",), "2.6", "code", "pip install pip-audit"),
    "trivy": (("trivy",), ("--version",), "0.45", "code", "https://aquasecurity.github.io/trivy/"),
    "gitleaks": (("gitleaks",), ("version",), "8.0", "code", "https://github.com/gitleaks/gitleaks"),
}
_VERSION = re.compile(r"\bv?(\d+\.\d+(?:\.\d+)?)")


def _in_cwd(path):
    """On Windows, shutil.which (Python < 3.12) looks in the current folder first: a binary
    planted there is never run."""
    return os.path.normcase(os.path.dirname(os.path.abspath(path))) == os.path.normcase(os.getcwd())


def _tuple(text):
    return tuple(int(part) for part in text.split("."))


def detect(name, timeout=5):
    """Availability, path, version and compatibility of a catalog tool."""
    executables, version_args, minimum, category, install = CATALOG[name]
    info = {"name": name, "category": category, "available": False, "minimum": minimum, "install": install}
    path = next((found for found in map(shutil.which, executables) if found and not _in_cwd(found)), None)
    if not path:
        info["reason"] = tr("not installed: module disabled")
        return info
    info.update(available=True, path=path)
    try:
        # Path from which() and fixed catalog arguments: nothing comes from the audited target.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [path, *version_args], capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
        match = _VERSION.search((result.stdout or "") + "\n" + (result.stderr or ""))
    except (OSError, subprocess.SubprocessError) as exc:
        info["error"] = tr("could not read the version: {error}", error=exc)
        info["compatible"] = None
        return info
    info["version"] = match.group(1) if match else None
    info["compatible"] = _tuple(info["version"]) >= _tuple(minimum) if info["version"] else None
    return info


def detect_all(timeout=5):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(CATALOG, pool.map(lambda name: detect(name, timeout), CATALOG), strict=True))
