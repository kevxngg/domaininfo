"""Catálogo de herramientas externas opcionales: detección, versión y compatibilidad.

Fase 1 solo detecta. Nunca descarga ni instala nada, nunca usa una shell y cada comprobación
de versión tiene un tiempo máximo. Si una herramienta falta, DomainInfo sigue funcionando y la
marca como desactivada. Los ejecutores llegarán en la Fase 3 (ver docs/V6_DESIGN.md).
"""

from concurrent.futures import ThreadPoolExecutor
import os
import re
import shutil
import subprocess  # nosec B404

# nombre: (ejecutables posibles, argumentos de versión, versión mínima, categoría, instalación)
CATALOG = {
    "nmap": (("nmap",), ("--version",), "7.80", "reconocimiento", "https://nmap.org/download · apt install nmap"),
    "subfinder": (("subfinder",), ("-version",), "2.6", "reconocimiento",
                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "amass": (("amass",), ("-version",), "4.0", "reconocimiento", "https://github.com/owasp-amass/amass"),
    "dnsx": (("dnsx",), ("-version",), "1.2", "reconocimiento",
             "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "httpx": (("httpx-pd", "httpx"), ("-version",), "1.6", "reconocimiento",
              "go install github.com/projectdiscovery/httpx/cmd/httpx@latest (no confundir con httpx de Python)"),
    "whatweb": (("whatweb",), ("--version",), "0.5", "reconocimiento", "apt install whatweb"),
    "zap": (("zap.sh", "zap.bat", "zaproxy"), ("-version",), "2.14", "web", "https://www.zaproxy.org/download/"),
    "nuclei": (("nuclei",), ("-version",), "3.0", "web",
               "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "playwright": (("playwright",), ("--version",), "1.40", "web", "pip install playwright && playwright install chromium"),
    "sslyze": (("sslyze",), ("--help",), "5.0", "web", "pip install sslyze"),
    "testssl.sh": (("testssl.sh", "testssl"), ("--version",), "3.0", "web", "https://testssl.sh/"),
    "semgrep": (("semgrep",), ("--version",), "1.0", "código", "pip install semgrep"),
    "bandit": (("bandit",), ("--version",), "1.7", "código", "pip install bandit"),
    "pip-audit": (("pip-audit",), ("--version",), "2.6", "código", "pip install pip-audit"),
    "trivy": (("trivy",), ("--version",), "0.45", "código", "https://aquasecurity.github.io/trivy/"),
    "gitleaks": (("gitleaks",), ("version",), "8.0", "código", "https://github.com/gitleaks/gitleaks"),
}
_VERSION = re.compile(r"\bv?(\d+\.\d+(?:\.\d+)?)")


def _in_cwd(path):
    """En Windows, shutil.which (Python < 3.12) busca primero en la carpeta actual: un binario
    plantado ahí no se ejecuta nunca."""
    return os.path.normcase(os.path.dirname(os.path.abspath(path))) == os.path.normcase(os.getcwd())


def _tuple(text):
    return tuple(int(part) for part in text.split("."))


def detect(name, timeout=5):
    """Disponibilidad, ruta, versión y compatibilidad de una herramienta del catálogo."""
    executables, version_args, minimum, category, install = CATALOG[name]
    info = {"name": name, "category": category, "available": False, "minimum": minimum, "install": install}
    path = next((found for found in map(shutil.which, executables) if found and not _in_cwd(found)), None)
    if not path:
        info["reason"] = "no instalada: módulo desactivado"
        return info
    info.update(available=True, path=path)
    try:
        # Ruta obtenida con which y argumentos fijos del catálogo: nada procede del objetivo auditado.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [path, *version_args], capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
        match = _VERSION.search((result.stdout or "") + "\n" + (result.stderr or ""))
    except (OSError, subprocess.SubprocessError) as exc:
        info["error"] = f"no se pudo leer la versión: {exc}"
        info["compatible"] = None
        return info
    info["version"] = match.group(1) if match else None
    info["compatible"] = _tuple(info["version"]) >= _tuple(minimum) if info["version"] else None
    return info


def detect_all(timeout=5):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(CATALOG, pool.map(lambda name: detect(name, timeout), CATALOG), strict=True))
