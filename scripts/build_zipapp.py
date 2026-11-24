#!/usr/bin/env python3
"""Build a single-file ``domaininfo.pyz`` with the standard-library ``zipapp`` module.

    python scripts/build_zipapp.py                 # -> dist/domaininfo.pyz
    python scripts/build_zipapp.py -o out/di.pyz
    python dist/domaininfo.pyz --version

The archive contains every top-level Python module of the project (the stdlib core, the Spanish
catalogs and the optional Security Center modules), the word lists and, when it has been built,
the web UI in ``webui/dist`` (``server.load_webui`` reads it from inside the archive). FastAPI and
uvicorn are not bundled: ``--serve`` still needs ``pip install fastapi uvicorn``.
"""

import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import zipapp

ROOT = Path(__file__).resolve().parents[1]
DATA_DIRS = ("wordlists",)
SKIP = {"setup.py", "conftest.py"}


def collect(staging):
    modules = sorted(p for p in ROOT.glob("*.py") if p.name not in SKIP)
    for path in modules:
        shutil.copy2(path, staging / path.name)
    for name in DATA_DIRS:
        if (ROOT / name).is_dir():
            shutil.copytree(ROOT / name, staging / name)
    webui = ROOT / "webui" / "dist"
    if (webui / "index.html").is_file():
        shutil.copytree(webui, staging / "webui" / "dist")
    else:
        print("warning: webui/dist is not built; the Security Center will show a placeholder page "
              "(run npm run build in webui/)", file=sys.stderr)
    return [p.name for p in modules]


def build(output, interpreter="/usr/bin/env python3"):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        staging = Path(folder) / "app"
        staging.mkdir()
        modules = collect(staging)
        if "domaininfo.py" not in modules:
            raise SystemExit("domaininfo.py not found in " + str(ROOT))
        zipapp.create_archive(staging, output, interpreter=interpreter, main="domaininfo:entry",
                              compressed=True, filter=lambda p: "__pycache__" not in p.parts)
    return output


def main(argv=None):
    cli = argparse.ArgumentParser(description="Build dist/domaininfo.pyz (single-file, cross-platform)")
    cli.add_argument("-o", "--output", default=str(ROOT / "dist" / "domaininfo.pyz"))
    cli.add_argument("--python", default="/usr/bin/env python3", help="shebang interpreter line")
    args = cli.parse_args(argv)
    path = build(args.output, args.python)
    print(f"{path} ({path.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
