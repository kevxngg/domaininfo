"""Guided terminal interface for DomainInfo. Kevin (@kevxngg).

Standard library only; numbered navigation also works in Android terminals.
Every label below is English source text and is translated with ``tr()`` when it is shown,
so changing the language in Preferences takes effect on the next screen.
"""

import argparse
from copy import deepcopy
from dataclasses import dataclass
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap
from urllib.parse import urlsplit
import webbrowser

import i18n
from i18n import tr


MODE_LABELS = {
    "quick": ("Quick analysis", "Resolve IPs and look up the domain registration"),
    "web": ("Website and certificate", "HTTP, security headers and TLS connection"),
    "ports": ("TCP ports", "Check which services are reachable from your computer"),
    "full": ("Full diagnostics", "Everything: DNS, registration, network, web, TLS, mail, subdomains and ports"),
    "mail": ("Domain mail", "SPF, DMARC, DKIM and MTA-STS: can the domain be spoofed?"),
    "recon": ("OSINT reconnaissance", "Subdomains, network (ASN), technologies and domain history"),
    "brand": ("Brand and phishing", "Registered lookalike domains that could imitate yours"),
    "mikrotik": ("MikroTik / RouterOS", "Version, management services and applicable advisories"),
    "webapp": ("Web application security", "One specific URL: forms, CSRF, cookies, CSP, CORS and errors"),
}
MODE_KEYS = {"1": "quick", "2": "web", "3": "ports", "4": "full", "5": "mikrotik",
             "e": "mail", "s": "recon", "p": "brand", "w": "webapp"}
STATUS_LABELS = {"confirmed": "CONFIRMED", "likely": "LIKELY", "informational": "INFO",
                 "pending": "PENDING VERIFICATION", "not_applicable": "NOT APPLICABLE",
                 "not_evaluated": "NOT EVALUATED", "error": "ERROR"}
CSRF_LABELS = {"token_visible": "token visible", "token_in_meta": "token in <meta> (check that it is sent)",
               "alternative_protection": "no token; SameSite cookies", "unknown": "no visible protection "
               "(pending verification)", "not_applicable": "not applicable (GET)"}
MODULE_LABELS = {"dns": "Address resolution", "rdap": "RDAP registration",
                 "http": "Website and HTTP headers", "tls": "TLS certificate",
                 "ports": "TCP services", "traceroute": "Network route",
                 "mikrotik": "RouterOS audit", "asn": "Network and operator (ASN)",
                 "mail": "Mail security", "tech": "Technologies and headers",
                 "subdomains": "Subdomains", "history": "Domain history",
                 "lookalike": "Lookalike domains", "webapp": "Web application security"}
MODULE_HELP = {
    "dns": "IPv4/IPv6 addresses the system returns for the target.",
    "rdap": "Public registration data of the domain or of the IP address block.",
    "http": "Page response and headers that state the site's security policies.",
    "tls": "Negotiated encrypted protocol and certificate validated by Python.",
    "ports": "TCP services that answered from this computer during the review.",
    "traceroute": "Network hops reported by the system's route tool.",
    "mikrotik": "Comparison of the RouterOS version with the advisories of the dated catalog.",
    "asn": "Autonomous system, network block, country, operator and reverse name of each IP.",
    "mail": "SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI: whether someone can send fake mail on behalf of the domain.",
    "tech": "Detected technologies, security header grade, cookies, favicon and security.txt.",
    "subdomains": "Subdomains published in certificate logs and subdomains that could be taken over.",
    "history": "Registration age and expiry, registrar and Wayback Machine captures.",
    "lookalike": "Name variants (typos, homoglyphs, other TLDs) that are registered.",
    "webapp": "Passive analysis of the requested URL (GET only): forms, CSRF, cookies, headers, CORS, "
              "technical errors and exposed data, compared with the site root.",
}
SEVERITY_COLORS = {"high": "1;31", "medium": "33", "low": "36", "info": "90"}
SEVERITY_LABELS = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
ADVISORY_LABELS = {"potentially_affected": "REVIEW: version included in the advisory",
                   "not_in_affected_range": "Version outside the affected range",
                   "unknown_version": "NOT EVALUATED: the version is missing",
                   "manual_review": "NO CONCLUSION: review the version manually"}
# Header checks from the tech module; the Spanish 5.x states are kept for old saved reports.
CHECK_MARKS = {"ok": ("[OK]", "32"), "warning": ("[WARNING]", "33"), "missing": ("[MISSING]", "33"),
               "aviso": ("[WARNING]", "33"), "falta": ("[MISSING]", "33")}
LANGUAGE_NAMES = {"en": "English", "es": "Español"}
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")

# Original ASCII letterforms; no figlet executable, font downloads or pip needed.
LOGO_FONT = {
    "D": (" ____  ", "|  _ \\ ", "| | | |", "| |_| |", "|____/ "),
    "o": ("       ", "  ___  ", " / _ \\ ", "| (_) |", " \\___/ "),
    "m": ("            ", " _ __ ___   ", "| '_ ` _ \\  ", "| | | | | | ", "|_| |_| |_| "),
    "a": ("       ", "  __ _ ", " / _` |", "| (_| |", " \\__,_|"),
    "i": (" _ ", "(_)", "| |", "| |", "|_|"),
    "n": ("       ", " _ __  ", "| '_ \\ ", "| | | |", "|_| |_|"),
    "I": (" ___ ", "|_ _|", " | | ", " | | ", "|___|"),
    "f": ("  __ ", " / _|", "| |_ ", "|  _|", "|_|  "),
}
MINI_FONT = {
    "D": (" _ ", "| \\", "|_/"), "O": (" _ ", "/ \\", "\\_/"),
    "M": ("   ", "|V|", "| |"), "A": (" _ ", "/_\\", "| |"),
    "I": ("_", "|", "_"), "N": ("   ", "|\\|", "| |"),
    "F": (" _ ", "|_ ", "|  "),
}


def logo_lines(available):
    large = ["".join(LOGO_FONT[letter][row] for letter in "DomainInfo").rstrip() for row in range(5)]
    if max(map(len, large)) <= available:
        return large
    words = ("DOMAININFO",) if available >= 35 else ("DOMAIN", "INFO")
    return [" ".join(MINI_FONT[letter][row] for letter in word).rstrip()
            for word in words for row in range(3)]


def safe_text(value):
    """Remote titles/errors and saved reports must not control the terminal."""
    text = ANSI.sub("", str(value))
    return "".join(char if char.isprintable() or char == "\n" else " " for char in text)


def mode_label(mode):
    return tr(MODE_LABELS[mode][0]) if mode in MODE_LABELS else str(mode)


def module_label(name):
    return tr(MODULE_LABELS[name]) if name in MODULE_LABELS else str(name)


def severity_label(level):
    return tr(SEVERITY_LABELS[level]) if level in SEVERITY_LABELS else str(level).upper()


def severity_color(level):
    return SEVERITY_COLORS.get(level, "90")


def status_label(status):
    return tr(STATUS_LABELS[status]) if status in STATUS_LABELS else str(status).upper()


COMMON_SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
                   135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 587: "submission", 993: "imaps", 995: "pop3s",
                   2000: "winbox-bw", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
                   8080: "http-alt", 8291: "winbox", 8443: "https-alt", 8728: "api", 8729: "api-ssl"}


def service_label(port):
    """'22 (ssh)'; the name is the usual one for that port, not a detected service."""
    name = COMMON_SERVICES.get(port)
    return f"{port} ({name})" if name else str(port)


class Back(Exception):
    pass


@dataclass
class Plan:
    args: argparse.Namespace
    targets: list
    batch: bool = False
    ignored: int = 0


class InteractiveApp:
    def __init__(self, core, defaults, input_fn=None, output=None):
        self.core = core
        self.defaults = deepcopy(defaults)
        self.read = input_fn or input
        self.out = output or sys.stdout
        self.tty = bool(getattr(self.out, "isatty", lambda: False)())
        self.color = self.tty and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        if self.color and os.name == "nt":
            # Enable ANSI on the current console only, without changing terminal settings globally.
            try:
                import ctypes
                kernel = ctypes.windll.kernel32
                handle = kernel.GetStdHandle(-11)
                mode = ctypes.c_ulong()
                self.color = bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and
                                  kernel.SetConsoleMode(handle, mode.value | 4))
            except (AttributeError, OSError):
                self.color = False
        self.history = []
        self.last_target = ""
        self.at_home = False
        # Single-key menus in a real terminal; DOMAININFO_ENTER=1 keeps NUMBER + ENTER.
        self.instant = (input_fn is None and self.tty and sys.stdin.isatty()
                        and not os.environ.get("DOMAININFO_ENTER"))

    @property
    def width(self):
        return max(32, min(shutil.get_terminal_size((80, 24)).columns, 90))

    def style(self, value, color="36"):
        return f"\033[{color}m{value}\033[0m" if self.color else value

    def line(self, text="", color=None):
        cleaned = safe_text(text)
        for part in cleaned.split("\n"):
            for wrapped in textwrap.wrap(part, self.width - 4, replace_whitespace=False) or [""]:
                print("  " + (self.style(wrapped, color) if color else wrapped), file=self.out)

    def center(self, text, color="90"):
        text = safe_text(text)
        self.line(text.center(self.width - 4), color)

    def frame(self, title, rows, width=None, accent="36", descriptions=True):
        """Return styled lines of a panel; geometry never counts ANSI bytes."""
        width = width or self.width - 4
        inner = width - 4
        heading = (" " + safe_text(title) + " ")[:width - 4]
        result = [self.style("╭─" + heading + "─" * (width - 3 - len(heading)) + "╮", accent)]
        for row in rows:
            if len(row) == 2:
                text, color = row
                chunks = textwrap.wrap(safe_text(text), inner) or [""]
                for chunk in chunks:
                    result.append(self.style("│ ", accent) + self.style(chunk.ljust(inner), color)
                                  + self.style(" │", accent))
            else:
                key, label, description = row
                text = f"[{key}] {label}"
                for chunk in textwrap.wrap(safe_text(text), inner) or [""]:
                    result.append(self.style("│ ", accent) + self.style(chunk.ljust(inner), "1;37")
                                  + self.style(" │", accent))
                if descriptions and description:
                    for chunk in textwrap.wrap(safe_text(description), inner - 4):
                        result.append(self.style("│ ", accent) + self.style(("    " + chunk).ljust(inner), "90")
                                      + self.style(" │", accent))
        result.append(self.style("╰" + "─" * (width - 2) + "╯", accent))
        return result

    def panel(self, title, rows, accent="36"):
        for row in self.frame(title, rows, accent=accent):
            print("  " + row, file=self.out)

    def home(self):
        self.screen(tr("MAIN MENU"), home=True)
        audit = [(key, mode_label(mode),
                  tr({"quick": "DNS + domain registration", "web": "HTTP + headers + TLS",
                      "ports": "Reachable TCP services", "full": "All general modules",
                      "mikrotik": "Router on the network or offline version", "mail": "Can the mail be spoofed?",
                      "recon": "Subdomains, network and technologies", "brand": "Domains that imitate yours",
                      "webapp": "Full URL: login, cookies, CSP"}[mode]))
                 for key, mode in MODE_KEYS.items()]
        workspace = [("6", tr("Several targets"), tr("Audit from a file")),
                     ("7", tr("My reports"), tr("Results and exports")),
                     ("8", tr("Preferences"), tr("Connections, timeouts, formats and language")),
                     ("9", tr("Computer diagnostics"), tr("Status of the tools")),
                     ("a", tr("Classic audits"), tr("ISP / WebApp / LAN with Bash"))]
        if self.width >= 78:
            panel_width = (self.width - 6) // 2
            detailed = shutil.get_terminal_size((80, 24)).lines >= 34
            left = self.frame(tr("01 / AUDITS"), audit, panel_width, "36", detailed)
            right = self.frame(tr("02 / TOOLS"), workspace, panel_width, "35", detailed)
            blank = " " * panel_width
            for index in range(max(len(left), len(right))):
                print("  " + (left[index] if index < len(left) else blank) + "  "
                      + (right[index] if index < len(right) else blank), file=self.out)
        else:
            for title, rows, accent in ((tr("AUDITS"), audit, "36"), (tr("TOOLS"), workspace, "35")):
                for row in self.frame(title, rows, accent=accent, descriptions=False):
                    print("  " + row, file=self.out)
        self.line()
        self.panel(tr("NAVIGATION"), [(tr("[h] Quick help     [0] Exit"), "90")], "90")
        if self.instant:
            self.line(tr("Press the option's key to start.") if self.width >= 60
                      else tr("Press a key · 0 to exit"), "90")
        else:
            self.line(tr("Choose a module to start. NUMBER + ENTER") if self.width >= 60
                      else tr("NUMBER + ENTER · 0 to exit"), "90")

    def screen(self, title, subtitle="", home=False):
        self.at_home = home
        if self.color:
            print("\033[2J\033[H", end="", file=self.out)
        print(file=self.out)
        if home:
            art = logo_lines(self.width - 4)
            size = max(map(len, art))
            gradient = ("1;96", "1;36", "36", "1;34", "34", "36")
            for index, row in enumerate(art):
                self.line(row.ljust(size).center(self.width - 4), gradient[index % len(gradient)])
            self.center(tr("DOMAINS / NETWORKS / ROUTEROS"), "90")
            system = "TERMUX" if os.environ.get("TERMUX_VERSION") else platform.system().upper()
            self.center(f"v{self.core.VERSION}  ·  Kevin / @kevxngg" +
                        (f"  ·  {system}" if self.width >= 60 else ""), "90")
            self.line()
        else:
            self.line("DOMAININFO / " + self.core.VERSION, "1;36")
        rows = [(title, "1;37")]
        if subtitle:
            rows.append((subtitle, "90"))
        if not home:
            self.panel(tr("ANALYSIS PANEL"), rows)
            self.line(tr("[0 / r] Back to the previous menu"), "90")
        else:
            self.center(title, "1;37")
        self.line()

    def item(self, key, label, description=""):
        self.line(f"  [{key}]  {label}", "1;36")
        if description:
            self.line("    " + description, "90")

    def ask(self, label, default=None, validator=None, allow_empty=False):
        suffix = f" [{safe_text(default)}]" if default not in (None, "") else ""
        while True:
            parts = textwrap.wrap("> " + safe_text(label) + suffix + ":", self.width - 4)
            for part in parts[:-1]:
                self.line(part)
            self.out.write("  " + self.style(parts[-1], "1;36") + " ")
            self.out.flush()
            value = self.read().strip()
            if not self.tty:
                self.out.write("\n")
            if value.lower() in ("r", "back", "return", "regresar", "volver"):
                if self.at_home:
                    self.line(tr("You are already at the main menu. Use 0 to exit."), "90")
                    continue
                raise Back()
            if value.isascii() and value.isdecimal():
                value = value.lstrip("0") or "0"
            if value == "0":
                raise Back()
            if not value and default is not None:
                value = str(default)
            if not value and allow_empty:
                return ""
            if not value:
                self.line(tr("Type a value or 0 to go back."), "33")
                continue
            try:
                return validator(value) if validator else value
            except (ValueError, UnicodeError, OSError, argparse.ArgumentTypeError) as exc:
                self.line(str(exc), "33")

    @staticmethod
    def read_key():
        """One key press without ENTER; CTRL+C and CTRL+D/Z keep their usual meaning."""
        if os.name == "nt":
            import msvcrt
            key = msvcrt.getwch()
            if key in ("\x00", "\xe0"):  # arrows and function keys send a second code
                msvcrt.getwch()
                return ""
        else:
            import select
            import termios
            import tty
            fd = sys.stdin.fileno()
            saved = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = os.read(fd, 4).decode("utf-8", "ignore")
                if key.startswith("\x1b"):  # escape sequences (arrows): drop the rest
                    while select.select([fd], [], [], 0.02)[0]:
                        os.read(fd, 16)
                    return ""
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            key = key[:1]
        if key == "\x03":
            raise KeyboardInterrupt
        if key in ("\x04", "\x1a"):
            raise EOFError
        return key

    def choose_key(self, keys, label, default):
        hint = f" [{safe_text(default)}]" if default not in (None, "") else ""
        while True:
            self.out.write("  " + self.style(f"> {safe_text(label)}{hint}:", "1;36") + " ")
            self.out.flush()
            key = self.read_key().lower()
            if key in ("\r", "\n"):
                if default is None:
                    self.out.write("\n")
                    continue
                key = str(default)
            self.out.write((key if key.isprintable() else "") + "\n")
            self.out.flush()
            if key == "0":
                raise Back()
            if key == "r":
                if self.at_home:
                    self.line(tr("You are already at the main menu. Use 0 to exit."), "90")
                    continue
                raise Back()
            if key in keys:
                return key
            if key:
                self.line(tr("Invalid option. Press one of the menu keys; 0 to go back."), "33")

    def choose(self, keys, label=None, default=None):
        label = label or tr("Choose an option")
        if self.instant and all(len(key) == 1 for key in keys):
            return self.choose_key(keys, label, default)

        def validate(value):
            value = value.lower()
            if value not in keys:
                raise ValueError(tr("Invalid option. Use the menu numbers; 0 to go back."))
            return value
        return self.ask(label, default, validate)

    def pause(self):
        self.out.write("\n  " + tr("[0 / r] Back · ENTER to continue..."))
        self.out.flush()
        self.read()
        if not self.tty:
            self.out.write("\n")

    def run(self):
        while True:
            try:
                self.home()
                try:
                    choice = self.choose(set(MODE_KEYS) | {"6", "7", "8", "9", "a", "h"})
                except Back:
                    self.line()
                    return 0
                try:
                    if choice in MODE_KEYS:
                        self.wizard(MODE_KEYS[choice])
                    elif choice == "6":
                        self.batch_wizard()
                    elif choice == "7":
                        self.reports()
                    elif choice == "8":
                        self.preferences(self.defaults)
                    elif choice == "9":
                        self.diagnostics()
                    elif choice == "a":
                        self.classic()
                    else:
                        self.help()
                except Back:
                    continue
            except KeyboardInterrupt:
                self.line(tr("Action cancelled. You can choose another option."), "33")
            except EOFError:
                self.line(tr("Session closed."))
                return 0

    def target(self, args):
        if args.mode in self.core.URL_MODES:
            self.line(tr("Full URL with path. Example: https://example.com/login"))
            self.line(tr("Only GET requests are made: no forms or credentials are submitted."), "90")
            raw = self.ask(tr("URL (0 to go back)"), self.last_target or None,
                           validator=lambda value: (value, self.core.normalize_for_mode(value, args.mode)))
            self.last_target = raw[1]
            return raw[1]
        self.line(tr("Accepts a domain, IPv4, IPv6 or URL. Example: 192.168.88.1"))
        raw = self.ask(tr("Target (0 to go back)"), self.last_target or None,
                       validator=lambda value: (value, self.core.normalize_target(value)))
        self.last_target = raw[1]
        if "://" in raw[0]:
            parsed = urlsplit(raw[0])
            self.set_web(args, parsed.scheme.lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        return raw[1]

    def set_web(self, args, scheme, port):
        args.scheme, args.web_port = scheme, port
        if args.mode in ("web", "full"):
            if scheme == "http" and "tls" not in args.skip:
                args.skip.append("tls")
                args.ui_tls_auto_skip = True
            elif scheme == "https" and getattr(args, "ui_tls_auto_skip", False):
                args.skip.remove("tls")
                args.ui_tls_auto_skip = False

    def version(self, required=False, default=None):
        import routeros
        self.line(tr("Version from your inventory. Examples: 7.25, 7.23.8."))
        if not required:
            self.line(tr("ENTER without a version: it will try to detect it from public banners."))
        return self.ask(tr("RouterOS version (0 to go back)"), default,
                        lambda value: routeros.parse_version(value).text,
                        allow_empty=not required) or None

    def fresh_args(self, mode):
        args = deepcopy(self.defaults)
        args.mode = mode
        args.target = None
        args.file = None
        args.offline = False
        args.routeros_version = None
        args.quiet = True
        args.interactive = False
        return args

    def wizard(self, mode):
        args = self.fresh_args(mode)
        if mode == "mikrotik":
            while True:
                self.screen(mode_label(mode), tr("Step 1 · Choose the type of review."))
                self.item("1", tr("Check a router on the network"), tr("Reachable services, banners and advisories by version"))
                self.item("2", tr("Check a version only"), tr("No connection to routers or Internet services"))
                args.offline = self.choose({"1", "2"}, default="1") == "2"
                try:
                    if args.offline:
                        args.routeros_version = self.version(required=True)
                        targets = ["routeros-offline"]
                    else:
                        targets = [self.target(args)]
                        args.routeros_version = self.version()
                except Back:
                    continue
                break
        else:
            self.screen(mode_label(mode), tr("Step 1 · Choose the target."))
            targets = [self.target(args)]
        self.review(Plan(args, targets))

    def read_targets(self, path, mode=None):
        """Valid, de-duplicated targets from a file; webapp keeps the full URLs."""
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        targets, ignored = [], 0
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                normalized = self.core.normalize_for_mode(line, mode or "quick")
                if normalized in targets:
                    ignored += 1
                else:
                    targets.append(normalized)
            except (ValueError, UnicodeError):
                ignored += 1
        if not targets:
            raise ValueError(tr("The file contains no valid targets."))
        return targets, ignored

    def load_batch(self, mode=None):
        def validate(value):
            path = Path(value.strip('"')).expanduser()
            targets, ignored = self.read_targets(path, mode)
            return path, targets, ignored
        self.line(tr("UTF-8 file with one target per line; comments and duplicates are skipped."))
        return self.ask(tr("File path (0 to go back)"), validator=validate)

    def batch_wizard(self):
        self.screen(tr("Several targets"), tr("Step 1 · Load your file. 0 to go back."))
        path, targets, ignored = self.load_batch()
        self.line(tr("{targets} targets ready; {ignored} invalid or duplicate lines skipped.",
                     targets=len(targets), ignored=ignored), "32")
        for key, mode in MODE_KEYS.items():
            self.item(key, mode_label(mode), tr(MODE_LABELS[mode][1]))
        mode = MODE_KEYS[self.choose(MODE_KEYS, tr("Type of audit"), "1")]
        if mode in self.core.URL_MODES:
            try:
                targets, ignored = self.read_targets(path, mode)
            except (OSError, ValueError, UnicodeError) as exc:
                self.line(tr("This file cannot be used in {mode}: {error}", mode=mode_label(mode), error=exc), "33")
                self.pause()
                return
        args = self.fresh_args(mode)
        args.file = path
        if mode == "mikrotik":
            self.line(tr("The version you give applies to every device; leave it empty if they differ."))
            args.routeros_version = self.version()
        self.review(Plan(args, targets, batch=True, ignored=ignored))

    def review(self, plan):
        while True:
            args = plan.args
            self.screen(tr("Ready to review"), tr("Step 2 · Check the options and choose Start."))
            self.line(tr("Audit: {mode}", mode=mode_label(args.mode)), "1;37")
            if args.offline:
                self.line(tr("Target: RouterOS version, no network connections"))
            elif plan.batch:
                self.line(tr("File: {path}", path=args.file))
                self.line(tr("Targets: {count} · skipped/duplicates: {ignored}",
                             count=len(plan.targets), ignored=plan.ignored))
                self.line(tr("Preview: {targets}", targets=", ".join(plan.targets[:4])))
            else:
                self.line(tr("Target: {target}", target=plan.targets[0]))
            if args.mode == "mikrotik":
                self.line(tr("RouterOS: {version}", version=args.routeros_version
                             or tr("detection from banners; it may not be published")))
            self.line(tr("Time per connection: {timeout} s · connections: {threads}",
                         timeout=f"{args.timeout:g}", threads=args.threads))
            if args.mode in ("web", "full", "mikrotik") and not args.offline:
                self.line(tr("Web: {scheme} · port {port}", scheme=args.scheme.upper(),
                             port=args.web_port or tr("default")))
            if args.mode in ("ports", "full", "mikrotik") and not args.offline:
                self.line(tr("TCP ports: {ports}", ports=", ".join(map(str, args.ports)) if args.ports
                             else tr("the mode's recommended list")))
            if args.mode in self.core.URL_MODES:
                extra = getattr(args, "scope", None) or []
                if extra:
                    self.line(tr("Scope: the URL's host + {hosts}; redirects outside it are not followed",
                                 hosts=", ".join(extra)))
                else:
                    self.line(tr("Scope: the URL's host; redirects outside it are not followed"))
                self.line(tr("GET requests only: no forms or credentials are submitted."), "90")
            active = [module_label(name) for name in self.core.MODES[args.mode] if name not in args.skip]
            self.line(tr("Modules: {modules}", modules=", ".join(active) or tr("none selected")))
            if "rdap" in self.core.MODES[args.mode] and "rdap" not in args.skip:
                self.line(tr("RDAP will look up the target's registration through rdap.org."), "90")
            self.line(tr("Reports: {folder} · {format}", folder=args.output, format=args.format.upper()))
            self.line()
            self.item("1", tr("Start audit"))
            self.item("2", tr("Change version") if args.offline else tr("Change file") if plan.batch
                      else tr("Change target"))
            self.item("3", tr("Adjust options for this audit"))
            if args.mode == "mikrotik" and not args.offline:
                self.item("4", tr("Set or change the RouterOS version"))
            self.item("0", tr("Back to the main menu"))
            allowed = {"1", "2", "3"} | ({"4"} if args.mode == "mikrotik" and not args.offline else set())
            choice = self.choose(allowed, default="1")
            if choice == "1":
                if not active:
                    self.line(tr("Enable at least one module from Adjust options."), "33")
                    self.pause()
                    continue
                self.execute(plan)
                return
            elif choice == "2":
                try:
                    if args.offline:
                        args.routeros_version = self.version(True, args.routeros_version)
                    elif plan.batch:
                        args.file, plan.targets, plan.ignored = self.load_batch(args.mode)
                    else:
                        plan.targets = [self.target(args)]
                except Back:
                    continue
            elif choice == "3":
                self.preferences(args, local=True)
            else:
                try:
                    args.routeros_version = self.version()
                except Back:
                    continue

    def preferences(self, args, local=False):
        while True:
            self.screen(tr("Options for this audit") if local else tr("Session preferences"),
                        tr("Changes apply when you go back; 0 to go back."))
            self.item("1", tr("Time per connection: {timeout} seconds", timeout=f"{args.timeout:g}"))
            self.item("2", tr("Simultaneous connections: {threads}", threads=args.threads))
            self.item("3", tr("Reports folder: {folder}", folder=args.output))
            self.item("4", tr("Format: {format}", format=args.format.upper()))
            if local and not args.offline:
                self.item("5", tr("TCP ports: {ports}", ports=", ".join(map(str, args.ports)) if args.ports
                                  else tr("recommended")))
                self.item("6", tr("Web: {scheme} · port {port}", scheme=args.scheme.upper(),
                                  port=args.web_port or tr("default")))
                self.item("7", tr("Choose modules"))
                if args.mode == "mikrotik":
                    self.item("8", tr("SSH port: {port}", port=args.ssh_port))
            if not local:
                self.item("l", tr("Language: {language}", language=LANGUAGE_NAMES[i18n.language()]))
            self.item("d", tr("Restore default values"))
            self.item("0", tr("Save and go back"))
            keys = {"1", "2", "3", "4", "d"}
            if local and not args.offline:
                keys |= {"5", "6", "7"}
                if args.mode == "mikrotik":
                    keys.add("8")
            if not local:
                keys.add("l")
            try:
                choice = self.choose(keys)
            except Back:
                return
            try:
                if choice == "1":
                    args.timeout = self.ask(tr("Seconds (0.1 to 60)"), args.timeout, self.core.timeout_value)
                elif choice == "2":
                    args.threads = self.ask(tr("Connections (1 to 64)"), args.threads, self.core.bounded_int(1, 64))
                elif choice == "3":
                    def directory(value):
                        path = Path(value.strip('"')).expanduser()
                        if path.exists() and not path.is_dir():
                            raise ValueError(tr("That path is a file. Choose a folder."))
                        return path
                    args.output = self.ask(tr("Folder"), str(args.output), directory)
                elif choice == "4":
                    for key, label in (("1", tr("All: HTML + JSON + TXT")), ("2", tr("HTML only")),
                                       ("3", tr("JSON only")), ("4", tr("TXT only"))):
                        self.item(key, label)
                    args.format = {"1": "all", "2": "html", "3": "json", "4": "txt"}[self.choose({"1", "2", "3", "4"})]
                elif choice == "5":
                    self.line(tr("Example: 22,80,443. Type auto for the recommended list."))
                    raw = self.ask(tr("Ports"), validator=lambda value: None if value.lower() == "auto" else self.core.port_list(value))
                    args.ports = raw
                elif choice == "6":
                    self.item("1", tr("HTTPS (encrypted)"))
                    self.item("2", "HTTP")
                    scheme = {"1": "https", "2": "http"}[self.choose({"1", "2"})]
                    port = self.ask(tr("Web port (auto for the default)"), "auto",
                                    lambda value: None if value.lower() == "auto" else self.core.bounded_int(1, 65535)(value))
                    self.set_web(args, scheme, port)
                elif choice == "7":
                    self.module_picker(args)
                elif choice == "8":
                    args.ssh_port = self.ask(tr("SSH port"), args.ssh_port, self.core.bounded_int(1, 65535))
                elif choice == "l":
                    self.item("1", LANGUAGE_NAMES["en"])
                    self.item("2", LANGUAGE_NAMES["es"])
                    current = "2" if i18n.language() == "es" else "1"
                    language = {"1": "en", "2": "es"}[self.choose({"1", "2"}, default=current)]
                    i18n.set_language(language)
                    args.lang = language
                else:
                    clean = self.core.parser().parse_args([])
                    for name in ("timeout", "threads", "output", "format", "ports", "scheme", "web_port", "ssh_port", "skip"):
                        setattr(args, name, deepcopy(getattr(clean, name)))
            except Back:
                continue

    def module_picker(self, args):
        while True:
            self.screen(tr("Audit modules"), tr("Select one to enable/disable it. 0 to go back."))
            modules = self.core.MODES[args.mode]
            for index, name in enumerate(modules, 1):
                self.item(str(index), f"[{' ' if name in args.skip else 'x'}] {module_label(name)}")
            try:
                key = self.choose({str(index) for index in range(1, len(modules) + 1)})
            except Back:
                return
            name = modules[int(key) - 1]
            if name == "tls":
                args.ui_tls_auto_skip = False
            if name in args.skip:
                args.skip.remove(name)
            else:
                args.skip.append(name)

    def execute(self, plan):
        self.screen(tr("Audit in progress"), tr("Finished results are saved even if you cancel later."))
        completed_count = 0
        last_entry = None
        for index, target in enumerate(plan.targets, 1):
            self.line(tr("Target {index}/{total} · {target}", index=index, total=len(plan.targets),
                         target=target), "1;36")

            def progress(name, status, position, total):
                labels = {"running": "RUNNING", "ok": "DONE", "error": "ERROR", "skipped": "SKIPPED"}
                text = f"[{position}/{total}] {module_label(name)} · {tr(labels[status])}"
                if self.tty:
                    self.out.write("\r\033[2K" if self.color else "\r" + " " * (self.width - 1) + "\r")
                    self.out.write("  " + self.style(text[:self.width - 4], "33" if status == "error" else "36"))
                    if status != "running":
                        self.out.write("\n")
                    self.out.flush()
                elif status != "running":
                    self.line(text)

            report = self.core.scan(target, plan.args, on_progress=progress)
            formats = ("json", "txt", "html") if plan.args.format == "all" else (plan.args.format,)
            try:
                paths = self.core.save_report(report, plan.args.output, formats)
            except OSError as exc:
                self.line(tr("Could not save the reports: {error}", error=exc), "33")
                paths = []
            entry = {"report": report, "paths": paths}
            self.history.append(entry)
            self.history = self.history[-20:]
            completed_count += 1
            last_entry = entry
            self.summary(report)
            for path in paths:
                self.line(tr("Saved: {path}", path=path), "90")
            self.line()
        if completed_count == 1:
            self.viewer(last_entry)
        else:
            self.line(tr("Batch finished: {count} targets. See the recent ones in My reports.",
                         count=completed_count), "32")
            self.pause()

    def summary(self, report):
        modules = report.get("modules", {})
        errors = sum(item.get("status") == "error" for item in modules.values())
        done = sum(item.get("status") == "ok" for item in modules.values())
        skipped = sum(item.get("status") == "skipped" for item in modules.values())
        self.panel(tr("SUMMARY"), [(tr("Checks: {done} finished / {errors} with errors / {skipped} skipped",
                                       done=done, errors=errors, skipped=skipped),
                                    "33" if errors else "32")])
        score = report.get("score")
        if isinstance(score, dict) and score.get("grade"):
            counts = {level: sum(f["severity"] == level for f in score.get("findings", []))
                      for level in ("high", "medium", "low")}
            color = "32" if score["grade"] in ("A", "B") else "33" if score["grade"] == "C" else "1;31"
            self.line(tr("Security grade: {grade} ({score}/100) · {high} high, {medium} medium, {low} low",
                         grade=score["grade"], score=score["score"], high=counts["high"],
                         medium=counts["medium"], low=counts["low"]), color)
            for finding in score.get("findings", [])[:5]:
                if finding["severity"] in ("high", "medium"):
                    self.line(f"  [{severity_label(finding['severity'])}] {finding['title']}",
                              severity_color(finding["severity"]))
        for name, item in modules.items():
            self.module_summary(name, item)

    def module_summary(self, name, item):
        label = module_label(name)
        if item.get("status") == "error":
            self.line(f"{label}: {self.explain_error(item.get('error', tr('no details')))}", "33")
            return
        if item.get("status") == "skipped":
            if item.get("reason"):
                self.line(tr("{module}: skipped ({reason})", module=label, reason=item["reason"]), "90")
            else:
                self.line(tr("{module}: skipped", module=label), "90")
            return
        data = item.get("data", {})
        if not isinstance(data, dict):
            return
        if name == "dns":
            self.line(tr("Addresses: {addresses}", addresses=", ".join(data.get("addresses", [])) or tr("none")))
            records = data.get("records") or {}
            if records.get("NS"):
                self.line(tr("DNS servers: {servers}", servers=", ".join(records["NS"][:4])))
            if records.get("MX"):
                self.line(tr("Mail (MX): {hosts}", hosts=", ".join(f"{r['host']} ({r['priority']})"
                                                                   for r in records["MX"][:4] if isinstance(r, dict))))
            if records.get("CNAME"):
                self.line(tr("Alias (CNAME): {names}", names=", ".join(records["CNAME"])))
            if data.get("records") is not None:
                self.line(tr("DNSSEC: {dnssec} · CAA: {caa}",
                             dnssec=tr("active") if data.get("dnssec") else tr("no"),
                             caa=tr("yes") if records.get("CAA") else tr("no")),
                          "32" if data.get("dnssec") else None)
            if data.get("ptr"):
                self.line(tr("Reverse name: {names}", names=", ".join(data["ptr"])))
        elif name == "rdap":
            registration = str(data.get("name") or data.get("ldhName") or data.get("handle")
                               or tr("response available in the report"))
            if isinstance(data.get("status"), list) and data["status"]:
                self.line(tr("Registration: {name} · status: {status}", name=registration,
                             status=", ".join(data["status"][:3])))
            else:
                self.line(tr("Registration: {name}", name=registration))
        elif name == "http":
            status = data.get("status", "?")
            color = "32" if str(status).startswith("2") else "36" if str(status).startswith("3") else "33"
            self.line(f"HTTP: {status} · {data.get('title') or tr('no title')}", color)
            missing = data.get("missing_headers", [])
            self.line(tr("Recommended headers missing: {headers}",
                         headers=", ".join(missing) if missing else tr("none of those checked")))
        elif name == "tls":
            self.tls_summary(data)
        elif name == "ports":
            rows = data.get("results", [])
            opened = [row.get("port") for row in rows if row.get("state") == "open"]
            self.line(tr("Reachable TCP ports: {ports}",
                         ports=", ".join(service_label(port) for port in opened) if opened
                         else tr("none in the reviewed list")),
                      "32" if opened else None)
            if rows:
                self.line(tr("No answer: {closed} of {total} ports reviewed",
                             closed=len(rows) - len(opened), total=len(rows)), "90")
        elif name == "traceroute":
            self.line(tr("Network route: {route}",
                         route=data.get("reason", tr("not available")) if data.get("status") == "unavailable"
                         else tr("available in the details")))
        elif name == "mikrotik":
            self.routeros_summary(data)
        elif name == "asn":
            groups = {}
            for row in data.get("networks", []):
                key = (f"AS{row['asn']} {row.get('as_name') or ''} · {row.get('country') or '?'}".strip()
                       if row.get("asn") else (row.get("note") or row.get("error") or tr("no public data")))
                groups.setdefault(key, []).append(row)
            for key, rows in groups.items():
                ptrs = sorted({r["ptr"] for r in rows if r.get("ptr")})
                ips = ", ".join(r["ip"] for r in rows[:3])
                if len(rows) > 3:
                    ips = tr("{ips} and {count} more", ips=ips, count=len(rows) - 3)
                self.line(tr("Network: {network} · {ips}", network=key, ips=ips)
                          + (f" · {', '.join(ptrs[:2])}" if ptrs else ""),
                          None if rows[0].get("asn") else "90")
        elif name == "mail":
            color = "1;31" if data.get("spoofable") else "32" if data.get("grade", "").startswith("A") else "33"
            if data.get("spoofable"):
                self.line(tr("Mail: grade {grade} · CAN BE SPOOFED (DMARC does not block fake mail)",
                             grade=data.get("grade")), color)
            else:
                self.line(tr("Mail: grade {grade} · protected against spoofing", grade=data.get("grade")), color)
            spf, dmarc = data.get("spf", {}), data.get("dmarc", {})
            self.line(tr("SPF: {spf} · DMARC: {dmarc} · DKIM: {dkim} · MTA-STS: {mta_sts}",
                         spf=spf.get("all") or (tr("no -all") if spf.get("present") else tr("missing")),
                         dmarc=dmarc.get("policy") or tr("missing"),
                         dkim=", ".join(data.get("dkim", {}).get("selectors_found", [])) or tr("not found"),
                         mta_sts=data.get("mta_sts", {}).get("mode") or tr("no")))
            if not data.get("accepts_mail"):
                self.line(tr("The domain does not receive mail (no MX or null MX)."), "90")
        elif name == "tech":
            grade = data.get("headers_grade", {})
            tech = ", ".join(t["name"] for t in data.get("technologies", [])) or tr("none identified")
            self.line(tr("Web: {status} · security headers: grade {grade} ({points}/100)",
                         status=data.get("status"), grade=grade.get("grade"), points=grade.get("points")),
                      "32" if grade.get("grade") in ("A", "B") else "33")
            if data.get("generator"):
                self.line(tr("Technologies: {list} · generator: {generator}", list=tech,
                             generator=data["generator"]))
            else:
                self.line(tr("Technologies: {list}", list=tech))
            if data.get("favicon"):
                self.line(tr("Favicon: {hash} (search it in Shodan to find identical servers)",
                             hash=data["favicon"]["shodan"]), "90")
            extra = []
            if data.get("security_txt"):
                extra.append(tr("security.txt published"))
            if data.get("redirects"):
                extra.append(tr("{count} redirects", count=len(data["redirects"])))
            weak = [c["name"] for c in data.get("cookies", []) if c.get("issues")]
            if weak:
                extra.append(tr("{count} cookies without protections", count=len(weak)))
            if extra:
                self.line(" · ".join(extra), "90")
        elif name == "subdomains":
            alive = data.get("alive", [])
            self.line(tr("Subdomains: {total} found ({sources}) · {alive} active", total=data.get("total", 0),
                         sources=", ".join(data.get("sources", [])) or tr("no source"), alive=len(alive)),
                      "32" if data.get("total") else None)
            for row in data.get("takeover", []):
                risk = row["takeover"]["risk"]
                tag = tr("POSSIBLE TAKEOVER") if risk != "review" else tr("REVIEW")
                self.line(f"[{tag}] {row['name']} → {row.get('cname')} · {row['takeover']['reason']}",
                          "1;31" if risk == "high" else "33")
            if data.get("warning"):
                self.line(data["warning"], "33")
        elif name == "history":
            parts = []
            if data.get("registered"):
                parts.append(tr("registered on {date} ({days} days)", date=data["registered"],
                                days=data.get("age_days")))
            if data.get("expires"):
                parts.append(tr("expires on {date}", date=data["expires"]))
            if data.get("registrar"):
                parts.append(tr("registrar: {name}", name=data["registrar"]))
            self.line(tr("Domain: {details}", details=" · ".join(parts) or tr("no public registration dates")),
                      "33" if data.get("new_domain") else None)
            if data.get("new_domain"):
                self.line(tr("Recent domain: a common sign of phishing sites."), "33")
            wb = data.get("wayback") or {}
            if wb.get("first_capture"):
                self.line(tr("Wayback Machine: first capture {first} · last {last}",
                             first=wb["first_capture"], last=wb.get("last_capture")), "90")
        elif name == "lookalike":
            rows = data.get("registered", [])
            self.line(tr("Lookalike domains: {registered} registered out of {checked} variants · "
                         "{mail} receive mail", registered=len(rows), checked=data.get("checked"),
                         mail=data.get("with_mail", 0)), "33" if data.get("with_mail") else None)
            for row in rows[:6]:
                self.line(f"  {row['domain']} ({row.get('kind')})" + (" · " + tr("receives mail") if row.get("mx") else ""),
                          "33" if row.get("mx") else "90")
        elif name == "webapp":
            self.webapp_summary(data)

    def webapp_summary(self, data):
        status = data.get("status")
        self.line(tr("URL: {url} · HTTP {status} · {title}", url=data.get("final_url"), status=status,
                     title=data.get("title") or tr("no title")),
                  "32" if str(status).startswith("2") else "33")
        root = data.get("root_comparison") or {}
        if root.get("same_as_target"):
            self.line(tr("Site root: it is the same URL being audited"), "90")
        elif root.get("error"):
            self.line(tr("Site root: not compared ({error})", error=root["error"]), "90")
        elif root:
            if root.get("differs"):
                self.line(tr("Site root: HTTP {status} · {title} · content differs from the requested URL",
                             status=root.get("status"), title=root.get("title") or tr("no title")), "90")
            else:
                self.line(tr("Site root: HTTP {status} · {title} · SAME content as the requested URL "
                             "(check whether the path exists)",
                             status=root.get("status"), title=root.get("title") or tr("no title")), "33")
        for hop in data.get("redirects", []):
            text = tr("Redirect {status} → {location}", status=hop.get("status"), location=hop.get("location"))
            if hop.get("blocked"):
                text += " · " + tr("NOT FOLLOWED: {reason}", reason=hop["blocked"])
            self.line(text, "33" if hop.get("blocked") or hop.get("downgrade") else "90")
        score = data.get("assessment") or {}
        if score:
            self.line(tr("Security {security}/100 · Coverage {coverage}% · Confidence {confidence}%",
                         security=score.get("security"), coverage=score.get("coverage"),
                         confidence=score.get("confidence")))
        for form in data.get("forms", [])[:6]:
            kind = tr("login") if form.get("login") else tr("form")
            fields = ", ".join(form.get("user_fields", []) + form.get("password_fields", []))
            csrf = form["csrf"]["state"]
            text = tr("Form {index} ({kind}): {method} → {action}", index=form["index"], kind=kind,
                      method=form["method"], action=form["action"])
            if fields:
                text += " · " + tr("fields {fields}", fields=fields)
            self.line(text + " · CSRF: " + (tr(CSRF_LABELS[csrf]) if csrf in CSRF_LABELS else str(csrf)))
        cookies = data.get("cookies", [])
        if cookies:
            self.line(tr("Cookies: {cookies}  (S=Secure, H=HttpOnly)", cookies=", ".join(
                f"{c['name']} [{'S' if c['secure'] else '-'}{'H' if c['httponly'] else '-'} "
                f"{c['samesite'] or tr('no SameSite')}]" for c in cookies[:6])), "90")
        relevant = [f for f in data.get("findings", []) if f.get("status") in ("confirmed", "likely", "pending")]
        for item in relevant[:10]:
            self.line(f"[{severity_label(item['severity'])}·{status_label(item['status'])}] {item['title']}",
                      severity_color(item["severity"]) if item["status"] != "pending" else "33")
        if len(relevant) > 10:
            self.line(tr("… and {count} more in the report", count=len(relevant) - 10), "90")
        if not relevant:
            self.line(tr("No confirmed or pending findings in the passive checks."), "32")

    def tls_summary(self, data):
        if data.get("verified") is False:
            self.line(tr("TLS: {protocol} · INVALID CERTIFICATE: {error}", protocol=data.get("protocol"),
                         error=data.get("verify_error")), "1;31")
            if data.get("issuer"):
                text = tr("Issued by {issuer} for {subject}", issuer=data.get("issuer"), subject=data.get("subject"))
                self.line(text + (" " + tr("(self-signed)") if data.get("self_signed") else ""), "90")
        versions = data.get("versions") or {}
        if versions:
            accepted = [v.replace("TLSv", "") for v, ok in versions.items() if ok]
            old = [v for v in ("TLSv1.0", "TLSv1.1") if versions.get(v)]
            self.line(tr("Accepted TLS versions: {versions}", versions=", ".join(accepted) or tr("none"))
                      + (" · " + tr("accepts old versions") if old else ""), "33" if old else "90")
        if data.get("verified") is False:
            return
        days, expires = data.get("days_remaining"), data.get("expires")
        when = tr("expires on {date}", date=expires) if expires else tr("expiry date not available")
        protocol = data.get("protocol")
        if days is not None and days < 0:
            self.line(tr("TLS: {protocol} · certificate EXPIRED {days} days ago ({date})",
                         protocol=protocol, days=-days, date=expires), "1;31")
        elif days is not None and days <= self.core.CERT_WARN_DAYS:
            self.line(tr("TLS: {protocol} · verified certificate · {when}", protocol=protocol, when=when), "33")
            self.line(tr("Warning: the certificate expires in {days} days. Renew it soon.", days=days), "33")
        else:
            self.line(tr("TLS: {protocol} · verified certificate · {when} ({days} days)",
                         protocol=protocol, when=when, days=days), "32")

    def routeros_summary(self, data):
        source = {"user_supplied": "given by you", "public_banner": "public banner", "unknown": "not obtained"}
        origin = data.get("version_source")
        self.line(tr("RouterOS: {version} · {source}", version=data.get("version") or tr("unknown"),
                     source=tr(source[origin]) if origin in source else tr("no source")), "1;37")
        self.line(tr("Catalog reviewed: {date}", date=data.get("catalog_reviewed", tr("no date"))), "90")
        groups = {state: [entry for entry in data.get("advisories", []) if entry.get("status") == state]
                  for state in ("potentially_affected", "not_in_affected_range", "unknown_version", "manual_review")}
        self.line(tr("Advisories that could affect this version: {count}",
                     count=len(groups["potentially_affected"])),
                  "33" if groups['potentially_affected'] else "37")
        self.line(tr("Advisories that do not include this version: {count}",
                     count=len(groups["not_in_affected_range"])))
        self.line(tr("Advisories not evaluated: {count}",
                     count=len(groups["unknown_version"]) + len(groups["manual_review"])))
        for entry in groups["potentially_affected"]:
            self.line(f"[{tr('REVIEW')}] {entry['id']} · {entry.get('component', '')}", "33")
        if data.get("version_conflict"):
            self.line(tr("There are contradictory versions. Validate the version in your inventory."), "33")
        elif not data.get("version"):
            self.line(tr("The version is not published. Give it from your inventory to evaluate the advisories."), "33")
        if groups["potentially_affected"]:
            self.line(tr("Next step: review the patches of your branch and restrict the management services."), "33")
        self.line(tr("The version comparison does not confirm exploitation or certify that the router is secure."), "90")

    @staticmethod
    def explain_error(error):
        text = str(error)
        lower = text.lower()
        if "certificate has expired" in lower:
            return tr("The certificate has expired. The site must renew it.")
        if "unable to get local issuer certificate" in lower:
            # Common on Windows: the root is only downloaded when a browser first needs it.
            return tr("This computer does not recognize the authority that signed the certificate (its root is "
                      "missing from the system store). That alone does not mean the site is misconfigured.")
        if any(word in lower for word in ("certificate_verify_failed", "certificate verify failed", "certificate failed")):
            return tr("The certificate could not be validated. Check its trust, name and date.")
        if any(word in lower for word in ("getaddrinfo", "name or service", "name resolution", "nodename nor servname")):
            return tr("The name could not be resolved. Check the target and the DNS connection.")
        if "timed out" in lower or "timeout" in lower:
            return tr("No answer within the configured time. You can increase the wait.")
        if "connection refused" in lower or "actively refused" in lower:
            return tr("The host refused the connection to the service.")
        return text

    def details(self, report):
        self.screen(tr("Explained results"), str(report.get("meta", {}).get("target", tr("no target"))))
        score = report.get("score")
        if isinstance(score, dict) and score.get("findings"):
            self.panel(tr("FINDINGS · GRADE {grade} ({score}/100)", grade=score.get("grade"), score=score.get("score")),
                       [(score.get("note", ""), "90")])
            for finding in score["findings"]:
                self.line(f"[{severity_label(finding['severity'])}] {tr(finding['area'])}: {finding['title']}",
                          severity_color(finding["severity"]))
                self.line("    " + tr("How to fix: {fix}", fix=finding["fix"]), "90")
            self.line()
        for name, module in report.get("modules", {}).items():
            self.panel(module_label(name).upper(),
                       [(tr(MODULE_HELP[name]) if name in MODULE_HELP else tr("Check data."), "90")])
            if module.get("status") == "skipped":
                self.line(tr("Status: skipped in the analysis options."))
                continue
            if module.get("status") == "error":
                self.line(tr("Status: could not be completed."), "33")
                self.line(self.explain_error(module.get("error", tr("no details"))))
                self.line(tr("Error details: {error}", error=module.get("error", tr("no details"))), "90")
                continue
            data = module.get("data", {})
            self.summary({"modules": {name: module}})
            if name == "mikrotik":
                for entry in data.get("advisories", []):
                    self.line()
                    self.line(str(entry.get("id", tr("Advisory"))) + " / " + str(entry.get("component", "")), "1;37")
                    status = entry.get("status")
                    self.line(tr("Status: {status}", status=tr(ADVISORY_LABELS[status]) if status in ADVISORY_LABELS
                                 else tr("no data")))
                    self.line(tr("What it checks: {summary}", summary=entry.get("summary", tr("see the source"))))
                    if entry.get("status") == "potentially_affected" and data.get("version"):
                        import routeros
                        installed = routeros.parse_version(data["version"]).numbers
                        fixes = [row["fixed"] for row in entry.get("affected_ranges", [])
                                 if routeros.parse_version(row["introduced"]).numbers <= installed
                                 < routeros.parse_version(row["fixed"]).numbers]
                        if fixes:
                            self.line(tr("Version that fixes this advisory in that branch: {versions}",
                                         versions=", ".join(fixes)), "33")
                    ports = entry.get("observed_default_ports", [])
                    self.line(tr("Related ports that answered: {ports}",
                                 ports=", ".join(map(str, ports)) if ports else tr("no exposure was established")))
                    for source in entry.get("sources", []):
                        self.line(tr("Source: {source}", source=source), "90")
            elif name == "ports":
                for row in data.get("results", []):
                    opened = row.get("state") == "open"
                    tag = tr("[ANSWERS]") if opened else tr("[NOT REACHABLE]")
                    self.line(f"{tag} {row.get('port')}/TCP", "32" if opened else "90")
                self.line(tr("Not reachable: the connection failed; it may be closed, filtered or not answering."))
            elif name == "http":
                explanations = {"content-security-policy": "limits the resources the page can load",
                                "strict-transport-security": "tells the browser to use HTTPS",
                                "x-content-type-options": "prevents guessing the content type",
                                "referrer-policy": "controls which URL is shared as the referrer"}
                for header in data.get("missing_headers", []):
                    self.line(tr("Missing: {header} — {why}", header=header,
                                 why=tr(explanations[header]) if header in explanations
                                 else tr("review the site's policy")))
            elif name == "traceroute" and data.get("output"):
                self.line(data["output"])
            elif name == "mail":
                for issue in data.get("spf", {}).get("issues", []) + data.get("dmarc", {}).get("issues", []):
                    self.line("• " + issue, "33")
                if data.get("spf", {}).get("record"):
                    self.line("SPF: " + data["spf"]["record"], "90")
                if data.get("dmarc", {}).get("record"):
                    self.line("DMARC: " + data["dmarc"]["record"], "90")
                self.line(tr("TLS-RPT: {tls_rpt} · BIMI: {bimi}",
                             tls_rpt=tr("yes") if data.get("tls_rpt") else tr("no"),
                             bimi=tr("yes") if data.get("bimi") else tr("no")))
            elif name == "tech":
                for check in data.get("headers_grade", {}).get("checks", []):
                    mark, color = CHECK_MARKS.get(check["state"], ("[" + str(check["state"]).upper() + "]", "33"))
                    self.line(f"{tr(mark)} {check['text']}", color)
                for cookie in data.get("cookies", []):
                    if cookie.get("issues"):
                        self.line(f"Cookie {cookie['name']}: " + ", ".join(cookie["issues"]), "90")
                for hop in data.get("redirects", []):
                    self.line(tr("Redirect {status} → {location}", status=hop["status"],
                                 location=hop["location"]), "90")
                if data.get("robots"):
                    self.line(tr("robots.txt: {count} blocked paths · {sitemaps}", count=data["robots"]["disallow"],
                                 sitemaps=", ".join(data["robots"]["sitemaps"]) or tr("no sitemap")), "90")
            elif name == "subdomains":
                for row in data.get("alive", [])[:60]:
                    target = row.get("cname") or ", ".join(row.get("addresses", [])[:2])
                    self.line(f"{row['name']} → {target}", "90")
                if len(data.get("alive", [])) > 60:
                    self.line(tr("… and {count} more in the report.", count=len(data["alive"]) - 60), "90")
                if data.get("note"):
                    self.line(data["note"], "90")
            elif name == "lookalike":
                for row in data.get("registered", []):
                    self.line(f"{row['domain']} · {row.get('kind')} · {', '.join(row.get('addresses', []))}"
                              + (" · " + tr("receives mail") if row.get("mx") else ""), "33" if row.get("mx") else "90")
                self.line(data.get("note", ""), "90")
            elif name == "rdap":
                for key, label in (("handle", "Identifier"), ("name", "Name"),
                                   ("country", "Registration country"), ("startAddress", "First IP"),
                                   ("endAddress", "Last IP")):
                    if data.get(key):
                        self.line(f"{tr(label)}: {data[key]}")
            self.line()

    def viewer(self, entry):
        while True:
            report = entry["report"]
            self.screen(tr("Analysis summary"), str(report.get("meta", {}).get("target", tr("no target"))))
            try:
                self.summary(report)
            except (TypeError, KeyError, AttributeError):
                self.line(tr("This report has no compatible summary. You can look at the details."), "33")
            self.line()
            self.item("1", tr("View explained results"))
            html_paths = [path for path in entry["paths"] if Path(path).suffix.lower() == ".html"]
            if html_paths:
                self.item("2", tr("Open the HTML report in the browser"))
            self.item("3", tr("View file paths"))
            self.item("4", tr("View JSON data (technical details)"))
            self.item("0", tr("Back"))
            try:
                choice = self.choose({"1", "3", "4"} | ({"2"} if html_paths else set()))
            except Back:
                return
            if choice == "1":
                try:
                    self.details(report)
                except (TypeError, KeyError, AttributeError, ValueError):
                    self.line(tr("Part of this report could not be interpreted. Check its JSON data."), "33")
            elif choice == "2":
                try:
                    opened = webbrowser.open(Path(html_paths[0]).resolve().as_uri())
                    self.line(tr("Report sent to the browser.") if opened
                              else tr("No browser available. Open the file from its path."))
                except (OSError, webbrowser.Error) as exc:
                    self.line(tr("Could not open the browser: {path}", path=exc), "33")
            elif choice == "4":
                self.screen(tr("JSON data"), tr("Complete technical information of the analysis."))
                self.line(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                if not entry["paths"]:
                    self.line(tr("No files were saved; the result stays available during this session."))
                for path in entry["paths"]:
                    self.line(str(Path(path).resolve()))
            self.pause()

    def stored_reports(self):
        entries = list(reversed(self.history[-20:]))
        seen = {str(Path(path).resolve()) for entry in entries for path in entry["paths"]}
        try:
            files = sorted(self.defaults.output.glob("domaininfo_*.json"),
                           key=lambda path: path.stat().st_mtime, reverse=True)[:20]
        except OSError:
            files = []
        for path in files:
            if str(path.resolve()) in seen:
                continue
            try:
                if path.stat().st_size > 4 * 1024 * 1024:
                    continue
                report = json.loads(path.read_text(encoding="utf-8"))
                if (not isinstance(report, dict) or not isinstance(report.get("meta"), dict)
                        or report["meta"].get("tool") != "DomainInfo"
                        or not isinstance(report.get("modules"), dict)
                        or not all(isinstance(value, dict) for value in report["modules"].values())):
                    continue
                paths = [str(candidate) for candidate in (path, path.with_suffix(".html"), path.with_suffix(".txt"))
                         if candidate.is_file()]
                entries.append({"report": report, "paths": paths})
            except (OSError, ValueError, UnicodeError):
                continue
        return entries[:20]

    def reports(self):
        while True:
            entries = self.stored_reports()
            self.screen(tr("My reports"), tr("Up to 20 recent results; 0 to go back."))
            if not entries:
                self.line(tr("No reports yet. Run an audit to see its results here."))
                self.line(tr("Current folder: {folder}", folder=self.defaults.output), "90")
                self.pause()
                return
            for index, entry in enumerate(entries, 1):
                meta = entry["report"].get("meta", {})
                self.item(str(index), str(meta.get("target", tr("no target"))),
                          f"{meta.get('date', '')} · {meta.get('mode', '')}")
            key = self.choose({str(index) for index in range(1, len(entries) + 1)})
            self.viewer(entries[int(key) - 1])

    def diagnostics(self):
        self.screen(tr("Diagnostics of this computer"), tr("This check makes no network connections."))
        data = self.core.doctor()
        self.line("Python: " + data["python"])
        self.line(tr("System: {platform}", platform=data["platform"]))
        self.line("TLS: " + data["openssl"])
        self.line(tr("Portable core ready: it needs no root and no pip packages."), "32")
        self.line()
        self.line(tr("Optional tools:"))
        for name, path in data["optional"].items():
            self.line(f"{'[OK]' if path else '[--]'} {name}: {path or tr('not installed (optional)')}")
        self.pause()

    def classic(self):
        self.screen(tr("Classic audits"), tr("Bash modules for ISP, web applications and local network."))
        if os.name == "nt":
            self.line(tr("These modules need a Linux/WSL environment and its tools."))
            self.line(tr("From that environment run: bash domaininfo.sh --legacy"))
            self.line(tr("The portable MikroTik audit is still available in option 5."))
            self.pause()
            return
        candidates = [shutil.which("bash"), "/opt/homebrew/bin/bash", "/usr/local/bin/bash"]
        selected = None
        for candidate in dict.fromkeys(item for item in candidates if item):
            try:
                check = subprocess.run([candidate, "-c", 'test "${BASH_VERSINFO[0]}" -ge 4'],
                                       capture_output=True, timeout=5)
                if check.returncode == 0:
                    selected = candidate
                    break
            except (OSError, subprocess.SubprocessError):
                continue
        missing = [name for name in ("curl", "dig") if not shutil.which(name)]
        if not selected or missing:
            self.line(tr("Bash 4+ or classic tools are missing: {missing}", missing=", ".join(missing) or "Bash 4+"), "33")
            self.line(tr("Install them from the project folder: bash install.sh --legacy"))
            self.pause()
            return
        self.line(tr("You will open the classic menu. When you leave it you will come back to this menu."))
        self.item("1", tr("Open classic menu"))
        self.item("0", tr("Back"))
        self.choose({"1"})
        script = Path(__file__).resolve().with_name("domaininfo.sh")
        if not script.exists():  # installed with pipx/pip: only the Python core is packaged
            self.line(tr("The Bash modules are not included in the pipx installation."), "33")
            self.line(tr("Clone the repository to use them: git clone https://github.com/kevxngg/domaininfo"))
            self.pause()
            return
        try:
            subprocess.run([selected, str(script), "--legacy"], check=False)
        except OSError as exc:
            self.line(tr("Could not open the classic menu: {error}", error=exc), "33")
            self.pause()

    def help(self):
        self.screen(tr("Quick guide"))
        self.line(tr("1. Choose what to review. For a MikroTik router use option 5."))
        self.line(tr("2. Give the domain/IP or check a RouterOS version offline."))
        self.line(tr("3. Check the summary. You can change options before starting."))
        self.line(tr("4. See the result and its reports from My reports."))
        self.line()
        self.line(tr("0 goes back to the previous menu; CTRL+C cancels the current action."))
        self.line(tr("Preferences last for this session; you do not need to type commands."))
        self.line(tr("For a URL, scheme and port are kept; the site root is reviewed."))
        self.line(tr("Use the network modes on hosts you are authorized to review."))
        self.pause()


class CliView:
    """Readable output for `domaininfo <target>` at a terminal; pipes keep the JSON."""

    STATUS = {"running": "running", "ok": "done", "error": "error", "skipped": "skipped"}

    def __init__(self, core, args, output=None, errors=None):
        self.app = InteractiveApp(core, args, output=output or sys.stdout)
        self.err = errors or sys.stderr
        self.live = bool(getattr(self.err, "isatty", lambda: False)())
        self.hinted = False

    def _status_line(self, text):
        if self.live:
            clear = "\r\033[2K" if self.app.color else "\r" + " " * (self.app.width - 1) + "\r"
            self.err.write(clear + (("  " + self.app.style(text[:self.app.width - 4], "90")) if text else ""))
            self.err.flush()

    def progress(self, name, status, position, total):
        if status == "running":
            self._status_line(f"[{position}/{total}] {module_label(name)} · {tr(self.STATUS[status])}…")
        else:
            self._status_line("")

    def report(self, report, paths):
        app, meta = self.app, report.get("meta", {})
        app.line()
        app.line(f"{meta.get('target', '')} · {mode_label(meta.get('mode'))}", "1;36")
        app.summary(report)
        if paths:
            folder = str(Path(paths[0]).parent)
            kinds = ", ".join(Path(path).suffix.lstrip(".") for path in paths)
            app.line(tr("Reports ({kinds}) in {folder}", kinds=kinds, folder=folder), "90")
        if not self.hinted:
            app.line(tr("JSON: --json · Help and examples: --help"), "90")
            self.hinted = True

    def note(self, text):
        self._status_line("")
        self.app.line(text, "90")

    def quiet_tick(self, text):
        self._status_line(text)

    def changes(self, stamp, target, changes):
        self._status_line("")
        self.app.line(tr("[{time}] {target}: {count} change(s)", time=stamp, target=target, count=len(changes)), "1;33")
        for change in changes:
            self.app.line("  • " + change, "33")
