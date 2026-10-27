"""Guided terminal interface for DomainInfo. Kevin (@kevxngg).

Standard library only; numbered navigation also works in Android terminals.
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


MODE_LABELS = {
    "quick": ("Análisis rápido", "Resolver IPs y consultar el registro del dominio"),
    "web": ("Sitio web y certificado", "HTTP, cabeceras de seguridad y conexión TLS"),
    "ports": ("Puertos TCP", "Comprobar servicios accesibles en tu equipo"),
    "full": ("Diagnóstico completo", "DNS, registro, web, TLS, puertos y ruta de red"),
    "mikrotik": ("MikroTik / RouterOS", "Versión, servicios de gestión y avisos aplicables"),
}
MODE_KEYS = {"1": "quick", "2": "web", "3": "ports", "4": "full", "5": "mikrotik"}
MODULE_LABELS = {"dns": "Resolución de direcciones", "rdap": "Registro RDAP",
                 "http": "Sitio y cabeceras HTTP", "tls": "Certificado TLS",
                 "ports": "Servicios TCP", "traceroute": "Ruta de red",
                 "mikrotik": "Auditoría RouterOS"}
MODULE_HELP = {
    "dns": "Direcciones IPv4/IPv6 que el sistema devuelve para el objetivo.",
    "rdap": "Datos públicos del registro del dominio o del bloque de direcciones IP.",
    "http": "Respuesta de la página y cabeceras que indican políticas de seguridad del sitio.",
    "tls": "Protocolo cifrado negociado y certificado validado por Python.",
    "ports": "Servicios TCP que respondieron desde este equipo durante la revisión.",
    "traceroute": "Saltos de red informados por la herramienta de ruta del sistema.",
    "mikrotik": "Comparación de la versión RouterOS con los avisos del catálogo fechado.",
}
ADVISORY_LABELS = {"potentially_affected": "REVISAR: versión incluida en el aviso",
                   "not_in_affected_range": "Versión fuera del intervalo afectado",
                   "unknown_version": "SIN EVALUAR: falta la versión",
                   "manual_review": "SIN CONCLUSIÓN: revisar la versión manualmente"}
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
        self.screen("MENÚ PRINCIPAL", home=True)
        audit = [(key, MODE_LABELS[mode][0],
                  {"quick": "DNS + registro del dominio", "web": "HTTP + cabeceras + TLS",
                   "ports": "Servicios TCP accesibles", "full": "Todos los módulos generales",
                   "mikrotik": "Router en red o versión offline"}[mode])
                 for key, mode in MODE_KEYS.items()]
        workspace = [("6", "Varios objetivos", "Auditoría desde un archivo"),
                     ("7", "Mis reportes", "Resultados y exportaciones"),
                     ("8", "Preferencias", "Conexiones, tiempos y formatos"),
                     ("9", "Diagnóstico del equipo", "Estado de las herramientas"),
                     ("a", "Auditorías clásicas", "ISP / WebApp / LAN con Bash")]
        if self.width >= 78:
            panel_width = (self.width - 6) // 2
            detailed = shutil.get_terminal_size((80, 24)).lines >= 34
            left = self.frame("01 / AUDITORÍAS", audit, panel_width, "36", detailed)
            right = self.frame("02 / HERRAMIENTAS", workspace, panel_width, "35", detailed)
            blank = " " * panel_width
            for index in range(max(len(left), len(right))):
                print("  " + (left[index] if index < len(left) else blank) + "  "
                      + (right[index] if index < len(right) else blank), file=self.out)
        else:
            for title, rows, accent in (("AUDITORÍAS", audit, "36"), ("HERRAMIENTAS", workspace, "35")):
                for row in self.frame(title, rows, accent=accent, descriptions=False):
                    print("  " + row, file=self.out)
        self.line()
        self.panel("NAVEGACIÓN", [("[h] Ayuda rápida     [0] Salir", "90")], "90")
        self.line("Elige un módulo para comenzar. NÚMERO + ENTER" if self.width >= 60
                  else "NÚMERO + ENTER · 0 para salir", "90")

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
            self.center("DOMINIOS / REDES / ROUTEROS", "90")
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
            self.panel("PANEL DE ANÁLISIS", rows)
            self.line("[0 / r] Regresar al menú anterior", "90")
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
            if value.lower() in ("r", "regresar", "volver"):
                if self.at_home:
                    self.line("Ya estás en el menú principal. Usa 0 para salir.", "90")
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
                self.line("Escribe un valor o 0 para volver.", "33")
                continue
            try:
                return validator(value) if validator else value
            except (ValueError, UnicodeError, OSError, argparse.ArgumentTypeError) as exc:
                self.line(str(exc), "33")

    def choose(self, keys, label="Elige una opción", default=None):
        def validate(value):
            value = value.lower()
            if value not in keys:
                raise ValueError("Opción no válida. Usa los números del menú; 0 para volver.")
            return value
        return self.ask(label, default, validate)

    def pause(self):
        self.out.write("\n  [0 / r] Regresar · ENTER para continuar...")
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
                self.line("Acción cancelada. Puedes elegir otra opción.", "33")
            except EOFError:
                self.line("Sesión cerrada.")
                return 0

    def target(self, args):
        self.line("Acepta dominio, IPv4, IPv6 o URL. Ejemplo: 192.168.88.1")
        raw = self.ask("Objetivo (0 para volver)", self.last_target or None,
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
        self.line("Versión de tu inventario. Ejemplos: 7.25, 7.23.8.")
        if not required:
            self.line("ENTER sin versión: se intentará detectar mediante banners públicos.")
        return self.ask("Versión RouterOS (0 para volver)", default,
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
                self.screen(MODE_LABELS[mode][0], "Paso 1 · Elige el tipo de revisión.")
                self.item("1", "Revisar un router en la red", "Servicios accesibles, banners y avisos por versión")
                self.item("2", "Revisar solo una versión", "Sin conexión a routers ni servicios de Internet")
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
            self.screen(MODE_LABELS[mode][0], "Paso 1 · Elige el objetivo.")
            targets = [self.target(args)]
        self.review(Plan(args, targets))

    def load_batch(self):
        def validate(value):
            path = Path(value.strip('"')).expanduser()
            lines = path.read_text(encoding="utf-8-sig").splitlines()
            targets, ignored = [], 0
            for line in lines:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                try:
                    normalized = self.core.normalize_target(line)
                    if normalized in targets:
                        ignored += 1
                    else:
                        targets.append(normalized)
                except (ValueError, UnicodeError):
                    ignored += 1
            if not targets:
                raise ValueError("El archivo no contiene objetivos válidos.")
            return path, targets, ignored
        self.line("Archivo UTF-8 con un objetivo por línea; se omiten comentarios y duplicados.")
        return self.ask("Ruta del archivo (0 para volver)", validator=validate)

    def batch_wizard(self):
        self.screen("Varios objetivos", "Paso 1 · Carga tu archivo. 0 para volver.")
        path, targets, ignored = self.load_batch()
        self.line(f"{len(targets)} objetivos preparados; {ignored} líneas inválidas o duplicadas omitidas.", "32")
        for key, mode in MODE_KEYS.items():
            self.item(key, *MODE_LABELS[mode])
        mode = MODE_KEYS[self.choose(MODE_KEYS, "Tipo de auditoría", "1")]
        args = self.fresh_args(mode)
        args.file = path
        if mode == "mikrotik":
            self.line("La versión indicada se aplicará a todos los equipos; déjala vacía si difieren.")
            args.routeros_version = self.version()
        self.review(Plan(args, targets, batch=True, ignored=ignored))

    def review(self, plan):
        while True:
            args = plan.args
            self.screen("Todo listo para revisar", "Paso 2 · Revisa las opciones y elige Iniciar.")
            self.line("Auditoría: " + MODE_LABELS[args.mode][0], "1;37")
            if args.offline:
                self.line("Objetivo: versión RouterOS, sin conexiones de red")
            elif plan.batch:
                self.line(f"Archivo: {args.file}")
                self.line(f"Objetivos: {len(plan.targets)} · omitidos/duplicados: {plan.ignored}")
                self.line("Vista previa: " + ", ".join(plan.targets[:4]))
            else:
                self.line("Objetivo: " + plan.targets[0])
            if args.mode == "mikrotik":
                self.line("RouterOS: " + (args.routeros_version or "detección por banners; puede no publicarse"))
            self.line(f"Tiempo por conexión: {args.timeout:g} s · conexiones: {args.threads}")
            if args.mode in ("web", "full", "mikrotik") and not args.offline:
                self.line(f"Web: {args.scheme.upper()} · puerto {args.web_port or 'predeterminado'}")
            if args.mode in ("ports", "full", "mikrotik") and not args.offline:
                self.line("Puertos TCP: " + (", ".join(map(str, args.ports)) if args.ports else "lista recomendada del modo"))
            active = [MODULE_LABELS[name] for name in self.core.MODES[args.mode] if name not in args.skip]
            self.line("Módulos: " + (", ".join(active) or "ninguno seleccionado"))
            if "rdap" in self.core.MODES[args.mode] and "rdap" not in args.skip:
                self.line("RDAP consultará el registro del objetivo a través de rdap.org.", "90")
            self.line(f"Reportes: {args.output} · {args.format.upper()}")
            self.line()
            self.item("1", "Iniciar auditoría")
            self.item("2", "Cambiar versión" if args.offline else "Cambiar archivo" if plan.batch else "Cambiar objetivo")
            self.item("3", "Ajustar opciones para esta auditoría")
            if args.mode == "mikrotik" and not args.offline:
                self.item("4", "Indicar o cambiar versión RouterOS")
            self.item("0", "Volver al menú principal")
            allowed = {"1", "2", "3"} | ({"4"} if args.mode == "mikrotik" and not args.offline else set())
            choice = self.choose(allowed, default="1")
            if choice == "1":
                if not active:
                    self.line("Activa al menos un módulo desde Ajustar opciones.", "33")
                    self.pause()
                    continue
                self.execute(plan)
                return
            elif choice == "2":
                try:
                    if args.offline:
                        args.routeros_version = self.version(True, args.routeros_version)
                    elif plan.batch:
                        args.file, plan.targets, plan.ignored = self.load_batch()
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
            self.screen("Opciones de esta auditoría" if local else "Preferencias de la sesión",
                        "Los cambios se aplican al volver; 0 para volver.")
            self.item("1", f"Tiempo por conexión: {args.timeout:g} segundos")
            self.item("2", f"Conexiones simultáneas: {args.threads}")
            self.item("3", f"Carpeta de reportes: {args.output}")
            self.item("4", f"Formato: {args.format.upper()}")
            if local and not args.offline:
                self.item("5", "Puertos TCP: " + (", ".join(map(str, args.ports)) if args.ports else "recomendados"))
                self.item("6", f"Web: {args.scheme.upper()} · puerto {args.web_port or 'predeterminado'}")
                self.item("7", "Elegir módulos")
                if args.mode == "mikrotik":
                    self.item("8", f"Puerto SSH: {args.ssh_port}")
            self.item("d", "Restablecer valores predeterminados")
            self.item("0", "Guardar y volver")
            keys = {"1", "2", "3", "4", "d"}
            if local and not args.offline:
                keys |= {"5", "6", "7"}
                if args.mode == "mikrotik":
                    keys.add("8")
            try:
                choice = self.choose(keys)
            except Back:
                return
            try:
                if choice == "1":
                    args.timeout = self.ask("Segundos (0.1 a 60)", args.timeout, self.core.timeout_value)
                elif choice == "2":
                    args.threads = self.ask("Conexiones (1 a 64)", args.threads, self.core.bounded_int(1, 64))
                elif choice == "3":
                    def directory(value):
                        path = Path(value.strip('"')).expanduser()
                        if path.exists() and not path.is_dir():
                            raise ValueError("Esa ruta es un archivo. Elige una carpeta.")
                        return path
                    args.output = self.ask("Carpeta", str(args.output), directory)
                elif choice == "4":
                    for key, label in (("1", "Todos: HTML + JSON + TXT"), ("2", "Solo HTML"),
                                       ("3", "Solo JSON"), ("4", "Solo TXT")):
                        self.item(key, label)
                    args.format = {"1": "all", "2": "html", "3": "json", "4": "txt"}[self.choose({"1", "2", "3", "4"})]
                elif choice == "5":
                    self.line("Ejemplo: 22,80,443. Escribe auto para la lista recomendada.")
                    raw = self.ask("Puertos", validator=lambda value: None if value.lower() == "auto" else self.core.port_list(value))
                    args.ports = raw
                elif choice == "6":
                    self.item("1", "HTTPS (cifrado)")
                    self.item("2", "HTTP")
                    scheme = {"1": "https", "2": "http"}[self.choose({"1", "2"})]
                    port = self.ask("Puerto web (auto para predeterminado)", "auto",
                                    lambda value: None if value.lower() == "auto" else self.core.bounded_int(1, 65535)(value))
                    self.set_web(args, scheme, port)
                elif choice == "7":
                    self.module_picker(args)
                elif choice == "8":
                    args.ssh_port = self.ask("Puerto SSH", args.ssh_port, self.core.bounded_int(1, 65535))
                else:
                    clean = self.core.parser().parse_args([])
                    for name in ("timeout", "threads", "output", "format", "ports", "scheme", "web_port", "ssh_port", "skip"):
                        setattr(args, name, deepcopy(getattr(clean, name)))
            except Back:
                continue

    def module_picker(self, args):
        while True:
            self.screen("Módulos de la auditoría", "Selecciona uno para activarlo/desactivarlo. 0 para volver.")
            modules = self.core.MODES[args.mode]
            for index, name in enumerate(modules, 1):
                self.item(str(index), f"[{' ' if name in args.skip else 'x'}] {MODULE_LABELS[name]}")
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
        self.screen("Auditoría en curso", "Los resultados terminados se guardan aunque canceles después.")
        completed_count = 0
        last_entry = None
        for index, target in enumerate(plan.targets, 1):
            self.line(f"Objetivo {index}/{len(plan.targets)} · {target}", "1;36")

            def progress(name, status, position, total):
                labels = {"running": "EN CURSO", "ok": "LISTO", "error": "ERROR", "skipped": "OMITIDO"}
                text = f"[{position}/{total}] {MODULE_LABELS[name]} · {labels[status]}"
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
                self.line(f"No se pudieron guardar los reportes: {exc}", "33")
                paths = []
            entry = {"report": report, "paths": paths}
            self.history.append(entry)
            self.history = self.history[-20:]
            completed_count += 1
            last_entry = entry
            self.summary(report)
            for path in paths:
                self.line(f"Guardado: {path}", "90")
            self.line()
        if completed_count == 1:
            self.viewer(last_entry)
        else:
            self.line(f"Batch terminado: {completed_count} objetivos. Consulta los recientes en Mis reportes.", "32")
            self.pause()

    def summary(self, report):
        modules = report.get("modules", {})
        errors = sum(item.get("status") == "error" for item in modules.values())
        done = sum(item.get("status") == "ok" for item in modules.values())
        skipped = sum(item.get("status") == "skipped" for item in modules.values())
        self.panel("RESUMEN", [(f"Comprobaciones: {done} terminadas / {errors} con error / {skipped} omitidas",
                                "33" if errors else "32")])
        for name, item in modules.items():
            label = MODULE_LABELS.get(name, name)
            if item.get("status") == "error":
                self.line(f"{label}: {self.explain_error(item.get('error', 'sin detalle'))}", "33")
                continue
            if item.get("status") == "skipped":
                self.line(f"{label}: omitido", "90")
                continue
            data = item.get("data", {})
            if not isinstance(data, dict):
                continue
            if name == "dns":
                self.line("Direcciones: " + ", ".join(data.get("addresses", [])))
            elif name == "rdap":
                self.line("Registro: " + str(data.get("name") or data.get("handle") or "respuesta disponible en el reporte"))
            elif name == "http":
                self.line(f"HTTP: {data.get('status', '?')} · {data.get('title') or 'sin título'}")
                missing = data.get("missing_headers", [])
                self.line("Cabeceras recomendadas ausentes: " + (", ".join(missing) if missing else "ninguna de las comprobadas"))
            elif name == "tls":
                self.line(f"TLS: {data.get('protocol')} · certificado verificado · {data.get('days_remaining')} días restantes")
            elif name == "ports":
                opened = [str(row.get("port")) for row in data.get("results", []) if row.get("state") == "open"]
                self.line("Puertos TCP accesibles: " + (", ".join(opened) if opened else "ninguno en la lista revisada"))
            elif name == "traceroute":
                self.line("Ruta de red: " + (data.get("reason", "no disponible") if data.get("status") == "unavailable" else "disponible en el detalle"))
            elif name == "mikrotik":
                self.routeros_summary(data)

    def routeros_summary(self, data):
        source = {"user_supplied": "indicada por ti", "public_banner": "banner público", "unknown": "no obtenida"}
        self.line(f"RouterOS: {data.get('version') or 'desconocida'} · {source.get(data.get('version_source'), 'sin fuente')}", "1;37")
        self.line("Catálogo revisado: " + str(data.get("catalog_reviewed", "sin fecha")), "90")
        groups = {state: [entry for entry in data.get("advisories", []) if entry.get("status") == state]
                  for state in ("potentially_affected", "not_in_affected_range", "unknown_version", "manual_review")}
        self.line(f"Avisos que podrían afectar esta versión: {len(groups['potentially_affected'])}",
                  "33" if groups['potentially_affected'] else "37")
        self.line(f"Avisos que no incluyen esta versión: {len(groups['not_in_affected_range'])}")
        self.line(f"Avisos sin evaluar: {len(groups['unknown_version']) + len(groups['manual_review'])}")
        for entry in groups["potentially_affected"]:
            self.line(f"[REVISAR] {entry['id']} · {entry.get('component', '')}", "33")
        if data.get("version_conflict"):
            self.line("Hay versiones contradictorias. Valida la versión en tu inventario.", "33")
        elif not data.get("version"):
            self.line("La versión no se publica. Indícala desde tu inventario para evaluar los avisos.", "33")
        if groups["potentially_affected"]:
            self.line("Siguiente paso: revisa los parches de tu rama y restringe los servicios de gestión.", "33")
        self.line("La comparación de versión no confirma explotación ni certifica que el router sea seguro.", "90")

    @staticmethod
    def explain_error(error):
        text = str(error)
        lower = text.lower()
        if any(word in lower for word in ("certificate_verify_failed", "certificate verify failed", "certificate failed")):
            return "No se pudo validar el certificado. Revisa su confianza, nombre y fecha."
        if any(word in lower for word in ("getaddrinfo", "name or service", "name resolution", "nodename nor servname")):
            return "No se pudo resolver el nombre. Revisa el objetivo y la conexión DNS."
        if "timed out" in lower or "timeout" in lower:
            return "No respondió dentro del tiempo configurado. Puedes aumentar la espera."
        if "connection refused" in lower or "actively refused" in lower:
            return "El equipo rechazó la conexión al servicio."
        return text

    def details(self, report):
        self.screen("Resultados explicados", str(report.get("meta", {}).get("target", "sin objetivo")))
        for name, module in report.get("modules", {}).items():
            self.panel(MODULE_LABELS.get(name, name).upper(),
                       [(MODULE_HELP.get(name, "Datos de la comprobación."), "90")])
            if module.get("status") == "skipped":
                self.line("Estado: omitido en las opciones del análisis.")
                continue
            if module.get("status") == "error":
                self.line("Estado: no se pudo completar.", "33")
                self.line(self.explain_error(module.get("error", "sin detalle")))
                self.line("Detalle del error: " + str(module.get("error", "sin detalle")), "90")
                continue
            data = module.get("data", {})
            self.summary({"modules": {name: module}})
            if name == "mikrotik":
                for entry in data.get("advisories", []):
                    self.line()
                    self.line(str(entry.get("id", "Aviso")) + " / " + str(entry.get("component", "")), "1;37")
                    self.line("Estado: " + ADVISORY_LABELS.get(entry.get("status"), "sin datos"))
                    self.line("Qué revisa: " + str(entry.get("summary", "consulta la fuente")))
                    if entry.get("status") == "potentially_affected" and data.get("version"):
                        import routeros
                        installed = routeros.parse_version(data["version"]).numbers
                        fixes = [row["fixed"] for row in entry.get("affected_ranges", [])
                                 if routeros.parse_version(row["introduced"]).numbers <= installed
                                 < routeros.parse_version(row["fixed"]).numbers]
                        if fixes:
                            self.line("Versión que corrige este aviso en esa rama: " + ", ".join(fixes), "33")
                    ports = entry.get("observed_default_ports", [])
                    self.line("Puertos asociados que respondieron: " + (", ".join(map(str, ports)) if ports else "no se estableció exposición"))
                    for source in entry.get("sources", []):
                        self.line("Fuente: " + str(source), "90")
            elif name == "ports":
                for row in data.get("results", []):
                    opened = row.get("state") == "open"
                    self.line(f"{'[RESPONDE]' if opened else '[NO ACCESIBLE]'} {row.get('port')}/TCP",
                              "32" if opened else "90")
                self.line("No accesible: la conexión falló; puede estar cerrado, filtrado o no responder.")
            elif name == "http":
                explanations = {"content-security-policy": "limita los recursos que la página puede cargar",
                                "strict-transport-security": "indica al navegador que use HTTPS",
                                "x-content-type-options": "evita adivinar el tipo de contenido",
                                "referrer-policy": "controla qué URL se comparte como referencia"}
                for header in data.get("missing_headers", []):
                    self.line(f"Ausente: {header} — {explanations.get(header, 'revisa la política del sitio')}")
            elif name == "traceroute" and data.get("output"):
                self.line(data["output"])
            elif name == "rdap":
                for key, label in (("handle", "Identificador"), ("name", "Nombre"),
                                   ("country", "País del registro"), ("startAddress", "IP inicial"),
                                   ("endAddress", "IP final")):
                    if data.get(key):
                        self.line(f"{label}: {data[key]}")
            self.line()

    def viewer(self, entry):
        while True:
            report = entry["report"]
            self.screen("Resumen del análisis", str(report.get("meta", {}).get("target", "sin objetivo")))
            try:
                self.summary(report)
            except (TypeError, KeyError, AttributeError):
                self.line("Este reporte no tiene un resumen compatible. Puedes consultar el detalle.", "33")
            self.line()
            self.item("1", "Ver resultados explicados")
            html_paths = [path for path in entry["paths"] if Path(path).suffix.lower() == ".html"]
            if html_paths:
                self.item("2", "Abrir reporte HTML en el navegador")
            self.item("3", "Ver rutas de los archivos")
            self.item("4", "Ver datos JSON (detalle técnico)")
            self.item("0", "Volver")
            try:
                choice = self.choose({"1", "3", "4"} | ({"2"} if html_paths else set()))
            except Back:
                return
            if choice == "1":
                try:
                    self.details(report)
                except (TypeError, KeyError, AttributeError, ValueError):
                    self.line("No se pudo interpretar parte de este reporte. Consulta sus datos JSON.", "33")
            elif choice == "2":
                try:
                    opened = webbrowser.open(Path(html_paths[0]).resolve().as_uri())
                    self.line("Reporte enviado al navegador." if opened else "No hay navegador disponible. Abre el archivo desde su ruta.")
                except (OSError, webbrowser.Error) as exc:
                    self.line(f"No se pudo abrir el navegador: {exc}", "33")
            elif choice == "4":
                self.screen("Datos JSON", "Información técnica completa del análisis.")
                self.line(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                if not entry["paths"]:
                    self.line("No se guardaron archivos; el resultado sigue disponible durante esta sesión.")
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
            self.screen("Mis reportes", "Hasta 20 resultados recientes; 0 para volver.")
            if not entries:
                self.line("Aún no hay reportes. Ejecuta una auditoría para ver sus resultados aquí.")
                self.line("Carpeta actual: " + str(self.defaults.output), "90")
                self.pause()
                return
            for index, entry in enumerate(entries, 1):
                meta = entry["report"].get("meta", {})
                self.item(str(index), str(meta.get("target", "sin objetivo")),
                          f"{meta.get('date', '')} · {meta.get('mode', '')}")
            key = self.choose({str(index) for index in range(1, len(entries) + 1)})
            self.viewer(entries[int(key) - 1])

    def diagnostics(self):
        self.screen("Diagnóstico de este equipo", "Esta comprobación no realiza conexiones de red.")
        data = self.core.doctor()
        self.line("Python: " + data["python"])
        self.line("Sistema: " + data["platform"])
        self.line("TLS: " + data["openssl"])
        self.line("Núcleo portable listo: no necesita root ni instalar paquetes pip.", "32")
        self.line()
        self.line("Herramientas opcionales:")
        for name, path in data["optional"].items():
            self.line(f"{'[OK]' if path else '[--]'} {name}: {path or 'no instalada (opcional)'}")
        self.pause()

    def classic(self):
        self.screen("Auditorías clásicas", "Módulos Bash de ISP, aplicaciones web y red local.")
        if os.name == "nt":
            self.line("Estos módulos necesitan un entorno Linux/WSL y sus herramientas.")
            self.line("Desde ese entorno ejecuta: bash domaininfo.sh --legacy")
            self.line("La auditoría MikroTik portable sigue disponible en la opción 5.")
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
            self.line("Falta Bash 4+ o herramientas clásicas: " + (", ".join(missing) or "Bash 4+"), "33")
            self.line("Instálalas desde la carpeta del proyecto: bash install.sh --legacy")
            self.pause()
            return
        self.line("Abrirás el menú clásico. Al salir volverás a este menú.")
        self.item("1", "Abrir menú clásico")
        self.item("0", "Volver")
        self.choose({"1"})
        try:
            script = Path(__file__).resolve().with_name("domaininfo.sh")
            subprocess.run([selected, str(script), "--legacy"], check=False)
        except OSError as exc:
            self.line(f"No se pudo abrir el menú clásico: {exc}", "33")
            self.pause()

    def help(self):
        self.screen("Guía rápida")
        self.line("1. Elige qué revisar. Para un router MikroTik usa la opción 5.")
        self.line("2. Indica el dominio/IP o revisa una versión RouterOS sin conexión.")
        self.line("3. Revisa el resumen. Puedes cambiar opciones antes de iniciar.")
        self.line("4. Consulta el resultado y sus reportes desde Mis reportes.")
        self.line()
        self.line("0 vuelve al menú anterior; CTRL+C cancela la acción en curso.")
        self.line("Las preferencias duran esta sesión; no necesitas escribir comandos.")
        self.line("En una URL se respeta protocolo y puerto; se revisa la raíz del sitio.")
        self.line("Usa los modos de red sobre equipos que tengas autorización para revisar.")
        self.pause()
