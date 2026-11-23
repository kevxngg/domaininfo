"""Tiny translation layer. English is the source language of every string in the code.

    from i18n import tr
    print(tr("Open ports: {ports}", ports="22, 443"))

Other languages live in catalog modules named ``i18n_<lang>_<part>.py`` that define
``STRINGS = {"English text": "Translated text"}``. Missing entries fall back to English,
so a partial catalog never breaks the tool. The language comes from ``set_language()``
(``--lang``), then the ``DOMAININFO_LANG`` environment variable, and defaults to English.
"""

import importlib
import os

SUPPORTED = ("en", "es")
_PARTS = ("ui", "modules", "phase2", "phase3", "phase4")
_current = None
_catalogs = {}


def _catalog(lang):
    if lang not in _catalogs:
        merged = {}
        for part in _PARTS:
            try:
                merged.update(importlib.import_module(f"i18n_{lang}_{part}").STRINGS)
            except ImportError:
                continue
        _catalogs[lang] = merged
    return _catalogs[lang]


def set_language(lang):
    """Select the output language ('en' or 'es'); unknown values fall back to English."""
    global _current
    _current = lang if lang in SUPPORTED else "en"


def language():
    if _current:
        return _current
    env = (os.environ.get("DOMAININFO_LANG") or "").strip().lower()[:2]
    return env if env in SUPPORTED else "en"


class Text(str):
    """A translated string that remembers its English ``source`` (used for language-independent ids)."""

    source = ""


def tr(text, **values):
    """Translate ``text`` into the current language and fill ``{placeholders}`` from ``values``."""
    source = text.format(**values) if values else text
    lang = language()
    if lang != "en":
        text = _catalog(lang).get(text, text)
    result = Text(text.format(**values) if values else text)
    result.source = source
    return result


def source(text):
    """English form of a string produced by ``tr()`` (the string itself otherwise)."""
    return getattr(text, "source", None) or str(text)


def catalog_problems(lang="es"):
    """Entries whose placeholders differ from the English text (used by the tests)."""
    import string
    problems = []
    for source, target in _catalog(lang).items():
        names = {f[1] for f in string.Formatter().parse(source) if f[1]}
        if names != {f[1] for f in string.Formatter().parse(target) if f[1]}:
            problems.append(source)
    return problems
