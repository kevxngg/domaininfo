"""Translation layer: English by default, Spanish catalog consistent with the English source."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import i18n  # noqa: E402


class I18nTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en")

    def test_english_is_default(self):
        i18n._current = None
        with patch.dict(os.environ, {"DOMAININFO_LANG": ""}):
            self.assertEqual(i18n.language(), "en")
            self.assertEqual(i18n.tr("Open ports: {ports}", ports="22"), "Open ports: 22")

    def test_environment_and_override(self):
        i18n._current = None
        with patch.dict(os.environ, {"DOMAININFO_LANG": "es_ES.UTF-8"}):
            self.assertEqual(i18n.language(), "es")
        i18n.set_language("xx")
        self.assertEqual(i18n.language(), "en")

    def test_missing_translation_falls_back(self):
        i18n.set_language("es")
        self.assertEqual(i18n.tr("A sentence nobody translated {x}", x=1), "A sentence nobody translated 1")

    def test_catalog_placeholders_match(self):
        self.assertEqual(i18n.catalog_problems("es"), [])


if __name__ == "__main__":
    unittest.main()
