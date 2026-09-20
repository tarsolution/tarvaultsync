"""Keep the static guide self-contained and its published links valid."""

from html.parser import HTMLParser
from pathlib import Path
import unittest
from urllib.parse import urlsplit


class GuideParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.scripts = []
        self.images = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            if key in attrs:
                self.links.append(attrs[key])
        if tag == "script":
            self.scripts.append(attrs)
        if tag == "img":
            self.images.append(attrs)


class GuideTests(unittest.TestCase):
    def test_static_guide_assets_and_navigation(self):
        root = Path(__file__).resolve().parents[1] / "docs"
        parser = GuideParser()
        parser.feed((root / "index.html").read_text(encoding="utf-8"))
        self.assertFalse(parser.scripts, "The guide must remain static and script-free")
        self.assertIn("https://fmarslan.com/", parser.links)
        self.assertEqual(len(parser.images), 7)
        for image in parser.images:
            self.assertIn("alt", image)
        for link in parser.links:
            parts = urlsplit(link)
            if parts.scheme:
                self.assertEqual(parts.scheme, "https")
            elif parts.path:
                target = (root / parts.path).resolve()
                self.assertTrue(target.is_relative_to(root.resolve()))
                self.assertTrue(target.is_file(), link)
            elif parts.fragment:
                self.assertIn(parts.fragment, parser.ids)
        self.assertEqual((root / "CNAME").read_text().strip(), "tarvault.tarsolution.com")


if __name__ == "__main__":
    unittest.main()
