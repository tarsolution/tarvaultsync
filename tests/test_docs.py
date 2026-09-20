"""Keep the static guide self-contained and its published links valid."""

from html.parser import HTMLParser
from pathlib import Path
import unittest
import importlib.util
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
    def test_catalogue_pages(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("index.html", "releases.html", "credits.html"):
            source = (root / "docs" / name).read_text(encoding="utf-8")
            parser = GuideParser()
            parser.feed(source)
            self.assertFalse(parser.scripts)
            self.assertIn("A TAR Solution project", source)
            self.assertIn("Developed by fmarslan.com", source)
            for target in ("https://fmarslan.com/", "releases.html", "credits.html"):
                self.assertIn(target, parser.links)
            for target in parser.links:
                parts = urlsplit(target)
                if not parts.scheme and parts.path:
                    self.assertTrue((root / "docs" / parts.path).is_file(), target)
        spec = importlib.util.spec_from_file_location("catalog", root / "scripts/update-docs-catalog.py")
        catalog = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(catalog)
        empty = catalog.releases_content([])
        self.assertIn("No stable release", empty)
        records = [dict(name="<Preview>", tag_name="v2", html_url="https://github.com/test/release",
                        published_at="2026-09-20T00:00:00Z", prerelease=True),
                   dict(name="Stable", tag_name="v1", html_url="https://github.com/test/stable",
                        published_at="2026-09-19T00:00:00Z", prerelease=False)]
        rendered = catalog.releases_content(records)
        latest, archive = rendered.split('id="archive"')
        self.assertIn("Stable", latest)
        self.assertNotIn("&lt;Preview&gt;", latest)
        self.assertIn("&lt;Preview&gt;", archive)
        self.assertIn("Pre-release", archive)
        with self.assertRaises(ValueError):
            catalog.link("javascript:alert(1)", "unsafe")

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
