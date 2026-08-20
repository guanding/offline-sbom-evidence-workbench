from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


STATIC_ROOT = Path(__file__).resolve().parents[1] / "src" / "sbom_workbench" / "static"


class StaticHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.labels: set[str] = set()
        self.controls: list[tuple[str, dict[str, str]]] = []
        self.asset_paths: list[str] = []
        self.inline_handlers: list[str] = []
        self.inline_script_count = 0
        self._inside_script_without_src = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if "id" in values:
            self.ids.append(values["id"])
        if tag == "label" and values.get("for"):
            self.labels.add(values["for"])
        if tag in {"button", "input", "select", "textarea"}:
            self.controls.append((tag, values))
        for key in values:
            if key.casefold().startswith("on"):
                self.inline_handlers.append(key)
        if tag == "script":
            source = values.get("src")
            if source:
                self.asset_paths.append(source)
            else:
                self._inside_script_without_src = True
        if tag == "link" and values.get("href"):
            self.asset_paths.append(values["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inside_script_without_src:
            self.inline_script_count += 1
            self._inside_script_without_src = False


class WebStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
        cls.css = (STATIC_ROOT / "style.css").read_text(encoding="utf-8")
        cls.javascript = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")
        cls.parser = StaticHTMLParser()
        cls.parser.feed(cls.html)

    def test_document_ids_are_unique_and_required_views_exist(self) -> None:
        self.assertEqual(len(self.parser.ids), len(set(self.parser.ids)))
        for required in {
            "scan-form",
            "files-input",
            "folder-input",
            "download-list",
            "generate-view",
            "evidence-view",
        }:
            self.assertIn(required, self.parser.ids)
        self.assertIn('<html lang="zh-CN">', self.html)

    def test_assets_are_same_origin_and_packaged(self) -> None:
        self.assertGreaterEqual(len(self.parser.asset_paths), 3)
        for reference in self.parser.asset_paths:
            self.assertTrue(reference.startswith("/static/"), reference)
            self.assertNotIn("..", reference)
            self.assertTrue((STATIC_ROOT / reference.removeprefix("/static/")).is_file())
        self.assertNotRegex(self.html, r"https?://")
        self.assertEqual(self.parser.inline_script_count, 0)
        self.assertEqual(self.parser.inline_handlers, [])

    def test_form_controls_have_programmatic_names(self) -> None:
        for tag, attributes in self.parser.controls:
            if attributes.get("type") == "hidden":
                continue
            control_id = attributes.get("id")
            named = bool(
                attributes.get("aria-label")
                or attributes.get("aria-labelledby")
                or (control_id and control_id in self.parser.labels)
                or (attributes.get("type") == "radio" and attributes.get("name"))
                or tag == "button"
            )
            self.assertTrue(named, f"unnamed control: {tag} {attributes}")

    def test_javascript_uses_no_html_injection_or_dynamic_code_sink(self) -> None:
        for forbidden in (
            ".innerHTML",
            ".outerHTML",
            "document.write",
            "eval(",
            "new Function",
        ):
            self.assertNotIn(forbidden, self.javascript)
        self.assertIn(".textContent", self.javascript)
        self.assertIn("replaceChildren", self.javascript)
        self.assertIn('target.origin !== window.location.origin', self.javascript)

    def test_responsive_focus_and_reduced_motion_contracts_exist(self) -> None:
        self.assertIn(":focus-visible", self.css)
        self.assertIn("prefers-reduced-motion: reduce", self.css)
        self.assertRegex(self.css, r"@media\s*\(max-width:\s*31rem\)")
        self.assertIn("min-height: 2.75rem", self.css)

    def test_candidate_boundary_and_receipt_are_visible_in_ui_contract(self) -> None:
        combined = self.html + self.javascript
        for phrase in ("单一源码面", "不构成制造商授权", "scan-receipt"):
            self.assertIn(phrase, combined)
        self.assertNotRegex(combined.casefold(), re.compile(r"t[üu]v\s*rheinland"))


if __name__ == "__main__":
    unittest.main()
