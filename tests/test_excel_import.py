from __future__ import annotations

import tempfile
import unittest
import zipfile
import re
import os
from pathlib import Path

from sbom_workbench.excel import ExcelImportError, import_pro03b


TEMPLATE_ENV = "SBOM_WORKBENCH_PRO03B_TEMPLATE"
_configured_template = os.environ.get(TEMPLATE_ENV)
TEMPLATE = Path(_configured_template).expanduser() if _configured_template else None


@unittest.skipUnless(
    TEMPLATE is not None and TEMPLATE.is_file(),
    f"external controlled PRO-03B fixture is unavailable; set {TEMPLATE_ENV}",
)
class Pro03BImportTests(unittest.TestCase):
    def _rewrite(self, destination: Path, transform) -> None:
        assert TEMPLATE is not None
        with zipfile.ZipFile(TEMPLATE) as source, zipfile.ZipFile(
            destination, "w", compression=zipfile.ZIP_DEFLATED
        ) as target:
            for entry in source.infolist():
                if entry.is_dir():
                    continue
                name, payload = transform(entry.filename, source.read(entry))
                target.writestr(name, payload)

    def test_real_template_is_read_only_manual_claim_input(self) -> None:
        assert TEMPLATE is not None
        result = import_pro03b(TEMPLATE)
        self.assertEqual(result["template_profile"], "PRO-03B-v1.4")
        self.assertEqual(result["intake_status"], "TEMPLATE_OR_INCOMPLETE_CUSTOMER_INPUT")
        self.assertFalse(result["build_inclusion_proven"])
        self.assertEqual(len(result["software_claims"]), 6)
        self.assertEqual(len(result["hardware_claims"]), 4)

    def test_macro_part_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            target = Path(directory_name) / "macro.xlsx"
            self._rewrite(target, lambda name, payload: (name, payload))
            with zipfile.ZipFile(target, "a") as archive:
                archive.writestr("xl/vbaProject.bin", b"not executable test data")
            with self.assertRaisesRegex(ExcelImportError, "macros"):
                import_pro03b(target)

    def test_formula_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            target = Path(directory_name) / "formula.xlsx"

            def transform(name: str, payload: bytes) -> tuple[str, bytes]:
                if name == "xl/worksheets/sheet1.xml":
                    payload = payload.replace(b"<v>", b"<f>1+1</f><v>", 1)
                return name, payload

            self._rewrite(target, transform)
            with self.assertRaisesRegex(ExcelImportError, "formulas"):
                import_pro03b(target)

    def test_external_link_part_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            target = Path(directory_name) / "external.xlsx"
            self._rewrite(target, lambda name, payload: (name, payload))
            with zipfile.ZipFile(target, "a") as archive:
                archive.writestr("xl/externalLinks/externalLink1.xml", b"<externalLink/>")
            with self.assertRaisesRegex(ExcelImportError, "external"):
                import_pro03b(target)

    def test_sparse_out_of_profile_column_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            target = Path(directory_name) / "sparse.xlsx"

            def transform(name: str, payload: bytes) -> tuple[str, bytes]:
                if name == "xl/worksheets/sheet1.xml":
                    payload = payload.replace(b'r="A1"', b'r="XFE1"', 1)
                return name, payload

            self._rewrite(target, transform)
            with self.assertRaisesRegex(ExcelImportError, "bounded template range"):
                import_pro03b(target)

    def test_duplicate_cell_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            target = Path(directory_name) / "duplicate-cell.xlsx"

            def transform(name: str, payload: bytes) -> tuple[str, bytes]:
                if name == "xl/worksheets/sheet1.xml":
                    match = re.search(br"(<c\b[^>]*\br=\"A1\".*?</c>)", payload)
                    self.assertIsNotNone(match)
                    payload = payload.replace(match.group(1), match.group(1) + match.group(1), 1)
                return name, payload

            self._rewrite(target, transform)
            with self.assertRaisesRegex(ExcelImportError, "duplicate cell"):
                import_pro03b(target)


if __name__ == "__main__":
    unittest.main()
