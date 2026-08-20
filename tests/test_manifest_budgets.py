from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sbom_workbench.manifest import ManifestError, build_bounded_exact_set_manifest


class BoundedExactSetManifestTests(unittest.TestCase):
    def test_within_budget_matches_expected_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.txt").write_text("abc", encoding="utf-8")
            manifest = build_bounded_exact_set_manifest(
                root,
                "source",
                max_files=2,
                max_total_bytes=10,
                max_single_file_bytes=10,
                max_depth=2,
            )
        self.assertEqual(manifest["file_count"], 1)
        self.assertEqual(manifest["total_bytes"], 3)

    def test_file_count_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a").write_text("a", encoding="utf-8")
            (root / "b").write_text("b", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "max_files"):
                build_bounded_exact_set_manifest(
                    root,
                    "source",
                    max_files=1,
                    max_total_bytes=10,
                    max_single_file_bytes=10,
                    max_depth=2,
                )

    def test_total_and_single_file_budgets_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "large").write_bytes(b"12345")
            with self.assertRaisesRegex(ManifestError, "max_single_file_bytes"):
                build_bounded_exact_set_manifest(
                    root,
                    "source",
                    max_files=2,
                    max_total_bytes=10,
                    max_single_file_bytes=4,
                    max_depth=2,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").write_bytes(b"123")
            (root / "two").write_bytes(b"456")
            with self.assertRaisesRegex(ManifestError, "max_total_bytes"):
                build_bounded_exact_set_manifest(
                    root,
                    "source",
                    max_files=2,
                    max_total_bytes=4,
                    max_single_file_bytes=3,
                    max_depth=2,
                )

    def test_depth_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "a" / "b"
            nested.mkdir(parents=True)
            (nested / "c").write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "max_depth"):
                build_bounded_exact_set_manifest(
                    root,
                    "source",
                    max_files=2,
                    max_total_bytes=10,
                    max_single_file_bytes=10,
                    max_depth=2,
                )


if __name__ == "__main__":
    unittest.main()
