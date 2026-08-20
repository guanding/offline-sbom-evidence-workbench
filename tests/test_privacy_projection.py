from __future__ import annotations

import unittest

from sbom_workbench.privacy_projection import _replace_strings, _sensitive_path_count


class PrivacyProjectionTests(unittest.TestCase):
    def test_only_declared_root_is_normalized_recursively(self) -> None:
        source_root = "/" + "Users/alice/work/repo"
        value = {
            "name": source_root + "/go.mod",
            "nested": [source_root + "/src/main.go", "pkg:npm/example@1.0.0"],
        }
        projected, count = _replace_strings(value, (source_root,))
        self.assertEqual(count, 2)
        self.assertEqual(projected["name"], "${SOURCE_ROOT}/go.mod")
        self.assertEqual(projected["nested"][1], "pkg:npm/example@1.0.0")

    def test_residual_home_paths_are_counted(self) -> None:
        value = {
            "mac": "/" + "Users/alice/other/file",
            "linux": "/home/bob/repo/file",
            "safe": "${SOURCE_ROOT}/file",
        }
        self.assertEqual(_sensitive_path_count(value), 2)


if __name__ == "__main__":
    unittest.main()
