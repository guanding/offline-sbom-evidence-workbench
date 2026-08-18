"""Unit tests for the zero-components-Python-project finding detector (M9-1).

The detector is a pure function over the source directory tree and the
component count from the CycloneDX projection; it does not invoke Syft. These
tests cover the four branches of the trigger condition plus the exclude-dir
rule and the declaration-file recognition set.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sbom_workbench.cli import (
    _DECLARED_C_CPP_DEPENDENCY_FILES,
    _DECLARED_PYTHON_DEPENDENCY_FILES,
    _detect_requirements_r_reference,
    _detect_zero_components_c_cpp_findings,
    _detect_zero_components_python_findings,
    _extract_home_assistant_manifest_deps,
    _extract_import_evidence,
)


class DetectZeroComponentsPythonFindingsTests(unittest.TestCase):
    def _write_main_py(self, root: Path) -> None:
        (root / "main.py").write_text("import pygame\n", encoding="utf-8")

    def test_zero_components_with_python_and_no_declaration_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_py(root)
            findings = _detect_zero_components_python_findings(root, 0)
            self.assertTrue(findings["zero_components_python_project"])
            self.assertEqual(findings["component_count"], 0)
            self.assertTrue(findings["python_source_files_present"])
            self.assertFalse(findings["declared_dependency_files_present"])

    def test_nonzero_components_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_py(root)
            findings = _detect_zero_components_python_findings(root, 3)
            self.assertFalse(findings["zero_components_python_project"])
            self.assertEqual(findings["component_count"], 3)

    def test_zero_components_with_declaration_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_py(root)
            (root / "requirements.txt").write_text("pygame\n", encoding="utf-8")
            findings = _detect_zero_components_python_findings(root, 0)
            self.assertFalse(findings["zero_components_python_project"])
            self.assertTrue(findings["declared_dependency_files_present"])

    def test_zero_components_without_python_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            findings = _detect_zero_components_python_findings(root, 0)
            self.assertFalse(findings["zero_components_python_project"])
            self.assertFalse(findings["python_source_files_present"])

    def test_python_files_under_venv_and_pycache_are_excluded(self) -> None:
        # A stray .py inside .venv/__pycache__/build must NOT count as project
        # source; only a top-level (or non-excluded) .py does.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".venv" / "lib").mkdir(parents=True)
            (root / ".venv" / "lib" / "installed.py").write_text("x = 1\n", encoding="utf-8")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "cached.py").write_text("x = 1\n", encoding="utf-8")
            findings = _detect_zero_components_python_findings(root, 0)
            self.assertFalse(findings["python_source_files_present"])
            self.assertFalse(findings["zero_components_python_project"])

    def test_nested_source_python_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "pkg").mkdir(parents=True)
            (root / "src" / "pkg" / "module.py").write_text("import os\n", encoding="utf-8")
            findings = _detect_zero_components_python_findings(root, 0)
            self.assertTrue(findings["python_source_files_present"])
            self.assertTrue(findings["zero_components_python_project"])

    def test_each_recognized_declaration_file_suppresses_trigger(self) -> None:
        for declaration in _DECLARED_PYTHON_DEPENDENCY_FILES:
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._write_main_py(root)
                    (root / declaration).write_text("placeholder\n", encoding="utf-8")
                    findings = _detect_zero_components_python_findings(root, 0)
                    self.assertTrue(findings["declared_dependency_files_present"])
                    self.assertFalse(findings["zero_components_python_project"])


class ImportEvidenceTests(unittest.TestCase):
    """M9-2: deterministic import extraction → apparent gap vs SBOM."""

    def _extract(
        self,
        files: dict[str, str],
        sbom_names: frozenset[str] | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return _extract_import_evidence(root, sbom_names or frozenset())

    def test_third_party_import_kept_and_reported_as_gap(self) -> None:
        result = self._extract({"main.py": "import pygame\n"}, frozenset())
        self.assertIn("pygame", result["imported_third_party_modules"])
        self.assertIn("pygame", result["apparent_gaps"])

    def test_stdlib_modules_filtered(self) -> None:
        result = self._extract(
            {"main.py": "import os\nimport sys\nimport json\nfrom abc import ABC\n"},
            frozenset(),
        )
        self.assertEqual(result["imported_third_party_modules"], [])

    def test_relative_import_filtered(self) -> None:
        result = self._extract(
            {"pkg/mod.py": "from . import sibling\nfrom .sub import thing\n"},
            frozenset(),
        )
        self.assertEqual(result["imported_third_party_modules"], [])

    def test_local_module_filtered(self) -> None:
        # localmod.py exists in the project → `import localmod` is local, not
        # third-party, so it must not appear as an imported third-party module.
        result = self._extract(
            {"main.py": "import localmod\n", "localmod.py": "x = 1\n"},
            frozenset(),
        )
        self.assertNotIn("localmod", result["imported_third_party_modules"])

    def test_local_namespace_package_directory_filtered(self) -> None:
        # source/ is a namespace package (contains .py, no __init__.py);
        # `import source` is local, not third-party. Regression for the
        # PythonPlantsVsZombies smoke test where `source` was mis-reported.
        result = self._extract(
            {"main.py": "import source\n", "source/foo.py": "x = 1\n"},
            frozenset(),
        )
        self.assertNotIn("source", result["imported_third_party_modules"])

    def test_module_present_in_sbom_not_a_gap(self) -> None:
        result = self._extract({"main.py": "import fastapi\n"}, frozenset({"fastapi"}))
        self.assertIn("fastapi", result["imported_third_party_modules"])
        self.assertNotIn("fastapi", result["apparent_gaps"])

    def test_dotted_import_uses_top_level(self) -> None:
        result = self._extract(
            {"main.py": "from xml.etree import ElementTree\nimport requests.models\n"},
            frozenset(),
        )
        # xml is stdlib → filtered; requests is third-party → kept as top level
        self.assertIn("requests", result["imported_third_party_modules"])
        self.assertNotIn("xml", result["imported_third_party_modules"])

    def test_boundary_and_heuristic_labels_present(self) -> None:
        result = self._extract({"main.py": "import pygame\n"}, frozenset())
        self.assertIn("AUXILIARY_NOT_SBOM", result["boundary"])
        self.assertTrue(result["heuristic"])


class DetectRequirementsRReferenceTests(unittest.TestCase):
    """M9 extension: detect `-r <file>` / `--requirement <file>` references in
    requirements*.txt that syft 1.50.0 does not follow. Advisory: surfaces the
    blind spot, does not patch the SBOM."""

    def _detect(self, files: dict[str, str]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return _detect_requirements_r_reference(root)

    def test_r_reference_detected(self) -> None:
        r = self._detect({"requirements.txt": "-r requirements/prod.txt\n"})
        self.assertTrue(r["requirements_r_reference_present"])
        self.assertIn("requirements/prod.txt", r["referenced_files"])

    def test_long_form_requirement_flag_detected(self) -> None:
        r = self._detect({"requirements.txt": "--requirement base.txt\n"})
        self.assertTrue(r["requirements_r_reference_present"])
        self.assertIn("base.txt", r["referenced_files"])

    def test_plain_requirements_no_reference(self) -> None:
        r = self._detect({"requirements.txt": "flask==2.2.3\nrequests\n"})
        self.assertFalse(r["requirements_r_reference_present"])
        self.assertEqual(r["referenced_files"], [])

    def test_no_requirements_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = _detect_requirements_r_reference(Path(tmp))
            self.assertFalse(r["requirements_r_reference_present"])

    def test_requirements_in_subdirectory_scanned(self) -> None:
        r = self._detect({"requirements/dev.txt": "-r common.in\n"})
        self.assertTrue(r["requirements_r_reference_present"])

    def test_requirements_under_venv_excluded(self) -> None:
        r = self._detect({".venv/requirements.txt": "-r x.txt\n"})
        self.assertFalse(r["requirements_r_reference_present"])


class DetectZeroComponentsCCppFindingsTests(unittest.TestCase):
    """M9 extension: detect C/C++ source-only projects that yield zero
    components because syft has no package-manager declaration to consume
    (was Python-only)."""

    def _write_main_cpp(self, root: Path) -> None:
        (root / "main.cpp").write_text("int main(){return 0;}\n", encoding="utf-8")

    def test_zero_components_with_cpp_and_no_declaration_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_cpp(root)
            f = _detect_zero_components_c_cpp_findings(root, 0)
            self.assertTrue(f["zero_components_c_cpp_project"])
            self.assertTrue(f["c_cpp_source_files_present"])
            self.assertFalse(f["declared_dependency_files_present"])

    def test_zero_components_with_platformio_ini_not_triggered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_cpp(root)
            (root / "platformio.ini").write_text("[env]\n", encoding="utf-8")
            f = _detect_zero_components_c_cpp_findings(root, 0)
            self.assertFalse(f["zero_components_c_cpp_project"])
            self.assertTrue(f["declared_dependency_files_present"])

    def test_zero_components_without_c_cpp_not_triggered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("import os\n", encoding="utf-8")
            f = _detect_zero_components_c_cpp_findings(root, 0)
            self.assertFalse(f["c_cpp_source_files_present"])
            self.assertFalse(f["zero_components_c_cpp_project"])

    def test_nonzero_components_not_triggered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_main_cpp(root)
            f = _detect_zero_components_c_cpp_findings(root, 5)
            self.assertFalse(f["zero_components_c_cpp_project"])

    def test_each_recognized_declaration_file_suppresses_trigger(self) -> None:
        for declaration in _DECLARED_C_CPP_DEPENDENCY_FILES:
            with self.subTest(declaration=declaration):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._write_main_cpp(root)
                    (root / declaration).write_text("placeholder\n", encoding="utf-8")
                    f = _detect_zero_components_c_cpp_findings(root, 0)
                    self.assertTrue(f["declared_dependency_files_present"])
                    self.assertFalse(f["zero_components_c_cpp_project"])

    def test_header_only_project_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.h").write_text("#pragma once\n", encoding="utf-8")
            f = _detect_zero_components_c_cpp_findings(root, 0)
            self.assertTrue(f["c_cpp_source_files_present"])
            self.assertTrue(f["zero_components_c_cpp_project"])


class HomeAssistantManifestDepsTests(unittest.TestCase):
    """M9 extension: detect Home Assistant manifest.json `requirements` deps
    that syft source-only does not consume. AUXILIARY: never enters CycloneDX."""

    def _extract(
        self,
        files: dict[str, str],
        sbom_names: frozenset[str] | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return _extract_home_assistant_manifest_deps(root, sbom_names or frozenset())

    def test_ha_manifest_requirements_reported_as_gap(self) -> None:
        r = self._extract(
            {"manifest.json": '{"domain":"x","requirements":["example-ha-client==0.3.17"]}'},
            frozenset(),
        )
        self.assertTrue(r["home_assistant_manifest_present"])
        self.assertIn("example-ha-client", r["manifest_dependencies"])
        self.assertIn("example-ha-client", r["apparent_gaps"])

    def test_requirement_present_in_sbom_not_a_gap(self) -> None:
        r = self._extract(
            {"manifest.json": '{"domain":"x","requirements":["foo>=1.0"]}'},
            frozenset({"foo"}),
        )
        self.assertEqual(r["apparent_gaps"], [])

    def test_manifest_without_domain_not_ha(self) -> None:
        r = self._extract({"manifest.json": '{"version":"1.0"}'}, frozenset())
        self.assertFalse(r["home_assistant_manifest_present"])

    def test_no_manifest_returns_absent(self) -> None:
        r = self._extract({"main.py": "x=1\n"}, frozenset())
        self.assertFalse(r["home_assistant_manifest_present"])

    def test_empty_requirements_no_gap(self) -> None:
        r = self._extract(
            {"manifest.json": '{"domain":"x","requirements":[]}'},
            frozenset(),
        )
        self.assertEqual(r["apparent_gaps"], [])

    def test_multiple_requirements_all_extracted(self) -> None:
        r = self._extract(
            {"manifest.json": '{"domain":"x","requirements":["a==1.0","b>=2.0","c"]}'},
            frozenset({"b"}),
        )
        self.assertEqual(r["manifest_dependencies"], ["a", "b", "c"])
        self.assertEqual(r["apparent_gaps"], ["a", "c"])

    def test_boundary_label_present(self) -> None:
        r = self._extract(
            {"manifest.json": '{"domain":"x","requirements":["foo"]}'},
            frozenset(),
        )
        self.assertIn("AUXILIARY_NOT_SBOM", r["boundary"])


if __name__ == "__main__":
    unittest.main()
