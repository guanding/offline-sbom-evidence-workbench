from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.source_audit import analyze_source_ecosystems


def _manifest(paths: list[str]) -> dict[str, object]:
    return {"files": [{"relative_path": path} for path in paths]}


def _projection(
    components: list[dict[str, object]],
    dependencies: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {"components": components, "dependencies": dependencies or []}


class SourceEcosystemAuditTests(unittest.TestCase):
    def _audit(
        self,
        files: dict[str, str],
        components: list[dict[str, object]],
        dependencies: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            raw = root.parent / f"{root.name}-raw.json"
            raw.write_text(json.dumps({"components": components}), encoding="utf-8")
            try:
                return analyze_source_ecosystems(
                    root,
                    _manifest(list(files)),
                    _projection(components, dependencies),
                    raw,
                )
            finally:
                raw.unlink()

    def test_ci_components_cannot_mask_missing_composer_dependencies(self) -> None:
        result = self._audit(
            {"composer.json": '{"require":{"slim/slim":"^4.0"}}'},
            [
                {
                    "type": "library",
                    "name": "actions/checkout",
                    "version": "v4",
                    "purl": "pkg:github/actions/checkout@v4",
                },
                {"type": "file", "name": ".github/workflows/test.yml", "purl": None},
            ],
        )
        self.assertEqual(result["component_scope"]["total_component_count"], 2)
        self.assertEqual(result["component_scope"]["product_package_candidate_count"], 0)
        self.assertIn(
            "NONZERO_TOTAL_MASKS_ZERO_PRODUCT_PACKAGE_COMPONENTS_REVIEW",
            result["findings"],
        )
        self.assertIn("DECLARED_DEPENDENCIES_NOT_REPRESENTED_REVIEW", result["findings"])
        self.assertEqual(result["release_quality_handoff"], "BLOCKED")

    def test_nested_dotnet_manifest_and_package_reference_are_detected(self) -> None:
        result = self._audit(
            {
                "src/App/App.csproj": (
                    '<Project><ItemGroup><PackageReference Include="Serilog" '
                    'Version="4.0.0" /></ItemGroup></Project>'
                )
            },
            [],
        )
        evidence = result["manifest_evidence"]["dotnet"]
        self.assertEqual(evidence["manifest_paths"], ["src/App/App.csproj"])
        self.assertEqual(evidence["declared_dependency_names"], ["Serilog"])
        self.assertIn("DECLARED_DEPENDENCIES_NOT_REPRESENTED_REVIEW", result["findings"])

    def test_go_packages_without_relationship_edges_are_held_for_review(self) -> None:
        result = self._audit(
            {"go.mod": "module example.test/app\nrequire example.test/dep v1.2.3\n"},
            [
                {
                    "type": "library",
                    "name": "example.test/dep",
                    "version": "v1.2.3",
                    "purl": "pkg:golang/example.test/dep@v1.2.3",
                }
            ],
        )
        self.assertEqual(result["component_scope"]["product_package_candidate_count"], 1)
        self.assertIn("DEPENDENCY_RELATIONSHIPS_ABSENT_REVIEW", result["findings"])

    def test_relationship_edges_clear_missing_relationship_finding(self) -> None:
        result = self._audit(
            {"go.mod": "module example.test/app\nrequire example.test/dep v1.2.3\n"},
            [
                {
                    "bom_ref": "dep",
                    "type": "library",
                    "name": "example.test/dep",
                    "version": "v1.2.3",
                    "purl": "pkg:golang/example.test/dep@v1.2.3",
                }
            ],
            [{"ref": "root", "depends_on": ["dep"], "provides": []}],
        )
        self.assertNotIn("DEPENDENCY_RELATIONSHIPS_ABSENT_REVIEW", result["findings"])

    def test_zephyr_west_projects_are_advisory_declared_dependencies(self) -> None:
        result = self._audit(
            {
                "west.yml": (
                    "manifest:\n  projects:\n    - name: zephyr\n      revision: main\n"
                    "      import:\n        name-allowlist:\n          - cmsis_6\n"
                    "          - hal_stm32 # board support\n"
                )
            },
            [],
        )
        self.assertEqual(
            result["manifest_evidence"]["zephyr-west"]["declared_dependency_names"],
            ["cmsis_6", "hal_stm32", "zephyr"],
        )

    def test_absolute_source_path_is_counted_without_echoing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "go.mod").write_text("module example.test/app\n", encoding="utf-8")
            raw = root.parent / f"{root.name}-raw.json"
            raw.write_text(json.dumps({"name": str(root / "go.mod")}), encoding="utf-8")
            try:
                result = analyze_source_ecosystems(
                    root,
                    _manifest(["go.mod"]),
                    _projection([]),
                    raw,
                )
            finally:
                raw.unlink()
        self.assertGreater(result["absolute_source_path_occurrences_in_raw_cyclonedx"], 0)
        self.assertIn("ABSOLUTE_LOCAL_PATH_IN_RAW_SBOM_REVIEW", result["findings"])


if __name__ == "__main__":
    unittest.main()
