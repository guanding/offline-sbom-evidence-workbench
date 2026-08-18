from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.evidence import canonical_graph_sha256
from sbom_workbench.exporters import ExportError, export_pair
from sbom_workbench.manifest import canonical_json_bytes
from sbom_workbench.pack import (
    PackError,
    verify_analysis_package,
    verify_run_package,
    write_analysis_package,
    write_run_package,
)
from sbom_workbench.resources import ResourceError, vendor_specs_root
from sbom_workbench.validation import validate_cyclonedx, validate_export_pair, validate_spdx
from sbom_workbench.workflow import analyze_fixture, diff_graphs


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "synthetic_orion"


def _has_byo_vendor_specs() -> bool:
    try:
        vendor_specs_root()
    except ResourceError:
        return False
    return True


requires_byo_vendor_specs = unittest.skipUnless(
    _has_byo_vendor_specs(),
    "BYO CycloneDX/SPDX validation specs are unavailable in the public source set",
)


class ExportWorkflowTests(unittest.TestCase):
    @requires_byo_vendor_specs
    def test_release_a_is_closed_and_both_formats_validate(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        self.assertEqual(graph["reconciliation"]["state"], "CLOSED")
        cyclonedx, spdx = export_pair(graph)
        report = validate_export_pair(cyclonedx, spdx, expected_graph=graph)
        self.assertEqual(report["status"], "MECHANICALLY_VALID")
        self.assertEqual(len(cyclonedx["dependencies"]), 7)
        self.assertTrue(all(item["ref"] for item in cyclonedx["dependencies"]))

    def test_three_runs_have_identical_canonical_graph_and_exports(self) -> None:
        graphs = [analyze_fixture(FIXTURES / "release-a") for _ in range(3)]
        self.assertEqual(len({graph["canonical_sha256"] for graph in graphs}), 1)
        self.assertEqual(export_pair(graphs[0]), export_pair(graphs[1]))
        self.assertEqual(export_pair(graphs[1]), export_pair(graphs[2]))

    def test_candidate_relationship_omission_blocks_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            fixture = Path(directory_name) / "release-a"
            shutil.copytree(FIXTURES / "release-a", fixture)
            candidate_path = fixture / "candidate-sbom.json"
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            candidate["relationships"] = candidate["relationships"][1:]
            candidate_path.write_text(
                json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            graph = analyze_fixture(fixture)
            self.assertEqual(graph["reconciliation"]["state"], "OPEN")
            self.assertGreater(graph["reconciliation"]["counts"]["MISSING_FROM_SBOM"], 0)
            with self.assertRaisesRegex(ExportError, "RECONCILIATION_CLOSED"):
                export_pair(graph)

    @requires_byo_vendor_specs
    def test_negative_serialization_mutations_fail(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        cyclonedx, spdx = export_pair(graph)
        broken_cdx = copy.deepcopy(cyclonedx)
        broken_cdx["dependencies"][0]["ref"] = "urn:uuid:00000000-0000-0000-0000-000000000000"
        self.assertEqual(validate_cyclonedx(broken_cdx)["status"], "INVALID")
        broken_spdx = copy.deepcopy(spdx)
        relation = next(item for item in broken_spdx["@graph"] if item.get("type") == "Relationship")
        relation["to"] = ["https://example.invalid/missing"]
        self.assertEqual(validate_spdx(broken_spdx)["status"], "INVALID")

    @requires_byo_vendor_specs
    def test_mixed_source_pair_and_invalid_timestamp_fail(self) -> None:
        first = analyze_fixture(FIXTURES / "release-a")
        second = analyze_fixture(FIXTURES / "release-b")
        first_cdx, _ = export_pair(first)
        _, second_spdx = export_pair(second)
        self.assertEqual(validate_export_pair(first_cdx, second_spdx)["status"], "INVALID")
        broken = copy.deepcopy(first_cdx)
        broken["metadata"]["timestamp"] = "not-a-date"
        self.assertEqual(validate_cyclonedx(broken)["status"], "INVALID")

    @requires_byo_vendor_specs
    def test_standalone_pair_is_only_self_declared_and_spoofed_content_fails_with_graph(self) -> None:
        first = analyze_fixture(FIXTURES / "release-a")
        second = analyze_fixture(FIXTURES / "release-b")
        first_cdx, first_spdx = export_pair(first)
        _, second_spdx = export_pair(second)
        first_comment = next(
            item["comment"] for item in first_spdx["@graph"] if item.get("type") == "SpdxDocument"
        )
        spoofed_spdx = copy.deepcopy(second_spdx)
        next(
            item for item in spoofed_spdx["@graph"] if item.get("type") == "SpdxDocument"
        )["comment"] = first_comment
        standalone = validate_export_pair(first_cdx, spoofed_spdx)
        self.assertEqual(standalone["status"], "SELF_DECLARED_BINDINGS_MATCHED")
        self.assertEqual(
            standalone["source_binding_validation"]["assurance"],
            "SELF_DECLARED_BINDINGS_MATCHED",
        )
        self.assertEqual(
            validate_export_pair(first_cdx, spoofed_spdx, expected_graph=first)["status"],
            "INVALID",
        )

    def test_finding_status_cannot_be_hidden_by_stale_counts(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        graph["reconciliation"]["findings"][0]["status"] = "CONFLICT"
        graph["canonical_sha256"] = canonical_graph_sha256(graph)
        with self.assertRaisesRegex(ExportError, "counts do not match|semantic recomputation"):
            export_pair(graph)

    def test_candidate_semantic_forgery_cannot_reuse_old_matched_findings(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        candidate = next(
            item for item in graph["candidate_input"]["components"] if item["candidate_id"] == "orion-app"
        )
        candidate["version"] = "999.0-forged"
        candidate_sha256 = hashlib.sha256(
            canonical_json_bytes(graph["candidate_input"]["components"])
        ).hexdigest()
        graph["candidate_input"]["sha256"] = candidate_sha256
        graph["reconciliation"]["candidate_sha256"] = candidate_sha256
        graph["canonical_sha256"] = canonical_graph_sha256(graph)
        with self.assertRaisesRegex(ExportError, "semantic recomputation"):
            export_pair(graph)

    def test_release_diff_records_component_and_relationship_change(self) -> None:
        previous = analyze_fixture(FIXTURES / "release-a")
        current = analyze_fixture(FIXTURES / "release-b")
        report = diff_graphs(previous, current)
        self.assertTrue(report["component_changes"])
        self.assertTrue(report["relationship_changes"]["removed"])
        self.assertTrue(report["relationship_changes"]["added"])


class PackTests(unittest.TestCase):
    def test_open_analysis_is_registered_without_sbom_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as fixture_name, tempfile.TemporaryDirectory() as data_name:
            fixture = Path(fixture_name) / "release-a"
            shutil.copytree(FIXTURES / "release-a", fixture)
            candidate_path = fixture / "candidate-sbom.json"
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            candidate["relationships"] = candidate["relationships"][1:]
            candidate_path.write_text(
                json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            graph = analyze_fixture(fixture)
            result = write_analysis_package(Path(data_name), graph)
            run_directory = Path(data_name) / "runs" / graph["run_id"]
            self.assertEqual(result["validation_status"], "NOT_RUN_RECONCILIATION_OPEN")
            self.assertFalse((run_directory / "cyclonedx-1.7.json").exists())
            self.assertFalse((run_directory / "spdx-3.0.1.json").exists())
            self.assertEqual(verify_analysis_package(run_directory)["status"], result["status"])

    @requires_byo_vendor_specs
    def test_sealed_package_verifies_and_cannot_be_overwritten(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        with tempfile.TemporaryDirectory() as directory_name:
            data_root = Path(directory_name)
            result = write_run_package(data_root, graph)
            self.assertEqual(result["validation_status"], "MECHANICALLY_VALID")
            run_directory = data_root / "runs" / graph["run_id"]
            self.assertEqual(verify_run_package(run_directory)["exact_set_sha256"], result["exact_set_sha256"])
            with self.assertRaisesRegex(PackError, "refusing overwrite"):
                write_run_package(data_root, graph)

    @requires_byo_vendor_specs
    def test_payload_tampering_is_detected(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        with tempfile.TemporaryDirectory() as directory_name:
            data_root = Path(directory_name)
            write_run_package(data_root, graph)
            run_directory = data_root / "runs" / graph["run_id"]
            dashboard = run_directory / "dashboard.json"
            dashboard.write_bytes(dashboard.read_bytes() + b" \n")
            with self.assertRaisesRegex(PackError, "MANIFEST"):
                verify_run_package(run_directory)

    @requires_byo_vendor_specs
    def test_complete_status_cannot_upgrade_to_certified(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        with tempfile.TemporaryDirectory() as directory_name:
            data_root = Path(directory_name)
            write_run_package(data_root, graph)
            run_directory = data_root / "runs" / graph["run_id"]
            complete_path = run_directory / "COMPLETE.json"
            complete = json.loads(complete_path.read_text(encoding="utf-8"))
            complete["status"] = "CERTIFIED"
            complete["boundary"] = "forged authority"
            complete_path.write_text(json.dumps(complete), encoding="utf-8")
            with self.assertRaisesRegex(PackError, "boundary"):
                verify_run_package(run_directory)

    @requires_byo_vendor_specs
    def test_registry_failure_does_not_leave_orphan_run(self) -> None:
        graph = analyze_fixture(FIXTURES / "release-a")
        with tempfile.TemporaryDirectory() as directory_name:
            data_root = Path(directory_name)
            (data_root / ".runs.json.tmp").write_text("stale", encoding="utf-8")
            with self.assertRaisesRegex(PackError, "stale runs registry"):
                write_run_package(data_root, graph)
            self.assertFalse((data_root / "runs" / graph["run_id"]).exists())
            self.assertFalse((data_root / "runs.json").exists())


if __name__ == "__main__":
    unittest.main()
