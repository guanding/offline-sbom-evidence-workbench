from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sbom_workbench.registry import (
    RegistryError,
    load_and_validate_registry,
    validate_runtime_registry,
    validate_source_registry,
)


ROOT = Path(__file__).resolve().parents[1]
LEGACY_RECEIPT = ROOT / "evidence" / "acquisition" / "cyclonedx-bom-examples.receipt.json"


class SourceRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry_path = ROOT / "datasets" / "source_registry.json"
        self.registry = json.loads(self.registry_path.read_text(encoding="utf-8"))

    def test_project_source_registry_passes(self) -> None:
        _, report = load_and_validate_registry(self.registry_path)
        self.assertEqual(report["entries"], 12)

    def test_runtime_registry_passes(self) -> None:
        _, report = load_and_validate_registry(ROOT / "datasets" / "runtime_registry.json")
        self.assertEqual(report["entries"], 6)

    def test_rejects_unknown_fields_at_every_tested_boundary(self) -> None:
        root_candidate = copy.deepcopy(self.registry)
        root_candidate["unreviewed_override"] = True
        governance_candidate = copy.deepcopy(self.registry)
        governance_candidate["sources"][0]["governance"]["unreviewed_override"] = True

        for location, candidate in (
            ("registry_root", root_candidate),
            ("source_governance", governance_candidate),
        ):
            with self.subTest(unknown_location=location):
                with self.assertRaisesRegex(RegistryError, "fields mismatch"):
                    validate_source_registry(candidate)

    def test_rejects_source_url_credentials(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["upstream_url"] = (
            "https://user:secret@github.com/CycloneDX/bom-examples.git"
        )
        with self.assertRaisesRegex(RegistryError, "must not contain user credentials"):
            validate_source_registry(candidate)

    def test_rejects_source_url_outside_acquisition_allowlist(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["upstream_url"] = "https://example.com/CycloneDX/bom-examples.git"
        with self.assertRaisesRegex(RegistryError, "host is not in the acquisition allowlist"):
            validate_source_registry(candidate)

    def test_rejects_floating_ref(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["pin"]["ref_name"] = "main"
        with self.assertRaisesRegex(RegistryError, "must not be floating"):
            validate_source_registry(candidate)

    def test_rejects_refs_heads_ref(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["pin"]["ref_name"] = "refs/heads/release"
        with self.assertRaisesRegex(RegistryError, "must not be floating"):
            validate_source_registry(candidate)

    def test_annotated_tag_requires_tag_object(self) -> None:
        candidate = copy.deepcopy(self.registry)
        pin = candidate["sources"][0]["pin"]
        pin["ref_type"] = "annotated_tag"
        pin["ref_name"] = "v1.0.0"
        pin["tag_object"] = None
        with self.assertRaisesRegex(RegistryError, "tag_object is required for annotated_tag"):
            validate_source_registry(candidate)

    def test_rejects_unsafe_license_path(self) -> None:
        for path in ("../LICENSE", "a//LICENSE", "a/./LICENSE", "a\\LICENSE"):
            with self.subTest(path=path):
                candidate = copy.deepcopy(self.registry)
                candidate["sources"][0]["license"]["evidence_paths"] = [path]
                with self.assertRaisesRegex(RegistryError, "normalized relative"):
                    validate_source_registry(candidate)

    def test_rejects_impossible_registry_date(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["updated_at"] = "2026-99-99"
        with self.assertRaisesRegex(RegistryError, "YYYY-MM-DD"):
            validate_source_registry(candidate)

    def test_training_is_default_denied(self) -> None:
        self.assertTrue(all(not source["governance"]["training_allowed"] for source in self.registry["sources"]))
        candidate = copy.deepcopy(self.registry)
        governance = candidate["sources"][0]["governance"]
        governance["training_allowed"] = True
        governance["rights_status"] = "RIGHTS_REVIEWED"
        governance["rights_decision_ref"] = "evidence/rights/cyclonedx-decision.json"
        governance["rights_decision_sha256"] = "a" * 64
        governance["admission_status"] = "ADMITTED_FOR_TRAINING"
        governance["usage_status"] = "ADMITTED_FOR_TRAINING"
        with self.assertRaisesRegex(RegistryError, "global training decision exceeds"):
            validate_source_registry(candidate)

    def test_use_beyond_quarantine_fails_closed_on_rights_prerequisites(self) -> None:
        baseline = copy.deepcopy(self.registry)
        source = baseline["sources"][0]
        governance = source["governance"]
        governance["internal_development_allowed"] = True
        governance["rights_status"] = "RIGHTS_REVIEWED"
        governance["rights_decision_ref"] = "evidence/rights/cyclonedx-decision.json"
        governance["rights_decision_sha256"] = "a" * 64
        governance["admission_status"] = "ADMITTED_FOR_INTERNAL_DEVELOPMENT"
        governance["usage_status"] = "ADMITTED_FOR_INTERNAL_DEVELOPMENT"
        governance["acquisition_status"] = "ACQUIRED_UNSEALED"
        with self.assertRaisesRegex(RegistryError, "Phase 1 does not accept source-use admission"):
            validate_source_registry(baseline)

        mutations = {
            "license_hash": lambda item: item["sources"][0]["license"]["evidence_hashes"].update(
                {"LICENSE": None}
            ),
            "rights_status": lambda item: item["sources"][0]["governance"].update(
                {"rights_status": "AWAITING_NAMED_REVIEW"}
            ),
            "decision_ref": lambda item: item["sources"][0]["governance"].update(
                {"rights_decision_ref": None}
            ),
            "decision_hash": lambda item: item["sources"][0]["governance"].update(
                {"rights_decision_sha256": None}
            ),
        }
        for missing, mutate in mutations.items():
            candidate = copy.deepcopy(baseline)
            mutate(candidate)
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(RegistryError, "use beyond quarantine requires"):
                    validate_source_registry(candidate)

    def test_non_admitted_source_cannot_claim_an_admitted_usage_status(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["governance"]["usage_status"] = "ADMITTED_FOR_EVALUATION"
        with self.assertRaisesRegex(RegistryError, "must retain NOT_ADMITTED"):
            validate_source_registry(candidate)

    def test_bool_is_not_accepted_as_max_files(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["acquisition"]["max_files"] = True
        with self.assertRaisesRegex(RegistryError, "max_files is invalid"):
            validate_source_registry(candidate)

    def test_duplicate_dataset_id_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.registry)
        duplicate = copy.deepcopy(candidate["sources"][0])
        candidate["sources"].append(duplicate)
        with self.assertRaisesRegex(RegistryError, "duplicate dataset_id"):
            validate_source_registry(candidate)

    def test_license_evidence_hashes_must_cover_paths(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["sources"][0]["license"]["evidence_hashes"] = {}
        with self.assertRaisesRegex(RegistryError, "exactly cover"):
            validate_source_registry(candidate)

    def test_acquisition_decision_is_explicit(self) -> None:
        candidate = copy.deepcopy(self.registry)
        del candidate["sources"][0]["governance"]["acquisition_allowed"]
        with self.assertRaisesRegex(RegistryError, "acquisition_allowed"):
            validate_source_registry(candidate)

    @unittest.skipUnless(
        LEGACY_RECEIPT.is_file(),
        "historical acquisition evidence is intentionally absent from the public source set",
    )
    def test_legacy_receipt_matches_only_acquired_artifact_identity(self) -> None:
        receipt = json.loads(
            LEGACY_RECEIPT.read_text(encoding="utf-8")
        )
        source = next(item for item in self.registry["sources"] if item["dataset_id"] == receipt["dataset_id"])
        self.assertEqual(receipt["schema_version"], "1.0")
        self.assertEqual(source["pin"]["resolved_commit"], receipt["resolved_commit"])
        self.assertEqual(source["pin"]["acquisition_artifact_sha256"], receipt["git_archive_sha256"])
        self.assertEqual(source["root_id"], receipt["tree_manifest"]["root_id"])
        receipt_license = {item["relative_path"]: item["sha256"] for item in receipt["license_evidence"]}
        self.assertEqual(source["license"]["evidence_hashes"], receipt_license)
        # v1.0 is retained as historical acquisition evidence. It is not a v1.1
        # consumer-verifiable package and must not be treated as registry-bound.
        self.assertNotIn("registry_sha256", receipt)
        self.assertNotIn("registry_entry_sha256", receipt)
        self.assertNotIn("acquisition_status", receipt)


class RuntimeRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry_path = ROOT / "datasets" / "runtime_registry.json"
        self.registry = json.loads(self.registry_path.read_text(encoding="utf-8"))

    def test_frozen_runtime_requires_each_of_three_hashes(self) -> None:
        required_hashes = ("artifact_sha256", "config_sha256", "dependency_manifest_sha256")
        for missing_hash in required_hashes:
            candidate = copy.deepcopy(self.registry)
            runtime = candidate["runtimes"][0]
            runtime["status"] = "FROZEN"
            for hash_key in required_hashes:
                runtime[hash_key] = "a" * 64
            runtime[missing_hash] = None
            with self.subTest(missing_hash=missing_hash):
                with self.assertRaisesRegex(
                    RegistryError,
                    "FROZEN requires artifact, config, and dependency manifest hashes",
                ):
                    validate_runtime_registry(candidate)

if __name__ == "__main__":
    unittest.main()
