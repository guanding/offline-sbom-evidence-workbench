"""Acceptance tests for the project-owned SYNTHETIC_NOT_EVIDENCE Orion fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any

from sbom_workbench.manifest import build_exact_set_manifest, sha256_file


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "synthetic_orion"
SCHEMAS = ROOT / "schemas"
CLASSIFICATION = "SYNTHETIC_NOT_EVIDENCE"
PACKAGES = ("release-a", "release-b", "conflict")
RELEASE_KEYS = {
    "schema_version",
    "classification",
    "release_id",
    "manufacturer",
    "product",
    "product_version",
    "build_id",
    "architecture",
    "hardware_revision",
    "artifact_relative_path",
    "artifact_sha256",
    "inputs",
    "release_timestamp",
    "sbom_author",
    "sbom_version",
    "evidence_cutoff",
}
CANDIDATE_KEYS = {
    "schema_version",
    "classification",
    "candidate_id",
    "release_id",
    "producer",
    "name",
    "version",
    "identifiers",
    "artifact_sha256",
    "technical_status",
    "product_conformity_status",
    "manufacturer_release_authority",
    "cab_conclusion",
    "components",
    "relationships",
    "reconciliation",
}
COMPONENT_KEYS = {"candidate_id", "producer", "name", "version", "identifiers"}
RELATIONSHIP_KEYS = {"from", "type", "to"}
DISCOVERY_KEYS = {
    "schema_version",
    "classification",
    "evidence_id",
    "release_id",
    "lane_id",
    "source_kind",
    "authorship",
    "origin",
    "subject",
    "artifact",
    "components",
    "relationships",
    "coverage",
    "blindspots",
}
EXPECTED_PACKAGE_PATHS = {
    "artifacts/orion-bundle.tar",
    "candidate-sbom.json",
    "evidence/artifact-inventory.json",
    "evidence/build-manifest.json",
    "release.json",
}
FORBIDDEN_STATES = {
    "C",
    "PC",
    "NC",
    "NA",
    "COMPLIANT",
    "CONFORMANT",
    "APPROVED",
    "RELEASED",
    "CERTIFIED",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def component_map(document: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    return {component[key]: component for component in document["components"]}


def identifier(component: dict[str, Any], identifier_type: str) -> dict[str, Any]:
    matches = [item for item in component["identifiers"] if item["type"] == identifier_type]
    if len(matches) != 1:
        raise AssertionError(f"expected one {identifier_type} for {component['candidate_id']}")
    return matches[0]


def tar_inventory(path: Path) -> tuple[dict[str, Any], list[tarfile.TarInfo], str]:
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        inventory_member = archive.getmember("artifact-inventory.json")
        inventory_handle = archive.extractfile(inventory_member)
        if inventory_handle is None:
            raise AssertionError("inventory member is not a regular file")
        inventory = json.loads(inventory_handle.read().decode("utf-8"))
        marker_handle = archive.extractfile("SYNTHETIC_NOT_EVIDENCE.txt")
        if marker_handle is None:
            raise AssertionError("classification marker is not a regular file")
        marker = marker_handle.read().decode("utf-8")
    return inventory, members, marker


class SyntheticFixtureAcceptanceTests(unittest.TestCase):
    maxDiff = None

    def test_all_controlled_assets_are_marked_synthetic(self) -> None:
        for path in sorted(FIXTURE.rglob("*")):
            if not path.is_file():
                continue
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                if path.suffix == ".json":
                    self.assertEqual(load_json(path).get("classification"), CLASSIFICATION)
                elif path.suffix == ".tar":
                    inventory, _, marker = tar_inventory(path)
                    self.assertEqual(inventory["classification"], CLASSIFICATION)
                    self.assertIn(CLASSIFICATION, marker)
                else:
                    self.assertIn(CLASSIFICATION, path.read_text(encoding="utf-8"))
        for name in (
            "synthetic-release.schema.json",
            "synthetic-discovery.schema.json",
            "synthetic-candidate.schema.json",
        ):
            self.assertEqual(load_json(SCHEMAS / name)["x-classification"], CLASSIFICATION)
        self.assertIn(CLASSIFICATION, (ROOT / "docs" / "SYNTHETIC_MVP_ACCEPTANCE.md").read_text(encoding="utf-8"))
        self.assertIn(CLASSIFICATION, Path(__file__).read_text(encoding="utf-8"))

    def test_schema_contracts_are_closed_and_match_core_adapter(self) -> None:
        release_schema = load_json(SCHEMAS / "synthetic-release.schema.json")
        discovery_schema = load_json(SCHEMAS / "synthetic-discovery.schema.json")
        candidate_schema = load_json(SCHEMAS / "synthetic-candidate.schema.json")
        for schema in (release_schema, discovery_schema, candidate_schema):
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["x-classification"], CLASSIFICATION)
        self.assertEqual(set(release_schema["required"]), RELEASE_KEYS)
        self.assertEqual(set(discovery_schema["required"]), DISCOVERY_KEYS)
        self.assertEqual(set(candidate_schema["required"]), CANDIDATE_KEYS)
        component_schema = candidate_schema["$defs"]["candidateComponent"]
        relationship_schema = candidate_schema["$defs"]["relationship"]
        self.assertFalse(component_schema["additionalProperties"])
        self.assertEqual(set(component_schema["required"]), COMPONENT_KEYS)
        self.assertFalse(relationship_schema["additionalProperties"])
        self.assertEqual(set(relationship_schema["required"]), RELATIONSHIP_KEYS)
        self.assertEqual(
            set(candidate_schema["properties"]["technical_status"]["enum"]),
            {"SYNTHETIC_RECONCILED", "SYNTHETIC_RECONCILIATION_OPEN"},
        )
        self.assertTrue(
            FORBIDDEN_STATES.isdisjoint(candidate_schema["properties"]["technical_status"]["enum"])
        )

    def test_release_bindings_and_identity_fields(self) -> None:
        for package_name in PACKAGES:
            package_root = FIXTURE / package_name
            release = load_json(package_root / "release.json")
            candidate = load_json(package_root / "candidate-sbom.json")
            with self.subTest(package=package_name):
                self.assertEqual(set(release), RELEASE_KEYS)
                self.assertEqual(release["classification"], CLASSIFICATION)
                self.assertEqual(release["artifact_relative_path"], "artifacts/orion-bundle.tar")
                artifact = package_root / release["artifact_relative_path"]
                self.assertEqual(sha256_file(artifact), release["artifact_sha256"])
                self.assertEqual(candidate["artifact_sha256"], release["artifact_sha256"])
                self.assertEqual(candidate["release_id"], release["release_id"])
                self.assertEqual(candidate["producer"], release["manufacturer"])
                self.assertEqual(candidate["name"], release["product"])
                self.assertEqual(candidate["version"], release["product_version"])
                self.assertEqual(
                    set(release["inputs"]), {"build_manifest", "artifact_inventory"}
                )
                for binding in release["inputs"].values():
                    self.assertNotIn("..", Path(binding["relative_path"]).parts)
                    self.assertEqual(
                        sha256_file(package_root / binding["relative_path"]), binding["sha256"]
                    )
                release_time = datetime.fromisoformat(release["release_timestamp"].replace("Z", "+00:00"))
                cutoff = datetime.fromisoformat(release["evidence_cutoff"].replace("Z", "+00:00"))
                self.assertLessEqual(cutoff, release_time)

    def test_exact_set_matches_external_acceptance_oracle(self) -> None:
        for package_name in PACKAGES:
            package_root = FIXTURE / package_name
            oracle = load_json(FIXTURE / "oracle" / f"{package_name}.json")
            expected = oracle["expected_exact_set"]
            actual = build_exact_set_manifest(package_root, expected["root_id"])
            with self.subTest(package=package_name):
                self.assertEqual(actual, expected)
                self.assertEqual(
                    {item["relative_path"] for item in actual["files"]}, EXPECTED_PACKAGE_PATHS
                )
                self.assertEqual(actual, build_exact_set_manifest(package_root, expected["root_id"]))

    def test_runtime_inputs_and_rebuild_tool_do_not_reference_oracle(self) -> None:
        for package_name in PACKAGES:
            for path in (FIXTURE / package_name).rglob("*.json"):
                with self.subTest(path=path.relative_to(ROOT).as_posix()):
                    self.assertNotIn("oracle", path.read_text(encoding="utf-8").casefold())
        rebuild_text = (FIXTURE / "tools" / "rebuild.py").read_text(encoding="utf-8").casefold()
        self.assertNotIn("oracle", rebuild_text)

    def test_deterministic_rebuild_matches_frozen_artifacts(self) -> None:
        tool = FIXTURE / "tools" / "rebuild.py"
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            for package_name in PACKAGES:
                first = temporary / f"{package_name}-first.tar"
                second = temporary / f"{package_name}-second.tar"
                for output in (first, second):
                    completed = subprocess.run(
                        [sys.executable, str(tool), "--release", package_name, "--output", str(output)],
                        check=True,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    report = json.loads(completed.stdout)
                    self.assertEqual(report["classification"], CLASSIFICATION)
                release = load_json(FIXTURE / package_name / "release.json")
                frozen = FIXTURE / package_name / release["artifact_relative_path"]
                with self.subTest(package=package_name):
                    self.assertEqual(first.read_bytes(), second.read_bytes())
                    self.assertEqual(first.read_bytes(), frozen.read_bytes())
                    self.assertEqual(sha256_file(first), release["artifact_sha256"])
                    inventory, members, marker = tar_inventory(first)
                    self.assertEqual(
                        [member.name for member in members],
                        ["SYNTHETIC_NOT_EVIDENCE.txt", "artifact-inventory.json"],
                    )
                    self.assertEqual(inventory["classification"], CLASSIFICATION)
                    self.assertIn(CLASSIFICATION, marker)
                    for member in members:
                        self.assertTrue(member.isfile())
                        self.assertEqual(member.mode, 0o644)
                        self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                        self.assertEqual((member.uname, member.gname), ("", ""))

    def test_discovery_lanes_are_manual_independent_and_bound(self) -> None:
        for package_name in PACKAGES:
            package_root = FIXTURE / package_name
            build = load_json(package_root / "evidence" / "build-manifest.json")
            artifact = load_json(package_root / "evidence" / "artifact-inventory.json")
            with self.subTest(package=package_name):
                for lane in (build, artifact):
                    self.assertEqual(set(lane), DISCOVERY_KEYS)
                    self.assertEqual(lane["authorship"], "HUMAN_AUTHORED_PROJECT_SYNTHETIC")
                    self.assertNotIn("candidate", json.dumps(lane, sort_keys=True).casefold())
                self.assertNotEqual(build["lane_id"], artifact["lane_id"])
                self.assertNotEqual(build["source_kind"], artifact["source_kind"])
                self.assertNotEqual(build["origin"]["kind"], artifact["origin"]["kind"])
                self.assertNotEqual(build["origin"]["relative_path"], artifact["origin"]["relative_path"])

                build_source = (package_root / build["origin"]["relative_path"]).resolve()
                self.assertEqual(sha256_file(build_source), build["origin"]["sha256"])
                descriptor = load_json(build_source)
                self.assertEqual(build["subject"], descriptor["subject"])
                self.assertEqual(build["components"], descriptor["components"])
                self.assertEqual(build["relationships"], descriptor["relationships"])

                artifact_path = package_root / artifact["origin"]["relative_path"]
                self.assertEqual(sha256_file(artifact_path), artifact["origin"]["sha256"])
                inventory, _, _ = tar_inventory(artifact_path)
                self.assertEqual(artifact["subject"], inventory["subject"])
                self.assertEqual(artifact["components"], inventory["components"])
                self.assertEqual(artifact["relationships"], inventory["relationships"])
                self.assertNotEqual(build_source.read_bytes(), json.dumps(inventory, sort_keys=True).encode())

    def test_fixture_covers_required_identity_and_hash_cases(self) -> None:
        evidence = load_json(FIXTURE / "release-a" / "evidence" / "artifact-inventory.json")
        candidate = load_json(FIXTURE / "release-a" / "candidate-sbom.json")
        root_roles = [item for item in candidate["identifiers"] if item["type"] == "COMPONENT_ROLE"]
        self.assertEqual(root_roles, [{"type": "COMPONENT_ROLE", "value": "ROOT_PRODUCT", "algorithm": None}])
        components = component_map(evidence, "component_id")
        self.assertTrue({"TOP_LEVEL", "TRANSITIVE", "BINARY_ONLY_FIRMWARE"}.issubset(
            {component["component_role"] for component in components.values()}
        ))
        firmware = components["orion-radio-fw"]
        self.assertFalse(firmware["provenance"]["source_available"])
        self.assertEqual(firmware["supplier_hash"]["algorithm"], "SHA-256")
        telemetry = components["orion-telemetry"]
        self.assertIsNone(telemetry["supplier_hash"]["algorithm"])

        first = components["orion-transport-source"]
        second = components["orion-transport-binary"]
        self.assertEqual((first["producer"], first["name"], first["version"]),
                         (second["producer"], second["name"], second["version"]))
        self.assertNotEqual(first["provenance"], second["provenance"])
        self.assertNotEqual(first["observed_hash"], second["observed_hash"])

        candidate_components = component_map(candidate, "candidate_id")
        self.assertEqual(identifier(candidate_components["orion-radio-fw"], "SUPPLIER_HASH")["algorithm"], "SHA-256")
        self.assertIsNone(identifier(candidate_components["orion-telemetry"], "SUPPLIER_HASH")["algorithm"])
        conflict = component_map(
            load_json(FIXTURE / "conflict" / "evidence" / "artifact-inventory.json"),
            "component_id",
        )["orion-unknown-blob"]
        self.assertEqual(conflict["component_role"], "BINARY_ONLY_FIRMWARE")
        self.assertEqual(conflict["provenance"]["kind"], "SYNTHETIC_UNRESOLVED_ARTIFACT")
        self.assertEqual(conflict["producer"], "UNKNOWN")
        self.assertEqual(conflict["name"], "UNKNOWN")
        self.assertEqual(conflict["version"], "UNKNOWN")
        self.assertEqual(conflict["identifiers"], ["UNKNOWN"])

    def test_release_b_changes_only_one_component_and_one_relationship(self) -> None:
        release_a = load_json(FIXTURE / "release-a" / "release.json")
        release_b = load_json(FIXTURE / "release-b" / "release.json")
        candidate_a = load_json(FIXTURE / "release-a" / "candidate-sbom.json")
        candidate_b = load_json(FIXTURE / "release-b" / "candidate-sbom.json")
        expected = load_json(FIXTURE / "oracle" / "expected-diff.json")

        a_components = component_map(candidate_a, "candidate_id")
        b_components = component_map(candidate_b, "candidate_id")
        self.assertEqual(set(a_components), set(b_components))
        changed_components = {
            component_id
            for component_id in a_components
            if a_components[component_id] != b_components[component_id]
        }
        self.assertEqual(changed_components, {expected["expected_component_change"]["candidate_id"]})
        crypto_a = a_components["orion-crypto"]
        crypto_b = b_components["orion-crypto"]
        self.assertEqual(crypto_a["version"], expected["expected_component_change"]["from_version"])
        self.assertEqual(crypto_b["version"], expected["expected_component_change"]["to_version"])
        self.assertEqual(identifier(crypto_a, "OBSERVED_HASH")["value"], expected["expected_component_change"]["from_observed_sha256"])
        self.assertEqual(identifier(crypto_b, "OBSERVED_HASH")["value"], expected["expected_component_change"]["to_observed_sha256"])

        self.assertEqual(len(candidate_a["relationships"]), len(candidate_b["relationships"]))
        changed_relationships = [
            index
            for index, (before, after) in enumerate(zip(candidate_a["relationships"], candidate_b["relationships"], strict=True))
            if before != after
        ]
        relationship_change = expected["expected_relationship_change"]
        self.assertEqual(changed_relationships, [relationship_change["index"]])
        self.assertEqual(candidate_a["relationships"][relationship_change["index"]], relationship_change["from"])
        self.assertEqual(candidate_b["relationships"][relationship_change["index"]], relationship_change["to"])

        actual_release_changes = {
            key for key in RELEASE_KEYS if release_a[key] != release_b[key]
        }
        self.assertEqual(
            actual_release_changes,
            set(expected["changed_release_event_fields"]) | {"inputs"},
        )
        for key in expected["unchanged_release_identity_fields"]:
            self.assertEqual(release_a[key], release_b[key])

    def test_conflict_and_unknown_remain_fail_closed(self) -> None:
        build = load_json(FIXTURE / "conflict" / "evidence" / "build-manifest.json")
        artifact = load_json(FIXTURE / "conflict" / "evidence" / "artifact-inventory.json")
        candidate = load_json(FIXTURE / "conflict" / "candidate-sbom.json")
        build_crypto = component_map(build, "component_id")["orion-crypto"]
        artifact_crypto = component_map(artifact, "component_id")["orion-crypto"]
        self.assertNotEqual(build_crypto["version"], artifact_crypto["version"])
        self.assertEqual(build_crypto["identifiers"], artifact_crypto["identifiers"])
        self.assertEqual(build_crypto["observed_hash"], artifact_crypto["observed_hash"])
        self.assertEqual(candidate["technical_status"], "SYNTHETIC_RECONCILIATION_OPEN")
        self.assertEqual(candidate["reconciliation"]["status"], "SYNTHETIC_RECONCILIATION_OPEN")
        self.assertEqual(candidate["reconciliation"]["component_population_status"], "SYNTHETIC_OPEN_SET")
        self.assertGreaterEqual(len(candidate["reconciliation"]["conflicts"]), 1)
        self.assertGreaterEqual(len(candidate["reconciliation"]["unknowns"]), 1)
        self.assertTrue(all(item["resolution"] is None for item in candidate["reconciliation"]["conflicts"]))
        candidate_components = component_map(candidate, "candidate_id")
        self.assertIsNone(candidate_components["orion-crypto"]["version"])
        unknown = candidate_components["orion-unknown-blob"]
        self.assertIsNone(unknown["producer"])
        self.assertIsNone(unknown["name"])
        self.assertIsNone(unknown["version"])

    def test_candidate_contract_forbids_authority_or_conformity_upgrade(self) -> None:
        for package_name in PACKAGES:
            candidate = load_json(FIXTURE / package_name / "candidate-sbom.json")
            with self.subTest(package=package_name):
                self.assertEqual(set(candidate), CANDIDATE_KEYS)
                self.assertEqual(candidate["classification"], CLASSIFICATION)
                self.assertEqual(candidate["product_conformity_status"], "NO_PRODUCT_CONFORMITY_STATUS")
                self.assertFalse(candidate["manufacturer_release_authority"])
                self.assertFalse(candidate["cab_conclusion"])
                self.assertNotIn(candidate["technical_status"], FORBIDDEN_STATES)
                self.assertNotIn(candidate["reconciliation"]["status"], FORBIDDEN_STATES)
                for component in candidate["components"]:
                    self.assertEqual(set(component), COMPONENT_KEYS)
                    for item in component["identifiers"]:
                        self.assertEqual(set(item), {"type", "value", "algorithm"})
                        if item["type"] == "OBSERVED_HASH":
                            self.assertEqual(item["algorithm"], "SHA-256")
                            self.assertEqual(len(item["value"]), 64)
                for relationship in candidate["relationships"]:
                    self.assertEqual(set(relationship), RELATIONSHIP_KEYS)


if __name__ == "__main__":
    unittest.main()
