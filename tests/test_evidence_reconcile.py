from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.evidence import EvidenceError, canonical_graph_sha256
from sbom_workbench.ingest import load_fixture
from sbom_workbench.reconcile import (
    build_canonical_graph,
    build_component_population,
    reconcile,
)


def _write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    path.write_text(payload, encoding="utf-8", newline="\n")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _component(
    component_id: str,
    producer: str,
    name: str,
    version: str,
    identifier: str,
    *,
    role: str = "TRANSITIVE",
    locator: str | None = None,
) -> dict[str, object]:
    return {
        "component_id": component_id,
        "component_role": role,
        "producer": producer,
        "name": name,
        "version": version,
        "identifiers": [identifier],
        "provenance": {
            "kind": "SYNTHETIC_BUILD_RECORD",
            "locator": locator or f"build/{component_id}",
            "source_available": True,
        },
        "observed_hash": {
            "algorithm": "SHA-256",
            "value": hashlib.sha256(identifier.encode("utf-8")).hexdigest(),
        },
        "supplier_hash": None,
    }


def _candidate(
    candidate_id: str,
    producer: str,
    name: str,
    version: str,
    identifier: str,
    *,
    role: str = "TRANSITIVE",
    provenance: str | None = None,
) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "producer": producer,
        "name": name,
        "version": version,
        "identifiers": [identifier],
        "roles": [role],
        "provenances": [provenance] if provenance is not None else [],
        "observed_hashes": [("SHA-256", hashlib.sha256(identifier.encode("utf-8")).hexdigest())],
        "supplier_hashes": [],
    }


class EvidenceReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact_payload = b"synthetic-release-artifact-v1\n"
        artifact_sha256 = hashlib.sha256(self.artifact_payload).hexdigest()
        envelope = {
            "schema_version": "1.0",
            "classification": "SYNTHETIC_NOT_EVIDENCE",
            "release_id": "synthetic-release-a",
            "authorship": "HUMAN_AUTHORED_PROJECT_SYNTHETIC",
            "origin": {
                "kind": "PROJECT_SYNTHETIC_DESCRIPTOR",
                "relative_path": "source/build-descriptor.json",
                "sha256": "e" * 64,
            },
            "subject": {
                "producer": "Example Manufacturer",
                "name": "Synthetic Device",
                "version": "1.0.0",
                "identifiers": ["urn:synthetic:example:device:1.0.0"],
                "role": "ROOT_PRODUCT",
            },
            "artifact": {
                "relative_path": "artifacts/synthetic-release.bin",
                "sha256": artifact_sha256,
            },
            "coverage": ["ROOT_PRODUCT", "TOP_LEVEL", "TRANSITIVE"],
            "blindspots": ["SYNTHETIC_ONLY"],
        }
        self.build = {
            **copy.deepcopy(envelope),
            "evidence_id": "synthetic-release-a-build-manifest",
            "lane_id": "build-manifest",
            "source_kind": "SYNTHETIC_BUILD_MANIFEST",
            "components": [
                _component(
                    "build-app",
                    "ExampleCo",
                    "demo-app",
                    "1.0.0",
                    "pkg:generic/demo-app@1.0.0",
                    role="TOP_LEVEL",
                    locator="build/app",
                ),
                _component("build-lib", "LibraryCo", "demo-lib", "2.0.0", "pkg:generic/demo-lib@2.0.0"),
                _component("build-fw", "FirmwareCo", "radio-fw", "3.0.0", "urn:example:radio-fw:3.0.0"),
                _component("build-conflict", "ConflictCo", "conflict-lib", "1.0.0", "pkg:generic/conflict-lib"),
            ],
            "relationships": [
                {
                    "from": "build-app",
                    "type": "DEPENDS_ON",
                    "to": "build-lib",
                }
            ],
        }
        self.artifact = {
            **copy.deepcopy(envelope),
            "evidence_id": "synthetic-release-a-artifact-inventory",
            "lane_id": "artifact-inventory",
            "source_kind": "SYNTHETIC_ARTIFACT_INVENTORY",
            "components": [
                _component(
                    "artifact-app",
                    "ExampleCo",
                    "demo-app",
                    "1.0.0",
                    "pkg:generic/demo-app@1.0.0",
                    role="TOP_LEVEL",
                    locator="build/app",
                ),
                _component("artifact-lib", "LibraryCo", "demo-lib", "2.0.0", "pkg:generic/demo-lib@2.0.0"),
                _component("artifact-unknown", "UNKNOWN", "mystery-runtime", "UNKNOWN", "UNKNOWN"),
                _component("artifact-conflict", "ConflictCo", "conflict-lib", "2.0.0", "pkg:generic/conflict-lib"),
            ],
            "relationships": [
                {
                    "from": "artifact-app",
                    "type": "DEPENDS_ON",
                    "to": "artifact-lib",
                }
            ],
        }
        self.candidates = [
            _candidate(
                "candidate-app",
                "ExampleCo",
                "demo-app",
                "1.0.0",
                "pkg:generic/demo-app@1.0.0",
                role="TOP_LEVEL",
                provenance="SYNTHETIC_BUILD_RECORD:build/app",
            ),
            _candidate("candidate-lib", "LibraryCo", "demo-lib", "2.0.0", "pkg:generic/demo-lib@2.0.0"),
            _candidate("candidate-conflict", "ConflictCo", "conflict-lib", "1.0.0", "pkg:generic/conflict-lib"),
            _candidate("candidate-extra", "ExtraCo", "not-shipped", "9.0.0", "pkg:generic/not-shipped@9.0.0"),
        ]
        self._write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fixture(self) -> None:
        artifact_path = self.root / "artifacts" / "synthetic-release.bin"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(self.artifact_payload)
        build_sha256 = _write_json(self.root / "evidence" / "build-manifest.json", self.build)
        artifact_sha256 = _write_json(
            self.root / "evidence" / "artifact-inventory.json", self.artifact
        )
        release = {
            "schema_version": "1.0",
            "classification": "SYNTHETIC_NOT_EVIDENCE",
            "release_id": "synthetic-release-a",
            "manufacturer": "Example Manufacturer",
            "product": "Synthetic Device",
            "product_version": "1.0.0",
            "build_id": "build-a",
            "architecture": "arm64",
            "hardware_revision": "rev-a",
            "artifact_relative_path": "artifacts/synthetic-release.bin",
            "artifact_sha256": hashlib.sha256(self.artifact_payload).hexdigest(),
            "release_timestamp": "2026-08-02T12:00:00Z",
            "sbom_author": "Example Manufacturer",
            "sbom_version": "1.0.0",
            "evidence_cutoff": "2026-08-02T11:59:00Z",
            "inputs": {
                "build_manifest": {
                    "relative_path": "evidence/build-manifest.json",
                    "sha256": build_sha256,
                },
                "artifact_inventory": {
                    "relative_path": "evidence/artifact-inventory.json",
                    "sha256": artifact_sha256,
                },
            },
        }
        _write_json(self.root / "release.json", release)

    def test_two_adapters_create_evidence_linked_claims(self) -> None:
        graph = load_fixture(self.root)

        self.assertEqual(graph["classification"], "SYNTHETIC_NOT_EVIDENCE")
        self.assertEqual(len(graph["lane_identities"]), 2)
        self.assertEqual(len({lane["adapter_id"] for lane in graph["lane_identities"]}), 2)
        self.assertEqual(len(graph["evidence_objects"]), 2)
        evidence_ids = {item["evidence_id"] for item in graph["evidence_objects"]}
        for claim in graph["component_claims"] + graph["relationship_claims"]:
            self.assertTrue(claim["evidence_ids"])
            self.assertTrue(set(claim["evidence_ids"]).issubset(evidence_ids))

        conflict_versions = {
            claim["value"]
            for claim in graph["component_claims"]
            if claim["field"] == "version"
            and claim["source_component_id"] in {"build-conflict", "artifact-conflict"}
        }
        self.assertEqual(conflict_versions, {"1.0.0", "2.0.0"})

    def test_population_is_built_without_candidate_or_oracle(self) -> None:
        _write_json(
            self.root / "candidate.json",
            {"components": [_candidate("poison", "Bad", "injected", "1", "urn:bad")]},
        )
        _write_json(
            self.root / "oracle.json",
            {"components": [_component("oracle", "Bad", "injected", "1", "urn:bad")]},
        )

        graph = load_fixture(self.root)
        population = build_component_population(graph)

        self.assertEqual(len(population), 6)
        self.assertNotIn("injected", {item["name"] for item in population})
        self.assertEqual(
            {lane for item in population for lane in item["discovery_lanes"]},
            {"build-manifest", "artifact-inventory"},
        )
        root_component = next(
            item
            for item in population
            if any(source["source_component_id"] == "orion-root" for source in item["source_components"])
        )
        self.assertEqual(root_component["roles"], ["ROOT_PRODUCT"])
        self.assertEqual(
            root_component["observed_hashes"],
            [
                {
                    "algorithm": "SHA-256",
                    "value": hashlib.sha256(self.artifact_payload).hexdigest(),
                }
            ],
        )
        self.assertEqual(
            root_component["supplier_hashes"],
            [{"algorithm": "UNKNOWN", "value": "UNKNOWN"}],
        )
        self.assertEqual(len(root_component["provenances"]), 2)
        self.assertIn("component_role", root_component["field_claim_ids"])
        self.assertIn("observed_hash_value", root_component["field_claim_ids"])

    def test_same_purl_different_hashes_remain_distinct_and_match_by_hash(self) -> None:
        for lane_name, document in (("build", self.build), ("artifact", self.artifact)):
            first = _component(
                f"{lane_name}-duplicate-a",
                "DuplicateCo",
                "duplicate-lib",
                "1.0.0",
                "pkg:generic/duplicate-lib@1.0.0",
                locator="duplicate/a",
            )
            second = _component(
                f"{lane_name}-duplicate-b",
                "DuplicateCo",
                "duplicate-lib",
                "1.0.0",
                "pkg:generic/duplicate-lib@1.0.0",
                locator="duplicate/b",
            )
            first["observed_hash"]["value"] = "a" * 64
            second["observed_hash"]["value"] = "b" * 64
            document["components"].extend([first, second])
        self._write_fixture()

        graph = load_fixture(self.root)
        duplicates = [
            item for item in build_component_population(graph) if item["name"] == "duplicate-lib"
        ]
        self.assertEqual(len(duplicates), 2)
        self.assertTrue(all("identity" not in item["conflict_fields"] for item in duplicates))

        duplicate_candidates = []
        for suffix, hash_value in (("a", "a" * 64), ("b", "b" * 64)):
            candidate = _candidate(
                f"candidate-duplicate-{suffix}",
                "DuplicateCo",
                "duplicate-lib",
                "1.0.0",
                "pkg:generic/duplicate-lib@1.0.0",
            )
            candidate["observed_hashes"] = [("SHA-256", hash_value)]
            duplicate_candidates.append(candidate)
        result = reconcile(graph, self.candidates + duplicate_candidates)
        duplicate_population_ids = {item["population_id"] for item in duplicates}
        duplicate_findings = [
            finding
            for finding in result["findings"]
            if finding.get("population_id") in duplicate_population_ids
        ]
        self.assertEqual({finding["status"] for finding in duplicate_findings}, {"MATCHED"})
        self.assertEqual(len({finding["candidate_id"] for finding in duplicate_findings}), 2)

    def test_cross_lane_identifier_enrichment_preserves_all_without_conflict(self) -> None:
        # Lane A carries one purl; lane B carries the same purl plus an alias.
        # They cluster (shared concrete identifier) and the union must keep
        # both purls without flagging "identifier" as a conflict field, since
        # flagging it would falsely block RECONCILIATION_CLOSED.
        build_component = _component(
            "build-enrichment-lib",
            "ExampleCo",
            "enrichment-lib",
            "1.0.0",
            "pkg:generic/enrichment-lib@1.0.0",
            locator="enrichment/build",
        )
        self.build["components"].append(build_component)
        artifact_component = _component(
            "artifact-enrichment-lib",
            "ExampleCo",
            "enrichment-lib",
            "1.0.0",
            "pkg:generic/enrichment-lib@1.0.0",
            locator="enrichment/artifact",
        )
        artifact_component["identifiers"] = [
            "pkg:generic/enrichment-lib@1.0.0",
            "pkg:generic/enrichment-lib-alias@1.0.0",
        ]
        self.artifact["components"].append(artifact_component)
        self._write_fixture()

        graph = load_fixture(self.root)
        population = [
            item for item in build_component_population(graph) if item["name"] == "enrichment-lib"
        ]
        self.assertEqual(len(population), 1)
        enriched = population[0]
        self.assertEqual(
            enriched["identifiers"],
            sorted(
                [
                    "pkg:generic/enrichment-lib@1.0.0",
                    "pkg:generic/enrichment-lib-alias@1.0.0",
                ],
                key=lambda value: value.encode("utf-8"),
            ),
        )
        self.assertNotIn("identifier", enriched["conflict_fields"])

    def test_disjoint_identifiers_do_not_cluster_even_with_shared_name(self) -> None:
        # Two records with the same producer/name/version but completely
        # disjoint purls must NOT cluster: _records_refer_to_same_component
        # treats disjoint concrete identifier sets as different components.
        build_component = _component(
            "build-disjoint-lib",
            "ExampleCo",
            "disjoint-lib",
            "1.0.0",
            "pkg:generic/disjoint-lib-x@1.0.0",
            locator="disjoint/build",
        )
        self.build["components"].append(build_component)
        artifact_component = _component(
            "artifact-disjoint-lib",
            "ExampleCo",
            "disjoint-lib",
            "1.0.0",
            "pkg:generic/disjoint-lib-y@1.0.0",
            locator="disjoint/artifact",
        )
        self.artifact["components"].append(artifact_component)
        self._write_fixture()

        graph = load_fixture(self.root)
        population = [
            item for item in build_component_population(graph) if item["name"] == "disjoint-lib"
        ]
        self.assertEqual(len(population), 2)

    def test_reconciliation_emits_all_required_statuses_and_stays_open(self) -> None:
        result = reconcile(load_fixture(self.root), self.candidates)

        statuses = {finding["status"] for finding in result["findings"]}
        self.assertEqual(
            statuses,
            {"MATCHED", "CONFLICT", "MISSING_FROM_SBOM", "NOT_IN_RELEASE", "UNKNOWN"},
        )
        self.assertEqual(result["state"], "OPEN")
        self.assertGreaterEqual(result["counts"]["MATCHED"], 1)
        self.assertEqual(
            set(result["blocking_statuses"]),
            {"CONFLICT", "MISSING_FROM_SBOM", "NOT_IN_RELEASE", "UNKNOWN"},
        )

    def test_same_inputs_are_byte_stable_across_three_runs(self) -> None:
        graphs = [build_canonical_graph(self.root, list(reversed(self.candidates))) for _ in range(3)]

        self.assertEqual(len({graph["run_id"] for graph in graphs}), 1)
        self.assertEqual(len({graph["canonical_sha256"] for graph in graphs}), 1)
        self.assertEqual(graphs[0], graphs[1])
        self.assertEqual(graphs[1], graphs[2])
        self.assertEqual(canonical_graph_sha256(graphs[0]), graphs[0]["canonical_sha256"])
        self.assertEqual(len(graphs[0]["relationships"]), 1)
        relationship = graphs[0]["relationships"][0]
        self.assertEqual(relationship["relationship"], "DEPENDS_ON")
        self.assertEqual(
            set(relationship["discovery_lanes"]),
            {"build-manifest", "artifact-inventory"},
        )
        self.assertEqual(len(relationship["claim_ids"]), 2)
        self.assertEqual(len(relationship["evidence_ids"]), 2)

    def test_graph_hash_changes_when_candidate_changes(self) -> None:
        graph = build_canonical_graph(self.root, self.candidates)
        changed_candidates = copy.deepcopy(self.candidates)
        changed_candidates[0]["version"] = "1.0.1"
        changed = build_canonical_graph(self.root, changed_candidates)

        self.assertNotEqual(graph["run_id"], changed["run_id"])
        self.assertNotEqual(graph["canonical_sha256"], changed["canonical_sha256"])

    def test_relationship_conflict_is_preserved_and_blocks_closure(self) -> None:
        self.artifact["relationships"][0]["type"] = "CONTAINS"
        self._write_fixture()

        graph = build_canonical_graph(self.root, self.candidates)
        relationship_findings = [
            finding
            for finding in graph["reconciliation"]["findings"]
            if finding["finding_type"] == "RELATIONSHIP"
        ]

        self.assertEqual(graph["reconciliation"]["state"], "OPEN")
        self.assertEqual(len(relationship_findings), 1)
        self.assertEqual(relationship_findings[0]["status"], "CONFLICT")
        self.assertEqual({item["relationship"] for item in graph["relationships"]}, {"DEPENDS_ON", "CONTAINS"})

    def test_rejects_input_hash_drift(self) -> None:
        self.build["components"][0]["version"] = "1.0.1"
        _write_json(self.root / "evidence" / "build-manifest.json", self.build)

        with self.assertRaisesRegex(EvidenceError, "SHA-256 mismatch"):
            load_fixture(self.root)

    def test_rejects_release_artifact_hash_drift(self) -> None:
        (self.root / "artifacts" / "synthetic-release.bin").write_bytes(b"tampered\n")

        with self.assertRaisesRegex(EvidenceError, "SHA-256 mismatch"):
            load_fixture(self.root)

    def test_rejects_invalid_or_future_evidence_cutoff(self) -> None:
        release_path = self.root / "release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        invalid_values = (
            "2026-08-02 12:00:00",
            "2026-99-02T12:00:00Z",
            "2026-08-02T12:01:00Z",
        )
        for invalid in invalid_values:
            with self.subTest(value=invalid):
                candidate = copy.deepcopy(release)
                candidate["evidence_cutoff"] = invalid
                _write_json(release_path, candidate)
                with self.assertRaises(EvidenceError):
                    load_fixture(self.root)

    def test_rejects_unknown_fields_at_root_and_component_boundaries(self) -> None:
        mutations = []
        build_root = copy.deepcopy(self.build)
        build_root["unreviewed"] = True
        mutations.append(build_root)
        build_component = copy.deepcopy(self.build)
        build_component["components"][0]["unreviewed"] = True
        mutations.append(build_component)

        for index, mutation in enumerate(mutations):
            with self.subTest(boundary=index):
                self.build = mutation
                self._write_fixture()
                with self.assertRaisesRegex(EvidenceError, "fields mismatch"):
                    load_fixture(self.root)

    def test_rejects_unsafe_or_unexpected_input_paths(self) -> None:
        release_path = self.root / "release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        for unsafe in ("../build-manifest.json", "evidence/../build-manifest.json", "/tmp/input.json"):
            with self.subTest(path=unsafe):
                candidate = copy.deepcopy(release)
                candidate["inputs"]["build_manifest"]["relative_path"] = unsafe
                _write_json(release_path, candidate)
                with self.assertRaises(EvidenceError):
                    load_fixture(self.root)

    def test_rejects_duplicate_json_keys(self) -> None:
        build_path = self.root / "evidence" / "build-manifest.json"
        payload = (
            '{"schema_version":"1.0","schema_version":"1.0",'
            '"lane_id":"build-manifest","components":[],"relationships":[]}'
        )
        build_path.write_text(payload, encoding="utf-8")
        release = json.loads((self.root / "release.json").read_text(encoding="utf-8"))
        release["inputs"]["build_manifest"]["sha256"] = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()
        _write_json(self.root / "release.json", release)

        with self.assertRaisesRegex(EvidenceError, "duplicate JSON key"):
            load_fixture(self.root)

    def test_candidate_schema_is_fail_closed(self) -> None:
        graph = load_fixture(self.root)
        candidate = copy.deepcopy(self.candidates)
        candidate[0]["confidence"] = 1.0

        with self.assertRaisesRegex(EvidenceError, "fields mismatch"):
            reconcile(graph, candidate)


    def test_canonical_graph_hash_excludes_reserved_run_metadata(self) -> None:
        graph = load_fixture(self.root)
        baseline = canonical_graph_sha256(graph)
        # Reserved run-metadata fields must NOT change the artifact-bound hash
        # even when added to the graph (EVD-2 versioned projection allowlist).
        observability = copy.deepcopy(graph)
        observability["actual_start_time"] = "2026-08-04T12:00:00Z"
        observability["actual_end_time"] = "2026-08-04T12:05:00Z"
        observability["host_identity"] = "build-host-42"
        observability["wall_clock_observation"] = "2026-08-04T12:00:00Z"
        self.assertEqual(canonical_graph_sha256(observability), baseline)
        # A semantic field outside the allowlist still changes the hash.
        semantic = copy.deepcopy(graph)
        semantic["__test_semantic_marker__"] = "changed"
        self.assertNotEqual(canonical_graph_sha256(semantic), baseline)


if __name__ == "__main__":
    unittest.main()
