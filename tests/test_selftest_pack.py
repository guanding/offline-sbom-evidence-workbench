from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.manifest import canonical_json_bytes, sha256_file
from sbom_workbench.selftest import (
    CLASSIFICATION,
    build_profile_observation,
    parse_cyclonedx_json,
    reconcile_profile_observations,
)
from sbom_workbench.selftest_pack import (
    PACKAGE_STATUS,
    SelfTestPackError,
    verify_selftest_package,
    write_selftest_package,
)
from sbom_workbench.webapp import RegisteredRunStore, WebAppError


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def source_manifest() -> dict[str, object]:
    files = [
        {
            "relative_path": "requirements.txt",
            "sha256": hashlib.sha256(b"flask==3.1.2\n").hexdigest(),
            "size": len(b"flask==3.1.2\n"),
            "executable": False,
        }
    ]
    identity = {"root_id": "source-snapshot-v23", "files": files}
    return {
        "schema_version": "1.0",
        "root_id": identity["root_id"],
        "file_count": 1,
        "total_bytes": files[0]["size"],
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": files,
    }


def cyclonedx_document(profile_id: str, version: str) -> dict[str, object]:
    root_ref = f"root-{profile_id}"
    package_ref = f"flask-{profile_id}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{profile_id}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": "EUVD matcher",
                "version": "2.3.0",
            },
            "tools": [
                {
                    "vendor": "Anchore",
                    "name": "syft",
                    "version": "1.50.0",
                }
            ],
        },
        "components": [
            {
                "bom-ref": package_ref,
                "type": "library",
                "name": "flask",
                "version": version,
                "purl": f"pkg:pypi/flask@{version}",
                "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
            }
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [package_ref]},
            {"ref": package_ref, "dependsOn": []},
        ],
    }


def profile(profile_id: str, profile_kind: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "profile_id": profile_id,
        "classification": CLASSIFICATION,
        "profile_kind": profile_kind,
        "independence_domain": {
            "SOURCE_DIRECTORY": "SOURCE_DECLARATION",
            "OCI_ARCHIVE": "BUILT_OCI_ARTIFACT",
            "PORTABLE_RUNTIME": "PORTABLE_RUNTIME_OBSERVATION",
        }[profile_kind],
        "subject": {
            "comparison_namespace": "euvd-matcher",
            "product_name": "EUVD SBOM matcher",
            "declared_version": "2.3.0" if profile_kind != "PORTABLE_RUNTIME" else "2.2.0",
        },
        "scanner": {
            "name": "syft",
            "version": "1.50.0",
            "binary_sha256": "1" * 64,
            "config_sha256": "2" * 64,
        },
        "scan": {
            "target_kind": "docker-archive" if profile_kind == "OCI_ARCHIVE" else "dir",
            "target_label": profile_id,
        },
        "limits": {
            "timeout_seconds": 600,
            "max_json_bytes": 1024 * 1024,
            "max_components": 100,
        },
        "blindspots": [
            "NO_CUSTOMER_OR_MANUFACTURER_CONTEXT",
            "NO_CRA_OR_PRE7_CONFORMITY_CLAIM",
            "NOT_YOCTO_M3B",
            f"PROFILE_ISOLATED_{profile_kind}",
        ],
    }


def make_case(root: Path) -> tuple[list[dict[str, object]], dict[str, object], dict[str, dict[str, Path]], dict[str, object]]:
    manifest = source_manifest()
    raw_documents: dict[str, dict[str, Path]] = {}
    observations: list[dict[str, object]] = []
    versions = {
        "SOURCE_DIRECTORY": "3.1.2",
        "OCI_ARCHIVE": "3.1.2",
        "PORTABLE_RUNTIME": "3.0.0",
    }
    for profile_kind in ("SOURCE_DIRECTORY", "OCI_ARCHIVE", "PORTABLE_RUNTIME"):
        profile_id = {
            "SOURCE_DIRECTORY": "source-profile",
            "OCI_ARCHIVE": "oci-profile",
            "PORTABLE_RUNTIME": "portable-profile",
        }[profile_kind]
        payload = json_bytes(cyclonedx_document(profile_id, versions[profile_kind]))
        cyclonedx_path = root / f"{profile_id}.cyclonedx.json"
        cyclonedx_path.write_bytes(payload)
        syft_path = root / f"{profile_id}.syft.json"
        syft_path.write_bytes(json_bytes({"artifacts": [], "source": {"type": "dir"}}))
        spdx_path = root / f"{profile_id}.spdx.json"
        spdx_path.write_bytes(
            json_bytes(
                {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "documentNamespace": "https://example.invalid/selftest-pack",
                    "packages": [],
                }
            )
        )
        raw_documents[profile_id] = {
            "syft": syft_path,
            "cyclonedx": cyclonedx_path,
            "spdx": spdx_path,
        }
        if profile_kind == "SOURCE_DIRECTORY":
            identity = {
                "root_id": manifest["root_id"],
                "sha256": manifest["exact_set_sha256"],
                "file_count": manifest["file_count"],
                "total_bytes": manifest["total_bytes"],
            }
        else:
            identity = {
                "root_id": f"{profile_id}-input",
                "sha256": hashlib.sha256(f"{profile_id}-input".encode()).hexdigest(),
                "file_count": 1,
                "total_bytes": len(payload),
            }
        normalized_profile = profile(profile_id, profile_kind)
        observation = build_profile_observation(
            normalized_profile,
            parse_cyclonedx_json(payload),
            identity,
            normalized_profile["scanner"],
        )
        observations.append(observation)
    comparison = reconcile_profile_observations(observations)
    return observations, comparison, raw_documents, manifest


class SelfTestPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.observations, self.comparison, self.raw_documents, self.source_manifest = make_case(
            self.inputs
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_pack(self, name: str = "data") -> tuple[Path, dict[str, object]]:
        data_root = self.root / name
        result = write_selftest_package(
            data_root,
            observations=self.observations,
            comparison=self.comparison,
            raw_documents=self.raw_documents,
            source_manifest=self.source_manifest,
        )
        return data_root / "runs" / self.comparison["run_id"], result

    def test_sealed_package_carries_all_three_native_formats_per_profile(self) -> None:
        # M3-1: the sealed package must carry syft + cyclonedx + spdx raw for
        # every profile, not only the CycloneDX projection, so downstream
        # reviewers and the EUVD matcher can see every native generator format.
        run, _ = self.write_pack()
        raw_directory = run / "raw"
        expected = {
            f"{profile_id}.{fmt}.json"
            for profile_id in ("source-profile", "oci-profile", "portable-profile")
            for fmt in ("syft", "cyclonedx", "spdx")
        }
        self.assertEqual({path.name for path in raw_directory.iterdir()}, expected)

    def test_seals_verifies_and_registers_three_isolated_profiles(self) -> None:
        run, result = self.write_pack()
        self.assertEqual(result["status"], PACKAGE_STATUS)
        self.assertEqual(result["profile_count"], 3)
        self.assertEqual(result["reconciliation_status"], "OPEN")

        comparison = json.loads((run / "reconciliation.json").read_text())
        self.assertEqual(comparison["population_policy"], "NO_CROSS_PROFILE_COMPONENT_POPULATION")
        self.assertEqual(
            {item["profile_kind"] for item in comparison["profile_evidence"]},
            {"SOURCE_DIRECTORY", "OCI_ARCHIVE", "PORTABLE_RUNTIME"},
        )
        self.assertIn("VERSION_CONFLICT", {item["code"] for item in comparison["comparison_findings"]})
        self.assertIn(
            "STALE_PORTABLE_RUNTIME", {item["code"] for item in comparison["comparison_findings"]}
        )

        dashboard = RegisteredRunStore(self.root / "data").get_run(self.comparison["run_id"])
        self.assertEqual(dashboard["classification"], CLASSIFICATION)
        self.assertFalse(dashboard["authority_boundary"]["manufacturer_authorization"])
        self.assertEqual(
            dashboard["reconciliation"]["population_policy"],
            "NO_CROSS_PROFILE_COMPONENT_POPULATION",
        )

    def test_no_overwrite_and_deterministic_pack_identity(self) -> None:
        _, first = self.write_pack("first")
        with self.assertRaisesRegex(SelfTestPackError, "refusing overwrite"):
            write_selftest_package(
                self.root / "first",
                observations=self.observations,
                comparison=self.comparison,
                raw_documents=self.raw_documents,
                source_manifest=self.source_manifest,
            )
        _, second = self.write_pack("second")
        for key in (
            "run_id",
            "canonical_reconciliation_sha256",
            "dashboard_sha256",
            "manifest_sha256",
            "exact_set_sha256",
        ):
            self.assertEqual(first[key], second[key])

    def test_sealed_pack_carries_in_toto_envelope_bound_to_canonical(self) -> None:
        # M7-2: every sealed pack carries an in-toto ITE-6 statement whose
        # subject binds the reconciliation canonical hash (logical identity)
        # and whose predicate binds the physical MANIFEST hash; COMPLETE.json
        # binds the statement sha256. The envelope is the unified evidence
        # container for external tools (GUAC/cosign/policy engines).
        run, _ = self.write_pack()
        statement = json.loads((run / "ite6-statement.json").read_text())
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(statement["predicateType"], "sbom-workbench.selftest-pack/v1")
        self.assertEqual(
            statement["subject"][0]["digest"]["sha256"],
            self.comparison["canonical_sha256"],
        )
        self.assertEqual(
            statement["subject"][0]["name"], "canonical-reconciliation"
        )
        self.assertEqual(
            statement["predicate"]["manifest_sha256"],
            sha256_file(run / "MANIFEST.json"),
        )
        self.assertEqual(statement["predicate"]["classification"], CLASSIFICATION)
        complete = json.loads((run / "COMPLETE.json").read_text())
        self.assertEqual(
            complete["ite6_statement_sha256"],
            sha256_file(run / "ite6-statement.json"),
        )

    def test_tampered_ite6_subject_is_rejected_fail_closed(self) -> None:
        # M7-2 fail-closed: a tampered ite6 subject (wrong canonical) must break
        # verify even if the attacker rewrites COMPLETE.json to rebind the
        # statement sha256 — the subject<->canonical binding is an independent gate.
        run, _ = self.write_pack()
        statement = json.loads((run / "ite6-statement.json").read_text())
        statement["subject"][0]["digest"]["sha256"] = "b" * 64
        (run / "ite6-statement.json").write_text(
            json.dumps(statement, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        complete = json.loads((run / "COMPLETE.json").read_text())
        complete["ite6_statement_sha256"] = sha256_file(run / "ite6-statement.json")
        (run / "COMPLETE.json").write_text(
            json.dumps(complete, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            SelfTestPackError, "ite6 statement subject does not bind"
        ):
            verify_selftest_package(run)

    def test_tampered_ite6_predicate_breaks_verify_fail_closed(self) -> None:
        # M7-2 review-hardened: every predicate field is verified, not only
        # manifest_sha256. An attacker who rewrites ite6 + COMPLETE to rebind
        # the statement sha256 must still match predicate.dashboard_sha256 etc.
        run, _ = self.write_pack()
        statement = json.loads((run / "ite6-statement.json").read_text())
        statement["predicate"]["dashboard_sha256"] = "c" * 64
        (run / "ite6-statement.json").write_text(
            json.dumps(statement, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        complete = json.loads((run / "COMPLETE.json").read_text())
        complete["ite6_statement_sha256"] = sha256_file(run / "ite6-statement.json")
        (run / "COMPLETE.json").write_text(
            json.dumps(complete, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            SelfTestPackError, "ite6 statement predicate does not bind dashboard"
        ):
            verify_selftest_package(run)

    def test_recursive_exact_set_rejects_add_remove_and_tamper(self) -> None:
        run, _ = self.write_pack("addition")
        (run / "unexpected.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(SelfTestPackError, "recursive exact-set mismatch"):
            verify_selftest_package(run)

        run, _ = self.write_pack("removal")
        (run / "validation.json").unlink()
        with self.assertRaises(SelfTestPackError):
            verify_selftest_package(run)

        run, _ = self.write_pack("tamper")
        raw = run / "raw" / "source-profile.cyclonedx.json"
        raw.write_bytes(raw.read_bytes() + b" ")
        with self.assertRaisesRegex(SelfTestPackError, "payload no longer matches"):
            verify_selftest_package(run)

    def test_write_rejects_duplicate_refs_and_dangling_dependencies(self) -> None:
        bad = cyclonedx_document("source-profile", "3.1.2")
        bad["components"].append(dict(bad["components"][0]))  # type: ignore[index,union-attr]
        self.raw_documents["source-profile"]["cyclonedx"].write_bytes(json_bytes(bad))
        with self.assertRaisesRegex(SelfTestPackError, "duplicate bom-ref"):
            write_selftest_package(
                self.root / "duplicate",
                observations=self.observations,
                comparison=self.comparison,
                raw_documents=self.raw_documents,
                source_manifest=self.source_manifest,
            )

        self.raw_documents["source-profile"]["cyclonedx"].write_bytes(
            json_bytes(cyclonedx_document("source-profile", "3.1.2"))
        )
        bad = cyclonedx_document("source-profile", "3.1.2")
        bad["dependencies"][0]["dependsOn"] = ["not-present"]  # type: ignore[index,union-attr]
        self.raw_documents["source-profile"]["cyclonedx"].write_bytes(json_bytes(bad))
        with self.assertRaisesRegex(SelfTestPackError, "dangling dependency endpoint"):
            write_selftest_package(
                self.root / "dangling",
                observations=self.observations,
                comparison=self.comparison,
                raw_documents=self.raw_documents,
                source_manifest=self.source_manifest,
            )

    def test_authority_escalation_and_source_manifest_spoof_fail_closed(self) -> None:
        escalated = [dict(item) for item in self.observations]
        escalated[0]["manufacturer_approval_status"] = "APPROVED"
        with self.assertRaisesRegex(SelfTestPackError, "profile observations are invalid"):
            write_selftest_package(
                self.root / "authority",
                observations=escalated,
                comparison=self.comparison,
                raw_documents=self.raw_documents,
                source_manifest=self.source_manifest,
            )

        spoofed_manifest = dict(self.source_manifest)
        spoofed_manifest["root_id"] = "different-source"
        identity = {
            "root_id": spoofed_manifest["root_id"],
            "files": spoofed_manifest["files"],
        }
        spoofed_manifest["exact_set_sha256"] = hashlib.sha256(
            canonical_json_bytes(identity)
        ).hexdigest()
        with self.assertRaisesRegex(SelfTestPackError, "not bound to the source"):
            write_selftest_package(
                self.root / "source-spoof",
                observations=self.observations,
                comparison=self.comparison,
                raw_documents=self.raw_documents,
                source_manifest=spoofed_manifest,
            )

    def test_selftest_dashboard_uses_public_reference_authority_guard(self) -> None:
        run, _ = self.write_pack("guard")
        dashboard_path = run / "dashboard.json"
        registry_path = self.root / "guard" / "runs.json"
        baseline = json.loads(dashboard_path.read_text())

        cases = (
            ("manufacturer_role", "Manufacturer", "cannot carry a manufacturer role"),
            ("product_conformity_status", "CRA_COMPLIANT", "cannot carry product conformity"),
            ("status", "CAB_APPROVED", "cannot carry manufacturer, CAB"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                dashboard = json.loads(json.dumps(baseline))
                dashboard["release"][field] = value
                payload = json_bytes(dashboard)
                dashboard_path.write_bytes(payload)
                registry = json.loads(registry_path.read_text())
                registry["runs"][0]["dashboard_sha256"] = hashlib.sha256(payload).hexdigest()
                registry_path.write_bytes(json_bytes(registry))
                store = RegisteredRunStore(self.root / "guard")
                with self.assertRaisesRegex(WebAppError, message):
                    store.get_run(self.comparison["run_id"])

    def test_verifier_is_read_only(self) -> None:
        run, _ = self.write_pack("readonly")
        before = {
            path.relative_to(run).as_posix(): (sha256_file(path), path.stat().st_mtime_ns)
            for path in run.rglob("*")
            if path.is_file()
        }
        verify_selftest_package(run)
        after = {
            path.relative_to(run).as_posix(): (sha256_file(path), path.stat().st_mtime_ns)
            for path in run.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
