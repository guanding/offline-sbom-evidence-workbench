from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sbom_workbench.selftest import (
    CLASSIFICATION,
    GENERATOR_STATUS,
    MILESTONE_SCOPE,
    PRODUCT_STATUS,
    RELEASE_STATUS,
    SelfTestError,
    build_profile_observation,
    build_syft_command,
    canonical_selftest_sha256,
    load_cyclonedx,
    load_selftest_profile,
    parse_cyclonedx_json,
    reconcile_profile_observations,
    selftest_run_id,
    validate_cyclonedx,
    validate_selftest_profile,
)


PROJECT = Path(__file__).resolve().parents[1]
KINDS = {
    "SOURCE_DIRECTORY": ("SOURCE_DECLARATION", "dir"),
    "OCI_ARCHIVE": ("BUILT_OCI_ARTIFACT", "docker-archive"),
    "PORTABLE_RUNTIME": ("PORTABLE_RUNTIME_OBSERVATION", "dir"),
}


def _profile(kind: str, *, profile_id: str | None = None) -> dict[str, object]:
    domain, target_kind = KINDS[kind]
    return {
        "schema_version": "1.0",
        "profile_id": profile_id or kind.lower().replace("_", "-"),
        "classification": CLASSIFICATION,
        "profile_kind": kind,
        "independence_domain": domain,
        "subject": {
            "comparison_namespace": "euvd-sbom-matcher-selftest",
            "product_name": "EUVD SBOM Matcher",
            "declared_version": "2.3.0-candidate",
        },
        "scanner": {
            "name": "syft",
            "version": "1.50.0",
            "binary_sha256": "a" * 64,
            "config_sha256": "b" * 64,
        },
        "scan": {
            "target_kind": target_kind,
            "target_label": f"euvd-{kind.lower().replace('_', '-')}",
        },
        "limits": {
            "timeout_seconds": 600,
            "max_json_bytes": 16 * 1024 * 1024,
            "max_components": 1000,
        },
        "blindspots": [
            "NOT_YOCTO_M3B",
            "NO_CRA_OR_PRE7_CONFORMITY_CLAIM",
            "NO_CUSTOMER_OR_MANUFACTURER_CONTEXT",
        ],
    }


def _component(name: str, version: str, *, suffix: str | None = None) -> dict[str, object]:
    suffix = suffix or name
    return {
        "type": "library",
        "bom-ref": f"pkg:pypi/{name}@{version}?source={suffix}",
        "group": "python",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "cpe": f"cpe:2.3:a:example:{name}:{version}:*:*:*:*:*:*:*",
        "hashes": [
            {"alg": "SHA-256", "content": hashlib.sha256(f"{name}-{version}".encode()).hexdigest()}
        ],
    }


def _cdx(version: str = "2.31.0", *, serial: str = "urn:uuid:00000000-0000-4000-8000-000000000001") -> dict[str, object]:
    root = {
        "type": "application",
        "bom-ref": "pkg:generic/euvd-sbom-matcher@2.3.0",
        "name": "euvd-sbom-matcher",
        "version": "2.3.0",
        "purl": "pkg:generic/euvd-sbom-matcher@2.3.0",
        "cpe": "cpe:2.3:a:example:euvd-sbom-matcher:2.3.0:*:*:*:*:*:*:*",
        "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
    }
    requests = _component("requests", version)
    flask = _component("flask", "3.1.2")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": "2026-08-04T01:02:03Z",
            "component": root,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "pkg:github/anchore/syft@1.50.0",
                        "name": "syft",
                        "version": "1.50.0",
                        "purl": "pkg:github/anchore/syft@1.50.0",
                    }
                ],
                "services": [],
            },
        },
        "components": [requests, flask],
        "dependencies": [
            {
                "ref": root["bom-ref"],
                "dependsOn": [requests["bom-ref"], flask["bom-ref"]],
            },
            {"ref": requests["bom-ref"], "dependsOn": []},
            {"ref": flask["bom-ref"], "dependsOn": [requests["bom-ref"]]},
        ],
    }


def _projection(version: str = "2.31.0") -> dict[str, object]:
    return parse_cyclonedx_json(json.dumps(_cdx(version), sort_keys=True) + "\n")


def _input_identity(seed: str) -> dict[str, object]:
    return {
        "root_id": f"euvd-{seed}",
        "sha256": hashlib.sha256(seed.encode()).hexdigest(),
        "file_count": 12,
        "total_bytes": 4096,
    }


def _observation(kind: str, version: str, seed: str) -> dict[str, object]:
    profile = _profile(kind)
    return build_profile_observation(
        profile,
        _projection(version),
        _input_identity(seed),
        profile["scanner"],
    )


class SelfTestProfileTests(unittest.TestCase):
    def test_all_three_profiles_are_isolated_and_schema_valid(self) -> None:
        schema = json.loads((PROJECT / "schemas" / "selftest-profile.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for kind, (domain, target_kind) in KINDS.items():
            with self.subTest(kind=kind):
                profile = _profile(kind)
                normalized = validate_selftest_profile(profile)
                self.assertEqual(list(validator.iter_errors(profile)), [])
                self.assertEqual(normalized["independence_domain"], domain)
                self.assertEqual(normalized["scan"]["target_kind"], target_kind)

    def test_profile_domain_target_spoof_and_missing_boundary_fail_closed(self) -> None:
        profile = _profile("OCI_ARCHIVE")
        profile["independence_domain"] = "SOURCE_DECLARATION"
        with self.assertRaisesRegex(SelfTestError, "independence domain"):
            validate_selftest_profile(profile)

        profile = _profile("OCI_ARCHIVE")
        profile["scan"]["target_kind"] = "dir"
        with self.assertRaisesRegex(SelfTestError, "target kind"):
            validate_selftest_profile(profile)

        profile = _profile("SOURCE_DIRECTORY")
        profile["blindspots"].remove("NOT_YOCTO_M3B")
        with self.assertRaisesRegex(SelfTestError, "mandatory M3A boundary"):
            validate_selftest_profile(profile)

    def test_profile_loader_rejects_duplicate_json_key_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}\n')
            with self.assertRaisesRegex(SelfTestError, "duplicate JSON key"):
                load_selftest_profile(duplicate)

            valid = root / "profile.json"
            valid.write_text(json.dumps(_profile("SOURCE_DIRECTORY")))
            link = root / "link.json"
            link.symlink_to(valid)
            with self.assertRaisesRegex(SelfTestError, "single-link regular file"):
                load_selftest_profile(link)


class CycloneDXStrictParsingTests(unittest.TestCase):
    def test_projection_preserves_root_components_hashes_identifiers_and_dependencies(self) -> None:
        projection = _projection()
        root = projection["metadata"]["component"]
        requests = next(item for item in projection["components"] if item["name"] == "requests")

        self.assertEqual(projection["document"]["spec_version"], "1.6")
        self.assertEqual(root["bom_ref"], "pkg:generic/euvd-sbom-matcher@2.3.0")
        self.assertEqual(root["purl"], "pkg:generic/euvd-sbom-matcher@2.3.0")
        self.assertTrue(root["cpe"].startswith("cpe:2.3:a:"))
        self.assertEqual(requests["hashes"][0]["algorithm"], "SHA-256")
        self.assertRegex(requests["hashes"][0]["content"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(projection["dependencies"]), 3)
        self.assertRegex(projection["source_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(projection["semantic_sha256"], r"^[0-9a-f]{64}$")

    def test_syft_1_50_cyclonedx_1_7_empty_shape_is_normalized_strictly(self) -> None:
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "metadata": {
                "timestamp": "2026-08-04T02:19:25Z",
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "author": "anchore",
                            "name": "syft",
                            "version": "1.50.0",
                        }
                    ]
                },
                "component": {
                    "bom-ref": "81c581ebb9cb2d65",
                    "type": "file",
                    "name": "/isolated/input",
                },
            },
            "components": None,
            "dependencies": None,
        }
        projection = validate_cyclonedx(document)

        self.assertEqual(projection["document"]["spec_version"], "1.7")
        self.assertEqual(projection["components"], [])
        self.assertEqual(projection["dependencies"], [])
        self.assertIsNone(projection["metadata"]["tools"]["components"][0]["bom_ref"])

    def test_duplicate_json_key_is_rejected_before_interpretation(self) -> None:
        payload = b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}'
        with self.assertRaisesRegex(SelfTestError, "duplicate JSON key"):
            parse_cyclonedx_json(payload)

    def test_nonstandard_json_constants_and_invalid_component_coordinates_fail_closed(self) -> None:
        with self.assertRaisesRegex(SelfTestError, "non-standard JSON constant"):
            parse_cyclonedx_json(
                b'{"bomFormat":"CycloneDX","specVersion":"1.7","version":NaN}'
            )

        document = _cdx()
        document["components"][0]["type"] = "CRA-approved-library"
        with self.assertRaisesRegex(SelfTestError, "recognized CycloneDX component type"):
            validate_cyclonedx(document)

        document = _cdx()
        document["components"][0]["purl"] = "https://example.invalid/package"
        with self.assertRaisesRegex(SelfTestError, "package-url profile"):
            validate_cyclonedx(document)

        document = _cdx()
        document["components"][0]["cpe"] = "not-a-cpe"
        with self.assertRaisesRegex(SelfTestError, "CPE 2.2/2.3 profile"):
            validate_cyclonedx(document)

    def test_duplicate_bom_ref_is_rejected_across_metadata_and_components(self) -> None:
        document = _cdx()
        document["components"][0]["bom-ref"] = document["metadata"]["component"]["bom-ref"]
        with self.assertRaisesRegex(SelfTestError, "duplicate bom-ref"):
            validate_cyclonedx(document)

    def test_dangling_dependency_node_and_endpoint_are_rejected(self) -> None:
        document = _cdx()
        document["dependencies"].append({"ref": "missing", "dependsOn": []})
        with self.assertRaisesRegex(SelfTestError, "dangling dependency ref"):
            validate_cyclonedx(document)

        document = _cdx()
        document["dependencies"][0]["dependsOn"].append("missing")
        with self.assertRaisesRegex(SelfTestError, "dangling dependency endpoint"):
            validate_cyclonedx(document)

    def test_duplicate_dependency_ref_and_edge_are_rejected(self) -> None:
        document = _cdx()
        document["dependencies"].append(copy.deepcopy(document["dependencies"][1]))
        with self.assertRaisesRegex(SelfTestError, "duplicate dependency ref"):
            validate_cyclonedx(document)

        document = _cdx()
        document["dependencies"][0]["dependsOn"].append(
            document["dependencies"][0]["dependsOn"][0]
        )
        with self.assertRaisesRegex(SelfTestError, "duplicate dependency edge"):
            validate_cyclonedx(document)

    def test_malformed_metadata_dependencies_and_hash_fail_closed(self) -> None:
        document = _cdx()
        document["metadata"] = []
        with self.assertRaisesRegex(SelfTestError, "metadata must be an object"):
            validate_cyclonedx(document)

        document = _cdx()
        document["dependencies"] = {}
        with self.assertRaisesRegex(SelfTestError, "dependencies must be an array"):
            validate_cyclonedx(document)

        document = _cdx()
        document["components"][0]["hashes"][0]["content"] = "xyz"
        with self.assertRaisesRegex(SelfTestError, "hash algorithm"):
            validate_cyclonedx(document)

        document = _cdx()
        document["components"][0]["hashes"][0] = {
            "alg": "CRA-CONFORMITY",
            "content": "aa",
        }
        with self.assertRaisesRegex(SelfTestError, "unsupported CycloneDX hash algorithm"):
            validate_cyclonedx(document)

    def test_file_loader_binds_hash_and_rejects_tamper_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bom.json"
            payload = json.dumps(_cdx(), sort_keys=True).encode() + b"\n"
            source.write_bytes(payload)
            expected = hashlib.sha256(payload).hexdigest()

            projection, identity = load_cyclonedx(source, expected_sha256=expected)
            self.assertEqual(identity, {"sha256": expected, "size": len(payload)})
            self.assertEqual(projection["source_sha256"], expected)
            with self.assertRaisesRegex(SelfTestError, "SHA-256 mismatch"):
                load_cyclonedx(source, expected_sha256="0" * 64)

            hardlink = root / "hardlink.json"
            os.link(source, hardlink)
            with self.assertRaisesRegex(SelfTestError, "single-link regular file"):
                load_cyclonedx(source)


class ScannerCommandTests(unittest.TestCase):
    def test_source_and_oci_commands_use_explicit_schemes_and_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "syft"
            config = root / "syft.yaml"
            output = root / "output"
            source = root / "snapshot"
            archive = root / "image.tar"

            source_command = build_syft_command(
                scanner,
                "SOURCE_DIRECTORY",
                source,
                output,
                config_path=config,
                sandbox_exec="/usr/bin/sandbox-exec",
                timeout_seconds=321,
            )
            oci_command = build_syft_command(scanner, "OCI_ARCHIVE", archive, output)

        self.assertIn(f"dir:{source.as_posix()}", source_command["argv"])
        self.assertIn(f"docker-archive:{archive.as_posix()}", oci_command["argv"])
        self.assertEqual(source_command["environment_overrides"]["SYFT_CHECK_FOR_APP_UPDATE"], "false")
        self.assertEqual(source_command["timeout_seconds"], 321)
        self.assertEqual(source_command["timeout_enforced_by"], "CALLER")
        self.assertEqual(source_command["network_policy"], "MACOS_SANDBOX_EXEC_DENY_NETWORK")
        self.assertTrue(any("(deny network*)" in item for item in source_command["argv"]))
        self.assertFalse(any("enrich" in item.lower() for item in source_command["argv"]))
        self.assertEqual(set(source_command["outputs"]), {"syft-json", "cyclonedx-json", "spdx-json"})
        for format_name, output_path in source_command["outputs"].items():
            self.assertIn(f"{format_name}={output_path}", source_command["argv"])

    def test_relative_paths_unknown_target_and_invalid_timeout_are_rejected(self) -> None:
        with self.assertRaisesRegex(SelfTestError, "absolute normalized"):
            build_syft_command("syft", "dir", "/tmp/source", "/tmp/output")
        with self.assertRaisesRegex(SelfTestError, "dir or docker-archive"):
            build_syft_command("/tmp/syft", "registry", "/tmp/source", "/tmp/output")
        with self.assertRaisesRegex(SelfTestError, "timeout_seconds"):
            build_syft_command("/tmp/syft", "dir", "/tmp/source", "/tmp/output", timeout_seconds=0)


class ObservationAndReconciliationTests(unittest.TestCase):
    def test_three_run_determinism_and_source_exact_set_change_new_identity(self) -> None:
        profile = _profile("SOURCE_DIRECTORY")
        projection = _projection()
        first = build_profile_observation(profile, projection, _input_identity("v1"), profile["scanner"])
        second = build_profile_observation(
            copy.deepcopy(profile), copy.deepcopy(projection), _input_identity("v1"), profile["scanner"]
        )
        third = build_profile_observation(
            copy.deepcopy(profile), copy.deepcopy(projection), _input_identity("v1"), profile["scanner"]
        )
        changed = build_profile_observation(profile, projection, _input_identity("v2"), profile["scanner"])

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(first["canonical_sha256"], canonical_selftest_sha256(first))
        self.assertEqual(first["run_id"], selftest_run_id(first))
        self.assertNotEqual(first["canonical_sha256"], changed["canonical_sha256"])
        self.assertNotEqual(first["run_id"], changed["run_id"])

    def test_real_scanner_uuid_and_timestamp_do_not_change_semantic_run_identity(self) -> None:
        first_document = _cdx(serial="urn:uuid:00000000-0000-4000-8000-000000000001")
        second_document = _cdx(serial="urn:uuid:00000000-0000-4000-8000-000000000002")
        second_document["metadata"]["timestamp"] = "2026-08-04T01:03:04Z"
        first_projection = parse_cyclonedx_json(json.dumps(first_document, sort_keys=True))
        second_projection = parse_cyclonedx_json(json.dumps(second_document, sort_keys=True))
        self.assertNotEqual(first_projection["source_sha256"], second_projection["source_sha256"])
        self.assertEqual(
            first_projection["semantic_sha256"], second_projection["semantic_sha256"]
        )

        profile = _profile("SOURCE_DIRECTORY")
        first = build_profile_observation(
            profile, first_projection, _input_identity("v1"), profile["scanner"]
        )
        second = build_profile_observation(
            profile, second_projection, _input_identity("v1"), profile["scanner"]
        )
        self.assertNotEqual(first["canonical_sha256"], second["canonical_sha256"])
        self.assertEqual(first["run_id"], second["run_id"])

    def test_observation_boundaries_and_scanner_identity_are_fail_closed(self) -> None:
        profile = _profile("OCI_ARCHIVE")
        wrong_scanner = copy.deepcopy(profile["scanner"])
        wrong_scanner["binary_sha256"] = "f" * 64
        with self.assertRaisesRegex(SelfTestError, "scanner identity"):
            build_profile_observation(profile, _projection(), _input_identity("oci"), wrong_scanner)

        observation = _observation("OCI_ARCHIVE", "2.31.0", "oci")
        self.assertEqual(observation["classification"], CLASSIFICATION)
        self.assertEqual(observation["generator_output_status"], GENERATOR_STATUS)
        self.assertEqual(observation["release_status"], RELEASE_STATUS)
        self.assertEqual(observation["product_conformity_status"], PRODUCT_STATUS)
        self.assertEqual(observation["manufacturer_approval_status"], "NOT_PROVIDED")
        self.assertEqual(observation["milestone_scope"], MILESTONE_SCOPE)

    def test_version_conflict_and_stale_portable_remain_open_without_population(self) -> None:
        source = _observation("SOURCE_DIRECTORY", "2.31.0", "source")
        oci = _observation("OCI_ARCHIVE", "2.31.0", "oci")
        portable = _observation("PORTABLE_RUNTIME", "2.28.0", "portable")

        first = reconcile_profile_observations([portable, source, oci])
        second = reconcile_profile_observations([copy.deepcopy(oci), copy.deepcopy(portable), copy.deepcopy(source)])
        codes = [item["code"] for item in first["comparison_findings"]]

        self.assertEqual(first, second)
        self.assertEqual(first["state"], "OPEN")
        self.assertIn("VERSION_CONFLICT", codes)
        self.assertIn("STALE_PORTABLE_RUNTIME", codes)
        self.assertEqual(first["population_policy"], "NO_CROSS_PROFILE_COMPONENT_POPULATION")
        self.assertNotIn("component_population", first)
        stale = next(item for item in first["comparison_findings"] if item["code"] == "STALE_PORTABLE_RUNTIME")
        self.assertIn("not semantic version ordering", stale["explanation"])
        self.assertEqual(
            {item["profile_kind"] for item in stale["evidence"]},
            {"SOURCE_DIRECTORY", "OCI_ARCHIVE", "PORTABLE_RUNTIME"},
        )

    def test_components_without_identifier_are_reported_not_silently_dropped(self) -> None:
        # A component carrying neither a valid purl nor a valid cpe cannot enter
        # cross-profile comparison; it must surface in unidentified_component_summary
        # instead of being silently dropped.
        cdx = _cdx("2.31.0")
        cdx["components"][0].pop("purl", None)
        cdx["components"][0].pop("cpe", None)
        source_projection = parse_cyclonedx_json(json.dumps(cdx, sort_keys=True) + "\n")
        source_profile = _profile("SOURCE_DIRECTORY")
        source = build_profile_observation(
            source_profile,
            source_projection,
            _input_identity("source"),
            source_profile["scanner"],
        )
        oci = _observation("OCI_ARCHIVE", "2.31.0", "oci")

        first = reconcile_profile_observations([source, oci])
        summary = first["unidentified_component_summary"]
        source_entry = next(
            item for item in summary if item["profile_kind"] == "SOURCE_DIRECTORY"
        )
        self.assertEqual(source_entry["count"], 1)
        self.assertEqual(source_entry["components"][0]["name"], "requests")
        self.assertNotIn("OCI_ARCHIVE", [item["profile_kind"] for item in summary])

        # Determinism: reordering the input observations yields a byte-identical
        # unidentified_component_summary, so the canonical hash stays stable.
        second = reconcile_profile_observations(
            [copy.deepcopy(oci), copy.deepcopy(source)]
        )
        self.assertEqual(
            first["unidentified_component_summary"],
            second["unidentified_component_summary"],
        )

    def test_tamper_duplicate_profile_kind_and_namespace_mismatch_are_rejected(self) -> None:
        source = _observation("SOURCE_DIRECTORY", "2.31.0", "source")
        oci = _observation("OCI_ARCHIVE", "2.31.0", "oci")
        forged = copy.deepcopy(oci)
        forged["release_status"] = "RELEASED"
        with self.assertRaisesRegex(SelfTestError, "cannot be released"):
            reconcile_profile_observations([source, forged])

        authority_side_channel = copy.deepcopy(oci)
        authority_side_channel["manufacturer_role"] = "APPROVED"
        authority_side_channel["canonical_sha256"] = canonical_selftest_sha256(
            authority_side_channel
        )
        authority_side_channel["run_id"] = selftest_run_id(authority_side_channel)
        with self.assertRaisesRegex(SelfTestError, "fields mismatch"):
            reconcile_profile_observations([source, authority_side_channel])

        duplicate = _observation("SOURCE_DIRECTORY", "2.31.0", "other")
        duplicate["profile_id"] = "different-source-profile"
        duplicate["canonical_sha256"] = canonical_selftest_sha256(duplicate)
        duplicate["run_id"] = selftest_run_id(duplicate)
        with self.assertRaisesRegex(SelfTestError, "one-per-profile-kind"):
            reconcile_profile_observations([source, duplicate])

        different = copy.deepcopy(oci)
        different["subject"]["comparison_namespace"] = "different-product"
        different["canonical_sha256"] = canonical_selftest_sha256(different)
        different["run_id"] = selftest_run_id(different)
        with self.assertRaisesRegex(SelfTestError, "comparison namespace"):
            reconcile_profile_observations([source, different])


if __name__ == "__main__":
    unittest.main()
