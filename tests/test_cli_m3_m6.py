from __future__ import annotations

import contextlib
import gzip
import hashlib
import functools
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbom_workbench.cli import _validate_docker_archive_budget, main
from sbom_workbench.manifest import build_exact_set_manifest
from sbom_workbench.model import build_minimal_conflict_card
from sbom_workbench.model_eval import rule_only_advice
from sbom_workbench.selftest import SelfTestError
from sbom_workbench.source_only_validation import (
    SourceOnlyValidationError,
    validate_source_only_output,
)


def _cyclonedx() -> dict[str, object]:
    root_ref = "pkg:generic/euvd-sbom-matcher@2.3.0"
    component_ref = "pkg:pypi/fastapi@0.140.7"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:12345678-1234-4234-9234-123456789abc",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": "euvd-sbom-matcher",
                "version": "2.3.0",
                "purl": root_ref,
            }
        },
        "components": [
            {
                "bom-ref": component_ref,
                "type": "library",
                "name": "fastapi",
                "version": "0.140.7",
                "purl": component_ref,
            }
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [component_ref]},
            {"ref": component_ref, "dependsOn": []},
        ],
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class CliM3M6Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source-snapshot"
        self.source.mkdir()
        (self.source / "requirements.txt").write_text("fastapi==0.140.7\n", encoding="utf-8")
        self.portable = self.root / "portable-snapshot"
        self.portable.mkdir()
        (self.portable / "requirements.txt").write_text("fastapi==0.116.1\n", encoding="utf-8")
        self.image = self.root / "image.tar"
        # Minimal but valid docker-archive-shaped tarball so the OCI extraction
        # budget guard (SEC-03) accepts it; the fake Syft process never reads it.
        with tarfile.open(self.image, "w:") as archive_bundle:
            manifest = b'{"schemaVersion":2}'
            manifest_info = tarfile.TarInfo("manifest.json")
            manifest_info.size = len(manifest)
            archive_bundle.addfile(manifest_info, io.BytesIO(manifest))
            layer = gzip.compress(b"fake-oci-layer-bytes")
            layer_info = tarfile.TarInfo("blobs/sha256/layer")
            layer_info.size = len(layer)
            archive_bundle.addfile(layer_info, io.BytesIO(layer))
        self.syft = self.root / "syft"
        self.syft.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.syft.chmod(0o700)
        self.config = self.root / "syft-m3a.yaml"
        self.config.write_text("check-for-app-update: false\n", encoding="utf-8")
        self.sandbox = self.root / "sandbox-exec"
        self.sandbox.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.sandbox.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _trust_files(self, binary_anchor: str | None = None):
        binary_hash = hashlib.sha256(self.syft.read_bytes()).hexdigest()
        config_hash = hashlib.sha256(self.config.read_bytes()).hexdigest()
        pinned_binary = binary_anchor or binary_hash
        receipt = self.root / "receipt.json"
        _write_json(
            receipt,
            {
                "schema_version": "m3a-runtime-acquisition-1.0",
                "status": "ARCHIVE_HASH_VERIFIED_BINARY_OBSERVED",
                "resolved_commit": "test-commit",
                "binary_relative_path": "syft",
                "binary_sha256": pinned_binary,
                "config_relative_path": "syft-m3a.yaml",
                "config_sha256": config_hash,
                "observed_version": "1.50.0",
                "dependency_manifest_status": "NOT_ACQUIRED",
            },
        )
        registry = self.root / "runtime-registry.json"
        _write_json(
            registry,
            {
                "registry_type": "runtime-registry",
                "schema_version": "1.0",
                "updated_at": "2026-08-04",
                "runtimes": [
                    {
                        "runtime_id": "syft-1.50.0",
                        "category": "scanner",
                        "name": "Syft",
                        "version": "1.50.0",
                        "resolved_commit": "test-commit",
                        "artifact_sha256": pinned_binary,
                        "config_sha256": config_hash,
                        "status": "LOCALLY_OBSERVED",
                    }
                ],
            },
        )
        anchors = {
            "TRUSTED_SYFT_BINARY_SHA256": pinned_binary,
            "TRUSTED_SYFT_CONFIG_SHA256": config_hash,
            "TRUSTED_SYFT_RECEIPT_SHA256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
            "TRUSTED_RUNTIME_REGISTRY_SHA256": hashlib.sha256(registry.read_bytes()).hexdigest(),
            "TRUSTED_SYFT_COMMIT": "test-commit",
        }
        return receipt, registry, anchors

    def _selftest_arguments(self, output: Path, receipt: Path, registry: Path) -> list[str]:
        return [
            "selftest",
            "--source-root",
            str(self.source),
            "--active-source-root",
            str(self.root / "active-euvd-source"),
            "--image-archive",
            str(self.image),
            "--portable-root",
            str(self.portable),
            "--syft-bin",
            str(self.syft),
            "--syft-config",
            str(self.config),
            "--syft-receipt",
            str(receipt),
            "--runtime-registry",
            str(registry),
            "--sandbox-exec",
            str(self.sandbox),
            "--output-root",
            str(output),
        ]

    @staticmethod
    def _fake_process(argv, cyclonedx_document=None, **kwargs):
        cache_root = Path(kwargs["env"]["XDG_CACHE_HOME"])
        (cache_root / "syft" / "python" / "v1" / "test-empty-cache-key").mkdir(
            parents=True,
            exist_ok=True,
        )
        if "version" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=json.dumps(
                    {"application": "syft", "version": "1.50.0"}
                ).encode(),
                stderr=b"",
            )
        for argument in argv:
            if "=" not in argument:
                continue
            format_name, output_name = argument.split("=", 1)
            if format_name not in {"syft-json", "cyclonedx-json", "spdx-json"}:
                continue
            output = Path(output_name)
            if format_name == "cyclonedx-json":
                _write_json(
                    output,
                    cyclonedx_document
                    if cyclonedx_document is not None
                    else _cyclonedx(),
                )
            elif format_name == "syft-json":
                _write_json(
                    output,
                    {
                        "artifacts": [],
                        "artifactRelationships": [],
                        "descriptor": {"name": "syft", "version": "1.50.0"},
                    },
                )
            else:
                _write_json(
                    output,
                    {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "documentNamespace": "https://example.invalid/selftest",
                        "packages": [],
                    },
                )
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    def _source_only_arguments(self, output: Path, receipt: Path, registry: Path) -> list[str]:
        return [
            "scan-source-only",
            "--source-root",
            str(self.source),
            "--active-source-root",
            str(self.root / "active-euvd-source"),
            "--syft-bin",
            str(self.syft),
            "--syft-config",
            str(self.config),
            "--syft-receipt",
            str(receipt),
            "--runtime-registry",
            str(registry),
            "--sandbox-exec",
            str(self.sandbox),
            "--output-root",
            str(output),
        ]

    def _source_acquisition_receipt(self) -> tuple[Path, str]:
        commit = "7" * 40
        tree_manifest = build_exact_set_manifest(
            self.source, f"source-fixture@{commit}"
        )
        evidence_path = "requirements.txt"
        evidence_sha256 = hashlib.sha256(
            (self.source / evidence_path).read_bytes()
        ).hexdigest()
        report = {
            "schema_version": "1.1",
            "acquisition_status": "ACQUIRED_UNSEALED",
            "acquired_at_utc": "2026-08-20T00:00:00Z",
            "dataset_id": "source-fixture",
            "source_url": "https://github.com/example/source-fixture.git",
            "resolved_source_ips": ["8.8.8.8"],
            "registry_sha256": "1" * 64,
            "registry_entry_sha256": "2" * 64,
            "resolved_commit": commit,
            "annotated_tag_object": None,
            "git_tree_sha": "3" * 40,
            "git_archive_sha256": "4" * 64,
            "license_expression": "LicenseRef-Test-Only",
            "license_review_status": "TEST_ONLY_NOT_RIGHTS_REVIEW",
            "license_evidence": [
                {"relative_path": evidence_path, "sha256": evidence_sha256}
            ],
            "tool_runtime": {
                "git": {
                    "path": "/usr/bin/git",
                    "version": "git version test",
                    "sha256": "5" * 64,
                },
                "python": {
                    "path": "/usr/bin/python3",
                    "version": "3.test",
                    "sha256": "6" * 64,
                },
            },
            "tree_manifest": tree_manifest,
        }
        path = self.root / "source-acquisition-receipt.json"
        _write_json(path, report)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_scan_source_only_produces_cyclonedx_json_not_xml(self) -> None:
        # Regression for the local-model failure mode where Syft was invoked
        # with cyclonedx-xml and the result was saved as .json: the downstream
        # EUVD matcher accepts CycloneDX JSON only (bomFormat == "CycloneDX").
        receipt, registry, anchors = self._trust_files()
        output = self.root / "source-only-output"
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(
                main(self._source_only_arguments(output, receipt, registry)), 0
            )
        report = json.loads(stdout.getvalue())
        cyclonedx_path = output / "raw" / "m3a-source-directory" / "raw.cyclonedx.json"
        raw_bytes = cyclonedx_path.read_bytes()
        self.assertFalse(raw_bytes.lstrip().startswith(b"<"))
        document = json.loads(raw_bytes.decode("utf-8"))
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(
            report["status"],
            "SOURCE_ONLY_SCAN_COMPLETE_OPEN_CANDIDATE",
        )
        self.assertEqual(report["profile_count"], 1)
        self.assertEqual(report["raw_format_count"], 3)
        self.assertEqual(report["reconciliation_status"], "NOT_APPLICABLE_SINGLE_FACE")
        self.assertEqual(report["network_policy"], "MACOS_SANDBOX_EXEC_DENY_NETWORK")
        # Single-face output must NOT synthesize the three-face artefacts.
        self.assertFalse((output / "data").exists())
        self.assertEqual(
            {item.name for item in (output / "raw").iterdir()},
            {"m3a-source-directory"},
        )
        self.assertEqual(
            {item.name for item in (output / "raw" / "m3a-source-directory").iterdir()},
            {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"},
        )
        validation = validate_source_only_output(output, source_root=self.source)
        self.assertEqual(
            validation["status"],
            "SOURCE_ONLY_OUTPUT_VALID_WITH_SINGLE_FACE_BOUNDARY",
        )
        self.assertEqual(validation["source_reverification"], "MATCHED_CURRENT_SOURCE_ROOT")
        complete = json.loads((output / "SELFTEST_COMPLETE.json").read_text("utf-8"))
        self.assertEqual(complete["status"], report["status"])
        self.assertEqual(complete["run_id"], report["run_id"])

    def test_source_only_binds_governed_acquisition_receipt_and_tree(self) -> None:
        receipt, registry, anchors = self._trust_files()
        source_receipt, source_receipt_sha256 = self._source_acquisition_receipt()
        output = self.root / "governed-source-output"
        arguments = self._source_only_arguments(output, receipt, registry) + [
            "--source-acquisition-receipt",
            str(source_receipt),
            "--trusted-source-acquisition-receipt-sha256",
            source_receipt_sha256,
        ]
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(main(arguments), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            report["source_provenance_status"],
            "GOVERNED_ACQUISITION_RECEIPT_AND_TREE_VERIFIED",
        )
        copied_receipt = output / "source-acquisition-receipt.json"
        self.assertEqual(copied_receipt.read_bytes(), source_receipt.read_bytes())
        validation = validate_source_only_output(output, source_root=self.source)
        self.assertEqual(
            validation["source_provenance_status"],
            "GOVERNED_ACQUISITION_RECEIPT_AND_TREE_VERIFIED",
        )

    def test_source_only_validator_rejects_copied_acquisition_receipt_tampering(self) -> None:
        receipt, registry, anchors = self._trust_files()
        source_receipt, source_receipt_sha256 = self._source_acquisition_receipt()
        output = self.root / "tampered-source-receipt-output"
        arguments = self._source_only_arguments(output, receipt, registry) + [
            "--source-acquisition-receipt",
            str(source_receipt),
            "--trusted-source-acquisition-receipt-sha256",
            source_receipt_sha256,
        ]
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(arguments), 0)
        copied = output / "source-acquisition-receipt.json"
        copied.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            SourceOnlyValidationError,
            "external trust anchor",
        ):
            validate_source_only_output(output, source_root=self.source)

    def test_source_only_validator_rejects_resealed_population_reconciliation_forgery(self) -> None:
        receipt, registry, anchors = self._trust_files()
        output = self.root / "population-forgery-output"
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(self._source_only_arguments(output, receipt, registry)), 0)
        population_path = output / "component-population.json"
        scan_receipt_path = output / "scan-receipt.json"
        completion_path = output / "SELFTEST_COMPLETE.json"
        population = json.loads(population_path.read_text("utf-8"))
        population["reconciliation"]["matched_item_count"] = 999
        _write_json(population_path, population)
        scan_receipt = json.loads(scan_receipt_path.read_text("utf-8"))
        scan_receipt["component_population"]["sha256"] = hashlib.sha256(
            population_path.read_bytes()
        ).hexdigest()
        _write_json(scan_receipt_path, scan_receipt)
        completion = json.loads(completion_path.read_text("utf-8"))
        completion["scan_receipt_sha256"] = hashlib.sha256(
            scan_receipt_path.read_bytes()
        ).hexdigest()
        _write_json(completion_path, completion)
        with self.assertRaisesRegex(
            SourceOnlyValidationError,
            "component reconciliation does not rederive",
        ):
            validate_source_only_output(output, source_root=self.source)

    @staticmethod
    def _empty_cyclonedx_document() -> dict[str, object]:
        # Models syft's source-only output for a Python project with no
        # declaration file and no installed environment: the catalogue is
        # empty even though third-party packages are imported.
        document = _cyclonedx()
        root_ref = document["metadata"]["component"]["bom-ref"]
        document["components"] = []
        document["dependencies"] = [{"ref": root_ref, "dependsOn": []}]
        return document

    def _source_only_args_for(
        self, source: Path, output: Path, receipt: Path, registry: Path
    ) -> list[str]:
        return [
            "scan-source-only",
            "--source-root",
            str(source),
            "--active-source-root",
            str(self.root / "active-euvd-source"),
            "--syft-bin",
            str(self.syft),
            "--syft-config",
            str(self.config),
            "--syft-receipt",
            str(receipt),
            "--runtime-registry",
            str(registry),
            "--sandbox-exec",
            str(self.sandbox),
            "--output-root",
            str(output),
        ]

    def _run_source_only_with(
        self, source: Path, output: Path, cyclonedx_document: dict[str, object]
    ) -> dict[str, object]:
        receipt, registry, anchors = self._trust_files()
        fake = functools.partial(
            self._fake_process, cyclonedx_document=cyclonedx_document
        )
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=fake),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(
                main(self._source_only_args_for(source, output, receipt, registry)),
                0,
            )
        return json.loads(stdout.getvalue())

    def test_scan_source_only_flags_zero_components_python_project(self) -> None:
        # M9-1: a Python project with imports (main.py: import pygame) but no
        # declaration file and no installed environment yields zero components
        # because syft's python-package-cataloger never reads import statements.
        # The workbench must surface this as an explicit finding rather than
        # silently accepting an empty SBOM as "complete".
        zero_source = self.root / "zero-components-source"
        zero_source.mkdir()
        (zero_source / "main.py").write_text("import pygame\n", encoding="utf-8")
        output = self.root / "zero-components-output"
        report = self._run_source_only_with(
            zero_source, output, self._empty_cyclonedx_document()
        )
        self.assertEqual(
            report["status"],
            "SOURCE_ONLY_SCAN_COMPLETE_ZERO_COMPONENTS_OPEN_CANDIDATE",
        )
        observation = json.loads((output / "source-observation.json").read_text("utf-8"))
        self.assertIn(
            "ZERO_COMPONENTS_PYTHON_PROJECT_REVIEW", observation["blindspots"]
        )
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        self.assertEqual(scan_receipt["status"], report["status"])
        self.assertEqual(scan_receipt["scans"][0]["component_count"], 0)
        self.assertTrue(scan_receipt["scans"][0]["python_source_files_present"])
        self.assertFalse(scan_receipt["scans"][0]["declared_dependency_files_present"])
        self.assertEqual(
            scan_receipt["scans"][0]["findings"],
            ["ZERO_COMPONENTS_PYTHON_PROJECT_REVIEW"],
        )
        complete = json.loads((output / "SELFTEST_COMPLETE.json").read_text("utf-8"))
        self.assertEqual(complete["status"], report["status"])

    def test_scan_source_only_zero_components_with_declaration_is_coverage_hold(self) -> None:
        # A declaration file is evidence that the software scope is non-empty;
        # it must not suppress a zero-product-package coverage warning.
        declared_source = self.root / "declared-zero-source"
        declared_source.mkdir()
        (declared_source / "main.py").write_text("import pygame\n", encoding="utf-8")
        (declared_source / "requirements.txt").write_text("pygame\n", encoding="utf-8")
        output = self.root / "declared-zero-output"
        report = self._run_source_only_with(
            declared_source, output, self._empty_cyclonedx_document()
        )
        self.assertEqual(
            report["status"],
            "SOURCE_ONLY_SCAN_COMPLETE_COVERAGE_HOLD_OPEN_CANDIDATE",
        )
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        self.assertIn(
            "NO_PRODUCT_PACKAGE_COMPONENTS_FOR_DECLARED_ECOSYSTEM_REVIEW",
            scan_receipt["scans"][0]["findings"],
        )
        self.assertTrue(scan_receipt["scans"][0]["declared_dependency_files_present"])

    def test_scan_source_only_zero_components_c_cpp_project_flagged(self) -> None:
        # M9 extension: a C/C++ source-only project (no .py, no package-manager
        # declaration) yielding zero components now fires the C/C++ blind spot
        # (was not flagged when M9-1 was Python-only).
        c_source = self.root / "c-source"
        c_source.mkdir()
        (c_source / "main.c").write_text(
            "int main(void){return 0;}\n", encoding="utf-8"
        )
        output = self.root / "c-source-output"
        report = self._run_source_only_with(
            c_source, output, self._empty_cyclonedx_document()
        )
        self.assertEqual(
            report["status"], "SOURCE_ONLY_SCAN_COMPLETE_ZERO_COMPONENTS_OPEN_CANDIDATE"
        )
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        self.assertIn(
            "ZERO_COMPONENTS_C_CPP_PROJECT_REVIEW", scan_receipt["scans"][0]["findings"]
        )
        self.assertFalse(scan_receipt["scans"][0]["python_source_files_present"])
        self.assertTrue(scan_receipt["scans"][0]["c_cpp_source_files_present"])

    def test_scan_source_only_requirements_r_reference_flagged(self) -> None:
        # M9 extension: a requirements.txt with `-r <file>` is flagged because
        # syft 1.50.0 does not follow the reference. Uses a non-empty SBOM so
        # the requirements-r finding is the only one (no zero-component status).
        rr_source = self.root / "requirements-r-source"
        rr_source.mkdir()
        (rr_source / "requirements.txt").write_text(
            "-r requirements/prod.txt\n", encoding="utf-8"
        )
        output = self.root / "requirements-r-output"
        self._run_source_only_with(rr_source, output, _cyclonedx())
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        rr = scan_receipt["scans"][0]["requirements_r_reference"]
        self.assertTrue(rr["requirements_r_reference_present"])
        self.assertIn("requirements/prod.txt", rr["referenced_files"])
        self.assertIn(
            "REQUIREMENTS_R_REFERENCE_NOT_FOLLOWED_BY_SYFT_REVIEW",
            scan_receipt["scans"][0]["findings"],
        )

    def test_scan_source_only_home_assistant_manifest_deps_flagged(self) -> None:
        # M9 extension: a Home Assistant manifest.json with `requirements` not
        # in the SBOM is flagged. AUXILIARY: never enters CycloneDX.
        ha_source = self.root / "ha-source"
        ha_source.mkdir()
        (ha_source / "manifest.json").write_text(
            '{"domain":"x","requirements":["example-ha-client==0.3.17"]}',
            encoding="utf-8",
        )
        output = self.root / "ha-output"
        self._run_source_only_with(ha_source, output, _cyclonedx())
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        ha = scan_receipt["scans"][0]["home_assistant_manifest"]
        self.assertTrue(ha["home_assistant_manifest_present"])
        self.assertIn("example-ha-client", ha["apparent_gaps"])
        self.assertIn(
            "HOME_ASSISTANT_MANIFEST_DEPS_NOT_IN_SBOM_REVIEW",
            scan_receipt["scans"][0]["findings"],
        )

    def test_scan_source_only_nonzero_components_records_scan_detail_fields(self) -> None:
        # M9-3: the four scan-detail fields are always recorded (even when no
        # finding fires), so the receipt is unambiguous about what was checked.
        output = self.root / "one-component-output"
        report = self._run_source_only_with(self.source, output, _cyclonedx())
        self.assertEqual(report["status"], "SOURCE_ONLY_SCAN_COMPLETE_OPEN_CANDIDATE")
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        self.assertEqual(scan_receipt["scans"][0]["component_count"], 1)
        self.assertEqual(scan_receipt["scans"][0]["findings"], [])
        for field in (
            "component_count",
            "python_source_files_present",
            "declared_dependency_files_present",
            "findings",
        ):
            self.assertIn(field, scan_receipt["scans"][0])

    def test_scan_source_only_import_evidence_reports_pygame_gap(self) -> None:
        # M9-2: for a zero-component Python project, the import evidence must
        # surface the third-party packages the code imports (here pygame) that
        # syft's catalogue missed, so the gap is explicit and auditable.
        zero_source = self.root / "import-evidence-source"
        zero_source.mkdir()
        (zero_source / "main.py").write_text(
            "import pygame\nimport os\n", encoding="utf-8"
        )
        output = self.root / "import-evidence-output"
        self._run_source_only_with(
            zero_source, output, self._empty_cyclonedx_document()
        )
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        evidence = scan_receipt["scans"][0]["import_evidence"]
        self.assertIsNotNone(evidence)
        self.assertIn("pygame", evidence["imported_third_party_modules"])
        self.assertIn("pygame", evidence["apparent_gaps"])
        self.assertNotIn("os", evidence["imported_third_party_modules"])  # stdlib
        self.assertIn("AUXILIARY_NOT_SBOM", evidence["boundary"])

    def test_scan_source_only_import_evidence_null_for_non_python(self) -> None:
        # Non-Python project → no .py files → import_evidence is null.
        non_python_source = self.root / "non-python-import-source"
        non_python_source.mkdir()
        (non_python_source / "main.c").write_text(
            "int main(void){return 0;}\n", encoding="utf-8"
        )
        output = self.root / "non-python-import-output"
        self._run_source_only_with(
            non_python_source, output, self._empty_cyclonedx_document()
        )
        scan_receipt = json.loads((output / "scan-receipt.json").read_text("utf-8"))
        self.assertIsNone(scan_receipt["scans"][0]["import_evidence"])

    def test_scan_source_only_output_is_rejected_by_three_face_root_validation(self) -> None:
        # A single-face scan must NOT pass verify_selftest_root (which requires
        # exactly three profiles and a sealed M4A package); this is the intended
        # isolation between the single-face escape hatch and the full pipeline.
        receipt, registry, anchors = self._trust_files()
        output = self.root / "source-only-output-rejected"
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(self._source_only_arguments(output, receipt, registry)), 0
            )
        stderr = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            contextlib.redirect_stdout(stderr),
        ):
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]), 2
            )
        self.assertIn("BLOCKED", stderr.getvalue())

    def test_selftest_runs_three_pinned_network_denied_scans_and_seals_pack(self) -> None:
        receipt, registry, anchors = self._trust_files()
        scanner_identity = {
            "name": "syft",
            "version": "1.50.0",
            "binary_sha256": anchors["TRUSTED_SYFT_BINARY_SHA256"],
            "config_sha256": anchors["TRUSTED_SYFT_CONFIG_SHA256"],
        }
        acquisition_identity = {
            "binary_sha256": anchors["TRUSTED_SYFT_BINARY_SHA256"],
            "config_sha256": anchors["TRUSTED_SYFT_CONFIG_SHA256"],
            "acquisition_receipt_sha256": anchors["TRUSTED_SYFT_RECEIPT_SHA256"],
            "runtime_registry_sha256": anchors["TRUSTED_RUNTIME_REGISTRY_SHA256"],
            "resolved_commit": anchors["TRUSTED_SYFT_COMMIT"],
        }
        output = self.root / "selftest-output"
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_process) as run,
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(main(self._selftest_arguments(output, receipt, registry)), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["raw_format_count"], 9)
        self.assertEqual(report["reconciliation_status"], "OPEN")
        self.assertEqual(report["privacy_gate"], "HOLD_NOT_TECHNICALLY_DEMONSTRATED")
        self.assertEqual(report["host_filesystem_isolation"], "NOT_PROVIDED_BY_NETWORK_SANDBOX")
        self.assertEqual(run.call_count, 4)
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[0], str(self.sandbox.resolve()))
            self.assertIn("(deny network*)", argv[2])
        for profile_id in (
            "m3a-source-directory",
            "m3a-oci-archive",
            "m3a-portable-runtime",
        ):
            self.assertEqual(
                {item.name for item in (output / "raw" / profile_id).iterdir()},
                {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"},
            )
        run_directory = Path(report["run_directory"])
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(["validate-selftest-output", "--run-directory", str(run_directory)]),
                0,
            )
        backup = self.root / "selftest-backup"
        restored = self.root / "selftest-restored"
        backup_stdout = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(backup_stdout),
        ):
            self.assertEqual(
                main(
                    [
                        "backup-selftest",
                        "--source-root",
                        str(output),
                        "--backup",
                        str(backup),
                    ]
                ),
                0,
            )
        manifest_anchor = json.loads(backup_stdout.getvalue())["manifest_sha256"]
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(
                    [
                        "validate-selftest-backup",
                        "--backup",
                        str(backup),
                        "--trusted-manifest-sha256",
                        manifest_anchor,
                    ]
                ),
                0,
            )
        handoffs = self.root / "handoffs"
        handoff_stdout = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(handoff_stdout),
        ):
            self.assertEqual(
                main(
                    [
                        "prepare-euvd-handoff",
                        "--selftest-root",
                        str(output),
                        "--profile-id",
                        "m3a-source-directory",
                        "--handoff-root",
                        str(handoffs),
                    ]
                ),
                0,
            )
        handoff_report = json.loads(handoff_stdout.getvalue())
        self.assertEqual(
            handoff_report["source_binding_status"],
            "DERIVED_FROM_VERIFIED_M3A_ROOT",
        )
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(
                    [
                        "validate-euvd-handoff",
                        "--handoff-directory",
                        str(handoffs / handoff_report["handoff_id"]),
                        "--selftest-root",
                        str(output),
                    ]
                ),
                0,
            )
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(
                    [
                        "restore-selftest",
                        "--backup",
                        str(backup),
                        "--destination",
                        str(restored),
                        "--trusted-manifest-sha256",
                        manifest_anchor,
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]),
                0,
            )

        unbound_profile = output / "raw" / "unbound-fourth-profile"
        unbound_profile.mkdir()
        raw_extra = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(raw_extra),
        ):
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]),
                2,
            )
        self.assertIn("raw profile directory exact-set mismatch", raw_extra.getvalue())
        unbound_profile.rmdir()

        unbound_data = output / "data" / "unbound.txt"
        unbound_data.write_text("unbound\n", encoding="utf-8")
        data_extra = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(data_extra),
        ):
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]),
                2,
            )
        self.assertIn("data top-level exact-set mismatch", data_extra.getvalue())
        unbound_data.unlink()

        receipt_path = output / "scan-receipt.json"
        completion_path = output / "SELFTEST_COMPLETE.json"
        original_receipt = receipt_path.read_bytes()
        original_completion = completion_path.read_bytes()
        forged_receipt = json.loads(original_receipt)
        forged_receipt["source_input_identity"] = {
            "root_id": "forged-source",
            "sha256": "0" * 64,
            "file_count": 999,
            "total_bytes": 999,
        }
        _write_json(receipt_path, forged_receipt)
        forged_completion = json.loads(original_completion)
        forged_completion["scan_receipt_sha256"] = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        _write_json(completion_path, forged_completion)
        provenance_tamper = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(provenance_tamper),
        ):
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]),
                2,
            )
        self.assertIn(
            "input identity does not match sealed profile",
            provenance_tamper.getvalue(),
        )
        receipt_path.write_bytes(original_receipt)
        completion_path.write_bytes(original_completion)
        blocked = io.StringIO()
        with (
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            contextlib.redirect_stdout(blocked),
        ):
            self.assertEqual(main(self._selftest_arguments(output, receipt, registry)), 2)
        self.assertIn("refusing overwrite", blocked.getvalue())
        (output / "raw" / "m3a-source-directory" / "raw.spdx.json").write_text(
            "{}\n", encoding="utf-8"
        )
        tampered = io.StringIO()
        with (
            patch("sbom_workbench.selftest_root.SCANNER_IDENTITY", scanner_identity),
            patch(
                "sbom_workbench.selftest_root.ACQUISITION_IDENTITY",
                acquisition_identity,
            ),
            contextlib.redirect_stdout(tampered),
        ):
            self.assertEqual(
                main(["validate-selftest-root", "--output-root", str(output)]),
                2,
            )
        self.assertIn("raw profile manifest mismatch", tampered.getvalue())

    def test_fake_syft_cannot_pass_a_pinned_binary_hash_mismatch(self) -> None:
        receipt, registry, anchors = self._trust_files(binary_anchor="0" * 64)
        output = self.root / "blocked-output"
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_EXEC", self.sandbox.resolve()),
            patch("sbom_workbench.cli.TRUSTED_SANDBOX_UID", os.getuid()),
            patch("sbom_workbench.cli.subprocess.run") as run,
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(main(self._selftest_arguments(output, receipt, registry)), 2)
        self.assertIn("binary SHA-256", stdout.getvalue())
        run.assert_not_called()
        self.assertTrue((output / "FAILED.json").is_file())

    def test_fake_sandbox_wrapper_is_rejected_before_scanner_execution(self) -> None:
        receipt, registry, anchors = self._trust_files()
        output = self.root / "fake-sandbox-output"
        stdout = io.StringIO()
        with (
            patch.multiple("sbom_workbench.cli", **anchors),
            patch(
                "sbom_workbench.cli.TRUSTED_SANDBOX_EXEC",
                self.syft.resolve(),
            ),
            patch("sbom_workbench.cli.subprocess.run") as run,
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(main(self._selftest_arguments(output, receipt, registry)), 2)
        self.assertIn("fixed macOS", stdout.getvalue())
        run.assert_not_called()

    def test_euvd_handoff_and_selftest_recovery_commands(self) -> None:
        blocked_backup = io.StringIO()
        with contextlib.redirect_stdout(blocked_backup):
            self.assertEqual(
                main(
                    [
                        "backup-selftest",
                        "--source-root",
                        str(self.source),
                        "--backup",
                        str(self.root / "invalid-backup"),
                    ]
                ),
                2,
            )
        self.assertIn("self-test output root exact-set", blocked_backup.getvalue())

    def test_clear_selftest_requires_marked_direct_child_and_external_receipt(self) -> None:
        sandbox = self.root / "clear-sandbox"
        sandbox.mkdir()
        (sandbox / ".ALLOW_SELFTEST_CLEAR").write_text(
            "SELF_TEST_CLEAR_SANDBOX_V1\n", encoding="utf-8"
        )
        run = sandbox / "selftest-run"
        run.mkdir()
        _write_json(
            run / "run.json",
            {
                "classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE",
                "run_id": "selftest-run",
            },
        )
        _write_json(run / "COMPLETE.json", {"status": "COMPLETE"})
        receipt = self.root / "clear-receipt.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    [
                        "clear-selftest",
                        "--run-directory",
                        str(run),
                        "--allowed-parent",
                        str(sandbox),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                0,
            )
        self.assertFalse(run.exists())
        self.assertTrue(receipt.is_file())
        self.assertEqual(
            json.loads(stdout.getvalue())["customer_volume_erasure"], "NOT_ASSESSED"
        )

    def test_model_evaluation_reads_key_only_from_environment_and_never_prints_it(self) -> None:
        cards = self.root / "cards.json"
        _write_json(
            cards,
            [
                build_minimal_conflict_card(
                    "selftest-run",
                    {
                        "conflict_id": "version-drift",
                        "field": "version",
                        "claims": [
                            {
                                "claim_id": "claim-source",
                                "value": "0.140.7",
                                "evidence_ids": ["evidence-source"],
                            },
                            {
                                "claim_id": "claim-portable",
                                "value": "0.116.1",
                                "evidence_ids": ["evidence-portable"],
                            },
                        ],
                    },
                )
            ],
        )
        runtime = self.root / "runtime.json"
        runtime.write_bytes(
            (
                Path(__file__).resolve().parents[1]
                / "datasets"
                / "m5_local_model_observations.json"
            ).read_bytes()
        )
        output = self.root / "evaluation.json"
        secret = "test-only-secret-value"

        def fake_transport(endpoint, headers, payload, timeout):
            request = json.loads(payload)
            sent_card = json.loads(request["input"])
            suggestion = rule_only_advice(sent_card)["suggestion"]
            return json.dumps(
                {
                    "object": "response",
                    "status": "completed",
                    "model": request["model"],
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": json.dumps(suggestion),
                                }
                            ],
                        }
                    ],
                }
            ).encode("utf-8")

        stdout = io.StringIO()
        with (
            patch.dict(os.environ, {"SBOM_OMLX_API_KEY": secret}, clear=False),
            patch("sbom_workbench.model._loopback_transport", fake_transport),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(
                main(
                    [
                        "run-model-evaluation",
                        "--cards",
                        str(cards),
                        "--runtime-observations",
                        str(runtime),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
        self.assertNotIn(secret, stdout.getvalue())
        report = json.loads(stdout.getvalue())
        self.assertFalse(report["api_key_captured"])
        self.assertEqual(report["decision"], "SHADOW_ONLY_HOLD")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["validate-model-evaluation", "--evaluation", str(output)]), 0
            )


class OciArchiveBudgetTests(unittest.TestCase):
    """OCI docker-archive extraction budget guard (SEC-03, M3-4)."""

    @staticmethod
    def _layer_info(name: str, payload: bytes) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        return info

    def _write_archive(self, members: list[tuple[str, bytes]]) -> Path:
        handle = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        archive = Path(handle.name)
        handle.close()
        with tarfile.open(archive, mode="w:") as bundle:
            for name, payload in members:
                bundle.addfile(self._layer_info(name, payload), io.BytesIO(payload))
        return archive

    def test_gzip_layer_exceeding_uncompressed_budget_is_rejected(self) -> None:
        payload = b"\x00" * 4096
        compressed = gzip.compress(payload)
        archive = self._write_archive([("blobs/sha256/layer", compressed)])
        try:
            with self.assertRaisesRegex(SelfTestError, "uncompressed size exceeds"):
                _validate_docker_archive_budget(archive, max_uncompressed_bytes=512)
        finally:
            archive.unlink()

    def test_layer_count_exceeding_budget_is_rejected(self) -> None:
        compressed = gzip.compress(b"x")
        archive = self._write_archive(
            [(f"blobs/sha256/layer-{index}", compressed) for index in range(3)]
        )
        try:
            with self.assertRaisesRegex(SelfTestError, "layer count exceeds budget"):
                _validate_docker_archive_budget(archive, max_layers=2)
        finally:
            archive.unlink()

    def test_layer_exceeding_compressed_size_budget_is_rejected(self) -> None:
        compressed = gzip.compress(b"x")
        archive = self._write_archive([("blobs/sha256/layer", compressed)])
        try:
            with self.assertRaisesRegex(SelfTestError, "compressed-size budget"):
                _validate_docker_archive_budget(archive, max_layer_compressed_bytes=1)
        finally:
            archive.unlink()

    def test_non_gzip_members_are_ignored_and_valid_archive_passes(self) -> None:
        manifest = b'{"schemaVersion":2}'
        compressed = gzip.compress(b"layer-bytes")
        archive = self._write_archive(
            [("manifest.json", manifest), ("blobs/sha256/layer", compressed)]
        )
        try:
            result = _validate_docker_archive_budget(archive)
        finally:
            archive.unlink()
        self.assertEqual(result["layer_count"], 1)
        self.assertEqual(result["total_uncompressed_bytes"], len(b"layer-bytes"))


if __name__ == "__main__":
    unittest.main()
