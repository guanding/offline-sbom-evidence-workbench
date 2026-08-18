from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbom_workbench.cli import main


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _cyclonedx_vex() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1234",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_present",
                    },
                    "affects": [{"ref": "pkg:pypi/requests@2.31.0?package-id=xyz"}],
                }
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")


class IntakeVexCliTests(unittest.TestCase):
    """M8-1: intake-vex end-to-end with mocked cosign.

    cosign binary is not acquired in this environment; the CLI path is exercised
    with a stub binary + subprocess mock. Trust anchors (cosign binary sha +
    runtime registry sha) are patched to stub identities, mirroring the M7-3
    signing test pattern. The issuer allowlist is a real vex-issuer-registry
    validated by load_and_validate_registry (no trust-anchor patch needed).
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        # VEX document + signature
        self.vex = self.root / "vex.json"
        _write(self.vex, _cyclonedx_vex())
        self.signature = self.root / "vex.json.sig"
        _write(self.signature, b"fake-detached-signature")
        # Issuer public key (trust anchor referenced by the allowlist)
        self.pubkey = self.root / "pubkey.pem"
        _write(self.pubkey, b"fake-public-key-material")
        self.pubkey_sha = hashlib.sha256(self.pubkey.read_bytes()).hexdigest()
        # Issuer allowlist (ADMITTED issuer)
        self.allowlist = self.root / "allowlist.json"
        self._write_allowlist(status="ADMITTED_FOR_VEX_INTAKE")
        # Stub cosign binary + cosign acquisition receipt + runtime registry
        self.cosign = self.root / "cosign"
        self.cosign.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.cosign.chmod(0o700)
        self.cosign_sha = hashlib.sha256(self.cosign.read_bytes()).hexdigest()
        self.cosign_receipt = self.root / "cosign-receipt.json"
        _write_json(
            self.cosign_receipt,
            {
                "schema_version": "cosign-acquisition-1.0",
                "status": "HASH_VERIFIED_BINARY_OBSERVED",
                "binary_relative_path": "cosign",
                "binary_sha256_expected": self.cosign_sha,
                "binary_sha256_observed": self.cosign_sha,
                "observed_version": "v3.1.2",
            },
        )
        self.registry = self.root / "runtime-registry.json"
        _write_json(
            self.registry,
            {
                "registry_type": "runtime-registry",
                "schema_version": "1.0",
                "updated_at": "2026-08-05",
                "runtimes": [
                    {
                        "runtime_id": "cosign-3.1.2",
                        "category": "signing",
                        "name": "cosign",
                        "version": "3.1.2",
                        "source_url": "https://github.com/sigstore/cosign.git",
                        "resolved_commit": "dc80df70da727f4abdd843640594025584a270ae",
                        "license_expression": "Apache-2.0",
                        "status": "LOCALLY_OBSERVED",
                        "artifact_sha256": self.cosign_sha,
                        "config_sha256": None,
                        "dependency_manifest_sha256": None,
                        "notes": "stub for offline test",
                    }
                ],
            },
        )
        self.registry_sha = hashlib.sha256(self.registry.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_allowlist(self, *, status: str, public_key_sha256: str | None = None) -> None:
        if status == "ADMITTED_FOR_VEX_INTAKE":
            issuer = {
                "issuer_id": "test-psirt-1",
                "display_name": "Test PSIRT",
                "identity_kind": "cosign-offline-key",
                "public_key_path": "pubkey.pem",
                "public_key_sha256": public_key_sha256 if public_key_sha256 is not None else self.pubkey_sha,
                "acquisition_receipt_ref": "evidence/acquisition/test-psirt-1-key.receipt.json",
                "status": "ADMITTED_FOR_VEX_INTAKE",
                "boundary": "admitted for VEX intake only",
            }
        else:
            issuer = {
                "issuer_id": "test-psirt-1",
                "display_name": "Test PSIRT",
                "identity_kind": "cosign-offline-key",
                "public_key_path": None,
                "public_key_sha256": None,
                "acquisition_receipt_ref": None,
                "status": "NOT_ADMITTED",
                "boundary": "not admitted",
            }
        _write_json(
            self.allowlist,
            {
                "registry_type": "vex-issuer-registry",
                "schema_version": "vex-issuer-allowlist-1.0",
                "updated_at": "2026-08-05",
                "issuers": [issuer],
            },
        )

    def _anchors(self) -> dict:
        return {
            "TRUSTED_COSIGN_BINARY_SHA256": self.cosign_sha,
            "TRUSTED_RUNTIME_REGISTRY_SHA256": self.registry_sha,
        }

    @staticmethod
    def _fake_cosign(argv, **kwargs):
        argv = list(argv)
        if "verify-blob" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=b"Verified OK", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    def _intake(self, output: Path, *, issuer_id: str = "test-psirt-1") -> int:
        return main(
            [
                "intake-vex",
                "--vex-document", str(self.vex),
                "--signature", str(self.signature),
                "--issuer-allowlist", str(self.allowlist),
                "--issuer-id", issuer_id,
                "--cosign-bin", str(self.cosign),
                "--cosign-receipt", str(self.cosign_receipt),
                "--runtime-registry", str(self.registry),
                "--output", str(output),
            ]
        )

    def test_intake_roundtrip(self) -> None:
        output = self.root / "intake-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._intake(output), 0)
        self.assertTrue(output.exists())
        receipt = json.loads(output.read_text())
        self.assertEqual(receipt["schema_version"], "sbom-workbench.vex-intake-receipt/v1")
        self.assertEqual(receipt["vex_format"], "cyclonedx-bom")
        self.assertEqual(receipt["statement_count"], 1)
        self.assertEqual(receipt["narrowing_eligible_count"], 1)
        self.assertEqual(receipt["issuer_id"], "test-psirt-1")
        self.assertEqual(
            receipt["vex_document_sha256"],
            hashlib.sha256(self.vex.read_bytes()).hexdigest(),
        )

    def test_intake_rejects_when_cosign_verify_fails(self) -> None:
        def rejecting_cosign(argv, **kwargs):
            argv = list(argv)
            if "verify-blob" in argv:
                return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"bad signature")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

        output = self.root / "intake-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=rejecting_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._intake(output), 2)
        self.assertFalse(output.exists())

    def test_intake_rejects_unregistered_issuer(self) -> None:
        output = self.root / "intake-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._intake(output, issuer_id="not-registered"), 2)

    def test_intake_rejects_not_admitted_issuer(self) -> None:
        self._write_allowlist(status="NOT_ADMITTED")
        output = self.root / "intake-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._intake(output), 2)

    def test_intake_rejects_public_key_hash_mismatch(self) -> None:
        self._write_allowlist(
            status="ADMITTED_FOR_VEX_INTAKE", public_key_sha256="b" * 64
        )
        output = self.root / "intake-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._intake(output), 2)


if __name__ == "__main__":
    unittest.main()
