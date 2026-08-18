from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock  # noqa: F401  (retained for mock.patch fallback)
from unittest.mock import patch

from sbom_workbench.cli import main


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


class CosignSigningCliTests(unittest.TestCase):
    """M7-3: sign/verify a sealed pack's ite6-statement.json with mocked cosign.

    cosign binary is not acquired in this environment (network-gated); the CLI
    path is exercised end-to-end with a stub binary + subprocess mock. Trust
    anchors (TRUSTED_COSIGN_BINARY_SHA256 / TRUSTED_RUNTIME_REGISTRY_SHA256)
    are patched to the stub identities, mirroring the Syft test pattern.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        # Minimal sealed pack: _execute_sign reads only ite6-statement.json.
        self.pack = self.root / "pack"
        self.pack.mkdir()
        self.ite6 = self.pack / "ite6-statement.json"
        _write_json(
            self.ite6,
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "sbom-workbench.selftest-pack/v1",
                "subject": [
                    {"name": "canonical-reconciliation", "digest": {"sha256": "a" * 64}}
                ],
                "predicate": {"run_id": "r1"},
            },
        )
        # Stub cosign binary + signing key.
        self.cosign = self.root / "cosign"
        self.cosign.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        self.cosign.chmod(0o700)
        self.cosign_sha = hashlib.sha256(self.cosign.read_bytes()).hexdigest()
        self.key = self.root / "cosign.key"
        self.key.write_text("fake-key-material", encoding="utf-8")
        self.key.chmod(0o600)
        # cosign acquisition receipt (only the fields _verify_cosign_acquisition checks).
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
        # Runtime registry with a cosign-3.1.2 signing entry bound to the stub binary.
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

    def _anchors(self) -> dict:
        return {
            "TRUSTED_COSIGN_BINARY_SHA256": self.cosign_sha,
            "TRUSTED_RUNTIME_REGISTRY_SHA256": self.registry_sha,
        }

    @staticmethod
    def _fake_cosign(argv, **kwargs):
        argv = list(argv)
        if "sign-blob" in argv:
            sig_path = None
            for idx, token in enumerate(argv):
                if token == "--output-signature" and idx + 1 < len(argv):
                    sig_path = Path(argv[idx + 1])
            if sig_path is not None:
                sig_path.write_bytes(b"fake-detached-signature")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        if "verify-blob" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=b"Verified OK", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    def _sign(self, output: Path) -> int:
        return main(
            [
                "sign-selftest-pack",
                "--pack-directory", str(self.pack),
                "--cosign-bin", str(self.cosign),
                "--cosign-receipt", str(self.cosign_receipt),
                "--runtime-registry", str(self.registry),
                "--key", str(self.key),
                "--key-id", "test-key-1",
                "--output", str(output),
            ]
        )

    def _verify(self, receipt: Path) -> int:
        return main(
            [
                "verify-signature",
                "--pack-directory", str(self.pack),
                "--cosign-bin", str(self.cosign),
                "--cosign-receipt", str(self.cosign_receipt),
                "--runtime-registry", str(self.registry),
                "--key", str(self.key),
                "--receipt", str(receipt),
            ]
        )

    def test_sign_then_verify_roundtrip(self) -> None:
        sig_receipt = self.root / "sig-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._sign(sig_receipt), 0)
        self.assertTrue(sig_receipt.exists())
        receipt = json.loads(sig_receipt.read_text())
        self.assertEqual(receipt["scheme"], "cosign-key-based-offline")
        self.assertEqual(
            receipt["subject"]["digest"]["sha256"],
            hashlib.sha256(self.ite6.read_bytes()).hexdigest(),
        )
        self.assertTrue((self.pack / "ite6-statement.json.sig").exists())
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._verify(sig_receipt), 0)

    def test_verify_rejects_when_cosign_verify_fails(self) -> None:
        sig_receipt = self.root / "sig-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self._sign(sig_receipt)
        # Tamper the signature on disk; cosign verify-blob must reject it.
        (self.pack / "ite6-statement.json.sig").write_bytes(b"forged-signature")
        # Rebuild the receipt's signature sha256 so the only failing gate is cosign verify.
        receipt = json.loads(sig_receipt.read_text())
        receipt["signature"]["sha256"] = hashlib.sha256(b"forged-signature").hexdigest()
        sig_receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
        )

        def rejecting_cosign(argv, **kwargs):
            argv = list(argv)
            if "verify-blob" in argv:
                return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"bad signature")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=rejecting_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self._verify(sig_receipt), 2)

    def test_sign_rejects_wrong_cosign_binary(self) -> None:
        # A cosign binary whose sha256 != trust anchor must BLOCK before signing.
        other = self.root / "other-cosign"
        other.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        other.chmod(0o700)
        sig_receipt = self.root / "sig-receipt.json"
        with (
            patch.multiple("sbom_workbench.cli", **self._anchors()),
            patch("sbom_workbench.cli.subprocess.run", side_effect=self._fake_cosign),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = main(
                [
                    "sign-selftest-pack",
                    "--pack-directory", str(self.pack),
                    "--cosign-bin", str(other),
                    "--cosign-receipt", str(self.cosign_receipt),
                    "--runtime-registry", str(self.registry),
                    "--key", str(self.key),
                    "--key-id", "test-key-1",
                    "--output", str(sig_receipt),
                ]
            )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
