from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sbom_workbench.registry import (
    RegistryError,
    _validate_registry_data,
    load_and_validate_registry,
    validate_vex_issuer_registry,
)


ROOT = Path(__file__).resolve().parents[1]


def _admitted_issuer() -> dict:
    return {
        "issuer_id": "admitted-psirt-1",
        "display_name": "Admitted PSIRT",
        "identity_kind": "cosign-offline-key",
        "public_key_path": "trust-anchors/vex/psirt.pub",
        "public_key_sha256": "a" * 64,
        "acquisition_receipt_ref": "evidence/acquisition/psirt-key.receipt.json",
        "status": "ADMITTED_FOR_VEX_INTAKE",
        "boundary": "admitted for VEX intake only",
    }


def _base_registry() -> dict:
    return {
        "registry_type": "vex-issuer-registry",
        "schema_version": "vex-issuer-allowlist-1.0",
        "updated_at": "2026-08-05",
        "issuers": [_admitted_issuer()],
    }


class VexIssuerRegistryTests(unittest.TestCase):
    def test_project_placeholder_registry_passes(self) -> None:
        report = validate_vex_issuer_registry(
            __import__("json").loads(
                (ROOT / "datasets" / "vex_issuer_allowlist.json").read_text(encoding="utf-8")
            )
        )
        self.assertEqual(report["entries"], 1)
        self.assertEqual(report["registry_type"], "vex-issuer-registry")

    def test_load_and_validate_dispatches_to_vex_issuer_registry(self) -> None:
        _, report = load_and_validate_registry(ROOT / "datasets" / "vex_issuer_allowlist.json")
        self.assertEqual(report["registry_type"], "vex-issuer-registry")

    def test_admitted_issuer_passes(self) -> None:
        report = validate_vex_issuer_registry(_base_registry())
        self.assertEqual(report["entries"], 1)

    def test_unknown_issuer_field_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["sneaky_override"] = True
        with self.assertRaisesRegex(RegistryError, "fields mismatch"):
            validate_vex_issuer_registry(candidate)

    def test_missing_boundary_is_rejected(self) -> None:
        candidate = _base_registry()
        del candidate["issuers"][0]["boundary"]
        with self.assertRaisesRegex(RegistryError, "fields mismatch"):
            validate_vex_issuer_registry(candidate)

    def test_unsupported_status_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["status"] = "SUPER_TRUSTED"
        with self.assertRaisesRegex(RegistryError, "status is unsupported"):
            validate_vex_issuer_registry(candidate)

    def test_unsupported_identity_kind_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["identity_kind"] = "pgp"
        with self.assertRaisesRegex(RegistryError, "identity_kind is unsupported"):
            validate_vex_issuer_registry(candidate)

    def test_unsafe_issuer_id_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["issuer_id"] = "Bad-Id"
        with self.assertRaisesRegex(RegistryError, "issuer_id is unsafe"):
            validate_vex_issuer_registry(candidate)

    def test_duplicate_issuer_id_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"].append(copy.deepcopy(candidate["issuers"][0]))
        with self.assertRaisesRegex(RegistryError, "issuer_id is unsafe or duplicated"):
            validate_vex_issuer_registry(candidate)

    def test_admitted_without_key_material_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["public_key_sha256"] = None
        with self.assertRaisesRegex(RegistryError, "ADMITTED_FOR_VEX_INTAKE requires"):
            validate_vex_issuer_registry(candidate)

    def test_not_admitted_with_key_material_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["issuers"][0]["status"] = "NOT_ADMITTED"
        # key material still present → must be rejected
        with self.assertRaisesRegex(RegistryError, "NOT_ADMITTED must not carry key material"):
            validate_vex_issuer_registry(candidate)

    def test_wrong_schema_version_is_rejected(self) -> None:
        candidate = _base_registry()
        candidate["schema_version"] = "1.0"
        with self.assertRaisesRegex(RegistryError, "unsupported vex issuer registry schema_version"):
            validate_vex_issuer_registry(candidate)

    def test_unknown_registry_type_is_rejected_by_dispatch(self) -> None:
        candidate = _base_registry()
        candidate["registry_type"] = "vex-mystery-registry"
        with self.assertRaisesRegex(RegistryError, "unknown registry_type"):
            _validate_registry_data(candidate)


if __name__ == "__main__":
    unittest.main()
