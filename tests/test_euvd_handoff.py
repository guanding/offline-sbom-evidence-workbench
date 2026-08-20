from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.euvd_handoff import (
    VERIFIED_SELFTEST_BINDING,
    EuvdHandoffError,
    _prepare_euvd_handoff,
    prepare_euvd_handoff,
    validate_euvd_handoff,
    validate_loopback_endpoint,
)


class EuvdHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "candidate.cdx.json"
        self.source.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.7",
                    "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
                    "version": 1,
                    "metadata": {
                        "timestamp": "2026-08-04T00:00:00Z",
                        "component": {
                            "type": "application",
                            "bom-ref": "root",
                            "name": "selftest-root",
                            "version": "1",
                        },
                    },
                    "components": [{"type": "library", "bom-ref": "pkg-a", "name": "a", "version": "1"}],
                    "dependencies": [
                        {"ref": "root", "dependsOn": ["pkg-a"]},
                        {"ref": "pkg-a", "dependsOn": []},
                    ],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepare_and_validate_one_way_handoff(self) -> None:
        before = self.source.read_bytes()
        result = prepare_euvd_handoff(self.source, self.root / "handoffs", source_run_id="run-1")
        self.assertEqual(result["status"], "SELF_CONSISTENCY_ONLY_CALLER_DECLARED_SOURCE")
        self.assertEqual(before, self.source.read_bytes())
        handoff = self.root / "handoffs" / result["handoff_id"]
        receipt = json.loads((handoff / "receipt.json").read_text())
        self.assertEqual(receipt["schema_version"], "1.1")
        self.assertFalse(receipt["reverse_fact_write"])
        self.assertFalse(receipt["automatic_art14_decision"])
        self.assertFalse(receipt["automatic_vulnerability_confirmation"])
        self.assertEqual(
            receipt["monitoring_purpose"],
            "PERIODIC_COMPONENT_RESCAN_CANDIDATE_ONLY",
        )
        self.assertEqual(
            receipt["version_applicability_boundary"],
            "MANUAL_REVIEW_REQUIRED",
        )

    def test_verified_binding_is_only_self_consistent_without_source_root(self) -> None:
        result = _prepare_euvd_handoff(
            self.source,
            self.root / "verified-handoffs",
            source_run_id="never-verified-run",
            source_binding_status=VERIFIED_SELFTEST_BINDING,
            source_profile_id="m3a-oci-archive",
            source_root_completion_sha256="0" * 64,
            endpoint="http://127.0.0.1:8090",
        )
        self.assertEqual(result["status"], "SELF_CONSISTENCY_ONLY_SOURCE_NOT_REVERIFIED")
        handoff = self.root / "verified-handoffs" / result["handoff_id"]
        with self.assertRaisesRegex(EuvdHandoffError, "source root revalidation failed"):
            validate_euvd_handoff(
                handoff,
                selftest_root=self.root / "missing-root",
            )

    def test_external_or_ambiguous_endpoint_is_rejected(self) -> None:
        for endpoint in (
            "https://127.0.0.1:8090",
            "http://localhost:8090",
            "http://127.0.0.1:8091",
            "http://127.0.0.1:8090/api?redirect=https://example.com",
            "http://example.com:8090",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(EuvdHandoffError):
                validate_loopback_endpoint(endpoint)

    def test_tamper_addition_and_overwrite_fail_closed(self) -> None:
        result = prepare_euvd_handoff(self.source, self.root / "handoffs", source_run_id="run-1")
        handoff = self.root / "handoffs" / result["handoff_id"]
        with self.assertRaisesRegex(EuvdHandoffError, "already exists"):
            prepare_euvd_handoff(self.source, self.root / "handoffs", source_run_id="run-1")
        (handoff / "extra.txt").write_text("unexpected")
        with self.assertRaisesRegex(EuvdHandoffError, "exact-set"):
            validate_euvd_handoff(handoff)

    def test_duplicate_json_keys_and_symlink_are_rejected(self) -> None:
        self.source.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.7","components":[]}', encoding="utf-8")
        with self.assertRaisesRegex(EuvdHandoffError, "duplicate"):
            prepare_euvd_handoff(self.source, self.root / "handoffs", source_run_id="run-1")
        self.source.write_text(
            '{"bomFormat":"CycloneDX","specVersion":"1.7","version":NaN,"components":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(EuvdHandoffError, "non-standard JSON constant"):
            prepare_euvd_handoff(
                self.source,
                self.root / "nan-handoffs",
                source_run_id="run-1",
            )
        self.source.unlink()
        target = self.root / "target.json"
        target.write_text('{}')
        self.source.symlink_to(target)
        with self.assertRaisesRegex(EuvdHandoffError, "symlink"):
            prepare_euvd_handoff(self.source, self.root / "handoffs", source_run_id="run-1")

    def test_receipt_authority_escalation_and_dangling_dependency_fail_closed(self) -> None:
        result = prepare_euvd_handoff(
            self.source, self.root / "handoffs", source_run_id="run-1"
        )
        handoff = self.root / "handoffs" / result["handoff_id"]
        receipt_path = handoff / "receipt.json"
        complete_path = handoff / "COMPLETE.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["authority_boundary"] = "CRA_CONFORMANT_RELEASED"
        receipt["release_authority"] = True
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        complete = json.loads(complete_path.read_text(encoding="utf-8"))
        complete["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        complete_path.write_text(json.dumps(complete), encoding="utf-8")
        with self.assertRaisesRegex(EuvdHandoffError, "receipt binding or boundary"):
            validate_euvd_handoff(handoff)

        result = prepare_euvd_handoff(
            self.source, self.root / "monitoring-handoffs", source_run_id="run-1"
        )
        monitoring_handoff = self.root / "monitoring-handoffs" / result["handoff_id"]
        receipt_path = monitoring_handoff / "receipt.json"
        complete_path = monitoring_handoff / "COMPLETE.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["automatic_vulnerability_confirmation"] = True
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        complete = json.loads(complete_path.read_text(encoding="utf-8"))
        complete["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        complete_path.write_text(json.dumps(complete), encoding="utf-8")
        with self.assertRaisesRegex(EuvdHandoffError, "receipt binding or boundary"):
            validate_euvd_handoff(monitoring_handoff)

        dangling = self.root / "dangling.cdx.json"
        dangling.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.7",
                    "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000002",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "type": "application",
                            "name": "root",
                            "bom-ref": "root",
                        }
                    },
                    "components": [],
                    "dependencies": [{"ref": "root", "dependsOn": ["missing"]}],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(EuvdHandoffError, "reference validation"):
            prepare_euvd_handoff(
                dangling, self.root / "other-handoffs", source_run_id="run-2"
            )


    def test_parse_rejects_cyclonedx_exceeding_component_budget(self) -> None:
        from sbom_workbench.euvd_handoff import _parse_cyclonedx

        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {"type": "library", "name": f"c{i}", "version": "1.0", "bom-ref": f"r{i}"}
                for i in range(5)
            ],
        }
        payload = json.dumps(document).encode("utf-8")
        with self.assertRaisesRegex(EuvdHandoffError, "component budget"):
            _parse_cyclonedx(payload, max_components=2)


if __name__ == "__main__":
    unittest.main()
