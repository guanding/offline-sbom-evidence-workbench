from __future__ import annotations

import copy
import hashlib
import json
import unittest

from sbom_workbench.vex_consume import (
    ALLOWED_STATUSES,
    VexConsumeError,
    build_vex_intake_receipt,
    parse_vex_document,
    statements_canonical_sha256,
    validate_vex_intake_receipt,
    validate_vex_statement,
    verify_vex_intake_binding,
)


def _b(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _cyclonedx_vex(*, state: str = "not_affected", justification: str = "code_not_present") -> bytes:
    return _b(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "vulnerabilities": [
                {
                    "id": "CVE-2024-9999",
                    "analysis": {
                        "state": state,
                        "justification": justification,
                        "detail": "vulnerable code path not compiled in",
                        "firstIssued": "2026-08-01T00:00:00Z",
                        "lastUpdated": "2026-08-02T00:00:00Z",
                    },
                    "affects": [
                        {"ref": "pkg:pypi/requests@2.31.0?package-id=abc123"},
                        {"ref": "pkg:pypi/requests@2.31.0?package-id=def456"},
                    ],
                }
            ],
        }
    )


def _openvex(*, status: str = "not_affected", justification: str = "vulnerable_code_not_present") -> bytes:
    return _b(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.com/vex/doc1",
            "author": "Example PSIRT",
            "timestamp": "2026-08-01T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-8888"},
                    "products": [{"@id": "pkg:pypi/cryptography@42.0.0"}],
                    "status": status,
                    "justification": justification,
                }
            ],
        }
    )


class CycloneDxVexParsingTests(unittest.TestCase):
    def test_not_affected_with_code_not_present_is_narrowing_eligible(self) -> None:
        fmt, raw = parse_vex_document(_cyclonedx_vex())
        self.assertEqual(fmt, "cyclonedx-bom")
        validated = [
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
            )
        ]
        self.assertTrue(validated[0]["narrowing_eligible"])
        # syft's ?package-id= qualifier stripped; duplicate purl deduped.
        self.assertEqual(validated[0]["product_purls"], ["pkg:pypi/requests@2.31.0"])

    def test_affected_status_is_recorded_but_not_narrowing(self) -> None:
        fmt, raw = parse_vex_document(_cyclonedx_vex(state="affected"))
        validated = validate_vex_statement(
            raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
        )
        self.assertFalse(validated["narrowing_eligible"])
        self.assertEqual(validated["status"], "affected")

    def test_free_text_justification_is_rejected(self) -> None:
        fmt, raw = parse_vex_document(_cyclonedx_vex(justification="trust me bro"))
        with self.assertRaisesRegex(VexConsumeError, "standard enum value"):
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
            )

    def test_cross_format_justification_enum_is_rejected(self) -> None:
        # CycloneDX document carrying an OpenVEX-style justification must be rejected.
        fmt, raw = parse_vex_document(
            _cyclonedx_vex(justification="vulnerable_code_not_present")
        )
        with self.assertRaisesRegex(VexConsumeError, "standard enum value"):
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
            )

    def test_empty_product_purls_is_rejected(self) -> None:
        payload = _b(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-9999",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_present",
                        },
                        "affects": [{"ref": "urn:non-purl-ref"}],
                    }
                ],
            }
        )
        fmt, raw = parse_vex_document(payload)
        with self.assertRaisesRegex(VexConsumeError, "at least one purl"):
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
            )

    def test_malformed_purl_is_rejected(self) -> None:
        payload = _b(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-9999",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_present",
                        },
                        "affects": [{"ref": "pkg:not-a-valid-purl"}],
                    }
                ],
            }
        )
        fmt, raw = parse_vex_document(payload)
        with self.assertRaisesRegex(VexConsumeError, "not a valid purl"):
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="a" * 64
            )


class OpenVexParsingTests(unittest.TestCase):
    def test_openvex_not_affected_is_narrowing_eligible(self) -> None:
        fmt, raw = parse_vex_document(_openvex())
        self.assertEqual(fmt, "openvex")
        validated = validate_vex_statement(
            raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256="b" * 64
        )
        self.assertTrue(validated["narrowing_eligible"])
        self.assertEqual(validated["product_purls"], ["pkg:pypi/cryptography@42.0.0"])
        self.assertEqual(validated["vulnerability_id"], "CVE-2024-8888")


class FormatDetectionTests(unittest.TestCase):
    def test_non_vex_json_is_rejected(self) -> None:
        with self.assertRaisesRegex(VexConsumeError, "neither CycloneDX BOM nor OpenVEX"):
            parse_vex_document(_b({"random": "document"}))

    def test_empty_vulnerabilities_array_is_rejected(self) -> None:
        payload = _b({"bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": []})
        with self.assertRaisesRegex(VexConsumeError, "no statements"):
            parse_vex_document(payload)

    def test_duplicate_json_key_is_rejected(self) -> None:
        payload = b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": []}'
        with self.assertRaisesRegex(VexConsumeError, "duplicate JSON key"):
            parse_vex_document(payload)


class IntakeReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fmt, raw = parse_vex_document(_cyclonedx_vex())
        self.doc_sha = hashlib.sha256(_cyclonedx_vex()).hexdigest()
        self.statements = [
            validate_vex_statement(
                raw[0], vex_format=self.fmt, issuer_id="psirt-1", vex_document_sha256=self.doc_sha
            )
        ]
        self.tool_identity = {"name": "cosign", "version": "3.1.2", "binary_sha256": "c" * 64}

    def _build(self) -> dict:
        return build_vex_intake_receipt(
            vex_format=self.fmt,
            vex_document_sha256=self.doc_sha,
            signature_sha256="d" * 64,
            issuer_id="psirt-1",
            validated_statements=self.statements,
            cosign_tool_identity=self.tool_identity,
        )

    def test_build_then_validate_roundtrip(self) -> None:
        receipt = self._build()
        validated = validate_vex_intake_receipt(receipt)
        self.assertEqual(validated["statement_count"], 1)
        self.assertEqual(validated["narrowing_eligible_count"], 1)
        self.assertEqual(validated["statements_canonical_sha256"], statements_canonical_sha256(self.statements))

    def test_extra_field_is_rejected(self) -> None:
        receipt = self._build()
        receipt["sneaky_override"] = True
        with self.assertRaisesRegex(VexConsumeError, "fields do not match"):
            validate_vex_intake_receipt(receipt)

    def test_missing_field_is_rejected(self) -> None:
        receipt = self._build()
        del receipt["boundary"]
        with self.assertRaisesRegex(VexConsumeError, "fields do not match"):
            validate_vex_intake_receipt(receipt)

    def test_narrowing_count_exceeding_statement_count_is_rejected(self) -> None:
        receipt = self._build()
        receipt["narrowing_eligible_count"] = 99
        with self.assertRaisesRegex(VexConsumeError, "cannot exceed statement_count"):
            validate_vex_intake_receipt(receipt)


class IntakeBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = _cyclonedx_vex()
        self.doc_sha = hashlib.sha256(self.payload).hexdigest()
        fmt, raw = parse_vex_document(self.payload)
        self.fmt = fmt
        self.statements = [
            validate_vex_statement(
                raw[0], vex_format=fmt, issuer_id="psirt-1", vex_document_sha256=self.doc_sha
            )
        ]
        self.receipt = build_vex_intake_receipt(
            vex_format=fmt,
            vex_document_sha256=self.doc_sha,
            signature_sha256="d" * 64,
            issuer_id="psirt-1",
            validated_statements=self.statements,
            cosign_tool_identity={"name": "cosign", "version": "3.1.2", "binary_sha256": "c" * 64},
        )

    def test_binding_roundtrip(self) -> None:
        verify_vex_intake_binding(self.receipt, vex_payload=self.payload, issuer_id="psirt-1")

    def test_tampered_vex_payload_is_rejected(self) -> None:
        tampered = _cyclonedx_vex(justification="code_not_reachable")
        with self.assertRaisesRegex(VexConsumeError, "vex_document_sha256 does not match"):
            verify_vex_intake_binding(self.receipt, vex_payload=tampered, issuer_id="psirt-1")

    def test_issuer_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(VexConsumeError, "issuer_id does not match"):
            verify_vex_intake_binding(self.receipt, vex_payload=self.payload, issuer_id="other")

    def test_tampered_statements_canonical_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["statements_canonical_sha256"] = "0" * 64
        # Structural validate passes (it is a 64-hex string) but binding re-derive fails.
        validate_vex_intake_receipt(receipt)
        with self.assertRaisesRegex(VexConsumeError, "statements_canonical_sha256 does not re-derive"):
            verify_vex_intake_binding(receipt, vex_payload=self.payload, issuer_id="psirt-1")


class AllowedStatusContractTests(unittest.TestCase):
    def test_narrowing_status_is_the_only_not_affected(self) -> None:
        for status in ALLOWED_STATUSES:
            with self.subTest(status=status):
                _, raw = parse_vex_document(_cyclonedx_vex(state=status) if status else _cyclonedx_vex())
                raw[0]["status"] = status
                # affected/fixed/unknown are recorded; only not_affected narrows.
                if status == "not_affected":
                    self.assertTrue(
                        validate_vex_statement(
                            raw[0], vex_format="cyclonedx-bom", issuer_id="x", vex_document_sha256="a" * 64
                        )["narrowing_eligible"]
                    )
                else:
                    self.assertFalse(
                        validate_vex_statement(
                            raw[0], vex_format="cyclonedx-bom", issuer_id="x", vex_document_sha256="a" * 64
                        )["narrowing_eligible"]
                    )


if __name__ == "__main__":
    unittest.main()
