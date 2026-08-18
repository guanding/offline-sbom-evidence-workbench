"""Unit tests for the M8-2 narrowing reconcile lane."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from sbom_workbench.narrowing_reconcile import (
    NARROWING_DIRECTION,
    NarrowingError,
    REASON_CONTRADICTORY_VEX,
    REASON_NO_VEX_MATCH,
    build_narrowed_receipt,
    canonicalize_purl,
    narrow_one_hit,
    parse_matcher_hits,
    validate_narrowed_receipt,
    validate_purl_presence,
)


def _hits_payload(source=None, hits=None) -> bytes:
    doc = {
        "source": source
        or {
            "matcher_name": "euvd-sbom-matcher",
            "matcher_version": "2.3.0",
            "handoff_id": "handoff-abc",
            "cyclonedx_sha256": "a" * 64,
        },
        "hits": hits or [],
    }
    return json.dumps(doc).encode("utf-8")


def _statement(vuln: str, status: str, purls: list[str], justification: str = "code_not_present") -> dict:
    return {
        "vulnerability_id": vuln,
        "status": status,
        "justification": justification,
        "product_purls": purls,
    }


class ParseMatcherHitsTests(unittest.TestCase):
    def test_valid_canonicalizes_purl(self) -> None:
        # M8-3: volatile qualifier (package-id) dropped; arch/distro kept
        payload = _hits_payload(
            hits=[
                {
                    "vulnerability_id": "CVE-2024-1",
                    "product_purl": "pkg:pypi/fastapi@0.140.7?arch=amd64&package-id=abc",
                    "original_status": "AFFECTED",
                }
            ]
        )
        doc = parse_matcher_hits(payload)
        self.assertEqual(doc["hits"][0]["product_purl"], "pkg:pypi/fastapi@0.140.7?arch=amd64")

    def test_rejects_oversized_payload(self) -> None:
        payload = b"x" * (16 * 1024 * 1024 + 1)
        with self.assertRaises(NarrowingError):
            parse_matcher_hits(payload)

    def test_rejects_duplicate_keys(self) -> None:
        payload = b'{"source":{},"source":{},"hits":[]}'
        with self.assertRaises(NarrowingError):
            parse_matcher_hits(payload)

    def test_rejects_wrong_root_fields(self) -> None:
        payload = b'{"source":{},"extra":1,"hits":[]}'
        with self.assertRaises(NarrowingError):
            parse_matcher_hits(payload)

    def test_rejects_invalid_purl(self) -> None:
        payload = _hits_payload(
            hits=[
                {"vulnerability_id": "CVE-1", "product_purl": "not-a-purl", "original_status": "X"}
            ]
        )
        with self.assertRaises(NarrowingError):
            parse_matcher_hits(payload)

    def test_rejects_invalid_cyclonedx_sha256(self) -> None:
        payload = _hits_payload(
            source={
                "matcher_name": "m", "matcher_version": "1", "handoff_id": "h",
                "cyclonedx_sha256": "not-a-hash",
            }
        )
        with self.assertRaises(NarrowingError):
            parse_matcher_hits(payload)

    def test_rejects_too_many_hits(self) -> None:
        payload = _hits_payload(
            hits=[
                {"vulnerability_id": f"CVE-{i}", "product_purl": f"pkg:pypi/p{i}", "original_status": "X"}
                for i in range(3)
            ]
        )
        with patch("sbom_workbench.narrowing_reconcile.MAX_HITS_COUNT", 2):
            with self.assertRaises(NarrowingError):
                parse_matcher_hits(payload)


class CanonicalizePurlTests(unittest.TestCase):
    def test_keeps_arch_distro_drops_volatile(self) -> None:
        # M8-3: arch/distro kept (affect identity/ABI); package-id dropped (volatile)
        self.assertEqual(
            canonicalize_purl("pkg:pypi/fastapi@1.0?arch=amd64&distro=debian&package-id=x"),
            "pkg:pypi/fastapi@1.0?arch=amd64&distro=debian",
        )

    def test_returns_none_for_non_purl(self) -> None:
        self.assertIsNone(canonicalize_purl("not-a-purl"))


class NarrowOneHitTests(unittest.TestCase):
    def _hit(self, vuln="CVE-1", purl="pkg:pypi/a") -> dict:
        return {"vulnerability_id": vuln, "product_purl": purl, "original_status": "AFFECTED"}

    def test_no_vex_match(self) -> None:
        d = narrow_one_hit(self._hit(), [])
        self.assertFalse(d["narrowed_by_trusted_vex"])
        self.assertEqual(d["rejection_reason"], REASON_NO_VEX_MATCH)
        self.assertTrue(d["original_hit_preserved"])

    def test_single_not_affected_narrows(self) -> None:
        d = narrow_one_hit(self._hit(), [_statement("CVE-1", "not_affected", ["pkg:pypi/a"])])
        self.assertTrue(d["narrowed_by_trusted_vex"])
        self.assertIsNone(d["rejection_reason"])

    def test_single_affected_retained_contradictory(self) -> None:
        d = narrow_one_hit(self._hit(), [_statement("CVE-1", "affected", ["pkg:pypi/a"])])
        self.assertFalse(d["narrowed_by_trusted_vex"])
        self.assertEqual(d["rejection_reason"], REASON_CONTRADICTORY_VEX)

    def test_multi_strictest_wins(self) -> None:
        stmts = [
            _statement("CVE-1", "not_affected", ["pkg:pypi/a"]),
            _statement("CVE-1", "affected", ["pkg:pypi/a"]),
        ]
        d = narrow_one_hit(self._hit(), stmts)
        self.assertFalse(d["narrowed_by_trusted_vex"])
        self.assertEqual(d["rejection_reason"], REASON_CONTRADICTORY_VEX)

    def test_multi_all_not_affected_narrows_with_all_pointers(self) -> None:
        stmts = [
            _statement("CVE-1", "not_affected", ["pkg:pypi/a"], "code_not_present"),
            _statement("CVE-1", "not_affected", ["pkg:pypi/a"], "requires_configuration"),
        ]
        d = narrow_one_hit(self._hit(), stmts)
        self.assertTrue(d["narrowed_by_trusted_vex"])
        self.assertEqual(len(d["vex_pointers"]), 2)

    def test_arch_qualifier_distinguishes_hits(self) -> None:
        # M8-3: arch kept, so a statement on amd64 does NOT narrow a bare hit
        # (different identity). Fixes v1 over-narrowing.
        stmts = [_statement("CVE-1", "not_affected", ["pkg:pypi/a?arch=amd64"])]
        hit = {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a", "original_status": "AFFECTED"}
        d = narrow_one_hit(hit, stmts)
        self.assertFalse(d["narrowed_by_trusted_vex"])
        self.assertEqual(d["rejection_reason"], "RETAINED_OPEN_NO_VEX_MATCH")

    def test_arm_vs_amd_not_over_narrowed(self) -> None:
        # M8-3 regression: arm64 not_affected must NOT narrow an amd64 hit.
        stmts = [_statement("CVE-1", "not_affected", ["pkg:pypi/a?arch=arm64"])]
        hit = {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a?arch=amd64", "original_status": "AFFECTED"}
        d = narrow_one_hit(hit, stmts)
        self.assertFalse(d["narrowed_by_trusted_vex"])

    def test_matching_arch_still_narrows(self) -> None:
        # Positive case: same arch → match → narrowed (arch not blocking valid narrow)
        stmts = [_statement("CVE-1", "not_affected", ["pkg:pypi/a?arch=amd64"])]
        hit = {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a?arch=amd64", "original_status": "AFFECTED"}
        d = narrow_one_hit(hit, stmts)
        self.assertTrue(d["narrowed_by_trusted_vex"])


class PurlPresenceTests(unittest.TestCase):
    def test_phantom_purl_rejected(self) -> None:
        hits = [{"product_purl": "pkg:pypi/ghost"}]
        with self.assertRaises(NarrowingError):
            validate_purl_presence(hits, {"pkg:pypi/real"})

    def test_all_present_passes(self) -> None:
        hits = [{"product_purl": "pkg:pypi/a"}, {"product_purl": "pkg:pypi/b"}]
        validate_purl_presence(hits, {"pkg:pypi/a", "pkg:pypi/b"})  # no raise


def _valid_receipt_kwargs(**overrides) -> dict:
    decisions = [
        {
            "vulnerability_id": "CVE-1",
            "product_purl": "pkg:pypi/a",
            "original_status": "AFFECTED",
            "narrowed_by_trusted_vex": True,
            "vex_pointers": [],
            "rejection_reason": None,
            "original_hit_preserved": True,
        }
    ]
    kwargs = dict(
        handoff_binding={
            "handoff_id": "h1",
            "cyclonedx_sha256": "b" * 64,
            "source_binding_status": "VERIFIED_SELFTEST_BINDING",
        },
        vex_intake_binding={
            "issuer_id": "psirt-1",
            "vex_document_sha256": "c" * 64,
            "signature_sha256": "d" * 64,
            "statements_canonical_sha256": "e" * 64,
            "narrowing_eligible_count": 1,
        },
        vex_document_last_updated_utc=None,
        operator_max_receipt_age_days=90,
        matcher_hits_sha256="f" * 64,
        decisions=decisions,
    )
    kwargs.update(overrides)
    return kwargs


class ReceiptTests(unittest.TestCase):
    def test_build_validate_roundtrip(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        validate_narrowed_receipt(r)  # no raise
        self.assertEqual(r["direction"], NARROWING_DIRECTION)
        self.assertTrue(r["original_handoff_untouched"])
        self.assertEqual(r["narrowed_count"], 1)
        self.assertEqual(r["not_narrowed_count"], 0)

    def test_rejects_tampered_matcher_hash(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        r["matcher_hits_sha256"] = "0" * 64
        with self.assertRaises(NarrowingError):
            validate_narrowed_receipt(r)

    def test_rejects_invariant_break(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        r["narrowed_count"] = 5  # break narrowed + not_narrowed == total
        with self.assertRaises(NarrowingError):
            validate_narrowed_receipt(r)

    def test_rejects_reconcile_id_mismatch(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        r["reconcile_id"] = "0" * 64
        with self.assertRaises(NarrowingError):
            validate_narrowed_receipt(r)

    def test_rejects_wrong_fact_write(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        r["fact_write"] = "FACT_DELETION_ALLOWED"
        with self.assertRaises(NarrowingError):
            validate_narrowed_receipt(r)

    def test_rejects_original_handoff_touched(self) -> None:
        r = build_narrowed_receipt(**_valid_receipt_kwargs())
        r["original_handoff_untouched"] = False
        with self.assertRaises(NarrowingError):
            validate_narrowed_receipt(r)


if __name__ == "__main__":
    unittest.main()
