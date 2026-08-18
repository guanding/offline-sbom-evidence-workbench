"""M8-2 narrowing reconcile lane (EUVD_TO_SBOM_NARROWING_ONLY).

Consumes externally-produced matcher hits (matcher-hits.json) plus a trusted
M8-1 VEX intake receipt, and annotates each hit whose (vulnerability_id, purl)
is covered by a not_affected VEX statement as NARROWED_BY_TRUSTED_VEX.

Hard rules (fail-closed):
* The outbound EUVD handoff (euvd_handoff.py) is NEVER opened for write —
  reverse_fact_write stays False. The narrowed receipt lands in a separate
  ``<output_root>/narrowed/<reconcile_id>/`` path; euvd_handoff.py is unchanged.
* Only VEX status==not_affected narrows. affected/fixed/unknown are recorded
  but never narrow. Multi-statement matches use strictest-wins: any matching
  statement that is not not_affected retains the hit (RETAINED_OPEN_CONTRADICTORY_VEX).
* Narrowing is evidence annotation, NOT hit deletion / resolution / Art.14
  decision. original_hit_preserved is always True; downstream must not close a
  hit because narrowed_by_trusted_vex is True.
* matcher-hits.json is untrusted claim data (no signature in v1). The receipt
  boundary explicitly states it does NOT prove hit-list completeness — only
  that narrowing was applied correctly to the provided hits. Hit-list
  completeness is the operator's archival responsibility.
* matcher hits whose canonicalized purl is absent from the handoff SBOM are
  rejected (PURL_NOT_IN_HANDOFF_SBOM) — closes phantom-hit / forged-narrowing.
"""
from __future__ import annotations

import hashlib
import json
import re
from json import JSONDecodeError
from typing import Any

from .vex_consume import _ref_to_purl


class NarrowingError(Exception):
    """Fail-closed error for the narrowing reconcile lane."""


# --- matcher-hits.json schema (input, exact-set) ---
_MATCHER_HITS_ROOT_KEYS = {"source", "hits"}
_MATCHER_HITS_SOURCE_KEYS = {
    "matcher_name",
    "matcher_version",
    "handoff_id",
    "cyclonedx_sha256",
}
_MATCHER_HIT_KEYS = {"vulnerability_id", "product_purl", "original_status"}

# --- narrowed-reconcile-receipt.json schema (output, exact-set) ---
_NARROWING_RECEIPT_KEYS = {
    "schema_version",
    "classification",
    "reconcile_id",
    "direction",
    "fact_write",
    "original_handoff_untouched",
    "handoff_binding",
    "vex_intake_binding",
    "vex_document_last_updated_utc",
    "operator_max_receipt_age_days",
    "matcher_hits_sha256",
    "total_hits",
    "narrowed_count",
    "not_narrowed_count",
    "decisions_canonical_sha256",
    "boundary",
}
_HANDOFF_BINDING_KEYS = {"handoff_id", "cyclonedx_sha256", "source_binding_status"}
_VEX_INTAKE_BINDING_KEYS = {
    "issuer_id",
    "vex_document_sha256",
    "signature_sha256",
    "statements_canonical_sha256",
    "narrowing_eligible_count",
}
_DECISION_KEYS = {
    "vulnerability_id",
    "product_purl",
    "original_status",
    "narrowed_by_trusted_vex",
    "vex_pointers",
    "rejection_reason",
    "original_hit_preserved",
}

MAX_MATCHES_BYTES = 16 * 1024 * 1024  # 16 MiB — mirrors euvd_handoff MAX_SBOM_BYTES philosophy
MAX_HITS_COUNT = 200_000

NARROWING_RECEIPT_SCHEMA_VERSION = "sbom-workbench.narrowing-reconcile-receipt/v1"
NARROWING_DIRECTION = "EUVD_TO_SBOM_NARROWING_ONLY"
NARROWING_FACT_WRITE = "EVIDENCE_ANNOTATION_ONLY_NO_HIT_DELETION"
NARROWING_CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
NARROWING_BOUNDARY = (
    "Narrowing reconcile is EVIDENCE ANNOTATION ONLY: it does not delete hits, "
    "does not resolve vulnerabilities, is not a CRA/prEN-7 conformity decision, "
    "not an Art.14 report, and not release authority. original_hit_preserved is "
    "always true; downstream must not close a hit because narrowed_by_trusted_vex "
    "is true. The receipt does NOT prove matcher-hits.json completeness — only "
    "that narrowing was applied correctly to the provided hits. Hit-list "
    "completeness is the operator's archival responsibility (v1: matcher output "
    "is unsigned; matcher is a hit-list data source, not a trust anchor)."
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Not-narrowed rejection reasons (machine-readable).
REASON_PURL_NOT_IN_HANDOFF = "PURL_NOT_IN_HANDOFF_SBOM"
REASON_NO_VEX_MATCH = "RETAINED_OPEN_NO_VEX_MATCH"
REASON_CONTRADICTORY_VEX = "RETAINED_OPEN_CONTRADICTORY_VEX"
REASON_VEX_NOT_NARROWING_ELIGIBLE = "VEX_STATUS_NOT_NARROWING_ELIGIBLE"
REASON_VEX_INTAKE_BINDING_FAILED = "VEX_INTAKE_BINDING_FAILED"


def canonicalize_purl(ref: Any) -> str | None:
    """v1 conservative canonicalization: strip ALL qualifiers. Reuses M8-1
    ``_ref_to_purl`` so M8-2 narrowing and M8-1 intake stay byte-identical in
    purl normalization. See _ref_to_purl docstring for the known PARTIAL risk.
    """
    return _ref_to_purl(ref)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Mirrors euvd_handoff._no_duplicate_keys / vex_consume._no_duplicate_keys:
    # reject JSON with duplicate keys (defense against crafted matcher output).
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NarrowingError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _strict_json(payload: bytes, label: str, max_bytes: int) -> dict[str, Any]:
    if not isinstance(payload, (bytes, bytearray)):
        raise NarrowingError(f"{label} must be bytes")
    if len(payload) > max_bytes:
        raise NarrowingError(f"{label} exceeds {max_bytes} bytes (got {len(payload)})")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, JSONDecodeError) as exc:
        raise NarrowingError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise NarrowingError(f"{label} must be a JSON object")
    return document


def parse_matcher_hits(payload: bytes) -> dict[str, Any]:
    """Parse + structurally validate matcher-hits.json. Canonicalizes each hit's
    product_purl in place. Fail-closed on any schema violation, oversized
    payload, duplicate keys, or invalid purl.
    """
    document = _strict_json(payload, "matcher-hits.json", MAX_MATCHES_BYTES)
    if set(document) != _MATCHER_HITS_ROOT_KEYS:
        raise NarrowingError("matcher-hits.json root fields do not match the fixed schema")
    source = document["source"]
    if not isinstance(source, dict) or set(source) != _MATCHER_HITS_SOURCE_KEYS:
        raise NarrowingError("matcher-hits.json source fields do not match the fixed schema")
    for field in ("matcher_name", "matcher_version", "handoff_id"):
        value = source[field]
        if not isinstance(value, str) or not value:
            raise NarrowingError(f"source.{field} must be a non-empty string")
    if not isinstance(source["cyclonedx_sha256"], str) or not _SHA256_RE.fullmatch(
        source["cyclonedx_sha256"]
    ):
        raise NarrowingError("source.cyclonedx_sha256 must be a lowercase SHA-256 hex")
    hits = document["hits"]
    if not isinstance(hits, list):
        raise NarrowingError("matcher-hits.json hits must be a list")
    if len(hits) > MAX_HITS_COUNT:
        raise NarrowingError(f"hits count {len(hits)} exceeds MAX_HITS_COUNT ({MAX_HITS_COUNT})")
    normalized_hits: list[dict[str, Any]] = []
    for index, hit in enumerate(hits):
        if not isinstance(hit, dict):
            raise NarrowingError(f"hits[{index}] must be an object")
        if set(hit) != _MATCHER_HIT_KEYS:
            raise NarrowingError(f"hits[{index}] fields do not match the fixed schema")
        vuln_id = hit["vulnerability_id"]
        if not isinstance(vuln_id, str) or not vuln_id:
            raise NarrowingError(f"hits[{index}].vulnerability_id must be a non-empty string")
        purl = canonicalize_purl(hit["product_purl"])
        if purl is None:
            raise NarrowingError(f"hits[{index}].product_purl must be a valid purl (pkg:...)")
        status = hit["original_status"]
        if not isinstance(status, str) or not status:
            raise NarrowingError(f"hits[{index}].original_status must be a non-empty string")
        normalized_hits.append(
            {
                "vulnerability_id": vuln_id,
                "product_purl": purl,
                "original_status": status,
            }
        )
    return {"source": source, "hits": normalized_hits}


def _statement_product_purls(statement: dict[str, Any]) -> set[str]:
    raw = statement.get("product_purls")
    if not isinstance(raw, list):
        return set()
    canonicalized = {canonicalize_purl(p) for p in raw}
    canonicalized.discard(None)
    return canonicalized  # type: ignore[return-value]


def _vex_pointers(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "vulnerability_id": stmt.get("vulnerability_id"),
            "status": stmt.get("status"),
            "justification": stmt.get("justification"),
        }
        for stmt in statements
    ]


def narrow_one_hit(
    hit: dict[str, Any],
    validated_statements: list[dict[str, Any]],
) -> dict[str, Any]:
    """Apply the strictest-wins narrowing decision to one hit.

    Match rule: a statement matches the hit iff statement.vulnerability_id ==
    hit.vulnerability_id AND hit.product_purl (already canonicalized) ∈ the
    statement's canonicalized product_purls.

    Decision:
    * no matching statement → RETAINED_OPEN_NO_VEX_MATCH (not narrowed)
    * any matching statement status != not_affected → RETAINED_OPEN_CONTRADICTORY_VEX
      (strictest-wins; never silently flip a blocked item)
    * all matching statements status == not_affected → NARROWED_BY_TRUSTED_VEX
    """
    vuln_id = hit["vulnerability_id"]
    purl = hit["product_purl"]
    matching = [
        stmt
        for stmt in validated_statements
        if stmt.get("vulnerability_id") == vuln_id and purl in _statement_product_purls(stmt)
    ]
    if not matching:
        return {
            "vulnerability_id": vuln_id,
            "product_purl": purl,
            "original_status": hit["original_status"],
            "narrowed_by_trusted_vex": False,
            "vex_pointers": [],
            "rejection_reason": REASON_NO_VEX_MATCH,
            "original_hit_preserved": True,
        }
    non_narrowing = [stmt for stmt in matching if stmt.get("status") != "not_affected"]
    if non_narrowing:
        return {
            "vulnerability_id": vuln_id,
            "product_purl": purl,
            "original_status": hit["original_status"],
            "narrowed_by_trusted_vex": False,
            "vex_pointers": _vex_pointers(matching),
            "rejection_reason": REASON_CONTRADICTORY_VEX,
            "original_hit_preserved": True,
        }
    return {
        "vulnerability_id": vuln_id,
        "product_purl": purl,
        "original_status": hit["original_status"],
        "narrowed_by_trusted_vex": True,
        "vex_pointers": _vex_pointers(matching),
        "rejection_reason": None,
        "original_hit_preserved": True,
    }


def validate_purl_presence(
    hits: list[dict[str, Any]],
    handoff_component_purls: set[str],
) -> None:
    """Fail-closed if any hit purl is absent from the handoff SBOM component
    purl set (phantom-hit / forged-narrowing defense). All hit purls must be
    canonicalized; handoff_component_purls must already be canonicalized.
    """
    missing = [
        hit["product_purl"]
        for hit in hits
        if hit["product_purl"] not in handoff_component_purls
    ]
    if missing:
        raise NarrowingError(
            f"{len(missing)} hit purl(s) absent from handoff SBOM (phantom/foreign); "
            f"first: {missing[0]!r}"
        )


def reconcile_id_of(
    handoff_id: str,
    cyclonedx_sha256: str,
    statements_canonical_sha256: str,
    matcher_hits_sha256: str,
) -> str:
    canonical = "\n".join(
        [handoff_id, cyclonedx_sha256, statements_canonical_sha256, matcher_hits_sha256]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decisions_canonical_sha256(decisions: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        decisions, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_narrowed_receipt(
    *,
    handoff_binding: dict[str, Any],
    vex_intake_binding: dict[str, Any],
    vex_document_last_updated_utc: str | None,
    operator_max_receipt_age_days: int,
    matcher_hits_sha256: str,
    decisions: list[dict[str, Any]],
) -> dict[str, Any]:
    total = len(decisions)
    narrowed = sum(1 for d in decisions if d["narrowed_by_trusted_vex"])
    not_narrowed = total - narrowed
    if narrowed + not_narrowed != total:
        raise NarrowingError("invariant broken: narrowed + not_narrowed != total")
    dec_sha = decisions_canonical_sha256(decisions)
    rec_id = reconcile_id_of(
        handoff_binding["handoff_id"],
        handoff_binding["cyclonedx_sha256"],
        vex_intake_binding["statements_canonical_sha256"],
        matcher_hits_sha256,
    )
    return {
        "schema_version": NARROWING_RECEIPT_SCHEMA_VERSION,
        "classification": NARROWING_CLASSIFICATION,
        "reconcile_id": rec_id,
        "direction": NARROWING_DIRECTION,
        "fact_write": NARROWING_FACT_WRITE,
        "original_handoff_untouched": True,
        "handoff_binding": handoff_binding,
        "vex_intake_binding": vex_intake_binding,
        "vex_document_last_updated_utc": vex_document_last_updated_utc,
        "operator_max_receipt_age_days": operator_max_receipt_age_days,
        "matcher_hits_sha256": matcher_hits_sha256,
        "total_hits": total,
        "narrowed_count": narrowed,
        "not_narrowed_count": not_narrowed,
        "decisions_canonical_sha256": dec_sha,
        "boundary": NARROWING_BOUNDARY,
    }


def validate_narrowed_receipt(receipt: Any) -> dict[str, Any]:
    """Fail-closed structural + invariant verification of a narrowed receipt."""
    if not isinstance(receipt, dict):
        raise NarrowingError("receipt must be a dict")
    if set(receipt) != _NARROWING_RECEIPT_KEYS:
        raise NarrowingError("receipt fields do not match the fixed schema")
    if receipt["schema_version"] != NARROWING_RECEIPT_SCHEMA_VERSION:
        raise NarrowingError("unsupported schema_version")
    if receipt["classification"] != NARROWING_CLASSIFICATION:
        raise NarrowingError("unsafe classification")
    if receipt["direction"] != NARROWING_DIRECTION:
        raise NarrowingError("direction must be EUVD_TO_SBOM_NARROWING_ONLY")
    if receipt["fact_write"] != NARROWING_FACT_WRITE:
        raise NarrowingError("fact_write must be EVIDENCE_ANNOTATION_ONLY_NO_HIT_DELETION")
    if receipt["original_handoff_untouched"] is not True:
        raise NarrowingError("original_handoff_untouched must be true")
    handoff_binding = receipt["handoff_binding"]
    if not isinstance(handoff_binding, dict) or set(handoff_binding) != _HANDOFF_BINDING_KEYS:
        raise NarrowingError("handoff_binding fields do not match")
    if not isinstance(handoff_binding["handoff_id"], str) or not handoff_binding["handoff_id"]:
        raise NarrowingError("handoff_binding.handoff_id must be a non-empty string")
    if not _SHA256_RE.fullmatch(handoff_binding["cyclonedx_sha256"]):
        raise NarrowingError("handoff_binding.cyclonedx_sha256 must be lowercase sha256")
    if not isinstance(handoff_binding["source_binding_status"], str):
        raise NarrowingError("handoff_binding.source_binding_status must be a string")
    vex_binding = receipt["vex_intake_binding"]
    if not isinstance(vex_binding, dict) or set(vex_binding) != _VEX_INTAKE_BINDING_KEYS:
        raise NarrowingError("vex_intake_binding fields do not match")
    if not isinstance(vex_binding["issuer_id"], str) or not vex_binding["issuer_id"]:
        raise NarrowingError("vex_intake_binding.issuer_id must be a non-empty string")
    for field in ("vex_document_sha256", "signature_sha256", "statements_canonical_sha256"):
        if not _SHA256_RE.fullmatch(vex_binding[field]):
            raise NarrowingError(f"vex_intake_binding.{field} must be lowercase sha256")
    if not isinstance(vex_binding["narrowing_eligible_count"], int) or vex_binding["narrowing_eligible_count"] < 0:
        raise NarrowingError("vex_intake_binding.narrowing_eligible_count must be a non-negative int")
    last_updated = receipt["vex_document_last_updated_utc"]
    if last_updated is not None and not isinstance(last_updated, str):
        raise NarrowingError("vex_document_last_updated_utc must be null or a string")
    if not isinstance(receipt["operator_max_receipt_age_days"], int) or receipt["operator_max_receipt_age_days"] < 0:
        raise NarrowingError("operator_max_receipt_age_days must be a non-negative int")
    if not _SHA256_RE.fullmatch(receipt["matcher_hits_sha256"]):
        raise NarrowingError("matcher_hits_sha256 must be lowercase sha256")
    if not _SHA256_RE.fullmatch(receipt["decisions_canonical_sha256"]):
        raise NarrowingError("decisions_canonical_sha256 must be lowercase sha256")
    if not _SHA256_RE.fullmatch(receipt["reconcile_id"]):
        raise NarrowingError("reconcile_id must be lowercase sha256")
    total = receipt["total_hits"]
    narrowed = receipt["narrowed_count"]
    not_narrowed = receipt["not_narrowed_count"]
    if not (isinstance(total, int) and isinstance(narrowed, int) and isinstance(not_narrowed, int)):
        raise NarrowingError("counts must be integers")
    if narrowed < 0 or not_narrowed < 0 or total < 0:
        raise NarrowingError("counts must be non-negative")
    if narrowed + not_narrowed != total:
        raise NarrowingError("invariant broken: narrowed + not_narrowed != total")
    expected_id = reconcile_id_of(
        handoff_binding["handoff_id"],
        handoff_binding["cyclonedx_sha256"],
        vex_binding["statements_canonical_sha256"],
        receipt["matcher_hits_sha256"],
    )
    if receipt["reconcile_id"] != expected_id:
        raise NarrowingError("reconcile_id does not match re-derived value")
    if not isinstance(receipt["boundary"], str) or not receipt["boundary"]:
        raise NarrowingError("boundary must be a non-empty string")
    return receipt
