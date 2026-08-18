"""VEX trusted-statement intake lane (M8-1).

Consumes externally-issued VEX (Vulnerability Exploitability eXchange)
``not_affected`` statements, verifies issuer allowlist + cosign offline
signature, and binds them to component identities (purl) via an exact-set
intake receipt.

Hard rules (fail-closed):

* **Only not_affected is narrowing-eligible.** ``affected`` / ``fixed`` /
  ``unknown`` are recorded but never narrow. The workbench NEVER flips an
  existing hit — no hit state lives here; narrowing happens downstream
  (matcher / human), never inside this lane.
* **justification MUST be a standard enum value** (CycloneDX 1.7 VEX profile /
  OpenVEX v0.2.0). Free text is rejected to prevent forged rationales.
* **issuer MUST be in the allowlist** (acquisition-receipt trust anchor).
  Unsigned or untrusted VEX is rejected entirely (no partial adoption).
* **Product association uses purl (stable), NOT bom-ref.** syft-generated
  CycloneDX bom-refs embed an unstable ``?package-id=`` hash; purl is the
  stable identity, so bom-refs are stripped to their purl prefix.
* **Intake receipt is exact-set bound.** Tampering any bound hash
  (document / signature / statements-canonical) fails closed.

Boundary: VEX intake is evidence recording only. It is NOT CRA/prEN
conformity, release authority, manufacturer authorization, or a CAB
conclusion.

NOTE on justification enums: the allowlists below are drawn from CycloneDX
1.7 VEX profile and OpenVEX v0.2.0 specification recall. Before formal
compliance use they MUST be cross-checked against the official spec PDFs —
this workbench does not treat AI-recalled markdown as a standard-interpretation
authority (per project CLAUDE.md).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .evidence import EvidenceError
from .manifest import canonical_json_bytes

# Justification enums — recalled from CycloneDX 1.7 VEX profile / OpenVEX v0.2.0.
# Cross-check against official spec PDFs before formal compliance use.
CYCLONEDX_JUSTIFICATIONS = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    }
)
OPENVEX_JUSTIFICATIONS = frozenset(
    {
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)
ALLOWED_STATUSES = frozenset({"not_affected", "affected", "fixed", "unknown"})
NARROWING_STATUS = "not_affected"
VEX_FORMAT_CYCLONEDX = "cyclonedx-bom"
VEX_FORMAT_OPENVEX = "openvex"
VEX_INTAKE_SCHEMA_VERSION = "sbom-workbench.vex-intake-receipt/v1"
_PURL_PREFIX = "pkg:"
# Minimal purl shape: pkg:<type>/<name-with-optional-namespace-and-version>.
_PURL_RE = re.compile(r"^pkg:[A-Za-z0-9.\-+]+/.+")
_SHA256_HEX_LEN = 64
VEX_INTAKE_KEYS = frozenset(
    {
        "schema_version",
        "vex_format",
        "vex_document_sha256",
        "signature_sha256",
        "issuer_id",
        "cosign_tool_identity",
        "statements_canonical_sha256",
        "statement_count",
        "narrowing_eligible_count",
        "boundary",
    }
)


class VexConsumeError(EvidenceError):
    """Raised when a VEX document or intake receipt fails fail-closed checks."""


# --------------------------------------------------------------------------- #
# Strict JSON helpers (mirror euvd_handoff: reject duplicate keys + constants) #
# --------------------------------------------------------------------------- #


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VexConsumeError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VexConsumeError(f"non-standard JSON constant is forbidden: {value}")


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except VexConsumeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VexConsumeError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise VexConsumeError(f"{label} must be a JSON object")
    return value


# --------------------------------------------------------------------------- #
# Identity helpers                                                            #
# --------------------------------------------------------------------------- #


_QUALIFIER_AWARE_KEEP = frozenset({"arch", "distro"})


def _ref_to_purl(ref: Any) -> str | None:
    """Qualifier-aware canonicalization (M8-3): drop volatile qualifiers
    (``package-id`` etc.) but KEEP ``arch``/``distro`` (which affect package
    identity / ABI). Fixes the v1 over-narrowing risk where an arm64
    ``not_affected`` statement would wrongly narrow an amd64 hit. Shared by
    M8-1 intake and M8-2 narrowing so both sides canonicalize identically.
    """
    if not isinstance(ref, str) or not ref.startswith(_PURL_PREFIX):
        return None
    base, _, query = ref.partition("?")
    if not query:
        return base
    kept = []
    for pair in query.split("&"):
        key, sep, value = pair.partition("=")
        if key in _QUALIFIER_AWARE_KEEP and sep:
            kept.append(f"{key}={value}")
    return base + ("?" + "&".join(kept) if kept else "")


def _openvex_product_purl(product: Any) -> str | None:
    if not isinstance(product, dict):
        return None
    ident = product.get("@id")
    return ident if isinstance(ident, str) and ident.startswith(_PURL_PREFIX) else None


def _detect_format(document: dict[str, Any]) -> str:
    context = document.get("@context")
    if isinstance(context, str) and "openvex" in context:
        return VEX_FORMAT_OPENVEX
    if document.get("bomFormat") == "CycloneDX":
        return VEX_FORMAT_CYCLONEDX
    raise VexConsumeError("VEX document is neither CycloneDX BOM nor OpenVEX")


# --------------------------------------------------------------------------- #
# Parsing                                                                     #
# --------------------------------------------------------------------------- #


def _parse_cyclonedx(document: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise VexConsumeError("CycloneDX VEX must carry a vulnerabilities array")
    statements: list[dict[str, Any]] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            raise VexConsumeError("CycloneDX vulnerability entry must be an object")
        analysis = entry.get("analysis")
        if not isinstance(analysis, dict):
            raise VexConsumeError("CycloneDX vulnerability must carry an analysis object")
        affects = entry.get("affects")
        if not isinstance(affects, list):
            raise VexConsumeError("CycloneDX vulnerability must carry an affects array")
        purls = sorted(
            {
                purl
                for affect in affects
                if isinstance(affect, dict)
                for purl in (_ref_to_purl(affect.get("ref")),)
                if purl
            }
        )
        statements.append(
            {
                "vulnerability_id": entry.get("id"),
                "status": analysis.get("state"),
                "justification": analysis.get("justification"),
                "detail": analysis.get("detail"),
                "first_issued_utc": analysis.get("firstIssued"),
                "last_updated_utc": analysis.get("lastUpdated"),
                "product_purls": purls,
            }
        )
    return statements


def _parse_openvex(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw_statements = document.get("statements")
    if not isinstance(raw_statements, list):
        raise VexConsumeError("OpenVEX document must carry a statements array")
    statements: list[dict[str, Any]] = []
    for entry in raw_statements:
        if not isinstance(entry, dict):
            raise VexConsumeError("OpenVEX statement must be an object")
        products = entry.get("products")
        if not isinstance(products, list):
            raise VexConsumeError("OpenVEX statement must carry a products array")
        purls = sorted(
            {
                purl
                for product in products
                for purl in (_openvex_product_purl(product),)
                if purl
            }
        )
        vuln = entry.get("vulnerability")
        vuln_id = None
        if isinstance(vuln, dict):
            vuln_id = vuln.get("name") or vuln.get("@id")
        statements.append(
            {
                "vulnerability_id": vuln_id,
                "status": entry.get("status"),
                "justification": entry.get("justification"),
                "detail": entry.get("impact_statement") or entry.get("action_statement"),
                "first_issued_utc": None,
                "last_updated_utc": None,
                "product_purls": purls,
            }
        )
    return statements


def parse_vex_document(payload: bytes) -> tuple[str, list[dict[str, Any]]]:
    """Parse a VEX document and return ``(format, raw_statements)``."""
    document = _strict_json(payload, "VEX document")
    fmt = _detect_format(document)
    statements = (
        _parse_cyclonedx(document)
        if fmt == VEX_FORMAT_CYCLONEDX
        else _parse_openvex(document)
    )
    if not statements:
        raise VexConsumeError("VEX document carries no statements")
    return fmt, statements


# --------------------------------------------------------------------------- #
# Fail-closed statement validation                                            #
# --------------------------------------------------------------------------- #


def validate_vex_statement(
    raw: dict[str, Any],
    *,
    vex_format: str,
    issuer_id: str,
    vex_document_sha256: str,
) -> dict[str, Any]:
    """Validate one raw VEX statement and return the normalized form."""
    allowed_just = (
        CYCLONEDX_JUSTIFICATIONS
        if vex_format == VEX_FORMAT_CYCLONEDX
        else OPENVEX_JUSTIFICATIONS
    )
    vuln_id = raw.get("vulnerability_id")
    if not isinstance(vuln_id, str) or not vuln_id:
        raise VexConsumeError("VEX statement vulnerability_id must be a non-empty string")
    status = raw.get("status")
    if status not in ALLOWED_STATUSES:
        raise VexConsumeError(f"VEX statement status {status!r} is not in the allowed set")
    justification = raw.get("justification")
    if not isinstance(justification, str) or justification not in allowed_just:
        raise VexConsumeError("VEX statement justification must be a standard enum value")
    purls = raw.get("product_purls")
    if not isinstance(purls, list) or not purls:
        raise VexConsumeError("VEX statement must bind to at least one purl")
    for purl in purls:
        if not isinstance(purl, str) or not _PURL_RE.fullmatch(purl):
            raise VexConsumeError(f"VEX product reference is not a valid purl: {purl!r}")
    detail = raw.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise VexConsumeError("VEX detail must be a string when present")
    return {
        "vulnerability_id": vuln_id,
        "vex_format": vex_format,
        "vex_document_sha256": vex_document_sha256,
        "issuer_id": issuer_id,
        "product_purls": list(purls),
        "status": status,
        "justification": justification,
        "detail": detail,
        "first_issued_utc": raw.get("first_issued_utc"),
        "last_updated_utc": raw.get("last_updated_utc"),
        "narrowing_eligible": status == NARROWING_STATUS,
    }


def _statement_sort_key(statement: dict[str, Any]) -> tuple[str, str]:
    return (statement["vulnerability_id"], "|".join(statement["product_purls"]))


def statements_canonical_sha256(statements: list[dict[str, Any]]) -> str:
    """Deterministic sha256 over the sorted validated-statement set."""
    canonical = canonical_json_bytes(sorted(statements, key=_statement_sort_key))
    return hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------- #
# Intake receipt                                                              #
# --------------------------------------------------------------------------- #


def build_vex_intake_receipt(
    *,
    vex_format: str,
    vex_document_sha256: str,
    signature_sha256: str,
    issuer_id: str,
    validated_statements: list[dict[str, Any]],
    cosign_tool_identity: dict[str, Any],
) -> dict[str, Any]:
    """Build an exact-set intake receipt binding a signed VEX document."""
    if not isinstance(validated_statements, list) or not validated_statements:
        raise VexConsumeError("intake receipt requires at least one validated statement")
    if not isinstance(issuer_id, str) or not issuer_id:
        raise VexConsumeError("issuer_id must be a non-empty string")
    if not isinstance(cosign_tool_identity, dict) or not isinstance(
        cosign_tool_identity.get("binary_sha256"), str
    ) or len(cosign_tool_identity["binary_sha256"]) != _SHA256_HEX_LEN:
        raise VexConsumeError("cosign_tool_identity.binary_sha256 must be a sha256 hex string")
    narrowing = sum(1 for s in validated_statements if s["narrowing_eligible"])
    return {
        "schema_version": VEX_INTAKE_SCHEMA_VERSION,
        "vex_format": vex_format,
        "vex_document_sha256": vex_document_sha256,
        "signature_sha256": signature_sha256,
        "issuer_id": issuer_id,
        "cosign_tool_identity": cosign_tool_identity,
        "statements_canonical_sha256": statements_canonical_sha256(validated_statements),
        "statement_count": len(validated_statements),
        "narrowing_eligible_count": narrowing,
        "boundary": (
            "VEX intake is evidence recording only; narrowing happens downstream. "
            "Not CRA/prEN conformity, release authority, manufacturer authorization, "
            "or CAB conclusion."
        ),
    }


def _require_sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LEN:
        raise VexConsumeError(f"{label} must be a {_SHA256_HEX_LEN}-char sha256 hex string")
    return value


def validate_vex_intake_receipt(receipt: Any) -> dict[str, Any]:
    """Fail-closed structural verification of an intake receipt."""
    if not isinstance(receipt, dict):
        raise VexConsumeError("intake receipt must be a dict")
    if set(receipt) != VEX_INTAKE_KEYS:
        raise VexConsumeError("intake receipt fields do not match the fixed schema")
    if receipt["schema_version"] != VEX_INTAKE_SCHEMA_VERSION:
        raise VexConsumeError("intake receipt schema_version is not supported")
    if receipt["vex_format"] not in {VEX_FORMAT_CYCLONEDX, VEX_FORMAT_OPENVEX}:
        raise VexConsumeError("intake receipt vex_format is not supported")
    for key in (
        "vex_document_sha256",
        "signature_sha256",
        "statements_canonical_sha256",
    ):
        _require_sha256_hex(receipt[key], f"intake receipt {key}")
    if not isinstance(receipt["issuer_id"], str) or not receipt["issuer_id"]:
        raise VexConsumeError("intake receipt issuer_id must be a non-empty string")
    tool = receipt["cosign_tool_identity"]
    if not isinstance(tool, dict):
        raise VexConsumeError("intake receipt cosign_tool_identity must be a dict")
    _require_sha256_hex(tool.get("binary_sha256"), "cosign_tool_identity.binary_sha256")
    if not isinstance(receipt["statement_count"], int) or receipt["statement_count"] <= 0:
        raise VexConsumeError("intake receipt statement_count must be a positive int")
    if not isinstance(receipt["narrowing_eligible_count"], int) or receipt["narrowing_eligible_count"] < 0:
        raise VexConsumeError("intake receipt narrowing_eligible_count is invalid")
    if receipt["narrowing_eligible_count"] > receipt["statement_count"]:
        raise VexConsumeError("intake receipt narrowing_eligible_count cannot exceed statement_count")
    if not isinstance(receipt["boundary"], str) or not receipt["boundary"]:
        raise VexConsumeError("intake receipt boundary must be present")
    return receipt


def verify_vex_intake_binding(
    receipt: dict[str, Any],
    *,
    vex_payload: bytes,
    issuer_id: str,
) -> list[dict[str, Any]]:
    """Re-derive the document hash + statements canonical hash and fail if bound.

    This is the exact-set binding check: the receipt's ``vex_document_sha256``
    and ``statements_canonical_sha256`` must re-derive from the supplied VEX
    bytes (parsed + validated afresh). Tampering the VEX, the issuer, or the
    receipt's bound hashes fails closed.

    Returns the freshly-validated statements on success so M8-2 narrowing can
    consume them without a second parse+validate pass.
    """
    validate_vex_intake_receipt(receipt)
    if issuer_id != receipt["issuer_id"]:
        raise VexConsumeError("intake receipt issuer_id does not match the verifier's issuer")
    observed_doc_sha = hashlib.sha256(vex_payload).hexdigest()
    if observed_doc_sha != receipt["vex_document_sha256"]:
        raise VexConsumeError("intake receipt vex_document_sha256 does not match the VEX bytes")
    vex_format, raw_statements = parse_vex_document(vex_payload)
    if vex_format != receipt["vex_format"]:
        raise VexConsumeError("intake receipt vex_format does not match the VEX bytes")
    validated = [
        validate_vex_statement(
            raw,
            vex_format=vex_format,
            issuer_id=issuer_id,
            vex_document_sha256=observed_doc_sha,
        )
        for raw in raw_statements
    ]
    if len(validated) != receipt["statement_count"]:
        raise VexConsumeError("intake receipt statement_count does not match the VEX bytes")
    if statements_canonical_sha256(validated) != receipt["statements_canonical_sha256"]:
        raise VexConsumeError("intake receipt statements_canonical_sha256 does not re-derive")
    narrowing = sum(1 for s in validated if s["narrowing_eligible"])
    if narrowing != receipt["narrowing_eligible_count"]:
        raise VexConsumeError("intake receipt narrowing_eligible_count does not re-derive")
    return validated
