"""in-toto ITE-6 statement wrapper for the unified evidence envelope.

Wraps heterogeneous workbench evidence (selftest pack / receipt / manifest /
handoff) into the standard in-toto Statement v1 format so external tools
(GUAC ingestion, cosign verify, policy engines) can consume them with zero
friction. This is a pure translation layer: ``subject`` = a canonical hash,
``predicate`` = the existing JSON payload. No semantic change to any evidence,
no new trust model, no external dependency.

The statement binds one evidence artefact to one digest. Callers own artefact
construction and digest computation; this module only shapes the envelope and
rejects malformed statements fail-closed.
"""

from __future__ import annotations

from typing import Any

from .evidence import EvidenceError

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_SHA256_HEX_LEN = 64


class InTotoError(EvidenceError):
    """Raised when an in-toto statement cannot be wrapped or verified without weakening a gate."""


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LEN:
        raise InTotoError(f"{label} must be a {_SHA256_HEX_LEN}-char sha256 hex string")
    return value


def wrap_statement(
    *,
    predicate_type: str,
    subject_name: str,
    subject_sha256: str,
    predicate: dict[str, Any],
) -> dict[str, Any]:
    """Build one in-toto Statement v1 envelope around a single-sha256 subject.

    ``predicate_type`` is a URI identifying the evidence kind (e.g.
    ``sbom-workbench.selftest-pack/v1``). ``predicate`` is carried verbatim.
    """
    if not isinstance(predicate_type, str) or not predicate_type:
        raise InTotoError("predicate_type must be a non-empty string")
    if not isinstance(subject_name, str) or not subject_name:
        raise InTotoError("subject_name must be a non-empty string")
    _require_sha256(subject_sha256, "subject_sha256")
    if not isinstance(predicate, dict):
        raise InTotoError("predicate must be a dict")
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": predicate_type,
        "subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}],
        "predicate": predicate,
    }


def validate_statement(statement: object) -> dict[str, Any]:
    """Fail-closed structural check for an in-toto Statement v1 envelope."""
    if not isinstance(statement, dict):
        raise InTotoError("statement must be a dict")
    if statement.get("_type") != STATEMENT_TYPE:
        raise InTotoError("statement _type must be the in-toto Statement v1 URI")
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type:
        raise InTotoError("predicateType must be a non-empty string")
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1:
        raise InTotoError("subject must be a single-element list")
    entry = subject[0]
    if not isinstance(entry, dict):
        raise InTotoError("subject entry must be a dict")
    if not isinstance(entry.get("name"), str) or not entry["name"]:
        raise InTotoError("subject entry name must be a non-empty string")
    digest = entry.get("digest")
    if not isinstance(digest, dict):
        raise InTotoError("subject entry digest must be a dict")
    _require_sha256(digest.get("sha256"), "subject digest sha256")
    if not isinstance(statement.get("predicate"), dict):
        raise InTotoError("predicate must be a dict")
    return statement
