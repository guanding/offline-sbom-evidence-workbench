"""Deterministic evidence primitives for the synthetic SBOM vertical slice."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .manifest import canonical_json_bytes


UNKNOWN = "UNKNOWN"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_COLLECTION_ITEMS = 100_000

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255}")


class EvidenceError(ValueError):
    """Raised when evidence cannot be accepted without weakening the boundary."""


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        raise EvidenceError(f"{label} fields mismatch; missing={missing}, extra={extra}")


def require_text(
    value: dict[str, Any],
    key: str,
    label: str,
    *,
    allow_unknown: bool = True,
    max_length: int = 4096,
) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not candidate or len(candidate) > max_length:
        raise EvidenceError(f"{label}.{key} must be a non-empty string")
    if any(ord(character) < 0x20 for character in candidate):
        raise EvidenceError(f"{label}.{key} must not contain control characters")
    if not allow_unknown and candidate == UNKNOWN:
        raise EvidenceError(f"{label}.{key} must not be UNKNOWN")
    return candidate


def require_safe_id(value: dict[str, Any], key: str, label: str) -> str:
    candidate = require_text(value, key, label, allow_unknown=False, max_length=256)
    if not _SAFE_ID_RE.fullmatch(candidate):
        raise EvidenceError(f"{label}.{key} is not a safe identifier")
    return candidate


def require_sha256(value: dict[str, Any], key: str, label: str) -> str:
    candidate = require_text(value, key, label, allow_unknown=False, max_length=64)
    if not _SHA256_RE.fullmatch(candidate):
        raise EvidenceError(f"{label}.{key} must be a lowercase SHA-256")
    return candidate


def require_string_list(
    value: dict[str, Any],
    key: str,
    label: str,
    *,
    require_nonempty: bool = True,
) -> list[str]:
    candidate = value.get(key)
    if not isinstance(candidate, list):
        raise EvidenceError(f"{label}.{key} must be an array")
    if require_nonempty and not candidate:
        raise EvidenceError(f"{label}.{key} must not be empty")
    if len(candidate) > MAX_COLLECTION_ITEMS:
        raise EvidenceError(f"{label}.{key} exceeds the item limit")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(candidate):
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise EvidenceError(f"{label}.{key}[{index}] must be a non-empty string")
        if any(ord(character) < 0x20 for character in item):
            raise EvidenceError(f"{label}.{key}[{index}] must not contain control characters")
        if item in seen:
            raise EvidenceError(f"{label}.{key} must not contain duplicates")
        seen.add(item)
        result.append(item)
    return result


def validate_safe_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise EvidenceError(f"{label} must be a non-empty relative path")
    if "\\" in value or "\x00" in value:
        raise EvidenceError(f"{label} must use a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise EvidenceError(f"{label} must be a normalized relative path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceError(f"{label} must not contain empty, dot, or parent segments")
    return value


def _safe_regular_file(root: Path, relative_path: str) -> tuple[Path, int]:
    if root.is_symlink():
        raise EvidenceError("fixture root must not be a symlink")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot resolve fixture root: {exc}") from exc
    if not resolved_root.is_dir():
        raise EvidenceError("fixture root must be a directory")

    current = resolved_root
    parts = PurePosixPath(relative_path).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise EvidenceError(f"cannot access input {relative_path}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise EvidenceError(f"symlink input is forbidden: {relative_path}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise EvidenceError(f"input parent is not a directory: {relative_path}")
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceError(f"input must be a regular file: {relative_path}")
    if info.st_nlink != 1:
        raise EvidenceError(f"hard-linked input is forbidden: {relative_path}")
    if info.st_size > MAX_INPUT_BYTES:
        raise EvidenceError(f"input exceeds the byte limit: {relative_path}")
    return current, info.st_size


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def read_json_object(
    root: Path,
    relative_path: str,
    *,
    expected_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read one bounded, non-linked JSON object and return its immutable identity."""

    normalized = validate_safe_relative_path(relative_path, "relative_path")
    path, size = _safe_regular_file(Path(root), normalized)
    if size > MAX_JSON_BYTES:
        raise EvidenceError(f"input exceeds the JSON byte limit: {normalized}")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read input {normalized}: {exc}") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise EvidenceError(f"input exceeds the JSON byte limit: {normalized}")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None:
        if not _SHA256_RE.fullmatch(expected_sha256):
            raise EvidenceError(f"expected SHA-256 is invalid for {normalized}")
        if actual_sha256 != expected_sha256:
            raise EvidenceError(
                f"input SHA-256 mismatch for {normalized}; expected {expected_sha256}, got {actual_sha256}"
            )
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_object_without_duplicate_keys)
    except EvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"input is not strict UTF-8 JSON: {normalized}: {exc}") from exc
    data = require_mapping(value, normalized)
    return data, {
        "relative_path": normalized,
        "sha256": actual_sha256,
        "size": len(payload),
    }


def read_file_identity(
    root: Path,
    relative_path: str,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Hash one bounded, non-linked input without interpreting its contents."""

    normalized = validate_safe_relative_path(relative_path, "relative_path")
    path, size = _safe_regular_file(Path(root), normalized)
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise EvidenceError(f"expected SHA-256 is invalid for {normalized}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceError(f"cannot read input {normalized}: {exc}") from exc
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise EvidenceError(
            f"input SHA-256 mismatch for {normalized}; expected {expected_sha256}, got {actual_sha256}"
        )
    return {"relative_path": normalized, "sha256": actual_sha256, "size": size}


def stable_id(prefix: str, value: object) -> str:
    if not _SAFE_ID_RE.fullmatch(prefix):
        raise EvidenceError("stable ID prefix is unsafe")
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"{prefix}-{digest}"


def make_evidence_object(
    *,
    lane_id: str,
    adapter_id: str,
    adapter_version: str,
    relative_path: str,
    sha256: str,
    size: int,
) -> dict[str, Any]:
    identity = {
        "lane_id": lane_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "relative_path": relative_path,
        "sha256": sha256,
    }
    return {
        "evidence_id": stable_id("evidence", identity),
        **identity,
        "size": size,
    }


def make_component_claim(
    *,
    lane_id: str,
    source_component_id: str,
    field: str,
    value: str,
    evidence_id: str,
) -> dict[str, Any]:
    body = {
        "lane_id": lane_id,
        "source_component_id": source_component_id,
        "field": field,
        "value": value,
        "evidence_ids": [evidence_id],
    }
    return {"claim_id": stable_id("component-claim", body), **body}


def make_relationship_claim(
    *,
    lane_id: str,
    source_component_id: str,
    relationship: str,
    target_component_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    body = {
        "lane_id": lane_id,
        "source_component_id": source_component_id,
        "relationship": relationship,
        "target_component_id": target_component_id,
        "evidence_ids": [evidence_id],
    }
    return {"claim_id": stable_id("relationship-claim", body), **body}


def validate_claim_evidence_links(graph: dict[str, Any]) -> None:
    evidence_objects = graph.get("evidence_objects")
    if not isinstance(evidence_objects, list):
        raise EvidenceError("graph.evidence_objects must be an array")
    evidence_ids = {
        item.get("evidence_id")
        for item in evidence_objects
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    for collection_name in ("component_claims", "relationship_claims"):
        claims = graph.get(collection_name)
        if not isinstance(claims, list):
            raise EvidenceError(f"graph.{collection_name} must be an array")
        for index, raw_claim in enumerate(claims):
            claim = require_mapping(raw_claim, f"graph.{collection_name}[{index}]")
            evidence_refs = claim.get("evidence_ids")
            if not isinstance(evidence_refs, list) or not evidence_refs:
                raise EvidenceError(f"graph.{collection_name}[{index}] has no evidence reference")
            if any(not isinstance(item, str) or item not in evidence_ids for item in evidence_refs):
                raise EvidenceError(f"graph.{collection_name}[{index}] has an unresolved evidence reference")


# Versioned projection allowlist for ``canonical_graph_sha256``. A field listed
# here is treated as non-deterministic run metadata (self-reference or reserved
# observability data such as actual wall-clock timestamps / host identity) and
# is excluded from the canonical hash, so adding it to a graph does not pollute
# the artifact-bound hash (EVD-2). The reserved names do not exist in current
# graphs, so existing hashes are byte-identical to before; the set is the
# contract for what may be added later as non-semantic observability. Note
# (M3-2): ``canonical_sha256`` is the artifact-bound hash (it changes whenever
# any semantic content changes, and also when a generator emits a fresh UUID);
# the stable cross-run identity is the separate ``run_id`` field, not this hash.
GRAPH_HASH_EXCLUDED_RUN_METADATA = frozenset(
    {
        "canonical_sha256",
        "actual_start_time",
        "actual_end_time",
        "host_identity",
        "wall_clock_observation",
    }
)


def canonical_graph_sha256(graph: dict[str, Any]) -> str:
    """Hash a graph excluding self-referential and reserved run-metadata fields.

    The projection contract is ``GRAPH_HASH_EXCLUDED_RUN_METADATA``: only those
    fields are dropped, and that frozen set is the versioned definition of what
    counts as non-deterministic observability versus a semantic graph fact.
    """

    if not isinstance(graph, dict):
        raise EvidenceError("canonical graph must be an object")
    projection = {
        key: value
        for key, value in graph.items()
        if key not in GRAPH_HASH_EXCLUDED_RUN_METADATA
    }
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
