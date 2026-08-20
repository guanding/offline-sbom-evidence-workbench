"""Hash-bound privacy projection for validated source-only CycloneDX evidence."""

from __future__ import annotations

import copy
import re
import stat
from pathlib import Path
from typing import Any

from .manifest import sha256_file, write_json_atomic
from .selftest import load_cyclonedx
from .source_only_validation import _json_file, validate_source_only_output


CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
_SENSITIVE_PATH_PATTERNS = (
    re.compile("/" + r"Users/[^/\s\"']+"),
    re.compile(r"/home/[^/\s\"']+"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+"),
)


class PrivacyProjectionError(ValueError):
    """Raised when a privacy projection cannot preserve its bounded contract."""


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _new_directory(path: Path) -> Path:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise PrivacyProjectionError("privacy projection output exists; refusing overwrite")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise PrivacyProjectionError("privacy projection parent is invalid")
    destination.mkdir(mode=0o700)
    return destination.resolve(strict=True)


def _replace_strings(value: Any, spellings: tuple[str, ...]) -> tuple[Any, int]:
    if isinstance(value, str):
        result = value
        count = 0
        for spelling in spellings:
            found = result.count(spelling)
            if found:
                result = result.replace(spelling, "${SOURCE_ROOT}")
                count += found
        return result, count
    if isinstance(value, list):
        result_list: list[Any] = []
        count = 0
        for item in value:
            projected, item_count = _replace_strings(item, spellings)
            result_list.append(projected)
            count += item_count
        return result_list, count
    if isinstance(value, dict):
        result_dict: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            projected, item_count = _replace_strings(item, spellings)
            result_dict[key] = projected
            count += item_count
        return result_dict, count
    return copy.deepcopy(value), 0


def _sensitive_path_count(value: Any) -> int:
    if isinstance(value, str):
        return sum(len(pattern.findall(value)) for pattern in _SENSITIVE_PATH_PATTERNS)
    if isinstance(value, list):
        return sum(_sensitive_path_count(item) for item in value)
    if isinstance(value, dict):
        return sum(_sensitive_path_count(item) for item in value.values())
    return 0


def prepare_source_analysis_projection(
    source_output_root: Path,
    source_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    source_output = Path(source_output_root).resolve(strict=True)
    source = Path(source_root).resolve(strict=True)
    prospective = Path(output_root).parent.resolve(strict=False) / Path(output_root).name
    if (
        _is_within(prospective, source)
        or _is_within(source, prospective)
        or _is_within(prospective, source_output)
        or _is_within(source_output, prospective)
    ):
        raise PrivacyProjectionError("projection output must remain isolated from source and raw roots")
    source_validation = validate_source_only_output(source_output, source_root=source)
    raw = source_output / "raw" / "m3a-source-directory" / "raw.cyclonedx.json"
    document = _json_file(raw, "raw source CycloneDX")
    if not isinstance(document, dict):
        raise PrivacyProjectionError("raw source CycloneDX must be a JSON object")
    spellings = tuple(
        sorted(
            {Path(source_root).absolute().as_posix(), source.as_posix()},
            key=lambda item: (-len(item), item.encode("utf-8")),
        )
    )
    projected, replacement_count = _replace_strings(document, spellings)
    if replacement_count <= 0:
        raise PrivacyProjectionError("raw CycloneDX contains no declared source-root path to normalize")
    residual_count = _sensitive_path_count(projected)
    destination = _new_directory(output_root)
    projection_path = destination / "analysis.cyclonedx.json"
    write_json_atomic(projection_path, projected)
    projection, projection_identity = load_cyclonedx(projection_path)
    receipt = {
        "schema_version": "1.0",
        "classification": CLASSIFICATION,
        "status": "SOURCE_ANALYSIS_PRIVACY_PROJECTION_CREATED",
        "source_run_id": source_validation["run_id"],
        "source_completion_sha256": source_validation["completion_sha256"],
        "raw_cyclonedx_sha256": source_validation["cyclonedx_sha256"],
        "projection_cyclonedx_sha256": projection_identity["sha256"],
        "projection_semantic_sha256": projection["semantic_sha256"],
        "normalized_token": "${SOURCE_ROOT}",
        "source_root_replacement_count": replacement_count,
        "residual_sensitive_path_count": residual_count,
        "privacy_gate": (
            "HOLD_RESIDUAL_SENSITIVE_PATHS"
            if residual_count
            else "REVIEW_READY_DECLARED_SOURCE_ROOT_NORMALIZED"
        ),
        "fact_policy": "NO_COMPONENT_ADD_DELETE_OR_INFERENCE_STRING_SUBSTITUTION_ONLY",
        "boundary": (
            "Analysis projection derived from hash-bound raw evidence. The raw SBOM remains "
            "authoritative scanner output; this projection is not customer evidence, proof of "
            "complete de-identification, release, PRE-7/CRA conformity, or certification."
        ),
    }
    receipt_path = destination / "projection-receipt.json"
    write_json_atomic(receipt_path, receipt)
    completion = {
        "schema_version": "1.0",
        "classification": CLASSIFICATION,
        "status": receipt["status"],
        "source_run_id": source_validation["run_id"],
        "projection_receipt_sha256": sha256_file(receipt_path),
    }
    completion_path = destination / "PROJECTION_COMPLETE.json"
    write_json_atomic(completion_path, completion)
    return {
        **receipt,
        "output_root": destination.as_posix(),
        "projection_path": projection_path.as_posix(),
        "projection_completion_sha256": sha256_file(completion_path),
    }


def validate_source_analysis_projection(
    projection_root: Path,
    *,
    source_output_root: Path,
    trusted_completion_sha256: str | None = None,
) -> dict[str, Any]:
    root = Path(projection_root)
    try:
        info = root.lstat()
    except OSError as exc:
        raise PrivacyProjectionError(f"cannot access projection root: {exc}") from exc
    if root.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise PrivacyProjectionError("projection root must be a non-symlink directory")
    root = root.resolve(strict=True)
    if {path.name for path in root.iterdir()} != {
        "analysis.cyclonedx.json",
        "projection-receipt.json",
        "PROJECTION_COMPLETE.json",
    }:
        raise PrivacyProjectionError("projection output exact filenames do not match")
    source_validation = validate_source_only_output(Path(source_output_root))
    receipt = _json_file(root / "projection-receipt.json", "privacy projection receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "classification",
        "status",
        "source_run_id",
        "source_completion_sha256",
        "raw_cyclonedx_sha256",
        "projection_cyclonedx_sha256",
        "projection_semantic_sha256",
        "normalized_token",
        "source_root_replacement_count",
        "residual_sensitive_path_count",
        "privacy_gate",
        "fact_policy",
        "boundary",
    }:
        raise PrivacyProjectionError("privacy projection receipt fields do not match")
    if (
        receipt["schema_version"] != "1.0"
        or receipt["classification"] != CLASSIFICATION
        or receipt["status"] != "SOURCE_ANALYSIS_PRIVACY_PROJECTION_CREATED"
        or receipt["source_run_id"] != source_validation["run_id"]
        or receipt["source_completion_sha256"] != source_validation["completion_sha256"]
        or receipt["raw_cyclonedx_sha256"] != source_validation["cyclonedx_sha256"]
        or receipt["normalized_token"] != "${SOURCE_ROOT}"
        or receipt["fact_policy"]
        != "NO_COMPONENT_ADD_DELETE_OR_INFERENCE_STRING_SUBSTITUTION_ONLY"
    ):
        raise PrivacyProjectionError("privacy projection boundary or source binding changed")
    document = _json_file(root / "analysis.cyclonedx.json", "analysis CycloneDX projection")
    residual = _sensitive_path_count(document)
    if residual != receipt["residual_sensitive_path_count"]:
        raise PrivacyProjectionError("privacy projection residual path count mismatch")
    projection, identity = load_cyclonedx(root / "analysis.cyclonedx.json")
    if (
        identity["sha256"] != receipt["projection_cyclonedx_sha256"]
        or projection["semantic_sha256"] != receipt["projection_semantic_sha256"]
    ):
        raise PrivacyProjectionError("privacy projection CycloneDX binding mismatch")
    completion_path = root / "PROJECTION_COMPLETE.json"
    completion = _json_file(completion_path, "privacy projection completion")
    if completion != {
        "schema_version": "1.0",
        "classification": CLASSIFICATION,
        "status": receipt["status"],
        "source_run_id": source_validation["run_id"],
        "projection_receipt_sha256": sha256_file(root / "projection-receipt.json"),
    }:
        raise PrivacyProjectionError("privacy projection completion binding mismatch")
    completion_sha256 = sha256_file(completion_path)
    if trusted_completion_sha256 is not None and completion_sha256 != trusted_completion_sha256:
        raise PrivacyProjectionError("trusted projection completion SHA-256 does not match")
    return {
        "status": "SOURCE_ANALYSIS_PRIVACY_PROJECTION_VALID",
        "classification": CLASSIFICATION,
        "source_run_id": source_validation["run_id"],
        "projection_cyclonedx_sha256": identity["sha256"],
        "projection_semantic_sha256": projection["semantic_sha256"],
        "source_root_replacement_count": receipt["source_root_replacement_count"],
        "residual_sensitive_path_count": residual,
        "privacy_gate": receipt["privacy_gate"],
        "completion_sha256": completion_sha256,
        "trusted_completion_anchor": (
            "MATCH" if trusted_completion_sha256 is not None else "NOT_PROVIDED"
        ),
        "boundary": receipt["boundary"],
    }
