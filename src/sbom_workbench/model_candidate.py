"""Versioned, single-model shadow evaluation without changing the sealed M5A baseline."""

from __future__ import annotations

import hashlib
import re
import stat
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .manifest import build_bounded_exact_set_manifest, canonical_json_bytes, sha256_file
from .model_eval import ModelEvaluationError, _run_arm, _validate_arm, seal_card_set


SCHEMA_VERSION = "1.0"
CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
PROFILE_ID = "M5B_SINGLE_MODEL_SHADOW_CANDIDATE_1.0"
DECISION = "SHADOW_ONLY_CANDIDATE_HOLD"
AUTHORITY_BOUNDARY = "NO_FACT_WRITE_NO_STATE_CHANGE_NO_RELEASE_OR_CONFORMITY_AUTHORITY"
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+:-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

Runner = Callable[[dict[str, Any]], dict[str, Any]]


def _hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ModelEvaluationError(f"{label} must be one bounded safe identifier")
    return value


def _is_exact_loopback_responses_endpoint(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/v1/responses", value)
    return match is not None and int(match.group(1)) <= 65_535


def _manifest_file_hash(manifest: dict[str, Any], relative_path: str) -> str | None:
    for item in manifest["files"]:
        if item["relative_path"] == relative_path:
            return item["sha256"]
    return None


def observe_candidate_profile(
    *,
    model_directory: Path,
    runtime_binary: Path,
    runtime_version: str,
    endpoint: str,
    model_id: str,
    observed_at: str,
    upstream_revision: str | None,
    quantization_observation: str,
) -> dict[str, Any]:
    """Hash the exact local candidate bytes and construct a privacy-HOLD profile."""

    model_id = _safe_id(model_id, "model_id")
    runtime_version = _safe_id(runtime_version, "runtime_version")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", observed_at):
        raise ModelEvaluationError("observed_at must be YYYY-MM-DD")
    if upstream_revision is not None and not re.fullmatch(r"[0-9a-f]{40}", upstream_revision):
        raise ModelEvaluationError("upstream_revision must be one lowercase 40-hex commit")
    if (
        not isinstance(quantization_observation, str)
        or not quantization_observation
        or len(quantization_observation) > 256
        or any(ord(character) < 0x20 for character in quantization_observation)
    ):
        raise ModelEvaluationError("quantization_observation must be bounded printable text")
    binary = Path(runtime_binary)
    try:
        binary_info = binary.lstat()
    except OSError as exc:
        raise ModelEvaluationError(f"cannot access runtime binary: {exc}") from exc
    if binary.is_symlink() or not stat.S_ISREG(binary_info.st_mode) or binary_info.st_nlink != 1:
        raise ModelEvaluationError("runtime binary must be a single-link regular file")
    directory = Path(model_directory)
    manifest = build_bounded_exact_set_manifest(
        directory,
        "local-model-candidate",
        max_files=10_000,
        max_total_bytes=200 * 1024 * 1024 * 1024,
        max_single_file_bytes=100 * 1024 * 1024 * 1024,
        max_depth=16,
    )
    profile = {
        "schema_version": SCHEMA_VERSION,
        "classification": "LOCAL_MODEL_CANDIDATE_OBSERVATION_NOT_APPROVAL",
        "profile_id": PROFILE_ID,
        "observed_at": observed_at,
        "runtime": {
            "runtime_id": f"omlx-{runtime_version}-local",
            "version": runtime_version,
            "binary_sha256": sha256_file(binary),
            "endpoint": endpoint,
            "credential_values_captured": False,
            "network_egress": "NOT_INDEPENDENTLY_VERIFIED",
            "cache_state": "NOT_INDEPENDENTLY_VERIFIED",
            "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
        },
        "model": {
            "server_model_id": model_id,
            "directory_label": directory.name,
            "directory_manifest": manifest,
            "config_sha256": _manifest_file_hash(manifest, "config.json"),
            "tokenizer_config_sha256": _manifest_file_hash(manifest, "tokenizer_config.json"),
            "model_card_sha256": _manifest_file_hash(manifest, "README.md"),
            "weight_index_sha256": _manifest_file_hash(manifest, "model.safetensors.index.json"),
            "upstream_revision": upstream_revision,
            "upstream_identity_status": "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
            "quantization_observation": quantization_observation,
            "rights_status": "HOLD_PENDING_NAMED_REVIEW",
        },
        "authority_boundary": (
            "Local byte/runtime observation only; not rights, privacy, model-quality, "
            "release, certification, or conformity approval."
        ),
    }
    return validate_candidate_profile(profile)


def validate_candidate_profile(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "classification",
        "profile_id",
        "observed_at",
        "runtime",
        "model",
        "authority_boundary",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ModelEvaluationError("candidate profile fields do not match")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["classification"] != "LOCAL_MODEL_CANDIDATE_OBSERVATION_NOT_APPROVAL"
        or value["profile_id"] != PROFILE_ID
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value["observed_at"]))
    ):
        raise ModelEvaluationError("candidate profile boundary is invalid")
    runtime = value["runtime"]
    runtime_keys = {
        "runtime_id",
        "version",
        "binary_sha256",
        "endpoint",
        "credential_values_captured",
        "network_egress",
        "cache_state",
        "privacy_gate",
    }
    if not isinstance(runtime, dict) or set(runtime) != runtime_keys:
        raise ModelEvaluationError("candidate runtime profile fields do not match")
    version = _safe_id(runtime["version"], "runtime.version")
    if (
        runtime["runtime_id"] != f"omlx-{version}-local"
        or not isinstance(runtime["binary_sha256"], str)
        or not _SHA256.fullmatch(runtime["binary_sha256"])
        or not _is_exact_loopback_responses_endpoint(runtime["endpoint"])
        or runtime["credential_values_captured"] is not False
        or runtime["network_egress"] != "NOT_INDEPENDENTLY_VERIFIED"
        or runtime["cache_state"] != "NOT_INDEPENDENTLY_VERIFIED"
        or runtime["privacy_gate"] != "HOLD_NOT_TECHNICALLY_DEMONSTRATED"
    ):
        raise ModelEvaluationError("candidate runtime profile is unsafe or invalid")
    model = value["model"]
    model_keys = {
        "server_model_id",
        "directory_label",
        "directory_manifest",
        "config_sha256",
        "tokenizer_config_sha256",
        "model_card_sha256",
        "weight_index_sha256",
        "upstream_revision",
        "upstream_identity_status",
        "quantization_observation",
        "rights_status",
    }
    if not isinstance(model, dict) or set(model) != model_keys:
        raise ModelEvaluationError("candidate model profile fields do not match")
    _safe_id(model["server_model_id"], "model.server_model_id")
    _safe_id(model["directory_label"], "model.directory_label")
    manifest = model["directory_manifest"]
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "root_id",
        "file_count",
        "total_bytes",
        "exact_set_sha256",
        "files",
    }:
        raise ModelEvaluationError("candidate model exact-set fields do not match")
    files = manifest["files"]
    if (
        manifest["schema_version"] != "1.0"
        or manifest["root_id"] != "local-model-candidate"
        or not isinstance(files, list)
        or manifest["file_count"] != len(files)
    ):
        raise ModelEvaluationError("candidate model exact-set identity is invalid")
    previous: bytes | None = None
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "relative_path",
            "sha256",
            "size",
            "executable",
        }:
            raise ModelEvaluationError("candidate model exact-set entry fields do not match")
        relative = item["relative_path"]
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ModelEvaluationError("candidate model exact-set path is unsafe")
        current = relative.encode("utf-8")
        if previous is not None and current <= previous:
            raise ModelEvaluationError("candidate model exact-set paths are not canonical")
        previous = current
        if (
            not isinstance(item["sha256"], str)
            or not _SHA256.fullmatch(item["sha256"])
            or type(item["size"]) is not int
            or item["size"] < 0
            or type(item["executable"]) is not bool
        ):
            raise ModelEvaluationError("candidate model exact-set metadata is invalid")
        total += item["size"]
    if manifest["total_bytes"] != total:
        raise ModelEvaluationError("candidate model exact-set byte count mismatch")
    expected_exact_set = _hash({"root_id": manifest["root_id"], "files": files})
    if manifest["exact_set_sha256"] != expected_exact_set:
        raise ModelEvaluationError("candidate model exact-set SHA-256 mismatch")
    by_path = {item["relative_path"]: item["sha256"] for item in files}
    for field, relative in (
        ("config_sha256", "config.json"),
        ("tokenizer_config_sha256", "tokenizer_config.json"),
        ("model_card_sha256", "README.md"),
        ("weight_index_sha256", "model.safetensors.index.json"),
    ):
        if model[field] != by_path.get(relative):
            raise ModelEvaluationError(f"candidate model {field} does not bind its exact-set")
    if model["upstream_revision"] is not None and not re.fullmatch(
        r"[0-9a-f]{40}", model["upstream_revision"]
    ):
        raise ModelEvaluationError("candidate model upstream revision is invalid")
    if (
        model["upstream_identity_status"]
        != "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
        or model["rights_status"] != "HOLD_PENDING_NAMED_REVIEW"
    ):
        raise ModelEvaluationError("candidate model identity or rights gate escalated")
    return dict(value)


def run_candidate_evaluation(
    cards: Iterable[object],
    runner: Runner,
    *,
    candidate_profile: object,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    sealed = seal_card_set(cards)
    profile = validate_candidate_profile(candidate_profile)
    model_id = profile["model"]["server_model_id"]
    profile_sha256 = _hash(profile)
    arm = _run_arm(
        f"model-candidate:{model_id}",
        model_id,
        sealed["cards"],
        runner,
        clock=clock,
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "evaluation_profile": PROFILE_ID,
        "evaluation_id": f"m5b-{_hash({'cards': sealed['card_set_sha256'], 'profile': profile_sha256})}",
        "card_set_sha256": sealed["card_set_sha256"],
        "cards": sealed["cards"],
        "candidate_profile": profile,
        "candidate_profile_sha256": profile_sha256,
        "arm": arm,
        "schema_evidence_gate": (
            "PASS" if arm["schema_and_evidence_rate"] == 1.0 else "HOLD"
        ),
        "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
        "rights_gate": "HOLD_PENDING_NAMED_REVIEW",
        "benefit_gate": "NOT_ASSESSED_NO_INDEPENDENT_HUMAN_TIMING",
        "decision": DECISION,
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
    return {**record, "evaluation_payload_sha256": _hash(record)}


def validate_candidate_evaluation(
    value: object,
    *,
    trusted_evaluation_sha256: str | None = None,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "classification",
        "evaluation_profile",
        "evaluation_id",
        "card_set_sha256",
        "cards",
        "candidate_profile",
        "candidate_profile_sha256",
        "arm",
        "schema_evidence_gate",
        "privacy_gate",
        "rights_gate",
        "benefit_gate",
        "decision",
        "authority_boundary",
        "evaluation_payload_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ModelEvaluationError("candidate evaluation fields do not match")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["classification"] != CLASSIFICATION
        or value["evaluation_profile"] != PROFILE_ID
        or value["decision"] != DECISION
        or value["authority_boundary"] != AUTHORITY_BOUNDARY
        or value["privacy_gate"] != "HOLD_NOT_TECHNICALLY_DEMONSTRATED"
        or value["rights_gate"] != "HOLD_PENDING_NAMED_REVIEW"
        or value["benefit_gate"] != "NOT_ASSESSED_NO_INDEPENDENT_HUMAN_TIMING"
    ):
        raise ModelEvaluationError("candidate evaluation boundary escalated")
    sealed = seal_card_set(value["cards"])
    if sealed["card_set_sha256"] != value["card_set_sha256"]:
        raise ModelEvaluationError("candidate evaluation card-set hash mismatch")
    profile = validate_candidate_profile(value["candidate_profile"])
    profile_sha256 = _hash(profile)
    if profile_sha256 != value["candidate_profile_sha256"]:
        raise ModelEvaluationError("candidate profile hash mismatch")
    expected_id = f"m5b-{_hash({'cards': sealed['card_set_sha256'], 'profile': profile_sha256})}"
    if value["evaluation_id"] != expected_id:
        raise ModelEvaluationError("candidate evaluation identity mismatch")
    model_id = profile["model"]["server_model_id"]
    arm = _validate_arm(
        value["arm"],
        arm_id=f"model-candidate:{model_id}",
        model_id=model_id,
        cards=sealed["cards"],
    )
    expected_gate = "PASS" if arm["schema_and_evidence_rate"] == 1.0 else "HOLD"
    if value["schema_evidence_gate"] != expected_gate:
        raise ModelEvaluationError("candidate schema/evidence gate does not rederive")
    body = {key: item for key, item in value.items() if key != "evaluation_payload_sha256"}
    if value["evaluation_payload_sha256"] != _hash(body):
        raise ModelEvaluationError("candidate evaluation payload hash mismatch")
    if trusted_evaluation_sha256 is not None:
        if not _SHA256.fullmatch(trusted_evaluation_sha256):
            raise ModelEvaluationError("trusted candidate evaluation SHA-256 is invalid")
        if trusted_evaluation_sha256 != value["evaluation_payload_sha256"]:
            raise ModelEvaluationError("trusted candidate evaluation SHA-256 does not match")
    return {
        "status": "MODEL_CANDIDATE_EVALUATION_VALID",
        "classification": CLASSIFICATION,
        "evaluation_id": value["evaluation_id"],
        "model_id": model_id,
        "card_count": len(sealed["cards"]),
        "valid_result_count": arm["valid_result_count"],
        "schema_and_evidence_rate": arm["schema_and_evidence_rate"],
        "schema_evidence_gate": expected_gate,
        "privacy_gate": value["privacy_gate"],
        "rights_gate": value["rights_gate"],
        "decision": DECISION,
        "evaluation_payload_sha256": value["evaluation_payload_sha256"],
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
