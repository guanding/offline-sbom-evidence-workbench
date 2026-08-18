"""Fail-closed validation for governed source and runtime registries."""

from __future__ import annotations

import json
import hashlib
import re
import unicodedata
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit


class RegistryError(ValueError):
    """Raised when a registry cannot be trusted for acquisition or execution."""


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SPLITS = {
    "TRAIN",
    "DEV",
    "PUBLIC_REGRESSION",
    "SEALED_BLIND_HOLDOUT",
    "CUSTOMER_SHADOW",
    "DEV_BUILD_YOCTO",
}
_ADMISSION = {
    "REGISTERED_PENDING_REVIEW",
    "QUARANTINE_ACQUIRED",
    "RIGHTS_REVIEWED",
    "ADMITTED_FOR_INTERNAL_DEVELOPMENT",
    "ADMITTED_FOR_EVALUATION",
    "ADMITTED_FOR_TRAINING",
    "ADMITTED_FOR_PUBLIC_REGRESSION",
    "REJECT",
}
_ADMITTED = {
    "ADMITTED_FOR_INTERNAL_DEVELOPMENT",
    "ADMITTED_FOR_EVALUATION",
    "ADMITTED_FOR_TRAINING",
    "ADMITTED_FOR_PUBLIC_REGRESSION",
}
_ACQUISITION_STATUS = {
    "REGISTERED_PENDING_ACQUISITION",
    "ACQUIRED_UNSEALED",
    "FROZEN_VERIFIED_TECHNICAL",
    "REJECTED",
}
_RIGHTS_STATUS = {"AWAITING_LICENSE_EVIDENCE", "AWAITING_NAMED_REVIEW", "RIGHTS_REVIEWED", "REJECTED"}
_USAGE_STATUS = {
    "NOT_ADMITTED",
    "ADMITTED_FOR_INTERNAL_DEVELOPMENT",
    "ADMITTED_FOR_EVALUATION",
    "ADMITTED_FOR_TRAINING",
    "ADMITTED_FOR_PUBLIC_REGRESSION",
}
_FORMAT_STATUS = {"NOT_ASSESSED", "MECHANICALLY_VALIDATED", "REJECTED"}
_RELEASE_STATUS = {"NOT_APPROVED", "APPROVED_FOR_SCOPED_USE", "REJECTED"}
_ALLOWED_ACQUISITION_HOSTS = {"github.com", "git.openembedded.org", "git.yoctoproject.org"}
_SOURCE_ROOT_KEYS = {"registry_type", "schema_version", "updated_at", "sources"}
_SOURCE_KEYS = {
    "dataset_id", "root_id", "name", "source_type", "upstream_url", "lineage_group",
    "pin", "license", "governance", "acquisition", "notes",
}
_PIN_KEYS = {
    "ref_type", "ref_name", "resolved_commit", "tag_object", "acquisition_artifact_sha256",
}
_LICENSE_KEYS = {"expression", "review_status", "evidence_paths", "evidence_hashes", "content_scopes"}
_SCOPE_KEYS = {"scope", "expression", "training_allowed", "raw_redistribution_allowed"}
_GOVERNANCE_KEYS = {
    "admission_status", "purposes", "split", "acquisition_allowed", "internal_development_allowed",
    "evaluation_allowed", "training_allowed", "fixture_distribution_allowed", "raw_redistribution_allowed",
    "adapter_distribution_allowed", "weight_distribution_allowed", "shipping_examples_allowed",
    "redistribution_status", "access_terms_status", "tdm_reservation_status", "submodules_status",
    "lfs_status", "generated_content_status", "binary_content_status", "attribution_status",
    "acquisition_status", "rights_status", "usage_status", "format_validation_status", "release_status",
    "rights_decision_ref", "rights_decision_sha256", "revalidation_triggers",
}
_ACQUISITION_KEYS = {"allow_submodules", "execute_code", "max_files", "max_total_bytes"}
_RUNTIME_ROOT_KEYS = {"registry_type", "schema_version", "updated_at", "runtimes"}
_RUNTIME_KEYS = {
    "runtime_id", "category", "name", "version", "source_url", "resolved_commit", "license_expression",
    "status", "artifact_sha256", "config_sha256", "dependency_manifest_sha256", "notes",
}
_VEX_ISSUER_ROOT_KEYS = {"registry_type", "schema_version", "updated_at", "issuers"}
_VEX_ISSUER_KEYS = {
    "issuer_id", "display_name", "identity_kind", "public_key_path",
    "public_key_sha256", "acquisition_receipt_ref", "status", "boundary",
}
_VEX_ISSUER_IDENTITY_KINDS = {"cosign-offline-key"}
_VEX_ISSUER_STATUSES = {"NOT_ADMITTED", "ADMITTED_FOR_VEX_INTAKE"}


def _load_json_payload(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        payload = path.read_bytes()
        data = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read registry {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError("registry root must be a JSON object")
    return data, payload


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    return value


def _require_exact_keys(mapping: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(mapping))
    unknown = sorted(set(mapping) - expected)
    if missing or unknown:
        raise RegistryError(f"{label} fields mismatch; missing={missing}, unknown={unknown}")


def _require_text(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{label}.{key} must be a non-empty string")
    return value


def _require_bool(mapping: dict[str, Any], key: str, label: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise RegistryError(f"{label}.{key} must be boolean")
    return value


def _safe_relative_path(value: str, label: str) -> None:
    path = PurePosixPath(value)
    if (
        unicodedata.normalize("NFC", value) != value
        or "\\" in value
        or path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise RegistryError(f"{label} must be a normalized relative POSIX path")


def _validate_https_url(value: str, label: str, *, acquisition: bool) -> None:
    if value.strip() != value or "\\" in value or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise RegistryError(f"{label} must use canonical printable ASCII URL syntax")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RegistryError(f"{label} is not a valid URL") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.path in {"", "/"}:
        raise RegistryError(f"{label} must use an absolute https URL")
    if parsed.username is not None or parsed.password is not None:
        raise RegistryError(f"{label} must not contain user credentials")
    if parsed.query or parsed.fragment or port not in {None, 443}:
        raise RegistryError(f"{label} must not contain query, fragment, or a non-443 port")
    if acquisition and parsed.hostname.lower() not in _ALLOWED_ACQUISITION_HOSTS:
        raise RegistryError(f"{label} host is not in the acquisition allowlist")


def validate_source_registry(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(data, _SOURCE_ROOT_KEYS, "registry")
    if data.get("registry_type") != "source-dataset-registry":
        raise RegistryError("registry_type must be source-dataset-registry")
    if data.get("schema_version") != "1.0":
        raise RegistryError("unsupported source registry schema_version")
    try:
        date.fromisoformat(data.get("updated_at"))
    except (TypeError, ValueError):
        raise RegistryError("updated_at must use YYYY-MM-DD")
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RegistryError("sources must be a non-empty array")

    seen: set[str] = set()
    for index, raw in enumerate(sources):
        label = f"sources[{index}]"
        source = _require_mapping(raw, label)
        _require_exact_keys(source, _SOURCE_KEYS, label)
        dataset_id = _require_text(source, "dataset_id", label)
        if not _ID_RE.fullmatch(dataset_id):
            raise RegistryError(f"{label}.dataset_id has unsafe characters")
        if dataset_id in seen:
            raise RegistryError(f"duplicate dataset_id: {dataset_id}")
        seen.add(dataset_id)
        _require_text(source, "name", label)
        _require_text(source, "notes", label)

        if source.get("source_type") != "git":
            raise RegistryError(f"{label}.source_type must be git in v1")
        url = _require_text(source, "upstream_url", label)
        _validate_https_url(url, f"{label}.upstream_url", acquisition=True)
        _require_text(source, "lineage_group", label)

        pin = _require_mapping(source.get("pin"), f"{label}.pin")
        _require_exact_keys(pin, _PIN_KEYS, f"{label}.pin")
        if pin.get("ref_type") not in {"commit", "annotated_tag"}:
            raise RegistryError(f"{label}.pin.ref_type must be commit or annotated_tag")
        ref_name = _require_text(pin, "ref_name", f"{label}.pin")
        commit = _require_text(pin, "resolved_commit", f"{label}.pin")
        if not _COMMIT_RE.fullmatch(commit):
            raise RegistryError(f"{label}.pin.resolved_commit must be 40 lowercase hex characters")
        if ref_name.lower() in {"main", "master", "head", "latest", "stable"} or ref_name.lower().startswith("refs/heads/"):
            raise RegistryError(f"{label}.pin.ref_name must not be floating")
        tag_object = pin.get("tag_object")
        if tag_object is not None and not _COMMIT_RE.fullmatch(str(tag_object)):
            raise RegistryError(f"{label}.pin.tag_object must be 40 lowercase hex characters")
        if pin["ref_type"] == "annotated_tag" and tag_object is None:
            raise RegistryError(f"{label}.pin.tag_object is required for annotated_tag")
        if pin["ref_type"] == "commit" and tag_object is not None:
            raise RegistryError(f"{label}.pin.tag_object must be null for commit")
        expected_archive_hash = pin.get("acquisition_artifact_sha256")
        if expected_archive_hash is not None and not _SHA256_RE.fullmatch(str(expected_archive_hash)):
            raise RegistryError(f"{label}.pin.acquisition_artifact_sha256 must be null or SHA-256")
        expected_root_id = f"{dataset_id}@{commit}"
        if source.get("root_id") != expected_root_id:
            raise RegistryError(f"{label}.root_id must equal {expected_root_id}")

        license_info = _require_mapping(source.get("license"), f"{label}.license")
        _require_exact_keys(license_info, _LICENSE_KEYS, f"{label}.license")
        _require_text(license_info, "expression", f"{label}.license")
        _require_text(license_info, "review_status", f"{label}.license")
        evidence_paths = license_info.get("evidence_paths")
        if not isinstance(evidence_paths, list) or not evidence_paths:
            raise RegistryError(f"{label}.license.evidence_paths must be a non-empty array")
        if len(evidence_paths) != len(set(evidence_paths)):
            raise RegistryError(f"{label}.license.evidence_paths must be unique")
        for evidence_index, evidence_path in enumerate(evidence_paths):
            if not isinstance(evidence_path, str):
                raise RegistryError(f"{label}.license.evidence_paths[{evidence_index}] must be text")
            _safe_relative_path(evidence_path, f"{label}.license.evidence_paths[{evidence_index}]")
        evidence_hashes = license_info.get("evidence_hashes")
        if not isinstance(evidence_hashes, dict) or set(evidence_hashes) != set(evidence_paths):
            raise RegistryError(f"{label}.license.evidence_hashes must exactly cover evidence_paths")
        for evidence_path, evidence_hash in evidence_hashes.items():
            if evidence_hash is not None and not _SHA256_RE.fullmatch(str(evidence_hash)):
                raise RegistryError(f"{label}.license.evidence_hashes[{evidence_path}] must be null or SHA-256")
        content_scopes = license_info.get("content_scopes")
        if not isinstance(content_scopes, list) or not content_scopes:
            raise RegistryError(f"{label}.license.content_scopes must be non-empty")
        seen_scopes: set[str] = set()
        for scope_index, raw_scope in enumerate(content_scopes):
            scope_label = f"{label}.license.content_scopes[{scope_index}]"
            scope = _require_mapping(raw_scope, scope_label)
            _require_exact_keys(scope, _SCOPE_KEYS, scope_label)
            scope_name = _require_text(scope, "scope", scope_label)
            if scope_name in seen_scopes:
                raise RegistryError(f"{label}.license.content_scopes scope names must be unique")
            seen_scopes.add(scope_name)
            _require_text(scope, "expression", scope_label)
            _require_bool(scope, "training_allowed", scope_label)
            _require_bool(scope, "raw_redistribution_allowed", scope_label)

        governance = _require_mapping(source.get("governance"), f"{label}.governance")
        _require_exact_keys(governance, _GOVERNANCE_KEYS, f"{label}.governance")
        admission = _require_text(governance, "admission_status", f"{label}.governance")
        if admission not in _ADMISSION:
            raise RegistryError(f"{label}.governance.admission_status is unsupported")
        split = _require_text(governance, "split", f"{label}.governance")
        if split not in _SPLITS:
            raise RegistryError(f"{label}.governance.split is unsupported")
        purposes = governance.get("purposes")
        if not isinstance(purposes, list) or not purposes or not all(isinstance(p, str) and p for p in purposes):
            raise RegistryError(f"{label}.governance.purposes must be non-empty text values")
        if len(purposes) != len(set(purposes)):
            raise RegistryError(f"{label}.governance.purposes must be unique")
        decision_keys = (
            "acquisition_allowed",
            "internal_development_allowed",
            "evaluation_allowed",
            "training_allowed",
            "fixture_distribution_allowed",
            "raw_redistribution_allowed",
            "adapter_distribution_allowed",
            "weight_distribution_allowed",
            "shipping_examples_allowed",
        )
        decisions = {key: _require_bool(governance, key, f"{label}.governance") for key in decision_keys}
        training_allowed = decisions["training_allowed"]
        for status_key in (
            "redistribution_status",
            "access_terms_status",
            "tdm_reservation_status",
            "submodules_status",
            "lfs_status",
            "generated_content_status",
            "binary_content_status",
            "attribution_status",
            "acquisition_status",
            "rights_status",
            "usage_status",
            "format_validation_status",
            "release_status",
        ):
            _require_text(governance, status_key, f"{label}.governance")
        controlled_statuses = {
            "acquisition_status": _ACQUISITION_STATUS,
            "rights_status": _RIGHTS_STATUS,
            "usage_status": _USAGE_STATUS,
            "format_validation_status": _FORMAT_STATUS,
            "release_status": _RELEASE_STATUS,
        }
        for status_key, allowed in controlled_statuses.items():
            if governance[status_key] not in allowed:
                raise RegistryError(f"{label}.governance.{status_key} is unsupported")
        rights_decision_ref = governance.get("rights_decision_ref")
        rights_decision_sha256 = governance.get("rights_decision_sha256")
        if rights_decision_ref is not None:
            if not isinstance(rights_decision_ref, str) or not rights_decision_ref.strip():
                raise RegistryError(f"{label}.governance.rights_decision_ref must be null or text")
            _safe_relative_path(rights_decision_ref, f"{label}.governance.rights_decision_ref")
        if rights_decision_sha256 is not None and not _SHA256_RE.fullmatch(str(rights_decision_sha256)):
            raise RegistryError(f"{label}.governance.rights_decision_sha256 must be null or SHA-256")
        triggers = governance.get("revalidation_triggers")
        if not isinstance(triggers, list) or not triggers or not all(isinstance(item, str) and item for item in triggers):
            raise RegistryError(f"{label}.governance.revalidation_triggers must be non-empty text values")
        if len(triggers) != len(set(triggers)):
            raise RegistryError(f"{label}.governance.revalidation_triggers must be unique")

        usage_decision_keys = tuple(key for key in decision_keys if key != "acquisition_allowed")
        any_usage_allowed = any(decisions[key] for key in usage_decision_keys)
        hashes_complete = all(value is not None for value in evidence_hashes.values())
        rights_reviewed = governance["rights_status"] == "RIGHTS_REVIEWED"
        acquisition_status = governance["acquisition_status"]
        if admission == "REGISTERED_PENDING_REVIEW" and acquisition_status != "REGISTERED_PENDING_ACQUISITION":
            raise RegistryError(f"{label}: pending review requires pending acquisition status")
        if admission == "QUARANTINE_ACQUIRED" and acquisition_status not in {
            "ACQUIRED_UNSEALED",
            "FROZEN_VERIFIED_TECHNICAL",
        }:
            raise RegistryError(f"{label}: quarantine acquisition requires an acquired status")
        if acquisition_status == "FROZEN_VERIFIED_TECHNICAL" and not (
            expected_archive_hash is not None and hashes_complete
        ):
            raise RegistryError(f"{label}: frozen acquisition requires archive and license evidence hashes")
        if admission == "REJECT" and (decisions["acquisition_allowed"] or any_usage_allowed):
            raise RegistryError(f"{label}: rejected source cannot authorize acquisition or usage")
        if any_usage_allowed and not (
            hashes_complete and rights_reviewed and rights_decision_ref is not None and rights_decision_sha256 is not None
        ):
            raise RegistryError(f"{label}: use beyond quarantine requires complete license hashes and a frozen rights decision")
        if rights_reviewed and (rights_decision_ref is None or rights_decision_sha256 is None):
            raise RegistryError(f"{label}: RIGHTS_REVIEWED requires a frozen rights decision")
        if admission in {"RIGHTS_REVIEWED", *_ADMITTED} and not rights_reviewed:
            raise RegistryError(f"{label}: admission status requires RIGHTS_REVIEWED")
        if any_usage_allowed and admission not in _ADMITTED:
            raise RegistryError(f"{label}: usage cannot be enabled before rights admission")
        if admission not in _ADMITTED and governance["usage_status"] != "NOT_ADMITTED":
            raise RegistryError(f"{label}: non-admitted source must retain NOT_ADMITTED usage status")
        primary_admissions = {
            "ADMITTED_FOR_INTERNAL_DEVELOPMENT": (
                decisions["internal_development_allowed"],
                "ADMITTED_FOR_INTERNAL_DEVELOPMENT",
            ),
            "ADMITTED_FOR_EVALUATION": (decisions["evaluation_allowed"], "ADMITTED_FOR_EVALUATION"),
            "ADMITTED_FOR_TRAINING": (decisions["training_allowed"], "ADMITTED_FOR_TRAINING"),
            "ADMITTED_FOR_PUBLIC_REGRESSION": (
                decisions["evaluation_allowed"],
                "ADMITTED_FOR_PUBLIC_REGRESSION",
            ),
        }
        if admission in primary_admissions:
            primary_allowed, expected_usage_status = primary_admissions[admission]
            primary_decisions = (
                decisions["internal_development_allowed"],
                decisions["evaluation_allowed"],
                decisions["training_allowed"],
            )
            if (
                not primary_allowed
                or sum(primary_decisions) != 1
                or governance["usage_status"] != expected_usage_status
            ):
                raise RegistryError(f"{label}: admitted purpose requires its matching decision and usage status")
        if admission == "ADMITTED_FOR_PUBLIC_REGRESSION" and (
            split != "PUBLIC_REGRESSION"
        ):
            raise RegistryError(f"{label}: public regression admission requires matching split and usage status")
        if governance["release_status"] != "NOT_APPROVED" and admission not in _ADMITTED:
            raise RegistryError(f"{label}: scoped release requires a purpose admission")
        if training_allowed:
            if split != "TRAIN" or not all(scope["training_allowed"] for scope in content_scopes):
                raise RegistryError(f"{label}: global training decision exceeds split or content-scope decisions")
        if decisions["raw_redistribution_allowed"] and not all(
            scope["raw_redistribution_allowed"] for scope in content_scopes
        ):
            raise RegistryError(f"{label}: global redistribution decision exceeds a content-scope decision")
        if rights_reviewed or admission in _ADMITTED or any_usage_allowed:
            raise RegistryError(
                f"{label}: Phase 1 does not accept source-use admission until the referenced rights decision "
                "artifact, subject, scope, reviewer, and hash are verified"
            )

        acquisition = _require_mapping(source.get("acquisition"), f"{label}.acquisition")
        _require_exact_keys(acquisition, _ACQUISITION_KEYS, f"{label}.acquisition")
        if _require_bool(acquisition, "allow_submodules", f"{label}.acquisition"):
            raise RegistryError(f"{label}: submodules are forbidden in v1")
        if _require_bool(acquisition, "execute_code", f"{label}.acquisition"):
            raise RegistryError(f"{label}: acquisition must never execute source code")
        max_files = acquisition.get("max_files")
        max_total_bytes = acquisition.get("max_total_bytes")
        if type(max_files) is not int or not 1 <= max_files <= 1_000_000:
            raise RegistryError(f"{label}.acquisition.max_files is invalid")
        if type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 20_000_000_000:
            raise RegistryError(f"{label}.acquisition.max_total_bytes is invalid")

    return {"registry_type": data["registry_type"], "schema_version": "1.0", "entries": len(sources)}


def validate_runtime_registry(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(data, _RUNTIME_ROOT_KEYS, "registry")
    if data.get("registry_type") != "runtime-registry":
        raise RegistryError("registry_type must be runtime-registry")
    if data.get("schema_version") != "1.0":
        raise RegistryError("unsupported runtime registry schema_version")
    try:
        date.fromisoformat(data.get("updated_at"))
    except (TypeError, ValueError):
        raise RegistryError("updated_at must use YYYY-MM-DD")
    runtimes = data.get("runtimes")
    if not isinstance(runtimes, list) or not runtimes:
        raise RegistryError("runtimes must be a non-empty array")
    seen: set[str] = set()
    for index, raw in enumerate(runtimes):
        label = f"runtimes[{index}]"
        runtime = _require_mapping(raw, label)
        _require_exact_keys(runtime, _RUNTIME_KEYS, label)
        runtime_id = _require_text(runtime, "runtime_id", label)
        if not _ID_RE.fullmatch(runtime_id) or runtime_id in seen:
            raise RegistryError(f"{label}.runtime_id is unsafe or duplicated")
        seen.add(runtime_id)
        if _require_text(runtime, "category", label) not in {"scanner", "validator", "model_server", "schema", "signing"}:
            raise RegistryError(f"{label}.category is unsupported")
        _require_text(runtime, "name", label)
        _require_text(runtime, "version", label)
        _require_text(runtime, "license_expression", label)
        _require_text(runtime, "notes", label)
        source_url = _require_text(runtime, "source_url", label)
        _validate_https_url(source_url, f"{label}.source_url", acquisition=False)
        commit = _require_text(runtime, "resolved_commit", label)
        if not _COMMIT_RE.fullmatch(commit):
            raise RegistryError(f"{label}.resolved_commit must be 40 lowercase hex characters")
        status = _require_text(runtime, "status", label)
        if status not in {"REGISTERED_NOT_ACQUIRED", "LOCALLY_OBSERVED", "FROZEN"}:
            raise RegistryError(f"{label}.status is unsupported")
        artifact_hash = runtime.get("artifact_sha256")
        if artifact_hash is not None and not _SHA256_RE.fullmatch(str(artifact_hash)):
            raise RegistryError(f"{label}.artifact_sha256 must be null or lowercase SHA-256")
        for hash_key in ("config_sha256", "dependency_manifest_sha256"):
            hash_value = runtime.get(hash_key)
            if hash_value is not None and not _SHA256_RE.fullmatch(str(hash_value)):
                raise RegistryError(f"{label}.{hash_key} must be null or lowercase SHA-256")
        if status == "FROZEN" and any(
            runtime.get(key) is None for key in ("artifact_sha256", "config_sha256", "dependency_manifest_sha256")
        ):
            raise RegistryError(f"{label}: FROZEN requires artifact, config, and dependency manifest hashes")
    return {"registry_type": data["registry_type"], "schema_version": "1.0", "entries": len(runtimes)}


def validate_vex_issuer_registry(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(data, _VEX_ISSUER_ROOT_KEYS, "registry")
    if data.get("registry_type") != "vex-issuer-registry":
        raise RegistryError("registry_type must be vex-issuer-registry")
    if data.get("schema_version") != "vex-issuer-allowlist-1.0":
        raise RegistryError("unsupported vex issuer registry schema_version")
    try:
        date.fromisoformat(data.get("updated_at"))
    except (TypeError, ValueError):
        raise RegistryError("updated_at must use YYYY-MM-DD")
    issuers = data.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        raise RegistryError("issuers must be a non-empty array")
    seen: set[str] = set()
    for index, raw in enumerate(issuers):
        label = f"issuers[{index}]"
        issuer = _require_mapping(raw, label)
        _require_exact_keys(issuer, _VEX_ISSUER_KEYS, label)
        issuer_id = _require_text(issuer, "issuer_id", label)
        if not _ID_RE.fullmatch(issuer_id) or issuer_id in seen:
            raise RegistryError(f"{label}.issuer_id is unsafe or duplicated")
        seen.add(issuer_id)
        _require_text(issuer, "display_name", label)
        if _require_text(issuer, "identity_kind", label) not in _VEX_ISSUER_IDENTITY_KINDS:
            raise RegistryError(f"{label}.identity_kind is unsupported")
        status = _require_text(issuer, "status", label)
        if status not in _VEX_ISSUER_STATUSES:
            raise RegistryError(f"{label}.status is unsupported")
        _require_text(issuer, "boundary", label)
        key_hash = issuer.get("public_key_sha256")
        if key_hash is not None and not _SHA256_RE.fullmatch(str(key_hash)):
            raise RegistryError(f"{label}.public_key_sha256 must be null or lowercase SHA-256")
        key_path = issuer.get("public_key_path")
        receipt_ref = issuer.get("acquisition_receipt_ref")
        if status == "ADMITTED_FOR_VEX_INTAKE":
            if (
                key_hash is None
                or not isinstance(key_path, str)
                or not key_path
                or not isinstance(receipt_ref, str)
                or not receipt_ref
            ):
                raise RegistryError(
                    f"{label}: ADMITTED_FOR_VEX_INTAKE requires public_key_sha256, "
                    "public_key_path, and acquisition_receipt_ref"
                )
            _safe_relative_path(key_path, f"{label}.public_key_path")
            _safe_relative_path(receipt_ref, f"{label}.acquisition_receipt_ref")
        else:  # NOT_ADMITTED must not carry key material
            if key_hash is not None or key_path is not None or receipt_ref is not None:
                raise RegistryError(f"{label}: NOT_ADMITTED must not carry key material")
    return {
        "registry_type": data["registry_type"],
        "schema_version": "vex-issuer-allowlist-1.0",
        "entries": len(issuers),
    }


def load_and_validate_registry(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    data, _ = _load_json_payload(path)
    report = _validate_registry_data(data)
    return data, report


def load_and_validate_registry_with_hash(path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Read once, validate, and bind exactly the bytes that were interpreted."""

    data, payload = _load_json_payload(path)
    report = _validate_registry_data(data)
    return data, report, hashlib.sha256(payload).hexdigest()


def _validate_registry_data(data: dict[str, Any]) -> dict[str, Any]:
    registry_type = data.get("registry_type")
    if registry_type == "source-dataset-registry":
        report = validate_source_registry(data)
    elif registry_type == "runtime-registry":
        report = validate_runtime_registry(data)
    elif registry_type == "vex-issuer-registry":
        report = validate_vex_issuer_registry(data)
    else:
        raise RegistryError("unknown registry_type")
    return report


def find_source(data: dict[str, Any], dataset_id: str) -> dict[str, Any]:
    validate_source_registry(data)
    for source in data["sources"]:
        if source["dataset_id"] == dataset_id:
            if source["governance"]["admission_status"] == "REJECT":
                raise RegistryError(f"dataset {dataset_id} is rejected")
            if not source["governance"]["acquisition_allowed"]:
                raise RegistryError(f"dataset {dataset_id} is not approved for acquisition")
            return source
    raise RegistryError(f"unknown dataset_id: {dataset_id}")
