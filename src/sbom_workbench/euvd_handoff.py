"""One-way, hash-bound CycloneDX handoff to the local EUVD matcher."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .manifest import canonical_json_bytes, sha256_file, write_json_atomic
from .selftest import SelfTestError, parse_cyclonedx_json


CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
DEFAULT_ENDPOINT = "http://127.0.0.1:8090"
MAX_SBOM_BYTES = 64 * 1024 * 1024
# Component-count budget independent of byte size: a 64 MiB CycloneDX can still
# carry millions of shallow components that exhaust memory on intake (CLI-4).
MAX_HANDOFF_COMPONENTS = 200_000
_SHA256 = re.compile(r"[0-9a-f]{64}")
AUTHORITY_BOUNDARY = "NO_SBOM_FACT_RELEASE_CONFORMITY_OR_REPORTING_AUTHORITY"
KEV_BOUNDARY = "KEV_PRESENCE_IS_PRIORITIZATION_ONLY_ABSENCE_IS_NOT_NON_EXPLOITATION_PROOF"
DECLARED_BINDING = "CALLER_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
VERIFIED_SELFTEST_BINDING = "DERIVED_FROM_VERIFIED_M3A_ROOT"
SELFTEST_PROFILE_IDS = frozenset(
    {"m3a-source-directory", "m3a-oci-archive", "m3a-portable-runtime"}
)
RECEIPT_KEYS = {
    "schema_version",
    "classification",
    "handoff_id",
    "source_run_id",
    "source_binding_status",
    "source_profile_id",
    "source_root_completion_sha256",
    "source_relative_name",
    "cyclonedx_spec_version",
    "cyclonedx_sha256",
    "component_record_count",
    "purl_coverage",
    "version_coverage",
    "target_endpoint",
    "direction",
    "reverse_fact_write",
    "automatic_art14_decision",
    "kev_boundary",
    "authority_boundary",
}
COMPLETE_KEYS = {
    "schema_version",
    "handoff_id",
    "cyclonedx_sha256",
    "receipt_sha256",
}


class EuvdHandoffError(ValueError):
    """Raised when a handoff would weaken source or network boundaries."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EuvdHandoffError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EuvdHandoffError(f"non-standard JSON constant is forbidden: {value}")


def _prepare_euvd_handoff(
    cyclonedx_path: Path,
    handoff_parent: Path,
    *,
    source_run_id: str,
    source_binding_status: str,
    source_profile_id: str | None,
    source_root_completion_sha256: str | None,
    endpoint: str,
) -> dict[str, Any]:
    """Internal writer after the caller has established the source binding."""

    validate_loopback_endpoint(endpoint)
    if source_binding_status not in {DECLARED_BINDING, VERIFIED_SELFTEST_BINDING}:
        raise EuvdHandoffError("source binding status is invalid")
    if source_binding_status == DECLARED_BINDING:
        if source_profile_id is not None or source_root_completion_sha256 is not None:
            raise EuvdHandoffError("declared source binding must not claim verified-root fields")
    elif (
        source_profile_id not in SELFTEST_PROFILE_IDS
        or not isinstance(source_root_completion_sha256, str)
        or not _SHA256.fullmatch(source_root_completion_sha256)
    ):
        raise EuvdHandoffError("verified self-test source binding fields are invalid")
    if not isinstance(source_run_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255}", source_run_id
    ):
        raise EuvdHandoffError("source_run_id is invalid")
    source = Path(cyclonedx_path)
    payload = _read_regular(source, maximum=MAX_SBOM_BYTES)
    document = _parse_cyclonedx(payload)
    source_sha256 = hashlib.sha256(payload).hexdigest()
    identity = {
        "source_run_id": source_run_id,
        "source_binding_status": source_binding_status,
        "source_profile_id": source_profile_id,
        "source_root_completion_sha256": source_root_completion_sha256,
        "cyclonedx_sha256": source_sha256,
        "endpoint": DEFAULT_ENDPOINT,
        "direction": "SBOM_TO_EUVD_ONLY",
    }
    handoff_id = f"euvd-{hashlib.sha256(canonical_json_bytes(identity)).hexdigest()}"
    parent = Path(handoff_parent)
    if parent.is_symlink():
        raise EuvdHandoffError("handoff parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    parent = parent.resolve(strict=True)
    destination = parent / handoff_id
    if destination.exists() or destination.is_symlink():
        raise EuvdHandoffError("handoff already exists; refusing overwrite")
    stage = Path(tempfile.mkdtemp(prefix=f".{handoff_id}.", dir=parent))
    moved = False
    try:
        output = stage / "cyclonedx-input.json"
        with output.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        receipt = {
            "schema_version": "1.0",
            "classification": CLASSIFICATION,
            "handoff_id": handoff_id,
            "source_run_id": source_run_id,
            "source_binding_status": source_binding_status,
            "source_profile_id": source_profile_id,
            "source_root_completion_sha256": source_root_completion_sha256,
            "source_relative_name": source.name,
            "cyclonedx_spec_version": document["specVersion"],
            "cyclonedx_sha256": source_sha256,
            "component_record_count": document["_validated_component_record_count"],
            "purl_coverage": {
                "with_purl": document["_purl_component_count"],
                "total": document["_validated_component_record_count"],
            },
            "version_coverage": {
                "with_version": document["_version_component_count"],
                "total": document["_validated_component_record_count"],
            },
            "target_endpoint": DEFAULT_ENDPOINT,
            "direction": "SBOM_TO_EUVD_ONLY",
            "reverse_fact_write": False,
            "automatic_art14_decision": False,
            "kev_boundary": KEV_BOUNDARY,
            "authority_boundary": AUTHORITY_BOUNDARY,
        }
        write_json_atomic(stage / "receipt.json", receipt)
        complete = {
            "schema_version": "1.0",
            "handoff_id": handoff_id,
            "cyclonedx_sha256": source_sha256,
            "receipt_sha256": sha256_file(stage / "receipt.json"),
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        os.replace(stage, destination)
        moved = True
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)
    if hashlib.sha256(_read_regular(source, maximum=MAX_SBOM_BYTES)).hexdigest() != source_sha256:
        raise EuvdHandoffError("source candidate changed during handoff")
    return validate_euvd_handoff(destination)


def _read_regular(path: Path, *, maximum: int) -> bytes:
    candidate = Path(path)
    if candidate.is_symlink():
        raise EuvdHandoffError("handoff input must not be a symlink")
    try:
        info = candidate.stat()
    except OSError as exc:
        raise EuvdHandoffError("handoff input is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise EuvdHandoffError("handoff input must be one regular non-hard-linked file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise EuvdHandoffError("handoff input is empty or exceeds its byte limit")
    try:
        payload = candidate.read_bytes()
    except OSError as exc:
        raise EuvdHandoffError("cannot read handoff input") from exc
    if len(payload) != info.st_size:
        raise EuvdHandoffError("handoff input changed while being read")
    return payload


def _parse_cyclonedx(
    payload: bytes, *, max_components: int = MAX_HANDOFF_COMPONENTS
) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except EuvdHandoffError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise EuvdHandoffError("handoff SBOM is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX":
        raise EuvdHandoffError("handoff accepts CycloneDX JSON only")
    if value.get("specVersion") not in {"1.4", "1.5", "1.6", "1.7"}:
        raise EuvdHandoffError("CycloneDX version is outside the local matcher intake profile")
    components = value.get("components")
    if not isinstance(components, list):
        raise EuvdHandoffError("CycloneDX components must be an array")
    if len(components) > max_components:
        raise EuvdHandoffError(
            f"handoff SBOM exceeds component budget ({max_components})"
        )
    try:
        projection = parse_cyclonedx_json(payload)
    except SelfTestError as exc:
        raise EuvdHandoffError(f"CycloneDX reference validation failed: {exc}") from exc
    all_records = [projection["metadata"]["component"], *projection["components"]]
    value["_validated_component_record_count"] = len(projection["components"]) + 1
    value["_purl_component_count"] = sum(1 for record in all_records if record.get("purl"))
    value["_version_component_count"] = sum(
        1 for record in all_records if record.get("version")
    )
    return value


def validate_loopback_endpoint(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise EuvdHandoffError("EUVD endpoint is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port != 8090
        or parsed.path not in {"", "/"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EuvdHandoffError("EUVD endpoint must be exactly http://127.0.0.1:8090")
    return DEFAULT_ENDPOINT


def prepare_euvd_handoff(
    cyclonedx_path: Path,
    handoff_parent: Path,
    *,
    source_run_id: str,
    endpoint: str = DEFAULT_ENDPOINT,
) -> dict[str, Any]:
    """Copy a caller-declared candidate without claiming a verified M3A binding."""

    return _prepare_euvd_handoff(
        cyclonedx_path,
        handoff_parent,
        source_run_id=source_run_id,
        source_binding_status=DECLARED_BINDING,
        source_profile_id=None,
        source_root_completion_sha256=None,
        endpoint=endpoint,
    )


def prepare_verified_selftest_euvd_handoff(
    selftest_root: Path,
    handoff_parent: Path,
    *,
    profile_id: str = "m3a-source-directory",
    endpoint: str = DEFAULT_ENDPOINT,
) -> dict[str, Any]:
    """Derive the EUVD input and run identity from a verified M3A output root."""

    if profile_id not in SELFTEST_PROFILE_IDS:
        raise EuvdHandoffError("EUVD source profile is not one of the three M3A profiles")
    from .selftest_root import SelfTestRootError, verify_selftest_root

    try:
        verified = verify_selftest_root(selftest_root)
    except SelfTestRootError as exc:
        raise EuvdHandoffError(f"verified self-test source binding failed: {exc}") from exc
    root = Path(selftest_root).resolve(strict=True)
    source = root / "raw" / profile_id / "raw.cyclonedx.json"
    prepared = _prepare_euvd_handoff(
        source,
        handoff_parent,
        source_run_id=verified["run_id"],
        source_binding_status=VERIFIED_SELFTEST_BINDING,
        source_profile_id=profile_id,
        source_root_completion_sha256=sha256_file(root / "SELFTEST_COMPLETE.json"),
        endpoint=endpoint,
    )
    return validate_euvd_handoff(
        Path(handoff_parent) / prepared["handoff_id"],
        selftest_root=root,
    )


def validate_euvd_handoff(
    handoff_directory: Path,
    *,
    selftest_root: Path | None = None,
) -> dict[str, Any]:
    root = Path(handoff_directory)
    if root.is_symlink() or not root.is_dir():
        raise EuvdHandoffError("handoff directory is invalid")
    actual = {path.name for path in root.iterdir()}
    expected = {"cyclonedx-input.json", "receipt.json", "COMPLETE.json"}
    if actual != expected:
        raise EuvdHandoffError("handoff exact-set mismatch")
    payload = _read_regular(root / "cyclonedx-input.json", maximum=MAX_SBOM_BYTES)
    document = _parse_cyclonedx(payload)
    try:
        receipt = json.loads(
            _read_regular(root / "receipt.json", maximum=1024 * 1024).decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
        complete = json.loads(
            _read_regular(root / "COMPLETE.json", maximum=1024 * 1024).decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EuvdHandoffError("handoff metadata is invalid JSON") from exc
    digest = hashlib.sha256(payload).hexdigest()
    if (
        not isinstance(receipt, dict)
        or set(receipt) != RECEIPT_KEYS
        or receipt.get("schema_version") != "1.0"
        or receipt.get("classification") != CLASSIFICATION
        or not isinstance(receipt.get("handoff_id"), str)
        or not re.fullmatch(r"euvd-[0-9a-f]{64}", receipt["handoff_id"])
        or not isinstance(receipt.get("source_run_id"), str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255}", receipt["source_run_id"])
        or not isinstance(receipt.get("source_relative_name"), str)
        or not receipt["source_relative_name"]
        or Path(receipt["source_relative_name"]).name != receipt["source_relative_name"]
        or receipt.get("cyclonedx_spec_version") != document.get("specVersion")
        or receipt.get("cyclonedx_sha256") != digest
        or receipt.get("component_record_count")
        != document["_validated_component_record_count"]
        or receipt.get("purl_coverage")
        != {
            "with_purl": document["_purl_component_count"],
            "total": document["_validated_component_record_count"],
        }
        or receipt.get("version_coverage")
        != {
            "with_version": document["_version_component_count"],
            "total": document["_validated_component_record_count"],
        }
        or receipt.get("target_endpoint") != DEFAULT_ENDPOINT
        or receipt.get("direction") != "SBOM_TO_EUVD_ONLY"
        or receipt.get("reverse_fact_write") is not False
        or receipt.get("automatic_art14_decision") is not False
        or receipt.get("kev_boundary") != KEV_BOUNDARY
        or receipt.get("authority_boundary") != AUTHORITY_BOUNDARY
    ):
        raise EuvdHandoffError("handoff receipt binding or boundary is invalid")
    binding_status = receipt.get("source_binding_status")
    if binding_status == DECLARED_BINDING:
        if (
            receipt.get("source_profile_id") is not None
            or receipt.get("source_root_completion_sha256") is not None
        ):
            raise EuvdHandoffError("declared source binding contains verified-root fields")
    elif binding_status == VERIFIED_SELFTEST_BINDING:
        if (
            receipt.get("source_profile_id") not in SELFTEST_PROFILE_IDS
            or not isinstance(receipt.get("source_root_completion_sha256"), str)
            or not _SHA256.fullmatch(receipt["source_root_completion_sha256"])
        ):
            raise EuvdHandoffError("verified source binding fields are invalid")
    else:
        raise EuvdHandoffError("handoff source binding status is invalid")
    expected_identity = {
        "source_run_id": receipt["source_run_id"],
        "source_binding_status": receipt["source_binding_status"],
        "source_profile_id": receipt["source_profile_id"],
        "source_root_completion_sha256": receipt["source_root_completion_sha256"],
        "cyclonedx_sha256": digest,
        "endpoint": DEFAULT_ENDPOINT,
        "direction": "SBOM_TO_EUVD_ONLY",
    }
    expected_handoff_id = (
        f"euvd-{hashlib.sha256(canonical_json_bytes(expected_identity)).hexdigest()}"
    )
    if receipt["handoff_id"] != expected_handoff_id:
        raise EuvdHandoffError("handoff identity does not rederive from its fixed inputs")
    if root.name != receipt["handoff_id"]:
        raise EuvdHandoffError("handoff directory name does not match its derived identity")
    if (
        not isinstance(complete, dict)
        or set(complete) != COMPLETE_KEYS
        or complete.get("schema_version") != "1.0"
        or complete.get("handoff_id") != receipt.get("handoff_id")
        or complete.get("cyclonedx_sha256") != digest
        or complete.get("receipt_sha256") != sha256_file(root / "receipt.json")
    ):
        raise EuvdHandoffError("handoff completion binding is invalid")
    status = "SELF_CONSISTENCY_ONLY_SOURCE_NOT_REVERIFIED"
    source_reverification_status = "NOT_REVERIFIED"
    if binding_status == VERIFIED_SELFTEST_BINDING and selftest_root is not None:
        from .selftest_root import SelfTestRootError, verify_selftest_root

        try:
            verified_root = verify_selftest_root(selftest_root)
        except (SelfTestRootError, OSError) as exc:
            raise EuvdHandoffError(f"handoff source root revalidation failed: {exc}") from exc
        source_root = Path(selftest_root).resolve(strict=True)
        if (
            verified_root["run_id"] != receipt["source_run_id"]
            or sha256_file(source_root / "SELFTEST_COMPLETE.json")
            != receipt["source_root_completion_sha256"]
        ):
            raise EuvdHandoffError("handoff source root identity or completion hash mismatch")
        source_candidate = (
            source_root
            / "raw"
            / str(receipt["source_profile_id"])
            / "raw.cyclonedx.json"
        )
        if sha256_file(source_candidate) != digest:
            raise EuvdHandoffError("handoff CycloneDX does not match the revalidated source profile")
        status = "VALIDATED_ONE_WAY_EUVD_HANDOFF"
        source_reverification_status = "VERIFIED_AGAINST_M3A_ROOT"
    elif binding_status == DECLARED_BINDING:
        status = "SELF_CONSISTENCY_ONLY_CALLER_DECLARED_SOURCE"
        source_reverification_status = "CALLER_DECLARED_NOT_REVERIFIED"
    return {
        "status": status,
        "handoff_id": receipt["handoff_id"],
        "cyclonedx_sha256": digest,
        "target_endpoint": DEFAULT_ENDPOINT,
        "source_binding_status": receipt["source_binding_status"],
        "source_reverification_status": source_reverification_status,
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
