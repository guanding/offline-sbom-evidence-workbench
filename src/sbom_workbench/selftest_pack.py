"""Immutable M4A packages for isolated self-test SBOM observations.

The package is deliberately a review candidate, not a component-population
union.  Each raw CycloneDX document remains bound to exactly one source, OCI,
or portable-runtime observation.  Verification is read-only and re-parses the
raw documents before accepting any derived projection.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .in_toto import InTotoError, validate_statement, wrap_statement
from .manifest import canonical_json_bytes, sha256_file, write_json_atomic
from .pack import PackError, _publish_registered_stage
from .selftest import (
    CLASSIFICATION,
    GENERATOR_STATUS,
    MANUFACTURER_STATUS,
    MILESTONE_SCOPE,
    PRODUCT_STATUS,
    PROFILE_DOMAINS,
    PROFILE_TARGETS,
    RELEASE_STATUS,
    REQUIRED_BLINDSPOTS,
    SelfTestError,
    load_cyclonedx,
    reconcile_profile_observations,
)


class SelfTestPackError(ValueError):
    """Raised when a self-test candidate cannot be sealed or verified."""


SCHEMA_VERSION = "1.0"
PACKAGE_STATUS = "SELF_TEST_PACK_PASS_OPEN_CANDIDATE"
BOUNDARY = (
    "Local engineering self-test only. Source, OCI and portable observations are isolated "
    "generator-output candidates, not a completeness union, customer evidence, manufacturer "
    "approval, SBOM release, Yocto M3B, PRE-7 or CRA conformity, a CAB conclusion, ground truth, "
    "or certification."
)
BASE_PAYLOAD_FILES = (
    "dashboard.json",
    "inputs/source-manifest.json",
    "profile-observations.json",
    "reconciliation.json",
    "run.json",
    "validation.json",
)
_SOURCE_MANIFEST_KEYS = {
    "schema_version",
    "root_id",
    "file_count",
    "total_bytes",
    "exact_set_sha256",
    "files",
}
_MANIFEST_ENTRY_KEYS = {"relative_path", "sha256", "size", "executable"}
_OBSERVATION_KEYS = {
    "schema_version",
    "classification",
    "generator_output_status",
    "release_status",
    "product_conformity_status",
    "manufacturer_approval_status",
    "milestone_scope",
    "profile_id",
    "profile_kind",
    "independence_domain",
    "subject",
    "scan_contract",
    "blindspots",
    "input_identity",
    "scanner_identity",
    "cyclonedx_evidence",
    "canonical_sha256",
    "run_id",
}
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+~-]{0,255}")
_SHA256 = frozenset("0123456789abcdef")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _SHA256


def _strict_json(path: Path, label: str, *, maximum: int = 256 * 1024 * 1024) -> Any:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SelfTestPackError(f"cannot access {label}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise SelfTestPackError(f"{label} must be one bounded single-link regular file")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SelfTestPackError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise SelfTestPackError(f"non-standard JSON constant is forbidden in {label}: {value}")

    try:
        payload = path.read_bytes()
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except SelfTestPackError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SelfTestPackError(f"{label} is not strict UTF-8 JSON") from exc


def _safe_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SelfTestPackError(f"{label} is not a safe relative path")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or candidate.as_posix() != value or any(
        part in {"", ".", ".."} for part in candidate.parts
    ):
        raise SelfTestPackError(f"{label} is not a normalized relative path")
    return value


def _normalize_source_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SOURCE_MANIFEST_KEYS:
        raise SelfTestPackError("source manifest fields do not match the exact-set profile")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise SelfTestPackError("source manifest version is unsupported")
    root_id = value.get("root_id")
    if not isinstance(root_id, str) or not root_id or len(root_id) > 4096:
        raise SelfTestPackError("source manifest root_id is invalid")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise SelfTestPackError("source manifest files must be a non-empty array")
    normalized_files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for index, item in enumerate(files):
        if not isinstance(item, dict) or set(item) != _MANIFEST_ENTRY_KEYS:
            raise SelfTestPackError(f"source manifest files[{index}] fields do not match")
        relative_path = _safe_relative_path(
            item.get("relative_path"), f"source manifest files[{index}].relative_path"
        )
        if relative_path in seen:
            raise SelfTestPackError("source manifest contains a duplicate relative path")
        seen.add(relative_path)
        digest = item.get("sha256")
        size = item.get("size")
        executable = item.get("executable")
        if not _is_sha256(digest) or type(size) is not int or size < 0 or type(executable) is not bool:
            raise SelfTestPackError(f"source manifest files[{index}] identity is invalid")
        total_bytes += size
        normalized_files.append(
            {
                "relative_path": relative_path,
                "sha256": digest,
                "size": size,
                "executable": executable,
            }
        )
    normalized_files.sort(key=lambda item: item["relative_path"].encode("utf-8"))
    identity = {"root_id": root_id, "files": normalized_files}
    exact_set_sha256 = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    if (
        value.get("file_count") != len(normalized_files)
        or value.get("total_bytes") != total_bytes
        or value.get("exact_set_sha256") != exact_set_sha256
    ):
        raise SelfTestPackError("source manifest exact-set identity is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "root_id": root_id,
        "file_count": len(normalized_files),
        "total_bytes": total_bytes,
        "exact_set_sha256": exact_set_sha256,
        "files": normalized_files,
    }


def _verify_authority(value: Mapping[str, Any], label: str) -> None:
    fixed = {
        "classification": CLASSIFICATION,
        "generator_output_status": GENERATOR_STATUS,
        "release_status": RELEASE_STATUS,
        "product_conformity_status": PRODUCT_STATUS,
        "manufacturer_approval_status": MANUFACTURER_STATUS,
        "milestone_scope": MILESTONE_SCOPE,
    }
    for key, expected in fixed.items():
        if value.get(key) != expected:
            raise SelfTestPackError(f"{label} attempted authority escalation through {key}")


def _verify_observation_shape(value: dict[str, Any]) -> None:
    label = f"profile {value.get('profile_id', 'UNKNOWN')}"
    if set(value) != _OBSERVATION_KEYS or value.get("schema_version") != SCHEMA_VERSION:
        raise SelfTestPackError(f"{label} fields do not match the sealed observation profile")
    profile_id = value.get("profile_id")
    if not isinstance(profile_id, str) or not _SAFE_ID_RE.fullmatch(profile_id):
        raise SelfTestPackError(f"{label} profile_id is unsafe")
    profile_kind = value.get("profile_kind")
    if profile_kind not in PROFILE_DOMAINS:
        raise SelfTestPackError(f"{label} profile_kind is unsupported")
    if value.get("independence_domain") != PROFILE_DOMAINS[profile_kind]:
        raise SelfTestPackError(f"{label} independence domain is inconsistent")
    subject = value.get("subject")
    if not isinstance(subject, dict) or set(subject) != {
        "comparison_namespace",
        "product_name",
        "declared_version",
    }:
        raise SelfTestPackError(f"{label} subject fields do not match")
    namespace = subject.get("comparison_namespace")
    if not isinstance(namespace, str) or not _SAFE_ID_RE.fullmatch(namespace):
        raise SelfTestPackError(f"{label} comparison namespace is unsafe")
    for key in ("product_name", "declared_version"):
        if not isinstance(subject.get(key), str) or not subject[key]:
            raise SelfTestPackError(f"{label} subject.{key} is invalid")
    scan_contract = value.get("scan_contract")
    if (
        not isinstance(scan_contract, dict)
        or set(scan_contract) != {"target_kind", "target_label"}
        or scan_contract.get("target_kind") != PROFILE_TARGETS[profile_kind]
        or not isinstance(scan_contract.get("target_label"), str)
        or not _SAFE_ID_RE.fullmatch(scan_contract["target_label"])
    ):
        raise SelfTestPackError(f"{label} scan contract is inconsistent")
    blindspots = value.get("blindspots")
    if (
        not isinstance(blindspots, list)
        or len(blindspots) != len(set(blindspots))
        or not REQUIRED_BLINDSPOTS.issubset(blindspots)
    ):
        raise SelfTestPackError(f"{label} mandatory blindspots are missing")
    input_identity = value.get("input_identity")
    if not isinstance(input_identity, dict) or set(input_identity) != {
        "root_id",
        "sha256",
        "file_count",
        "total_bytes",
    }:
        raise SelfTestPackError(f"{label} input identity fields do not match")
    if (
        not isinstance(input_identity.get("root_id"), str)
        or not input_identity["root_id"]
        or not _is_sha256(input_identity.get("sha256"))
        or type(input_identity.get("file_count")) is not int
        or input_identity["file_count"] < 1
        or type(input_identity.get("total_bytes")) is not int
        or input_identity["total_bytes"] < 1
    ):
        raise SelfTestPackError(f"{label} input identity is invalid")
    scanner = value.get("scanner_identity")
    if (
        not isinstance(scanner, dict)
        or set(scanner) != {"name", "version", "binary_sha256", "config_sha256"}
        or scanner.get("name") != "syft"
        or scanner.get("version") != "1.50.0"
        or not _is_sha256(scanner.get("binary_sha256"))
        or not _is_sha256(scanner.get("config_sha256"))
    ):
        raise SelfTestPackError(f"{label} scanner identity is invalid")


def _normalize_analysis(
    observations: list[object], comparison: object, source_manifest: object
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if not isinstance(observations, list) or len(observations) != len(PROFILE_DOMAINS):
        raise SelfTestPackError("one source, OCI and portable observation is required")
    try:
        expected_comparison = reconcile_profile_observations(observations)
    except (SelfTestError, KeyError, TypeError, ValueError) as exc:
        raise SelfTestPackError(f"profile observations are invalid: {exc}") from exc
    if not isinstance(comparison, dict) or comparison != expected_comparison:
        raise SelfTestPackError("reconciliation is not deterministic from profile observations")
    verified = sorted(
        [dict(item) for item in observations if isinstance(item, dict)],
        key=lambda item: item["profile_kind"].encode("utf-8"),
    )
    if len(verified) != len(observations) or {item["profile_kind"] for item in verified} != set(
        PROFILE_DOMAINS
    ):
        raise SelfTestPackError("profile observations do not preserve the three isolated kinds")
    for item in verified:
        _verify_observation_shape(item)
        _verify_authority(item, f"profile {item.get('profile_id', 'UNKNOWN')}")
    _verify_authority(expected_comparison, "reconciliation")
    if expected_comparison.get("state") != "OPEN":
        raise SelfTestPackError("self-test reconciliation must remain OPEN")
    if expected_comparison.get("population_policy") != "NO_CROSS_PROFILE_COMPONENT_POPULATION":
        raise SelfTestPackError("cross-profile component population is forbidden")

    normalized_manifest = _normalize_source_manifest(source_manifest)
    source_observation = next(
        item for item in verified if item["profile_kind"] == "SOURCE_DIRECTORY"
    )
    input_identity = source_observation.get("input_identity")
    if not isinstance(input_identity, dict) or (
        input_identity.get("root_id") != normalized_manifest["root_id"]
        or input_identity.get("sha256") != normalized_manifest["exact_set_sha256"]
        or input_identity.get("file_count") != normalized_manifest["file_count"]
        or input_identity.get("total_bytes") != normalized_manifest["total_bytes"]
    ):
        raise SelfTestPackError("source observation is not bound to the source exact-set manifest")
    return verified, expected_comparison, normalized_manifest


RAW_FORMATS = ("syft", "cyclonedx", "spdx")


def _raw_relative_path(profile_id: str, fmt: str) -> str:
    if fmt not in RAW_FORMATS:
        raise SelfTestPackError(f"unsupported raw format: {fmt}")
    return f"raw/{profile_id}.{fmt}.json"


def _auxiliary_raw_identity(path: Path) -> dict[str, Any]:
    """Byte identity for syft/spdx raw, which carry no observation projection."""

    if not path.is_file() or path.is_symlink():
        raise SelfTestPackError(f"auxiliary raw evidence is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def _validate_raw_documents(
    observations: list[dict[str, Any]],
    raw_documents: Mapping[str, Mapping[str, Path | str]],
) -> dict[str, dict[str, tuple[Path, dict[str, Any]]]]:
    expected_ids = {item["profile_id"] for item in observations}
    if not isinstance(raw_documents, Mapping) or set(raw_documents) != expected_ids:
        raise SelfTestPackError("raw document profile IDs do not match the observations")
    results: dict[str, dict[str, tuple[Path, dict[str, Any]]]] = {}
    for observation in observations:
        profile_id = observation["profile_id"]
        per_profile = raw_documents[profile_id]
        if not isinstance(per_profile, Mapping) or set(per_profile) != set(RAW_FORMATS):
            raise SelfTestPackError(
                f"profile {profile_id} raw formats do not match {RAW_FORMATS}"
            )
        entry: dict[str, tuple[Path, dict[str, Any]]] = {}
        cyclonedx_path = Path(per_profile["cyclonedx"])
        evidence = observation.get("cyclonedx_evidence")
        expected_sha256 = evidence.get("source_sha256") if isinstance(evidence, dict) else None
        if not _is_sha256(expected_sha256):
            raise SelfTestPackError(f"profile {profile_id} lacks a raw CycloneDX hash")
        try:
            # Re-parse first so malformed references remain explicit findings;
            # the independent byte-identity comparison follows immediately.
            projection, identity = load_cyclonedx(cyclonedx_path)
        except (SelfTestError, OSError, ValueError) as exc:
            raise SelfTestPackError(f"raw CycloneDX validation failed for {profile_id}: {exc}") from exc
        if identity["sha256"] != expected_sha256:
            raise SelfTestPackError(f"raw CycloneDX SHA-256 mismatch for {profile_id}")
        if projection != evidence:
            raise SelfTestPackError(
                f"profile observation does not derive from raw CycloneDX for {profile_id}"
            )
        entry["cyclonedx"] = (cyclonedx_path, identity)
        # Syft and SPDX 2.3 raw carry no observation projection to compare
        # against; record byte identity so the sealed package preserves every
        # native generator format (M3-1) and the manifest binds them on
        # re-verify. CycloneDX remains the strong projection anchor.
        for fmt in ("syft", "spdx"):
            path = Path(per_profile[fmt])
            entry[fmt] = (path, _auxiliary_raw_identity(path))
        results[profile_id] = entry
    return results


def _expected_directories(relative_files: tuple[str, ...]) -> set[str]:
    directories: set[str] = set()
    for relative_path in relative_files:
        for parent in PurePosixPath(relative_path).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
    return directories


def _payload_manifest(
    run_directory: Path, run_id: str, payload_files: tuple[str, ...], *, sealed: bool = False
) -> dict[str, Any]:
    expected_files = set(payload_files)
    if sealed:
        expected_files.update({"MANIFEST.json", "COMPLETE.json", "ite6-statement.json"})
    expected_directories = _expected_directories(tuple(expected_files))
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in run_directory.rglob("*"):
        relative_path = path.relative_to(run_directory).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SelfTestPackError(f"self-test package contains a symlink: {relative_path}")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative_path)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            actual_files.add(relative_path)
        else:
            raise SelfTestPackError(f"self-test package contains an unsafe entry: {relative_path}")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise SelfTestPackError(
            "self-test package recursive exact-set mismatch; "
            f"files={sorted(actual_files)}, directories={sorted(actual_directories)}"
        )
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for relative_path in sorted(payload_files, key=lambda item: item.encode("utf-8")):
        path = run_directory / relative_path
        info = path.lstat()
        entries.append(
            {
                "relative_path": relative_path,
                "sha256": sha256_file(path),
                "size": info.st_size,
                "executable": bool(info.st_mode & stat.S_IXUSR),
            }
        )
        total_bytes += info.st_size
    identity = {"root_id": run_id, "files": entries}
    return {
        "schema_version": SCHEMA_VERSION,
        "root_id": run_id,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": entries,
    }


def _validation(
    observations: list[dict[str, Any]], raw_identities: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    profiles = []
    for observation in observations:
        profile_id = observation["profile_id"]
        evidence = observation["cyclonedx_evidence"]
        profiles.append(
            {
                "profile_id": profile_id,
                "profile_kind": observation["profile_kind"],
                "raw_sha256": raw_identities[profile_id]["sha256"],
                "raw_size": raw_identities[profile_id]["size"],
                "semantic_sha256": evidence["semantic_sha256"],
                "component_count": len(evidence["components"]) + 1,
                "dependency_row_count": len(evidence["dependencies"]),
                "status": "MECHANICALLY_VALID",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "MECHANICALLY_VALID",
        "profiles": sorted(profiles, key=lambda item: item["profile_kind"].encode("utf-8")),
        "reconciliation_status": "OPEN",
        "population_policy": "NO_CROSS_PROFILE_COMPONENT_POPULATION",
        "network_resolution": "NOT_USED_READ_ONLY_REPARSE",
        "boundary": (
            "Raw CycloneDX syntax/reference validation passed. This does not establish component "
            "completeness, profile equivalence, manufacturer approval, release, or conformity."
        ),
    }


def _dashboard(
    observations: list[dict[str, Any]], comparison: dict[str, Any], validation: dict[str, Any]
) -> dict[str, Any]:
    components = [
        {
            "component_id": item["profile_id"],
            "name": item["profile_id"],
            "version": item["subject"]["declared_version"],
            "producer": item["profile_kind"],
            "identifiers": [item["cyclonedx_evidence"]["source_sha256"]],
            "status": "PROFILE_ISOLATED_OPEN",
            "profile_kind": item["profile_kind"],
            "component_count": len(item["cyclonedx_evidence"]["components"]) + 1,
            "observation_run_id": item["run_id"],
        }
        for item in observations
    ]
    conflicts = [
        {
            "conflict_id": finding["finding_id"],
            "field": finding["code"],
            "status": finding["state"],
            "details": [finding["explanation"]],
            "claims": [],
            "evidence_refs": sorted(
                {record["observation_run_id"] for record in finding["evidence"]}
            ),
        }
        for finding in comparison["comparison_findings"]
    ]
    namespace = comparison["comparison_namespace"]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": comparison["run_id"],
        "classification": CLASSIFICATION,
        "release": {
            "release_id": namespace,
            "product": namespace,
            "product_version": "MULTI_PROFILE_OBSERVATION",
            "build_id": comparison["run_id"],
            "status": RELEASE_STATUS,
            "generator_output_status": GENERATOR_STATUS,
            "manufacturer_role": None,
            "product_conformity_status": PRODUCT_STATUS,
        },
        "components": sorted(components, key=lambda item: item["profile_kind"].encode("utf-8")),
        "reconciliation": {
            "status": "SELF_TEST_RECONCILIATION_OPEN",
            "population_policy": comparison["population_policy"],
            "profile_count": len(observations),
            "profiles": [
                {
                    "profile_id": item["profile_id"],
                    "profile_kind": item["profile_kind"],
                    "independence_domain": item["independence_domain"],
                    "blindspots": item["blindspots"],
                }
                for item in observations
            ],
            "conflicts": conflicts,
        },
        "validation": validation,
    }


def _run_record(comparison: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "status": PACKAGE_STATUS,
        "run_id": comparison["run_id"],
        "canonical_reconciliation_sha256": comparison["canonical_sha256"],
        "generator_output_status": GENERATOR_STATUS,
        "release_status": RELEASE_STATUS,
        "product_conformity_status": PRODUCT_STATUS,
        "manufacturer_approval_status": MANUFACTURER_STATUS,
        "milestone_scope": MILESTONE_SCOPE,
        "reconciliation_status": "OPEN",
        "serialization_status": validation["status"],
        "population_policy": comparison["population_policy"],
        "boundary": BOUNDARY,
    }


def _copy_raw(source: Path, destination: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, source_flags)
        source_info = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1:
            os.close(source_descriptor)
            raise SelfTestPackError("raw CycloneDX source is not one safe regular file")
        with os.fdopen(source_descriptor, "rb", closefd=True) as reader, destination.open("xb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    except OSError as exc:
        raise SelfTestPackError("cannot snapshot raw CycloneDX evidence") from exc
    if digest.hexdigest() != expected_sha256:
        raise SelfTestPackError("raw CycloneDX changed while the package was staged")


def write_selftest_package(
    data_root: Path,
    *,
    observations: list[object],
    comparison: object,
    raw_documents: Mapping[str, Mapping[str, Path | str]],
    source_manifest: object,
) -> dict[str, Any]:
    """Seal and register a no-overwrite three-profile self-test package."""

    verified, verified_comparison, normalized_manifest = _normalize_analysis(
        observations, comparison, source_manifest
    )
    raw_sources = _validate_raw_documents(verified, raw_documents)
    run_id = verified_comparison["run_id"]
    data_root = Path(data_root)
    if data_root.is_symlink():
        raise SelfTestPackError("data root must not be a symlink")
    data_root.mkdir(parents=True, exist_ok=True)
    data_root = data_root.resolve(strict=True)
    runs_root = data_root / "runs"
    runs_root.mkdir(exist_ok=True)
    if runs_root.is_symlink():
        raise SelfTestPackError("runs root must not be a symlink")
    destination = runs_root / run_id
    if destination.exists() or destination.is_symlink():
        raise SelfTestPackError(f"self-test package already exists; refusing overwrite: {run_id}")

    stage = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=runs_root))
    moved = False
    try:
        raw_identities: dict[str, dict[str, Any]] = {}
        for observation in verified:
            profile_id = observation["profile_id"]
            sources = raw_sources[profile_id]
            for fmt in RAW_FORMATS:
                source, identity = sources[fmt]
                _copy_raw(source, stage / _raw_relative_path(profile_id, fmt), identity["sha256"])
            raw_identities[profile_id] = sources["cyclonedx"][1]
        validation = _validation(verified, raw_identities)
        dashboard = _dashboard(verified, verified_comparison, validation)
        values = {
            "dashboard.json": dashboard,
            "inputs/source-manifest.json": normalized_manifest,
            "profile-observations.json": {
                "schema_version": SCHEMA_VERSION,
                "classification": CLASSIFICATION,
                "profiles": verified,
            },
            "reconciliation.json": verified_comparison,
            "run.json": _run_record(verified_comparison, validation),
            "validation.json": validation,
        }
        for relative_path in BASE_PAYLOAD_FILES:
            write_json_atomic(stage / relative_path, values[relative_path])
        raw_files = tuple(
            _raw_relative_path(item["profile_id"], fmt)
            for item in sorted(verified, key=lambda item: item["profile_id"].encode("utf-8"))
            for fmt in RAW_FORMATS
        )
        payload_files = (*BASE_PAYLOAD_FILES, *raw_files)
        manifest = _payload_manifest(stage, run_id, payload_files)
        write_json_atomic(stage / "MANIFEST.json", manifest)
        manifest_sha256 = sha256_file(stage / "MANIFEST.json")
        dashboard_sha256 = sha256_file(stage / "dashboard.json")
        # M7-2: in-toto ITE-6 envelope. subject binds the reconciliation
        # canonical hash (logical identity, excludes the physical pack files);
        # predicate records the physical pack hashes (MANIFEST/dashboard). The
        # envelope lives inside the pack but outside MANIFEST.json payload to
        # avoid a hash cycle (ite6 records manifest_sha256; MANIFEST does not
        # record ite6). exact-set admission is via _payload_manifest's sealed
        # set, and COMPLETE.json binds ite6_statement_sha256.
        ite6_statement = wrap_statement(
            predicate_type="sbom-workbench.selftest-pack/v1",
            subject_name="canonical-reconciliation",
            subject_sha256=verified_comparison["canonical_sha256"],
            predicate={
                "run_id": run_id,
                "manifest_sha256": manifest_sha256,
                "dashboard_sha256": dashboard_sha256,
                "classification": CLASSIFICATION,
                "boundary": BOUNDARY,
            },
        )
        write_json_atomic(stage / "ite6-statement.json", ite6_statement)
        complete = {
            "schema_version": SCHEMA_VERSION,
            "classification": CLASSIFICATION,
            "status": PACKAGE_STATUS,
            "run_id": run_id,
            "canonical_reconciliation_sha256": verified_comparison["canonical_sha256"],
            "dashboard_sha256": dashboard_sha256,
            "manifest_relative_path": "MANIFEST.json",
            "manifest_sha256": manifest_sha256,
            "ite6_statement_sha256": sha256_file(stage / "ite6-statement.json"),
            "boundary": BOUNDARY,
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        try:
            _publish_registered_stage(
                data_root,
                verified_comparison,
                dashboard_sha256,
                stage,
                destination,
            )
        except PackError as exc:
            raise SelfTestPackError(f"cannot publish self-test package: {exc}") from exc
        moved = True
        return verify_selftest_package(destination)
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)


def verify_selftest_package(run_directory: Path) -> dict[str, Any]:
    """Read-only verification of one sealed M4A self-test package."""

    run_directory = Path(run_directory)
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise SelfTestPackError("self-test run directory must be a non-symlink directory")
    complete = _strict_json(run_directory / "COMPLETE.json", "COMPLETE.json", maximum=1024**2)
    expected_complete_keys = {
        "schema_version",
        "classification",
        "status",
        "run_id",
        "canonical_reconciliation_sha256",
        "dashboard_sha256",
        "manifest_relative_path",
        "manifest_sha256",
        "ite6_statement_sha256",
        "boundary",
    }
    if not isinstance(complete, dict) or set(complete) != expected_complete_keys:
        raise SelfTestPackError("COMPLETE.json fields do not match")
    if (
        complete.get("schema_version") != SCHEMA_VERSION
        or complete.get("classification") != CLASSIFICATION
        or complete.get("status") != PACKAGE_STATUS
        or complete.get("manifest_relative_path") != "MANIFEST.json"
        or complete.get("boundary") != BOUNDARY
        or not _is_sha256(complete.get("dashboard_sha256"))
        or not _is_sha256(complete.get("manifest_sha256"))
        or not _is_sha256(complete.get("ite6_statement_sha256"))
    ):
        raise SelfTestPackError("COMPLETE.json changed the fixed self-test boundary")
    if complete["manifest_sha256"] != sha256_file(run_directory / "MANIFEST.json"):
        raise SelfTestPackError("COMPLETE.json does not bind MANIFEST.json")
    # M7-2: verify the in-toto envelope that wraps this sealed pack.
    ite6_statement = _strict_json(
        run_directory / "ite6-statement.json", "ite6-statement.json"
    )
    try:
        validate_statement(ite6_statement)
    except InTotoError as exc:
        raise SelfTestPackError(f"ite6 statement is malformed: {exc}") from exc
    if ite6_statement["predicateType"] != "sbom-workbench.selftest-pack/v1":
        raise SelfTestPackError("ite6 statement predicateType is not the selftest-pack kind")
    if ite6_statement["subject"][0]["name"] != "canonical-reconciliation":
        raise SelfTestPackError(
            "ite6 statement subject name is not the canonical-reconciliation kind"
        )
    if (
        ite6_statement["subject"][0]["digest"]["sha256"]
        != complete["canonical_reconciliation_sha256"]
    ):
        raise SelfTestPackError(
            "ite6 statement subject does not bind the reconciliation canonical hash"
        )
    # M7-2 (review-hardened): every predicate field written by write_selftest_package
    # is verified here — an attacker who rewrites ite6 + COMPLETE.json to rebind the
    # statement sha256 must still match every predicate binding or verify fails closed.
    predicate = ite6_statement["predicate"]
    if predicate["manifest_sha256"] != complete["manifest_sha256"]:
        raise SelfTestPackError("ite6 statement predicate does not bind MANIFEST.json")
    if predicate["dashboard_sha256"] != complete["dashboard_sha256"]:
        raise SelfTestPackError("ite6 statement predicate does not bind dashboard.json")
    if predicate["run_id"] != complete["run_id"]:
        raise SelfTestPackError("ite6 statement predicate does not bind run_id")
    if predicate["classification"] != CLASSIFICATION:
        raise SelfTestPackError("ite6 statement predicate classification mismatch")
    if predicate["boundary"] != BOUNDARY:
        raise SelfTestPackError("ite6 statement predicate boundary mismatch")
    if complete["ite6_statement_sha256"] != sha256_file(
        run_directory / "ite6-statement.json"
    ):
        raise SelfTestPackError("COMPLETE.json does not bind ite6-statement.json")

    profiles_wrapper = _strict_json(
        run_directory / "profile-observations.json", "profile-observations.json"
    )
    if (
        not isinstance(profiles_wrapper, dict)
        or set(profiles_wrapper) != {"schema_version", "classification", "profiles"}
        or profiles_wrapper.get("schema_version") != SCHEMA_VERSION
        or profiles_wrapper.get("classification") != CLASSIFICATION
        or not isinstance(profiles_wrapper.get("profiles"), list)
    ):
        raise SelfTestPackError("profile-observations.json fields do not match")
    observations = profiles_wrapper["profiles"]
    comparison = _strict_json(run_directory / "reconciliation.json", "reconciliation.json")
    source_manifest = _strict_json(
        run_directory / "inputs/source-manifest.json", "inputs/source-manifest.json"
    )
    verified, expected_comparison, normalized_manifest = _normalize_analysis(
        observations, comparison, source_manifest
    )
    if complete["run_id"] != expected_comparison["run_id"] or (
        complete["canonical_reconciliation_sha256"]
        != expected_comparison["canonical_sha256"]
    ):
        raise SelfTestPackError("COMPLETE.json does not bind the reconciliation")
    raw_files = tuple(
        _raw_relative_path(item["profile_id"], fmt)
        for item in sorted(verified, key=lambda item: item["profile_id"].encode("utf-8"))
        for fmt in RAW_FORMATS
    )
    payload_files = (*BASE_PAYLOAD_FILES, *raw_files)
    manifest = _strict_json(run_directory / "MANIFEST.json", "MANIFEST.json", maximum=8 * 1024**2)
    observed_manifest = _payload_manifest(
        run_directory, expected_comparison["run_id"], payload_files, sealed=True
    )
    if manifest != observed_manifest:
        raise SelfTestPackError("self-test payload no longer matches MANIFEST.json")

    raw_documents = {
        item["profile_id"]: {
            fmt: run_directory / _raw_relative_path(item["profile_id"], fmt)
            for fmt in RAW_FORMATS
        }
        for item in verified
    }
    raw_sources = _validate_raw_documents(verified, raw_documents)
    raw_identities = {
        profile_id: sources["cyclonedx"][1] for profile_id, sources in raw_sources.items()
    }
    expected_validation = _validation(verified, raw_identities)
    if _strict_json(run_directory / "validation.json", "validation.json") != expected_validation:
        raise SelfTestPackError("validation projection does not match raw evidence")
    expected_dashboard = _dashboard(verified, expected_comparison, expected_validation)
    if _strict_json(run_directory / "dashboard.json", "dashboard.json") != expected_dashboard:
        raise SelfTestPackError("dashboard projection does not match the isolated profiles")
    if complete["dashboard_sha256"] != sha256_file(run_directory / "dashboard.json"):
        raise SelfTestPackError("COMPLETE.json does not bind dashboard.json")
    expected_run = _run_record(expected_comparison, expected_validation)
    if _strict_json(run_directory / "run.json", "run.json") != expected_run:
        raise SelfTestPackError("run projection changed its fixed authority boundary")
    if normalized_manifest != source_manifest:
        raise SelfTestPackError("source manifest serialization is not canonical")
    return {
        "status": PACKAGE_STATUS,
        "classification": CLASSIFICATION,
        "run_id": expected_comparison["run_id"],
        "canonical_reconciliation_sha256": expected_comparison["canonical_sha256"],
        "dashboard_sha256": complete["dashboard_sha256"],
        "manifest_sha256": complete["manifest_sha256"],
        "exact_set_sha256": manifest["exact_set_sha256"],
        "file_count": len(payload_files) + 3,
        "profile_count": len(verified),
        "validation_status": expected_validation["status"],
        "reconciliation_status": "OPEN",
        "product_conformity_status": PRODUCT_STATUS,
        "boundary": BOUNDARY,
    }
