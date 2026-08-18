"""Read-only verification of a complete M3A scan root and its M4A pack."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from .manifest import build_exact_set_manifest, sha256_file
from .selftest import CLASSIFICATION, SelfTestError, load_cyclonedx
from .selftest_pack import SelfTestPackError, verify_selftest_package


class SelfTestRootError(ValueError):
    """Raised when raw scan evidence or its completion binding has drifted."""


PROFILE_IDS = (
    "m3a-source-directory",
    "m3a-oci-archive",
    "m3a-portable-runtime",
)
PROFILE_KINDS = {
    "m3a-source-directory": "SOURCE_DIRECTORY",
    "m3a-oci-archive": "OCI_ARCHIVE",
    "m3a-portable-runtime": "PORTABLE_RUNTIME",
}
SCANNER_IDENTITY = {
    "name": "syft",
    "version": "1.50.0",
    "binary_sha256": "5d59c9e6fa641793ddb48bc90b5b7ad63bf7303a52835b75b1beee3757463998",
    "config_sha256": "9aee3e875e9cafcb974a70517a522059598073e0f809dcd2dd9fab9bbb5eb5a5",
}
ACQUISITION_IDENTITY = {
    "binary_sha256": SCANNER_IDENTITY["binary_sha256"],
    "config_sha256": SCANNER_IDENTITY["config_sha256"],
    "acquisition_receipt_sha256": "66714f0dc084a4d7777ad2558d17001bd984e08a64ea7f773cd7959dacd91892",
    "runtime_registry_sha256": "0050130f5d039a5ac27509b9e883bc3cf11eed98d5290410f63f6d1a7c31baad",
    "resolved_commit": "16223e6dd7893fe578787658ceb876257483d404",
}
STATUS = "M3A_SCAN_AND_M4A_PACKAGE_COMPLETE_OPEN_CANDIDATE"
BOUNDARY = (
    "Three isolated, network-denied generator observations were compared without forming a "
    "component-population union. sandbox-exec denies network access but does not isolate "
    "host-file reads; only the pinned scanner and explicit trusted snapshots are in scope. "
    "Privacy remains HOLD. Output is not customer evidence, release, PRE-7/CRA conformity, "
    "or certification."
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _reject_constant(value: str) -> None:
    raise SelfTestRootError(f"non-standard JSON constant is forbidden: {value}")


def _strict_json(path: Path, label: str, *, maximum: int = 256 * 1024 * 1024) -> Any:
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise SelfTestRootError(f"{label} is unavailable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > maximum
    ):
        raise SelfTestRootError(f"{label} must be one bounded single-link regular file")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SelfTestRootError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=_reject_constant,
        )
    except SelfTestRootError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SelfTestRootError(f"{label} is not strict UTF-8 JSON") from exc


def _safe_root(path: Path) -> Path:
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise SelfTestRootError("self-test output root must be a non-symlink directory")
    root = root.resolve(strict=True)
    expected = {"SELFTEST_COMPLETE.json", "scan-receipt.json", "raw", "runtime", "data"}
    if {item.name for item in root.iterdir()} != expected:
        raise SelfTestRootError("self-test output root exact-set mismatch")
    for name in ("raw", "runtime", "data"):
        child = root / name
        if child.is_symlink() or not child.is_dir():
            raise SelfTestRootError(f"self-test {name} directory is unsafe")
    return root


def _verify_raw_profile(root: Path, record: object) -> None:
    if not isinstance(record, dict) or set(record) != {
        "profile_id",
        "profile_kind",
        "network_policy",
        "raw_exact_set",
    }:
        raise SelfTestRootError("raw scan record fields do not match")
    profile_id = record.get("profile_id")
    if profile_id not in PROFILE_KINDS or record.get("profile_kind") != PROFILE_KINDS[profile_id]:
        raise SelfTestRootError("raw scan profile identity is invalid")
    if record.get("network_policy") != "MACOS_SANDBOX_EXEC_DENY_NETWORK":
        raise SelfTestRootError("raw scan network policy was weakened")
    raw_root = root / "raw" / profile_id
    if raw_root.is_symlink() or not raw_root.is_dir():
        raise SelfTestRootError(f"raw profile directory is unsafe: {profile_id}")
    expected_names = {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"}
    if {item.name for item in raw_root.iterdir()} != expected_names:
        raise SelfTestRootError(f"raw profile exact-set mismatch: {profile_id}")
    observed = build_exact_set_manifest(raw_root, f"{profile_id}-raw")
    if observed != record.get("raw_exact_set"):
        raise SelfTestRootError(f"raw profile manifest mismatch: {profile_id}")

    syft = _strict_json(raw_root / "raw.syft.json", f"{profile_id} Syft JSON")
    if (
        not isinstance(syft, dict)
        or not isinstance(syft.get("artifacts"), list)
        or not isinstance(syft.get("artifactRelationships"), list)
        or not isinstance(syft.get("descriptor"), dict)
        or syft["descriptor"].get("name") != "syft"
        or syft["descriptor"].get("version") != "1.50.0"
    ):
        raise SelfTestRootError(f"{profile_id} Syft JSON profile is invalid")
    try:
        load_cyclonedx(raw_root / "raw.cyclonedx.json")
    except (SelfTestError, OSError) as exc:
        raise SelfTestRootError(f"{profile_id} CycloneDX validation failed: {exc}") from exc
    spdx = _strict_json(raw_root / "raw.spdx.json", f"{profile_id} SPDX JSON")
    if (
        not isinstance(spdx, dict)
        or spdx.get("spdxVersion") != "SPDX-2.3"
        or spdx.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(spdx.get("documentNamespace"), str)
        or not spdx["documentNamespace"]
        or not isinstance(spdx.get("packages"), list)
    ):
        raise SelfTestRootError(f"{profile_id} SPDX 2.3 generator profile is invalid")


def _verify_raw_tree(root: Path) -> None:
    raw = root / "raw"
    entries: dict[str, Path] = {item.name: item for item in raw.iterdir()}
    if set(entries) != set(PROFILE_IDS):
        raise SelfTestRootError("raw profile directory exact-set mismatch")
    for profile_id, path in entries.items():
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise SelfTestRootError(f"raw profile directory is unsafe: {profile_id}")


def _verify_data_tree(
    root: Path,
    *,
    run_id: str,
    dashboard_sha256: str,
) -> Path:
    data = root / "data"
    entries: dict[str, Path] = {item.name: item for item in data.iterdir()}
    if set(entries) != {".runs.lock", "runs.json", "runs"}:
        raise SelfTestRootError("self-test data top-level exact-set mismatch")
    lock_info = entries[".runs.lock"].lstat()
    if (
        entries[".runs.lock"].is_symlink()
        or not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_nlink != 1
        or lock_info.st_size != 0
    ):
        raise SelfTestRootError("self-test data lock file is unsafe")
    runs = entries["runs"]
    if runs.is_symlink() or not runs.is_dir():
        raise SelfTestRootError("self-test runs directory is unsafe")
    run_entries: dict[str, Path] = {item.name: item for item in runs.iterdir()}
    if set(run_entries) != {run_id}:
        raise SelfTestRootError("self-test run directory exact-set mismatch")
    run_directory = run_entries[run_id]
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise SelfTestRootError("bound self-test run directory is unsafe")

    registry = _strict_json(entries["runs.json"], "self-test run registry")
    expected_registry = {
        "schema_version": "1.0",
        "runs": [
            {
                "run_id": run_id,
                "relative_path": f"runs/{run_id}",
                "dashboard_sha256": dashboard_sha256,
            }
        ],
    }
    if registry != expected_registry:
        raise SelfTestRootError("self-test run registry binding is invalid")
    return run_directory


def _verify_package_cross_bindings(
    run_directory: Path,
    receipt: dict[str, Any],
) -> None:
    wrapper = _strict_json(
        run_directory / "profile-observations.json",
        "sealed M4A profile observations",
    )
    if (
        not isinstance(wrapper, dict)
        or set(wrapper) != {"schema_version", "classification", "profiles"}
        or wrapper.get("schema_version") != "1.0"
        or wrapper.get("classification") != CLASSIFICATION
        or not isinstance(wrapper.get("profiles"), list)
    ):
        raise SelfTestRootError("sealed profile observation wrapper is invalid")
    profiles = wrapper["profiles"]
    profile_map = {
        item.get("profile_id"): item for item in profiles if isinstance(item, dict)
    }
    if len(profiles) != len(PROFILE_IDS) or set(profile_map) != set(PROFILE_IDS):
        raise SelfTestRootError("sealed profile observation set is invalid")
    receipt_bindings = {
        "m3a-source-directory": "source_input_identity",
        "m3a-oci-archive": "oci_input_identity",
        "m3a-portable-runtime": "portable_input_identity",
    }
    for profile_id, receipt_key in receipt_bindings.items():
        observation = profile_map[profile_id]
        if observation.get("scanner_identity") != SCANNER_IDENTITY:
            raise SelfTestRootError(
                f"sealed profile scanner identity mismatch: {profile_id}"
            )
        if receipt.get(receipt_key) != observation.get("input_identity"):
            raise SelfTestRootError(
                f"scan receipt input identity does not match sealed profile: {profile_id}"
            )


def _verify_runtime_tree(root: Path) -> None:
    runtime = root / "runtime"
    expected_directories = {
        "pinned-scanner",
        "version-runtime",
        "version-runtime/cache",
        "version-runtime/config",
        "version-runtime/tmp",
        *PROFILE_IDS,
        *{
            f"{profile_id}/{leaf}"
            for profile_id in PROFILE_IDS
            for leaf in ("cache", "config", "tmp")
        },
    }
    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    for path in runtime.rglob("*"):
        relative = path.relative_to(runtime).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SelfTestRootError(f"runtime evidence contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            actual_files.add(relative)
        else:
            raise SelfTestRootError(f"runtime evidence contains an unsafe entry: {relative}")
    if actual_directories != expected_directories or actual_files != {
        "pinned-scanner/syft",
        "pinned-scanner/syft-m3a.yaml",
    }:
        raise SelfTestRootError("runtime evidence recursive exact-set mismatch")
    if (
        sha256_file(runtime / "pinned-scanner" / "syft")
        != SCANNER_IDENTITY["binary_sha256"]
        or sha256_file(runtime / "pinned-scanner" / "syft-m3a.yaml")
        != SCANNER_IDENTITY["config_sha256"]
    ):
        raise SelfTestRootError("pinned scanner runtime hash mismatch")


def verify_selftest_root(output_root: Path) -> dict[str, Any]:
    """Recheck all 3x3 raw outputs, their receipt, and the sealed M4A pack."""

    root = _safe_root(output_root)
    receipt = _strict_json(root / "scan-receipt.json", "scan receipt", maximum=64 * 1024 * 1024)
    receipt_keys = {
        "schema_version",
        "classification",
        "status",
        "scanner_identity",
        "scanner_acquisition_identity",
        "source_input_identity",
        "oci_input_identity",
        "portable_input_identity",
        "scans",
        "package",
        "boundary",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != receipt_keys
        or receipt.get("schema_version") != "1.0"
        or receipt.get("classification") != CLASSIFICATION
        or receipt.get("status") != STATUS
        or receipt.get("scanner_identity") != SCANNER_IDENTITY
        or receipt.get("scanner_acquisition_identity") != ACQUISITION_IDENTITY
        or receipt.get("boundary") != BOUNDARY
    ):
        raise SelfTestRootError("scan receipt identity or authority boundary is invalid")
    scans = receipt.get("scans")
    if not isinstance(scans, list) or len(scans) != len(PROFILE_IDS):
        raise SelfTestRootError("scan receipt does not contain exactly three profiles")
    if {item.get("profile_id") for item in scans if isinstance(item, dict)} != set(PROFILE_IDS):
        raise SelfTestRootError("scan receipt profile set is invalid")
    _verify_raw_tree(root)
    for record in scans:
        _verify_raw_profile(root, record)
    _verify_runtime_tree(root)

    package_record = receipt.get("package")
    if not isinstance(package_record, dict) or not isinstance(package_record.get("run_id"), str):
        raise SelfTestRootError("scan receipt package binding is invalid")
    package_run_id = package_record["run_id"]
    package_dashboard_sha256 = package_record.get("dashboard_sha256")
    if (
        not isinstance(package_dashboard_sha256, str)
        or not _SHA256_RE.fullmatch(package_dashboard_sha256)
    ):
        raise SelfTestRootError("scan receipt dashboard binding is invalid")
    run_directory = _verify_data_tree(
        root,
        run_id=package_run_id,
        dashboard_sha256=package_dashboard_sha256,
    )
    try:
        verified_package = verify_selftest_package(run_directory)
    except (SelfTestPackError, OSError) as exc:
        raise SelfTestRootError(f"sealed M4A package verification failed: {exc}") from exc
    if package_record != verified_package:
        raise SelfTestRootError("scan receipt package record does not rederive from the M4A pack")
    _verify_package_cross_bindings(run_directory, receipt)

    complete = _strict_json(root / "SELFTEST_COMPLETE.json", "self-test completion")
    if (
        not isinstance(complete, dict)
        or set(complete)
        != {
            "schema_version",
            "classification",
            "status",
            "run_id",
            "scan_receipt_sha256",
            "package_manifest_sha256",
            "reconciliation_status",
        }
        or complete.get("schema_version") != "1.0"
        or complete.get("classification") != CLASSIFICATION
        or complete.get("status") != STATUS
        or complete.get("run_id") != verified_package["run_id"]
        or complete.get("scan_receipt_sha256") != sha256_file(root / "scan-receipt.json")
        or complete.get("package_manifest_sha256") != verified_package["manifest_sha256"]
        or complete.get("reconciliation_status") != "OPEN"
    ):
        raise SelfTestRootError("self-test completion binding is invalid")
    return {
        "status": "M3A_ROOT_AND_M4A_PACK_VERIFIED_OPEN_CANDIDATE",
        "classification": CLASSIFICATION,
        "run_id": verified_package["run_id"],
        "raw_profile_count": 3,
        "raw_format_count": 9,
        "m4_package_status": verified_package["status"],
        "reconciliation_status": "OPEN",
        "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
        "selftest_completion_sha256": sha256_file(root / "SELFTEST_COMPLETE.json"),
        "scan_receipt_sha256": sha256_file(root / "scan-receipt.json"),
        "external_anchor_status": "SELF_CONSISTENCY_ONLY_UNTIL_HASH_RECORDED_OUT_OF_BAND",
        "boundary": (
            "Raw-generator and package mechanics verified only; no component completeness, "
            "customer evidence, manufacturer approval, release, PRE-7/CRA conformity or certification."
        ),
    }
