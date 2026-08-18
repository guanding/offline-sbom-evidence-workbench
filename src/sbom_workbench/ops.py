"""Recovery-friendly operations for self-test evidence only."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from .manifest import build_exact_set_manifest, sha256_file, write_json_atomic


CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
CLEAR_MARKER = ".ALLOW_SELFTEST_CLEAR"
CLEAR_MARKER_VALUE = "SELF_TEST_CLEAR_SANDBOX_V1\n"
CLEAR_QUARANTINE = ".selftest-clear-quarantine"


class OperationsError(ValueError):
    """Raised when backup, restore, or clear safety evidence is invalid."""


def _strict_json(path: Path, label: str, *, maximum: int = 8 * 1024 * 1024) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise OperationsError(f"{label} must not be a symlink")
    try:
        info = candidate.stat()
    except OSError as exc:
        raise OperationsError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise OperationsError(f"{label} must be one bounded regular file")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OperationsError(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise OperationsError(f"{label} contains forbidden non-standard JSON constant: {value}")

    try:
        value = json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except OperationsError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperationsError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise OperationsError(f"{label} must be an object")
    return value


def _copy_exact_tree(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_directory = destination / relative
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink():
                raise OperationsError(f"source contains symlink directory: {(relative / name).as_posix()}")
            (target_directory / name).mkdir(mode=0o700)
        for name in files:
            candidate = current_path / name
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OperationsError(f"source contains unsafe file: {(relative / name).as_posix()}")
            target = target_directory / name
            with candidate.open("rb") as input_handle, target.open("xb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            os.chmod(target, stat.S_IMODE(info.st_mode) & 0o700)


def create_selftest_backup(source_root: Path, backup_path: Path, *, root_id: str) -> dict[str, Any]:
    if not isinstance(root_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255}", root_id):
        raise OperationsError("backup root_id is invalid")
    source = Path(source_root)
    if source.is_symlink() or not source.is_dir():
        raise OperationsError("backup source must be a non-symlink directory")
    source = source.resolve(strict=True)
    manifest = build_exact_set_manifest(source, root_id)
    destination = Path(backup_path)
    if destination.exists() or destination.is_symlink():
        raise OperationsError("backup destination exists; refusing overwrite")
    parent = destination.parent
    if parent.is_symlink():
        raise OperationsError("backup parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    parent = parent.resolve(strict=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    moved = False
    try:
        payload = stage / "payload"
        _copy_exact_tree(source, payload)
        copied_manifest = build_exact_set_manifest(payload, root_id)
        if copied_manifest != manifest:
            raise OperationsError("backup payload changed during copy")
        write_json_atomic(stage / "BACKUP_MANIFEST.json", manifest)
        complete = {
            "schema_version": "1.0",
            "classification": CLASSIFICATION,
            "status": "SELFTEST_BACKUP_COMPLETE",
            "root_id": root_id,
            "exact_set_sha256": manifest["exact_set_sha256"],
            "manifest_sha256": sha256_file(stage / "BACKUP_MANIFEST.json"),
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        os.replace(stage, destination)
        moved = True
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)
    validation = validate_selftest_backup(destination)
    return {
        **validation,
        "status": "SELFTEST_BACKUP_CREATED_EXTERNAL_ANCHOR_REQUIRED",
        "manifest_sha256": sha256_file(destination / "BACKUP_MANIFEST.json"),
        "external_anchor_instruction": (
            "Record manifest_sha256 outside this backup before validation or restore."
        ),
    }


def validate_selftest_backup(
    backup_path: Path,
    *,
    trusted_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    root = Path(backup_path)
    if root.is_symlink() or not root.is_dir():
        raise OperationsError("backup root is invalid")
    actual = {path.name for path in root.iterdir()}
    if actual != {"payload", "BACKUP_MANIFEST.json", "COMPLETE.json"}:
        raise OperationsError("backup top-level exact-set mismatch")
    if (root / "payload").is_symlink() or not (root / "payload").is_dir():
        raise OperationsError("backup payload is invalid")
    manifest = _strict_json(root / "BACKUP_MANIFEST.json", "backup manifest")
    complete = _strict_json(root / "COMPLETE.json", "backup completion")
    manifest_sha256 = sha256_file(root / "BACKUP_MANIFEST.json")
    if trusted_manifest_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", trusted_manifest_sha256):
            raise OperationsError("trusted backup manifest SHA-256 is invalid")
        if manifest_sha256 != trusted_manifest_sha256:
            raise OperationsError("backup manifest does not match the external trust anchor")
    root_id = manifest.get("root_id")
    if not isinstance(root_id, str):
        raise OperationsError("backup root identity is invalid")
    observed = build_exact_set_manifest(root / "payload", root_id)
    if observed != manifest:
        raise OperationsError("backup payload does not match its exact-set manifest")
    if (
        set(complete)
        != {
            "schema_version",
            "classification",
            "status",
            "root_id",
            "exact_set_sha256",
            "manifest_sha256",
        }
        or complete.get("schema_version") != "1.0"
        or complete.get("classification") != CLASSIFICATION
        or complete.get("status") != "SELFTEST_BACKUP_COMPLETE"
        or complete.get("root_id") != root_id
        or complete.get("exact_set_sha256") != manifest.get("exact_set_sha256")
        or complete.get("manifest_sha256") != manifest_sha256
    ):
        raise OperationsError("backup completion binding is invalid")
    return {
        "status": (
            "VALIDATED_SELFTEST_BACKUP_WITH_EXTERNAL_ANCHOR"
            if trusted_manifest_sha256 is not None
            else "SELF_CONSISTENCY_ONLY_NOT_EXTERNALLY_ANCHORED"
        ),
        "root_id": root_id,
        "exact_set_sha256": manifest["exact_set_sha256"],
        "manifest_sha256": manifest_sha256,
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
    }


def restore_selftest_backup(
    backup_path: Path,
    destination_path: Path,
    *,
    trusted_manifest_sha256: str,
) -> dict[str, Any]:
    validation = validate_selftest_backup(
        backup_path,
        trusted_manifest_sha256=trusted_manifest_sha256,
    )
    backup = Path(backup_path).resolve(strict=True)
    destination = Path(destination_path)
    if destination.exists() or destination.is_symlink():
        raise OperationsError("restore destination exists; refusing overwrite")
    parent = destination.parent
    if parent.is_symlink():
        raise OperationsError("restore parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    parent = parent.resolve(strict=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    stage.rmdir()
    moved = False
    try:
        _copy_exact_tree(backup / "payload", stage)
        restored = build_exact_set_manifest(stage, validation["root_id"])
        if restored["exact_set_sha256"] != validation["exact_set_sha256"]:
            raise OperationsError("restored payload does not match backup exact-set")
        os.replace(stage, destination)
        moved = True
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)
    return {
        "status": "SELFTEST_RESTORE_VERIFIED",
        "root_id": validation["root_id"],
        "exact_set_sha256": validation["exact_set_sha256"],
        "manifest_sha256": validation["manifest_sha256"],
        "backup_validation_status": validation["status"],
        "destination": str(destination.resolve(strict=True)),
    }


def clear_selftest_sandbox_run(
    run_path: Path,
    *,
    allowed_parent: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    """Remove one validated run from service into recoverable quarantine.

    This is intentionally unsuitable for customer volumes.  The caller must
    create a dedicated sandbox marker and keep the receipt outside the target.
    The verified run is atomically renamed, re-verified under its new name, and
    retained.  This avoids an irreversible delete/receipt failure window and
    prevents a path-swapped replacement from being deleted.
    """

    parent = Path(allowed_parent)
    if parent.is_symlink() or not parent.is_dir():
        raise OperationsError("clear sandbox is invalid")
    parent = parent.resolve(strict=True)
    marker = parent / CLEAR_MARKER
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="utf-8") != CLEAR_MARKER_VALUE:
        raise OperationsError("clear sandbox marker is missing or invalid")
    run = Path(run_path)
    if run.is_symlink() or not run.is_dir():
        raise OperationsError("clear target must be a non-symlink directory")
    run = run.resolve(strict=True)
    if run.parent != parent or run == parent:
        raise OperationsError("clear target must be one direct sandbox child")
    run_record = _strict_json(run / "run.json", "self-test run record")
    _strict_json(run / "COMPLETE.json", "self-test completion")
    if run_record.get("classification") != CLASSIFICATION:
        raise OperationsError("clear target is not classified as self-test data")
    root_id = run_record.get("run_id")
    if not isinstance(root_id, str) or root_id != run.name:
        raise OperationsError("self-test run identity is invalid")
    manifest = build_exact_set_manifest(run, root_id)
    receipt = Path(receipt_path)
    if receipt.exists() or receipt.is_symlink():
        raise OperationsError("clear receipt exists; refusing overwrite")
    receipt_resolved = receipt.resolve(strict=False)
    try:
        receipt_resolved.relative_to(parent)
    except ValueError:
        pass
    else:
        raise OperationsError("clear receipt must be outside the entire allowed sandbox")
    quarantine_root = parent / CLEAR_QUARANTINE
    if quarantine_root.is_symlink():
        raise OperationsError("self-test clear quarantine must not be a symlink")
    quarantine_root.mkdir(mode=0o700, exist_ok=True)
    quarantine = quarantine_root / f"{root_id}-{manifest['exact_set_sha256']}"
    if quarantine.exists() or quarantine.is_symlink():
        raise OperationsError("self-test clear quarantine destination already exists")
    try:
        os.rename(run, quarantine)
    except OSError as exc:
        raise OperationsError("cannot atomically quarantine the self-test run") from exc
    try:
        quarantined_manifest = build_exact_set_manifest(quarantine, root_id)
        if quarantined_manifest != manifest:
            raise OperationsError("quarantined target does not match the verified self-test run")
        if run.exists() or run.is_symlink():
            raise OperationsError("self-test run path was replaced during clear")
        cleared = {
            "schema_version": "1.0",
            "classification": CLASSIFICATION,
            "status": "SELFTEST_DIRECTORY_QUARANTINED_RECOVERABLE_NOT_ERASED",
            "run_id": root_id,
            "cleared_exact_set_sha256": manifest["exact_set_sha256"],
            "cleared_file_count": manifest["file_count"],
            "cleared_total_bytes": manifest["total_bytes"],
            "target_absent": True,
            "recoverable_quarantine_path": str(quarantine),
            "customer_volume_erasure": "NOT_ASSESSED",
            "model_cache_erasure": "NOT_ASSESSED",
        }
        write_json_atomic(receipt, cleared)
        if build_exact_set_manifest(quarantine, root_id) != manifest:
            raise OperationsError("quarantine changed while writing the external clear receipt")
    except Exception:
        # Quarantine is recoverable.  If the active name is still free, restore
        # the original path before surfacing the failed clear transaction.
        if quarantine.exists() and not run.exists() and not run.is_symlink():
            try:
                os.rename(quarantine, run)
            except OSError:
                pass
        if receipt.exists() and receipt.is_file() and not receipt.is_symlink():
            try:
                receipt.unlink()
            except OSError:
                pass
        raise
    return cleared
