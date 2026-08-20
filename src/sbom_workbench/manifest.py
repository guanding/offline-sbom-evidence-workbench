"""Deterministic exact-set manifests for evidence roots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised when a tree contains unsafe or unsupported entries."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def build_exact_set_manifest(root: Path, root_id: str) -> dict[str, Any]:
    if root.is_symlink():
        raise ManifestError("manifest root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ManifestError("manifest root must be a directory")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    def fail_on_walk_error(error: OSError) -> None:
        raise ManifestError(f"cannot enumerate evidence root: {error}") from error

    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=fail_on_walk_error
    ):
        current_path = Path(current)
        for directory in list(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                raise ManifestError(f"symlink directory is forbidden: {candidate.relative_to(root)}")
        for filename in files:
            candidate = current_path / filename
            relative = candidate.relative_to(root).as_posix()
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ManifestError(f"non-regular file is forbidden: {relative}")
            if info.st_nlink != 1:
                raise ManifestError(f"hard-linked file is forbidden: {relative}")
            size = info.st_size
            total_bytes += size
            entries.append(
                {
                    "relative_path": relative,
                    "sha256": sha256_file(candidate),
                    "size": size,
                    "executable": bool(info.st_mode & stat.S_IXUSR),
                }
            )
    entries.sort(key=lambda item: item["relative_path"].encode("utf-8"))
    identity = {"root_id": root_id, "files": entries}
    return {
        "schema_version": "1.0",
        "root_id": root_id,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": entries,
    }


def build_bounded_exact_set_manifest(
    root: Path,
    root_id: str,
    *,
    max_files: int,
    max_total_bytes: int,
    max_single_file_bytes: int,
    max_depth: int,
) -> dict[str, Any]:
    """Build an exact-set while enforcing source-tree resource budgets.

    The limits are checked before each file is hashed.  This prevents an
    untrusted repository from turning a source-only scan into an unbounded
    filesystem walk or byte-read operation.  The resulting manifest is byte
    compatible with :func:`build_exact_set_manifest` when the tree is within
    budget.
    """

    limits = {
        "max_files": max_files,
        "max_total_bytes": max_total_bytes,
        "max_single_file_bytes": max_single_file_bytes,
        "max_depth": max_depth,
    }
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise ManifestError("source manifest resource budgets must be positive integers")
    if max_single_file_bytes > max_total_bytes:
        raise ManifestError("single-file budget must not exceed total-byte budget")
    if root.is_symlink():
        raise ManifestError("manifest root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ManifestError("manifest root must be a directory")

    entries: list[dict[str, Any]] = []
    total_bytes = 0

    def fail_on_walk_error(error: OSError) -> None:
        raise ManifestError(f"cannot enumerate evidence root: {error}") from error

    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=fail_on_walk_error
    ):
        current_path = Path(current)
        relative_directory = current_path.relative_to(root)
        directory_depth = 0 if relative_directory == Path(".") else len(relative_directory.parts)
        if directory_depth > max_depth:
            raise ManifestError("source tree exceeds max_depth resource budget")
        for directory in list(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                raise ManifestError(f"symlink directory is forbidden: {candidate.relative_to(root)}")
        for filename in files:
            candidate = current_path / filename
            relative = candidate.relative_to(root)
            if len(relative.parts) > max_depth:
                raise ManifestError("source tree exceeds max_depth resource budget")
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ManifestError(f"non-regular file is forbidden: {relative.as_posix()}")
            if info.st_nlink != 1:
                raise ManifestError(f"hard-linked file is forbidden: {relative.as_posix()}")
            size = info.st_size
            if size > max_single_file_bytes:
                raise ManifestError(
                    f"source file exceeds max_single_file_bytes resource budget: {relative.as_posix()}"
                )
            if len(entries) + 1 > max_files:
                raise ManifestError("source tree exceeds max_files resource budget")
            if total_bytes + size > max_total_bytes:
                raise ManifestError("source tree exceeds max_total_bytes resource budget")
            total_bytes += size
            entries.append(
                {
                    "relative_path": relative.as_posix(),
                    "sha256": sha256_file(candidate),
                    "size": size,
                    "executable": bool(info.st_mode & stat.S_IXUSR),
                }
            )
    entries.sort(key=lambda item: item["relative_path"].encode("utf-8"))
    identity = {"root_id": root_id, "files": entries}
    return {
        "schema_version": "1.0",
        "root_id": root_id,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": entries,
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()
