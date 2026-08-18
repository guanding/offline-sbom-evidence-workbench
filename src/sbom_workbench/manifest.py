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
