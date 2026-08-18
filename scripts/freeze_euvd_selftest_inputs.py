#!/usr/bin/env python3
"""Freeze the selected EUVD workbench into isolated M3A scan inputs.

This is intentionally a narrow, project-specific copier.  It snapshots only
the reviewed source allowlist and the Windows portable runtime, compares the
selected source identities before and after copying, and publishes the result
only when both copies match their source identities exactly.  Data, outputs,
backups, exports and live SQLite/WAL files are never selected.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

from sbom_workbench.manifest import build_exact_set_manifest, canonical_json_bytes, write_json_atomic


SOURCE_FILES = (
    ".dockerignore",
    "Dockerfile",
    "README.md",
    "RELEASE_NOTES_v2.2.0.md",
    "RELEASE_NOTES_v2.3.0.md",
    "docker-compose.yml",
    "export-portable.cmd",
    "requirements.txt",
    "start.cmd",
    "stop.cmd",
)
SOURCE_DIRECTORIES = ("app", "config", "docs", "scripts", "tests")
IGNORED_NAMES = frozenset({".DS_Store", "__pycache__"})
IGNORED_SUFFIXES = (".pyc", ".pyo")


class FreezeError(ValueError):
    """Raised when an input cannot be frozen without weakening identity."""


def _relative_files(root: Path, *, portable: bool) -> list[PurePosixPath]:
    candidates: list[Path] = []
    if portable:
        candidates.extend(path for path in root.rglob("*") if path.is_file())
    else:
        for name in SOURCE_FILES:
            candidates.append(root / name)
        for name in SOURCE_DIRECTORIES:
            directory = root / name
            if directory.is_symlink() or not directory.is_dir():
                raise FreezeError(f"required source directory is unavailable: {name}")
            candidates.extend(path for path in directory.rglob("*") if path.is_file())

    result: list[PurePosixPath] = []
    seen: set[str] = set()
    for path in candidates:
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if any(part in IGNORED_NAMES for part in relative.parts) or relative.name.endswith(
            IGNORED_SUFFIXES
        ):
            continue
        text = relative.as_posix()
        if text in seen:
            continue
        seen.add(text)
        result.append(relative)
    result.sort(key=lambda item: item.as_posix().encode("utf-8"))
    if not result:
        raise FreezeError("selected input set is empty")
    return result


def _entry(path: Path, relative: PurePosixPath) -> dict[str, object]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FreezeError(f"selected input is not a single-link regular file: {relative}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    if (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_mode,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_mode,
    ):
        raise FreezeError(f"selected input changed while being hashed: {relative}")
    return {
        "relative_path": relative.as_posix(),
        "sha256": digest.hexdigest(),
        "size": info.st_size,
        "executable": bool(info.st_mode & stat.S_IXUSR),
    }


def _identity(root: Path, relative_files: list[PurePosixPath], root_id: str) -> dict[str, object]:
    files = [_entry(root / relative.as_posix(), relative) for relative in relative_files]
    identity = {"root_id": root_id, "files": files}
    return {
        "schema_version": "1.0",
        "root_id": root_id,
        "file_count": len(files),
        "total_bytes": sum(int(item["size"]) for item in files),
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": files,
    }


def _copy_selected(
    source: Path,
    destination: Path,
    relative_files: list[PurePosixPath],
) -> None:
    destination.mkdir(mode=0o700)
    for relative in relative_files:
        source_path = source / relative.as_posix()
        target = destination / relative.as_posix()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        before = _entry(source_path, relative)
        with source_path.open("rb") as reader, target.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        os.chmod(target, 0o700 if before["executable"] else 0o600)
        copied = _entry(target, relative)
        if any(copied[key] != before[key] for key in ("sha256", "size", "executable")):
            raise FreezeError(f"copied input does not match its source: {relative}")


def freeze(source_root: Path, destination: Path) -> dict[str, object]:
    source = Path(source_root)
    if source.is_symlink() or not source.is_dir():
        raise FreezeError("source root must be an operator-supplied non-symlink directory")
    source = source.resolve(strict=True)
    portable_source = source / "runtime"
    if portable_source.is_symlink() or not portable_source.is_dir():
        raise FreezeError("portable runtime is unavailable")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FreezeError("destination exists; refusing overwrite")
    destination_parent = destination.parent
    if destination_parent.is_symlink():
        raise FreezeError("destination parent must not be a symlink")
    destination_parent.mkdir(parents=True, exist_ok=True)
    destination_parent = destination_parent.resolve(strict=True)
    try:
        destination.resolve().relative_to(source)
    except ValueError:
        pass
    else:
        raise FreezeError("destination must not be inside the active source tree")

    source_files = _relative_files(source, portable=False)
    portable_files = _relative_files(portable_source, portable=True)
    source_root_id = "euvd-workbench-v2.3-source-selftest"
    portable_root_id = "euvd-workbench-v2.3-portable-selftest"
    source_before = _identity(source, source_files, source_root_id)
    portable_before = _identity(portable_source, portable_files, portable_root_id)

    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination_parent))
    moved = False
    try:
        _copy_selected(source, stage / "source", source_files)
        _copy_selected(portable_source, stage / "portable", portable_files)
        source_after = _identity(source, source_files, source_root_id)
        portable_after = _identity(portable_source, portable_files, portable_root_id)
        if source_before != source_after or portable_before != portable_after:
            raise FreezeError("selected inputs changed during the stable-copy window")
        frozen_source = build_exact_set_manifest(stage / "source", source_root_id)
        frozen_portable = build_exact_set_manifest(stage / "portable", portable_root_id)
        if frozen_source != source_before or frozen_portable != portable_before:
            raise FreezeError("frozen exact-set does not match the selected source identity")
        manifests = stage / "manifests"
        write_json_atomic(manifests / "source-manifest.json", frozen_source)
        write_json_atomic(manifests / "portable-manifest.json", frozen_portable)
        receipt = {
            "schema_version": "1.0",
            "classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE",
            "source_root": str(source),
            "source_allowlist_files": list(SOURCE_FILES),
            "source_allowlist_directories": list(SOURCE_DIRECTORIES),
            "excluded_live_domains": ["backups", "data", "exports", "outputs", "runtime"],
            "source_exact_set_sha256": frozen_source["exact_set_sha256"],
            "portable_exact_set_sha256": frozen_portable["exact_set_sha256"],
            "stable_copy_check": "PRE_COPY_EQUALS_POST_COPY_EQUALS_FROZEN_COPY",
            "authority_boundary": (
                "Engineering self-test snapshot only; not customer evidence, manufacturer approval, "
                "release approval, component completeness, PRE-7 or CRA conformity."
            ),
        }
        write_json_atomic(stage / "FREEZE_RECEIPT.json", receipt)
        os.replace(stage, destination)
        moved = True
        return receipt
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root",
        required=True,
        type=Path,
        help="operator-selected active EUVD source tree to freeze",
    )
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args()
    receipt = freeze(arguments.source_root, arguments.destination)
    print(receipt["source_exact_set_sha256"])
    print(receipt["portable_exact_set_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
