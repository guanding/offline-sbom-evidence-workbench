#!/usr/bin/env python3
"""Deterministically rebuild project-owned SYNTHETIC_NOT_EVIDENCE tar artifacts."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
from pathlib import Path


CLASSIFICATION = "SYNTHETIC_NOT_EVIDENCE"
FIXTURE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = FIXTURE_ROOT / "source"
RELEASES = ("release-a", "release-b", "conflict")


def _payload_files(payload_root: Path) -> list[Path]:
    if payload_root.is_symlink() or not payload_root.is_dir():
        raise ValueError(f"unsafe or missing payload root: {payload_root}")
    files: list[Path] = []
    for path in payload_root.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if path.is_symlink():
                raise ValueError(f"symlink directory is forbidden: {path}")
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"only single-link regular files are permitted: {path}")
        files.append(path)
    files.sort(key=lambda path: path.relative_to(payload_root).as_posix().encode("utf-8"))
    if not files:
        raise ValueError("payload must contain at least one file")
    return files


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rebuild(release_name: str, output: Path) -> dict[str, object]:
    if release_name not in RELEASES:
        raise ValueError(f"unknown synthetic release: {release_name}")
    payload_root = SOURCE_ROOT / release_name / "payload"
    files = _payload_files(payload_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in files:
                relative = path.relative_to(payload_root).as_posix()
                payload = path.read_bytes()
                member = tarfile.TarInfo(relative)
                member.size = len(payload)
                member.mode = 0o644
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = 0
                archive.addfile(member, io.BytesIO(payload))
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "classification": CLASSIFICATION,
        "release_name": release_name,
        "artifact_sha256": sha256_file(output),
        "artifact_size": output.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", choices=RELEASES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(rebuild(args.release, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
