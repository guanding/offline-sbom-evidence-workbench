#!/usr/bin/env python3
"""Normalize a setuptools sdist tarball for privacy and reproducibility."""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile


DEFAULT_SOURCE_DATE_EPOCH = 315532800  # 1980-01-01T00:00:00Z


def normalize_sdist(path: Path, *, epoch: int = DEFAULT_SOURCE_DATE_EPOCH) -> None:
    path = path.resolve(strict=True)
    if epoch < DEFAULT_SOURCE_DATE_EPOCH:
        raise ValueError("SOURCE_DATE_EPOCH must be at least 1980-01-01")

    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"unsupported sdist member type: {member.name}")
            payload: bytes | None = None
            if member.isfile():
                handle = source.extractfile(member)
                if handle is None:
                    raise ValueError(f"unable to read sdist member: {member.name}")
                payload = handle.read()
            entries.append((member, payload))

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=temporary, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as target:
                    for original, payload in sorted(entries, key=lambda item: item[0].name):
                        normalized = tarfile.TarInfo(original.name)
                        normalized.type = original.type
                        normalized.uid = 0
                        normalized.gid = 0
                        normalized.uname = ""
                        normalized.gname = ""
                        normalized.mtime = epoch
                        normalized.mode = (
                            0o755
                            if original.isdir() or original.mode & 0o111
                            else 0o644
                        )
                        normalized.size = len(payload) if payload is not None else 0
                        target.addfile(
                            normalized,
                            io.BytesIO(payload) if payload is not None else None,
                        )
        assert temporary_path is not None
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdist", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_SOURCE_DATE_EPOCH)),
    )
    args = parser.parse_args()
    normalize_sdist(args.sdist, epoch=args.epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
