#!/usr/bin/env python3
"""Verify the exact file set and hashes of a generated public candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


MANIFEST_NAME = "PUBLIC_RELEASE_MANIFEST.sha256"
STATUS_NAME = "PUBLIC_RELEASE_STATUS.json"
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)")
EXPECTED_BOUNDARY = "NOT_CUSTOMER_EVIDENCE_NOT_CONFORMITY_NOT_RELEASE_APPROVAL"


class CandidateVerificationError(ValueError):
    """Raised when public-candidate bytes do not match their manifest."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateVerificationError(
                f"public release status contains duplicate JSON key: {key!r}"
            )
        result[key] = value
    return result


def _safe_relative_path(raw: str) -> PurePosixPath:
    relative = PurePosixPath(raw)
    if (
        "\\" in raw
        or relative.is_absolute()
        or relative.as_posix() != raw
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise CandidateVerificationError(f"unsafe manifest path: {raw!r}")
    if raw == MANIFEST_NAME:
        raise CandidateVerificationError("manifest cannot include its own hash")
    return relative


def _load_manifest(root: Path) -> dict[PurePosixPath, str]:
    manifest = root / MANIFEST_NAME
    if manifest.is_symlink() or not manifest.is_file():
        raise CandidateVerificationError("public manifest is missing or unsafe")
    try:
        payload = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CandidateVerificationError("public manifest is unreadable") from exc
    if not payload.endswith("\n") or "\r" in payload:
        raise CandidateVerificationError("public manifest is not canonical UTF-8 text")

    expected: dict[PurePosixPath, str] = {}
    ordered_paths: list[str] = []
    for line in payload.splitlines():
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise CandidateVerificationError("public manifest contains an invalid line")
        relative = _safe_relative_path(match.group(2))
        if relative in expected:
            raise CandidateVerificationError(
                f"public manifest contains duplicate path: {relative.as_posix()}"
            )
        expected[relative] = match.group(1)
        ordered_paths.append(relative.as_posix())
    if not expected:
        raise CandidateVerificationError("public manifest is empty")
    if ordered_paths != sorted(ordered_paths):
        raise CandidateVerificationError("public manifest paths are not sorted")
    return expected


def _load_status(root: Path) -> dict[str, Any]:
    status_path = root / STATUS_NAME
    if status_path.is_symlink() or not status_path.is_file():
        raise CandidateVerificationError("public release status is missing or unsafe")
    try:
        status = json.loads(
            status_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateVerificationError("public release status is unreadable") from exc
    if not isinstance(status, dict):
        raise CandidateVerificationError("public release status must be an object")
    if status.get("boundary") != EXPECTED_BOUNDARY:
        raise CandidateVerificationError("public release status boundary is invalid")
    release_eligible = status.get("release_eligible")
    blocking_reasons = status.get("blocking_reasons")
    if not isinstance(release_eligible, bool) or not isinstance(blocking_reasons, list):
        raise CandidateVerificationError("public release status types are invalid")
    if any(not isinstance(item, str) or not item for item in blocking_reasons):
        raise CandidateVerificationError("public release blocking reasons are invalid")
    expected_label = (
        "RELEASE_ELIGIBLE_CANDIDATE"
        if release_eligible
        else "BLOCKED_RELEASE_GATES"
    )
    if status.get("candidate_status") != expected_label:
        raise CandidateVerificationError("public release status label is inconsistent")
    if release_eligible and blocking_reasons:
        raise CandidateVerificationError("release-eligible status has blocking reasons")
    if not release_eligible and not blocking_reasons:
        raise CandidateVerificationError("blocked status has no blocking reason")
    return status


def verify_candidate(candidate: Path) -> dict[str, Any]:
    if candidate.is_symlink():
        raise CandidateVerificationError("candidate root must not be a symlink")
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise CandidateVerificationError("candidate root does not exist") from exc
    if not root.is_dir():
        raise CandidateVerificationError("candidate root is not a directory")

    expected = _load_manifest(root)
    actual: dict[PurePosixPath, str] = {}
    for path in root.rglob("*"):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if path.is_symlink():
            raise CandidateVerificationError(
                f"candidate contains symlink: {relative.as_posix()}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise CandidateVerificationError(
                f"candidate contains unsupported entry: {relative.as_posix()}"
            )
        if relative.as_posix() != MANIFEST_NAME:
            actual[relative] = _sha256(path)

    missing = sorted(path.as_posix() for path in expected.keys() - actual.keys())
    extra = sorted(path.as_posix() for path in actual.keys() - expected.keys())
    if missing or extra:
        raise CandidateVerificationError(
            f"candidate exact set mismatch: missing={missing}, extra={extra}"
        )
    mismatched = sorted(
        path.as_posix() for path in expected if expected[path] != actual[path]
    )
    if mismatched:
        raise CandidateVerificationError(
            f"candidate hash mismatch: paths={mismatched}"
        )

    status = _load_status(root)
    selected_count = status.get("file_count_before_generated_metadata")
    if not isinstance(selected_count, int) or isinstance(selected_count, bool):
        raise CandidateVerificationError("candidate selected-file count is invalid")
    if selected_count != len(expected) - 1:
        raise CandidateVerificationError("candidate selected-file count is inconsistent")

    return {
        "verified_file_count": len(expected),
        "selected_file_count": selected_count,
        "manifest_sha256": _sha256(root / MANIFEST_NAME),
        "candidate_status": status["candidate_status"],
        "release_eligible": status["release_eligible"],
        "blocking_reasons": status["blocking_reasons"],
        "source_head": status.get("source_head"),
        "boundary": status["boundary"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    try:
        summary = verify_candidate(args.candidate)
    except CandidateVerificationError as exc:
        print(f"PUBLIC_CANDIDATE_INVALID: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
