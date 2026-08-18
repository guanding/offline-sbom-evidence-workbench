#!/usr/bin/env python3
"""Build a public-source candidate from an explicit allowlist.

The builder never copies the repository wholesale. It considers only tracked or
non-ignored files, applies the repository's allowlist, refuses common private
runtime/data formats, and writes an exact SHA-256 manifest. A candidate can be
built while rights review is pending, but ``--strict`` will refuse to call it
release-eligible until the license and rights gates are closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = Path(__file__).with_name("public_files.txt")
BLOCKED_ANY_PART = {
    ".git",
    ".serena",
    ".venv",
    ".cache",
    "__pycache__",
}
BLOCKED_TOP_LEVEL = {
    "backups",
    "data",
    "evidence",
    "outputs",
    "runtime",
    "self-test",
}
BLOCKED_SUFFIXES = {
    ".db",
    ".dump",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".xls",
    ".xlsm",
    ".xlsx",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".cmd",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
LOCAL_MARKERS = (
    "/" + "Users/",
    "C:" + "\\Users\\",
    "@oai/" + "artifact-tool",
)
SECRET_PATTERNS = (
    re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
APACHE_2_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
EXPECTED_COPYRIGHT_NOTICE = "Copyright 2026 Ding Guan"
PROJECT_OWNED_ASSET_ROOTS = (
    PurePosixPath("schemas"),
    PurePosixPath("datasets"),
    PurePosixPath("fixtures/synthetic_orion"),
)
PROJECT_OWNED_ASSET_MANIFEST = PurePosixPath("release/project_owned_assets.sha256")


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=REPO_ROOT, text=True, encoding="utf-8"
    ).strip()


def _candidate_paths() -> list[PurePosixPath]:
    raw = subprocess.check_output(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=REPO_ROOT,
    )
    return sorted(
        (PurePosixPath(item.decode("utf-8")) for item in raw.split(b"\0") if item),
        key=str,
    )


def _load_rules() -> tuple[tuple[str, ...], tuple[str, ...]]:
    includes: list[str] = []
    excludes: list[str] = []
    for raw in RULES_PATH.read_text(encoding="utf-8").splitlines():
        rule = raw.strip()
        if not rule or rule.startswith("#"):
            continue
        if rule.startswith("!"):
            excludes.append(rule[1:])
        else:
            includes.append(rule)
    if not includes:
        raise RuntimeError("public allowlist is empty")
    return tuple(includes), tuple(excludes)


def _matches(path: str, rule: str) -> bool:
    return path.startswith(rule) if rule.endswith("/") else path == rule


def _selected_paths() -> list[PurePosixPath]:
    includes, excludes = _load_rules()
    selected: list[PurePosixPath] = []
    for rel in _candidate_paths():
        value = rel.as_posix()
        if not any(_matches(value, rule) for rule in includes):
            continue
        if any(_matches(value, rule) for rule in excludes):
            continue
        if any(part in BLOCKED_ANY_PART for part in rel.parts) or (
            rel.parts and rel.parts[0] in BLOCKED_TOP_LEVEL
        ):
            raise RuntimeError(f"blocked path entered public set: {value}")
        if rel.suffix.lower() in BLOCKED_SUFFIXES:
            raise RuntimeError(f"blocked file type entered public set: {value}")
        source = REPO_ROOT / rel
        if source.is_symlink():
            raise RuntimeError(f"symlink is not allowed in public set: {value}")
        if source.is_file():
            selected.append(rel)
    return selected


def _scan_text(rel: PurePosixPath) -> list[str]:
    if rel.suffix.lower() not in TEXT_SUFFIXES:
        return []
    content = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
    findings: list[str] = []
    for marker in LOCAL_MARKERS:
        if marker in content:
            findings.append(f"local/private marker {marker!r}")
    for pattern in SECRET_PATTERNS:
        if pattern.search(content):
            findings.append(f"high-signal secret pattern {pattern.pattern!r}")
    return findings


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_owned_asset_gate(output: Path) -> tuple[bool, str | None]:
    manifest_path = output / PROJECT_OWNED_ASSET_MANIFEST
    rights_path = output / "release" / "rights_review.json"
    if not manifest_path.is_file() or not rights_path.is_file():
        return False, "OWNED_ASSET_RECORD_MISSING"

    expected: dict[PurePosixPath, str] = {}
    try:
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if match is None:
                return False, "OWNED_ASSET_MANIFEST_INVALID"
            rel = PurePosixPath(match.group(2))
            if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
                return False, "OWNED_ASSET_MANIFEST_INVALID"
            if not any(rel.parts[: len(root.parts)] == root.parts for root in PROJECT_OWNED_ASSET_ROOTS):
                return False, "OWNED_ASSET_MANIFEST_SCOPE_MISMATCH"
            if rel in expected:
                return False, "OWNED_ASSET_MANIFEST_DUPLICATE"
            expected[rel] = match.group(1)
        review = json.loads(rights_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "OWNED_ASSET_RECORD_UNREADABLE"
    if not expected:
        return False, "OWNED_ASSET_MANIFEST_EMPTY"

    records = [
        item
        for item in review.get("items", [])
        if item.get("id") == "project-owned-release-assets"
    ]
    if len(records) != 1:
        return False, "OWNED_ASSET_RIGHTS_RECORD_MISMATCH"
    record = records[0]
    if (
        record.get("included") is not True
        or record.get("status") != "APPROVED"
        or record.get("license_expression") != "Apache-2.0"
        or record.get("copyright_holder") != "Ding Guan"
        or record.get("source_paths")
        != ["schemas/", "datasets/", "fixtures/synthetic_orion/"]
        or record.get("asset_manifest") != PROJECT_OWNED_ASSET_MANIFEST.as_posix()
        or record.get("asset_manifest_sha256") != _sha256(manifest_path)
    ):
        return False, "OWNED_ASSET_RIGHTS_RECORD_MISMATCH"

    actual: dict[PurePosixPath, str] = {}
    for root in PROJECT_OWNED_ASSET_ROOTS:
        root_path = output / root
        if not root_path.is_dir() or root_path.is_symlink():
            return False, "OWNED_ASSET_ROOT_MISSING"
        for path in root_path.rglob("*"):
            if path.is_symlink():
                return False, "OWNED_ASSET_SYMLINK"
            if path.is_file():
                rel = PurePosixPath(path.relative_to(output).as_posix())
                actual[rel] = _sha256(path)
    if actual.keys() != expected.keys():
        return False, "OWNED_ASSET_SET_MISMATCH"
    if any(actual[rel] != digest for rel, digest in expected.items()):
        return False, "OWNED_ASSET_HASH_MISMATCH"
    return True, None


def _rights_pending(output: Path) -> bool:
    notices = output / "THIRD_PARTY_NOTICES.md"
    rights_review = output / "release" / "rights_review.json"
    if not notices.is_file() or not rights_review.is_file():
        return True
    try:
        review = json.loads(rights_review.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return True
    if review.get("overall_status") not in {"APPROVED", "APPROVED_WITH_EXCLUSIONS"}:
        return True
    approved = {"APPROVED", "NOT_APPLICABLE"}
    return any(
        item.get("included") is True and item.get("status") not in approved
        for item in review.get("items", [])
    )


def _license_gate(output: Path) -> tuple[bool, str | None]:
    license_path = output / "LICENSE"
    notice_path = output / "NOTICE"
    metadata_path = output / "pyproject.toml"
    if not license_path.is_file():
        return False, "LICENSE_MISSING"
    if _sha256(license_path) != APACHE_2_LICENSE_SHA256:
        return False, "LICENSE_CONTENT_MISMATCH"
    if not notice_path.is_file():
        return False, "NOTICE_MISSING"
    if not (output / "THIRD_PARTY_NOTICES.md").is_file():
        return False, "THIRD_PARTY_NOTICES_MISSING"
    try:
        notice = notice_path.read_text(encoding="utf-8")
        metadata = tomllib.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False, "LICENSE_METADATA_UNREADABLE"
    if EXPECTED_COPYRIGHT_NOTICE not in notice.splitlines():
        return False, "NOTICE_COPYRIGHT_MISMATCH"
    project = metadata.get("project", {})
    if project.get("license") != "Apache-2.0":
        return False, "LICENSE_METADATA_MISMATCH"
    if project.get("license-files") != [
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
    ]:
        return False, "LICENSE_FILES_METADATA_MISMATCH"
    return True, None


def build(output: Path, strict: bool) -> int:
    output = output.resolve()
    try:
        output.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError("output must be outside the source repository")
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")

    owned_assets_consistent, owned_asset_reason = _project_owned_asset_gate(REPO_ROOT)
    if not owned_assets_consistent:
        raise RuntimeError(f"project-owned asset gate failed: {owned_asset_reason}")

    selected = _selected_paths()
    if not selected:
        raise RuntimeError("public candidate would be empty")
    scan_findings = {
        rel.as_posix(): findings
        for rel in selected
        if (findings := _scan_text(rel))
    }
    if scan_findings:
        detail = json.dumps(scan_findings, ensure_ascii=False, indent=2)
        raise RuntimeError(f"public text scan failed:\n{detail}")

    output.mkdir(parents=True)
    for rel in selected:
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, target)

    copied_assets_consistent, copied_asset_reason = _project_owned_asset_gate(output)
    if not copied_assets_consistent:
        raise RuntimeError(f"copied project-owned asset gate failed: {copied_asset_reason}")

    license_present = (output / "LICENSE").is_file()
    license_consistent, license_blocking_reason = _license_gate(output)
    rights_pending = _rights_pending(output)
    source_worktree_dirty = bool(_git("status", "--porcelain"))
    release_eligible = license_consistent and not rights_pending and not source_worktree_dirty
    blocking_reasons = []
    if license_blocking_reason is not None:
        blocking_reasons.append(license_blocking_reason)
    if rights_pending:
        blocking_reasons.append("THIRD_PARTY_RIGHTS_PENDING")
    if source_worktree_dirty:
        blocking_reasons.append("SOURCE_WORKTREE_DIRTY")
    status = {
        "candidate_status": "RELEASE_ELIGIBLE_CANDIDATE" if release_eligible else "BLOCKED_RELEASE_GATES",
        "release_eligible": release_eligible,
        "blocking_reasons": blocking_reasons,
        "source_head": _git("rev-parse", "HEAD"),
        "source_worktree_dirty": source_worktree_dirty,
        "file_count_before_generated_metadata": len(selected),
        "license_present": license_present,
        "license_consistent": license_consistent,
        "license_expression": "Apache-2.0" if license_consistent else None,
        "copyright_notice": EXPECTED_COPYRIGHT_NOTICE if license_consistent else None,
        "project_owned_assets_consistent": copied_assets_consistent,
        "project_owned_asset_manifest_sha256": _sha256(
            output / PROJECT_OWNED_ASSET_MANIFEST
        ),
        "third_party_rights_pending": rights_pending,
        "boundary": "NOT_CUSTOMER_EVIDENCE_NOT_CONFORMITY_NOT_RELEASE_APPROVAL",
    }
    status_path = output / "PUBLIC_RELEASE_STATUS.json"
    status_path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    manifest_lines: list[str] = []
    for path in sorted((item for item in output.rglob("*") if item.is_file()), key=str):
        rel = path.relative_to(output).as_posix()
        if rel == "PUBLIC_RELEASE_MANIFEST.sha256":
            continue
        manifest_lines.append(f"{_sha256(path)}  {rel}")
    (output / "PUBLIC_RELEASE_MANIFEST.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))
    if strict and not release_eligible:
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero until license and third-party rights gates are closed",
    )
    args = parser.parse_args()
    try:
        return build(args.output, args.strict)
    except (FileExistsError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"PUBLIC_CANDIDATE_BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
