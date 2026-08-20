"""Pinned, non-executing Git acquisition with fail-closed integrity checks."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .manifest import ManifestError, build_exact_set_manifest, canonical_json_bytes, sha256_file, write_json_atomic
from .registry import validate_source_registry


class AcquisitionError(RuntimeError):
    """Raised when acquisition cannot preserve the governed boundary."""


_GIT_CONFIG = [
    "-c", "credential.helper=",
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "-c", "http.followRedirects=false",
]
_RECEIPT_KEYS = {
    "schema_version",
    "acquisition_status",
    "acquired_at_utc",
    "dataset_id",
    "source_url",
    "resolved_source_ips",
    "registry_sha256",
    "registry_entry_sha256",
    "resolved_commit",
    "annotated_tag_object",
    "git_tree_sha",
    "git_archive_sha256",
    "license_expression",
    "license_review_status",
    "license_evidence",
    "tool_runtime",
    "tree_manifest",
}


def _is_lower_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(
        character in "0123456789abcdef" for character in value
    )


def _validate_acquisition_report_shape(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != _RECEIPT_KEYS:
        raise AcquisitionError("acquisition manifest fields do not match schema 1.1")
    if report.get("schema_version") != "1.1" or report.get("acquisition_status") not in {
        "SEALED_EXPECTATIONS_MATCHED",
        "ACQUIRED_UNSEALED",
    }:
        raise AcquisitionError("acquisition manifest version or status is unsupported")
    acquired_at = report.get("acquired_at_utc")
    try:
        parsed_time = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AcquisitionError("acquisition timestamp is invalid") from exc
    if parsed_time.tzinfo is None:
        raise AcquisitionError("acquisition timestamp must include UTC offset")
    for field in ("registry_sha256", "registry_entry_sha256", "git_archive_sha256"):
        if not _is_lower_hex(report.get(field), 64):
            raise AcquisitionError(f"acquisition manifest {field} is invalid")
    if not _is_lower_hex(report.get("resolved_commit"), 40) or not _is_lower_hex(report.get("git_tree_sha"), 40):
        raise AcquisitionError("acquisition manifest Git identity is invalid")
    tag_object = report.get("annotated_tag_object")
    if tag_object is not None and not _is_lower_hex(tag_object, 40):
        raise AcquisitionError("acquisition manifest annotated tag is invalid")
    resolved_ips = report.get("resolved_source_ips")
    if not isinstance(resolved_ips, list) or not resolved_ips or not all(isinstance(item, str) for item in resolved_ips):
        raise AcquisitionError("acquisition manifest resolved IP list is invalid")
    if resolved_ips != sorted(set(resolved_ips)):
        raise AcquisitionError("acquisition manifest resolved IP list must be sorted and unique")
    try:
        if any(not ipaddress.ip_address(item).is_global for item in resolved_ips):
            raise AcquisitionError("acquisition manifest contains a non-public resolved IP")
    except ValueError as exc:
        raise AcquisitionError("acquisition manifest contains an invalid resolved IP") from exc
    license_evidence = report.get("license_evidence")
    if not isinstance(license_evidence, list) or not license_evidence:
        raise AcquisitionError("acquisition manifest license evidence is invalid")
    for item in license_evidence:
        if not isinstance(item, dict) or set(item) != {"relative_path", "sha256"}:
            raise AcquisitionError("acquisition manifest license evidence fields are invalid")
        if not isinstance(item["relative_path"], str) or not _is_lower_hex(item["sha256"], 64):
            raise AcquisitionError("acquisition manifest license evidence value is invalid")
        _normalized_member_path(item["relative_path"])
    license_paths = [item["relative_path"] for item in license_evidence]
    if license_paths != sorted(set(license_paths)):
        raise AcquisitionError("acquisition manifest license evidence must be sorted and unique")
    tool_runtime = report.get("tool_runtime")
    if not isinstance(tool_runtime, dict) or set(tool_runtime) != {"git", "python"}:
        raise AcquisitionError("acquisition manifest runtime identities are invalid")
    for identity in tool_runtime.values():
        if not isinstance(identity, dict) or set(identity) != {"path", "version", "sha256"}:
            raise AcquisitionError("acquisition manifest runtime identity fields are invalid")
        if not all(isinstance(identity[key], str) and identity[key] for key in ("path", "version")):
            raise AcquisitionError("acquisition manifest runtime identity values are invalid")
        if not _is_lower_hex(identity["sha256"], 64):
            raise AcquisitionError("acquisition manifest runtime hash is invalid")
    return report


def load_trusted_acquisition_receipt(
    receipt_path: Path,
    trusted_sha256: str,
) -> dict[str, Any]:
    """Load one acquisition receipt under an external SHA-256 trust anchor.

    This validates only the acquisition receipt's syntax and cryptographic
    identity.  Callers must separately bind ``tree_manifest`` to the source
    tree they consume; the receipt never establishes rights or release status.
    """

    path = Path(receipt_path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise AcquisitionError("source acquisition receipt is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > 256 * 1024 * 1024
    ):
        raise AcquisitionError(
            "source acquisition receipt must be one bounded single-link regular file"
        )
    if not _is_lower_hex(trusted_sha256, 64):
        raise AcquisitionError(
            "source acquisition receipt requires an external SHA-256 trust anchor"
        )
    observed_sha256 = sha256_file(path)
    if observed_sha256 != trusted_sha256:
        raise AcquisitionError(
            "source acquisition receipt does not match the external trust anchor"
        )

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AcquisitionError(
                    f"source acquisition receipt contains duplicate JSON key: {key}"
                )
            value[key] = item
        return value

    try:
        report = json.loads(
            path.read_bytes().decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AcquisitionError("source acquisition receipt is not strict JSON") from exc
    return _validate_acquisition_report_shape(report)


def _git_binary() -> Path:
    candidate = shutil.which("git", path=os.defpath)
    if candidate is None:
        raise AcquisitionError("git executable is unavailable")
    resolved = Path(candidate).resolve(strict=True)
    if not resolved.is_file():
        raise AcquisitionError("git executable is not a regular file")
    return resolved


def _git_environment(git_binary: Path) -> dict[str, str]:
    return {
        "PATH": os.pathsep.join((str(git_binary.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false",
    }


def _run_git_raw(arguments: list[str], working_directory: Path) -> bytes:
    git_binary = _git_binary()
    try:
        result = subprocess.run(
            [str(git_binary), *_GIT_CONFIG, *arguments],
            cwd=working_directory,
            env=_git_environment(git_binary),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcquisitionError(f"git command could not complete: {type(exc).__name__}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:]
        message = detail[0] if detail else "unknown git error"
        raise AcquisitionError(f"git command failed: {message}")
    return result.stdout


def _run_git(arguments: list[str], working_directory: Path) -> str:
    try:
        return _run_git_raw(arguments, working_directory).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise AcquisitionError("git output is not valid UTF-8") from exc


def _git_runtime_identity() -> dict[str, str]:
    git_binary = _git_binary()
    version = _run_git(["--version"], git_binary.parent)
    return {
        "path": str(git_binary),
        "version": version,
        "sha256": sha256_file(git_binary),
    }


def _python_runtime_identity() -> dict[str, str]:
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "path": str(executable),
        "version": sys.version.split()[0],
        "sha256": sha256_file(executable),
    }


def resolve_public_source_ips(url: str) -> list[str]:
    host = urlsplit(url).hostname
    if host is None:
        raise AcquisitionError("source URL has no hostname")
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AcquisitionError("source hostname could not be resolved") from exc
    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise AcquisitionError("source hostname resolved to no addresses")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise AcquisitionError("source hostname returned an invalid address") from exc
        if not parsed.is_global:
            raise AcquisitionError("source hostname resolved to a non-public address")
    return addresses


def _normalized_member_path(name: str) -> PurePosixPath:
    normalized_name = name[:-1] if name.endswith("/") else name
    if unicodedata.normalize("NFC", normalized_name) != normalized_name:
        raise AcquisitionError(f"archive path is not Unicode NFC: {name!r}")
    try:
        normalized_name.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AcquisitionError(f"archive path is not valid UTF-8: {name!r}") from exc
    raw_parts = normalized_name.split("/")
    path = PurePosixPath(normalized_name)
    if (
        not normalized_name
        or "\\" in normalized_name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise AcquisitionError(f"unsafe archive path: {name!r}")
    return path


def safe_extract_tar(archive: Path, destination: Path, max_files: int, max_total_bytes: int) -> None:
    regular_count = 0
    member_count = 0
    total_bytes = 0
    seen: set[str] = set()
    try:
        destination.mkdir(parents=True, exist_ok=False)
        destination_root = destination.resolve(strict=True)
        with tarfile.open(archive, mode="r|") as bundle:
            for member in bundle:
                member_count += 1
                if member_count > max_files * 2 + 1024:
                    raise AcquisitionError("archive exceeds registered header-count limit")
                relative = _normalized_member_path(member.name)
                relative_text = relative.as_posix()
                if relative_text in seen:
                    raise AcquisitionError(f"duplicate archive path: {relative_text}")
                seen.add(relative_text)
                target = destination.joinpath(*relative.parts)
                target_parent = target.parent
                target_parent.mkdir(parents=True, exist_ok=True)
                if not target_parent.resolve(strict=True).is_relative_to(destination_root):
                    raise AcquisitionError(f"archive path escaped destination: {member.name}")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isreg():
                    raise AcquisitionError(f"unsupported archive entry type: {member.name}")
                regular_count += 1
                total_bytes += member.size
                if regular_count > max_files:
                    raise AcquisitionError("archive exceeds registered file-count limit")
                if total_bytes > max_total_bytes:
                    raise AcquisitionError("archive exceeds registered expanded-size limit")
                source = bundle.extractfile(member)
                if source is None:
                    raise AcquisitionError(f"cannot read archive member: {member.name}")
                with source, target.open("xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                if target.stat().st_size != member.size:
                    raise AcquisitionError(f"archive member size mismatch: {member.name}")
                target.chmod(0o755 if member.mode & 0o100 else 0o644)
    except (AcquisitionError, OSError, tarfile.TarError) as exc:
        try:
            if os.path.lexists(destination):
                if destination.is_symlink():
                    raise OSError("extraction destination became a symlink")
                shutil.rmtree(destination)
        except OSError as cleanup_error:
            raise AcquisitionError("archive extraction failed and partial destination cleanup failed") from cleanup_error
        if isinstance(exc, AcquisitionError):
            raise
        raise AcquisitionError(f"archive extraction failed: {type(exc).__name__}") from exc


def _validate_source_entry(source: dict[str, Any]) -> None:
    validate_source_registry(
        {
            "registry_type": "source-dataset-registry",
            "schema_version": "1.0",
            "updated_at": "1970-01-01",
            "sources": [source],
        }
    )
    if not source["governance"]["acquisition_allowed"]:
        raise AcquisitionError("source is not approved for quarantine acquisition")


def _fetch_pinned_object(repository: Path, source: dict[str, Any]) -> tuple[str, str | None]:
    pin = source["pin"]
    if pin["ref_type"] == "annotated_tag":
        local_ref = "refs/tags/sbom-workbench-acquisition"
        _run_git(
            ["fetch", "--depth=1", "--no-tags", "origin", f"refs/tags/{pin['ref_name']}:{local_ref}"],
            repository,
        )
        observed_tag = _run_git(["rev-parse", local_ref], repository)
        if observed_tag != pin["tag_object"]:
            raise AcquisitionError("annotated tag object mismatch")
        resolved = _run_git(["rev-parse", f"{local_ref}^{{commit}}"], repository)
        return resolved, observed_tag
    _run_git(["fetch", "--depth=1", "--no-tags", "origin", pin["resolved_commit"]], repository)
    resolved = _run_git(["rev-parse", "FETCH_HEAD^{commit}"], repository)
    return resolved, None


def _git_tree_entries(repository: Path, commit: str) -> tuple[dict[str, dict[str, Any]], str]:
    tree_sha = _run_git(["rev-parse", f"{commit}^{{tree}}"], repository)
    raw = _run_git_raw(["ls-tree", "-r", "-l", "-z", commit], repository)
    entries: dict[str, dict[str, Any]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            prefix, raw_path = record.split(b"\t", 1)
            parts = prefix.split()
            if len(parts) != 4:
                raise ValueError("unexpected git ls-tree prefix")
            mode, object_type, _object_id, raw_size = parts
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AcquisitionError("git tree contains an unsupported entry encoding") from exc
        normalized = _normalized_member_path(path).as_posix()
        if object_type != b"blob" or mode not in {b"100644", b"100755"}:
            raise AcquisitionError(f"git tree contains unsupported object or gitlink: {normalized}")
        if normalized in entries:
            raise AcquisitionError(f"git tree contains duplicate path: {normalized}")
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise AcquisitionError(f"git tree entry has no concrete size: {normalized}") from exc
        entries[normalized] = {"size": size, "executable": mode == b"100755"}
    return entries, tree_sha


def _reject_archive_transform_attributes(repository: Path, commit: str, tree: dict[str, dict[str, Any]]) -> None:
    for path in sorted(item for item in tree if PurePosixPath(item).name == ".gitattributes"):
        content = _run_git_raw(["show", f"{commit}:{path}"], repository)
        if b"export-ignore" in content or b"export-subst" in content:
            raise AcquisitionError(f"git archive transform attribute is forbidden: {path}")


def _reject_lfs_pointers(root: Path, manifest: dict[str, Any]) -> None:
    marker = b"version https://git-lfs.github.com/spec/v1\n"
    for entry in manifest["files"]:
        path = root.joinpath(*PurePosixPath(entry["relative_path"]).parts)
        with path.open("rb") as handle:
            prefix = handle.read(256)
        normalized_prefix = prefix.replace(b"\r\n", b"\n")
        if normalized_prefix.startswith(marker) and b"\noid sha256:" in normalized_prefix:
            raise AcquisitionError(f"Git LFS pointer is forbidden in v1: {entry['relative_path']}")


def _compare_tree_and_archive(tree: dict[str, dict[str, Any]], manifest: dict[str, Any]) -> None:
    archive_entries = {
        item["relative_path"]: {"size": item["size"], "executable": item["executable"]}
        for item in manifest["files"]
    }
    if tree != archive_entries:
        missing = sorted(set(tree) - set(archive_entries))[:10]
        extra = sorted(set(archive_entries) - set(tree))[:10]
        raise AcquisitionError(f"git tree/archive exact-set mismatch; missing={missing}, extra={extra}")


def _assert_safe_destination(path: Path) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if os.path.lexists(current):
            information = current.lstat()
            if stat.S_ISLNK(information.st_mode):
                raise AcquisitionError(f"destination contains a symlink component: {current}")
    absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
    information = absolute.lstat()
    if not stat.S_ISDIR(information.st_mode) or information.st_mode & 0o022:
        raise AcquisitionError("destination must be a non-shared directory")
    if hasattr(os, "getuid") and information.st_uid != os.getuid():
        raise AcquisitionError("destination must be owned by the current user")
    return absolute.resolve(strict=True)


def _acquisition_status(source: dict[str, Any]) -> str:
    sealed = source["pin"]["acquisition_artifact_sha256"] is not None and all(
        value is not None for value in source["license"]["evidence_hashes"].values()
    )
    return "SEALED_EXPECTATIONS_MATCHED" if sealed else "ACQUIRED_UNSEALED"


def verify_acquisition(
    target: Path,
    source: dict[str, Any],
    *,
    registry_sha256: str | None = None,
    trusted_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    _validate_source_entry(source)
    manifest_path = target / "acquisition_manifest.json"
    complete_path = target / "COMPLETE.json"
    tree = target / "tree"
    try:
        package_entries = {item.name for item in target.iterdir()}
    except OSError as exc:
        raise AcquisitionError("acquisition package cannot be enumerated") from exc
    if package_entries != {"COMPLETE.json", "acquisition_manifest.json", "tree"}:
        raise AcquisitionError("acquisition package contains an unexpected top-level entry")
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or not complete_path.is_file()
        or complete_path.is_symlink()
        or not tree.is_dir()
        or tree.is_symlink()
    ):
        raise AcquisitionError("acquisition package is incomplete")
    manifest_sha256 = sha256_file(manifest_path)
    if not _is_lower_hex(trusted_manifest_sha256, 64):
        raise AcquisitionError("consumer verification requires an external acquisition-manifest SHA-256 trust anchor")
    if manifest_sha256 != trusted_manifest_sha256:
        raise AcquisitionError("acquisition manifest does not match the external trust anchor")
    try:
        report = _validate_acquisition_report_shape(json.loads(manifest_path.read_text(encoding="utf-8")))
        complete = json.loads(complete_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AcquisitionError("acquisition package metadata is unreadable") from exc
    if complete != {"acquisition_manifest_sha256": manifest_sha256}:
        raise AcquisitionError("acquisition COMPLETE seal does not match manifest")
    expected_entry_hash = registry_entry_hash(source)
    expected_fields = {
        "schema_version": "1.1",
        "acquisition_status": _acquisition_status(source),
        "dataset_id": source["dataset_id"],
        "source_url": source["upstream_url"],
        "registry_entry_sha256": expected_entry_hash,
        "resolved_commit": source["pin"]["resolved_commit"],
        "annotated_tag_object": source["pin"]["tag_object"],
        "license_expression": source["license"]["expression"],
        "license_review_status": source["license"]["review_status"],
    }
    for field, expected in expected_fields.items():
        if report.get(field) != expected:
            raise AcquisitionError(f"acquisition manifest/source mismatch: {field}")
    if registry_sha256 is not None and report.get("registry_sha256") != registry_sha256:
        raise AcquisitionError("acquisition manifest/registry mismatch")
    expected_archive = source["pin"]["acquisition_artifact_sha256"]
    if expected_archive is not None and report.get("git_archive_sha256") != expected_archive:
        raise AcquisitionError("acquisition archive expectation mismatch")
    try:
        recomputed = build_exact_set_manifest(tree, source["root_id"])
    except ManifestError as exc:
        raise AcquisitionError(f"acquisition tree cannot be verified: {exc}") from exc
    if recomputed != report.get("tree_manifest"):
        raise AcquisitionError("acquisition tree no longer matches its exact-set manifest")
    expected_license = source["license"]["evidence_hashes"]
    actual_license = {item["relative_path"]: item["sha256"] for item in report.get("license_evidence", [])}
    if set(actual_license) != set(expected_license):
        raise AcquisitionError("acquisition license evidence set does not match registry")
    for path, expected in expected_license.items():
        if expected is not None and actual_license.get(path) != expected:
            raise AcquisitionError(f"license evidence drift detected: {path}")
        license_path = tree.joinpath(*PurePosixPath(path).parts)
        if not license_path.is_file() or license_path.is_symlink() or sha256_file(license_path) != actual_license[path]:
            raise AcquisitionError(f"license evidence does not match acquisition tree: {path}")
    return report


def acquire_git_source(
    source: dict[str, Any],
    destination_root: Path,
    *,
    registry_sha256: str,
    registry_entry_sha256: str,
) -> dict[str, Any]:
    _validate_source_entry(source)
    if not isinstance(registry_sha256, str) or len(registry_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in registry_sha256
    ):
        raise AcquisitionError("trusted registry SHA-256 is invalid")
    if registry_entry_sha256 != registry_entry_hash(source):
        raise AcquisitionError("registry entry SHA-256 does not match canonical source entry")
    resolved_ips = resolve_public_source_ips(source["upstream_url"])
    destination = _assert_safe_destination(destination_root)
    dataset_id = source["dataset_id"]
    expected_commit = source["pin"]["resolved_commit"]
    target = destination / dataset_id / expected_commit
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_safe_destination(target.parent)
    if os.path.lexists(target):
        raise AcquisitionError(f"target already exists; refusing overwrite: {target}")

    lock = target.parent / f".{expected_commit}.acquisition.lock"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lock_descriptor = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise AcquisitionError("cannot acquire exclusive destination lock") from exc
    os.close(lock_descriptor)

    try:
        with tempfile.TemporaryDirectory(prefix=f".{dataset_id}-", dir=target.parent) as temporary_name:
            temporary = Path(temporary_name)
            repository = temporary / "repository.git"
            archive = temporary / "source.tar"
            extracted = temporary / "tree"
            repository.mkdir()
            _run_git(["init", "--bare", "."], repository)
            _run_git(["remote", "add", "origin", source["upstream_url"]], repository)
            resolved, observed_tag = _fetch_pinned_object(repository, source)
            if resolved != expected_commit:
                raise AcquisitionError(f"resolved commit mismatch: expected {expected_commit}, got {resolved}")
            git_tree, git_tree_sha256 = _git_tree_entries(repository, resolved)
            _reject_archive_transform_attributes(repository, resolved, git_tree)
            _run_git(["archive", "--format=tar", f"--output={archive}", resolved], repository)
            archive_sha256 = sha256_file(archive)
            expected_archive_sha256 = source["pin"]["acquisition_artifact_sha256"]
            if expected_archive_sha256 is not None and archive_sha256 != expected_archive_sha256:
                raise AcquisitionError(
                    f"acquisition archive hash mismatch: expected {expected_archive_sha256}, got {archive_sha256}"
                )
            safe_extract_tar(
                archive,
                extracted,
                max_files=source["acquisition"]["max_files"],
                max_total_bytes=source["acquisition"]["max_total_bytes"],
            )
            manifest = build_exact_set_manifest(extracted, source["root_id"])
            _reject_lfs_pointers(extracted, manifest)
            _compare_tree_and_archive(git_tree, manifest)

            license_evidence = []
            for relative in source["license"]["evidence_paths"]:
                evidence = extracted.joinpath(*PurePosixPath(relative).parts)
                if not evidence.is_file() or evidence.is_symlink():
                    raise AcquisitionError(f"license evidence missing or unsafe: {relative}")
                evidence_sha256 = sha256_file(evidence)
                expected_evidence_sha256 = source["license"]["evidence_hashes"].get(relative)
                if expected_evidence_sha256 is not None and evidence_sha256 != expected_evidence_sha256:
                    raise AcquisitionError(
                        f"license evidence hash mismatch for {relative}: expected {expected_evidence_sha256}, got {evidence_sha256}"
                    )
                license_evidence.append({"relative_path": relative, "sha256": evidence_sha256})

            report = {
                "schema_version": "1.1",
                "acquisition_status": _acquisition_status(source),
                "acquired_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "dataset_id": dataset_id,
                "source_url": source["upstream_url"],
                "resolved_source_ips": resolved_ips,
                "registry_sha256": registry_sha256,
                "registry_entry_sha256": registry_entry_sha256,
                "resolved_commit": resolved,
                "annotated_tag_object": observed_tag,
                "git_tree_sha": git_tree_sha256,
                "git_archive_sha256": archive_sha256,
                "license_expression": source["license"]["expression"],
                "license_review_status": source["license"]["review_status"],
                "license_evidence": sorted(license_evidence, key=lambda item: item["relative_path"]),
                "tool_runtime": {"git": _git_runtime_identity(), "python": _python_runtime_identity()},
                "tree_manifest": manifest,
            }

            package = temporary / "package"
            package.mkdir()
            extracted.replace(package / "tree")
            write_json_atomic(package / "acquisition_manifest.json", report)
            acquisition_manifest_sha256 = sha256_file(package / "acquisition_manifest.json")
            complete = {"acquisition_manifest_sha256": acquisition_manifest_sha256}
            write_json_atomic(package / "COMPLETE.json", complete)

            if os.path.lexists(target):
                raise AcquisitionError("acquisition target appeared while the package was being prepared")
            package.replace(target)
            parent_descriptor = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            return verify_acquisition(
                target,
                source,
                registry_sha256=registry_sha256,
                trusted_manifest_sha256=acquisition_manifest_sha256,
            )
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def registry_entry_hash(source: dict[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json_bytes(source)).hexdigest()
