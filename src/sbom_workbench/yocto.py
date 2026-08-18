"""Fail-closed adapters for public Yocto reference build payloads.

This module deliberately has a separate profile from the synthetic MVP.  A
successful run is an engineering reference candidate, never manufacturer
evidence, product ground truth, a PRE-7 decision, or a conformity status.
"""

from __future__ import annotations

import configparser
import contextlib
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

from .evidence import UNKNOWN, EvidenceError, stable_id
from .manifest import canonical_json_bytes
from .validation import SPDX_CONTEXT_URI


class YoctoReferenceError(EvidenceError):
    """Raised when accepting input would weaken the reference boundary."""


SCHEMA_VERSION = "1.0"
GRAPH_PROFILE = "YOCTO_PUBLIC_REFERENCE_1.0"
CLASSIFICATION = "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE"
GENERATOR_STATUS = "GENERATOR_OUTPUT_CANDIDATE"
PRODUCT_STATUS = "NO_PRODUCT_CONFORMITY_STATUS"
GROUND_TRUTH_STATUS = "REFERENCE_NOT_GROUND_TRUTH"
ALLOWED_ORIGIN = "https://downloads.yoctoproject.org"
ADAPTER_VERSION = "1.0.0"

BUILD_ADAPTER = "yocto-spdx-3.0.1-build-metadata"
ARTIFACT_ADAPTER = "rootfs-tar-artifact-observation"
BUILD_DOMAIN = "BUILD_METADATA"
ARTIFACT_DOMAIN = "ARTIFACT_OBSERVATION"
PAYLOAD_ROLES = frozenset(
    {"build_spdx", "rootfs_archive", "image_manifest", "testdata", "qemuboot"}
)
INCLUDED_SCOPE = frozenset(
    {"INSTALLED_PACKAGES", "ROOTFS_REGULAR_FILES", "ROOTFS_SYMLINKS"}
)
STATUSES = ("MATCHED", "CONFLICT", "MISSING_FROM_SBOM", "NOT_IN_RELEASE", "UNKNOWN")

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SHA1_RE = re.compile(r"[0-9a-f]{40}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+~-]{0,255}")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TOP_KEYS = {
    "profile_id", "classification", "reference", "lanes", "payloads", "scope", "limits"
}
_REFERENCE_KEYS = {
    "upstream_release", "release_notes_url", "source_revisions", "image_name", "machine",
    "architecture", "build_timestamp", "build_id", "reference_builder", "release_timestamp",
}
_SOURCE_REVISION_KEYS = {"openembedded_core", "bitbake", "meta_yocto"}
_LANE_KEYS = {"lane_id", "adapter_id", "independence_domain"}
_PAYLOAD_KEYS = {"role", "url", "relative_path", "sha256", "max_bytes", "media_type"}
_SCOPE_KEYS = {"included", "declared_exclusions", "blindspots"}
_LIMIT_KEYS = {
    "max_json_bytes", "max_rootfs_files", "max_rootfs_expanded_bytes", "max_path_bytes",
    "zstd_timeout_seconds",
}
_GRAPH_KEYS = {
    "schema_version", "graph_profile", "classification", "generator_output_status",
    "product_conformity_status", "manufacturer_role", "ground_truth_status", "profile_id",
    "profile_sha256", "reference", "scope", "inputs", "evidence_objects", "lanes",
    "identity", "component_population", "relationships", "file_reconciliation",
    "reconciliation", "pre7_app1_status", "run_id", "canonical_sha256",
}


def _exact(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise YoctoReferenceError(
            f"{label} fields mismatch; missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise YoctoReferenceError(f"{label} must be an object")
    return value


def _text(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise YoctoReferenceError(f"{label} must be non-empty bounded text")
    if any(ord(character) < 0x20 for character in value):
        raise YoctoReferenceError(f"{label} contains control characters")
    return value


def _safe_id(value: object, label: str) -> str:
    result = _text(value, label, maximum=256)
    if not _SAFE_ID_RE.fullmatch(result):
        raise YoctoReferenceError(f"{label} is not a safe identifier")
    return result


def _sha256(value: object, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not _SHA256_RE.fullmatch(result):
        raise YoctoReferenceError(f"{label} must be a lowercase SHA-256")
    return result


def _bounded_int(value: object, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise YoctoReferenceError(f"{label} must be an integer in [{low}, {high}]")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > 10_000:
        raise YoctoReferenceError(f"{label} must be a bounded array")
    result = [_text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise YoctoReferenceError(f"{label} contains duplicates")
    return sorted(result, key=lambda item: item.encode("utf-8"))


def _relative_path(value: object, label: str) -> str:
    text = _text(value, label)
    if "\\" in text or "\x00" in text:
        raise YoctoReferenceError(f"{label} must be a safe POSIX relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or path.as_posix() != text or any(part in {"", ".", ".."} for part in path.parts):
        raise YoctoReferenceError(f"{label} must be a normalized relative path")
    return text


def _official_url(value: object, label: str) -> str:
    url = _text(value, label)
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise YoctoReferenceError(f"{label} is invalid") from exc
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme != "https" or parsed.hostname != "downloads.yoctoproject.org"
        or port not in (None, 443) or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or not decoded_path.startswith("/")
        or "\\" in decoded_path or "\x00" in decoded_path
        or any(part in {"", ".", ".."} for part in PurePosixPath(decoded_path).parts[1:])
    ):
        raise YoctoReferenceError(f"{label} must use the fixed {ALLOWED_ORIGIN} HTTPS origin")
    return url


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, maximum=20)
    if not _UTC_RE.fullmatch(text):
        raise YoctoReferenceError(f"{label} must be an ISO 8601 UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise YoctoReferenceError(f"{label} is not a valid timestamp") from exc
    return text


def validate_reference_profile(profile: object) -> dict[str, Any]:
    """Strictly validate and normalize one public Yocto reference profile."""

    value = _mapping(profile, "profile")
    _exact(value, _TOP_KEYS, "profile")
    if value["classification"] != CLASSIFICATION:
        raise YoctoReferenceError(f"profile.classification must be {CLASSIFICATION}")
    reference = _mapping(value["reference"], "profile.reference")
    _exact(reference, _REFERENCE_KEYS, "profile.reference")
    revisions = _mapping(reference["source_revisions"], "profile.reference.source_revisions")
    _exact(revisions, _SOURCE_REVISION_KEYS, "profile.reference.source_revisions")
    normalized_revisions: dict[str, str] = {}
    for key in sorted(_SOURCE_REVISION_KEYS):
        revision = _text(revisions[key], f"profile.reference.source_revisions.{key}", maximum=40)
        if not _SHA1_RE.fullmatch(revision):
            raise YoctoReferenceError(f"profile.reference.source_revisions.{key} must be lowercase SHA-1")
        normalized_revisions[key] = revision
    build_timestamp = _text(reference["build_timestamp"], "profile.reference.build_timestamp", maximum=14)
    if not re.fullmatch(r"\d{14}", build_timestamp):
        raise YoctoReferenceError("profile.reference.build_timestamp must contain 14 digits")
    release_timestamp = _timestamp(reference["release_timestamp"], "profile.reference.release_timestamp")
    if datetime.strptime(build_timestamp, "%Y%m%d%H%M%S").strftime("%Y-%m-%dT%H:%M:%SZ") != release_timestamp:
        raise YoctoReferenceError("profile reference timestamps do not identify the same build")
    normalized_reference = {
        "upstream_release": _text(reference["upstream_release"], "profile.reference.upstream_release"),
        "release_notes_url": _official_url(reference["release_notes_url"], "profile.reference.release_notes_url"),
        "source_revisions": normalized_revisions,
        "image_name": _safe_id(reference["image_name"], "profile.reference.image_name"),
        "machine": _safe_id(reference["machine"], "profile.reference.machine"),
        "architecture": _safe_id(reference["architecture"], "profile.reference.architecture"),
        "build_timestamp": build_timestamp,
        "build_id": _safe_id(reference["build_id"], "profile.reference.build_id"),
        "reference_builder": _text(reference["reference_builder"], "profile.reference.reference_builder"),
        "release_timestamp": release_timestamp,
    }

    lanes = _mapping(value["lanes"], "profile.lanes")
    _exact(lanes, {"build_metadata", "artifact_observation"}, "profile.lanes")
    normalized_lanes: dict[str, dict[str, str]] = {}
    lane_requirements = {
        "build_metadata": (BUILD_ADAPTER, BUILD_DOMAIN),
        "artifact_observation": (ARTIFACT_ADAPTER, ARTIFACT_DOMAIN),
    }
    for name, (adapter, domain) in lane_requirements.items():
        lane = _mapping(lanes[name], f"profile.lanes.{name}")
        _exact(lane, _LANE_KEYS, f"profile.lanes.{name}")
        normalized = {
            "lane_id": _safe_id(lane["lane_id"], f"profile.lanes.{name}.lane_id"),
            "adapter_id": _safe_id(lane["adapter_id"], f"profile.lanes.{name}.adapter_id"),
            "independence_domain": _text(lane["independence_domain"], f"profile.lanes.{name}.independence_domain"),
        }
        if normalized["adapter_id"] != adapter or normalized["independence_domain"] != domain:
            raise YoctoReferenceError(f"profile.lanes.{name} adapter/domain is not the fixed profile")
        normalized_lanes[name] = normalized
    if len({lane["lane_id"] for lane in normalized_lanes.values()}) != 2:
        raise YoctoReferenceError("profile lane IDs must be distinct")

    raw_payloads = value["payloads"]
    if not isinstance(raw_payloads, list) or len(raw_payloads) != len(PAYLOAD_ROLES):
        raise YoctoReferenceError("profile.payloads must contain exactly five payloads")
    normalized_payloads: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    for index, raw_payload in enumerate(raw_payloads):
        label = f"profile.payloads[{index}]"
        payload = _mapping(raw_payload, label)
        _exact(payload, _PAYLOAD_KEYS, label)
        role = _text(payload["role"], f"{label}.role", maximum=32)
        if role not in PAYLOAD_ROLES or role in seen_roles:
            raise YoctoReferenceError(f"{label}.role is unsupported or duplicated")
        seen_roles.add(role)
        path = _relative_path(payload["relative_path"], f"{label}.relative_path")
        if path in seen_paths:
            raise YoctoReferenceError("profile payload paths must be distinct")
        seen_paths.add(path)
        url = _official_url(payload["url"], f"{label}.url")
        if PurePosixPath(unquote(urlsplit(url).path)).name != PurePosixPath(path).name:
            raise YoctoReferenceError(f"{label} URL basename does not match relative_path")
        if role == "rootfs_archive" and not path.endswith((".tar", ".tar.zst")):
            raise YoctoReferenceError("rootfs_archive must be .tar or .tar.zst")
        expected_suffix = {
            "build_spdx": ".spdx.json", "image_manifest": ".manifest",
            "testdata": ".testdata.json", "qemuboot": ".qemuboot.conf",
        }.get(role)
        if expected_suffix and not path.endswith(expected_suffix):
            raise YoctoReferenceError(f"{role} has an unexpected filename")
        normalized_payloads.append(
            {
                "role": role, "url": url, "relative_path": path,
                "sha256": _sha256(payload["sha256"], f"{label}.sha256"),
                "max_bytes": _bounded_int(payload["max_bytes"], f"{label}.max_bytes", 1, 4 * 1024**3),
                "media_type": _text(payload["media_type"], f"{label}.media_type", maximum=128),
            }
        )
    if seen_roles != PAYLOAD_ROLES:
        raise YoctoReferenceError("profile payload role exact-set mismatch")

    scope = _mapping(value["scope"], "profile.scope")
    _exact(scope, _SCOPE_KEYS, "profile.scope")
    normalized_scope = {
        "included": _string_list(scope["included"], "profile.scope.included"),
        "declared_exclusions": _string_list(scope["declared_exclusions"], "profile.scope.declared_exclusions"),
        "blindspots": _string_list(scope["blindspots"], "profile.scope.blindspots"),
    }
    if set(normalized_scope["included"]) != INCLUDED_SCOPE:
        raise YoctoReferenceError("profile.scope.included exact-set mismatch")
    limits = _mapping(value["limits"], "profile.limits")
    _exact(limits, _LIMIT_KEYS, "profile.limits")
    normalized_limits = {
        "max_json_bytes": _bounded_int(limits["max_json_bytes"], "profile.limits.max_json_bytes", 1024, 512 * 1024**2),
        "max_rootfs_files": _bounded_int(limits["max_rootfs_files"], "profile.limits.max_rootfs_files", 1, 1_000_000),
        "max_rootfs_expanded_bytes": _bounded_int(limits["max_rootfs_expanded_bytes"], "profile.limits.max_rootfs_expanded_bytes", 1, 32 * 1024**3),
        "max_path_bytes": _bounded_int(limits["max_path_bytes"], "profile.limits.max_path_bytes", 64, 16_384),
        "zstd_timeout_seconds": _bounded_int(limits["zstd_timeout_seconds"], "profile.limits.zstd_timeout_seconds", 1, 900),
    }
    return {
        "profile_id": _safe_id(value["profile_id"], "profile.profile_id"),
        "classification": CLASSIFICATION,
        "reference": normalized_reference,
        "lanes": normalized_lanes,
        "payloads": sorted(normalized_payloads, key=lambda item: item["role"]),
        "scope": normalized_scope,
        "limits": normalized_limits,
    }


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise YoctoReferenceError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def load_profile_registry(path: Path | str) -> list[dict[str, Any]]:
    """Load a strict registry and return profiles sorted by profile ID."""

    source = Path(path)
    info = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024**2:
        raise YoctoReferenceError("profile registry must be a bounded single-link regular file")
    try:
        value = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except YoctoReferenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise YoctoReferenceError("profile registry is not strict UTF-8 JSON") from exc
    registry = _mapping(value, "profile registry")
    _exact(registry, {"schema_version", "profiles"}, "profile registry")
    if registry["schema_version"] != SCHEMA_VERSION:
        raise YoctoReferenceError("profile registry schema_version is unsupported")
    if not isinstance(registry["profiles"], list) or not registry["profiles"]:
        raise YoctoReferenceError("profile registry profiles must be non-empty")
    profiles = [validate_reference_profile(item) for item in registry["profiles"]]
    ids = [item["profile_id"] for item in profiles]
    if len(ids) != len(set(ids)):
        raise YoctoReferenceError("profile registry contains duplicate profile IDs")
    return sorted(profiles, key=lambda item: item["profile_id"].encode("utf-8"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _safe_destination(root: Path, relative_path: str) -> Path:
    if root.exists() and root.is_symlink():
        raise YoctoReferenceError("destination root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    current = root
    parts = PurePosixPath(relative_path).parts
    for part in parts[:-1]:
        current = current / part
        if current.exists():
            if current.is_symlink() or not current.is_dir():
                raise YoctoReferenceError("payload destination parent is unsafe")
        else:
            current.mkdir(mode=0o700)
    target = current / parts[-1]
    if target.exists() or target.is_symlink():
        raise YoctoReferenceError(f"refusing overwrite: {relative_path}")
    return target


def acquire_profile(profile: object, destination: Path | str) -> dict[str, Any]:
    """Acquire all registered payloads with no proxies, redirects, or overwrite."""

    normalized = validate_reference_profile(profile)
    root = Path(destination)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    acquired: list[dict[str, Any]] = []
    for payload in normalized["payloads"]:
        target = _safe_destination(root, payload["relative_path"])
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        digest = hashlib.sha256()
        size = 0
        try:
            request = urllib.request.Request(
                payload["url"], headers={"Accept-Encoding": "identity", "User-Agent": "sbom-workbench/yocto-reference-1"}
            )
            with opener.open(request, timeout=60) as response, temporary.open("xb") as output:
                if getattr(response, "status", 200) != 200 or response.geturl() != payload["url"]:
                    raise YoctoReferenceError("official payload response changed origin or status")
                if response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                    raise YoctoReferenceError("encoded HTTP payloads are forbidden")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > payload["max_bytes"]):
                    raise YoctoReferenceError("official payload Content-Length exceeds its limit")
                while True:
                    chunk = response.read(min(1024 * 1024, payload["max_bytes"] - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > payload["max_bytes"]:
                        raise YoctoReferenceError("official payload exceeds its streaming byte limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            observed = digest.hexdigest()
            if observed != payload["sha256"]:
                raise YoctoReferenceError(
                    f"payload SHA-256 mismatch for {payload['role']}; expected {payload['sha256']}, got {observed}"
                )
            os.link(temporary, target, follow_symlinks=False)
            temporary.unlink()
            acquired.append({**payload, "size": size, "observed_sha256": observed})
        except YoctoReferenceError:
            raise
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise YoctoReferenceError(f"official payload acquisition failed for {payload['role']}") from exc
        finally:
            with contextlib.suppress(OSError):
                temporary.unlink()
    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": normalized["profile_id"],
        "profile_sha256": hashlib.sha256(canonical_json_bytes(normalized)).hexdigest(),
        "origin_policy": "FIXED_HTTPS_DOWNLOADS_YOCTOPROJECT_ORG_NO_REDIRECT_NO_PROXY",
        "overwrite_policy": "CREATE_ONLY",
        "payloads": acquired,
    }


def _safe_input(root: Path, relative_path: str, maximum: int) -> tuple[Path, int]:
    if root.is_symlink():
        raise YoctoReferenceError("input root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise YoctoReferenceError("input root must be a directory")
    current = root
    for index, part in enumerate(PurePosixPath(relative_path).parts):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise YoctoReferenceError(f"symlink input is forbidden: {relative_path}")
        if index < len(PurePosixPath(relative_path).parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise YoctoReferenceError(f"input parent is not a directory: {relative_path}")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise YoctoReferenceError(f"input is not an admissible bounded regular file: {relative_path}")
    return current, info.st_size


def _read_payload(root: Path, payload: dict[str, Any], *, materialize: bool) -> tuple[bytes | None, dict[str, Any], Path]:
    path, declared_size = _safe_input(root, payload["relative_path"], payload["max_bytes"])
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    snapshot_path: Path | None = None
    snapshot_handle = None
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise YoctoReferenceError(f"cannot safely open payload: {payload['role']}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != declared_size
            or info.st_size > payload["max_bytes"]
        ):
            raise YoctoReferenceError(f"payload identity changed before read: {payload['role']}")
        if not materialize:
            snapshot_descriptor, snapshot_name = tempfile.mkstemp(
                prefix="sbom-yocto-payload-", suffix=".snapshot"
            )
            snapshot_path = Path(snapshot_name)
            snapshot_handle = os.fdopen(snapshot_descriptor, "wb")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > payload["max_bytes"]:
                    raise YoctoReferenceError(f"payload exceeds limit: {payload['role']}")
                digest.update(chunk)
                if materialize:
                    chunks.append(chunk)
                else:
                    assert snapshot_handle is not None
                    snapshot_handle.write(chunk)
        if snapshot_handle is not None:
            snapshot_handle.flush()
            os.fsync(snapshot_handle.fileno())
            snapshot_handle.close()
            snapshot_handle = None
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if snapshot_handle is not None:
            snapshot_handle.close()
        if snapshot_path is not None:
            with contextlib.suppress(OSError):
                snapshot_path.unlink()
        raise
    observed = digest.hexdigest()
    if observed != payload["sha256"] or size != declared_size:
        if snapshot_path is not None:
            with contextlib.suppress(OSError):
                snapshot_path.unlink()
        raise YoctoReferenceError(
            f"payload SHA-256 mismatch for {payload['role']}; expected {payload['sha256']}, got {observed}"
        )
    identity = {
        "role": payload["role"], "relative_path": payload["relative_path"], "url": payload["url"],
        "sha256": observed, "size": size, "media_type": payload["media_type"],
    }
    return (b"".join(chunks) if materialize else None), identity, (snapshot_path or path)


def snapshot_profile_inputs(
    profile: object, input_root: Path | str, destination: Path | str
) -> dict[str, Any]:
    """Copy hash-verified inputs into a create-only private evidence snapshot."""

    normalized = validate_reference_profile(profile)
    source_root = Path(input_root)
    destination_root = Path(destination)
    if destination_root.exists() and destination_root.is_symlink():
        raise YoctoReferenceError("input snapshot destination must not be a symlink")
    destination_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    created: list[Path] = []
    identities: list[dict[str, Any]] = []
    try:
        for payload in normalized["payloads"]:
            _, identity, snapshot = _read_payload(source_root, payload, materialize=False)
            try:
                target = _safe_destination(destination_root, payload["relative_path"])
                with snapshot.open("rb") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(target, 0o400)
                created.append(target)
                identities.append(identity)
            finally:
                with contextlib.suppress(OSError):
                    snapshot.unlink()
    except BaseException:
        for target in reversed(created):
            with contextlib.suppress(OSError):
                target.unlink()
        raise
    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": normalized["profile_id"],
        "profile_sha256": hashlib.sha256(canonical_json_bytes(normalized)).hexdigest(),
        "snapshot_policy": "CREATE_ONLY_HASH_VERIFIED_PRIVATE_COPY",
        "inputs": sorted(identities, key=lambda item: item["role"]),
    }


def _json_payload(payload: bytes, label: str, maximum: int) -> dict[str, Any]:
    if len(payload) > maximum:
        raise YoctoReferenceError(f"{label} exceeds JSON limit")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except YoctoReferenceError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise YoctoReferenceError(f"{label} is not strict UTF-8 JSON") from exc
    return _mapping(value, label)


def _normalize_tar_path(raw: object, label: str, maximum: int) -> str | None:
    value = _text(raw, label, maximum=maximum)
    while value.startswith("./"):
        value = value[2:]
    if value in {"", "."}:
        return None
    if "\\" in value or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise YoctoReferenceError(f"{label} is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise YoctoReferenceError(f"{label} contains path traversal")
    return path.as_posix()


def _zstd_executable() -> str:
    """Resolve the system zstd binary used to decompress Yocto rootfs layers.

    ACQ-1 / GOV-05 (known PARTIAL): zstd is a system binary resolved by path
    and is NOT hash-pinned or registered in a runtime registry, unlike the
    Syft scanner. The reference graph cannot bind rootfs decompression to a
    fixed zstd digest, and recording the host zstd sha256 in the graph would
    break cross-machine determinism (different hosts have different zstd
    builds). Closing this gap requires a controlled zstd acquisition + runtime
    registry flow analogous to Syft; until then cross-machine zstd identity is
    an OPEN provenance assumption, not a verified binding.
    """
    for candidate in ("/opt/homebrew/bin/zstd", "/usr/local/bin/zstd", "/usr/bin/zstd"):
        try:
            resolved = Path(candidate).resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    raise YoctoReferenceError("controlled zstd executable is unavailable")


def _decompress_zstd(source: Path, output: Path, limits: dict[str, int]) -> None:
    command = [_zstd_executable(), "-d", "--stdout", "--quiet", "--no-progress", "--", str(source)]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + limits["zstd_timeout_seconds"]
    cap = limits["max_rootfs_expanded_bytes"] + limits["max_rootfs_files"] * 2048 + 10 * 1024**2
    written = 0
    stderr = bytearray()
    try:
        with output.open("xb") as handle:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise YoctoReferenceError("controlled zstd decompression timed out")
                events = selector.select(min(0.5, remaining))
                if not events and process.poll() is not None:
                    events = [(key, selectors.EVENT_READ) for key in list(selector.get_map().values())]
                for key, _ in events:
                    chunk = os.read(key.fd, 1024 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.data == "stdout":
                        written += len(chunk)
                        if written > cap:
                            raise YoctoReferenceError("decompressed tar stream exceeds its limit")
                        handle.write(chunk)
                    elif len(stderr) < 16_384:
                        stderr.extend(chunk[: 16_384 - len(stderr)])
            handle.flush()
            os.fsync(handle.fileno())
        if process.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
            raise YoctoReferenceError(f"controlled zstd failed: {stderr.decode('utf-8', 'replace')[:512]}")
    except BaseException:
        process.kill()
        with contextlib.suppress(Exception):
            process.wait(timeout=5)
        raise
    finally:
        selector.close()


@contextlib.contextmanager
def _plain_tar(path: Path, relative_path: str, limits: dict[str, int]) -> Iterator[Path]:
    if relative_path.endswith(".tar"):
        yield path
        return
    temporary = Path(tempfile.mkstemp(prefix="sbom-yocto-rootfs-", suffix=".tar")[1])
    temporary.unlink()
    try:
        _decompress_zstd(path, temporary, limits)
        yield temporary
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _observe_rootfs(path: Path, relative_path: str, limits: dict[str, int]) -> dict[str, Any]:
    regular: list[dict[str, Any]] = []
    symlinks: list[dict[str, str]] = []
    seen: set[str] = set()
    entry_count = 0
    expanded = 0
    with _plain_tar(path, relative_path, limits) as tar_path:
        try:
            archive = tarfile.open(tar_path, mode="r:")
        except (OSError, tarfile.TarError) as exc:
            raise YoctoReferenceError("rootfs payload is not a valid tar archive") from exc
        with archive:
            try:
                for member in archive:
                    normalized = _normalize_tar_path(member.name, "rootfs member path", limits["max_path_bytes"])
                    if normalized is None:
                        if not member.isdir():
                            raise YoctoReferenceError("root tar member must be a directory")
                        continue
                    entry_count += 1
                    if entry_count > limits["max_rootfs_files"]:
                        raise YoctoReferenceError("rootfs member count exceeds its limit")
                    if normalized in seen:
                        raise YoctoReferenceError(f"duplicate rootfs member path: {normalized}")
                    seen.add(normalized)
                    if member.isdir():
                        continue
                    if member.isreg():
                        expanded += member.size
                        if member.size < 0 or expanded > limits["max_rootfs_expanded_bytes"]:
                            raise YoctoReferenceError("rootfs expanded regular-file bytes exceed limit")
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise YoctoReferenceError(f"cannot stream rootfs member: {normalized}")
                        digest = hashlib.sha256()
                        observed_size = 0
                        with stream:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                observed_size += len(chunk)
                                digest.update(chunk)
                        if observed_size != member.size:
                            raise YoctoReferenceError(f"rootfs member size mismatch: {normalized}")
                        regular.append({"path": normalized, "sha256": digest.hexdigest(), "size": observed_size})
                    elif member.issym():
                        target = _text(member.linkname, f"rootfs symlink target {normalized}", maximum=limits["max_path_bytes"])
                        if len(target.encode("utf-8")) > limits["max_path_bytes"]:
                            raise YoctoReferenceError("rootfs symlink target exceeds limit")
                        symlinks.append({"path": normalized, "target": target})
                    else:
                        raise YoctoReferenceError(f"hardlink or special rootfs member is forbidden: {normalized}")
            except (OSError, tarfile.TarError) as exc:
                raise YoctoReferenceError("rootfs archive read failed") from exc
    regular.sort(key=lambda item: item["path"].encode("utf-8"))
    symlinks.sort(key=lambda item: item["path"].encode("utf-8"))
    return {
        "entry_count": entry_count, "regular_file_count": len(regular), "symlink_count": len(symlinks),
        "expanded_regular_bytes": expanded,
        "regular_exact_set_sha256": hashlib.sha256(canonical_json_bytes(regular)).hexdigest(),
        "symlink_exact_set_sha256": hashlib.sha256(canonical_json_bytes(symlinks)).hexdigest(),
        "regular_files": regular, "symlinks": symlinks,
    }


def _manifest_packages(payload: bytes) -> list[dict[str, str]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise YoctoReferenceError("image manifest is not UTF-8") from exc
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3:
            raise YoctoReferenceError(f"image manifest line {number} must have package architecture version")
        name, architecture, version = (
            _text(parts[0], f"manifest line {number} package", maximum=512),
            _text(parts[1], f"manifest line {number} architecture", maximum=256),
            _text(parts[2], f"manifest line {number} version", maximum=512),
        )
        if name in seen:
            raise YoctoReferenceError(f"image manifest contains duplicate package {name}")
        seen.add(name)
        packages.append({"name": name, "architecture": architecture, "version": version})
    if not packages:
        raise YoctoReferenceError("image manifest has no installed packages")
    return sorted(packages, key=lambda item: item["name"].encode("utf-8"))


def _qemuboot_identity(payload: bytes, reference: dict[str, Any]) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise YoctoReferenceError("qemuboot is not UTF-8") from exc
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise YoctoReferenceError("qemuboot is not strict INI") from exc
    if set(parser.sections()) != {"config_bsp"}:
        raise YoctoReferenceError("qemuboot must contain only config_bsp")
    section = parser["config_bsp"]
    expected = {
        "machine": reference["machine"],
        "image_name": reference["build_id"],
        "image_link_name": f"{reference['image_name']}-{reference['machine']}.rootfs",
        "tune_arch": reference["architecture"].split("-", 1)[0],
    }
    for key, value in expected.items():
        if section.get(key) != value:
            raise YoctoReferenceError(f"qemuboot {key} does not match the profile")
    return expected


def _build_identity(
    manifest: bytes, testdata: dict[str, Any], qemuboot: bytes, reference: dict[str, Any]
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    packages = _manifest_packages(manifest)
    expected = {
        "MACHINE": reference["machine"],
        "TARGET_SYS": reference["architecture"],
        "IMAGE_BASENAME": reference["image_name"],
        "BUILDNAME": reference["build_timestamp"],
        "DATETIME": reference["build_timestamp"],
        "DISTRO_VERSION": reference["upstream_release"].removeprefix("yocto-"),
        "IMAGE_NAME": reference["build_id"],
        "METADATA_REVISION": reference["source_revisions"]["openembedded_core"],
    }
    for key, expected_value in expected.items():
        if testdata.get(key) != expected_value:
            raise YoctoReferenceError(f"testdata {key} does not match the profile")
    qemu = _qemuboot_identity(qemuboot, reference)
    return packages, {
        "manifest_package_count": len(packages),
        "testdata": {key: expected[key] for key in sorted(expected)},
        "qemuboot": qemu,
        "identity_status": "PROFILE_IDENTITY_MATCHED",
    }


def _spdx_id(item: dict[str, Any], label: str) -> str:
    identifier = item.get("spdxId", item.get("@id"))
    return _text(identifier, label, maximum=4096)


def _hash_from_verified_using(value: object, label: str) -> str:
    if value is None:
        return UNKNOWN
    if not isinstance(value, list):
        raise YoctoReferenceError(f"{label} must be an array")
    hashes: set[str] = set()
    for index, item in enumerate(value):
        record = _mapping(item, f"{label}[{index}]")
        algorithm = record.get("algorithm")
        candidate = record.get("hashValue")
        if isinstance(algorithm, str) and algorithm.lower().replace("-", "") == "sha256":
            hashes.add(_sha256(candidate, f"{label}[{index}].hashValue"))
    if len(hashes) > 1:
        raise YoctoReferenceError(f"{label} contains conflicting SHA-256 values")
    return next(iter(hashes), UNKNOWN)


def _adapt_spdx(
    document: dict[str, Any], limits: dict[str, int], reference: dict[str, Any]
) -> dict[str, Any]:
    _exact(document, {"@context", "@graph"}, "native SPDX")
    if document["@context"] != SPDX_CONTEXT_URI:
        raise YoctoReferenceError("native SPDX context is not SPDX 3.0.1")
    raw_graph = document["@graph"]
    if not isinstance(raw_graph, list) or not raw_graph or len(raw_graph) > limits["max_rootfs_files"] * 20:
        raise YoctoReferenceError("native SPDX graph is empty or exceeds the profile limit")
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw_item in enumerate(raw_graph):
        item = _mapping(raw_item, f"native SPDX @graph[{index}]")
        if "spdxId" not in item and "@id" not in item:
            continue
        identifier = _spdx_id(item, f"native SPDX @graph[{index}] ID")
        if identifier in by_id:
            raise YoctoReferenceError(f"native SPDX contains duplicate ID {identifier}")
        by_id[identifier] = item

    packages: list[dict[str, Any]] = []
    package_by_id: dict[str, dict[str, Any]] = {}
    root_archive_ids: set[str] = set()
    agents = {
        identifier: item
        for identifier, item in by_id.items()
        if item.get("type") in {"Organization", "Person"}
    }
    for identifier, item in by_id.items():
        if (
            item.get("type") == "software_Package"
            and item.get("software_primaryPurpose") == "archive"
            and item.get("name") == reference["image_name"]
        ):
            root_archive_ids.add(identifier)
        if item.get("type") != "software_Package" or item.get("software_primaryPurpose") != "install":
            continue
        name = _text(item.get("name"), f"installed package {identifier}.name", maximum=512)
        version_raw = item.get("software_packageVersion")
        version = UNKNOWN if version_raw is None else _text(version_raw, f"installed package {identifier}.version", maximum=512)
        identifiers: set[str] = set()
        purl = item.get("software_packageUrl")
        if isinstance(purl, str) and purl:
            identifiers.add(_text(purl, f"installed package {identifier}.purl"))
        external = item.get("externalIdentifier", [])
        if not isinstance(external, list):
            raise YoctoReferenceError(f"installed package {identifier}.externalIdentifier must be an array")
        for external_item in external:
            external_record = _mapping(external_item, f"installed package {identifier}.externalIdentifier")
            candidate = external_record.get("identifier")
            if isinstance(candidate, str) and candidate:
                identifiers.add(_text(candidate, f"installed package {identifier}.externalIdentifier.identifier"))
        supplier = item.get("suppliedBy")
        producer = UNKNOWN
        producer_evidenced = False
        if isinstance(supplier, str) and supplier in agents:
            agent_name = agents[supplier].get("name")
            if isinstance(agent_name, str) and agent_name:
                producer = _text(agent_name, f"installed package {identifier}.suppliedBy.name")
                producer_evidenced = True
        package = {
            "source_id": identifier,
            "name": name,
            "version": version,
            "producer": producer,
            "producer_evidenced": producer_evidenced,
            "identifiers": sorted(identifiers, key=lambda item: item.encode("utf-8")) or [UNKNOWN],
            "file_ids": [],
        }
        packages.append(package)
        package_by_id[identifier] = package
    if not packages:
        raise YoctoReferenceError("native SPDX contains no software_primaryPurpose=install packages")

    files: dict[str, dict[str, Any]] = {}
    for identifier, item in by_id.items():
        if item.get("type") != "software_File":
            continue
        path = _normalize_tar_path(item.get("name"), f"native SPDX file {identifier}.name", limits["max_path_bytes"])
        if path is None:
            raise YoctoReferenceError("native SPDX rootfs file path is empty")
        files[identifier] = {
            "path": path,
            "sha256": _hash_from_verified_using(item.get("verifiedUsing"), f"native SPDX file {identifier}.verifiedUsing"),
        }

    dependencies: set[tuple[str, str]] = set()
    root_file_ids: set[str] = set()
    for identifier, item in by_id.items():
        if item.get("type") not in {"Relationship", "LifecycleScopedRelationship"}:
            continue
        source = item.get("from")
        targets = item.get("to", [])
        relation = item.get("relationshipType")
        if not isinstance(source, str) or not isinstance(targets, list) or any(not isinstance(target, str) for target in targets):
            continue
        if source in package_by_id and relation in {"contains", "hasPart"}:
            package_by_id[source]["file_ids"].extend(target for target in targets if target in files)
        if source in root_archive_ids and relation in {"contains", "hasPart"}:
            root_file_ids.update(target for target in targets if target in files)
        if source in package_by_id and relation == "dependsOn" and item.get("scope") in {None, "runtime"}:
            dependencies.update((source, target) for target in targets if target in package_by_id)

    owners_by_file_id: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        package["file_ids"] = sorted(set(package["file_ids"]), key=lambda item: item.encode("utf-8"))
        for file_id in package["file_ids"]:
            owners_by_file_id[file_id].add(package["source_id"])
    if len(root_archive_ids) != 1 or not root_file_ids:
        raise YoctoReferenceError("native SPDX must contain one image archive package with rootfs files")
    expected_by_path: dict[str, dict[str, Any]] = {}
    for file_id in root_file_ids:
        file = files[file_id]
        current = expected_by_path.setdefault(
            file["path"], {"path": file["path"], "sha256_values": set(), "owner_source_ids": set()}
        )
        current["sha256_values"].add(file["sha256"])
        current["owner_source_ids"].update(owners_by_file_id[file_id])
    expected_files: list[dict[str, Any]] = []
    for path, item in expected_by_path.items():
        concrete = {value for value in item["sha256_values"] if value != UNKNOWN}
        if len(concrete) > 1:
            raise YoctoReferenceError(f"native SPDX has conflicting hashes for rootfs path {path}")
        expected_files.append(
            {
                "path": path,
                "sha256": next(iter(concrete), UNKNOWN),
                "owner_source_ids": sorted(item["owner_source_ids"], key=lambda value: value.encode("utf-8")),
            }
        )
    packages.sort(key=lambda item: (item["name"].encode("utf-8"), item["source_id"].encode("utf-8")))
    expected_files.sort(key=lambda item: item["path"].encode("utf-8"))
    return {
        "packages": packages,
        "expected_regular_files": expected_files,
        "runtime_dependencies": [
            {"from_source_id": source, "to_source_id": target}
            for source, target in sorted(dependencies)
        ],
    }


def _evidence_object(identity: dict[str, Any], lane: dict[str, str]) -> dict[str, Any]:
    body = {
        "role": identity["role"], "relative_path": identity["relative_path"],
        "sha256": identity["sha256"], "lane_id": lane["lane_id"],
        "adapter_id": lane["adapter_id"], "adapter_version": ADAPTER_VERSION,
        "independence_domain": lane["independence_domain"],
    }
    hash_kind = "RELEASE_ARTIFACT_HASH" if identity["role"] == "rootfs_archive" else "BUILD_OBSERVED_HASH"
    return {
        "evidence_id": stable_id("yocto-evidence", body), **body, "url": identity["url"],
        "size": identity["size"], "media_type": identity["media_type"], "hash_kind": hash_kind,
    }


def _finding(kind: str, identity: dict[str, Any]) -> dict[str, Any]:
    body = {"finding_type": kind, **identity}
    return {"finding_id": stable_id("yocto-finding", body), **body}


def _build_population(
    manifest: list[dict[str, str]], spdx: dict[str, Any], build_evidence: str,
    manifest_evidence: str, artifact_evidence: str,
    reference: dict[str, Any], lanes: dict[str, dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    spdx_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for package in spdx["packages"]:
        spdx_by_name[package["name"]].append(package)
    manifest_names = {item["name"] for item in manifest}
    findings: list[dict[str, Any]] = []
    population: list[dict[str, Any]] = []
    source_to_population: dict[str, str] = {}
    root_id = stable_id("population", {"kind": "REFERENCE_IMAGE_ROOT", "build_id": reference["build_id"]})
    population.append(
        {
            "population_id": root_id, "kind": "REFERENCE_IMAGE_ROOT", "producer": UNKNOWN,
            "name": reference["image_name"], "version": reference["upstream_release"],
            "architecture": reference["architecture"],
            "identifiers": [f"urn:yocto-reference:{reference['build_id']}"],
            "roles": ["REFERENCE_IMAGE_ROOT"],
            "discovery_lanes": sorted([lanes["build_metadata"]["lane_id"], lanes["artifact_observation"]["lane_id"]]),
            "evidence_ids": sorted([build_evidence, artifact_evidence]), "producer_evidence_ids": [],
            "file_paths": [], "critical_unknown_fields": [],
        }
    )
    for manifest_package in manifest:
        matches = spdx_by_name.get(manifest_package["name"], [])
        match = matches[0] if len(matches) == 1 else None
        if not matches:
            status, details = "MISSING_FROM_SBOM", ["installed_package"]
        elif len(matches) > 1:
            status, details = "UNKNOWN", ["ambiguous_native_spdx_identity"]
        else:
            status, details = "MATCHED", (
                ["MANIFEST_PKGV_AND_NATIVE_SPDX_PV_HAVE_DIFFERENT_VERSION_SEMANTICS"]
                if match["version"] not in {UNKNOWN, manifest_package["version"]}
                else []
            )
        component_identity = {
            "kind": "RUNTIME_PACKAGE", "name": manifest_package["name"],
            "architecture": manifest_package["architecture"],
        }
        population_id = stable_id("population", component_identity)
        evidence_ids = sorted([build_evidence, manifest_evidence])
        identifiers = [
            f"urn:yocto-manifest:{manifest_package['architecture']}:{manifest_package['name']}:{manifest_package['version']}"
        ]
        producer = UNKNOWN
        producer_evidence_ids: list[str] = []
        file_paths: list[str] = []
        if match is not None:
            source_to_population[match["source_id"]] = population_id
            identifiers.extend(identifier for identifier in match["identifiers"] if identifier != UNKNOWN)
            producer = match["producer"]
            if match["producer_evidenced"]:
                producer_evidence_ids = [build_evidence]
            file_paths = sorted(
                {
                    file["path"]
                    for file in spdx["expected_regular_files"]
                    if match["source_id"] in file["owner_source_ids"]
                },
                key=lambda value: value.encode("utf-8"),
            )
        findings.append(
            _finding(
                "COMPONENT_IDENTITY",
                {
                    "population_id": population_id, "candidate_source_id": match["source_id"] if match else None,
                    "status": status, "details": details,
                    "evidence_ids": sorted([build_evidence, manifest_evidence]),
                },
            )
        )
        if producer == UNKNOWN:
            findings.append(
                _finding(
                    "COMPONENT_FIELD",
                    {"population_id": population_id, "field": "producer", "status": "UNKNOWN",
                     "details": ["NO_PER_COMPONENT_PRODUCER_EVIDENCE"],
                     "evidence_ids": sorted([build_evidence, manifest_evidence])},
                )
            )
        population.append(
            {
                "population_id": population_id, "kind": "RUNTIME_PACKAGE", "producer": producer,
                "name": manifest_package["name"], "version": manifest_package["version"],
                "architecture": manifest_package["architecture"],
                "identifiers": sorted(set(identifiers), key=lambda value: value.encode("utf-8")),
                "roles": ["RUNTIME_PACKAGE"], "discovery_lanes": [lanes["build_metadata"]["lane_id"]],
                "evidence_ids": evidence_ids, "producer_evidence_ids": producer_evidence_ids,
                "file_paths": file_paths,
                "critical_unknown_fields": ["producer"] if producer == UNKNOWN else [],
            }
        )
    for package in spdx["packages"]:
        if package["name"] not in manifest_names:
            findings.append(
                _finding(
                    "COMPONENT_IDENTITY",
                    {"population_id": None, "candidate_source_id": package["source_id"],
                     "status": "NOT_IN_RELEASE", "details": [package["name"]], "evidence_ids": [build_evidence]},
                )
            )
    relationships: list[dict[str, Any]] = []
    for component in population[1:]:
        body = {
            "source_population_id": root_id, "relationship": "CONTAINS",
            "target_population_id": component["population_id"], "evidence_ids": component["evidence_ids"],
        }
        relationships.append({"relationship_id": stable_id("relationship", body), **body})
    for dependency in spdx["runtime_dependencies"]:
        source = source_to_population.get(dependency["from_source_id"])
        target = source_to_population.get(dependency["to_source_id"])
        if source and target:
            body = {"source_population_id": source, "relationship": "DEPENDS_ON", "target_population_id": target, "evidence_ids": [build_evidence]}
            relationships.append({"relationship_id": stable_id("relationship", body), **body})
    population.sort(key=lambda item: item["population_id"])
    relationships = sorted({item["relationship_id"]: item for item in relationships}.values(), key=lambda item: item["relationship_id"])
    return population, relationships, findings


def _reconcile_files(
    expected: list[dict[str, Any]], observed: list[dict[str, Any]], build_evidence: str, artifact_evidence: str,
) -> dict[str, Any]:
    expected_by_path = {item["path"]: item for item in expected}
    observed_by_path = {item["path"]: item for item in observed}
    findings: list[dict[str, Any]] = []
    for path in sorted(set(expected_by_path) | set(observed_by_path), key=lambda value: value.encode("utf-8")):
        build_file = expected_by_path.get(path)
        artifact_file = observed_by_path.get(path)
        if build_file is None:
            status, details, evidence = "MISSING_FROM_SBOM", ["path"], [artifact_evidence]
        elif artifact_file is None:
            status, details, evidence = "NOT_IN_RELEASE", ["path"], [build_evidence]
        elif build_file["sha256"] == UNKNOWN:
            status, details, evidence = "UNKNOWN", ["build_metadata_sha256"], [build_evidence, artifact_evidence]
        elif build_file["sha256"] != artifact_file["sha256"]:
            status, details, evidence = "CONFLICT", ["sha256"], [build_evidence, artifact_evidence]
        else:
            status, details, evidence = "MATCHED", [], [build_evidence, artifact_evidence]
        findings.append(
            _finding(
                "ROOTFS_FILE",
                {"path": path, "expected_sha256": build_file["sha256"] if build_file else None,
                 "observed_sha256": artifact_file["sha256"] if artifact_file else None,
                 "status": status, "details": details, "evidence_ids": sorted(evidence)},
            )
        )
    counts = {status: 0 for status in STATUSES}
    for finding in findings:
        counts[finding["status"]] += 1
    return {
        "expected_file_count": len(expected), "observed_file_count": len(observed),
        "expected_exact_set_sha256": hashlib.sha256(canonical_json_bytes(expected)).hexdigest(),
        "observed_exact_set_sha256": hashlib.sha256(canonical_json_bytes(observed)).hexdigest(),
        "counts": counts, "findings": findings,
    }


def _graph_run_id(graph: dict[str, Any]) -> str:
    return stable_id(
        "yocto-reference-run",
        {
            "profile_id": graph["profile_id"], "profile_sha256": graph["profile_sha256"],
            "inputs": graph["inputs"],
            "lanes": [
                {key: lane[key] for key in ("lane_id", "adapter_id", "adapter_version", "independence_domain", "evidence_ids")}
                for lane in graph["lanes"]
            ],
        },
    )


def _canonical_graph_sha256(graph: dict[str, Any]) -> str:
    projection = dict(graph)
    projection.pop("canonical_sha256", None)
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def analyze_reference(profile: object, input_root: Path | str) -> dict[str, Any]:
    """Analyze five frozen payloads into a deterministic public-reference graph."""

    normalized = validate_reference_profile(profile)
    root = Path(input_root)
    payload_by_role = {item["role"]: item for item in normalized["payloads"]}
    identities: dict[str, dict[str, Any]] = {}
    materialized: dict[str, bytes] = {}
    paths: dict[str, Path] = {}
    snapshots: list[Path] = []
    try:
        for role in sorted(PAYLOAD_ROLES):
            raw, identity, path = _read_payload(
                root, payload_by_role[role], materialize=role != "rootfs_archive"
            )
            identities[role] = identity
            paths[role] = path
            if role == "rootfs_archive":
                snapshots.append(path)
            if raw is not None:
                materialized[role] = raw
        testdata = _json_payload(
            materialized["testdata"], "testdata", normalized["limits"]["max_json_bytes"]
        )
        native_spdx = _json_payload(
            materialized["build_spdx"], "native SPDX", normalized["limits"]["max_json_bytes"]
        )
        manifest, identity = _build_identity(
            materialized["image_manifest"], testdata, materialized["qemuboot"], normalized["reference"]
        )
        spdx = _adapt_spdx(native_spdx, normalized["limits"], normalized["reference"])
        artifact = _observe_rootfs(
            paths["rootfs_archive"],
            payload_by_role["rootfs_archive"]["relative_path"],
            normalized["limits"],
        )
    finally:
        for snapshot in snapshots:
            with contextlib.suppress(OSError):
                snapshot.unlink()
    evidence: list[dict[str, Any]] = []
    build_lane = normalized["lanes"]["build_metadata"]
    artifact_lane = normalized["lanes"]["artifact_observation"]
    for role in sorted(PAYLOAD_ROLES):
        lane = artifact_lane if role == "rootfs_archive" else build_lane
        evidence.append(_evidence_object(identities[role], lane))
    evidence.sort(key=lambda item: item["evidence_id"])
    evidence_by_role = {item["role"]: item for item in evidence}
    build_evidence = evidence_by_role["build_spdx"]["evidence_id"]
    manifest_evidence = evidence_by_role["image_manifest"]["evidence_id"]
    artifact_evidence = evidence_by_role["rootfs_archive"]["evidence_id"]
    population, relationships, component_findings = _build_population(
        manifest, spdx, build_evidence, manifest_evidence, artifact_evidence,
        normalized["reference"], normalized["lanes"]
    )
    file_reconciliation = _reconcile_files(
        spdx["expected_regular_files"], artifact["regular_files"], build_evidence, artifact_evidence
    )
    findings = sorted(component_findings + file_reconciliation["findings"], key=lambda item: item["finding_id"])
    counts = {status: 0 for status in STATUSES}
    for finding in findings:
        counts[finding["status"]] += 1
    blocking = sorted(status for status in STATUSES if status != "MATCHED" and counts[status])
    state = "OPEN" if blocking else "CLOSED"
    graph: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "graph_profile": GRAPH_PROFILE,
        "classification": CLASSIFICATION, "generator_output_status": GENERATOR_STATUS,
        "product_conformity_status": PRODUCT_STATUS, "manufacturer_role": None,
        "ground_truth_status": GROUND_TRUTH_STATUS, "profile_id": normalized["profile_id"],
        "profile_sha256": hashlib.sha256(canonical_json_bytes(normalized)).hexdigest(),
        "reference": normalized["reference"], "scope": normalized["scope"],
        "inputs": sorted(identities.values(), key=lambda item: item["role"]),
        "evidence_objects": evidence,
        "lanes": [
            {
                **build_lane, "adapter_version": ADAPTER_VERSION,
                "evidence_ids": sorted(item["evidence_id"] for item in evidence if item["independence_domain"] == BUILD_DOMAIN),
                "coverage": ["INSTALLED_PACKAGES", "ROOTFS_REGULAR_FILES"],
                "manifest_packages": manifest,
                "native_spdx_packages": spdx["packages"],
                "runtime_dependencies": spdx["runtime_dependencies"],
                "version_semantics": {
                    "manifest": "INSTALLED_PKGV",
                    "native_spdx": "RECIPE_PV",
                    "comparison": "PRESERVED_SEPARATELY_NOT_EXACT_VERSION_EQUIVALENCE",
                },
                "regular_files": spdx["expected_regular_files"], "symlinks": [],
                "exact_set_sha256": hashlib.sha256(canonical_json_bytes(spdx["expected_regular_files"])).hexdigest(),
            },
            {
                **artifact_lane, "adapter_version": ADAPTER_VERSION,
                "evidence_ids": [artifact_evidence], "coverage": ["ROOTFS_REGULAR_FILES", "ROOTFS_SYMLINKS"],
                "manifest_packages": [], "native_spdx_packages": [], "runtime_dependencies": [],
                "version_semantics": {
                    "manifest": "NOT_APPLICABLE",
                    "native_spdx": "NOT_APPLICABLE",
                    "comparison": "ARTIFACT_OBSERVATION_HAS_NO_PACKAGE_VERSION_AUTHORITY",
                },
                "regular_files": artifact["regular_files"], "symlinks": artifact["symlinks"],
                "exact_set_sha256": artifact["regular_exact_set_sha256"],
            },
        ],
        "identity": identity, "component_population": population, "relationships": relationships,
        "file_reconciliation": file_reconciliation,
        "reconciliation": {
            "state": state,
            "technical_status": "REFERENCE_RECONCILIATION_OPEN" if state == "OPEN" else "REFERENCE_RECONCILIATION_CLOSED_NOT_GROUND_TRUTH",
            "counts": counts, "blocking_statuses": blocking, "findings": findings,
        },
        "pre7_app1_status": {
            "effective_obligation": "Not Assessed", "PRE-7-RQ-03-RE": "Not Assessed",
            "PRE-7-RQ-07-RE": "Not Assessed", "APP-1": "Not Assessed",
            "boundary": "NO_MANUFACTURER_PRODUCT_CONTEXT_OR_APP1_SOA_EXCHANGE",
        },
    }
    graph["lanes"].sort(key=lambda item: item["lane_id"])
    graph["run_id"] = _graph_run_id(graph)
    graph["canonical_sha256"] = _canonical_graph_sha256(graph)
    _verify_reference_graph_structure(graph)
    return graph


def _verify_reference_graph_structure(graph: object) -> dict[str, Any]:
    """Verify internal derivations; this does not authenticate the raw inputs."""

    value = _mapping(graph, "reference graph")
    _exact(value, _GRAPH_KEYS, "reference graph")
    fixed = {
        "schema_version": SCHEMA_VERSION, "graph_profile": GRAPH_PROFILE,
        "classification": CLASSIFICATION, "generator_output_status": GENERATOR_STATUS,
        "product_conformity_status": PRODUCT_STATUS, "ground_truth_status": GROUND_TRUTH_STATUS,
    }
    for key, expected in fixed.items():
        if value.get(key) != expected:
            raise YoctoReferenceError(f"reference graph {key} is invalid")
    if value.get("manufacturer_role") is not None:
        raise YoctoReferenceError("public reference graph must not claim a manufacturer role")
    if not _SHA256_RE.fullmatch(value.get("profile_sha256", "")):
        raise YoctoReferenceError("reference graph profile_sha256 is invalid")
    lanes = value.get("lanes")
    if not isinstance(lanes, list) or len(lanes) != 2:
        raise YoctoReferenceError("reference graph requires exactly two lanes")
    domains = {lane.get("independence_domain") for lane in lanes if isinstance(lane, dict)}
    adapters = {lane.get("adapter_id") for lane in lanes if isinstance(lane, dict)}
    if domains != {BUILD_DOMAIN, ARTIFACT_DOMAIN} or adapters != {BUILD_ADAPTER, ARTIFACT_ADAPTER}:
        raise YoctoReferenceError("reference graph lane independence domain is invalid")
    inputs = value.get("inputs")
    if not isinstance(inputs, list) or {item.get("role") for item in inputs if isinstance(item, dict)} != PAYLOAD_ROLES:
        raise YoctoReferenceError("reference graph input exact-set is invalid")
    evidence = value.get("evidence_objects")
    if not isinstance(evidence, list) or len(evidence) != 5:
        raise YoctoReferenceError("reference graph evidence exact-set is invalid")
    evidence_ids = {item.get("evidence_id") for item in evidence if isinstance(item, dict)}
    if len(evidence_ids) != 5 or None in evidence_ids:
        raise YoctoReferenceError("reference graph evidence identities are invalid")
    try:
        input_by_role = {item["role"]: item for item in inputs}
        evidence_by_role = {item["role"]: item for item in evidence}
        if len(input_by_role) != 5 or len(evidence_by_role) != 5:
            raise YoctoReferenceError("reference graph input/evidence roles are not unique")
        lane_by_domain = {lane["independence_domain"]: lane for lane in lanes}
        build_lane = lane_by_domain[BUILD_DOMAIN]
        artifact_lane = lane_by_domain[ARTIFACT_DOMAIN]
        for role in sorted(PAYLOAD_ROLES):
            item = evidence_by_role[role]
            source = input_by_role[role]
            expected_lane = artifact_lane if role == "rootfs_archive" else build_lane
            body = {
                "role": role,
                "relative_path": source["relative_path"],
                "sha256": source["sha256"],
                "lane_id": expected_lane["lane_id"],
                "adapter_id": expected_lane["adapter_id"],
                "adapter_version": ADAPTER_VERSION,
                "independence_domain": expected_lane["independence_domain"],
            }
            expected_evidence = {
                "evidence_id": stable_id("yocto-evidence", body),
                **body,
                "url": source["url"],
                "size": source["size"],
                "media_type": source["media_type"],
                "hash_kind": "RELEASE_ARTIFACT_HASH" if role == "rootfs_archive" else "BUILD_OBSERVED_HASH",
            }
            if item != expected_evidence:
                raise YoctoReferenceError(f"reference graph evidence projection changed for {role}")

        expected_build_evidence = sorted(
            evidence_by_role[role]["evidence_id"] for role in PAYLOAD_ROLES if role != "rootfs_archive"
        )
        if build_lane.get("evidence_ids") != expected_build_evidence:
            raise YoctoReferenceError("build lane evidence exact-set changed")
        if artifact_lane.get("evidence_ids") != [evidence_by_role["rootfs_archive"]["evidence_id"]]:
            raise YoctoReferenceError("artifact lane evidence exact-set changed")
        for lane in lanes:
            regular = lane.get("regular_files")
            if (
                not isinstance(regular, list)
                or lane.get("exact_set_sha256")
                != hashlib.sha256(canonical_json_bytes(regular)).hexdigest()
            ):
                raise YoctoReferenceError("reference graph lane exact-set hash mismatch")

        expected_version_semantics = {
            BUILD_DOMAIN: {
                "manifest": "INSTALLED_PKGV",
                "native_spdx": "RECIPE_PV",
                "comparison": "PRESERVED_SEPARATELY_NOT_EXACT_VERSION_EQUIVALENCE",
            },
            ARTIFACT_DOMAIN: {
                "manifest": "NOT_APPLICABLE",
                "native_spdx": "NOT_APPLICABLE",
                "comparison": "ARTIFACT_OBSERVATION_HAS_NO_PACKAGE_VERSION_AUTHORITY",
            },
        }
        for lane in lanes:
            if lane.get("version_semantics") != expected_version_semantics[lane["independence_domain"]]:
                raise YoctoReferenceError("reference graph version semantics changed")

        manifest_packages = build_lane.get("manifest_packages")
        native_packages = build_lane.get("native_spdx_packages")
        runtime_dependencies = build_lane.get("runtime_dependencies")
        build_regular_files = build_lane.get("regular_files")
        artifact_regular_files = artifact_lane.get("regular_files")
        if not all(
            isinstance(item, list)
            for item in (
                manifest_packages,
                native_packages,
                runtime_dependencies,
                build_regular_files,
                artifact_regular_files,
            )
        ):
            raise YoctoReferenceError("reference graph lane source projections are invalid")
        if (
            artifact_lane.get("manifest_packages") != []
            or artifact_lane.get("native_spdx_packages") != []
            or artifact_lane.get("runtime_dependencies") != []
            or build_lane.get("symlinks") != []
        ):
            raise YoctoReferenceError("reference graph lane authority boundary changed")
        lane_config = {
            "build_metadata": {"lane_id": build_lane["lane_id"]},
            "artifact_observation": {"lane_id": artifact_lane["lane_id"]},
        }
        spdx_projection = {
            "packages": native_packages,
            "expected_regular_files": build_regular_files,
            "runtime_dependencies": runtime_dependencies,
        }
        build_evidence = evidence_by_role["build_spdx"]["evidence_id"]
        manifest_evidence = evidence_by_role["image_manifest"]["evidence_id"]
        artifact_evidence = evidence_by_role["rootfs_archive"]["evidence_id"]
        expected_population, expected_relationships, component_findings = _build_population(
            manifest_packages,
            spdx_projection,
            build_evidence,
            manifest_evidence,
            artifact_evidence,
            value["reference"],
            lane_config,
        )
        if value.get("component_population") != expected_population:
            raise YoctoReferenceError("reference graph component population is not source-derived")
        if value.get("relationships") != expected_relationships:
            raise YoctoReferenceError("reference graph relationships are not source-derived")
        expected_file_reconciliation = _reconcile_files(
            build_regular_files, artifact_regular_files, build_evidence, artifact_evidence
        )
        if value.get("file_reconciliation") != expected_file_reconciliation:
            raise YoctoReferenceError("reference graph file reconciliation is not source-derived")
        expected_findings = sorted(
            component_findings + expected_file_reconciliation["findings"],
            key=lambda item: item["finding_id"],
        )
        counts = {status: 0 for status in STATUSES}
        for finding in expected_findings:
            counts[finding["status"]] += 1
        blocking = sorted(status for status in STATUSES if status != "MATCHED" and counts[status])
        state = "OPEN" if blocking else "CLOSED"
        technical = (
            "REFERENCE_RECONCILIATION_OPEN"
            if state == "OPEN"
            else "REFERENCE_RECONCILIATION_CLOSED_NOT_GROUND_TRUTH"
        )
        expected_reconciliation = {
            "state": state,
            "technical_status": technical,
            "counts": counts,
            "blocking_statuses": blocking,
            "findings": expected_findings,
        }
        if value.get("reconciliation") != expected_reconciliation:
            raise YoctoReferenceError("reference graph reconciliation is not source-derived")
        expected_identity = {
            "manifest_package_count": len(manifest_packages),
            "testdata": {
                key: expected
                for key, expected in sorted(
                    {
                        "MACHINE": value["reference"]["machine"],
                        "TARGET_SYS": value["reference"]["architecture"],
                        "IMAGE_BASENAME": value["reference"]["image_name"],
                        "BUILDNAME": value["reference"]["build_timestamp"],
                        "DATETIME": value["reference"]["build_timestamp"],
                        "DISTRO_VERSION": value["reference"]["upstream_release"].removeprefix("yocto-"),
                        "IMAGE_NAME": value["reference"]["build_id"],
                        "METADATA_REVISION": value["reference"]["source_revisions"]["openembedded_core"],
                    }.items()
                )
            },
            "qemuboot": {
                "machine": value["reference"]["machine"],
                "image_name": value["reference"]["build_id"],
                "image_link_name": f"{value['reference']['image_name']}-{value['reference']['machine']}.rootfs",
                "tune_arch": value["reference"]["architecture"].split("-", 1)[0],
            },
            "identity_status": "PROFILE_IDENTITY_MATCHED",
        }
        if value.get("identity") != expected_identity:
            raise YoctoReferenceError("reference graph build identity projection changed")
    except YoctoReferenceError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise YoctoReferenceError("reference graph source derivation is malformed") from exc
    if value.get("pre7_app1_status") != {
        "effective_obligation": "Not Assessed", "PRE-7-RQ-03-RE": "Not Assessed",
        "PRE-7-RQ-07-RE": "Not Assessed", "APP-1": "Not Assessed",
        "boundary": "NO_MANUFACTURER_PRODUCT_CONTEXT_OR_APP1_SOA_EXCHANGE",
    }:
        raise YoctoReferenceError("reference graph PRE-7/APP-1 boundary changed")
    if value.get("run_id") != _graph_run_id(value):
        raise YoctoReferenceError("reference graph run_id does not match its inputs")
    if value.get("canonical_sha256") != _canonical_graph_sha256(value):
        raise YoctoReferenceError("reference graph canonical hash does not match its content")
    return {
        "status": "INTERNAL_STRUCTURE_VERIFIED_NOT_RAW_INPUT_REDERIVED",
        "run_id": value["run_id"],
        "canonical_sha256": value["canonical_sha256"],
    }


def verify_reference_graph(
    graph: object,
    *,
    profile: object,
    input_root: Path | str,
) -> dict[str, Any]:
    """Re-derive a graph from a trusted profile and the declared raw input bytes."""

    value = _mapping(graph, "reference graph")
    _verify_reference_graph_structure(value)
    expected = analyze_reference(profile, input_root)
    if value != expected:
        raise YoctoReferenceError(
            "reference graph does not deterministically derive from the trusted raw inputs"
        )
    return {
        "status": "VERIFIED_REFERENCE_GRAPH_FROM_TRUSTED_RAW_INPUTS",
        "run_id": value["run_id"],
        "canonical_sha256": value["canonical_sha256"],
    }


def _root_component(graph: dict[str, Any]) -> dict[str, Any]:
    roots = [item for item in graph["component_population"] if item.get("kind") == "REFERENCE_IMAGE_ROOT"]
    if len(roots) != 1:
        raise YoctoReferenceError("reference graph must contain exactly one image root")
    return roots[0]


def _reference_uuid(graph: dict[str, Any], kind: str, identity: str) -> str:
    seed = f"{graph['run_id']}:{kind}:{identity}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _artifact_sha256(graph: dict[str, Any]) -> str:
    matches = [item["sha256"] for item in graph["inputs"] if item["role"] == "rootfs_archive"]
    if len(matches) != 1:
        raise YoctoReferenceError("reference rootfs artifact identity is missing")
    return matches[0]


def _source_binding(graph: dict[str, Any]) -> dict[str, str]:
    return {
        "build_id": graph["reference"]["build_id"],
        "canonical_sha256": graph["canonical_sha256"],
        "classification": graph["classification"],
        "release_artifact_sha256": _artifact_sha256(graph),
        "run_id": graph["run_id"],
    }


def _export_cyclonedx_reference(graph: dict[str, Any]) -> dict[str, Any]:
    root = _root_component(graph)
    reference_by_population = {
        component["population_id"]: _reference_uuid(graph, "component", component["population_id"])
        for component in graph["component_population"]
    }

    def component_record(component: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "type": "operating-system" if component["kind"] == "REFERENCE_IMAGE_ROOT" else "library",
            "bom-ref": reference_by_population[component["population_id"]],
            "name": component["name"],
            "version": component["version"],
            "properties": [
                {"name": "sbom-workbench:component-kind", "value": component["kind"]},
                {"name": "sbom-workbench:producer-evidence-status", "value": "UNKNOWN" if component["producer"] == UNKNOWN else "PER_COMPONENT_EVIDENCED"},
                *[
                    {"name": "sbom-workbench:identifier", "value": identifier}
                    for identifier in sorted(component["identifiers"], key=lambda value: value.encode("utf-8"))
                ],
                *[
                    {"name": "sbom-workbench:evidence-id", "value": evidence_id}
                    for evidence_id in component["evidence_ids"]
                ],
            ],
        }
        if component["producer"] != UNKNOWN:
            record["publisher"] = component["producer"]
        purls = sorted(
            item for item in component["identifiers"] if item.startswith("pkg:")
        )
        if purls:
            record["purl"] = purls[0]
        return record

    dependency_targets: dict[str, set[str]] = defaultdict(set)
    relationship_properties: list[dict[str, str]] = []
    for relationship in graph["relationships"]:
        source = reference_by_population[relationship["source_population_id"]]
        target = reference_by_population[relationship["target_population_id"]]
        if relationship["relationship"] in {"DEPENDS_ON", "CONTAINS"}:
            dependency_targets[source].add(target)
        relationship_properties.append(
            {"name": "sbom-workbench:relationship", "value": f"{source}|{relationship['relationship']}|{target}"}
        )
    binding = _source_binding(graph)
    all_refs = sorted(reference_by_population.values(), key=lambda item: item.encode("utf-8"))
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "serialNumber": _reference_uuid(graph, "bom", graph["profile_id"]), "version": 1,
        "metadata": {
            "timestamp": graph["reference"]["release_timestamp"],
            "authors": [{"name": "Offline SBOM Evidence Workbench candidate generator"}],
            "component": component_record(root),
            "properties": [
                {"name": "sbom-workbench:build-id", "value": binding["build_id"]},
                {"name": "sbom-workbench:canonical-sha256", "value": binding["canonical_sha256"]},
                {"name": "sbom-workbench:classification", "value": binding["classification"]},
                {"name": "sbom-workbench:release-artifact-sha256", "value": binding["release_artifact_sha256"]},
                {"name": "sbom-workbench:run-id", "value": binding["run_id"]},
                {"name": "sbom-workbench:generator-output-status", "value": GENERATOR_STATUS},
                {"name": "sbom-workbench:product-conformity-status", "value": PRODUCT_STATUS},
            ],
        },
        "components": [
            component_record(component)
            for component in sorted(graph["component_population"], key=lambda item: item["population_id"])
            if component["population_id"] != root["population_id"]
        ],
        "dependencies": [
            {"ref": reference, "dependsOn": sorted(dependency_targets.get(reference, set()))}
            for reference in all_refs
        ],
        "properties": sorted(relationship_properties, key=lambda item: item["value"]),
    }


def _export_spdx_reference(graph: dict[str, Any]) -> dict[str, Any]:
    root = _root_component(graph)
    prefix = f"https://example.invalid/sbom-workbench/yocto/{hashlib.sha256(graph['run_id'].encode()).hexdigest()[:24]}"
    creation_id = f"_:creation-{hashlib.sha256(graph['run_id'].encode()).hexdigest()[:20]}"
    generator_id = f"{prefix}/organization/candidate-generator"
    tool_id = f"{prefix}/tool/offline-sbom-evidence-workbench"
    document_id = f"{prefix}/document/reference"
    sbom_id = f"{prefix}/sbom/reference"
    package_ids = {
        item["population_id"]: f"{prefix}/package/{hashlib.sha256(item['population_id'].encode()).hexdigest()[:32]}"
        for item in graph["component_population"]
    }
    known_producers = sorted(
        {item["producer"] for item in graph["component_population"] if item["producer"] != UNKNOWN},
        key=lambda item: item.encode("utf-8"),
    )
    producer_ids = {
        producer: f"{prefix}/organization/{hashlib.sha256(producer.encode()).hexdigest()[:32]}"
        for producer in known_producers
    }
    items: list[dict[str, Any]] = [
        {
            "@id": creation_id, "type": "CreationInfo", "specVersion": "3.0.1",
            "createdBy": [generator_id], "createdUsing": [tool_id],
            "created": graph["reference"]["release_timestamp"],
        },
        {
            "spdxId": generator_id, "type": "Organization",
            "name": "Offline SBOM Evidence Workbench candidate generator",
            "comment": "GENERATOR_ONLY_NOT_MANUFACTURER", "creationInfo": creation_id,
        },
        {
            "spdxId": tool_id, "type": "Tool", "name": "Offline SBOM Evidence Workbench",
            "creationInfo": creation_id,
        },
    ]
    for producer in known_producers:
        items.append(
            {"spdxId": producer_ids[producer], "type": "Organization", "name": producer, "creationInfo": creation_id}
        )
    package_items: list[dict[str, Any]] = []
    for component in sorted(graph["component_population"], key=lambda item: item["population_id"]):
        external = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl" if identifier.startswith("pkg:") else "other",
                "identifier": identifier,
            }
            for identifier in component["identifiers"]
        ]
        package: dict[str, Any] = {
            "spdxId": package_ids[component["population_id"]], "type": "software_Package",
            "name": component["name"], "software_packageVersion": component["version"],
            "software_primaryPurpose": "application" if component["kind"] == "REFERENCE_IMAGE_ROOT" else "library",
            "externalIdentifier": external,
            "comment": (
                f"{GENERATOR_STATUS};{PRODUCT_STATUS};producer={component['producer']};"
                f"evidence_ids={','.join(component['evidence_ids'])}"
            ),
            "creationInfo": creation_id,
        }
        if component["producer"] != UNKNOWN:
            package["suppliedBy"] = producer_ids[component["producer"]]
        purls = [item for item in component["identifiers"] if item.startswith("pkg:")]
        if purls:
            package["software_packageUrl"] = sorted(purls)[0]
        package_items.append(package)
    relation_type = {"CONTAINS": "contains", "DEPENDS_ON": "dependsOn"}
    relationship_items: list[dict[str, Any]] = []
    for relationship in sorted(graph["relationships"], key=lambda item: item["relationship_id"]):
        body = relationship["relationship"]
        if body not in relation_type:
            raise YoctoReferenceError(f"unsupported reference relationship: {body}")
        relationship_items.append(
            {
                "spdxId": f"{prefix}/relationship/{hashlib.sha256(relationship['relationship_id'].encode()).hexdigest()[:32]}",
                "type": "Relationship", "relationshipType": relation_type[body],
                "from": package_ids[relationship["source_population_id"]],
                "to": [package_ids[relationship["target_population_id"]]],
                "comment": "evidence_ids=" + ",".join(relationship["evidence_ids"]),
                "creationInfo": creation_id,
            }
        )
    binding_comment = "sbom-workbench:binding=" + canonical_json_bytes(_source_binding(graph)).decode("utf-8")
    element_ids = [item["spdxId"] for item in package_items + relationship_items]
    items.extend(
        [
            {
                "spdxId": document_id, "type": "SpdxDocument",
                "name": f"{graph['reference']['build_id']} SPDX candidate document",
                "summary": f"{GENERATOR_STATUS}; {PRODUCT_STATUS}; public reference is not ground truth.",
                "comment": binding_comment, "creationInfo": creation_id,
                "profileConformance": ["core", "software"],
                "element": [sbom_id, *element_ids], "rootElement": [sbom_id],
            },
            {
                "spdxId": sbom_id, "type": "software_Sbom",
                "name": f"{graph['reference']['build_id']} generator output candidate",
                "creationInfo": creation_id, "profileConformance": ["core", "software"],
                "element": element_ids, "rootElement": [package_ids[root["population_id"]]],
                "software_sbomType": ["build"], "comment": binding_comment,
            },
        ]
    )
    items.extend(package_items)
    items.extend(relationship_items)
    return {"@context": SPDX_CONTEXT_URI, "@graph": items}


def export_reference_pair(
    graph: object,
    *,
    profile: object,
    input_root: Path | str,
) -> dict[str, Any]:
    """Export independent CycloneDX/SPDX candidates from the same verified graph."""

    value = _mapping(graph, "reference graph")
    verify_reference_graph(value, profile=profile, input_root=input_root)
    return {
        "profile": GRAPH_PROFILE, "status": GENERATOR_STATUS,
        "product_conformity_status": PRODUCT_STATUS,
        "source_graph_sha256": value["canonical_sha256"],
        "cyclonedx": _export_cyclonedx_reference(value),
        "spdx": _export_spdx_reference(value),
    }


def _artifact_regular_files(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lanes = [lane for lane in graph["lanes"] if lane["independence_domain"] == ARTIFACT_DOMAIN]
    if len(lanes) != 1:
        raise YoctoReferenceError("artifact observation lane is not unique")
    return {item["path"]: item for item in lanes[0]["regular_files"]}


def diff_references(a: object, b: object) -> dict[str, Any]:
    """Produce a deterministic package and rootfs A/B reference diff."""

    before = _mapping(a, "reference A")
    after = _mapping(b, "reference B")
    _verify_reference_graph_structure(before)
    _verify_reference_graph_structure(after)

    def components(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in graph["component_population"]:
            if item["kind"] != "RUNTIME_PACKAGE":
                continue
            key = f"{item['architecture']}:{item['name']}"
            if key in result:
                raise YoctoReferenceError(f"duplicate A/B component logical key: {key}")
            result[key] = item
        return result

    left = components(before)
    right = components(after)
    added = [
        {"logical_key": key, "name": right[key]["name"], "version": right[key]["version"]}
        for key in sorted(set(right) - set(left))
    ]
    removed = [
        {"logical_key": key, "name": left[key]["name"], "version": left[key]["version"]}
        for key in sorted(set(left) - set(right))
    ]
    updated: list[dict[str, str]] = []
    unchanged = 0
    for key in sorted(set(left) & set(right)):
        if left[key]["version"] != right[key]["version"]:
            updated.append(
                {"logical_key": key, "name": right[key]["name"], "from_version": left[key]["version"], "to_version": right[key]["version"]}
            )
        else:
            unchanged += 1
    left_files = _artifact_regular_files(before)
    right_files = _artifact_regular_files(after)
    file_added = sorted(set(right_files) - set(left_files), key=lambda item: item.encode("utf-8"))
    file_removed = sorted(set(left_files) - set(right_files), key=lambda item: item.encode("utf-8"))
    file_modified = [
        {"path": path, "from_sha256": left_files[path]["sha256"], "to_sha256": right_files[path]["sha256"]}
        for path in sorted(set(left_files) & set(right_files), key=lambda item: item.encode("utf-8"))
        if left_files[path]["sha256"] != right_files[path]["sha256"]
    ]
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "diff_profile": "YOCTO_PUBLIC_REFERENCE_AB_1.0",
        "classification": CLASSIFICATION,
        "from": {"profile_id": before["profile_id"], "run_id": before["run_id"], "canonical_sha256": before["canonical_sha256"]},
        "to": {"profile_id": after["profile_id"], "run_id": after["run_id"], "canonical_sha256": after["canonical_sha256"]},
        "source_revision_changes": {
            key: {"from": before["reference"]["source_revisions"][key], "to": after["reference"]["source_revisions"][key]}
            for key in sorted(_SOURCE_REVISION_KEYS)
            if before["reference"]["source_revisions"][key] != after["reference"]["source_revisions"][key]
        },
        "components": {"added": added, "removed": removed, "updated": updated, "unchanged_count": unchanged},
        "files": {"added": file_added, "removed": file_removed, "modified": file_modified},
        "update_reflected": bool(updated), "product_conformity_status": PRODUCT_STATUS,
    }
    result["diff_sha256"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result
