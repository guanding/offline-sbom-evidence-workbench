"""Bounded browser intake and offline source-scan jobs for the loopback UI.

The browser never supplies a host filesystem path.  It declares a bounded list
of relative paths and streams each file into a server-owned temporary root.
The production backend invokes the existing ``scan-source-only`` command in a
separate process, then independently invokes ``validate-source-only-output``.
Raw scanner evidence remains untouched; downloadable files are deterministic
string-substitution projections that remove known session/runtime paths.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol

from .manifest import canonical_json_bytes
from .resources import optional_checkout_path, resource_path
from .selftest import load_cyclonedx


MAX_INTAKE_JSON_BYTES = 2 * 1024 * 1024
MAX_UI_FILES = 10_000
MAX_UI_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_UI_SINGLE_FILE_BYTES = 256 * 1024 * 1024
MAX_UI_DEPTH = 64
MAX_UI_PATH_BYTES = 1024
MAX_SESSION_JOBS = 8
MAX_SESSION_DECLARED_BYTES = 2 * 1024 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
DEFAULT_SCAN_TIMEOUT_SECONDS = 600
DEFAULT_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")

OUTPUTS = {
    "cyclonedx-json": ("raw.cyclonedx.json", "CycloneDX JSON", "cyclonedx"),
    "spdx-json": ("raw.spdx.json", "SPDX JSON", "spdx"),
    "syft-json": ("raw.syft.json", "Syft JSON", "syft"),
}
SCAN_RECEIPT_FORMAT = "scan-receipt"
DOWNLOAD_FORMATS = frozenset((*OUTPUTS, SCAN_RECEIPT_FORMAT))
JOB_ID_RE = re.compile(r"[0-9a-f]{24}")
SAFE_ASCII_SLUG_RE = re.compile(r"[^a-z0-9]+")
SENSITIVE_PATH_PATTERNS = (
    re.compile("/" + r"Users/[^/\s\"']+"),
    re.compile(r"/home/[^/\s\"']+"),
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+"),
)

BOUNDARY = (
    "Browser-selected byte snapshot only. Symlinks, hard-link identity, file ownership, "
    "and executable bits are not preserved. The result is a single source-face candidate, "
    "not proof of product completeness, release, manufacturer approval, PRE-7/CRA "
    "conformity, CAB conclusion, or certification."
)


class WebScanError(ValueError):
    """A bounded intake or scan failure safe to map to an API response."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _strict_json(payload: bytes, label: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WebScanError(400, "INVALID_JSON", f"{label} contains a duplicate key")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise WebScanError(400, "INVALID_JSON", f"{label} contains {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except WebScanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WebScanError(400, "INVALID_JSON", f"{label} is not strict UTF-8 JSON") from exc


def _safe_regular_file(
    path: Path,
    label: str,
    *,
    executable: bool = False,
    maximum: int = 512 * 1024 * 1024,
) -> Path:
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise WebScanError(500, "SCANNER_RUNTIME_UNAVAILABLE", f"{label} is unavailable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > maximum
    ):
        raise WebScanError(
            500,
            "SCANNER_RUNTIME_UNSAFE",
            f"{label} must be one bounded, single-link regular file",
        )
    if executable and not bool(info.st_mode & stat.S_IXUSR):
        raise WebScanError(500, "SCANNER_RUNTIME_UNSAFE", f"{label} is not executable")
    return candidate.resolve(strict=True)


@dataclass(frozen=True)
class ScannerRuntimeConfig:
    """Explicit local scanner inputs; each scan re-verifies their trust anchors."""

    syft_bin: Path
    syft_config: Path
    syft_receipt: Path
    runtime_registry: Path
    sandbox_exec: Path = DEFAULT_SANDBOX_EXEC
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS

    def normalized(self) -> "ScannerRuntimeConfig":
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 3600:
            raise WebScanError(
                500,
                "SCANNER_CONFIGURATION_INVALID",
                "scan timeout must be an integer from 1 to 3600 seconds",
            )
        return ScannerRuntimeConfig(
            syft_bin=_safe_regular_file(self.syft_bin, "Syft binary", executable=True),
            syft_config=_safe_regular_file(self.syft_config, "Syft configuration", maximum=1024 * 1024),
            syft_receipt=_safe_regular_file(
                self.syft_receipt,
                "Syft acquisition receipt",
                maximum=1024 * 1024,
            ),
            runtime_registry=_safe_regular_file(
                self.runtime_registry,
                "runtime registry",
                maximum=4 * 1024 * 1024,
            ),
            sandbox_exec=_safe_regular_file(
                self.sandbox_exec,
                "macOS sandbox-exec",
                executable=True,
                maximum=16 * 1024 * 1024,
            ),
            timeout_seconds=self.timeout_seconds,
        )


def discover_scanner_runtime(
    *,
    syft_bin: Path | None = None,
    syft_config: Path | None = None,
    syft_receipt: Path | None = None,
    runtime_registry: Path | None = None,
    sandbox_exec: Path = DEFAULT_SANDBOX_EXEC,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    disabled: bool = False,
) -> ScannerRuntimeConfig | None:
    """Resolve either one explicit runtime tuple or the checkout-local default."""

    explicit = (syft_bin, syft_config, syft_receipt)
    if disabled:
        if any(value is not None for value in explicit):
            raise WebScanError(
                400,
                "SCANNER_CONFIGURATION_INVALID",
                "scanner paths cannot be combined with --disable-scanning",
            )
        return None
    if any(value is not None for value in explicit) and not all(
        value is not None for value in explicit
    ):
        raise WebScanError(
            400,
            "SCANNER_CONFIGURATION_INVALID",
            "Syft binary, configuration, and acquisition receipt must be provided together",
        )
    if not any(value is not None for value in explicit):
        syft_bin = optional_checkout_path("runtime/tools/syft-1.50.0/syft")
        syft_config = optional_checkout_path("runtime/tools/syft-1.50.0/syft-m3a.yaml")
        syft_receipt = optional_checkout_path(
            "runtime/tools/syft-1.50.0/acquisition-receipt.json"
        )
        if not all(value is not None for value in (syft_bin, syft_config, syft_receipt)):
            return None
    selected_registry = runtime_registry or resource_path("datasets/runtime_registry.json")
    return ScannerRuntimeConfig(
        syft_bin=Path(syft_bin),
        syft_config=Path(syft_config),
        syft_receipt=Path(syft_receipt),
        runtime_registry=Path(selected_registry),
        sandbox_exec=Path(sandbox_exec),
        timeout_seconds=timeout_seconds,
    ).normalized()


@dataclass(frozen=True)
class DownloadArtifact:
    format_id: str
    label: str
    path: Path
    filename: str
    sha256: str
    size: int


@dataclass(frozen=True)
class BackendResult:
    public: dict[str, Any]
    artifacts: dict[str, DownloadArtifact]


class ScannerBackend(Protocol):
    def status(self) -> dict[str, Any]: ...

    def scan(
        self,
        *,
        job_root: Path,
        source_root: Path,
        output_root: Path,
        product_name: str,
        declared_version: str,
    ) -> BackendResult: ...


def _clean_diagnostic(value: object, roots: tuple[Path, ...]) -> str:
    message = str(value) if value is not None else "scan command was blocked"
    for root in sorted({path.as_posix() for path in roots}, key=len, reverse=True):
        message = message.replace(root, "${LOCAL_PATH}")
    message = " ".join(message.split())
    return message[:1200] or "scan command was blocked"


def _run_cli(
    arguments: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    sensitive_roots: tuple[Path, ...],
) -> dict[str, Any]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    argv = [sys.executable, "-m", "sbom_workbench.cli", *arguments]
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise WebScanError(
                422,
                "SCAN_TIMEOUT",
                "离线扫描超过时间预算；请缩小选择范围后重试。",
            ) from exc
    except WebScanError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise WebScanError(
            500,
            "SCAN_PROCESS_UNAVAILABLE",
            "无法启动隔离扫描进程；请检查本地 Python 与扫描器配置。",
        ) from exc
    if len(stdout) > 2 * 1024 * 1024 or len(stderr) > 2 * 1024 * 1024:
        raise WebScanError(422, "SCAN_DIAGNOSTIC_TOO_LARGE", "扫描诊断输出超过安全预算。")
    try:
        payload = _strict_json(stdout, "scan command output")
    except WebScanError as exc:
        diagnostic = _clean_diagnostic(stderr.decode("utf-8", errors="replace"), sensitive_roots)
        raise WebScanError(
            422,
            "SCAN_OUTPUT_INVALID",
            f"扫描进程未返回有效结果：{diagnostic}",
        ) from exc
    if not isinstance(payload, dict):
        raise WebScanError(422, "SCAN_OUTPUT_INVALID", "扫描进程结果不是 JSON 对象。")
    if process.returncode != 0 or payload.get("status") == "BLOCKED":
        message = _clean_diagnostic(payload.get("message") or stderr, sensitive_roots)
        raise WebScanError(422, "SCAN_BLOCKED", f"离线扫描被安全门阻止：{message}")
    return payload


def _replace_known_paths(value: Any, replacements: tuple[tuple[str, str], ...]) -> tuple[Any, int]:
    if isinstance(value, str):
        result = value
        count = 0
        for spelling, token in replacements:
            occurrences = result.count(spelling)
            if occurrences:
                result = result.replace(spelling, token)
                count += occurrences
        return result, count
    if isinstance(value, list):
        projected: list[Any] = []
        count = 0
        for item in value:
            replacement, item_count = _replace_known_paths(item, replacements)
            projected.append(replacement)
            count += item_count
        return projected, count
    if isinstance(value, dict):
        projected_dict: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            replacement, item_count = _replace_known_paths(item, replacements)
            projected_dict[key] = replacement
            count += item_count
        return projected_dict, count
    return value, 0


def _sensitive_path_count(value: Any) -> int:
    if isinstance(value, str):
        return sum(len(pattern.findall(value)) for pattern in SENSITIVE_PATH_PATTERNS)
    if isinstance(value, list):
        return sum(_sensitive_path_count(item) for item in value)
    if isinstance(value, dict):
        return sum(_sensitive_path_count(item) for item in value.values())
    return 0


def _replace_sensitive_home_roots(value: Any) -> tuple[Any, int]:
    """Replace user-home prefixes that scanner defaults may disclose.

    This remains a string-only privacy projection.  It deliberately does not
    delete, add, or infer components, relationships, identifiers, or versions.
    """

    if isinstance(value, str):
        result = value
        count = 0
        for pattern in SENSITIVE_PATH_PATTERNS:
            result, replacements = pattern.subn("${USER_HOME}", result)
            count += replacements
        return result, count
    if isinstance(value, list):
        projected: list[Any] = []
        count = 0
        for item in value:
            replacement, item_count = _replace_sensitive_home_roots(item)
            projected.append(replacement)
            count += item_count
        return projected, count
    if isinstance(value, dict):
        projected_dict: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            replacement, item_count = _replace_sensitive_home_roots(item)
            projected_dict[key] = replacement
            count += item_count
        return projected_dict, count
    return value, 0


def _read_bounded_json(path: Path, label: str) -> tuple[Any, bytes]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise WebScanError(422, "SCAN_ARTIFACT_MISSING", f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > MAX_DOWNLOAD_BYTES
    ):
        raise WebScanError(
            422,
            "SCAN_ARTIFACT_UNSAFE",
            f"{label} is not one bounded regular JSON file",
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise WebScanError(422, "SCAN_ARTIFACT_UNAVAILABLE", f"cannot read {label}") from exc
    return _strict_json(payload, label), payload


def _write_projected_json(path: Path, value: Any) -> tuple[str, int]:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", errors="ignore").decode()
    result = SAFE_ASCII_SLUG_RE.sub("-", normalized.casefold()).strip("-")
    return result[:48] or "sbom"


class SubprocessScanner:
    """Production backend that reuses the governed CLI in a child process."""

    def __init__(self, runtime: ScannerRuntimeConfig) -> None:
        self.runtime = runtime.normalized()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "status": "CONFIGURED_VERIFIED_PER_SCAN",
            "name": "Syft",
            "version": "1.50.0",
            "network_policy": "MACOS_SANDBOX_EXEC_DENY_NETWORK",
            "formats": list(OUTPUTS),
            "boundary": "Runtime hashes, receipt, registry, version, and network deny are verified again for every scan.",
        }

    def scan(
        self,
        *,
        job_root: Path,
        source_root: Path,
        output_root: Path,
        product_name: str,
        declared_version: str,
    ) -> BackendResult:
        active_boundary = job_root / "nonexistent-active-source-boundary"
        roots = (
            job_root,
            source_root,
            self.runtime.syft_bin.parent,
            self.runtime.runtime_registry.parent,
        )
        arguments = [
            "scan-source-only",
            "--source-root",
            source_root.as_posix(),
            "--active-source-root",
            active_boundary.as_posix(),
            "--syft-bin",
            self.runtime.syft_bin.as_posix(),
            "--syft-config",
            self.runtime.syft_config.as_posix(),
            "--syft-receipt",
            self.runtime.syft_receipt.as_posix(),
            "--runtime-registry",
            self.runtime.runtime_registry.as_posix(),
            "--output-root",
            output_root.as_posix(),
            "--sandbox-exec",
            self.runtime.sandbox_exec.as_posix(),
            "--timeout-seconds",
            str(self.runtime.timeout_seconds),
            "--max-source-files",
            str(MAX_UI_FILES),
            "--max-source-bytes",
            str(MAX_UI_TOTAL_BYTES),
            "--max-single-source-file-bytes",
            str(MAX_UI_SINGLE_FILE_BYTES),
            "--max-source-depth",
            str(MAX_UI_DEPTH),
            "--comparison-namespace",
            "workbench-ui-source-scan",
            "--product-name",
            product_name,
            "--declared-version",
            declared_version,
        ]
        scan_result = _run_cli(
            arguments,
            cwd=job_root,
            timeout_seconds=self.runtime.timeout_seconds + 180,
            sensitive_roots=roots,
        )
        validation = _run_cli(
            [
                "validate-source-only-output",
                "--output-root",
                output_root.as_posix(),
                "--source-root",
                source_root.as_posix(),
            ],
            cwd=job_root,
            timeout_seconds=self.runtime.timeout_seconds,
            sensitive_roots=roots,
        )
        if validation.get("status") != "SOURCE_ONLY_OUTPUT_VALID_WITH_SINGLE_FACE_BOUNDARY":
            raise WebScanError(
                422,
                "SCAN_VALIDATION_BLOCKED",
                "扫描输出未通过独立的 source-only 绑定验证。",
            )

        raw_root = output_root / "raw" / "m3a-source-directory"
        download_root = job_root / "downloads"
        download_root.mkdir(mode=0o700)
        spellings = {
            source_root.absolute().as_posix(): "${SOURCE_ROOT}",
            source_root.resolve(strict=True).as_posix(): "${SOURCE_ROOT}",
            job_root.resolve(strict=True).as_posix(): "${SESSION_ROOT}",
            self.runtime.syft_bin.parent.as_posix(): "${SCANNER_ROOT}",
            self.runtime.runtime_registry.parent.as_posix(): "${WORKBENCH_DATA_ROOT}",
        }
        replacements = tuple(
            sorted(spellings.items(), key=lambda item: (-len(item[0]), item[0].encode("utf-8")))
        )
        artifacts: dict[str, DownloadArtifact] = {}
        projection_replacements = 0
        projection_records: dict[str, dict[str, Any]] = {}
        product_slug = _slug(product_name)
        version_slug = _slug(declared_version)
        for format_id, (raw_name, label, suffix) in OUTPUTS.items():
            raw_path = raw_root / raw_name
            document, raw_payload = _read_bounded_json(raw_path, f"raw {label}")
            raw_sha256 = hashlib.sha256(raw_payload).hexdigest()
            try:
                projected, count = _replace_known_paths(document, replacements)
                projected, home_count = _replace_sensitive_home_roots(projected)
                count += home_count
                residual = _sensitive_path_count(projected)
            except RecursionError as exc:
                raise WebScanError(
                    422,
                    "PRIVACY_PROJECTION_BLOCKED",
                    f"{label} nesting exceeds the privacy projection budget.",
                ) from exc
            if residual:
                raise WebScanError(
                    422,
                    "PRIVACY_PROJECTION_BLOCKED",
                    f"{label} still contains {residual} user-specific path candidate(s); download is blocked.",
                )
            projection_replacements += count
            filename = f"{product_slug}-{version_slug}.{suffix}.json"
            destination = download_root / filename
            digest, size = _write_projected_json(destination, projected)
            if format_id == "cyclonedx-json":
                projection, identity = load_cyclonedx(destination)
                if identity["sha256"] != digest or len(projection["components"]) != validation.get(
                    "component_count"
                ):
                    raise WebScanError(
                        422,
                        "PRIVACY_PROJECTION_BLOCKED",
                        "CycloneDX projection changed the validated component population.",
                    )
            artifacts[format_id] = DownloadArtifact(
                format_id=format_id,
                label=label,
                path=destination,
                filename=filename,
                sha256=digest,
                size=size,
            )
            projection_records[format_id] = {
                "raw_sha256": raw_sha256,
                "raw_size": len(raw_payload),
                "projected_sha256": digest,
                "projected_size": size,
                "known_path_replacement_count": count,
                "fact_policy": "STRING_SUBSTITUTION_ONLY_NO_COMPONENT_ADD_DELETE_OR_INFERENCE",
            }

        receipt_value = {
            "schema_version": "1.0",
            "classification": validation.get("classification"),
            "status": "UI_SOURCE_SCAN_CANDIDATE_GENERATED",
            "run_id": validation.get("run_id"),
            "operator_declaration": {
                "product_name": product_name,
                "declared_version": declared_version,
                "authority": "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
            },
            "source_snapshot": {
                "exact_set_sha256": validation.get("source_exact_set_sha256"),
                "completion_sha256": validation.get("completion_sha256"),
                "source_reverification": validation.get("source_reverification"),
                "snapshot_boundary": BOUNDARY,
            },
            "scanner": {
                "name": "Syft",
                "version": "1.50.0",
                "network_policy": "MACOS_SANDBOX_EXEC_DENY_NETWORK",
                "runtime_verification": "HASH_RECEIPT_REGISTRY_VERSION_VERIFIED_PER_SCAN",
            },
            "validation": {
                "status": validation.get("status"),
                "component_count": validation.get("component_count"),
                "coverage_gate": validation.get("coverage_gate"),
                "component_population_gate": validation.get("component_population_gate"),
                "build_binding_status": validation.get("build_binding_status"),
            },
            "privacy_projection": {
                "gate": "PASS_KNOWN_LOCAL_PATHS_REMOVED_NO_RESIDUAL_USER_PATH_PATTERN",
                "normalized_tokens": [
                    "${SOURCE_ROOT}",
                    "${SESSION_ROOT}",
                    "${SCANNER_ROOT}",
                    "${WORKBENCH_DATA_ROOT}",
                    "${USER_HOME}",
                ],
                "total_replacement_count": projection_replacements,
                "outputs": projection_records,
            },
            "authority_boundary": BOUNDARY,
        }
        receipt_filename = f"{product_slug}-{version_slug}.scan-receipt.json"
        receipt_path = download_root / receipt_filename
        receipt_sha256, receipt_size = _write_projected_json(receipt_path, receipt_value)
        artifacts[SCAN_RECEIPT_FORMAT] = DownloadArtifact(
            format_id=SCAN_RECEIPT_FORMAT,
            label="Scan evidence receipt JSON",
            path=receipt_path,
            filename=receipt_filename,
            sha256=receipt_sha256,
            size=receipt_size,
        )

        public_downloads = {
            format_id: {
                "format": artifact.format_id,
                "label": artifact.label,
                "filename": artifact.filename,
                "sha256": artifact.sha256,
                "size": artifact.size,
                "url": f"/api/intakes/{{job_id}}/downloads/{format_id}",
            }
            for format_id, artifact in artifacts.items()
        }
        public = {
            "scan_status": scan_result.get("status"),
            "validation_status": validation.get("status"),
            "classification": validation.get("classification"),
            "run_id": validation.get("run_id"),
            "component_count": validation.get("component_count"),
            "coverage_gate": validation.get("coverage_gate"),
            "component_population_gate": validation.get("component_population_gate"),
            "component_population_item_count": validation.get(
                "component_population_item_count"
            ),
            "component_population_matched_count": validation.get(
                "component_population_matched_count"
            ),
            "component_population_unmatched_count": validation.get(
                "component_population_unmatched_count"
            ),
            "build_binding_status": validation.get("build_binding_status"),
            "completion_sha256": validation.get("completion_sha256"),
            "source_exact_set_sha256": validation.get("source_exact_set_sha256"),
            "privacy_projection_replacement_count": projection_replacements,
            "privacy_gate": "PASS_KNOWN_LOCAL_PATHS_REMOVED_NO_RESIDUAL_USER_PATH_PATTERN",
            "downloads": public_downloads,
            "boundary": BOUNDARY,
        }
        return BackendResult(public=public, artifacts=artifacts)


@dataclass(frozen=True)
class FileSpec:
    relative_path: str
    size: int


@dataclass
class IntakeJob:
    job_id: str
    root: Path
    source_root: Path
    output_root: Path
    product_name: str
    declared_version: str
    source_kind: str
    requested_format: str
    files: tuple[FileSpec, ...]
    total_bytes: int
    created_at: str
    status: str = "UPLOADING"
    uploaded_indexes: set[int] = field(default_factory=set)
    uploading_indexes: set[int] = field(default_factory=set)
    uploaded_bytes: int = 0
    file_hashes: dict[int, str] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    artifacts: dict[str, DownloadArtifact] = field(default_factory=dict)
    error: dict[str, str] | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)


def _bounded_declaration(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise WebScanError(
            400,
            "INVALID_DECLARATION",
            f"{label} must be 1–128 visible characters without leading or trailing spaces",
        )
    return value


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WebScanError(400, "INVALID_SOURCE_PATH", "source path is not safe POSIX text")
    if value != unicodedata.normalize("NFC", value):
        raise WebScanError(400, "INVALID_SOURCE_PATH", "source paths must use Unicode NFC")
    if len(value.encode("utf-8")) > MAX_UI_PATH_BYTES:
        raise WebScanError(400, "INVALID_SOURCE_PATH", "source path exceeds its byte limit")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or len(path.parts) > MAX_UI_DEPTH
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(any(ord(character) < 0x20 for character in part) for part in path.parts)
    ):
        raise WebScanError(400, "INVALID_SOURCE_PATH", "source path is not normalized")
    return value


def _parse_intake(value: object) -> tuple[str, str, str, str, tuple[FileSpec, ...], int]:
    if not isinstance(value, dict) or set(value) != {
        "source_kind",
        "product_name",
        "declared_version",
        "output_format",
        "files",
    }:
        raise WebScanError(400, "INVALID_INTAKE", "intake fields do not match the contract")
    source_kind = value["source_kind"]
    if source_kind not in {"files", "directory"}:
        raise WebScanError(400, "INVALID_INTAKE", "source_kind must be files or directory")
    product_name = _bounded_declaration(value["product_name"], "product_name")
    declared_version = _bounded_declaration(value["declared_version"], "declared_version")
    output_format = value["output_format"]
    if output_format not in OUTPUTS:
        raise WebScanError(400, "INVALID_INTAKE", "requested output format is unsupported")
    raw_files = value["files"]
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_UI_FILES:
        raise WebScanError(400, "SOURCE_FILE_BUDGET", "select between 1 and 10,000 files")
    files: list[FileSpec] = []
    canonical_paths: set[str] = set()
    total_bytes = 0
    for index, raw in enumerate(raw_files):
        if not isinstance(raw, dict) or set(raw) != {"relative_path", "size"}:
            raise WebScanError(400, "INVALID_INTAKE", f"files[{index}] fields do not match")
        relative_path = _safe_relative_path(raw["relative_path"])
        if source_kind == "files" and "/" in relative_path:
            raise WebScanError(
                400,
                "INVALID_SOURCE_PATH",
                "individual file selection cannot declare directory segments",
            )
        collision_key = unicodedata.normalize("NFC", relative_path).casefold()
        if collision_key in canonical_paths:
            raise WebScanError(
                400,
                "SOURCE_PATH_COLLISION",
                "source paths contain a duplicate or case-insensitive collision",
            )
        canonical_paths.add(collision_key)
        size = raw["size"]
        if type(size) is not int or size < 0 or size > MAX_UI_SINGLE_FILE_BYTES:
            raise WebScanError(
                400,
                "SOURCE_FILE_BUDGET",
                f"files[{index}] exceeds the single-file byte budget",
            )
        total_bytes += size
        if total_bytes > MAX_UI_TOTAL_BYTES:
            raise WebScanError(400, "SOURCE_TOTAL_BUDGET", "selection exceeds the 1 GiB budget")
        files.append(FileSpec(relative_path=relative_path, size=size))
    file_keys = {
        tuple(part.casefold() for part in PurePosixPath(item.relative_path).parts)
        for item in files
    }
    for parts in file_keys:
        if any(parts[:depth] in file_keys for depth in range(1, len(parts))):
            raise WebScanError(
                400,
                "SOURCE_PATH_COLLISION",
                "one selected file path is also a parent directory of another file",
            )
    directory_spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for item in files:
        parts = PurePosixPath(item.relative_path).parts
        for depth in range(1, len(parts)):
            original = tuple(parts[:depth])
            folded = tuple(part.casefold() for part in original)
            previous = directory_spellings.setdefault(folded, original)
            if previous != original:
                raise WebScanError(
                    400,
                    "SOURCE_PATH_COLLISION",
                    "source directory spellings collide on a case-insensitive filesystem",
                )
    if total_bytes <= 0:
        raise WebScanError(400, "EMPTY_SOURCE_SELECTION", "selected files contain no bytes")
    return source_kind, product_name, declared_version, output_format, tuple(files), total_bytes


class ScanJobStore:
    """Server-owned, bounded job state and temporary byte snapshots."""

    def __init__(self, root: Path, scanner: ScannerBackend | None) -> None:
        candidate = Path(root)
        if candidate.exists() or candidate.is_symlink():
            raise WebScanError(500, "SCAN_ROOT_EXISTS", "scan session root must be new")
        candidate.mkdir(mode=0o700, parents=True)
        if candidate.is_symlink() or not candidate.is_dir():
            raise WebScanError(500, "SCAN_ROOT_UNSAFE", "scan session root is unsafe")
        self.root = candidate.resolve(strict=True)
        self.scanner = scanner
        self._jobs: dict[str, IntakeJob] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sbom-scan")
        self._closed = False

    def scanner_status(self) -> dict[str, Any]:
        base = {
            "limits": {
                "max_files": MAX_UI_FILES,
                "max_total_bytes": MAX_UI_TOTAL_BYTES,
                "max_single_file_bytes": MAX_UI_SINGLE_FILE_BYTES,
                "max_depth": MAX_UI_DEPTH,
            },
            "snapshot_boundary": BOUNDARY,
        }
        if self.scanner is None:
            return {
                **base,
                "enabled": False,
                "status": "SCANNER_NOT_CONFIGURED",
                "formats": list(OUTPUTS),
                "setup": "Run scripts/acquire_syft_m3a.sh or pass the three explicit Syft paths.",
            }
        return {**base, **self.scanner.status()}

    def _job(self, job_id: object) -> IntakeJob:
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            raise WebScanError(400, "INVALID_JOB_ID", "scan job ID is invalid")
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise WebScanError(404, "JOB_NOT_FOUND", "scan job is not registered")
        return job

    def create(self, request: object) -> dict[str, Any]:
        if self.scanner is None:
            raise WebScanError(
                409,
                "SCANNER_DISABLED",
                "本地扫描器尚未配置；请先运行固定版本的 Syft 获取脚本。",
            )
        source_kind, product, version, output_format, files, total_bytes = _parse_intake(
            request
        )
        with self._lock:
            if self._closed:
                raise WebScanError(503, "SCAN_SERVICE_CLOSED", "scan service is closing")
            if len(self._jobs) >= MAX_SESSION_JOBS:
                raise WebScanError(
                    409,
                    "JOB_LIMIT_REACHED",
                    "本次本地会话已有 8 个任务；请清除不再需要的任务。",
                )
            declared = sum(job.total_bytes for job in self._jobs.values())
            if declared + total_bytes > MAX_SESSION_DECLARED_BYTES:
                raise WebScanError(
                    409,
                    "SESSION_BYTE_BUDGET",
                    "本次会话的已声明源码超过 2 GiB；请清除旧任务。",
                )
            job_id = secrets.token_hex(12)
            while job_id in self._jobs:
                job_id = secrets.token_hex(12)
            root = self.root / job_id
            root.mkdir(mode=0o700)
            source_root = root / "source"
            source_root.mkdir(mode=0o700)
            job = IntakeJob(
                job_id=job_id,
                root=root,
                source_root=source_root,
                output_root=root / "output",
                product_name=product,
                declared_version=version,
                source_kind=source_kind,
                requested_format=output_format,
                files=files,
                total_bytes=total_bytes,
                created_at=_utc_now(),
            )
            self._jobs[job_id] = job
        return self.public(job_id)

    def upload(self, job_id: str, index: int, stream: BinaryIO, content_length: int) -> dict[str, Any]:
        job = self._job(job_id)
        if type(index) is not int or not 0 <= index < len(job.files):
            raise WebScanError(404, "FILE_NOT_REGISTERED", "upload file index is not registered")
        spec = job.files[index]
        if content_length != spec.size:
            raise WebScanError(
                400,
                "UPLOAD_SIZE_MISMATCH",
                "uploaded Content-Length differs from the declared file size",
            )
        with job.lock:
            if job.status not in {"UPLOADING", "READY"}:
                raise WebScanError(409, "JOB_STATE_CONFLICT", "job no longer accepts files")
            if index in job.uploaded_indexes or index in job.uploading_indexes:
                raise WebScanError(409, "DUPLICATE_UPLOAD", "file index was already uploaded")
            job.uploading_indexes.add(index)
            job.status = "UPLOADING"
        destination = job.source_root / spec.relative_path
        partial = destination.with_name(f".{destination.name}.uploading")
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            resolved_parent = destination.parent.resolve(strict=True)
            resolved_parent.relative_to(job.source_root)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(partial, flags, 0o600)
            digest = hashlib.sha256()
            received = 0
            try:
                remaining = content_length
                while remaining:
                    chunk = stream.read(min(UPLOAD_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise WebScanError(
                            400,
                            "TRUNCATED_UPLOAD",
                            "uploaded file ended before its declared Content-Length",
                        )
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(descriptor, chunk[offset:])
                    digest.update(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if received != content_length:
                raise WebScanError(400, "TRUNCATED_UPLOAD", "uploaded file is incomplete")
            os.link(partial, destination, follow_symlinks=False)
            partial.unlink()
            with job.lock:
                job.uploaded_indexes.add(index)
                job.file_hashes[index] = digest.hexdigest()
                job.uploaded_bytes += received
                if len(job.uploaded_indexes) == len(job.files):
                    job.status = "READY"
        except WebScanError:
            if partial.exists() and not partial.is_symlink():
                partial.unlink()
            raise
        except (OSError, ValueError) as exc:
            if partial.exists() and not partial.is_symlink():
                partial.unlink()
            raise WebScanError(
                500,
                "UPLOAD_WRITE_FAILED",
                "无法保存所选文件；请检查本地磁盘空间并重试。",
            ) from exc
        finally:
            with job.lock:
                job.uploading_indexes.discard(index)
        return self.public(job_id)

    def start(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        with job.lock:
            if job.status != "READY" or len(job.uploaded_indexes) != len(job.files):
                raise WebScanError(
                    409,
                    "JOB_NOT_READY",
                    "所有已声明文件完成上传后才能开始扫描。",
                )
            job.status = "QUEUED"
        self._executor.submit(self._run_job, job)
        return self.public(job_id)

    def _run_job(self, job: IntakeJob) -> None:
        with job.lock:
            if job.status != "QUEUED":
                return
            job.status = "SCANNING"
        try:
            if self.scanner is None:
                raise WebScanError(409, "SCANNER_DISABLED", "scanner is not configured")
            result = self.scanner.scan(
                job_root=job.root,
                source_root=job.source_root,
                output_root=job.output_root,
                product_name=job.product_name,
                declared_version=job.declared_version,
            )
            for format_id, artifact in result.artifacts.items():
                if format_id not in DOWNLOAD_FORMATS or artifact.format_id != format_id:
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned an unknown or mismatched format",
                    )
                if (
                    not isinstance(artifact.label, str)
                    or not 1 <= len(artifact.label) <= 128
                    or artifact.label != artifact.label.strip()
                    or any(ord(character) < 0x20 for character in artifact.label)
                ):
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned an invalid download label",
                    )
                if (
                    not isinstance(artifact.filename, str)
                    or not artifact.filename.endswith(".json")
                    or not 1 <= len(artifact.filename.encode("utf-8")) <= 255
                    or PurePosixPath(artifact.filename).name != artifact.filename
                    or artifact.filename != unicodedata.normalize("NFC", artifact.filename)
                    or any(ord(character) < 0x20 for character in artifact.filename)
                ):
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned an invalid download filename",
                    )
                if not isinstance(artifact.sha256, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", artifact.sha256
                ):
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned an invalid download hash",
                    )
                try:
                    resolved = artifact.path.resolve(strict=True)
                    resolved.relative_to(job.root)
                    info = artifact.path.lstat()
                except (OSError, ValueError) as exc:
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned a download outside the scan session",
                    ) from exc
                if (
                    artifact.path.is_symlink()
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or type(artifact.size) is not int
                    or artifact.size != info.st_size
                    or not 0 < artifact.size <= MAX_DOWNLOAD_BYTES
                ):
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner returned an unsafe download file",
                    )
                digest = hashlib.sha256()
                with artifact.path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != artifact.sha256:
                    raise WebScanError(
                        500,
                        "SCAN_ARTIFACT_UNSAFE",
                        "scanner download does not match its declared hash",
                    )
            if job.requested_format not in result.artifacts:
                raise WebScanError(
                    500,
                    "SCAN_ARTIFACT_UNSAFE",
                    "scanner omitted the requested download format",
                )
            if not isinstance(result.public, dict):
                raise WebScanError(500, "SCAN_RESULT_INVALID", "scanner result is not an object")
            try:
                public = json.loads(json.dumps(result.public, allow_nan=False))
            except (TypeError, ValueError, RecursionError) as exc:
                raise WebScanError(
                    500,
                    "SCAN_RESULT_INVALID",
                    "scanner result is not bounded JSON data",
                ) from exc
            public["downloads"] = {
                format_id: {
                    "format": artifact.format_id,
                    "label": artifact.label,
                    "filename": artifact.filename,
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                    "url": f"/api/intakes/{job.job_id}/downloads/{format_id}",
                }
                for format_id, artifact in result.artifacts.items()
            }
            with job.lock:
                job.result = public
                job.artifacts = dict(result.artifacts)
                job.status = "COMPLETE"
        except WebScanError as exc:
            with job.lock:
                job.status = "BLOCKED"
                job.error = {"code": exc.code, "message": exc.message}
        except Exception:
            with job.lock:
                job.status = "BLOCKED"
                job.error = {
                    "code": "SCAN_INTERNAL_ERROR",
                    "message": "扫描任务发生内部错误；未生成可下载候选。",
                }

    def public(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        with job.lock:
            return {
                "job_id": job.job_id,
                "status": job.status,
                "created_at": job.created_at,
                "source": {
                    "kind": job.source_kind,
                    "file_count": len(job.files),
                    "total_bytes": job.total_bytes,
                    "uploaded_files": len(job.uploaded_indexes),
                    "uploaded_bytes": job.uploaded_bytes,
                    "snapshot_boundary": BOUNDARY,
                },
                "declaration": {
                    "product_name": job.product_name,
                    "declared_version": job.declared_version,
                    "authority": "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
                },
                "requested_format": job.requested_format,
                "result": job.result,
                "error": job.error,
            }

    def artifact(self, job_id: str, format_id: str) -> DownloadArtifact:
        job = self._job(job_id)
        if format_id not in DOWNLOAD_FORMATS:
            raise WebScanError(404, "FORMAT_NOT_FOUND", "download format is unsupported")
        with job.lock:
            if job.status != "COMPLETE":
                raise WebScanError(409, "DOWNLOAD_NOT_READY", "scan result is not ready")
            artifact = job.artifacts.get(format_id)
        if artifact is None:
            raise WebScanError(404, "ARTIFACT_NOT_FOUND", "download artifact is unavailable")
        try:
            resolved = artifact.path.resolve(strict=True)
            resolved.relative_to(job.root)
            info = artifact.path.lstat()
        except (OSError, ValueError) as exc:
            raise WebScanError(409, "ARTIFACT_DRIFT", "download artifact is no longer trusted") from exc
        if (
            artifact.path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != artifact.size
            or info.st_size > MAX_DOWNLOAD_BYTES
        ):
            raise WebScanError(409, "ARTIFACT_DRIFT", "download artifact metadata changed")
        digest = hashlib.sha256()
        with artifact.path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact.sha256:
            raise WebScanError(409, "ARTIFACT_DRIFT", "download artifact hash changed")
        return artifact

    def discard(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        with job.lock:
            if job.status in {"QUEUED", "SCANNING"} or job.uploading_indexes:
                raise WebScanError(409, "JOB_ACTIVE", "正在上传或扫描的任务不能清除。")
            job.status = "DISCARDED"
        try:
            resolved = job.root.resolve(strict=True)
            if resolved.parent != self.root or not JOB_ID_RE.fullmatch(resolved.name):
                raise WebScanError(500, "JOB_ROOT_UNSAFE", "job root failed cleanup validation")
            shutil.rmtree(resolved)
        except WebScanError:
            raise
        except OSError as exc:
            raise WebScanError(500, "JOB_CLEANUP_FAILED", "无法清除本次临时数据。") from exc
        with self._lock:
            self._jobs.pop(job_id, None)
        return {"status": "DISCARDED", "job_id": job_id}

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=True)
        if self.root.exists() and not self.root.is_symlink():
            shutil.rmtree(self.root)


def artifact_digest_header(artifact: DownloadArtifact) -> str:
    return "sha-256=" + base64.b64encode(bytes.fromhex(artifact.sha256)).decode("ascii")


def intake_request_from_bytes(payload: bytes) -> object:
    if not 1 <= len(payload) <= MAX_INTAKE_JSON_BYTES:
        raise WebScanError(413, "INTAKE_TOO_LARGE", "intake manifest exceeds its byte budget")
    return _strict_json(payload, "intake manifest")


def canonical_intake_fingerprint(value: object) -> str:
    """Test/support helper for deterministic intake contract fingerprints."""

    parsed = _parse_intake(value)
    normalized = {
        "source_kind": parsed[0],
        "product_name": parsed[1],
        "declared_version": parsed[2],
        "output_format": parsed[3],
        "files": [
            {"relative_path": item.relative_path, "size": item.size} for item in parsed[4]
        ],
        "total_bytes": parsed[5],
    }
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
