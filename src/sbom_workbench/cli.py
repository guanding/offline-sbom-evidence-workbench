"""Command-line interface for the governed Phase 1 foundation."""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

from . import __version__
from .acquire import (
    AcquisitionError,
    acquire_git_source,
    load_trusted_acquisition_receipt,
    registry_entry_hash,
    verify_acquisition,
)
from .evidence import EvidenceError
from .component_population import (
    ComponentPopulationError,
    build_component_population,
)
from .excel import ExcelImportError, import_pro03b
from .euvd_handoff import (
    EuvdHandoffError,
    prepare_verified_selftest_euvd_handoff,
    validate_euvd_handoff,
)
from .signing import (
    SigningError,
    build_cosign_sign_command,
    build_cosign_verify_command,
    build_receipt,
    validate_receipt,
)
from .manifest import (
    ManifestError,
    build_bounded_exact_set_manifest,
    build_exact_set_manifest,
    canonical_json_bytes,
    sha256_file,
    write_json_atomic,
)
from .model import ModelAdapterError, OmlxModelAdapter
from .model_candidate import (
    observe_candidate_profile,
    run_candidate_evaluation,
    validate_candidate_evaluation,
)
from .model_eval import (
    ModelEvaluationError,
    cards_from_selftest_comparison,
    normalize_runtime_observations,
    run_sealed_evaluation,
    seal_card_set,
    validate_evaluation,
)
from .ops import (
    OperationsError,
    clear_selftest_sandbox_run,
    create_selftest_backup,
    restore_selftest_backup,
    validate_selftest_backup,
)
from .pack import (
    PackError,
    verify_analysis_package,
    verify_run_package,
    write_analysis_package,
    write_run_package,
)
from .privacy_projection import (
    PrivacyProjectionError,
    prepare_source_analysis_projection,
    validate_source_analysis_projection,
)
from .reference_pack import (
    ReferencePackError,
    verify_reference_package,
    write_reference_package,
)
from .resources import ResourceError, data_root, optional_checkout_path, resource_path
from .registry import (
    RegistryError,
    find_source,
    load_and_validate_registry,
    load_and_validate_registry_with_hash,
)
from .selftest import (
    CLASSIFICATION as SELFTEST_CLASSIFICATION,
    MAX_COMPONENTS as SELFTEST_MAX_COMPONENTS,
    MAX_JSON_BYTES as SELFTEST_MAX_JSON_BYTES,
    PROFILE_DOMAINS,
    PROFILE_TARGETS,
    REQUIRED_BLINDSPOTS,
    SANDBOX_NETWORK_DENY_PROFILE,
    SelfTestError,
    build_profile_observation,
    build_syft_command,
    load_cyclonedx,
    reconcile_profile_observations,
    validate_selftest_profile,
)
from .selftest_pack import (
    SelfTestPackError,
    verify_selftest_package,
    write_selftest_package,
)
from .selftest_root import SelfTestRootError, verify_selftest_root
from .source_audit import analyze_source_ecosystems
from .source_only_validation import SourceOnlyValidationError, validate_source_only_output
from .vex_consume import (
    VexConsumeError,
    build_vex_intake_receipt,
    parse_vex_document,
    validate_vex_statement,
    verify_vex_intake_binding,
)
from .narrowing_reconcile import (
    NarrowingError,
    REASON_VEX_INTAKE_BINDING_FAILED,
    build_narrowed_receipt,
    canonicalize_purl,
    narrow_one_hit,
    parse_matcher_hits,
    validate_narrowed_receipt,
    validate_purl_presence,
)
from .webapp import WebAppError, create_server
from .web_scan import (
    SubprocessScanner,
    WebScanError,
    discover_scanner_runtime,
)
from .workflow import analyze_fixture, diff_graphs
from .yocto import (
    acquire_profile,
    analyze_reference,
    diff_references,
    load_profile_registry,
)


DEFAULT_TRUSTED_SOURCE_REGISTRY_SHA256 = "64ddea706ac4b388f878eda2c768e0f7c6b7cbeeaf1a6031f927e28930473981"
DEFAULT_TRUSTED_MODEL_INTAKE_SHA256 = "86a4be5e7e57e9b344a6139297ef935e0a8580d87f2a2b0b5f1ef38141ffe0de"
DEFAULT_TRUSTED_YOCTO_PROFILE_REGISTRY_SHA256 = (
    "818f06294dd8ce113ccb446af3cae7f3817266c78be0a04a00b3f272038bdfd1"
)
DEFAULT_OMLX_ENDPOINT = "http://127.0.0.1:8000/v1/responses"
DEFAULT_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
TRUSTED_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
TRUSTED_SANDBOX_UID = 0
# docker-archive (OCI) pre-scan extraction budget. Syft decompresses image
# layers itself and exposes no extraction cap in its configuration, so the
# workbench rejects an archive whose gzip layers exceed these budgets before
# handing it to the scanner; this closes the SEC-03 archive-bomb gap on the
# OCI lane (M3-4).
SELFTEST_OCI_MAX_LAYERS = 256
SELFTEST_OCI_MAX_LAYER_COMPRESSED_BYTES = 1024 * 1024 * 1024  # 1 GiB per layer
SELFTEST_OCI_MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB cumulative
SELFTEST_OCI_DECOMPRESS_CHUNK = 4 * 1024 * 1024
SOURCE_ONLY_STATUS = "SOURCE_ONLY_SCAN_COMPLETE_OPEN_CANDIDATE"
SOURCE_ONLY_BOUNDARY = (
    "Single source-directory scan only; no OCI or portable face, no cross-face "
    "reconciliation, and no sealed M4A package. raw.cyclonedx.json is the CycloneDX "
    "1.7 JSON input for downstream EUVD matching (the matcher accepts CycloneDX JSON "
    "only). sandbox-exec denies network access but does not isolate host-file reads. "
    "Output is not customer evidence, release, PRE-7/CRA conformity, or certification; "
    "to enter the full self-test pipeline, supply OCI and portable faces via the "
    "three-face selftest command."
)
SOURCE_ONLY_ZERO_COMPONENTS_STATUS = "SOURCE_ONLY_SCAN_COMPLETE_ZERO_COMPONENTS_OPEN_CANDIDATE"
SOURCE_ONLY_COVERAGE_HOLD_STATUS = "SOURCE_ONLY_SCAN_COMPLETE_COVERAGE_HOLD_OPEN_CANDIDATE"
SOURCE_ONLY_DEFAULT_MAX_FILES = 200_000
SOURCE_ONLY_DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
SOURCE_ONLY_DEFAULT_MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024 * 1024
SOURCE_ONLY_DEFAULT_MAX_DEPTH = 64
# Python declaration files that syft's python-package-cataloger consumes as
# input (installed environments are the other input). When none of these is
# present AND no environment is installed, the cataloger cannot see imports,
# so a pure-source Python snapshot yields an empty SBOM even for code that
# clearly imports third-party packages (e.g. ``import pygame``). This set is
# the recognition list for the zero-components finding (M9-1); it stays
# advisory (OPEN_CANDIDATE), it does not patch the SBOM or halt the handoff.
_DECLARED_PYTHON_DEPENDENCY_FILES = frozenset(
    {
        "requirements.txt",
        "requirements.in",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
    }
)
_ZERO_COMPONENTS_PYTHON_BLINDSPOT = "ZERO_COMPONENTS_PYTHON_PROJECT_REVIEW"
# M9 extension: syft 1.50.0 does NOT follow `-r <file>` / `--requirement <file>`
# references in requirements.txt (PaaS-style organisation). Advisory: surfaces
# the blind spot so a scan that under-reports dependencies is never silently
# accepted. Does not patch the SBOM (syft's catalogue remains authoritative).
_REQUIREMENTS_R_REFERENCE_BLINDSPOT = "REQUIREMENTS_R_REFERENCE_NOT_FOLLOWED_BY_SYFT_REVIEW"
# M9 extension: C/C++ source-only projects without a package-manager declaration
# file yield zero components (syft has no input to consume). Recognition set for
# the zero-components-C/C++ finding; advisory only.
_DECLARED_C_CPP_DEPENDENCY_FILES = frozenset(
    {
        "platformio.ini",
        "library.json",
        "library.properties",
        "conanfile.txt",
        "CONANFILE.txt",
        "vcpkg.json",
    }
)
_ZERO_COMPONENTS_C_CPP_BLINDSPOT = "ZERO_COMPONENTS_C_CPP_PROJECT_REVIEW"
# M9 extension: Home Assistant integration manifest.json carries pip
# `requirements` that syft source-only does not consume (HA custom-component
# dependency blind spot). AUXILIARY: surfaces the gap, never enters CycloneDX.
_HOME_ASSISTANT_MANIFEST_BLINDSPOT = "HOME_ASSISTANT_MANIFEST_DEPS_NOT_IN_SBOM_REVIEW"
# Directories whose .py contents are not project source (installed packages,
# bytecode caches, build artefacts). A stray .py under one of these must not
# count as evidence that the project is a Python project.
_PYTHON_SOURCE_EXCLUDE_DIRS = frozenset(
    {
        "__pycache__",
        "venv",
        ".venv",
        "env",
        ".env",
        "node_modules",
        "build",
        "dist",
        ".tox",
        ".eggs",
        "site-packages",
    }
)
QWEN_MODEL_ID = "Qwen3.6-35B-A3B-Uncensored-Heretic-MLX-4bit"
GEMMA_MODEL_ID = "gemma-4-26b-a4b-it-6bit"
MODEL_API_KEY_ENV = "SBOM_OMLX_API_KEY"
ACTIVE_EUVD_SOURCE_ENV = "SBOM_WORKBENCH_EUVD_SOURCE_ROOT"
DEFAULT_SYFT_RECEIPT = optional_checkout_path(
    "evidence/acquisition/syft-1.50.0-darwin-arm64.receipt.json"
)
DEFAULT_RUNTIME_REGISTRY = resource_path("datasets/runtime_registry.json")
DEFAULT_COSIGN_RECEIPT = optional_checkout_path(
    "runtime/tools/cosign-3.1.2/acquisition-receipt.json"
)
DEFAULT_SYNTHETIC_FIXTURES = data_root() / "fixtures" / "synthetic_orion"
DEFAULT_YOCTO_PROFILES = resource_path("datasets/yocto_reference_profiles.json")
TRUSTED_COSIGN_BINARY_SHA256 = (
    "dec1c3f802320b19c2fbcf2dc7bcfb3f258e1c181a046c23a1a074bdf932f10a"
)
TRUSTED_COSIGN_VERSION = "3.1.2"
TRUSTED_SYFT_BINARY_SHA256 = "5d59c9e6fa641793ddb48bc90b5b7ad63bf7303a52835b75b1beee3757463998"
TRUSTED_SYFT_CONFIG_SHA256 = "9aee3e875e9cafcb974a70517a522059598073e0f809dcd2dd9fab9bbb5eb5a5"
TRUSTED_SYFT_RECEIPT_SHA256 = "66714f0dc084a4d7777ad2558d17001bd984e08a64ea7f773cd7959dacd91892"
TRUSTED_RUNTIME_REGISTRY_SHA256 = "b37d65e011173a6e7fddb2d7c1798dbaca041a50422e1614c661b0cbef3a4dc3"
TRUSTED_SYFT_COMMIT = "16223e6dd7893fe578787658ceb876257483d404"
_MODEL_PERMISSION_KEYS = {
    "local_execution",
    "hosted_service",
    "internal_evaluation",
    "training_or_finetuning",
    "create_derivative_model",
    "distribute_derivative_model",
    "redistribute_original_weights",
    "redistribute_quantized_weights",
    "distribute_adapter",
    "distribute_merged_weights",
}


def _emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _source_only_implementation_identity() -> dict[str, object]:
    """Bind source-only behavior to the current Python implementation bytes."""

    package_root = Path(__file__).resolve(strict=True).parent
    files: list[dict[str, object]] = []
    for path in package_root.rglob("*.py"):
        relative = path.relative_to(package_root)
        if "__pycache__" in relative.parts:
            continue
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SelfTestError(
                f"implementation source must be a single-link regular file: {relative.as_posix()}"
            )
        files.append(
            {
                "relative_path": relative.as_posix(),
                "sha256": sha256_file(path),
                "size": info.st_size,
            }
        )
    files.sort(key=lambda item: str(item["relative_path"]).encode("utf-8"))
    return {
        "workbench_version": __version__,
        "identity_scope": "src/sbom_workbench/**/*.py",
        "file_count": len(files),
        "exact_set_sha256": hashlib.sha256(
            canonical_json_bytes({"workbench_version": __version__, "files": files})
        ).hexdigest(),
        "files": files,
        "boundary": "Current implementation bytes; not a clean-git or release attestation.",
    }


def _declared_source_provenance(
    parsed: argparse.Namespace,
    source_manifest: dict[str, object],
    output_root: Path,
) -> dict[str, object]:
    repository_url = parsed.source_url
    commit = parsed.source_commit
    if (repository_url is None) != (commit is None):
        raise SelfTestError("source_url and source_commit must be declared together")
    if repository_url is not None:
        if (
            not isinstance(repository_url, str)
            or not repository_url.startswith("https://")
            or len(repository_url) > 2048
            or any(ord(character) < 0x20 for character in repository_url)
        ):
            raise SelfTestError("source_url must be one bounded HTTPS URL")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SelfTestError("source_commit must be one lowercase 40-hex Git commit")
    license_expression = parsed.source_license
    if license_expression is not None and (
        not isinstance(license_expression, str)
        or not license_expression
        or len(license_expression) > 256
        or any(ord(character) < 0x20 for character in license_expression)
    ):
        raise SelfTestError("source_license must be bounded printable text")
    acquisition_receipt = parsed.source_acquisition_receipt
    trusted_acquisition_sha256 = parsed.trusted_source_acquisition_receipt_sha256
    if (acquisition_receipt is None) != (trusted_acquisition_sha256 is None):
        raise SelfTestError(
            "source acquisition receipt and its trusted SHA-256 must be declared together"
        )
    if acquisition_receipt is not None:
        try:
            report = load_trusted_acquisition_receipt(
                acquisition_receipt,
                trusted_acquisition_sha256,
            )
        except AcquisitionError as exc:
            raise SelfTestError(f"source acquisition receipt is invalid: {exc}") from exc
        acquisition_tree = report.get("tree_manifest")
        if not isinstance(acquisition_tree, dict) or set(acquisition_tree) != {
            "schema_version",
            "root_id",
            "file_count",
            "total_bytes",
            "exact_set_sha256",
            "files",
        }:
            raise SelfTestError("source acquisition receipt tree manifest is invalid")
        tree_root_id = acquisition_tree.get("root_id")
        tree_files = acquisition_tree.get("files")
        if (
            acquisition_tree.get("schema_version") != "1.0"
            or not isinstance(tree_root_id, str)
            or not tree_root_id
            or not isinstance(tree_files, list)
            or acquisition_tree.get("file_count") != source_manifest.get("file_count")
            or acquisition_tree.get("total_bytes") != source_manifest.get("total_bytes")
            or tree_files != source_manifest.get("files")
        ):
            raise SelfTestError(
                "source snapshot does not match the acquisition receipt exact-set"
            )
        expected_tree_sha256 = hashlib.sha256(
            canonical_json_bytes({"root_id": tree_root_id, "files": tree_files})
        ).hexdigest()
        if acquisition_tree.get("exact_set_sha256") != expected_tree_sha256:
            raise SelfTestError("source acquisition tree exact-set SHA-256 is invalid")
        if repository_url is not None and repository_url != report["source_url"]:
            raise SelfTestError("source_url differs from the acquisition receipt")
        if commit is not None and commit != report["resolved_commit"]:
            raise SelfTestError("source_commit differs from the acquisition receipt")
        if (
            license_expression is not None
            and license_expression != report["license_expression"]
        ):
            raise SelfTestError("source_license differs from the acquisition receipt")
        snapshot = _snapshot_pinned_runtime_file(
            Path(acquisition_receipt),
            output_root / "source-acquisition-receipt.json",
            expected_sha256=trusted_acquisition_sha256,
            executable=False,
        )
        return {
            "repository_url": report["source_url"],
            "commit": report["resolved_commit"],
            "declared_license_expression": report["license_expression"],
            "status": "GOVERNED_ACQUISITION_RECEIPT_AND_TREE_VERIFIED",
            "dataset_id": report["dataset_id"],
            "acquisition_status": report["acquisition_status"],
            "license_review_status": report["license_review_status"],
            "registry_sha256": report["registry_sha256"],
            "registry_entry_sha256": report["registry_entry_sha256"],
            "acquisition_receipt": {
                "path": snapshot.name,
                "sha256": trusted_acquisition_sha256,
            },
            "acquisition_tree": {
                "root_id": tree_root_id,
                "exact_set_sha256": expected_tree_sha256,
                "file_count": acquisition_tree["file_count"],
                "total_bytes": acquisition_tree["total_bytes"],
            },
            "boundary": (
                "Governed acquisition identity and source-tree exact-set are verified. "
                "ACQUIRED_UNSEALED or a license declaration does not establish rights, "
                "SBOM completeness, product release, or conformity."
            ),
        }
    return {
        "repository_url": repository_url,
        "commit": commit,
        "declared_license_expression": license_expression,
        "status": (
            "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
            if repository_url is not None
            else "NOT_DECLARED"
        ),
        "boundary": (
            "Declaration is bound into this receipt but is not a governed-acquisition "
            "verification or rights approval."
        ),
    }


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_directory(path: Path, label: str) -> Path:
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise SelfTestError(f"{label} is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise SelfTestError(f"{label} must be a non-symlink directory")
    return candidate.resolve(strict=True)


def _safe_regular_file(path: Path, label: str, *, executable: bool = False) -> Path:
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise SelfTestError(f"{label} is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SelfTestError(f"{label} must be one non-symlink, single-link regular file")
    if executable and not bool(info.st_mode & stat.S_IXUSR):
        raise SelfTestError(f"{label} must be executable by its owner")
    return candidate.resolve(strict=True)


def _trusted_system_sandbox(path: Path) -> Path:
    sandbox = _safe_regular_file(path, "sandbox-exec", executable=True)
    try:
        trusted = TRUSTED_SANDBOX_EXEC.resolve(strict=True)
        info = sandbox.stat()
    except OSError as exc:
        raise SelfTestError("trusted macOS sandbox-exec is unavailable") from exc
    if sandbox != trusted:
        raise SelfTestError("self-test requires the fixed macOS /usr/bin/sandbox-exec")
    if info.st_uid != TRUSTED_SANDBOX_UID or info.st_mode & 0o022:
        raise SelfTestError("trusted sandbox-exec ownership or write permissions are unsafe")
    return sandbox


def _configured_active_euvd_source_root(value: Path | None) -> Path:
    selected = value
    if selected is None:
        environment_value = os.environ.get(ACTIVE_EUVD_SOURCE_ENV)
        if environment_value:
            selected = Path(environment_value)
    if selected is None:
        raise SelfTestError(
            "active EUVD source boundary is not configured; pass --active-source-root "
            f"or set {ACTIVE_EUVD_SOURCE_ENV}"
        )
    candidate = Path(selected).expanduser()
    if not candidate.is_absolute():
        raise SelfTestError("active EUVD source boundary must be an absolute path")
    # Normalize lexically without statting or enumerating an operator-controlled
    # live tree.  Input snapshots are resolved separately by _safe_* helpers.
    return Path(os.path.abspath(os.fspath(candidate)))


def _new_output_root(path: Path) -> Path:
    requested = Path(path)
    if requested.name in {"", ".", ".."}:
        raise SelfTestError("output root must name one new directory")
    if requested.exists() or requested.is_symlink():
        raise SelfTestError(f"output root exists; refusing overwrite: {requested}")
    parent = requested.parent
    if parent.is_symlink():
        raise SelfTestError("output parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise SelfTestError("output parent is not a safe directory")
    destination = parent.resolve(strict=True) / requested.name
    if destination.exists() or destination.is_symlink():
        raise SelfTestError(f"output root exists; refusing overwrite: {destination}")
    destination.mkdir(mode=0o700)
    return destination


def _strict_json_file(path: Path, label: str, *, maximum: int = 64 * 1024 * 1024) -> object:
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise EvidenceError(f"{label} is unavailable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > maximum
    ):
        raise EvidenceError(f"{label} must be one bounded non-empty regular file")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise EvidenceError(f"{label} contains forbidden non-standard JSON constant: {value}")

    try:
        return json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise EvidenceError(f"{label} is not strict UTF-8 JSON") from exc


def _validate_docker_archive_budget(
    archive: Path,
    *,
    max_layers: int = SELFTEST_OCI_MAX_LAYERS,
    max_layer_compressed_bytes: int = SELFTEST_OCI_MAX_LAYER_COMPRESSED_BYTES,
    max_uncompressed_bytes: int = SELFTEST_OCI_MAX_UNCOMPRESSED_BYTES,
) -> dict[str, int]:
    """Pre-scan a docker-archive tarball and reject gzip layers whose
    cumulative uncompressed size, single-layer compressed size, or count
    exceeds the budget, BEFORE handing the archive to Syft.

    Syft decompresses image layers itself and exposes no extraction budget in
    its configuration; without this guard a malicious nested-gzip layer could
    exhaust TMPDIR before the post-scan JSON byte limit triggers (SEC-03).
    Only regular gzip-compressed members (magic 0x1f 0x8b) are counted as
    layers; manifest/config/index entries are ignored.
    """

    layer_count = 0
    total_uncompressed = 0
    try:
        bundle = tarfile.open(archive, mode="r:")
    except tarfile.ReadError as exc:
        raise SelfTestError("OCI archive is not a valid docker-archive tarball") from exc
    with bundle:
        for member in bundle:
            if not member.isreg():
                continue
            if member.size > max_layer_compressed_bytes:
                raise SelfTestError(
                    f"OCI archive layer exceeds compressed-size budget: {member.name}"
                )
            extracted = bundle.extractfile(member)
            if extracted is None:
                continue
            magic = extracted.read(2)
            if magic != b"\x1f\x8b":
                continue
            extracted.seek(0)
            layer_count += 1
            if layer_count > max_layers:
                raise SelfTestError(
                    f"OCI archive layer count exceeds budget ({max_layers})"
                )
            try:
                decompressor = gzip.GzipFile(fileobj=extracted)
                while True:
                    chunk = decompressor.read(SELFTEST_OCI_DECOMPRESS_CHUNK)
                    if not chunk:
                        break
                    total_uncompressed += len(chunk)
                    if total_uncompressed > max_uncompressed_bytes:
                        raise SelfTestError(
                            "OCI archive uncompressed size exceeds extraction budget"
                        )
            except (OSError, EOFError):
                # Not a valid gzip stream despite the magic; skip and let Syft
                # decide. The budget guard only counts decompressible layers.
                continue
    return {"layer_count": layer_count, "total_uncompressed_bytes": total_uncompressed}


def _minimal_process_environment(work_root: Path) -> dict[str, str]:
    cache = work_root / "cache"
    config = work_root / "config"
    temporary = work_root / "tmp"
    for directory in (cache, config, temporary):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": temporary.as_posix(),
        "XDG_CACHE_HOME": cache.as_posix(),
        "XDG_CONFIG_HOME": config.as_posix(),
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }


def _normalize_empty_scanner_cache(cache_root: Path) -> None:
    """Remove scanner-created empty cache directories from a new output root.

    Cache files are not silently discarded: their appearance changes the
    execution boundary and therefore fails closed.  Only empty descendants of
    the caller-created cache directory are removed; the cache root remains as
    part of the fixed runtime layout.
    """

    root = Path(cache_root)
    if root.is_symlink() or not root.is_dir():
        raise SelfTestError("scanner cache root is unsafe")
    descendants = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for path in descendants:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SelfTestError("scanner cache contains a symlink")
        if stat.S_ISREG(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SelfTestError("scanner cache contains persistent data; refusing silent deletion")
        try:
            path.rmdir()
        except OSError as exc:
            raise SelfTestError("scanner cache directory is not empty") from exc


def _run_bounded_process(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelfTestError(f"{label} could not complete under the network-deny sandbox") from exc
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise SelfTestError(f"{label} process output exceeded the diagnostic byte limit")
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()[:2048]
        raise SelfTestError(
            f"{label} failed under the network-deny sandbox"
            + (f": {diagnostic}" if diagnostic else "")
        )
    return result


def _verify_syft_runtime(
    syft_binary: Path,
    sandbox_exec: Path,
    *,
    work_root: Path,
    timeout_seconds: int,
) -> None:
    argv = [
        sandbox_exec.as_posix(),
        "-p",
        SANDBOX_NETWORK_DENY_PROFILE,
        syft_binary.as_posix(),
        "version",
        "-o",
        "json",
    ]
    result = _run_bounded_process(
        argv,
        cwd=work_root,
        environment=_minimal_process_environment(work_root / "version-runtime"),
        timeout_seconds=min(timeout_seconds, 120),
        label="Syft version check",
    )
    _normalize_empty_scanner_cache(work_root / "version-runtime" / "cache")
    try:
        version = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SelfTestError("Syft version output is not valid JSON") from exc
    if not isinstance(version, dict) or version.get("application") != "syft" or version.get(
        "version"
    ) != "1.50.0":
        raise SelfTestError("M3A requires the exact Syft 1.50.0 runtime")


def _verify_syft_acquisition(
    syft_binary: Path,
    syft_config: Path,
    acquisition_receipt: Path,
    runtime_registry: Path,
) -> dict[str, str]:
    if acquisition_receipt is None:
        raise SelfTestError(
            "Syft acquisition receipt is checkout-only and was not found; "
            "pass --syft-receipt explicitly"
        )
    receipt_path = _safe_regular_file(acquisition_receipt, "Syft acquisition receipt")
    registry_path = _safe_regular_file(runtime_registry, "runtime registry")
    if sha256_file(receipt_path) != TRUSTED_SYFT_RECEIPT_SHA256:
        raise SelfTestError("Syft acquisition receipt does not match the fixed trust anchor")
    if sha256_file(registry_path) != TRUSTED_RUNTIME_REGISTRY_SHA256:
        raise SelfTestError("runtime registry does not match the fixed M3A trust anchor")
    receipt = _strict_json_file(
        receipt_path, "Syft acquisition receipt", maximum=1024 * 1024
    )
    if not isinstance(receipt, dict) or any(
        receipt.get(key) != expected
        for key, expected in {
            "schema_version": "m3a-runtime-acquisition-1.0",
            "status": "ARCHIVE_HASH_VERIFIED_BINARY_OBSERVED",
            "resolved_commit": TRUSTED_SYFT_COMMIT,
            "binary_relative_path": "syft",
            "binary_sha256": TRUSTED_SYFT_BINARY_SHA256,
            "config_relative_path": "syft-m3a.yaml",
            "config_sha256": TRUSTED_SYFT_CONFIG_SHA256,
            "observed_version": "1.50.0",
            "dependency_manifest_status": "NOT_ACQUIRED",
        }.items()
    ):
        raise SelfTestError("Syft acquisition receipt fields do not match the pinned M3A runtime")
    if syft_binary.name != receipt["binary_relative_path"] or syft_config.name != receipt[
        "config_relative_path"
    ]:
        raise SelfTestError("Syft binary/config names do not match the acquisition receipt")

    registry = _strict_json_file(registry_path, "runtime registry", maximum=8 * 1024 * 1024)
    if (
        not isinstance(registry, dict)
        or registry.get("registry_type") != "runtime-registry"
        or registry.get("schema_version") != "1.0"
        or not isinstance(registry.get("runtimes"), list)
    ):
        raise SelfTestError("runtime registry root is invalid")
    matches = [
        item
        for item in registry["runtimes"]
        if isinstance(item, dict) and item.get("runtime_id") == "syft-1.50.0"
    ]
    if len(matches) != 1:
        raise SelfTestError("runtime registry does not uniquely register Syft 1.50.0")
    registered = matches[0]
    if any(
        registered.get(key) != expected
        for key, expected in {
            "category": "scanner",
            "name": "Syft",
            "version": "1.50.0",
            "resolved_commit": TRUSTED_SYFT_COMMIT,
            "artifact_sha256": TRUSTED_SYFT_BINARY_SHA256,
            "config_sha256": TRUSTED_SYFT_CONFIG_SHA256,
            "status": "LOCALLY_OBSERVED",
        }.items()
    ):
        raise SelfTestError("runtime registry Syft record differs from the pinned M3A identity")

    binary_sha256 = sha256_file(syft_binary)
    config_sha256 = sha256_file(syft_config)
    if binary_sha256 != TRUSTED_SYFT_BINARY_SHA256:
        raise SelfTestError("Syft binary SHA-256 does not match the pinned acquisition")
    if config_sha256 != TRUSTED_SYFT_CONFIG_SHA256:
        raise SelfTestError("Syft configuration SHA-256 does not match the pinned acquisition")
    return {
        "binary_sha256": binary_sha256,
        "config_sha256": config_sha256,
        "acquisition_receipt_sha256": TRUSTED_SYFT_RECEIPT_SHA256,
        "runtime_registry_sha256": TRUSTED_RUNTIME_REGISTRY_SHA256,
        "resolved_commit": TRUSTED_SYFT_COMMIT,
    }


def _verify_cosign_acquisition(
    cosign_binary: Path,
    acquisition_receipt: Path,
    runtime_registry: Path,
) -> dict[str, str]:
    """Verify cosign acquisition against the pinned binary sha256 + registry.

    Unlike Syft, the cosign acquisition receipt SHA-256 is intentionally NOT
    pinned: the receipt is a script product (scripts/acquire_cosign_m7.sh) and
    the trust root is the binary SHA-256 pinned to the official
    cosign_checksums.txt entry, re-checked against the on-disk binary here.
    """
    if acquisition_receipt is None:
        raise SigningError(
            "cosign acquisition receipt is not bundled; pass --cosign-receipt explicitly"
        )
    receipt_path = _safe_regular_file(acquisition_receipt, "cosign acquisition receipt")
    registry_path = _safe_regular_file(runtime_registry, "runtime registry")
    if sha256_file(registry_path) != TRUSTED_RUNTIME_REGISTRY_SHA256:
        raise SigningError("runtime registry does not match the fixed trust anchor")
    receipt = _strict_json_file(
        receipt_path, "cosign acquisition receipt", maximum=1024 * 1024
    )
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != "cosign-acquisition-1.0"
        or receipt.get("status") != "HASH_VERIFIED_BINARY_OBSERVED"
        or receipt.get("binary_relative_path") != "cosign"
        or receipt.get("binary_sha256_expected") != TRUSTED_COSIGN_BINARY_SHA256
        or receipt.get("binary_sha256_observed") != TRUSTED_COSIGN_BINARY_SHA256
    ):
        raise SigningError("cosign acquisition receipt fields do not match the pinned identity")
    observed_version = receipt.get("observed_version")
    if not isinstance(observed_version, str) or not observed_version.endswith(TRUSTED_COSIGN_VERSION):
        raise SigningError("cosign acquisition receipt observed_version does not match")
    registry = _strict_json_file(registry_path, "runtime registry", maximum=8 * 1024 * 1024)
    if not isinstance(registry, dict) or not isinstance(registry.get("runtimes"), list):
        raise SigningError("runtime registry root is invalid")
    matches = [
        item
        for item in registry["runtimes"]
        if isinstance(item, dict) and item.get("runtime_id") == "cosign-3.1.2"
    ]
    if len(matches) != 1:
        raise SigningError("runtime registry does not uniquely register cosign-3.1.2")
    if matches[0].get("artifact_sha256") != TRUSTED_COSIGN_BINARY_SHA256:
        raise SigningError("runtime registry cosign record differs from the pinned identity")
    binary_sha256 = sha256_file(cosign_binary)
    if binary_sha256 != TRUSTED_COSIGN_BINARY_SHA256:
        raise SigningError("cosign binary SHA-256 does not match the pinned acquisition")
    return {"binary_sha256": binary_sha256}


def _snapshot_pinned_runtime_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    executable: bool,
) -> Path:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(descriptor)
            raise SelfTestError("pinned runtime source is not one safe regular file")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=True) as reader, destination.open("xb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    except OSError as exc:
        raise SelfTestError("cannot snapshot the pinned scanner runtime") from exc
    if digest.hexdigest() != expected_sha256:
        raise SelfTestError("pinned scanner runtime changed while being snapshotted")
    destination.chmod(0o700 if executable else 0o600)
    return destination.resolve(strict=True)


def _file_input_identity(path: Path, root_id: str) -> dict[str, object]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise SelfTestError("OCI archive identity requires one non-empty single-link regular file")
    return {
        "root_id": root_id,
        "sha256": sha256_file(path),
        "file_count": 1,
        "total_bytes": info.st_size,
    }


def _directory_input_identity(manifest: dict[str, object]) -> dict[str, object]:
    if not manifest.get("file_count") or not manifest.get("total_bytes"):
        raise SelfTestError("self-test directory snapshot must contain non-empty regular-file evidence")
    return {
        "root_id": manifest["root_id"],
        "sha256": manifest["exact_set_sha256"],
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
    }


def _selftest_profile(
    *,
    profile_id: str,
    profile_kind: str,
    comparison_namespace: str,
    product_name: str,
    declared_version: str,
    scanner_identity: dict[str, str],
    timeout_seconds: int,
    extra_blindspots: frozenset[str] = frozenset(),
) -> dict[str, object]:
    return validate_selftest_profile({
        "schema_version": "1.0",
        "profile_id": profile_id,
        "classification": SELFTEST_CLASSIFICATION,
        "profile_kind": profile_kind,
        "independence_domain": PROFILE_DOMAINS[profile_kind],
        "subject": {
            "comparison_namespace": comparison_namespace,
            "product_name": product_name,
            "declared_version": declared_version,
        },
        "scanner": scanner_identity,
        "scan": {
            "target_kind": PROFILE_TARGETS[profile_kind],
            "target_label": profile_id,
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "max_json_bytes": SELFTEST_MAX_JSON_BYTES,
            "max_components": SELFTEST_MAX_COMPONENTS,
        },
        "blindspots": sorted(
            {
                *REQUIRED_BLINDSPOTS,
                "NO_NETWORK_ENRICHMENT",
                "NO_CROSS_PROFILE_COMPONENT_POPULATION",
                "SCANNER_OUTPUT_REQUIRES_HUMAN_REVIEW",
                *extra_blindspots,
            },
            key=lambda value: value.encode("utf-8"),
        ),
    })


def _assert_selftest_path_separation(
    source_root: Path,
    image_archive: Path,
    portable_root: Path,
    output_root: Path,
    active_source_root: Path,
) -> None:
    # The active path is an operator-configured, normalized absolute boundary.
    # Do not stat or
    # enumerate it: input paths have already been resolved, so lexical overlap
    # is sufficient to refuse the live tree and any ancestor containing it.
    # M3-6 (known PARTIAL): the configured active root is compared lexically
    # against resolved inputs; an alias symlink that resolves the active tree
    # outside its literal path could slip past this check. Resolving the active
    # path would close that gap but requires stating the live tree, which this
    # boundary deliberately avoids. The active path is operator-controlled (not
    # customer data), so the lexical guard is the chosen trade-off.
    active = active_source_root
    for label, path in (
        ("source snapshot", source_root),
        ("OCI archive", image_archive),
        ("portable snapshot", portable_root),
    ):
        if _is_within(path, active) or _is_within(active, path):
            raise SelfTestError(f"{label} overlaps the active EUVD source tree; use an isolated snapshot")
        if _is_within(output_root, path) or _is_within(path, output_root):
            raise SelfTestError(f"{label} and output root must not overlap")
    if (
        _is_within(source_root, portable_root)
        or _is_within(portable_root, source_root)
        or _is_within(image_archive, source_root)
        or _is_within(image_archive, portable_root)
    ):
        raise SelfTestError("source, OCI and portable inputs must remain isolated")


def _write_selftest_failure(output_root: Path, exc: Exception) -> None:
    failure = output_root / "FAILED.json"
    if failure.exists() or failure.is_symlink():
        return
    try:
        write_json_atomic(
            failure,
            {
                "schema_version": "1.0",
                "classification": SELFTEST_CLASSIFICATION,
                "status": "SELFTEST_FAIL_CLOSED_PARTIAL_EVIDENCE_PRESERVED",
                "error_type": type(exc).__name__,
                "message": str(exc)[:2048],
                "boundary": "Partial scanner output is not a sealed package or customer evidence.",
            },
        )
    except OSError:
        pass


def _execute_selftest(parsed: argparse.Namespace) -> dict[str, object]:
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise SelfTestError("timeout_seconds must be an integer in [1, 3600]")
    source_root = _safe_directory(parsed.source_root, "source snapshot")
    portable_root = _safe_directory(parsed.portable_root, "portable snapshot")
    image_archive = _safe_regular_file(parsed.image_archive, "OCI archive")
    syft_binary = _safe_regular_file(parsed.syft_bin, "Syft binary", executable=True)
    syft_config = _safe_regular_file(parsed.syft_config, "Syft configuration")
    sandbox_exec = _trusted_system_sandbox(parsed.sandbox_exec)

    requested_output = Path(parsed.output_root)
    prospective_parent = requested_output.parent.resolve(strict=False)
    prospective_output = prospective_parent / requested_output.name
    active_source_root = _configured_active_euvd_source_root(parsed.active_source_root)
    _assert_selftest_path_separation(
        source_root,
        image_archive,
        portable_root,
        prospective_output,
        active_source_root,
    )
    output_root = _new_output_root(requested_output)
    try:
        acquisition_identity = _verify_syft_acquisition(
            syft_binary,
            syft_config,
            parsed.syft_receipt,
            parsed.runtime_registry,
        )
        pinned_runtime_root = output_root / "runtime" / "pinned-scanner"
        execution_syft = _snapshot_pinned_runtime_file(
            syft_binary,
            pinned_runtime_root / "syft",
            expected_sha256=acquisition_identity["binary_sha256"],
            executable=True,
        )
        execution_config = _snapshot_pinned_runtime_file(
            syft_config,
            pinned_runtime_root / "syft-m3a.yaml",
            expected_sha256=acquisition_identity["config_sha256"],
            executable=False,
        )
        _verify_syft_runtime(
            execution_syft,
            sandbox_exec,
            work_root=output_root / "runtime",
            timeout_seconds=parsed.timeout_seconds,
        )
        scanner_identity = {
            "name": "syft",
            "version": "1.50.0",
            "binary_sha256": acquisition_identity["binary_sha256"],
            "config_sha256": acquisition_identity["config_sha256"],
        }
        source_manifest = build_exact_set_manifest(source_root, "euvd-source-snapshot")
        portable_manifest = build_exact_set_manifest(
            portable_root, "euvd-portable-runtime-snapshot"
        )
        image_identity = _file_input_identity(image_archive, "euvd-oci-archive")
        _validate_docker_archive_budget(image_archive)
        source_identity = _directory_input_identity(source_manifest)
        portable_identity = _directory_input_identity(portable_manifest)

        profile_specs = (
            (
                "m3a-source-directory",
                "SOURCE_DIRECTORY",
                source_root,
                source_identity,
            ),
            ("m3a-oci-archive", "OCI_ARCHIVE", image_archive, image_identity),
            (
                "m3a-portable-runtime",
                "PORTABLE_RUNTIME",
                portable_root,
                portable_identity,
            ),
        )
        observations: list[dict[str, object]] = []
        raw_documents: dict[str, dict[str, Path]] = {}
        scan_records: list[dict[str, object]] = []
        for profile_id, profile_kind, target, input_identity in profile_specs:
            profile = _selftest_profile(
                profile_id=profile_id,
                profile_kind=profile_kind,
                comparison_namespace=parsed.comparison_namespace,
                product_name=parsed.product_name,
                declared_version=parsed.declared_version,
                scanner_identity=scanner_identity,
                timeout_seconds=parsed.timeout_seconds,
            )
            raw_root = output_root / "raw" / profile_id
            raw_root.mkdir(mode=0o700, parents=True)
            contract = build_syft_command(
                execution_syft,
                profile_kind,
                target,
                raw_root.resolve(strict=True),
                config_path=execution_config,
                sandbox_exec=sandbox_exec,
                timeout_seconds=parsed.timeout_seconds,
            )
            if contract.get("network_policy") != "MACOS_SANDBOX_EXEC_DENY_NETWORK" or not any(
                "(deny network*)" in argument for argument in contract["argv"]
            ):
                raise SelfTestError("self-test scan lacks the mandatory OS network-deny contract")
            environment = _minimal_process_environment(
                output_root / "runtime" / profile_id
            )
            environment.update(contract["environment_overrides"])
            _run_bounded_process(
                list(contract["argv"]),
                cwd=raw_root,
                environment=environment,
                timeout_seconds=int(contract["timeout_seconds"]),
                label=f"Syft {profile_kind} scan",
            )
            _normalize_empty_scanner_cache(
                output_root / "runtime" / profile_id / "cache"
            )
            expected_names = {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"}
            if {path.name for path in raw_root.iterdir()} != expected_names:
                raise SelfTestError(f"Syft {profile_kind} raw output exact-set mismatch")
            for name in expected_names:
                _strict_json_file(
                    raw_root / name,
                    f"Syft {profile_kind} {name}",
                    maximum=SELFTEST_MAX_JSON_BYTES,
                )
            cyclonedx_path = raw_root / "raw.cyclonedx.json"
            projection, _ = load_cyclonedx(
                cyclonedx_path,
                max_json_bytes=SELFTEST_MAX_JSON_BYTES,
                max_components=SELFTEST_MAX_COMPONENTS,
            )
            observation = build_profile_observation(
                profile,
                projection,
                input_identity,
                scanner_identity,
            )
            observations.append(observation)
            raw_documents[profile_id] = {
                "syft": raw_root / "raw.syft.json",
                "cyclonedx": cyclonedx_path,
                "spdx": raw_root / "raw.spdx.json",
            }
            raw_manifest = build_exact_set_manifest(raw_root, f"{profile_id}-raw")
            scan_records.append(
                {
                    "profile_id": profile_id,
                    "profile_kind": profile_kind,
                    "network_policy": contract["network_policy"],
                    "raw_exact_set": raw_manifest,
                }
            )

        if build_exact_set_manifest(source_root, "euvd-source-snapshot") != source_manifest:
            raise SelfTestError("source snapshot changed during the self-test")
        if (
            build_exact_set_manifest(portable_root, "euvd-portable-runtime-snapshot")
            != portable_manifest
        ):
            raise SelfTestError("portable snapshot changed during the self-test")
        if _file_input_identity(image_archive, "euvd-oci-archive") != image_identity:
            raise SelfTestError("OCI archive changed during the self-test")
        if (
            sha256_file(syft_binary) != scanner_identity["binary_sha256"]
            or sha256_file(syft_config) != scanner_identity["config_sha256"]
            or sha256_file(execution_syft) != scanner_identity["binary_sha256"]
            or sha256_file(execution_config) != scanner_identity["config_sha256"]
        ):
            raise SelfTestError("Syft binary or configuration changed during the self-test")
        if (
            sha256_file(Path(parsed.syft_receipt))
            != acquisition_identity["acquisition_receipt_sha256"]
            or sha256_file(Path(parsed.runtime_registry))
            != acquisition_identity["runtime_registry_sha256"]
        ):
            raise SelfTestError("Syft receipt or runtime registry changed during the self-test")

        comparison = reconcile_profile_observations(observations)
        package = write_selftest_package(
            output_root / "data",
            observations=observations,
            comparison=comparison,
            raw_documents=raw_documents,
            source_manifest=source_manifest,
        )
        receipt = {
            "schema_version": "1.0",
            "classification": SELFTEST_CLASSIFICATION,
            "status": "M3A_SCAN_AND_M4A_PACKAGE_COMPLETE_OPEN_CANDIDATE",
            "scanner_identity": scanner_identity,
            "scanner_acquisition_identity": acquisition_identity,
            "source_input_identity": source_identity,
            "oci_input_identity": image_identity,
            "portable_input_identity": portable_identity,
            "scans": scan_records,
            "package": package,
            "boundary": (
                "Three isolated, network-denied generator observations were compared without "
                "forming a component-population union. sandbox-exec denies network access but does "
                "not isolate host-file reads; only the pinned scanner and explicit trusted snapshots "
                "are in scope. Privacy remains HOLD. Output is not customer evidence, release, "
                "PRE-7/CRA conformity, or certification."
            ),
        }
        write_json_atomic(output_root / "scan-receipt.json", receipt)
        write_json_atomic(
            output_root / "SELFTEST_COMPLETE.json",
            {
                "schema_version": "1.0",
                "classification": SELFTEST_CLASSIFICATION,
                "status": receipt["status"],
                "run_id": package["run_id"],
                "scan_receipt_sha256": sha256_file(output_root / "scan-receipt.json"),
                "package_manifest_sha256": package["manifest_sha256"],
                "reconciliation_status": "OPEN",
            },
        )
        completion_sha256 = sha256_file(output_root / "SELFTEST_COMPLETE.json")
        return {
            **package,
            "status": receipt["status"],
            "output_root": output_root.as_posix(),
            "run_directory": (output_root / "data" / "runs" / str(package["run_id"])).as_posix(),
            "raw_format_count": len(scan_records) * 3,
            "network_policy": "MACOS_SANDBOX_EXEC_DENY_NETWORK",
            "host_filesystem_isolation": "NOT_PROVIDED_BY_NETWORK_SANDBOX",
            "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
            "selftest_completion_sha256": completion_sha256,
            "external_anchor_instruction": (
                "Record selftest_completion_sha256 outside output_root before relying on later verification."
            ),
        }
    except Exception as exc:
        _write_selftest_failure(output_root, exc)
        raise


def _detect_zero_components_python_findings(
    source_root: Path, component_count: int
) -> dict[str, object]:
    """Detect the source-only failure mode where a Python project yields zero
    components because syft's python-package-cataloger inspects only installed
    environments and declaration files (requirements.txt / pyproject.toml /
    setup.py), never ``import`` statements.

    A pure-source snapshot with no declaration file and no installed
    environment therefore produces an empty SBOM even when third-party packages
    are clearly imported. This does NOT patch the SBOM — syft's catalogue
    remains authoritative — it surfaces the gap as an explicit, auditable
    finding so a zero-component Python result is never silently accepted as
    "complete". The finding is advisory (OPEN_CANDIDATE), not a halt: it does
    not block the downstream EUVD handoff.
    """
    python_source_files_present = False
    for path in source_root.rglob("*.py"):
        parents = path.relative_to(source_root).parts[:-1]
        if any(
            part in _PYTHON_SOURCE_EXCLUDE_DIRS or part.startswith(".")
            for part in parents
        ):
            continue
        python_source_files_present = True
        break
    declared_dependency_files_present = any(
        (source_root / name).exists() for name in _DECLARED_PYTHON_DEPENDENCY_FILES
    )
    zero_components_python_project = (
        component_count == 0
        and python_source_files_present
        and not declared_dependency_files_present
    )
    return {
        "component_count": component_count,
        "python_source_files_present": python_source_files_present,
        "declared_dependency_files_present": declared_dependency_files_present,
        "zero_components_python_project": zero_components_python_project,
    }


def _detect_requirements_r_reference(source_root: Path) -> dict[str, object]:
    """Detect ``-r <file>`` / ``--requirement <file>`` references in
    requirements*.txt files (M9 extension).

    syft 1.50.0's python-package-cataloger does NOT follow these references,
    so a PaaS-style ``requirements.txt`` that only contains ``-r prod.txt``
    yields a near-empty SBOM even when prod.txt lists the real dependencies
    A source tree can therefore yield an incomplete catalog even though the
    referenced requirements file contains additional dependencies. Advisory
    (OPEN_CANDIDATE): does not patch the SBOM and does not halt the handoff.
    """
    requirements_r_reference_present = False
    referenced_files: list[str] = []
    for path in source_root.rglob("*.txt"):
        parts = path.relative_to(source_root).parts
        if not parts:
            continue
        parents = parts[:-1]
        if any(
            part in _PYTHON_SOURCE_EXCLUDE_DIRS or part.startswith(".")
            for part in parents
        ):
            continue
        # match: filename starts with "requirements" (requirements.txt /
        # requirements-dev.txt) OR direct parent dir is "requirements"
        # (for example, a PaaS-style requirements/prod.txt layout)
        filename = parts[-1]
        parent_dir = parts[-2] if len(parts) >= 2 else ""
        if not (filename.startswith("requirements") or parent_dir == "requirements"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = stripped.split()
            if len(tokens) >= 2 and tokens[0] in ("-r", "--requirement"):
                requirements_r_reference_present = True
                referenced_files.append(tokens[1])
    return {
        "requirements_r_reference_present": requirements_r_reference_present,
        "referenced_files": sorted(set(referenced_files)),
    }


def _detect_zero_components_c_cpp_findings(
    source_root: Path, component_count: int
) -> dict[str, object]:
    """Detect the source-only failure mode where a C/C++ project yields zero
    components because syft has no package-manager declaration to consume
    (M9 extension; was Python-only).

    A pure-source C/C++ snapshot without platformio.ini / library.json /
    conanfile.txt / vcpkg.json produces an empty SBOM even for clearly
    third-party-dependent firmware. Advisory (OPEN_CANDIDATE).
    """
    c_cpp_source_files_present = False
    for pattern in ("*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.ino"):
        for path in source_root.rglob(pattern):
            parents = path.relative_to(source_root).parts[:-1]
            if any(
                part in _PYTHON_SOURCE_EXCLUDE_DIRS or part.startswith(".")
                for part in parents
            ):
                continue
            c_cpp_source_files_present = True
            break
        if c_cpp_source_files_present:
            break
    declared_dependency_files_present = any(
        (source_root / name).exists() for name in _DECLARED_C_CPP_DEPENDENCY_FILES
    )
    zero_components_c_cpp_project = (
        component_count == 0
        and c_cpp_source_files_present
        and not declared_dependency_files_present
    )
    return {
        "c_cpp_source_files_present": c_cpp_source_files_present,
        "declared_dependency_files_present": declared_dependency_files_present,
        "zero_components_c_cpp_project": zero_components_c_cpp_project,
    }


_HA_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


def _extract_home_assistant_manifest_deps(
    source_root: Path, sbom_component_names: frozenset[str]
) -> dict[str, object]:
    """Detect Home Assistant integration manifest.json ``requirements`` deps
    that syft source-only does not consume (M9 extension).

    HA custom integrations declare pip dependencies in ``manifest.json`` under
    the ``requirements`` key (e.g. ``["example-ha-client==0.3.17"]``); syft
    source-only does not parse this file, so the deps can be absent from the
    SBOM. HEURISTIC and AUXILIARY — never enters CycloneDX components. Only a
    manifest with a ``domain`` key is treated as a HA integration manifest.
    """
    home_assistant_manifest_present = False
    manifest_dependencies: list[str] = []
    for candidate in source_root.rglob("manifest.json"):
        parents = candidate.relative_to(source_root).parts[:-1]
        if any(
            part in _PYTHON_SOURCE_EXCLUDE_DIRS or part.startswith(".")
            for part in parents
        ):
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or "domain" not in data:
            continue
        home_assistant_manifest_present = True
        requirements = data.get("requirements", [])
        if isinstance(requirements, list):
            for entry in requirements:
                if not isinstance(entry, str):
                    continue
                name_match = _HA_REQUIREMENT_NAME_RE.match(entry)
                if name_match:
                    manifest_dependencies.append(name_match.group(1))
        break
    sbom_names_lower = {name.lower() for name in sbom_component_names}
    apparent_gaps = sorted(
        name
        for name in manifest_dependencies
        if name.lower() not in sbom_names_lower
    )
    return {
        "home_assistant_manifest_present": home_assistant_manifest_present,
        "manifest_dependencies": sorted(set(manifest_dependencies)),
        "apparent_gaps": apparent_gaps,
        "heuristic": (
            "manifest.json `requirements` parsed by leading package-name token; "
            "extras/source-URLs ignored; only manifests with a `domain` key are "
            "treated as Home Assistant integrations"
        ),
        "boundary": (
            "AUXILIARY_NOT_SBOM: Home Assistant manifest.json dependency "
            "extraction for gap awareness only; never enters CycloneDX "
            "components, never claims SBOM completeness, not CRA/prEN conformity."
        ),
    }


_IMPORT_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+([a-zA-Z_][\w.]*)", re.MULTILINE)


def _extract_import_evidence(
    source_root: Path, sbom_component_names: frozenset[str]
) -> dict[str, object]:
    """Extract third-party imports as AUXILIARY evidence (M9-2).

    Deterministic regex extraction of ``import`` / ``from ... import``
    statements across the project's ``.py`` files, filtered to third-party
    modules (stdlib and local project modules removed). The result is compared
    to the SBOM's component names to surface an apparent gap: modules the code
    imports but the SBOM does not list.

    This is HEURISTIC and AUXILIARY — it never enters CycloneDX components
    (syft's catalogue remains authoritative) and never claims completeness:

    * import name may differ from package name (cv2 vs opencv-python, PIL vs
      Pillow, yaml vs PyYAML) → apparent_gaps may over-report;
    * regex extraction cannot distinguish code from docstrings / strings;
    * the stdlib set is the runtime Python's, not the target project's.
    """
    local_modules: set[str] = set()
    py_files: list[Path] = []
    for path in source_root.rglob("*.py"):
        parents = path.relative_to(source_root).parts[:-1]
        if any(
            part in _PYTHON_SOURCE_EXCLUDE_DIRS or part.startswith(".")
            for part in parents
        ):
            continue
        py_files.append(path)
        local_modules.add(path.stem)
        # Each ancestor directory of a .py file is a potential local module /
        # package name (covers regular packages with __init__.py AND namespace
        # packages without). Heuristic: a project directory whose name collides
        # with a third-party package would over-filter, but that is rare and
        # the result is AUXILIARY anyway.
        local_modules.update(parents)
    imported: set[str] = set()
    for path in py_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _IMPORT_RE.findall(text):
            top_level = match.split(".")[0]
            if not top_level:
                continue  # relative import ("from . import x" → top_level "")
            imported.add(top_level)
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    sbom_names_lower = {name.lower() for name in sbom_component_names}
    imported_third_party = sorted(
        name
        for name in imported
        if name not in stdlib and name not in local_modules
    )
    apparent_gaps = sorted(
        name
        for name in imported_third_party
        if name.lower() not in sbom_names_lower
    )
    return {
        "imported_third_party_modules": imported_third_party,
        "apparent_gaps": apparent_gaps,
        "sbom_component_names": sorted(sbom_component_names),
        "heuristic": (
            "import-name vs package-name may differ (cv2/opencv-python, "
            "PIL/Pillow, yaml/PyYAML); regex may include docstrings/strings; "
            "stdlib set is the runtime Python's; local-module detection "
            "includes ancestor directory names (covers namespace packages) "
            "and may over-filter a dir name colliding with a 3rd-party package"
        ),
        "boundary": (
            "AUXILIARY_NOT_SBOM: deterministic import extraction for gap "
            "awareness only; never enters CycloneDX components, never claims "
            "SBOM completeness, not CRA/prEN conformity."
        ),
    }


def _execute_scan_source_only(parsed: argparse.Namespace) -> dict[str, object]:
    """Run one isolated source-directory Syft scan without the OCI/portable faces.

    Single-face escape hatch for users (and local models) that have only source
    code: produces the same CycloneDX 1.7 JSON the full three-face selftest
    produces for the source profile, so the downstream EUVD matcher (which
    accepts CycloneDX JSON only) can consume it directly. Deliberately does NOT
    synthesise cross-face reconciliation or a sealed M4A package, so the output
    cannot pass verify_selftest_root (three-face) — that isolation is the point.
    """
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise SelfTestError("timeout_seconds must be an integer in [1, 3600]")
    source_root = _safe_directory(parsed.source_root, "source snapshot")
    syft_binary = _safe_regular_file(parsed.syft_bin, "Syft binary", executable=True)
    syft_config = _safe_regular_file(parsed.syft_config, "Syft configuration")
    sandbox_exec = _trusted_system_sandbox(parsed.sandbox_exec)
    requested_output = Path(parsed.output_root)
    prospective_output = requested_output.parent.resolve(strict=False) / requested_output.name
    active_source_root = _configured_active_euvd_source_root(parsed.active_source_root)
    if _is_within(source_root, active_source_root) or _is_within(active_source_root, source_root):
        raise SelfTestError(
            "source snapshot overlaps the active EUVD source tree; use an isolated snapshot"
        )
    if _is_within(prospective_output, source_root) or _is_within(source_root, prospective_output):
        raise SelfTestError("source snapshot and output root must not overlap")
    output_root = _new_output_root(requested_output)
    try:
        implementation_identity = _source_only_implementation_identity()
        acquisition_identity = _verify_syft_acquisition(
            syft_binary,
            syft_config,
            parsed.syft_receipt,
            parsed.runtime_registry,
        )
        pinned_runtime_root = output_root / "runtime" / "pinned-scanner"
        execution_syft = _snapshot_pinned_runtime_file(
            syft_binary,
            pinned_runtime_root / "syft",
            expected_sha256=acquisition_identity["binary_sha256"],
            executable=True,
        )
        execution_config = _snapshot_pinned_runtime_file(
            syft_config,
            pinned_runtime_root / "syft-m3a.yaml",
            expected_sha256=acquisition_identity["config_sha256"],
            executable=False,
        )
        _verify_syft_runtime(
            execution_syft,
            sandbox_exec,
            work_root=output_root / "runtime",
            timeout_seconds=parsed.timeout_seconds,
        )
        scanner_identity = {
            "name": "syft",
            "version": "1.50.0",
            "binary_sha256": acquisition_identity["binary_sha256"],
            "config_sha256": acquisition_identity["config_sha256"],
        }
        source_resource_budgets = {
            "max_files": parsed.max_source_files,
            "max_total_bytes": parsed.max_source_bytes,
            "max_single_file_bytes": parsed.max_single_source_file_bytes,
            "max_depth": parsed.max_source_depth,
        }
        source_manifest = build_bounded_exact_set_manifest(
            source_root,
            "euvd-source-snapshot",
            **source_resource_budgets,
        )
        source_provenance = _declared_source_provenance(
            parsed,
            source_manifest,
            output_root,
        )
        source_identity = _directory_input_identity(source_manifest)
        profile_id = "m3a-source-directory"
        raw_root = output_root / "raw" / profile_id
        raw_root.mkdir(mode=0o700, parents=True)
        contract = build_syft_command(
            execution_syft,
            "SOURCE_DIRECTORY",
            source_root,
            raw_root.resolve(strict=True),
            config_path=execution_config,
            sandbox_exec=sandbox_exec,
            timeout_seconds=parsed.timeout_seconds,
        )
        if contract.get("network_policy") != "MACOS_SANDBOX_EXEC_DENY_NETWORK" or not any(
            "(deny network*)" in argument for argument in contract["argv"]
        ):
            raise SelfTestError("source-only scan lacks the mandatory OS network-deny contract")
        environment = _minimal_process_environment(output_root / "runtime" / profile_id)
        environment.update(contract["environment_overrides"])
        _run_bounded_process(
            list(contract["argv"]),
            cwd=raw_root,
            environment=environment,
            timeout_seconds=int(contract["timeout_seconds"]),
            label="Syft SOURCE_DIRECTORY scan",
        )
        _normalize_empty_scanner_cache(output_root / "runtime" / profile_id / "cache")
        expected_names = {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"}
        if {path.name for path in raw_root.iterdir()} != expected_names:
            raise SelfTestError("Syft SOURCE_DIRECTORY raw output exact-set mismatch")
        for name in expected_names:
            _strict_json_file(
                raw_root / name,
                f"Syft SOURCE_DIRECTORY {name}",
                maximum=SELFTEST_MAX_JSON_BYTES,
            )
        cyclonedx_path = raw_root / "raw.cyclonedx.json"
        projection, _ = load_cyclonedx(
            cyclonedx_path,
            max_json_bytes=SELFTEST_MAX_JSON_BYTES,
            max_components=SELFTEST_MAX_COMPONENTS,
        )
        component_count = len(projection["components"])
        component_population = build_component_population(
            source_root,
            source_manifest,
            projection,
            product_name=parsed.product_name,
            declared_version=parsed.declared_version,
            build_id=parsed.build_id,
            release_artifact_sha256=parsed.release_artifact_sha256,
        )
        ecosystem_audit = analyze_source_ecosystems(
            source_root,
            source_manifest,
            projection,
            cyclonedx_path,
        )
        source_findings = _detect_zero_components_python_findings(
            source_root, component_count
        )
        c_cpp_findings = _detect_zero_components_c_cpp_findings(source_root, component_count)
        requirements_r_reference = _detect_requirements_r_reference(source_root)
        sbom_component_names = frozenset(
            component.get("name")
            for component in projection["components"]
            if isinstance(component, dict) and component.get("name")
        )
        import_evidence = None
        if source_findings["python_source_files_present"]:
            import_evidence = _extract_import_evidence(source_root, sbom_component_names)
        home_assistant_manifest = _extract_home_assistant_manifest_deps(
            source_root, sbom_component_names
        )
        # Aggregate advisory blindspots (M9-1 Python zero + M9 extensions:
        # C/C++ zero, requirements -r reference, HA manifest deps). Advisory
        # only — never patches the SBOM, never halts the EUVD handoff.
        blindspots: set[str] = set()
        if source_findings["zero_components_python_project"]:
            blindspots.add(_ZERO_COMPONENTS_PYTHON_BLINDSPOT)
        if c_cpp_findings["zero_components_c_cpp_project"]:
            blindspots.add(_ZERO_COMPONENTS_C_CPP_BLINDSPOT)
        if requirements_r_reference["requirements_r_reference_present"]:
            blindspots.add(_REQUIREMENTS_R_REFERENCE_BLINDSPOT)
        if (
            home_assistant_manifest["home_assistant_manifest_present"]
            and home_assistant_manifest["apparent_gaps"]
        ):
            blindspots.add(_HOME_ASSISTANT_MANIFEST_BLINDSPOT)
        blindspots.update(ecosystem_audit["findings"])
        population_gate = component_population["reconciliation"]["gate"]
        if population_gate.startswith("HOLD_"):
            blindspots.add(f"COMPONENT_POPULATION_{population_gate}")
        profile = _selftest_profile(
            profile_id=profile_id,
            profile_kind="SOURCE_DIRECTORY",
            comparison_namespace=parsed.comparison_namespace,
            product_name=parsed.product_name,
            declared_version=parsed.declared_version,
            scanner_identity=scanner_identity,
            timeout_seconds=parsed.timeout_seconds,
            extra_blindspots=frozenset(blindspots),
        )
        if ecosystem_audit["coverage_gate"] == "HOLD" or population_gate.startswith(
            "HOLD_"
        ):
            status = SOURCE_ONLY_COVERAGE_HOLD_STATUS
        elif (
            source_findings["zero_components_python_project"]
            or c_cpp_findings["zero_components_c_cpp_project"]
        ):
            status = SOURCE_ONLY_ZERO_COMPONENTS_STATUS
        else:
            status = SOURCE_ONLY_STATUS
        observation = build_profile_observation(
            profile,
            projection,
            source_identity,
            scanner_identity,
        )
        if (
            build_bounded_exact_set_manifest(
                source_root,
                "euvd-source-snapshot",
                **source_resource_budgets,
            )
            != source_manifest
        ):
            raise SelfTestError("source snapshot changed during the scan")
        if (
            sha256_file(syft_binary) != scanner_identity["binary_sha256"]
            or sha256_file(syft_config) != scanner_identity["config_sha256"]
            or sha256_file(execution_syft) != scanner_identity["binary_sha256"]
            or sha256_file(execution_config) != scanner_identity["config_sha256"]
        ):
            raise SelfTestError("Syft binary or configuration changed during the scan")
        if (
            sha256_file(Path(parsed.syft_receipt))
            != acquisition_identity["acquisition_receipt_sha256"]
            or sha256_file(Path(parsed.runtime_registry))
            != acquisition_identity["runtime_registry_sha256"]
        ):
            raise SelfTestError("Syft receipt or runtime registry changed during the scan")
        if _source_only_implementation_identity() != implementation_identity:
            raise SelfTestError("Workbench implementation changed during the scan")
        raw_manifest = build_exact_set_manifest(raw_root, f"{profile_id}-raw")
        source_manifest_path = output_root / "source-manifest.json"
        write_json_atomic(source_manifest_path, source_manifest)
        component_population_path = output_root / "component-population.json"
        write_json_atomic(component_population_path, component_population)
        observation_path = output_root / "source-observation.json"
        write_json_atomic(observation_path, observation)
        run_id = observation["run_id"]
        receipt = {
            "schema_version": "1.0",
            "classification": SELFTEST_CLASSIFICATION,
            "status": status,
            "scanner_identity": scanner_identity,
            "scanner_acquisition_identity": acquisition_identity,
            "implementation_identity": implementation_identity,
            "source_provenance": source_provenance,
            "source_input_identity": source_identity,
            "source_manifest": {
                "path": "source-manifest.json",
                "sha256": sha256_file(source_manifest_path),
                "exact_set_sha256": source_manifest["exact_set_sha256"],
                "file_count": source_manifest["file_count"],
                "total_bytes": source_manifest["total_bytes"],
            },
            "component_population": {
                "path": "component-population.json",
                "sha256": sha256_file(component_population_path),
                "population_sha256": component_population["population_sha256"],
                "item_count": component_population["discovery"]["item_count"],
                "reconciliation_gate": population_gate,
            },
            "source_resource_budgets": source_resource_budgets,
            "scans": [
                {
                    "profile_id": profile_id,
                    "profile_kind": "SOURCE_DIRECTORY",
                    "network_policy": contract["network_policy"],
                    "raw_exact_set": raw_manifest,
                    "component_count": source_findings["component_count"],
                    "python_source_files_present": source_findings["python_source_files_present"],
                    "declared_dependency_files_present": source_findings["declared_dependency_files_present"],
                    "c_cpp_source_files_present": c_cpp_findings["c_cpp_source_files_present"],
                    "c_cpp_declared_dependency_files_present": c_cpp_findings["declared_dependency_files_present"],
                    "requirements_r_reference": requirements_r_reference,
                    "home_assistant_manifest": home_assistant_manifest,
                    "ecosystem_audit": ecosystem_audit,
                    "findings": sorted(blindspots),
                    "import_evidence": import_evidence,
                }
            ],
            "source_observation": {
                "run_id": run_id,
                "canonical_sha256": observation["canonical_sha256"],
                "observation_sha256": sha256_file(observation_path),
            },
            "boundary": SOURCE_ONLY_BOUNDARY,
        }
        write_json_atomic(output_root / "scan-receipt.json", receipt)
        write_json_atomic(
            output_root / "SELFTEST_COMPLETE.json",
            {
                "schema_version": "1.0",
                "classification": SELFTEST_CLASSIFICATION,
                "status": status,
                "run_id": run_id,
                "scan_receipt_sha256": sha256_file(output_root / "scan-receipt.json"),
                "reconciliation_status": "NOT_APPLICABLE_SINGLE_FACE",
                "component_population_sha256": component_population["population_sha256"],
                "component_population_gate": population_gate,
            },
        )
        completion_sha256 = sha256_file(output_root / "SELFTEST_COMPLETE.json")
        return {
            "status": status,
            "classification": SELFTEST_CLASSIFICATION,
            "run_id": run_id,
            "output_root": output_root.as_posix(),
            "raw_root": (output_root / "raw" / profile_id).as_posix(),
            "cyclonedx_path": cyclonedx_path.as_posix(),
            "cyclonedx_sha256": sha256_file(cyclonedx_path),
            "component_count": len(projection["components"]),
            "product_package_candidate_count": ecosystem_audit["component_scope"][
                "product_package_candidate_count"
            ],
            "coverage_gate": ecosystem_audit["coverage_gate"],
            "component_population_gate": population_gate,
            "component_population_item_count": component_population["discovery"]["item_count"],
            "component_population_unmatched_count": component_population["reconciliation"][
                "unmatched_item_count"
            ],
            "component_population_root_identity_hold_count": component_population[
                "reconciliation"
            ]["root_identity_hold_item_count"],
            "build_binding_status": component_population["product_build_binding"]["status"],
            "source_manifest_sha256": sha256_file(source_manifest_path),
            "source_provenance_status": source_provenance["status"],
            "profile_count": 1,
            "raw_format_count": 3,
            "network_policy": "MACOS_SANDBOX_EXEC_DENY_NETWORK",
            "host_filesystem_isolation": "NOT_PROVIDED_BY_NETWORK_SANDBOX",
            "reconciliation_status": "NOT_APPLICABLE_SINGLE_FACE",
            "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
            "selftest_completion_sha256": completion_sha256,
            "external_anchor_instruction": (
                "Record selftest_completion_sha256 outside output_root before relying on "
                "later verification. raw.cyclonedx.json is the CycloneDX 1.7 JSON input for "
                "downstream EUVD matching."
            ),
            "boundary": SOURCE_ONLY_BOUNDARY,
        }
    except Exception as exc:
        _write_selftest_failure(output_root, exc)
        raise


def _execute_sign(parsed: argparse.Namespace) -> dict[str, object]:
    """Sign a sealed pack's ite6-statement.json with cosign offline key-based mode."""
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise SigningError("timeout_seconds must be an integer in [1, 3600]")
    cosign_binary = _safe_regular_file(parsed.cosign_bin, "cosign binary", executable=True)
    key_path = _safe_regular_file(parsed.key, "signing key")
    pack_directory = _safe_directory(parsed.pack_directory, "sealed pack")
    acquisition = _verify_cosign_acquisition(
        cosign_binary, parsed.cosign_receipt, parsed.runtime_registry
    )
    artefact = pack_directory / "ite6-statement.json"
    _safe_regular_file(artefact, "ite6-statement.json")
    signature_path = pack_directory / "ite6-statement.json.sig"
    if signature_path.exists() or signature_path.is_symlink():
        raise SigningError(f"signature already exists; refusing overwrite: {signature_path}")
    argv = build_cosign_sign_command(cosign_binary, key_path, artefact, signature_path)
    environment = _minimal_process_environment(pack_directory / ".cosign-runtime")
    environment["COSIGN_PASSWORD"] = os.environ.get("COSIGN_PASSWORD", "")
    _run_bounded_process(
        list(argv),
        cwd=pack_directory,
        environment=environment,
        timeout_seconds=parsed.timeout_seconds,
        label="cosign sign-blob (offline key-based)",
    )
    tool_identity = {
        "name": "cosign",
        "version": TRUSTED_COSIGN_VERSION,
        "binary_sha256": acquisition["binary_sha256"],
    }
    receipt = build_receipt(
        subject_name="canonical-reconciliation-ite6",
        subject_sha256=sha256_file(artefact),
        signature_path=signature_path.name,
        signature_sha256=sha256_file(signature_path),
        key_id=parsed.key_id,
        signed_at_utc=datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        tool_identity=tool_identity,
    )
    output_path = _new_output_file(parsed.output, "signature receipt output")
    write_json_atomic(output_path, receipt)
    return {
        "status": "SIGNATURE_RECEIPT_WRITTEN",
        "subject_sha256": receipt["subject"]["digest"]["sha256"],
        "signature_sha256": receipt["signature"]["sha256"],
        "key_id": receipt["key_id"],
        "receipt_path": output_path.as_posix(),
        "boundary": receipt["boundary"],
    }


def _execute_verify(parsed: argparse.Namespace) -> dict[str, object]:
    """Verify a sealed pack signature receipt + cosign verify-blob (offline)."""
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise SigningError("timeout_seconds must be an integer in [1, 3600]")
    cosign_binary = _safe_regular_file(parsed.cosign_bin, "cosign binary", executable=True)
    key_path = _safe_regular_file(parsed.key, "verification key")
    pack_directory = _safe_directory(parsed.pack_directory, "sealed pack")
    receipt_path = _safe_regular_file(parsed.receipt, "signature receipt")
    _verify_cosign_acquisition(
        cosign_binary, parsed.cosign_receipt, parsed.runtime_registry
    )
    receipt = _strict_json_file(receipt_path, "signature receipt", maximum=1024 * 1024)
    validate_receipt(receipt)
    artefact = pack_directory / "ite6-statement.json"
    _safe_regular_file(artefact, "ite6-statement.json")
    signature_path = pack_directory / receipt["signature"]["path"]
    _safe_regular_file(signature_path, "signature file")
    if receipt["subject"]["digest"]["sha256"] != sha256_file(artefact):
        raise SigningError("receipt subject does not bind ite6-statement.json")
    if receipt["signature"]["sha256"] != sha256_file(signature_path):
        raise SigningError("receipt does not bind the signature file")
    argv = build_cosign_verify_command(cosign_binary, key_path, artefact, signature_path)
    environment = _minimal_process_environment(pack_directory / ".cosign-runtime")
    try:
        _run_bounded_process(
            list(argv),
            cwd=pack_directory,
            environment=environment,
            timeout_seconds=parsed.timeout_seconds,
            label="cosign verify-blob (offline key-based)",
        )
    except subprocess.CalledProcessError as exc:
        raise SigningError(f"cosign verify-blob rejected the signature: {exc}") from exc
    return {
        "status": "SIGNATURE_VERIFIED",
        "subject_sha256": receipt["subject"]["digest"]["sha256"],
        "signature_sha256": receipt["signature"]["sha256"],
        "key_id": receipt["key_id"],
        "boundary": "Signature verified against the on-disk cosign binary; not release, conformity, or CAB.",
    }


def _execute_intake_vex(parsed: argparse.Namespace) -> dict[str, object]:
    """Consume a signed VEX document from a trusted issuer (M8-1).

    Verifies cosign acquisition (tool trust anchor) → issuer allowlist +
    pinned public key (issuer trust anchor) → cosign verify-blob (signature)
    → parse + fail-closed validate each statement → exact-set intake receipt.
    Narrowing happens downstream; this lane only records evidence.
    """
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise VexConsumeError("timeout_seconds must be an integer in [1, 3600]")
    cosign_binary = _safe_regular_file(parsed.cosign_bin, "cosign binary", executable=True)
    acquisition = _verify_cosign_acquisition(
        cosign_binary, parsed.cosign_receipt, parsed.runtime_registry
    )
    allowlist_path = _safe_regular_file(parsed.issuer_allowlist, "issuer allowlist")
    allowlist, _ = load_and_validate_registry(allowlist_path)
    matches = [
        issuer
        for issuer in allowlist.get("issuers", [])
        if isinstance(issuer, dict) and issuer.get("issuer_id") == parsed.issuer_id
    ]
    if len(matches) != 1:
        raise VexConsumeError(f"issuer_id {parsed.issuer_id!r} is not uniquely registered")
    issuer = matches[0]
    if issuer.get("status") != "ADMITTED_FOR_VEX_INTAKE":
        raise VexConsumeError(f"issuer {parsed.issuer_id!r} is not admitted for VEX intake")
    public_key_path = (allowlist_path.parent / issuer["public_key_path"]).resolve(strict=True)
    _safe_regular_file(public_key_path, "issuer public key")
    if sha256_file(public_key_path) != issuer["public_key_sha256"]:
        raise VexConsumeError("issuer public key sha256 does not match the allowlist")
    vex_path = _safe_regular_file(parsed.vex_document, "VEX document")
    signature_path = _safe_regular_file(parsed.signature, "VEX signature")
    verify_argv = build_cosign_verify_command(
        cosign_binary, public_key_path, vex_path, signature_path
    )
    environment = _minimal_process_environment(vex_path.parent / ".cosign-runtime")
    try:
        _run_bounded_process(
            list(verify_argv),
            cwd=vex_path.parent,
            environment=environment,
            timeout_seconds=parsed.timeout_seconds,
            label="cosign verify-blob (VEX intake, offline key-based)",
        )
    except SelfTestError as exc:
        raise VexConsumeError(f"cosign verify-blob rejected the VEX signature: {exc}") from exc
    vex_payload = vex_path.read_bytes()
    vex_format, raw_statements = parse_vex_document(vex_payload)
    vex_document_sha256 = hashlib.sha256(vex_payload).hexdigest()
    validated = [
        validate_vex_statement(
            raw,
            vex_format=vex_format,
            issuer_id=parsed.issuer_id,
            vex_document_sha256=vex_document_sha256,
        )
        for raw in raw_statements
    ]
    receipt = build_vex_intake_receipt(
        vex_format=vex_format,
        vex_document_sha256=vex_document_sha256,
        signature_sha256=sha256_file(signature_path),
        issuer_id=parsed.issuer_id,
        validated_statements=validated,
        cosign_tool_identity={
            "name": "cosign",
            "version": TRUSTED_COSIGN_VERSION,
            "binary_sha256": acquisition["binary_sha256"],
        },
    )
    output_path = _new_output_file(parsed.output, "VEX intake receipt output")
    write_json_atomic(output_path, receipt)
    return {
        "status": "VEX_INTAKE_RECORDED",
        "vex_format": receipt["vex_format"],
        "vex_document_sha256": receipt["vex_document_sha256"],
        "statement_count": receipt["statement_count"],
        "narrowing_eligible_count": receipt["narrowing_eligible_count"],
        "issuer_id": receipt["issuer_id"],
        "receipt_path": output_path.as_posix(),
        "boundary": receipt["boundary"],
    }


def _execute_intake_narrowed(parsed: argparse.Namespace) -> dict[str, object]:
    """Reconcile matcher hits against a trusted M8-1 VEX intake receipt (M8-2).

    EUVD_TO_SBOM_NARROWING_ONLY lane: read-only ``validate_euvd_handoff`` →
    ``verify_vex_intake_binding`` (re-derive VEX hashes, NOT just structural
    validate) → ``parse_matcher_hits`` + purl-presence gate → strictest-wins
    ``narrow_one_hit`` per hit → exact-set narrowed-reconcile-receipt. The
    outbound handoff directory is NEVER opened for write; the receipt lands in
    ``<output>/narrowed/<reconcile_id>/``. VEX binding failure still COMPLEtes
    (writes a receipt with all narrowed=false + rejection_reason) so a corrupt
    VEX file cannot DoS evidence recording — hits are preserved either way.
    """
    if type(parsed.timeout_seconds) is not int or not 1 <= parsed.timeout_seconds <= 3600:
        raise NarrowingError("timeout_seconds must be an integer in [1, 3600]")
    if parsed.operator_max_receipt_age_days < 0:
        raise NarrowingError("operator_max_receipt_age_days must be >= 0")
    handoff_dir = _safe_directory(parsed.euvd_handoff, "euvd handoff directory")
    handoff_info = validate_euvd_handoff(handoff_dir)
    handoff_binding = {
        "handoff_id": handoff_info["handoff_id"],
        "cyclonedx_sha256": handoff_info["cyclonedx_sha256"],
        "source_binding_status": handoff_info["source_binding_status"],
    }
    cyclonedx_path = handoff_dir / "cyclonedx-input.json"
    _safe_regular_file(cyclonedx_path, "handoff cyclonedx-input.json")
    projection, _ = load_cyclonedx(
        cyclonedx_path,
        max_json_bytes=SELFTEST_MAX_JSON_BYTES,
        max_components=SELFTEST_MAX_COMPONENTS,
    )
    handoff_purls = {
        canonicalize_purl(component.get("purl"))
        for component in projection.get("components", [])
        if isinstance(component, dict)
    }
    handoff_purls.discard(None)
    vex_receipt_path = _safe_regular_file(parsed.vex_intake_receipt, "VEX intake receipt")
    vex_receipt = json.loads(vex_receipt_path.read_bytes().decode("utf-8"))
    if not isinstance(vex_receipt, dict):
        raise NarrowingError("VEX intake receipt must be a JSON object")
    vex_payload = _safe_regular_file(parsed.vex_document, "VEX document").read_bytes()
    vex_intake_binding = {
        "issuer_id": vex_receipt["issuer_id"],
        "vex_document_sha256": vex_receipt["vex_document_sha256"],
        "signature_sha256": vex_receipt["signature_sha256"],
        "statements_canonical_sha256": vex_receipt["statements_canonical_sha256"],
        "narrowing_eligible_count": vex_receipt["narrowing_eligible_count"],
    }
    vex_binding_failed = False
    validated_statements: list[dict[str, object]] = []
    try:
        validated_statements = verify_vex_intake_binding(
            vex_receipt, vex_payload=vex_payload, issuer_id=parsed.issuer_id
        )
    except VexConsumeError:
        vex_binding_failed = True
    matcher_hits_path = _safe_regular_file(parsed.matcher_hits, "matcher-hits.json")
    matcher_hits_payload = matcher_hits_path.read_bytes()
    matcher_hits_sha256 = hashlib.sha256(matcher_hits_payload).hexdigest()
    hits_doc = parse_matcher_hits(matcher_hits_payload)
    if hits_doc["source"]["handoff_id"] != handoff_binding["handoff_id"]:
        raise NarrowingError(
            "matcher-hits source handoff_id does not match the euvd handoff"
        )
    if hits_doc["source"]["cyclonedx_sha256"] != handoff_binding["cyclonedx_sha256"]:
        raise NarrowingError(
            "matcher-hits source cyclonedx_sha256 does not match the euvd handoff"
        )
    validate_purl_presence(hits_doc["hits"], handoff_purls)
    if vex_binding_failed:
        decisions = [
            {
                "vulnerability_id": hit["vulnerability_id"],
                "product_purl": hit["product_purl"],
                "original_status": hit["original_status"],
                "narrowed_by_trusted_vex": False,
                "vex_pointers": [],
                "rejection_reason": REASON_VEX_INTAKE_BINDING_FAILED,
                "original_hit_preserved": True,
            }
            for hit in hits_doc["hits"]
        ]
    else:
        decisions = [narrow_one_hit(hit, validated_statements) for hit in hits_doc["hits"]]
    receipt = build_narrowed_receipt(
        handoff_binding=handoff_binding,
        vex_intake_binding=vex_intake_binding,
        vex_document_last_updated_utc=None,  # v1: STALE detection deferred (M8-3 may parse VEX last_updated)
        operator_max_receipt_age_days=parsed.operator_max_receipt_age_days,
        matcher_hits_sha256=matcher_hits_sha256,
        decisions=decisions,
    )
    validate_narrowed_receipt(receipt)  # self-check before persisting
    output_root = Path(parsed.output)
    output_root.mkdir(parents=True, exist_ok=True)
    narrowed_dir = output_root / "narrowed" / receipt["reconcile_id"]
    if narrowed_dir.exists():
        raise NarrowingError(
            f"narrowed receipt output already exists; refusing overwrite: {narrowed_dir}"
        )
    narrowed_dir.mkdir(parents=True, exist_ok=False)
    write_json_atomic(narrowed_dir / "decisions.json", decisions)
    write_json_atomic(narrowed_dir / "narrowed-reconcile-receipt.json", receipt)
    return {
        "status": "NARROWING_RECONCILE_RECORDED",
        "reconcile_id": receipt["reconcile_id"],
        "total_hits": receipt["total_hits"],
        "narrowed_count": receipt["narrowed_count"],
        "not_narrowed_count": receipt["not_narrowed_count"],
        "vex_intake_binding_failed": vex_binding_failed,
        "direction": receipt["direction"],
        "receipt_path": (narrowed_dir / "narrowed-reconcile-receipt.json").as_posix(),
        "boundary": receipt["boundary"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbom-workbench")
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate-registry", help="fail-closed registry validation")
    validate.add_argument("registry", type=Path)

    sources = subcommands.add_parser("list-sources", help="list governed source records")
    sources.add_argument("registry", type=Path)

    model_status = subcommands.add_parser("model-status", help="fail-closed Phase 1 model intake gate")
    model_status.add_argument("registry", type=Path)
    model_status.add_argument(
        "--trusted-model-intake-sha256",
        default=DEFAULT_TRUSTED_MODEL_INTAKE_SHA256,
        help="out-of-band trusted SHA-256 for the blocked model intake baseline",
    )

    acquire = subcommands.add_parser("acquire", help="explicit online acquisition of one pinned source")
    acquire.add_argument("--registry", required=True, type=Path)
    acquire.add_argument("--dataset-id", required=True)
    acquire.add_argument("--destination", required=True, type=Path)
    acquire.add_argument(
        "--trusted-registry-sha256",
        default=DEFAULT_TRUSTED_SOURCE_REGISTRY_SHA256,
        help="out-of-band trusted SHA-256; changing it is a governed operator decision",
    )
    acquire.add_argument("--receipt-out", type=Path, help="optional immutable full acquisition receipt")

    verify = subcommands.add_parser("verify-acquisition", help="read-only consumer verification of an acquisition")
    verify.add_argument("--registry", required=True, type=Path)
    verify.add_argument("--dataset-id", required=True)
    verify.add_argument("--target", required=True, type=Path)
    verify.add_argument(
        "--trusted-acquisition-manifest-sha256",
        required=True,
        help="SHA-256 from an independently controlled evidence index or release manifest",
    )
    verify.add_argument(
        "--trusted-registry-sha256",
        default=DEFAULT_TRUSTED_SOURCE_REGISTRY_SHA256,
        help="out-of-band trusted SHA-256; changing it is a governed operator decision",
    )

    analyze = subcommands.add_parser(
        "analyze",
        help="analyze and seal one project-owned synthetic release fixture",
    )
    analyze.add_argument("--fixture", required=True, type=Path)
    analyze.add_argument("--data-root", required=True, type=Path)

    demo = subcommands.add_parser(
        "demo",
        help="run synthetic release A/B and the expected-open conflict control",
    )
    demo.add_argument(
        "--fixtures-root",
        type=Path,
        default=DEFAULT_SYNTHETIC_FIXTURES,
    )
    demo.add_argument("--data-root", required=True, type=Path)

    validate_output = subcommands.add_parser(
        "validate-output",
        help="read-only verification of one sealed synthetic run package",
    )
    validate_output.add_argument("--run-directory", required=True, type=Path)
    validate_output.add_argument(
        "--trusted-manifest-sha256",
        help="optional package-external trust anchor for a closed run manifest",
    )

    import_excel = subcommands.add_parser(
        "import-pro03b",
        help="read-only import of PRO-03B v1.4 manual/supplier claims",
    )
    import_excel.add_argument("workbook", type=Path)

    validate_yocto_profiles = subcommands.add_parser(
        "validate-yocto-profiles",
        help="validate the strict public Yocto reference profile registry",
    )
    validate_yocto_profiles.add_argument("registry", type=Path)

    acquire_yocto = subcommands.add_parser(
        "acquire-yocto-reference",
        help="explicit online acquisition of one hash-pinned public Yocto reference",
    )
    acquire_yocto.add_argument("--profiles", required=True, type=Path)
    acquire_yocto.add_argument("--profile-id", required=True)
    acquire_yocto.add_argument("--destination", required=True, type=Path)
    acquire_yocto.add_argument(
        "--trusted-profile-registry-sha256",
        default=DEFAULT_TRUSTED_YOCTO_PROFILE_REGISTRY_SHA256,
        help="out-of-band trusted SHA-256 for the checked-in M2 profile registry",
    )

    analyze_yocto = subcommands.add_parser(
        "analyze-yocto-reference",
        help="offline analysis and candidate export for one acquired public Yocto reference",
    )
    analyze_yocto.add_argument("--profiles", required=True, type=Path)
    analyze_yocto.add_argument("--profile-id", required=True)
    analyze_yocto.add_argument("--input-root", required=True, type=Path)
    analyze_yocto.add_argument("--data-root", required=True, type=Path)
    analyze_yocto.add_argument(
        "--trusted-profile-registry-sha256",
        default=DEFAULT_TRUSTED_YOCTO_PROFILE_REGISTRY_SHA256,
    )

    yocto_demo = subcommands.add_parser(
        "yocto-reference-demo",
        help="offline A/B analysis of all acquired public Yocto reference profiles",
    )
    yocto_demo.add_argument("--profiles", required=True, type=Path)
    yocto_demo.add_argument("--inputs-root", required=True, type=Path)
    yocto_demo.add_argument("--data-root", required=True, type=Path)
    yocto_demo.add_argument(
        "--trusted-profile-registry-sha256",
        default=DEFAULT_TRUSTED_YOCTO_PROFILE_REGISTRY_SHA256,
    )

    validate_reference = subcommands.add_parser(
        "validate-reference-output",
        help="read-only verification of one sealed public-reference candidate package",
    )
    validate_reference.add_argument("--run-directory", required=True, type=Path)
    validate_reference.add_argument(
        "--profiles",
        type=Path,
        default=DEFAULT_YOCTO_PROFILES,
    )
    validate_reference.add_argument(
        "--trusted-profile-registry-sha256",
        default=DEFAULT_TRUSTED_YOCTO_PROFILE_REGISTRY_SHA256,
    )

    selftest = subcommands.add_parser(
        "selftest",
        help="run isolated source, OCI and portable Syft scans and seal an OPEN self-test pack",
    )
    selftest.add_argument("--source-root", required=True, type=Path)
    selftest.add_argument("--image-archive", required=True, type=Path)
    selftest.add_argument("--portable-root", required=True, type=Path)
    selftest.add_argument(
        "--active-source-root",
        type=Path,
        help=f"absolute live EUVD tree boundary; alternatively set {ACTIVE_EUVD_SOURCE_ENV}",
    )
    selftest.add_argument("--syft-bin", required=True, type=Path)
    selftest.add_argument("--syft-config", required=True, type=Path)
    selftest.add_argument(
        "--syft-receipt",
        type=Path,
        default=DEFAULT_SYFT_RECEIPT,
        help="checked-in acquisition receipt bound to a fixed SHA-256 trust anchor",
    )
    selftest.add_argument(
        "--runtime-registry",
        type=Path,
        default=DEFAULT_RUNTIME_REGISTRY,
        help="checked-in runtime registry bound to a fixed SHA-256 trust anchor",
    )
    selftest.add_argument("--output-root", required=True, type=Path)
    selftest.add_argument(
        "--sandbox-exec",
        type=Path,
        default=DEFAULT_SANDBOX_EXEC,
        help="fixed /usr/bin/sandbox-exec used with an explicit deny-network profile",
    )
    selftest.add_argument("--timeout-seconds", type=int, default=600)
    selftest.add_argument(
        "--comparison-namespace", default="euvd-sbom-matcher-selftest"
    )
    selftest.add_argument("--product-name", default="euvd-sbom-matcher")
    selftest.add_argument("--declared-version", default="2.3.0")

    source_only = subcommands.add_parser(
        "scan-source-only",
        help="scan one source directory to CycloneDX 1.7 JSON (single-face; no OCI/portable/M4A)",
    )
    source_only.add_argument("--source-root", required=True, type=Path)
    source_only.add_argument(
        "--active-source-root",
        type=Path,
        help=f"absolute live EUVD tree boundary; alternatively set {ACTIVE_EUVD_SOURCE_ENV}",
    )
    source_only.add_argument("--syft-bin", required=True, type=Path)
    source_only.add_argument("--syft-config", required=True, type=Path)
    source_only.add_argument(
        "--syft-receipt",
        type=Path,
        default=DEFAULT_SYFT_RECEIPT,
        help="checked-in acquisition receipt bound to a fixed SHA-256 trust anchor",
    )
    source_only.add_argument(
        "--runtime-registry",
        type=Path,
        default=DEFAULT_RUNTIME_REGISTRY,
        help="checked-in runtime registry bound to a fixed SHA-256 trust anchor",
    )
    source_only.add_argument("--output-root", required=True, type=Path)
    source_only.add_argument(
        "--sandbox-exec",
        type=Path,
        default=DEFAULT_SANDBOX_EXEC,
        help="fixed /usr/bin/sandbox-exec used with an explicit deny-network profile",
    )
    source_only.add_argument("--timeout-seconds", type=int, default=600)
    source_only.add_argument("--source-url")
    source_only.add_argument("--source-commit")
    source_only.add_argument("--source-license")
    source_only.add_argument(
        "--source-acquisition-receipt",
        type=Path,
        help="governed acquisition receipt whose tree_manifest must match source-root",
    )
    source_only.add_argument(
        "--trusted-source-acquisition-receipt-sha256",
        help="external SHA-256 trust anchor for --source-acquisition-receipt",
    )
    source_only.add_argument(
        "--max-source-files",
        type=int,
        default=SOURCE_ONLY_DEFAULT_MAX_FILES,
    )
    source_only.add_argument(
        "--max-source-bytes",
        type=int,
        default=SOURCE_ONLY_DEFAULT_MAX_TOTAL_BYTES,
    )
    source_only.add_argument(
        "--max-single-source-file-bytes",
        type=int,
        default=SOURCE_ONLY_DEFAULT_MAX_SINGLE_FILE_BYTES,
    )
    source_only.add_argument(
        "--max-source-depth",
        type=int,
        default=SOURCE_ONLY_DEFAULT_MAX_DEPTH,
    )
    source_only.add_argument(
        "--comparison-namespace", default="euvd-sbom-matcher-selftest"
    )
    source_only.add_argument("--product-name", default="euvd-sbom-matcher")
    source_only.add_argument("--declared-version", default="2.3.0")
    source_only.add_argument(
        "--build-id",
        help="bounded release/build identifier; requires --release-artifact-sha256",
    )
    source_only.add_argument(
        "--release-artifact-sha256",
        help="lowercase SHA-256 of the release artifact; requires --build-id",
    )

    validate_selftest = subcommands.add_parser(
        "validate-selftest-output",
        help="read-only verification of one sealed M4A self-test run directory",
    )
    validate_selftest.add_argument("--run-directory", required=True, type=Path)

    validate_source_only = subcommands.add_parser(
        "validate-source-only-output",
        help="read-only verification of one source-only scan and its single-face boundary",
    )
    validate_source_only.add_argument("--output-root", required=True, type=Path)
    validate_source_only.add_argument("--source-root", type=Path)
    validate_source_only.add_argument("--trusted-completion-sha256")

    prepare_privacy_projection = subcommands.add_parser(
        "prepare-source-analysis-projection",
        help="create a hash-bound CycloneDX analysis projection with declared source-root paths normalized",
    )
    prepare_privacy_projection.add_argument("--source-output-root", required=True, type=Path)
    prepare_privacy_projection.add_argument("--source-root", required=True, type=Path)
    prepare_privacy_projection.add_argument("--output-root", required=True, type=Path)

    validate_privacy_projection = subcommands.add_parser(
        "validate-source-analysis-projection",
        help="read-only validation of one hash-bound source analysis projection",
    )
    validate_privacy_projection.add_argument("--projection-root", required=True, type=Path)
    validate_privacy_projection.add_argument("--source-output-root", required=True, type=Path)
    validate_privacy_projection.add_argument("--trusted-completion-sha256")

    validate_selftest_root = subcommands.add_parser(
        "validate-selftest-root",
        help="read-only verification of all 3x3 raw outputs plus the sealed M4A package",
    )
    validate_selftest_root.add_argument("--output-root", required=True, type=Path)

    prepare_handoff = subcommands.add_parser(
        "prepare-euvd-handoff",
        help="prepare a no-overwrite, one-way CycloneDX handoff for the loopback EUVD matcher",
    )
    prepare_handoff.add_argument("--selftest-root", required=True, type=Path)
    prepare_handoff.add_argument(
        "--profile-id",
        choices=(
            "m3a-source-directory",
            "m3a-oci-archive",
            "m3a-portable-runtime",
        ),
        default="m3a-source-directory",
    )
    prepare_handoff.add_argument("--handoff-root", required=True, type=Path)

    validate_handoff = subcommands.add_parser(
        "validate-euvd-handoff",
        help="read-only verification of one EUVD handoff; pass its M3A root to reverify provenance",
    )
    validate_handoff.add_argument("--handoff-directory", required=True, type=Path)
    validate_handoff.add_argument("--selftest-root", type=Path)

    run_model_evaluation = subcommands.add_parser(
        "run-model-evaluation",
        help="run the sealed Qwen/Gemma/rule shadow comparison without fact-write authority",
    )
    run_model_evaluation.add_argument("--cards", required=True, type=Path)
    run_model_evaluation.add_argument("--runtime-observations", required=True, type=Path)
    run_model_evaluation.add_argument("--output", required=True, type=Path)
    run_model_evaluation.add_argument("--endpoint", default=DEFAULT_OMLX_ENDPOINT)
    run_model_evaluation.add_argument("--timeout-seconds", type=float, default=120.0)
    run_model_evaluation.add_argument("--max-output-tokens", type=int, default=1200)

    run_model_candidate = subcommands.add_parser(
        "run-model-candidate-evaluation",
        help="evaluate one versioned local model candidate without changing the sealed M5A baseline",
    )
    card_source = run_model_candidate.add_mutually_exclusive_group(required=True)
    card_source.add_argument("--cards", type=Path)
    card_source.add_argument("--baseline-evaluation", type=Path)
    run_model_candidate.add_argument("--model-dir", required=True, type=Path)
    run_model_candidate.add_argument("--runtime-binary", required=True, type=Path)
    run_model_candidate.add_argument("--runtime-version", required=True)
    run_model_candidate.add_argument("--model-id", required=True)
    run_model_candidate.add_argument("--endpoint", default=DEFAULT_OMLX_ENDPOINT)
    run_model_candidate.add_argument("--observed-at", default=datetime.date.today().isoformat())
    run_model_candidate.add_argument("--upstream-revision")
    run_model_candidate.add_argument("--quantization-observation", required=True)
    run_model_candidate.add_argument("--output", required=True, type=Path)
    run_model_candidate.add_argument("--timeout-seconds", type=float, default=120.0)
    run_model_candidate.add_argument("--max-output-tokens", type=int, default=1200)

    prepare_model_cards = subcommands.add_parser(
        "prepare-model-evaluation-cards",
        help="derive sealed minimal conflict cards from one verified M3A/M4A output root",
    )
    prepare_model_cards.add_argument("--selftest-root", required=True, type=Path)
    prepare_model_cards.add_argument("--output", required=True, type=Path)

    validate_model_evaluation = subcommands.add_parser(
        "validate-model-evaluation",
        help="read-only validation of one sealed shadow-model evaluation record",
    )
    validate_model_evaluation.add_argument("--evaluation", required=True, type=Path)
    validate_model_evaluation.add_argument("--trusted-evaluation-sha256")

    validate_model_candidate = subcommands.add_parser(
        "validate-model-candidate-evaluation",
        help="read-only validation of one M5B single-model shadow candidate record",
    )
    validate_model_candidate.add_argument("--evaluation", required=True, type=Path)
    validate_model_candidate.add_argument("--trusted-evaluation-sha256")

    backup_selftest = subcommands.add_parser(
        "backup-selftest",
        help="create a no-overwrite exact-set backup of self-test evidence",
    )
    backup_selftest.add_argument("--source-root", required=True, type=Path)
    backup_selftest.add_argument("--backup", required=True, type=Path)
    backup_selftest.add_argument(
        "--root-id",
        help="optional consistency assertion; the verified M3A run_id remains authoritative",
    )

    validate_backup = subcommands.add_parser(
        "validate-selftest-backup",
        aliases=["validate-backup-selftest"],
        help="read-only validation of one self-test backup",
    )
    validate_backup.add_argument("--backup", required=True, type=Path)
    validate_backup.add_argument("--trusted-manifest-sha256")

    restore_selftest = subcommands.add_parser(
        "restore-selftest",
        help="restore one validated backup to a new destination",
    )
    restore_selftest.add_argument("--backup", required=True, type=Path)
    restore_selftest.add_argument("--destination", required=True, type=Path)
    restore_selftest.add_argument("--trusted-manifest-sha256", required=True)

    clear_selftest = subcommands.add_parser(
        "clear-selftest",
        help="move one marked direct-child self-test run into recoverable quarantine and write a receipt",
    )
    clear_selftest.add_argument("--run-directory", required=True, type=Path)
    clear_selftest.add_argument("--allowed-parent", required=True, type=Path)
    clear_selftest.add_argument("--receipt", required=True, type=Path)

    sign_pack = subcommands.add_parser(
        "sign-selftest-pack",
        help="sign a sealed pack's ite6-statement.json with cosign offline key-based mode",
    )
    sign_pack.add_argument("--pack-directory", required=True, type=Path)
    sign_pack.add_argument("--cosign-bin", required=True, type=Path)
    sign_pack.add_argument(
        "--cosign-receipt",
        type=Path,
        default=DEFAULT_COSIGN_RECEIPT,
        help="cosign acquisition receipt (runtime/tools/cosign-3.1.2/acquisition-receipt.json)",
    )
    sign_pack.add_argument(
        "--runtime-registry",
        type=Path,
        default=DEFAULT_RUNTIME_REGISTRY,
        help="checked-in runtime registry bound to a fixed SHA-256 trust anchor",
    )
    sign_pack.add_argument("--key", required=True, type=Path)
    sign_pack.add_argument("--key-id", required=True)
    sign_pack.add_argument("--output", required=True, type=Path)
    sign_pack.add_argument("--timeout-seconds", type=int, default=120)

    verify_sig = subcommands.add_parser(
        "verify-signature",
        help="verify a sealed pack signature receipt + cosign verify-blob (offline)",
    )
    verify_sig.add_argument("--pack-directory", required=True, type=Path)
    verify_sig.add_argument("--cosign-bin", required=True, type=Path)
    verify_sig.add_argument(
        "--cosign-receipt", type=Path, default=DEFAULT_COSIGN_RECEIPT
    )
    verify_sig.add_argument(
        "--runtime-registry", type=Path, default=DEFAULT_RUNTIME_REGISTRY
    )
    verify_sig.add_argument("--key", required=True, type=Path)
    verify_sig.add_argument("--receipt", required=True, type=Path)
    verify_sig.add_argument("--timeout-seconds", type=int, default=120)

    intake_vex = subcommands.add_parser(
        "intake-vex",
        help="consume a signed VEX not_affected statement from a trusted issuer (M8-1)",
    )
    intake_vex.add_argument("--vex-document", required=True, type=Path)
    intake_vex.add_argument("--signature", required=True, type=Path)
    intake_vex.add_argument("--issuer-allowlist", required=True, type=Path)
    intake_vex.add_argument("--issuer-id", required=True)
    intake_vex.add_argument("--cosign-bin", required=True, type=Path)
    intake_vex.add_argument(
        "--cosign-receipt", type=Path, default=DEFAULT_COSIGN_RECEIPT
    )
    intake_vex.add_argument(
        "--runtime-registry", type=Path, default=DEFAULT_RUNTIME_REGISTRY
    )
    intake_vex.add_argument("--output", required=True, type=Path)
    intake_vex.add_argument("--timeout-seconds", type=int, default=120)

    intake_narrowed = subcommands.add_parser(
        "intake-narrowed",
        help="reconcile matcher hits against a trusted VEX intake receipt (M8-2 narrowing)",
    )
    intake_narrowed.add_argument("--matcher-hits", required=True, type=Path)
    intake_narrowed.add_argument("--euvd-handoff", required=True, type=Path)
    intake_narrowed.add_argument("--vex-intake-receipt", required=True, type=Path)
    intake_narrowed.add_argument("--vex-document", required=True, type=Path)
    intake_narrowed.add_argument("--issuer-id", required=True)
    intake_narrowed.add_argument(
        "--operator-max-receipt-age-days", type=int, default=90
    )
    intake_narrowed.add_argument("--output", required=True, type=Path)
    intake_narrowed.add_argument("--timeout-seconds", type=int, default=120)

    serve = subcommands.add_parser(
        "serve",
        help="serve source generation and optional registered evidence on loopback only",
    )
    serve.add_argument(
        "--data-root",
        type=Path,
        help="optional hash-bound run registry; omit for source-generation-only mode",
    )
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--syft-bin", type=Path)
    serve.add_argument("--syft-config", type=Path)
    serve.add_argument("--syft-receipt", type=Path)
    serve.add_argument("--runtime-registry", type=Path)
    serve.add_argument("--sandbox-exec", type=Path, default=DEFAULT_SANDBOX_EXEC)
    serve.add_argument("--scan-timeout-seconds", type=int, default=600)
    serve.add_argument("--disable-scanning", action="store_true")
    return parser


def _trusted_yocto_profiles(registry_path: Path, expected_sha256: str) -> list[dict[str, object]]:
    path = Path(registry_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise EvidenceError("Yocto profile registry must be a bounded regular file")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise EvidenceError(
            "Yocto profile registry does not match the out-of-band trust anchor; "
            f"expected {expected_sha256}, got {actual}"
        )
    return load_profile_registry(path)


def _yocto_profile(profiles: list[dict[str, object]], profile_id: str) -> dict[str, object]:
    matches = [profile for profile in profiles if profile.get("profile_id") == profile_id]
    if len(matches) != 1:
        raise EvidenceError(f"Yocto reference profile is not uniquely registered: {profile_id}")
    return matches[0]


def _trusted_source(
    registry_path: Path,
    dataset_id: str,
    expected_registry_sha256: str,
) -> tuple[dict[str, object], str]:
    data, _, actual_registry_sha256 = load_and_validate_registry_with_hash(registry_path)
    if data["registry_type"] != "source-dataset-registry":
        raise RegistryError("operation requires a source dataset registry")
    if actual_registry_sha256 != expected_registry_sha256:
        raise RegistryError(
            "source registry does not match the out-of-band trust anchor; "
            f"expected {expected_registry_sha256}, got {actual_registry_sha256}"
        )
    return find_source(data, dataset_id), actual_registry_sha256


def _blocked_model_intake_status(registry_path: Path, expected_sha256: str) -> list[dict[str, str]]:
    try:
        payload = registry_path.read_bytes()
        data = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read model intake registry: {exc}") from exc
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RegistryError(
            "model intake does not match the out-of-band blocked baseline; "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    if not isinstance(data, dict) or set(data) != {
        "registry_type",
        "schema_version",
        "updated_at",
        "default_policy",
        "models",
    }:
        raise RegistryError("model intake root does not match the Phase 1 blocked contract")
    if data.get("registry_type") != "model-runtime-intake" or data.get("schema_version") != "1.0":
        raise RegistryError("model intake type or version is unsupported")
    models = data.get("models")
    if not isinstance(models, list) or not models:
        raise RegistryError("model intake must contain at least one blocked model record")
    statuses: list[dict[str, str]] = []
    seen: set[str] = set()
    for model in models:
        if not isinstance(model, dict):
            raise RegistryError("model intake entry must be an object")
        intake_id = model.get("intake_id")
        if not isinstance(intake_id, str) or not intake_id or intake_id in seen:
            raise RegistryError("model intake IDs must be non-empty and unique")
        seen.add(intake_id)
        if model.get("intake_status") != "BLOCKED_PENDING_EXACT_MODEL_ID":
            raise RegistryError("Phase 1 model gate cannot authorize or execute a model")
        decision = model.get("rights_decision")
        if not isinstance(decision, dict) or decision.get("decision_status") != "BLOCKED_PENDING_EXACT_MODEL_ID":
            raise RegistryError("Phase 1 model rights decision must remain blocked")
        permissions = decision.get("permissions")
        if not isinstance(permissions, dict) or set(permissions) != _MODEL_PERMISSION_KEYS or any(
            value != "NOT_AUTHORIZED" for value in permissions.values()
        ):
            raise RegistryError("Phase 1 model permissions must all be NOT_AUTHORIZED")
        statuses.append(
            {
                "intake_id": intake_id,
                "family_hint": str(model.get("family_hint", "")),
                "status": "BLOCKED_PENDING_EXACT_MODEL_ID",
            }
        )
    return statuses


def _new_output_file(path: Path, label: str) -> Path:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise EvidenceError(f"{label} exists; refusing overwrite")
    parent = destination.parent
    if parent.is_symlink():
        raise EvidenceError(f"{label} parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise EvidenceError(f"{label} parent is invalid")
    resolved = parent.resolve(strict=True) / destination.name
    if resolved.exists() or resolved.is_symlink():
        raise EvidenceError(f"{label} exists; refusing overwrite")
    return resolved


def _validated_runtime_observations(value: object, endpoint: str) -> dict[str, object]:
    normalized = normalize_runtime_observations(value)
    if normalized["runtime"]["endpoint"] != endpoint:
        raise ModelEvaluationError("runtime observation endpoint differs from the requested endpoint")
    return normalized


def _execute_model_evaluation(parsed: argparse.Namespace) -> dict[str, object]:
    cards = _strict_json_file(parsed.cards, "model evaluation cards", maximum=8 * 1024 * 1024)
    if not isinstance(cards, list):
        raise ModelEvaluationError("model evaluation cards file must contain one JSON array")
    runtime = _validated_runtime_observations(
        _strict_json_file(
            parsed.runtime_observations,
            "model runtime observations",
            maximum=8 * 1024 * 1024,
        ),
        parsed.endpoint,
    )
    output = _new_output_file(parsed.output, "model evaluation output")
    api_key = os.environ.get(MODEL_API_KEY_ENV)
    if api_key is None:
        raise ModelAdapterError(
            f"enabled shadow evaluation requires {MODEL_API_KEY_ENV} in the process environment"
        )

    adapters = {
        model_id: OmlxModelAdapter(
            enabled=True,
            endpoint=parsed.endpoint,
            model_id=model_id,
            allowed_model_ids=frozenset({model_id}),
            api_key=api_key,
            timeout=parsed.timeout_seconds,
            seed=20260804,
            max_output_tokens=parsed.max_output_tokens,
        )
        for model_id in (QWEN_MODEL_ID, GEMMA_MODEL_ID)
    }
    record = run_sealed_evaluation(
        cards,
        {model_id: adapter.advise for model_id, adapter in adapters.items()},
        runtime_observations=runtime,
    )
    validation = validate_evaluation(record)
    write_json_atomic(output, record)
    persisted = _strict_json_file(output, "model evaluation output", maximum=64 * 1024 * 1024)
    if persisted != record:
        raise ModelEvaluationError("persisted model evaluation differs from the sealed record")
    validate_evaluation(persisted)
    return {
        **validation,
        "safety_gate": record["safety_gate"],
        "privacy_gate": record["privacy_gate"],
        "benefit_gate": record["benefit_gate"],
        "output": output.as_posix(),
        "output_sha256": sha256_file(output),
        "external_anchor_instruction": (
            "Record evaluation_payload_sha256 outside this evaluation before later validation."
        ),
        "api_key_source": f"ENVIRONMENT_ONLY:{MODEL_API_KEY_ENV}",
        "api_key_captured": False,
        "api_key_present": api_key is not None,
    }


def _execute_model_candidate_evaluation(parsed: argparse.Namespace) -> dict[str, object]:
    output = _new_output_file(parsed.output, "model candidate evaluation output")
    if parsed.baseline_evaluation is not None:
        baseline = _strict_json_file(
            parsed.baseline_evaluation,
            "baseline model evaluation",
            maximum=64 * 1024 * 1024,
        )
        validate_evaluation(baseline)
        cards = baseline["cards"]
        card_source = {
            "kind": "VALIDATED_M5A_EVALUATION",
            "path": Path(parsed.baseline_evaluation).name,
            "sha256": sha256_file(parsed.baseline_evaluation),
        }
    else:
        cards = _strict_json_file(
            parsed.cards,
            "model candidate evaluation cards",
            maximum=8 * 1024 * 1024,
        )
        if not isinstance(cards, list):
            raise ModelEvaluationError("model candidate cards must be one JSON array")
        card_source = {
            "kind": "STANDALONE_SEALED_CARD_SET",
            "path": Path(parsed.cards).name,
            "sha256": sha256_file(parsed.cards),
        }
    profile = observe_candidate_profile(
        model_directory=parsed.model_dir,
        runtime_binary=parsed.runtime_binary,
        runtime_version=parsed.runtime_version,
        endpoint=parsed.endpoint,
        model_id=parsed.model_id,
        observed_at=parsed.observed_at,
        upstream_revision=parsed.upstream_revision,
        quantization_observation=parsed.quantization_observation,
    )
    api_key = os.environ.get(MODEL_API_KEY_ENV)
    if api_key is None:
        raise ModelAdapterError(
            f"enabled shadow evaluation requires {MODEL_API_KEY_ENV} in the process environment"
        )
    adapter = OmlxModelAdapter(
        enabled=True,
        endpoint=parsed.endpoint,
        model_id=parsed.model_id,
        allowed_model_ids=frozenset({parsed.model_id}),
        api_key=api_key,
        timeout=parsed.timeout_seconds,
        seed=20260804,
        max_output_tokens=parsed.max_output_tokens,
    )
    record = run_candidate_evaluation(
        cards,
        adapter.advise,
        candidate_profile=profile,
    )
    validation = validate_candidate_evaluation(record)
    write_json_atomic(output, record)
    persisted = _strict_json_file(
        output,
        "model candidate evaluation output",
        maximum=128 * 1024 * 1024,
    )
    if persisted != record:
        raise ModelEvaluationError("persisted model candidate evaluation differs")
    validate_candidate_evaluation(persisted)
    return {
        **validation,
        "output": output.as_posix(),
        "output_sha256": sha256_file(output),
        "card_source": card_source,
        "model_directory_exact_set_sha256": profile["model"]["directory_manifest"][
            "exact_set_sha256"
        ],
        "runtime_binary_sha256": profile["runtime"]["binary_sha256"],
        "api_key_source": f"ENVIRONMENT_ONLY:{MODEL_API_KEY_ENV}",
        "api_key_captured": False,
        "external_anchor_instruction": (
            "Record evaluation_payload_sha256 outside this output before later validation."
        ),
    }


def main(arguments: list[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "validate-registry":
            _, report = load_and_validate_registry(parsed.registry)
            _emit(
                {
                    "status": "REGISTRY_STRUCTURE_VALIDATED",
                    "boundary": "does not grant acquisition, use, rights, format, or release approval",
                    **report,
                    "registry": str(parsed.registry),
                }
            )
            return 0
        if parsed.command == "list-sources":
            data, _ = load_and_validate_registry(parsed.registry)
            if data["registry_type"] != "source-dataset-registry":
                raise RegistryError("list-sources requires a source dataset registry")
            _emit(
                {
                    "status": "REGISTRY_STRUCTURE_VALIDATED",
                    "boundary": "individual governance fields remain controlling",
                    "sources": [
                        {
                            "dataset_id": source["dataset_id"],
                            "commit": source["pin"]["resolved_commit"],
                            "admission": source["governance"]["admission_status"],
                            "split": source["governance"]["split"],
                            "training_allowed": source["governance"]["training_allowed"],
                        }
                        for source in data["sources"]
                    ],
                }
            )
            return 0
        if parsed.command == "model-status":
            statuses = _blocked_model_intake_status(
                parsed.registry,
                parsed.trusted_model_intake_sha256,
            )
            _emit(
                {
                    "status": "MODEL_PATH_BLOCKED",
                    "boundary": "no model execution or use right is authorized by this Phase 1 gate",
                    "models": statuses,
                }
            )
            return 0
        if parsed.command == "acquire":
            if parsed.receipt_out is not None and (parsed.receipt_out.exists() or parsed.receipt_out.is_symlink()):
                raise AcquisitionError(f"receipt already exists; refusing overwrite: {parsed.receipt_out}")
            source, registry_sha256 = _trusted_source(
                parsed.registry,
                parsed.dataset_id,
                parsed.trusted_registry_sha256,
            )
            report = acquire_git_source(
                source,
                parsed.destination,
                registry_sha256=registry_sha256,
                registry_entry_sha256=registry_entry_hash(source),
            )
            target = parsed.destination / report["dataset_id"] / report["resolved_commit"]
            acquisition_manifest_sha256 = sha256_file(target / "acquisition_manifest.json")
            if parsed.receipt_out is not None:
                write_json_atomic(parsed.receipt_out, report)
                if sha256_file(parsed.receipt_out) != acquisition_manifest_sha256:
                    raise AcquisitionError("external receipt does not match the acquisition package manifest")
            _emit(
                {
                    "status": report["acquisition_status"],
                    "boundary": "acquisition identity only; no rights, format, completeness, or release approval",
                    "dataset_id": report["dataset_id"],
                    "resolved_commit": report["resolved_commit"],
                    "file_count": report["tree_manifest"]["file_count"],
                    "total_bytes": report["tree_manifest"]["total_bytes"],
                    "exact_set_sha256": report["tree_manifest"]["exact_set_sha256"],
                    "acquisition_manifest_sha256": acquisition_manifest_sha256,
                }
            )
            return 0
        if parsed.command == "verify-acquisition":
            source, registry_sha256 = _trusted_source(
                parsed.registry,
                parsed.dataset_id,
                parsed.trusted_registry_sha256,
            )
            report = verify_acquisition(
                parsed.target,
                source,
                registry_sha256=registry_sha256,
                trusted_manifest_sha256=parsed.trusted_acquisition_manifest_sha256,
            )
            _emit(
                {
                    "status": "ACQUISITION_PACKAGE_VERIFIED",
                    "acquisition_status": report["acquisition_status"],
                    "boundary": "read-only identity recheck; no rights, format, completeness, or release approval",
                    "dataset_id": report["dataset_id"],
                    "resolved_commit": report["resolved_commit"],
                    "exact_set_sha256": report["tree_manifest"]["exact_set_sha256"],
                }
            )
            return 0
        if parsed.command == "analyze":
            graph = analyze_fixture(parsed.fixture)
            if graph["reconciliation"]["state"] != "CLOSED":
                analysis = write_analysis_package(parsed.data_root, graph)
                _emit(
                    {
                        "status": "SYNTHETIC_RECONCILIATION_OPEN",
                        "classification": graph["classification"],
                        "run_id": graph["run_id"],
                        "counts": graph["reconciliation"]["counts"],
                        "blocking_statuses": graph["reconciliation"]["blocking_statuses"],
                        "review_package": analysis,
                        "boundary": "open reconciliation is registered for review but no SBOM is exported",
                    }
                )
                return 2
            _emit(write_run_package(parsed.data_root, graph))
            return 0
        if parsed.command == "demo":
            graphs: dict[str, dict[str, object]] = {}
            packages: dict[str, dict[str, object]] = {}
            for release_name in ("release-a", "release-b"):
                graph = analyze_fixture(parsed.fixtures_root / release_name)
                if graph["reconciliation"]["state"] != "CLOSED":
                    raise EvidenceError(f"{release_name} did not reach the expected CLOSED state")
                graphs[release_name] = graph
                packages[release_name] = write_run_package(parsed.data_root, graph)
            conflict = analyze_fixture(parsed.fixtures_root / "conflict")
            if conflict["reconciliation"]["state"] != "OPEN":
                raise EvidenceError("conflict control unexpectedly reached CLOSED")
            conflict_package = write_analysis_package(parsed.data_root, conflict)
            _emit(
                {
                    "status": "SYNTHETIC_MVP_DEMO_PASS",
                    "classification": "SYNTHETIC_NOT_EVIDENCE",
                    "packages": packages,
                    "release_diff": diff_graphs(graphs["release-a"], graphs["release-b"]),
                    "negative_control": {
                        "status": "EXPECTED_RECONCILIATION_OPEN",
                        "run_id": conflict["run_id"],
                        "counts": conflict["reconciliation"]["counts"],
                        "blocking_statuses": conflict["reconciliation"]["blocking_statuses"],
                        "exported": False,
                        "review_package": conflict_package,
                    },
                    "boundary": (
                        "Synthetic engineering validation only; no real-product completeness, "
                        "manufacturer approval, CRA conformity, CAB conclusion, or certification."
                    ),
                }
            )
            return 0
        if parsed.command == "validate-output":
            if (parsed.run_directory / "cyclonedx-1.7.json").is_file():
                _emit(
                    verify_run_package(
                        parsed.run_directory,
                        trusted_manifest_sha256=parsed.trusted_manifest_sha256,
                    )
                )
            else:
                if parsed.trusted_manifest_sha256 is not None:
                    raise PackError("external manifest anchor is currently supported for closed runs only")
                _emit(verify_analysis_package(parsed.run_directory))
            return 0
        if parsed.command == "import-pro03b":
            _emit(import_pro03b(parsed.workbook))
            return 0
        if parsed.command == "validate-yocto-profiles":
            profiles = load_profile_registry(parsed.registry)
            _emit(
                {
                    "status": "YOCTO_REFERENCE_PROFILES_VALIDATED",
                    "classification": "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE",
                    "profile_registry_sha256": sha256_file(parsed.registry),
                    "profiles": [profile["profile_id"] for profile in profiles],
                    "boundary": (
                        "profile structure and pinned identities only; no acquisition, completeness, "
                        "manufacturer, PRE-7, CRA, CAB, ground-truth, or certification conclusion"
                    ),
                }
            )
            return 0
        if parsed.command == "acquire-yocto-reference":
            profiles = _trusted_yocto_profiles(
                parsed.profiles,
                parsed.trusted_profile_registry_sha256,
            )
            profile = _yocto_profile(profiles, parsed.profile_id)
            receipt = acquire_profile(profile, parsed.destination)
            _emit(
                {
                    "status": "OFFICIAL_REFERENCE_PAYLOADS_HASH_VERIFIED",
                    "profile_id": parsed.profile_id,
                    "receipt": receipt,
                    "boundary": (
                        "official public-reference acquisition only; not a local rebuild, customer "
                        "evidence, rights decision, SBOM completeness, or release approval"
                    ),
                }
            )
            return 0
        if parsed.command == "analyze-yocto-reference":
            profiles = _trusted_yocto_profiles(
                parsed.profiles,
                parsed.trusted_profile_registry_sha256,
            )
            profile = _yocto_profile(profiles, parsed.profile_id)
            graph = analyze_reference(profile, parsed.input_root)
            package = write_reference_package(
                parsed.data_root,
                graph,
                profile=profile,
                input_root=parsed.input_root,
            )
            _emit(
                {
                    **package,
                    "generator_output_status": "GENERATOR_OUTPUT_CANDIDATE",
                    "component_count": len(graph["component_population"]),
                    "reconciliation_counts": graph["reconciliation"]["counts"],
                }
            )
            return 0
        if parsed.command == "yocto-reference-demo":
            profiles = _trusted_yocto_profiles(
                parsed.profiles,
                parsed.trusted_profile_registry_sha256,
            )
            ordered = sorted(
                profiles,
                key=lambda profile: str(profile["reference"]["release_timestamp"]).encode("utf-8"),
            )
            graphs: list[dict[str, object]] = []
            packages: list[dict[str, object]] = []
            for profile in ordered:
                profile_id = str(profile["profile_id"])
                graph = analyze_reference(profile, parsed.inputs_root / profile_id)
                graphs.append(graph)
                packages.append(
                    write_reference_package(
                        parsed.data_root,
                        graph,
                        profile=profile,
                        input_root=parsed.inputs_root / profile_id,
                    )
                )
            if len(graphs) != 2:
                raise EvidenceError("M2 A/B demo requires exactly two registered profiles")
            difference = diff_references(graphs[0], graphs[1])
            _emit(
                {
                    "status": "PUBLIC_BUILD_REFERENCE_AB_PIPELINE_PASS",
                    "classification": "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE",
                    "packages": packages,
                    "reference_diff": difference,
                    "boundary": (
                        "A/B engineering mechanism demonstration only; both candidates remain OPEN "
                        "and do not prove customer or manufacturer PRE-7 implementation"
                    ),
                }
            )
            return 0
        if parsed.command == "validate-reference-output":
            trusted_profiles = _trusted_yocto_profiles(
                parsed.profiles,
                parsed.trusted_profile_registry_sha256,
            )
            _emit(
                verify_reference_package(
                    parsed.run_directory,
                    trusted_profiles=trusted_profiles,
                )
            )
            return 0
        if parsed.command == "selftest":
            _emit(_execute_selftest(parsed))
            return 0
        if parsed.command == "scan-source-only":
            _emit(_execute_scan_source_only(parsed))
            return 0
        if parsed.command == "validate-source-only-output":
            _emit(
                validate_source_only_output(
                    parsed.output_root,
                    source_root=parsed.source_root,
                    trusted_completion_sha256=parsed.trusted_completion_sha256,
                )
            )
            return 0
        if parsed.command == "prepare-source-analysis-projection":
            _emit(
                prepare_source_analysis_projection(
                    parsed.source_output_root,
                    parsed.source_root,
                    parsed.output_root,
                )
            )
            return 0
        if parsed.command == "validate-source-analysis-projection":
            _emit(
                validate_source_analysis_projection(
                    parsed.projection_root,
                    source_output_root=parsed.source_output_root,
                    trusted_completion_sha256=parsed.trusted_completion_sha256,
                )
            )
            return 0
        if parsed.command == "validate-selftest-output":
            _emit(verify_selftest_package(parsed.run_directory))
            return 0
        if parsed.command == "validate-selftest-root":
            _emit(verify_selftest_root(parsed.output_root))
            return 0
        if parsed.command == "prepare-euvd-handoff":
            _emit(
                prepare_verified_selftest_euvd_handoff(
                    parsed.selftest_root,
                    parsed.handoff_root,
                    profile_id=parsed.profile_id,
                )
            )
            return 0
        if parsed.command == "validate-euvd-handoff":
            _emit(
                validate_euvd_handoff(
                    parsed.handoff_directory,
                    selftest_root=parsed.selftest_root,
                )
            )
            return 0
        if parsed.command == "run-model-evaluation":
            _emit(_execute_model_evaluation(parsed))
            return 0
        if parsed.command == "run-model-candidate-evaluation":
            _emit(_execute_model_candidate_evaluation(parsed))
            return 0
        if parsed.command == "prepare-model-evaluation-cards":
            source_validation = verify_selftest_root(parsed.selftest_root)
            run_directory = (
                Path(parsed.selftest_root)
                / "data"
                / "runs"
                / source_validation["run_id"]
            )
            comparison = _strict_json_file(
                run_directory / "reconciliation.json",
                "verified M4A reconciliation",
                maximum=64 * 1024 * 1024,
            )
            cards = cards_from_selftest_comparison(comparison)
            sealed = seal_card_set(cards)
            output = _new_output_file(parsed.output, "model evaluation cards output")
            write_json_atomic(output, cards)
            _emit(
                {
                    "status": "M5_MINIMAL_CONFLICT_CARDS_PREPARED",
                    "classification": SELFTEST_CLASSIFICATION,
                    "source_run_id": source_validation["run_id"],
                    "card_count": sealed["card_count"],
                    "card_set_sha256": sealed["card_set_sha256"],
                    "output": output.as_posix(),
                    "output_sha256": sha256_file(output),
                    "authority_boundary": (
                        "Minimal shadow inputs only; no source tree, fact-write, release or conformity authority."
                    ),
                }
            )
            return 0
        if parsed.command == "validate-model-evaluation":
            record = _strict_json_file(
                parsed.evaluation,
                "model evaluation",
                maximum=64 * 1024 * 1024,
            )
            _emit(
                {
                    **validate_evaluation(
                        record,
                        trusted_evaluation_sha256=parsed.trusted_evaluation_sha256,
                    ),
                    "evaluation_sha256": sha256_file(parsed.evaluation),
                }
            )
            return 0
        if parsed.command == "validate-model-candidate-evaluation":
            record = _strict_json_file(
                parsed.evaluation,
                "model candidate evaluation",
                maximum=128 * 1024 * 1024,
            )
            _emit(
                {
                    **validate_candidate_evaluation(
                        record,
                        trusted_evaluation_sha256=parsed.trusted_evaluation_sha256,
                    ),
                    "evaluation_file_sha256": sha256_file(parsed.evaluation),
                }
            )
            return 0
        if parsed.command == "backup-selftest":
            source_validation = verify_selftest_root(parsed.source_root)
            root_id = source_validation["run_id"]
            if parsed.root_id is not None and parsed.root_id != root_id:
                raise OperationsError(
                    "declared backup root_id does not match the verified self-test run_id"
                )
            backup = create_selftest_backup(
                parsed.source_root,
                parsed.backup,
                root_id=root_id,
            )
            _emit(
                {
                    **backup,
                    "source_validation_status": source_validation["status"],
                }
            )
            return 0
        if parsed.command in {"validate-selftest-backup", "validate-backup-selftest"}:
            _emit(
                validate_selftest_backup(
                    parsed.backup,
                    trusted_manifest_sha256=parsed.trusted_manifest_sha256,
                )
            )
            return 0
        if parsed.command == "restore-selftest":
            restore = restore_selftest_backup(
                parsed.backup,
                parsed.destination,
                trusted_manifest_sha256=parsed.trusted_manifest_sha256,
            )
            restored_validation = verify_selftest_root(parsed.destination)
            _emit(
                {
                    **restore,
                    "restored_validation_status": restored_validation["status"],
                }
            )
            return 0
        if parsed.command == "clear-selftest":
            _emit(
                clear_selftest_sandbox_run(
                    parsed.run_directory,
                    allowed_parent=parsed.allowed_parent,
                    receipt_path=parsed.receipt,
                )
            )
            return 0
        if parsed.command == "sign-selftest-pack":
            _emit(_execute_sign(parsed))
            return 0
        if parsed.command == "verify-signature":
            _emit(_execute_verify(parsed))
            return 0
        if parsed.command == "intake-vex":
            _emit(_execute_intake_vex(parsed))
            return 0
        if parsed.command == "intake-narrowed":
            _emit(_execute_intake_narrowed(parsed))
            return 0
        if parsed.command == "serve":
            scanner_runtime = discover_scanner_runtime(
                syft_bin=parsed.syft_bin,
                syft_config=parsed.syft_config,
                syft_receipt=parsed.syft_receipt,
                runtime_registry=parsed.runtime_registry,
                sandbox_exec=parsed.sandbox_exec,
                timeout_seconds=parsed.scan_timeout_seconds,
                disabled=parsed.disable_scanning,
            )
            server = create_server(
                parsed.data_root,
                port=parsed.port,
                scanner_backend=(
                    SubprocessScanner(scanner_runtime)
                    if scanner_runtime is not None
                    else None
                ),
            )
            print(f"Local UI: {server.launch_url}", file=sys.stderr)
            print("Model adapter: DISABLED", file=sys.stderr)
            print(
                "Source scanner: "
                + (
                    "ENABLED"
                    if scanner_runtime is not None
                    else "DISABLED_NOT_CONFIGURED"
                ),
                file=sys.stderr,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
    except (
        RegistryError,
        AcquisitionError,
        EvidenceError,
        ComponentPopulationError,
        ExcelImportError,
        PackError,
        ReferencePackError,
        SelfTestError,
        SelfTestPackError,
        SelfTestRootError,
        SourceOnlyValidationError,
        PrivacyProjectionError,
        ModelEvaluationError,
        EuvdHandoffError,
        OperationsError,
        ManifestError,
        WebAppError,
        WebScanError,
        ModelAdapterError,
        NarrowingError,
        ResourceError,
        OSError,
    ) as exc:
        _emit({"status": "BLOCKED", "error_type": type(exc).__name__, "message": str(exc)})
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
