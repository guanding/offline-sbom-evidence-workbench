"""Read-only verification for one source-only scan output root."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

from .acquire import AcquisitionError, load_trusted_acquisition_receipt
from .component_population import (
    ComponentPopulationError,
    build_component_population,
    validate_component_population,
)
from .manifest import (
    build_bounded_exact_set_manifest,
    build_exact_set_manifest,
    canonical_json_bytes,
    sha256_file,
)
from .selftest import _verify_observation, load_cyclonedx


CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
VALID_STATUSES = frozenset(
    {
        "SOURCE_ONLY_SCAN_COMPLETE_OPEN_CANDIDATE",
        "SOURCE_ONLY_SCAN_COMPLETE_ZERO_COMPONENTS_OPEN_CANDIDATE",
        "SOURCE_ONLY_SCAN_COMPLETE_COVERAGE_HOLD_OPEN_CANDIDATE",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RAW_NAMES = {"raw.syft.json", "raw.cyclonedx.json", "raw.spdx.json"}


class SourceOnlyValidationError(ValueError):
    """Raised when a source-only output cannot be independently verified."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SourceOnlyValidationError(f"duplicate JSON key is forbidden: {key}")
        value[key] = item
    return value


def _json_file(path: Path, label: str, *, maximum: int = 64 * 1024 * 1024) -> Any:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SourceOnlyValidationError(f"cannot access {label}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SourceOnlyValidationError(f"{label} must be a single-link regular file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise SourceOnlyValidationError(f"{label} exceeds its JSON byte budget")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceOnlyValidationError(f"{label} is not strict JSON: {exc}") from exc


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SourceOnlyValidationError(f"{label} fields do not match")
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SourceOnlyValidationError(f"{label} is not a lowercase SHA-256")
    return value


def _validate_manifest(value: object, *, root_id: str) -> dict[str, Any]:
    manifest = _exact(
        value,
        {
            "schema_version",
            "root_id",
            "file_count",
            "total_bytes",
            "exact_set_sha256",
            "files",
        },
        "source manifest",
    )
    if manifest["schema_version"] != "1.0" or manifest["root_id"] != root_id:
        raise SourceOnlyValidationError("source manifest identity is invalid")
    files = manifest["files"]
    if not isinstance(files, list):
        raise SourceOnlyValidationError("source manifest files must be an array")
    normalized: list[dict[str, Any]] = []
    previous: bytes | None = None
    total = 0
    for index, raw in enumerate(files):
        item = _exact(
            raw,
            {"relative_path", "sha256", "size", "executable"},
            f"source manifest files[{index}]",
        )
        relative = item["relative_path"]
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or "\\" in relative
        ):
            raise SourceOnlyValidationError("source manifest contains an unsafe relative path")
        current = relative.encode("utf-8")
        if previous is not None and current <= previous:
            raise SourceOnlyValidationError("source manifest paths are duplicated or not canonical")
        previous = current
        size = item["size"]
        if type(size) is not int or size < 0 or type(item["executable"]) is not bool:
            raise SourceOnlyValidationError("source manifest file metadata is invalid")
        _hash(item["sha256"], "source manifest file SHA-256")
        total += size
        normalized.append(dict(item))
    if manifest["file_count"] != len(normalized) or manifest["total_bytes"] != total:
        raise SourceOnlyValidationError("source manifest counts do not rederive")
    expected = hashlib.sha256(
        canonical_json_bytes({"root_id": root_id, "files": normalized})
    ).hexdigest()
    if manifest["exact_set_sha256"] != expected:
        raise SourceOnlyValidationError("source manifest exact-set SHA-256 mismatch")
    return dict(manifest)


def _validate_implementation_identity(value: object) -> dict[str, Any]:
    identity = _exact(
        value,
        {
            "workbench_version",
            "identity_scope",
            "file_count",
            "exact_set_sha256",
            "files",
            "boundary",
        },
        "implementation identity",
    )
    if identity["identity_scope"] != "src/sbom_workbench/**/*.py":
        raise SourceOnlyValidationError("implementation identity scope changed")
    files = identity["files"]
    if not isinstance(files, list) or identity["file_count"] != len(files):
        raise SourceOnlyValidationError("implementation identity file count mismatch")
    previous: bytes | None = None
    for index, raw in enumerate(files):
        item = _exact(
            raw,
            {"relative_path", "sha256", "size"},
            f"implementation identity files[{index}]",
        )
        relative = item["relative_path"]
        if not isinstance(relative, str) or not relative.endswith(".py"):
            raise SourceOnlyValidationError("implementation identity path is invalid")
        current = relative.encode("utf-8")
        if previous is not None and current <= previous:
            raise SourceOnlyValidationError("implementation identity paths are not canonical")
        previous = current
        _hash(item["sha256"], "implementation file SHA-256")
        if type(item["size"]) is not int or item["size"] < 0:
            raise SourceOnlyValidationError("implementation file size is invalid")
    expected = hashlib.sha256(
        canonical_json_bytes(
            {"workbench_version": identity["workbench_version"], "files": files}
        )
    ).hexdigest()
    if identity["exact_set_sha256"] != expected:
        raise SourceOnlyValidationError("implementation exact-set SHA-256 mismatch")
    return dict(identity)


def _validate_source_provenance(
    value: object,
    *,
    source_manifest: dict[str, Any],
    output_root: Path,
) -> str:
    if not isinstance(value, dict):
        raise SourceOnlyValidationError("source provenance must be an object")
    status = value.get("status")
    if status == "GOVERNED_ACQUISITION_RECEIPT_AND_TREE_VERIFIED":
        provenance = _exact(
            value,
            {
                "repository_url",
                "commit",
                "declared_license_expression",
                "status",
                "dataset_id",
                "acquisition_status",
                "license_review_status",
                "registry_sha256",
                "registry_entry_sha256",
                "acquisition_receipt",
                "acquisition_tree",
                "boundary",
            },
            "governed source provenance",
        )
        if (
            not isinstance(provenance["repository_url"], str)
            or not provenance["repository_url"].startswith("https://")
            or not isinstance(provenance["commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["commit"])
            or not isinstance(provenance["declared_license_expression"], str)
            or not provenance["declared_license_expression"]
            or not isinstance(provenance["dataset_id"], str)
            or not provenance["dataset_id"]
            or not isinstance(provenance["license_review_status"], str)
            or not provenance["license_review_status"]
            or not isinstance(provenance["boundary"], str)
            or not provenance["boundary"]
        ):
            raise SourceOnlyValidationError("governed source provenance identity is invalid")
        _hash(provenance["registry_sha256"], "source registry SHA-256")
        _hash(
            provenance["registry_entry_sha256"],
            "source registry entry SHA-256",
        )
        receipt_link = _exact(
            provenance["acquisition_receipt"],
            {"path", "sha256"},
            "source acquisition receipt link",
        )
        if receipt_link["path"] != "source-acquisition-receipt.json":
            raise SourceOnlyValidationError("source acquisition receipt path is invalid")
        receipt_sha256 = _hash(
            receipt_link["sha256"], "source acquisition receipt SHA-256"
        )
        try:
            report = load_trusted_acquisition_receipt(
                output_root / receipt_link["path"], receipt_sha256
            )
        except AcquisitionError as exc:
            raise SourceOnlyValidationError(
                f"source acquisition receipt is invalid: {exc}"
            ) from exc
        expected_report_fields = {
            "dataset_id": provenance["dataset_id"],
            "source_url": provenance["repository_url"],
            "resolved_commit": provenance["commit"],
            "acquisition_status": provenance["acquisition_status"],
            "license_expression": provenance["declared_license_expression"],
            "license_review_status": provenance["license_review_status"],
            "registry_sha256": provenance["registry_sha256"],
            "registry_entry_sha256": provenance["registry_entry_sha256"],
        }
        if any(report.get(key) != expected for key, expected in expected_report_fields.items()):
            raise SourceOnlyValidationError(
                "source acquisition receipt differs from source provenance"
            )
        tree = report.get("tree_manifest")
        if not isinstance(tree, dict) or set(tree) != {
            "schema_version",
            "root_id",
            "file_count",
            "total_bytes",
            "exact_set_sha256",
            "files",
        }:
            raise SourceOnlyValidationError("source acquisition tree manifest is invalid")
        if (
            tree.get("schema_version") != "1.0"
            or not isinstance(tree.get("root_id"), str)
            or not tree["root_id"]
            or tree.get("files") != source_manifest["files"]
            or tree.get("file_count") != source_manifest["file_count"]
            or tree.get("total_bytes") != source_manifest["total_bytes"]
        ):
            raise SourceOnlyValidationError(
                "source acquisition tree differs from sealed source exact-set"
            )
        expected_tree_sha256 = hashlib.sha256(
            canonical_json_bytes({"root_id": tree["root_id"], "files": tree["files"]})
        ).hexdigest()
        if tree.get("exact_set_sha256") != expected_tree_sha256:
            raise SourceOnlyValidationError(
                "source acquisition tree exact-set SHA-256 does not rederive"
            )
        acquisition_tree = _exact(
            provenance["acquisition_tree"],
            {"root_id", "exact_set_sha256", "file_count", "total_bytes"},
            "source acquisition tree summary",
        )
        if acquisition_tree != {
            "root_id": tree["root_id"],
            "exact_set_sha256": expected_tree_sha256,
            "file_count": tree["file_count"],
            "total_bytes": tree["total_bytes"],
        }:
            raise SourceOnlyValidationError(
                "source acquisition tree summary does not rederive"
            )
        return status

    provenance = _exact(
        value,
        {
            "repository_url",
            "commit",
            "declared_license_expression",
            "status",
            "boundary",
        },
        "operator-declared source provenance",
    )
    repository_url = provenance["repository_url"]
    commit = provenance["commit"]
    if (repository_url is None) != (commit is None):
        raise SourceOnlyValidationError("operator source URL and commit must be paired")
    if repository_url is not None and (
        not isinstance(repository_url, str)
        or not repository_url.startswith("https://")
        or not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or status != "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
    ):
        raise SourceOnlyValidationError("operator source provenance is invalid")
    if repository_url is None and status != "NOT_DECLARED":
        raise SourceOnlyValidationError("undeclared source provenance status is invalid")
    license_expression = provenance["declared_license_expression"]
    if license_expression is not None and (
        not isinstance(license_expression, str) or not license_expression
    ):
        raise SourceOnlyValidationError("source license declaration is invalid")
    if not isinstance(provenance["boundary"], str) or not provenance["boundary"]:
        raise SourceOnlyValidationError("source provenance boundary is invalid")
    return status


def validate_source_only_output(
    output_root: Path,
    *,
    source_root: Path | None = None,
    trusted_completion_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify sealed bindings without writing to the output root."""

    root = Path(output_root)
    try:
        info = root.lstat()
    except OSError as exc:
        raise SourceOnlyValidationError(f"cannot access source-only output root: {exc}") from exc
    if root.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise SourceOnlyValidationError("source-only output root must be a non-symlink directory")
    root = root.resolve(strict=True)

    receipt_path = root / "scan-receipt.json"
    completion_path = root / "SELFTEST_COMPLETE.json"
    observation_path = root / "source-observation.json"
    source_manifest_path = root / "source-manifest.json"
    component_population_path = root / "component-population.json"
    receipt = _exact(
        _json_file(receipt_path, "source-only scan receipt"),
        {
            "schema_version",
            "classification",
            "status",
            "scanner_identity",
            "scanner_acquisition_identity",
            "implementation_identity",
            "source_provenance",
            "source_input_identity",
            "source_manifest",
            "component_population",
            "source_resource_budgets",
            "scans",
            "source_observation",
            "boundary",
        },
        "source-only scan receipt",
    )
    if (
        receipt["schema_version"] != "1.0"
        or receipt["classification"] != CLASSIFICATION
        or receipt["status"] not in VALID_STATUSES
    ):
        raise SourceOnlyValidationError("source-only receipt boundary is invalid")
    implementation = _validate_implementation_identity(receipt["implementation_identity"])

    completion = _exact(
        _json_file(completion_path, "source-only completion"),
        {
            "schema_version",
            "classification",
            "status",
            "run_id",
            "scan_receipt_sha256",
            "reconciliation_status",
            "component_population_sha256",
            "component_population_gate",
        },
        "source-only completion",
    )
    if (
        completion["schema_version"] != "1.0"
        or completion["classification"] != CLASSIFICATION
        or completion["status"] != receipt["status"]
        or completion["reconciliation_status"] != "NOT_APPLICABLE_SINGLE_FACE"
        or completion["scan_receipt_sha256"] != sha256_file(receipt_path)
    ):
        raise SourceOnlyValidationError("source-only completion does not bind the receipt")
    completion_sha256 = sha256_file(completion_path)
    if trusted_completion_sha256 is not None:
        if _hash(trusted_completion_sha256, "trusted completion SHA-256") != completion_sha256:
            raise SourceOnlyValidationError("trusted completion SHA-256 does not match")

    source_manifest = _validate_manifest(
        _json_file(source_manifest_path, "source exact-set manifest"),
        root_id="euvd-source-snapshot",
    )
    manifest_link = _exact(
        receipt["source_manifest"],
        {"path", "sha256", "exact_set_sha256", "file_count", "total_bytes"},
        "source manifest receipt link",
    )
    if (
        manifest_link["path"] != "source-manifest.json"
        or manifest_link["sha256"] != sha256_file(source_manifest_path)
        or manifest_link["exact_set_sha256"] != source_manifest["exact_set_sha256"]
        or manifest_link["file_count"] != source_manifest["file_count"]
        or manifest_link["total_bytes"] != source_manifest["total_bytes"]
    ):
        raise SourceOnlyValidationError("source manifest receipt binding mismatch")
    source_identity = _exact(
        receipt["source_input_identity"],
        {"root_id", "sha256", "file_count", "total_bytes"},
        "source input identity",
    )
    if source_identity != {
        "root_id": source_manifest["root_id"],
        "sha256": source_manifest["exact_set_sha256"],
        "file_count": source_manifest["file_count"],
        "total_bytes": source_manifest["total_bytes"],
    }:
        raise SourceOnlyValidationError("source input identity does not match its manifest")
    source_provenance_status = _validate_source_provenance(
        receipt["source_provenance"],
        source_manifest=source_manifest,
        output_root=root,
    )

    budgets = _exact(
        receipt["source_resource_budgets"],
        {"max_files", "max_total_bytes", "max_single_file_bytes", "max_depth"},
        "source resource budgets",
    )
    if any(type(value) is not int or value <= 0 for value in budgets.values()):
        raise SourceOnlyValidationError("source resource budgets are invalid")
    source_reverification = "NOT_REQUESTED_MANIFEST_ONLY"
    if source_root is not None:
        current = build_bounded_exact_set_manifest(
            Path(source_root),
            "euvd-source-snapshot",
            **budgets,
        )
        if current != source_manifest:
            raise SourceOnlyValidationError("current source root differs from sealed source manifest")
        source_reverification = "MATCHED_CURRENT_SOURCE_ROOT"

    scans = receipt["scans"]
    if not isinstance(scans, list) or len(scans) != 1 or not isinstance(scans[0], dict):
        raise SourceOnlyValidationError("source-only receipt must contain exactly one scan")
    scan = scans[0]
    if scan.get("profile_id") != "m3a-source-directory" or scan.get(
        "profile_kind"
    ) != "SOURCE_DIRECTORY":
        raise SourceOnlyValidationError("source-only scan profile is invalid")
    raw_root = root / "raw" / "m3a-source-directory"
    try:
        names = {path.name for path in raw_root.iterdir()}
    except OSError as exc:
        raise SourceOnlyValidationError(f"cannot enumerate raw source outputs: {exc}") from exc
    if names != _RAW_NAMES:
        raise SourceOnlyValidationError("raw source output exact filenames do not match")
    actual_raw_manifest = build_exact_set_manifest(raw_root, "m3a-source-directory-raw")
    if scan.get("raw_exact_set") != actual_raw_manifest:
        raise SourceOnlyValidationError("raw source output exact-set mismatch")

    observation = _verify_observation(
        _json_file(observation_path, "source-only profile observation")
    )
    observation_link = _exact(
        receipt["source_observation"],
        {"run_id", "canonical_sha256", "observation_sha256"},
        "source observation receipt link",
    )
    if observation_link != {
        "run_id": observation["run_id"],
        "canonical_sha256": observation["canonical_sha256"],
        "observation_sha256": sha256_file(observation_path),
    }:
        raise SourceOnlyValidationError("source observation receipt binding mismatch")
    if completion["run_id"] != observation["run_id"]:
        raise SourceOnlyValidationError("completion run ID does not match the observation")

    raw_cyclonedx = raw_root / "raw.cyclonedx.json"
    projection, cyclonedx_identity = load_cyclonedx(raw_cyclonedx)
    if projection != observation["cyclonedx_evidence"]:
        raise SourceOnlyValidationError("raw CycloneDX does not reproduce the observation")
    scanner = _exact(
        receipt["scanner_identity"],
        {"name", "version", "binary_sha256", "config_sha256"},
        "scanner identity",
    )
    if scanner != observation["scanner_identity"]:
        raise SourceOnlyValidationError("scanner identity differs from the observation")
    pinned = root / "runtime" / "pinned-scanner"
    if (
        sha256_file(pinned / "syft") != scanner["binary_sha256"]
        or sha256_file(pinned / "syft-m3a.yaml") != scanner["config_sha256"]
    ):
        raise SourceOnlyValidationError("pinned scanner snapshot hash mismatch")

    population_value = _json_file(
        component_population_path,
        "source-only component population",
        maximum=128 * 1024 * 1024,
    )
    try:
        population_validation = validate_component_population(
            population_value,
            source_manifest=source_manifest,
            cyclonedx_projection=projection,
        )
    except (ComponentPopulationError, KeyError, TypeError, ValueError) as exc:
        raise SourceOnlyValidationError(f"component population is invalid: {exc}") from exc
    population_link = _exact(
        receipt["component_population"],
        {"path", "sha256", "population_sha256", "item_count", "reconciliation_gate"},
        "component population receipt link",
    )
    if population_link != {
        "path": "component-population.json",
        "sha256": sha256_file(component_population_path),
        "population_sha256": population_validation["population_sha256"],
        "item_count": population_validation["item_count"],
        "reconciliation_gate": population_validation["gate"],
    }:
        raise SourceOnlyValidationError("component population receipt binding mismatch")
    if (
        completion["component_population_sha256"]
        != population_validation["population_sha256"]
        or completion["component_population_gate"] != population_validation["gate"]
    ):
        raise SourceOnlyValidationError("completion does not bind the component population")
    population_reverification = "NOT_REQUESTED_SEALED_ARTIFACT_ONLY"
    if source_root is not None:
        binding = population_value["product_build_binding"]
        rebuilt_population = build_component_population(
            Path(source_root),
            source_manifest,
            projection,
            product_name=binding["product_name"],
            declared_version=binding["declared_version"],
            build_id=binding["build_id"],
            release_artifact_sha256=binding["release_artifact_sha256"],
        )
        if rebuilt_population != population_value:
            raise SourceOnlyValidationError(
                "current source root does not reproduce the component population"
            )
        population_reverification = "MATCHED_CURRENT_SOURCE_ROOT"

    ecosystem_audit = scan.get("ecosystem_audit")
    if not isinstance(ecosystem_audit, dict):
        raise SourceOnlyValidationError("source-only receipt lacks ecosystem audit evidence")
    return {
        "status": "SOURCE_ONLY_OUTPUT_VALID_WITH_SINGLE_FACE_BOUNDARY",
        "classification": CLASSIFICATION,
        "run_id": observation["run_id"],
        "completion_sha256": completion_sha256,
        "trusted_completion_anchor": (
            "MATCH" if trusted_completion_sha256 is not None else "NOT_PROVIDED"
        ),
        "source_manifest_sha256": sha256_file(source_manifest_path),
        "source_exact_set_sha256": source_manifest["exact_set_sha256"],
        "source_reverification": source_reverification,
        "source_provenance_status": source_provenance_status,
        "implementation_exact_set_sha256": implementation["exact_set_sha256"],
        "cyclonedx_sha256": cyclonedx_identity["sha256"],
        "cyclonedx_semantic_sha256": projection["semantic_sha256"],
        "component_count": scan.get("component_count"),
        "product_package_candidate_count": ecosystem_audit.get("component_scope", {}).get(
            "product_package_candidate_count"
        ),
        "coverage_gate": ecosystem_audit.get("coverage_gate"),
        "component_population_sha256": population_validation["population_sha256"],
        "component_population_item_count": population_validation["item_count"],
        "component_population_matched_count": population_validation["matched_item_count"],
        "component_population_unmatched_count": population_validation["unmatched_item_count"],
        "component_population_ambiguous_count": population_validation["ambiguous_item_count"],
        "component_population_root_identity_hold_count": population_validation[
            "root_identity_hold_item_count"
        ],
        "component_population_gate": population_validation["gate"],
        "component_population_reverification": population_reverification,
        "build_binding_status": population_validation["build_binding_status"],
        "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
        "reconciliation_status": "NOT_APPLICABLE_SINGLE_FACE",
        "boundary": (
            "Integrity and internal bindings verified for one source face only. No OCI/portable "
            "reconciliation, product completeness, release, PRE-7/CRA conformity, or certification."
        ),
    }
