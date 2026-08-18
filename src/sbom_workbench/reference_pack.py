"""Immutable packages for public Yocto reference candidates.

This module is intentionally separate from the synthetic packer.  A public
reference candidate may be serialized while its reconciliation remains OPEN,
but every projection keeps the non-customer/non-conformity boundary.
"""

from __future__ import annotations

import hashlib
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence import canonical_graph_sha256
from .manifest import canonical_json_bytes, sha256_file, write_json_atomic
from .pack import _publish_registered_stage
from .validation import validate_export_pair
from .yocto import (
    analyze_reference,
    export_reference_pair,
    snapshot_profile_inputs,
    validate_reference_profile,
    verify_reference_graph,
)


class ReferencePackError(ValueError):
    """Raised when a public-reference candidate cannot be sealed or verified."""


CLASSIFICATION = "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE"
PACKAGE_STATUS = "PUBLIC_BUILD_REFERENCE_PIPELINE_PASS_OPEN_CANDIDATE"
BOUNDARY = (
    "Public Yocto reference candidate only. The upstream Autobuilder output is not a customer "
    "product, a local rebuild, a manufacturer-approved SBOM, PRE-7 conformity evidence, CRA "
    "conformity, a CAB conclusion, ground truth, or certification."
)
OUTPUT_FILES = (
    "component-population.json",
    "cyclonedx-1.7.json",
    "dashboard.json",
    "evidence-graph.json",
    "reconciliation.json",
    "run.json",
    "spdx-3.0.1.json",
    "validation.json",
)


def _profile_sha256(profile: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(profile)).hexdigest()


def _input_payload_files(profile: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        f"inputs/{payload['relative_path']}"
        for payload in sorted(profile["payloads"], key=lambda item: item["role"])
    )


def _expected_directories(relative_files: tuple[str, ...]) -> set[str]:
    directories: set[str] = set()
    for relative_path in relative_files:
        for parent in PurePosixPath(relative_path).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
    return directories


def _reference_payload_manifest(
    run_directory: Path,
    run_id: str,
    payload_files: tuple[str, ...],
    *,
    sealed: bool = False,
) -> dict[str, Any]:
    expected_files = set(payload_files)
    if sealed:
        expected_files.update({"MANIFEST.json", "COMPLETE.json"})
    expected_directories = _expected_directories(tuple(expected_files))
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in run_directory.rglob("*"):
        relative_path = path.relative_to(run_directory).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReferencePackError(f"reference package contains a symlink: {relative_path}")
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative_path)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            actual_files.add(relative_path)
        else:
            raise ReferencePackError(f"reference package contains an unsafe entry: {relative_path}")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReferencePackError(
            "reference package recursive exact-set mismatch; "
            f"files={sorted(actual_files)}, directories={sorted(actual_directories)}"
        )
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for relative_path in sorted(payload_files, key=lambda item: item.encode("utf-8")):
        path = run_directory / relative_path
        info = path.lstat()
        entry = {
            "relative_path": relative_path,
            "sha256": sha256_file(path),
            "size": info.st_size,
            "executable": bool(info.st_mode & stat.S_IXUSR),
        }
        entries.append(entry)
        total_bytes += info.st_size
    identity = {"root_id": run_id, "files": entries}
    return {
        "schema_version": "1.0",
        "root_id": run_id,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": entries,
    }


def _select_trusted_profile(
    trusted_profiles: list[dict[str, Any]] | tuple[dict[str, Any], ...], profile_id: object
) -> dict[str, Any]:
    if not isinstance(trusted_profiles, (list, tuple)) or not trusted_profiles:
        raise ReferencePackError("trusted public-reference profiles are required")
    normalized = [validate_reference_profile(profile) for profile in trusted_profiles]
    matches = [profile for profile in normalized if profile["profile_id"] == profile_id]
    if len(matches) != 1:
        raise ReferencePackError("reference package is not uniquely bound to a trusted profile")
    return matches[0]


def _rootfs_sha256(graph: dict[str, Any]) -> str:
    inputs = graph.get("inputs")
    if isinstance(inputs, dict):
        values = list(inputs.values())
    elif isinstance(inputs, list):
        values = inputs
    else:
        raise ReferencePackError("reference graph inputs are invalid")
    matches = [
        item.get("sha256")
        for item in values
        if isinstance(item, dict) and item.get("role") == "rootfs_archive"
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ReferencePackError("reference graph does not uniquely bind the rootfs archive")
    return matches[0]


def _validation(
    graph: dict[str, Any],
    pair: dict[str, Any],
    *,
    profile: dict[str, Any],
    input_root: Path,
) -> dict[str, Any]:
    expected = export_reference_pair(graph, profile=profile, input_root=input_root)
    if pair != expected:
        raise ReferencePackError("serialized reference pair is not deterministic from the graph")
    base = validate_export_pair(pair["cyclonedx"], pair["spdx"])
    reports_passed = all(
        isinstance(report, dict) and report.get("status") == "MECHANICALLY_VALID"
        for report in base.get("reports", [])
    )
    binding = base.get("source_binding_validation", {})
    if not reports_passed or not isinstance(binding, dict) or not binding.get("passed"):
        raise ReferencePackError("reference candidate failed frozen offline format validation")
    return {
        "schema_version": "1.0",
        "status": "MECHANICALLY_VALID",
        "reports": base["reports"],
        "source_binding_validation": {
            **binding,
            "assurance": "EXPECTED_REFERENCE_GRAPH_AND_DETERMINISTIC_CONTENT_MATCHED",
        },
        "candidate_state": graph["reconciliation"]["technical_status"],
        "boundary": (
            base["boundary"]
            + "; the candidate remains OPEN and is not a completeness, manufacturer, conformity, or release decision"
        ),
    }


def _release_projection(graph: dict[str, Any]) -> dict[str, Any]:
    reference = graph["reference"]
    return {
        "release_id": graph["profile_id"],
        "product": reference["image_name"],
        "product_version": reference["upstream_release"],
        "build_id": reference["build_id"],
        "artifact_sha256": _rootfs_sha256(graph),
        "release_timestamp": reference["release_timestamp"],
        "reference_builder": reference["reference_builder"],
        "manufacturer_role": None,
        "product_conformity_status": "NO_PRODUCT_CONFORMITY_STATUS",
        "status": graph["reconciliation"]["technical_status"],
    }


def _component_projection(graph: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for item in graph["component_population"]:
        value = dict(item)
        value["status"] = (
            "UNKNOWN" if item.get("critical_unknown_fields") else "MATCHED"
        )
        components.append(value)
    return components


def _dashboard(graph: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    findings = graph["reconciliation"].get("findings", [])
    conflicts = [
        {
            "conflict_id": finding.get("finding_id", f"finding-{index}"),
            "field": finding.get("field", finding.get("finding_type", "UNKNOWN")),
            "status": finding.get("status", "UNKNOWN"),
            "details": finding.get("details", []),
            "claims": [],
            "evidence_refs": sorted(finding.get("evidence_ids", [])),
        }
        for index, finding in enumerate(findings)
        if isinstance(finding, dict) and finding.get("status") != "MATCHED"
    ]
    return {
        "schema_version": "1.0",
        "run_id": graph["run_id"],
        "classification": graph["classification"],
        "release": _release_projection(graph),
        "components": _component_projection(graph),
        "reconciliation": {
            "status": graph["reconciliation"]["technical_status"],
            "counts": graph["reconciliation"]["counts"],
            "blocking_statuses": graph["reconciliation"]["blocking_statuses"],
            "file_reconciliation": graph["file_reconciliation"],
            "blindspots": graph["scope"]["blindspots"],
            "conflicts": conflicts,
        },
        "validation": validation,
    }


def _run_record(graph: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "classification": CLASSIFICATION,
        "status": PACKAGE_STATUS,
        "run_id": graph["run_id"],
        "profile_id": graph["profile_id"],
        "build_id": graph["reference"]["build_id"],
        "release_artifact_sha256": _rootfs_sha256(graph),
        "canonical_graph_sha256": graph["canonical_sha256"],
        "reconciliation_state": graph["reconciliation"]["state"],
        "technical_status": graph["reconciliation"]["technical_status"],
        "serialization_status": validation["status"],
        "generator_output_status": "GENERATOR_OUTPUT_CANDIDATE",
        "ground_truth_status": "NOT_GROUND_TRUTH",
        "product_conformity_status": "NO_PRODUCT_CONFORMITY_STATUS",
        "manufacturer_role": None,
        "pre7_rq03_re": "Not Assessed",
        "pre7_rq07_re": "Not Assessed",
        "boundary": BOUNDARY,
    }


def _verify_graph(
    graph: dict[str, Any], *, profile: dict[str, Any], input_root: Path
) -> None:
    try:
        verify_reference_graph(graph, profile=profile, input_root=input_root)
    except (KeyError, TypeError, ValueError) as exc:
        raise ReferencePackError(f"reference graph is not source-derived: {exc}") from exc
    if graph.get("classification") != CLASSIFICATION:
        raise ReferencePackError("reference graph classification changed")
    if graph.get("canonical_sha256") != canonical_graph_sha256(graph):
        raise ReferencePackError("reference graph canonical hash is invalid")
    if graph.get("manufacturer_role") is not None:
        raise ReferencePackError("public reference cannot carry a manufacturer role")
    if graph.get("product_conformity_status") != "NO_PRODUCT_CONFORMITY_STATUS":
        raise ReferencePackError("public reference cannot carry product conformity status")
    if graph.get("generator_output_status") != "GENERATOR_OUTPUT_CANDIDATE":
        raise ReferencePackError("public reference output must remain a candidate")


def write_reference_package(
    data_root: Path,
    graph: dict[str, Any],
    *,
    profile: dict[str, Any],
    input_root: Path,
) -> dict[str, Any]:
    """Seal and register an immutable OPEN public-reference candidate package."""

    normalized_profile = validate_reference_profile(profile)
    _verify_graph(graph, profile=normalized_profile, input_root=Path(input_root))
    if (
        graph.get("profile_id") != normalized_profile["profile_id"]
        or graph.get("profile_sha256") != _profile_sha256(normalized_profile)
    ):
        raise ReferencePackError("reference graph is not bound to the trusted profile")
    if graph["reconciliation"]["technical_status"] != "REFERENCE_RECONCILIATION_OPEN":
        raise ReferencePackError("this M2 package profile is fixed to REFERENCE_RECONCILIATION_OPEN")

    data_root = Path(data_root)
    if data_root.is_symlink():
        raise ReferencePackError("data root must not be a symlink")
    data_root.mkdir(parents=True, exist_ok=True)
    data_root = data_root.resolve(strict=True)
    runs_root = data_root / "runs"
    runs_root.mkdir(exist_ok=True)
    if runs_root.is_symlink():
        raise ReferencePackError("runs root must not be a symlink")
    run_id = graph["run_id"]
    destination = runs_root / run_id
    if destination.exists() or destination.is_symlink():
        raise ReferencePackError(f"reference package already exists; refusing overwrite: {run_id}")

    stage = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=runs_root))
    moved = False
    try:
        snapshot_profile_inputs(normalized_profile, input_root, stage / "inputs")
        expected_graph = analyze_reference(normalized_profile, stage / "inputs")
        if graph != expected_graph:
            raise ReferencePackError(
                "reference graph does not deterministically derive from the packaged trusted inputs"
            )
        pair = export_reference_pair(
            expected_graph,
            profile=normalized_profile,
            input_root=stage / "inputs",
        )
        validation = _validation(
            expected_graph,
            pair,
            profile=normalized_profile,
            input_root=stage / "inputs",
        )
        values = {
            "component-population.json": expected_graph["component_population"],
            "cyclonedx-1.7.json": pair["cyclonedx"],
            "dashboard.json": _dashboard(expected_graph, validation),
            "evidence-graph.json": expected_graph,
            "reconciliation.json": expected_graph["reconciliation"],
            "run.json": _run_record(expected_graph, validation),
            "spdx-3.0.1.json": pair["spdx"],
            "validation.json": validation,
        }
        for filename in OUTPUT_FILES:
            write_json_atomic(stage / filename, values[filename])
        payload_files = (*OUTPUT_FILES, *_input_payload_files(normalized_profile))
        manifest = _reference_payload_manifest(stage, run_id, payload_files)
        write_json_atomic(stage / "MANIFEST.json", manifest)
        complete = {
            "schema_version": "1.0",
            "classification": CLASSIFICATION,
            "status": PACKAGE_STATUS,
            "run_id": run_id,
            "canonical_graph_sha256": graph["canonical_sha256"],
            "manifest_relative_path": "MANIFEST.json",
            "manifest_sha256": sha256_file(stage / "MANIFEST.json"),
            "boundary": BOUNDARY,
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        _publish_registered_stage(
            data_root,
            expected_graph,
            sha256_file(stage / "dashboard.json"),
            stage,
            destination,
        )
        moved = True
        return verify_reference_package(destination, trusted_profiles=[normalized_profile])
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)


def verify_reference_package(
    run_directory: Path,
    *,
    trusted_profiles: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    """Read-only verification of one immutable public-reference candidate package."""

    run_directory = Path(run_directory)
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise ReferencePackError("reference run directory must be a non-symlink directory")

    import json

    def load(name: str) -> Any:
        path = run_directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ReferencePackError(f"unsafe or oversized reference package file: {name}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReferencePackError(f"invalid JSON in reference package: {name}") from exc

    graph = load("evidence-graph.json")
    if not isinstance(graph, dict):
        raise ReferencePackError("reference evidence graph must be an object")
    trusted_profile = _select_trusted_profile(trusted_profiles, graph.get("profile_id"))
    if graph.get("profile_sha256") != _profile_sha256(trusted_profile):
        raise ReferencePackError("reference graph profile hash does not match the trusted profile")
    payload_files = (*OUTPUT_FILES, *_input_payload_files(trusted_profile))

    complete = load("COMPLETE.json")
    expected_complete_keys = {
        "schema_version",
        "classification",
        "status",
        "run_id",
        "canonical_graph_sha256",
        "manifest_relative_path",
        "manifest_sha256",
        "boundary",
    }
    if not isinstance(complete, dict) or set(complete) != expected_complete_keys:
        raise ReferencePackError("reference COMPLETE.json fields do not match")
    if (
        complete.get("schema_version") != "1.0"
        or complete.get("classification") != CLASSIFICATION
        or complete.get("status") != PACKAGE_STATUS
        or complete.get("manifest_relative_path") != "MANIFEST.json"
        or complete.get("boundary") != BOUNDARY
    ):
        raise ReferencePackError("reference COMPLETE.json changed the fixed boundary")
    if complete["manifest_sha256"] != sha256_file(run_directory / "MANIFEST.json"):
        raise ReferencePackError("reference COMPLETE.json does not bind MANIFEST.json")
    manifest = load("MANIFEST.json")
    observed = _reference_payload_manifest(
        run_directory,
        str(complete["run_id"]),
        payload_files,
        sealed=True,
    )
    if manifest != observed:
        raise ReferencePackError("reference package payload no longer matches MANIFEST.json")

    _verify_graph(graph, profile=trusted_profile, input_root=run_directory / "inputs")
    expected_graph = analyze_reference(trusted_profile, run_directory / "inputs")
    if graph != expected_graph:
        raise ReferencePackError(
            "reference graph does not deterministically derive from its trusted packaged inputs"
        )
    if (
        graph["run_id"] != complete["run_id"]
        or graph["canonical_sha256"] != complete["canonical_graph_sha256"]
    ):
        raise ReferencePackError("reference COMPLETE.json does not bind the graph")
    pair = export_reference_pair(
        graph,
        profile=trusted_profile,
        input_root=run_directory / "inputs",
    )
    if load("cyclonedx-1.7.json") != pair["cyclonedx"] or load("spdx-3.0.1.json") != pair["spdx"]:
        raise ReferencePackError("reference SBOM candidates do not match deterministic regeneration")
    validation = _validation(
        graph,
        pair,
        profile=trusted_profile,
        input_root=run_directory / "inputs",
    )
    if load("validation.json") != validation:
        raise ReferencePackError("reference validation projection does not match")
    if load("component-population.json") != graph["component_population"]:
        raise ReferencePackError("reference component population projection does not match")
    if load("reconciliation.json") != graph["reconciliation"]:
        raise ReferencePackError("reference reconciliation projection does not match")
    if load("dashboard.json") != _dashboard(graph, validation):
        raise ReferencePackError("reference dashboard projection does not match")
    if load("run.json") != _run_record(graph, validation):
        raise ReferencePackError("reference run projection does not match")
    return {
        "status": PACKAGE_STATUS,
        "classification": CLASSIFICATION,
        "run_id": graph["run_id"],
        "profile_id": graph["profile_id"],
        "canonical_graph_sha256": graph["canonical_sha256"],
        "manifest_sha256": complete["manifest_sha256"],
        "exact_set_sha256": manifest["exact_set_sha256"],
        "file_count": len(payload_files) + 2,
        "validation_status": validation["status"],
        "technical_status": graph["reconciliation"]["technical_status"],
        "product_conformity_status": "NO_PRODUCT_CONFORMITY_STATUS",
        "boundary": BOUNDARY,
    }
