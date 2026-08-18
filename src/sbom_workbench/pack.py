"""Immutable synthetic run packages and the localhost dashboard registry."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from .evidence import EvidenceError, canonical_graph_sha256
from .exporters import export_pair
from .manifest import canonical_json_bytes, sha256_file, write_json_atomic
from .validation import validate_export_pair
from .workflow import recompute_graph_reconciliation


class PackError(ValueError):
    """Raised when a run cannot be sealed or an immutable pack has drifted."""


CLOSED_RUN_FILES = (
    "component-population.json",
    "cyclonedx-1.7.json",
    "dashboard.json",
    "evidence-graph.json",
    "inputs.json",
    "reconciliation.json",
    "run.json",
    "spdx-3.0.1.json",
    "tools.json",
    "validation.json",
)
OPEN_RUN_FILES = (
    "component-population.json",
    "dashboard.json",
    "evidence-graph.json",
    "reconciliation.json",
    "run.json",
    "validation.json",
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
CLOSED_STATUS = "SYNTHETIC_ENGINEERING_PASS_WITH_DECLARED_SCOPE"
CLOSED_BOUNDARY = (
    "Synthetic engineering fixture only; no manufacturer release authority, product conformity, "
    "CAB conclusion, CRA conformity, or certification."
)
OPEN_STATUS = "SYNTHETIC_RECONCILIATION_OPEN_REVIEW_REQUIRED"
OPEN_BOUNDARY = (
    "Open synthetic analysis for local review only. No SBOM artifact, manufacturer authority, "
    "product conformity, CAB conclusion, CRA conformity, or certification."
)
_COMPLETE_KEYS = {
    "schema_version",
    "classification",
    "status",
    "run_id",
    "canonical_graph_sha256",
    "manifest_relative_path",
    "manifest_sha256",
    "boundary",
}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _payload_manifest(
    run_directory: Path,
    run_id: str,
    payload_files: tuple[str, ...],
    *,
    sealed: bool = False,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    actual_names = sorted(path.name for path in run_directory.iterdir())
    expected_names = (*payload_files, "MANIFEST.json", "COMPLETE.json") if sealed else payload_files
    if actual_names != sorted(expected_names):
        raise PackError(f"run payload exact-set mismatch: {actual_names}")
    for relative_path in payload_files:
        path = run_directory / relative_path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PackError(f"run payload must be a single-link regular file: {relative_path}")
        entry = {
            "relative_path": relative_path,
            "sha256": sha256_file(path),
            "size": info.st_size,
            "executable": bool(info.st_mode & stat.S_IXUSR),
        }
        entries.append(entry)
        total_bytes += info.st_size
    entries.sort(key=lambda item: item["relative_path"].encode("utf-8"))
    identity = {"root_id": run_id, "files": entries}
    return {
        "schema_version": "1.0",
        "root_id": run_id,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "exact_set_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "files": entries,
    }


def _conflict_claims(graph: dict[str, Any], finding: dict[str, Any]) -> list[dict[str, Any]]:
    claim_ids = set(finding.get("claim_ids", []))
    population_id = finding.get("population_id")
    if isinstance(population_id, str):
        population = next(
            (item for item in graph["component_population"] if item["population_id"] == population_id),
            None,
        )
        if population is not None:
            source_keys = {
                (item["lane_id"], item["source_component_id"])
                for item in population["source_components"]
            }
            requested_fields = set(finding.get("details", []))
            for claim in graph["component_claims"]:
                if (claim["lane_id"], claim["source_component_id"]) not in source_keys:
                    continue
                if requested_fields and claim["field"] not in requested_fields:
                    continue
                claim_ids.add(claim["claim_id"])
    claims = [
        {
            "claim_id": claim["claim_id"],
            "value": claim.get("value")
            or (
                f"{claim['source_component_id']}|{claim['relationship']}|"
                f"{claim['target_component_id']}"
            ),
            "evidence_ids": list(claim["evidence_ids"]),
        }
        for claim in [*graph["component_claims"], *graph["relationship_claims"]]
        if claim["claim_id"] in claim_ids
    ]
    return sorted(claims, key=lambda item: item["claim_id"].encode("utf-8"))[:64]


def _dashboard(graph: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    findings = graph["reconciliation"]["findings"]
    conflicts = [
        {
            "conflict_id": finding["finding_id"],
            "field": ",".join(finding.get("details", [])) or finding["finding_type"],
            "status": finding["status"],
            "details": finding.get("details", []),
            "claims": _conflict_claims(graph, finding),
            "evidence_refs": sorted(finding.get("evidence_ids", [])),
        }
        for finding in findings
        if finding["status"] != "MATCHED"
    ]
    return {
        "schema_version": "1.0",
        "run_id": graph["run_id"],
        "classification": graph["classification"],
        "release": graph["release"],
        "components": graph["component_population"],
        "reconciliation": {
            "status": "SYNTHETIC_RECONCILIATION_CLOSED"
            if graph["reconciliation"]["state"] == "CLOSED"
            else "SYNTHETIC_RECONCILIATION_OPEN",
            "counts": graph["reconciliation"]["counts"],
            "conflicts": conflicts,
        },
        "validation": validation,
    }


def _run_record(graph: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    passed = validation.get("status") == "MECHANICALLY_VALID"
    return {
        "schema_version": "1.0",
        "classification": "SYNTHETIC_NOT_EVIDENCE",
        "run_id": graph["run_id"],
        "release_id": graph["release"]["release_id"],
        "build_id": graph["release"]["build_id"],
        "release_artifact_sha256": graph["release"]["artifact_sha256"],
        "canonical_graph_sha256": graph["canonical_sha256"],
        "reconciliation_state": graph["reconciliation"]["state"],
        "serialization_status": (
            "MECHANICALLY_VALID"
            if passed
            else "NOT_RUN_RECONCILIATION_OPEN"
            if graph["reconciliation"]["state"] == "OPEN"
            else "INVALID"
        ),
        "engineering_status": (
            "SYNTHETIC_ENGINEERING_PASS_WITH_DECLARED_SCOPE"
            if passed and graph["reconciliation"]["state"] == "CLOSED"
            else "SYNTHETIC_ENGINEERING_BLOCKED"
        ),
        "product_conformity_status": "NO_PRODUCT_CONFORMITY_STATUS",
        "manufacturer_release_authority": False,
        "cab_conclusion": False,
        "boundary": (
            "Synthetic engineering fixture only. This status does not establish component completeness "
            "for a real product, manufacturer approval, CRA conformity, CAB conclusion, or certification."
        ),
    }


def _read_registry(data_root: Path) -> dict[str, Any]:
    path = data_root / "runs.json"
    if not path.exists():
        return {"schema_version": "1.0", "runs": []}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
        raise PackError("runs.json is not a bounded, single-link regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackError("runs.json is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "runs"}:
        raise PackError("runs.json fields do not match")
    if value["schema_version"] != "1.0" or not isinstance(value["runs"], list):
        raise PackError("runs.json version or entries are invalid")
    return value


def _publish_registered_stage(
    data_root: Path,
    graph: dict[str, Any],
    dashboard_sha256: str,
    stage: Path,
    destination: Path,
) -> None:
    """Publish a staged directory and registry update under one recovery lock."""

    lock_path = data_root / ".runs.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "r+b", closefd=True) as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            registry = _read_registry(data_root)
            run_id = graph["run_id"]
            if destination.exists() or destination.is_symlink():
                raise PackError(f"run package already exists; refusing overwrite: {run_id}")
            if any(entry.get("run_id") == run_id for entry in registry["runs"] if isinstance(entry, dict)):
                raise PackError(f"run is already registered: {run_id}")
            registry["runs"].append(
                {
                    "run_id": run_id,
                    "relative_path": f"runs/{run_id}",
                    "dashboard_sha256": dashboard_sha256,
                }
            )
            registry["runs"].sort(key=lambda item: item["run_id"].encode("utf-8"))
            temporary = data_root / ".runs.json.tmp"
            if temporary.exists() or temporary.is_symlink():
                raise PackError("stale runs registry temporary file exists")
            try:
                with temporary.open("xb") as handle:
                    handle.write(_json_bytes(registry))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(stage, destination)
                try:
                    os.replace(temporary, data_root / "runs.json")
                except Exception:
                    os.replace(destination, stage)
                    raise
                directory_descriptor = os.open(data_root, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            finally:
                if temporary.exists():
                    temporary.unlink()
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _inputs_record(graph: dict[str, Any]) -> dict[str, Any]:
    """Standalone input provenance for the evidence pack (REV-03)."""

    release = graph["release"]
    return {
        "schema_version": "1.0",
        "classification": graph["classification"],
        "release_id": release["release_id"],
        "build_id": release["build_id"],
        "release_artifact_sha256": release["artifact_sha256"],
        "release_record": release,
    }


def _tools_record(graph: dict[str, Any]) -> dict[str, Any]:
    """Standalone tool/adapter provenance for the evidence pack (REV-03).

    Synthetic runs use deterministic rules only; there is no oMLX model card
    or analysis configuration to emit, so ``model_card``/``config`` stay null
    until a real model lane or explicit configuration record exists (REV-1).
    """

    return {
        "schema_version": "1.0",
        "classification": graph["classification"],
        "lane_identities": graph.get("lane_identities", []),
        "model_card": None,
        "config": None,
    }


def write_run_package(data_root: Path, graph: dict[str, Any]) -> dict[str, Any]:
    """Validate, seal, and register one immutable synthetic run."""

    cyclonedx, spdx = export_pair(graph)
    validation = validate_export_pair(cyclonedx, spdx, expected_graph=graph)
    if validation["status"] != "MECHANICALLY_VALID":
        raise PackError("export validation failed; refusing to seal a run")

    data_root = Path(data_root)
    if data_root.is_symlink():
        raise PackError("data root must not be a symlink")
    data_root.mkdir(parents=True, exist_ok=True)
    data_root = data_root.resolve(strict=True)
    runs_root = data_root / "runs"
    runs_root.mkdir(exist_ok=True)
    if runs_root.is_symlink():
        raise PackError("runs root must not be a symlink")
    run_id = graph["run_id"]
    destination = runs_root / run_id
    if destination.exists() or destination.is_symlink():
        raise PackError(f"run package already exists; refusing overwrite: {run_id}")

    stage = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=runs_root))
    moved = False
    try:
        values = {
            "component-population.json": graph["component_population"],
            "cyclonedx-1.7.json": cyclonedx,
            "dashboard.json": _dashboard(graph, validation),
            "evidence-graph.json": graph,
            "inputs.json": _inputs_record(graph),
            "reconciliation.json": graph["reconciliation"],
            "run.json": _run_record(graph, validation),
            "spdx-3.0.1.json": spdx,
            "tools.json": _tools_record(graph),
            "validation.json": validation,
        }
        for filename in CLOSED_RUN_FILES:
            write_json_atomic(stage / filename, values[filename])
        manifest = _payload_manifest(stage, run_id, CLOSED_RUN_FILES)
        write_json_atomic(stage / "MANIFEST.json", manifest)
        manifest_sha256 = sha256_file(stage / "MANIFEST.json")
        complete = {
            "schema_version": "1.0",
            "classification": "SYNTHETIC_NOT_EVIDENCE",
            "status": CLOSED_STATUS,
            "run_id": run_id,
            "canonical_graph_sha256": graph["canonical_sha256"],
            "manifest_relative_path": "MANIFEST.json",
            "manifest_sha256": manifest_sha256,
            "boundary": CLOSED_BOUNDARY,
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        if sorted(path.name for path in stage.iterdir()) != sorted(
            (*CLOSED_RUN_FILES, "MANIFEST.json", "COMPLETE.json")
        ):
            raise PackError("sealed run exact-set is unexpected")
        _publish_registered_stage(
            data_root,
            graph,
            sha256_file(stage / "dashboard.json"),
            stage,
            destination,
        )
        moved = True
        return verify_run_package(destination)
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)


def write_analysis_package(data_root: Path, graph: dict[str, Any]) -> dict[str, Any]:
    """Seal and register an OPEN analysis without emitting an SBOM artifact."""

    if graph.get("classification") != "SYNTHETIC_NOT_EVIDENCE":
        raise PackError("open analysis accepts only SYNTHETIC_NOT_EVIDENCE")
    if graph.get("canonical_sha256") != canonical_graph_sha256(graph):
        raise PackError("canonical graph hash does not match its content")
    if graph.get("reconciliation", {}).get("state") != "OPEN":
        raise PackError("analysis package is reserved for RECONCILIATION_OPEN")
    try:
        expected_reconciliation = recompute_graph_reconciliation(graph)
    except (EvidenceError, KeyError, TypeError, ValueError) as exc:
        raise PackError(f"analysis reconciliation cannot be recomputed: {exc}") from exc
    if graph["reconciliation"] != expected_reconciliation:
        raise PackError("analysis reconciliation does not match independent semantic recomputation")
    validation = {
        "schema_version": "1.0",
        "status": "NOT_RUN_RECONCILIATION_OPEN",
        "reports": [],
        "boundary": (
            "No SBOM was serialized because reconciliation is open. This is a local review artifact only."
        ),
    }
    data_root = Path(data_root)
    if data_root.is_symlink():
        raise PackError("data root must not be a symlink")
    data_root.mkdir(parents=True, exist_ok=True)
    data_root = data_root.resolve(strict=True)
    runs_root = data_root / "runs"
    runs_root.mkdir(exist_ok=True)
    if runs_root.is_symlink():
        raise PackError("runs root must not be a symlink")
    run_id = graph["run_id"]
    destination = runs_root / run_id
    if destination.exists() or destination.is_symlink():
        raise PackError(f"analysis package already exists; refusing overwrite: {run_id}")
    stage = Path(tempfile.mkdtemp(prefix=f".{run_id}.", dir=runs_root))
    moved = False
    try:
        values = {
            "component-population.json": graph["component_population"],
            "dashboard.json": _dashboard(graph, validation),
            "evidence-graph.json": graph,
            "reconciliation.json": graph["reconciliation"],
            "run.json": _run_record(graph, validation),
            "validation.json": validation,
        }
        for filename in OPEN_RUN_FILES:
            write_json_atomic(stage / filename, values[filename])
        manifest = _payload_manifest(stage, run_id, OPEN_RUN_FILES)
        write_json_atomic(stage / "MANIFEST.json", manifest)
        manifest_sha256 = sha256_file(stage / "MANIFEST.json")
        complete = {
            "schema_version": "1.0",
            "classification": "SYNTHETIC_NOT_EVIDENCE",
            "status": OPEN_STATUS,
            "run_id": run_id,
            "canonical_graph_sha256": graph["canonical_sha256"],
            "manifest_relative_path": "MANIFEST.json",
            "manifest_sha256": manifest_sha256,
            "boundary": OPEN_BOUNDARY,
        }
        write_json_atomic(stage / "COMPLETE.json", complete)
        _publish_registered_stage(
            data_root,
            graph,
            sha256_file(stage / "dashboard.json"),
            stage,
            destination,
        )
        moved = True
        return verify_analysis_package(destination)
    finally:
        if not moved and stage.exists():
            shutil.rmtree(stage)


def _load_json(path: Path) -> Any:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024:
        raise PackError(f"unsafe or oversized run file: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackError(f"invalid run JSON: {path.name}") from exc


def verify_run_package(
    run_directory: Path,
    *,
    trusted_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Read-only verification of an immutable run's exact set and formats."""

    run_directory = Path(run_directory)
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise PackError("run directory must be a non-symlink directory")
    names = sorted(path.name for path in run_directory.iterdir())
    expected_names = sorted((*CLOSED_RUN_FILES, "MANIFEST.json", "COMPLETE.json"))
    if names != expected_names:
        raise PackError(f"sealed run exact-set mismatch: {names}")
    manifest = _load_json(run_directory / "MANIFEST.json")
    complete = _load_json(run_directory / "COMPLETE.json")
    if not isinstance(complete, dict) or set(complete) != _COMPLETE_KEYS:
        raise PackError("COMPLETE.json fields do not match the closed profile")
    if (
        complete.get("schema_version") != "1.0"
        or complete.get("classification") != "SYNTHETIC_NOT_EVIDENCE"
        or complete.get("status") != CLOSED_STATUS
        or complete.get("boundary") != CLOSED_BOUNDARY
        or complete.get("manifest_relative_path") != "MANIFEST.json"
    ):
        raise PackError("COMPLETE.json attempts to change the closed profile boundary")
    observed_manifest_sha256 = sha256_file(run_directory / "MANIFEST.json")
    if complete.get("manifest_sha256") != observed_manifest_sha256:
        raise PackError("COMPLETE.json does not bind MANIFEST.json")
    if trusted_manifest_sha256 is not None:
        if not _SHA256_RE.fullmatch(trusted_manifest_sha256):
            raise PackError("trusted manifest SHA-256 is invalid")
        if trusted_manifest_sha256 != observed_manifest_sha256:
            raise PackError("run manifest does not match the external trust anchor")
    observed_manifest = _payload_manifest(
        run_directory,
        str(complete.get("run_id")),
        CLOSED_RUN_FILES,
        sealed=True,
    )
    if manifest != observed_manifest:
        raise PackError("run payload no longer matches MANIFEST.json")
    graph = _load_json(run_directory / "evidence-graph.json")
    if graph.get("canonical_sha256") != canonical_graph_sha256(graph):
        raise PackError("canonical evidence graph hash is invalid")
    if (
        graph.get("canonical_sha256") != complete.get("canonical_graph_sha256")
        or graph.get("run_id") != complete.get("run_id")
        or graph.get("classification") != "SYNTHETIC_NOT_EVIDENCE"
    ):
        raise PackError("COMPLETE.json does not bind the canonical evidence graph")
    cyclonedx = _load_json(run_directory / "cyclonedx-1.7.json")
    spdx = _load_json(run_directory / "spdx-3.0.1.json")
    expected_cyclonedx, expected_spdx = export_pair(graph)
    if cyclonedx != expected_cyclonedx or spdx != expected_spdx:
        raise PackError("serialized SBOMs do not match deterministic regeneration from the evidence graph")
    validation = validate_export_pair(cyclonedx, spdx, expected_graph=graph)
    if validation["status"] != "MECHANICALLY_VALID":
        raise PackError("sealed SBOM output is no longer mechanically valid")
    if _load_json(run_directory / "component-population.json") != graph["component_population"]:
        raise PackError("component population projection does not match the evidence graph")
    if _load_json(run_directory / "reconciliation.json") != graph["reconciliation"]:
        raise PackError("reconciliation projection does not match the evidence graph")
    if _load_json(run_directory / "validation.json") != validation:
        raise PackError("validation projection does not match current offline validation")
    if _load_json(run_directory / "dashboard.json") != _dashboard(graph, validation):
        raise PackError("dashboard projection does not match the evidence graph")
    if _load_json(run_directory / "run.json") != _run_record(graph, validation):
        raise PackError("run projection does not match the evidence graph")
    return {
        "status": CLOSED_STATUS,
        "classification": "SYNTHETIC_NOT_EVIDENCE",
        "run_id": complete["run_id"],
        "canonical_graph_sha256": complete["canonical_graph_sha256"],
        "manifest_sha256": complete["manifest_sha256"],
        "exact_set_sha256": manifest["exact_set_sha256"],
        "file_count": len(names),
        "validation_status": validation["status"],
        "integrity_trust": (
            "EXTERNAL_MANIFEST_ANCHOR_MATCHED"
            if trusted_manifest_sha256 is not None
            else "SELF_CONSISTENCY_ONLY"
        ),
        "boundary": CLOSED_BOUNDARY,
    }


def verify_analysis_package(run_directory: Path) -> dict[str, Any]:
    """Read-only verification of a registered OPEN review analysis."""

    run_directory = Path(run_directory)
    if run_directory.is_symlink() or not run_directory.is_dir():
        raise PackError("analysis directory must be a non-symlink directory")
    names = sorted(path.name for path in run_directory.iterdir())
    expected_names = sorted((*OPEN_RUN_FILES, "MANIFEST.json", "COMPLETE.json"))
    if names != expected_names:
        raise PackError(f"analysis exact-set mismatch: {names}")
    manifest = _load_json(run_directory / "MANIFEST.json")
    complete = _load_json(run_directory / "COMPLETE.json")
    if not isinstance(complete, dict) or set(complete) != _COMPLETE_KEYS:
        raise PackError("analysis COMPLETE.json fields do not match")
    if (
        complete.get("schema_version") != "1.0"
        or complete.get("classification") != "SYNTHETIC_NOT_EVIDENCE"
        or complete.get("status") != OPEN_STATUS
        or complete.get("boundary") != OPEN_BOUNDARY
        or complete.get("manifest_relative_path") != "MANIFEST.json"
    ):
        raise PackError("analysis COMPLETE.json attempts to change its boundary")
    if complete.get("manifest_sha256") != sha256_file(run_directory / "MANIFEST.json"):
        raise PackError("COMPLETE.json does not bind MANIFEST.json")
    observed_manifest = _payload_manifest(
        run_directory,
        str(complete.get("run_id")),
        OPEN_RUN_FILES,
        sealed=True,
    )
    if manifest != observed_manifest:
        raise PackError("analysis payload no longer matches MANIFEST.json")
    graph = _load_json(run_directory / "evidence-graph.json")
    if graph.get("reconciliation", {}).get("state") != "OPEN":
        raise PackError("registered analysis is not RECONCILIATION_OPEN")
    try:
        expected_reconciliation = recompute_graph_reconciliation(graph)
    except (EvidenceError, KeyError, TypeError, ValueError) as exc:
        raise PackError(f"registered analysis reconciliation cannot be recomputed: {exc}") from exc
    if graph["reconciliation"] != expected_reconciliation:
        raise PackError("registered analysis reconciliation does not match semantic recomputation")
    if graph.get("canonical_sha256") != canonical_graph_sha256(graph):
        raise PackError("registered analysis canonical graph hash is invalid")
    if graph["canonical_sha256"] != complete.get("canonical_graph_sha256"):
        raise PackError("COMPLETE.json does not bind the analysis graph")
    if graph.get("run_id") != complete.get("run_id"):
        raise PackError("analysis run identity does not match COMPLETE.json")
    validation = {
        "schema_version": "1.0",
        "status": "NOT_RUN_RECONCILIATION_OPEN",
        "reports": [],
        "boundary": (
            "No SBOM was serialized because reconciliation is open. This is a local review artifact only."
        ),
    }
    if _load_json(run_directory / "component-population.json") != graph["component_population"]:
        raise PackError("analysis population projection does not match the graph")
    if _load_json(run_directory / "reconciliation.json") != graph["reconciliation"]:
        raise PackError("analysis reconciliation projection does not match the graph")
    if _load_json(run_directory / "validation.json") != validation:
        raise PackError("analysis validation projection does not match the OPEN state")
    if _load_json(run_directory / "dashboard.json") != _dashboard(graph, validation):
        raise PackError("analysis dashboard projection does not match the graph")
    if _load_json(run_directory / "run.json") != _run_record(graph, validation):
        raise PackError("analysis run projection does not match the graph")
    return {
        "status": OPEN_STATUS,
        "classification": "SYNTHETIC_NOT_EVIDENCE",
        "run_id": complete["run_id"],
        "canonical_graph_sha256": complete["canonical_graph_sha256"],
        "manifest_sha256": complete["manifest_sha256"],
        "exact_set_sha256": manifest["exact_set_sha256"],
        "file_count": len(names),
        "validation_status": "NOT_RUN_RECONCILIATION_OPEN",
        "integrity_trust": "SELF_CONSISTENCY_ONLY",
        "boundary": OPEN_BOUNDARY,
    }
