"""Offline structural and semantic validation for deterministic SBOM exports."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from pyshacl import validate as validate_shacl
from rdflib import Graph

from .resources import ResourceError, vendor_specs_root


class SbomValidationError(RuntimeError):
    """Raised when the frozen validation closure is missing, changed or unusable."""


SPEC_HASHES = {
    "cyclonedx-1.7/bom-1.7.schema.json": "df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221",
    "spdx-3.0.1/spdx-json-schema.json": "582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1",
    "spdx-3.0.1/spdx-context.jsonld": "c72b0928f094c83e5c127784edb1ebca2af74a104fcacc007c332b23cbc788bd",
    "spdx-3.0.1/spdx-model.ttl": "30ebb4af2d70a9809044ef46f44cc3dc5125226d70f818a50ed2e1d5f404c593",
}
SPDX_CONTEXT_URI = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
VALIDATION_BOUNDARY = (
    "MECHANICALLY_VALID verifies the frozen engineering serialization profile only; "
    "it does not establish component completeness, manufacturer approval, PRE-7 conformity, CRA conformity, or certification"
)


def default_spec_root() -> Path:
    try:
        return vendor_specs_root()
    except ResourceError as exc:
        raise SbomValidationError(str(exc)) from exc


def _load_frozen_bytes(spec_root: Path, relative_path: str) -> bytes:
    path = spec_root / relative_path
    if not path.is_file() or path.is_symlink():
        raise SbomValidationError(f"frozen validation artifact is missing or unsafe: {relative_path}")
    payload = path.read_bytes()
    observed = hashlib.sha256(payload).hexdigest()
    expected = SPEC_HASHES[relative_path]
    if observed != expected:
        raise SbomValidationError(
            f"frozen validation artifact hash mismatch for {relative_path}: expected {expected}, got {observed}"
        )
    return payload


def _load_frozen_json(spec_root: Path, relative_path: str) -> Any:
    try:
        return json.loads(_load_frozen_bytes(spec_root, relative_path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SbomValidationError(f"frozen validation artifact is not valid JSON: {relative_path}") from exc


def _error_path(parts: Iterable[Any]) -> str:
    return "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in parts)


def _schema_errors(schema: dict[str, Any], document: Any) -> list[dict[str, str]]:
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: (list(item.absolute_path), item.message))
    return [
        {"path": _error_path(error.absolute_path), "message": error.message}
        for error in errors
    ]


def _remote_references(value: Any, path: tuple[Any, ...] = ()) -> list[str]:
    references: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = (*path, key)
            if key == "$ref" and isinstance(item, str) and item.startswith(("http://", "https://")):
                references.append(f"{_error_path(child_path)}={item}")
            references.extend(_remote_references(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            references.extend(_remote_references(item, (*path, index)))
    return references


def _cyclonedx_semantic_errors(document: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("timestamp"):
        errors.append({"path": "$.metadata.timestamp", "message": "timestamp is required by the workbench profile"})
    else:
        timestamp = metadata["timestamp"]
        try:
            if not isinstance(timestamp, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z",
                timestamp,
            ):
                raise ValueError
            datetime.fromisoformat(timestamp[:-1] + "+00:00")
        except ValueError:
            errors.append(
                {"path": "$.metadata.timestamp", "message": "timestamp must be a valid ISO 8601 UTC value ending in Z"}
            )
    if isinstance(metadata, dict) and not metadata.get("authors"):
        errors.append({"path": "$.metadata.authors", "message": "at least one SBOM author is required"})

    references: list[str] = []
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    if isinstance(root_component, dict) and isinstance(root_component.get("bom-ref"), str):
        references.append(root_component["bom-ref"])
    components = document.get("components", [])
    for index, component in enumerate(components if isinstance(components, list) else []):
        if isinstance(component, dict) and isinstance(component.get("bom-ref"), str):
            references.append(component["bom-ref"])
        else:
            errors.append({"path": f"$.components[{index}].bom-ref", "message": "bom-ref is required"})
    if len(references) != len(set(references)):
        errors.append({"path": "$.components", "message": "bom-ref values must be unique across the BOM"})
    known = set(references)
    dependency_refs: set[str] = set()
    for index, dependency in enumerate(document.get("dependencies", [])):
        if not isinstance(dependency, dict):
            continue
        reference = dependency.get("ref")
        if reference not in known:
            errors.append({"path": f"$.dependencies[{index}].ref", "message": "dependency ref is not a BOM object"})
        if isinstance(reference, str):
            dependency_refs.add(reference)
        for target in dependency.get("dependsOn", []):
            if target not in known:
                errors.append(
                    {"path": f"$.dependencies[{index}].dependsOn", "message": f"unknown dependency target: {target}"}
                )
    missing_rows = sorted(known - dependency_refs)
    if missing_rows:
        errors.append(
            {"path": "$.dependencies", "message": f"dependency rows are missing for: {', '.join(missing_rows)}"}
        )
    return errors


def validate_cyclonedx(document: dict[str, Any], spec_root: Path | None = None) -> dict[str, Any]:
    """Validate CycloneDX structure + semantics via the frozen JSON Schema.

    EXP-06 / TRACEABILITY: this uses the frozen CycloneDX 1.7 JSON Schema plus
    workbench-defined semantic checks (bom-ref uniqueness, dangling dependency
    refs, hash algorithm/coordinate consistency). It does NOT invoke
    ``cyclonedx-cli validate --fail-on-errors``; that standalone CLI validator
    is a known PARTIAL gap pending controlled acquisition and hash-pinning of
    the cyclonedx-cli binary (analogous to the Syft runtime registry). The
    structural + semantic coverage here is the engineering fallback, not a
    CycloneDX-CLI equivalence claim.
    """
    spec_root = spec_root or default_spec_root()
    schema_path = "cyclonedx-1.7/bom-1.7.schema.json"
    schema = _load_frozen_json(spec_root, schema_path)
    remote_refs = _remote_references(schema)
    if remote_refs:
        raise SbomValidationError(f"CycloneDX schema contains remote references: {remote_refs[:3]}")
    structure_errors = _schema_errors(schema, document)
    semantic_errors = _cyclonedx_semantic_errors(document) if not structure_errors else []
    valid = not structure_errors and not semantic_errors
    return {
        "format": "CycloneDX",
        "profile_version": "1.7",
        "status": "MECHANICALLY_VALID" if valid else "INVALID",
        "structural_validation": {"passed": not structure_errors, "errors": structure_errors},
        "semantic_profile_validation": {"passed": not semantic_errors, "errors": semantic_errors},
        "frozen_artifacts": [{"relative_path": schema_path, "sha256": SPEC_HASHES[schema_path]}],
        "network_resolution": "DISABLED_LOCAL_CLOSURE",
        "boundary": VALIDATION_BOUNDARY,
    }


def _spdx_reference_errors(document: dict[str, Any]) -> list[dict[str, str]]:
    graph = document.get("@graph", [])
    identifiers: set[str] = set()
    documents = 0
    for index, item in enumerate(graph if isinstance(graph, list) else []):
        if not isinstance(item, dict):
            continue
        identifier = item.get("spdxId") or item.get("@id")
        if isinstance(identifier, str):
            if identifier in identifiers:
                return [{"path": f"$.@graph[{index}]", "message": f"duplicate SPDX identifier: {identifier}"}]
            identifiers.add(identifier)
        if item.get("type") == "SpdxDocument":
            documents += 1
    errors: list[dict[str, str]] = []
    if documents != 1:
        errors.append({"path": "$.@graph", "message": "exactly one SpdxDocument is required"})

    scalar_reference_fields = {"creationInfo", "from", "suppliedBy"}
    array_reference_fields = {"createdBy", "createdUsing", "element", "rootElement", "to", "originatedBy"}
    for index, item in enumerate(graph if isinstance(graph, list) else []):
        if not isinstance(item, dict):
            continue
        for field in scalar_reference_fields:
            reference = item.get(field)
            if isinstance(reference, str) and reference not in identifiers:
                errors.append(
                    {"path": f"$.@graph[{index}].{field}", "message": f"reference does not resolve locally: {reference}"}
                )
        for field in array_reference_fields:
            references = item.get(field, [])
            if not isinstance(references, list):
                continue
            for reference in references:
                if isinstance(reference, str) and reference not in identifiers:
                    errors.append(
                        {"path": f"$.@graph[{index}].{field}", "message": f"reference does not resolve locally: {reference}"}
                    )
    return errors


_BINDING_KEYS = {
    "build_id",
    "canonical_sha256",
    "classification",
    "release_artifact_sha256",
    "run_id",
}


def _spdx_source_binding(document: dict[str, Any]) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
    documents = [
        item
        for item in document.get("@graph", [])
        if isinstance(item, dict) and item.get("type") == "SpdxDocument"
    ]
    if len(documents) != 1:
        return None, [{"path": "$.@graph", "message": "source binding requires one SpdxDocument"}]
    prefix = "sbom-workbench:binding="
    comment = documents[0].get("comment")
    if not isinstance(comment, str) or not comment.startswith(prefix):
        return None, [{"path": "$.@graph.SpdxDocument.comment", "message": "source binding is missing"}]
    try:
        binding = json.loads(comment[len(prefix) :])
    except json.JSONDecodeError:
        return None, [{"path": "$.@graph.SpdxDocument.comment", "message": "source binding is not JSON"}]
    if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
        return None, [{"path": "$.@graph.SpdxDocument.comment", "message": "source binding fields do not match"}]
    for key, value in binding.items():
        if not isinstance(value, str) or not value:
            return None, [{"path": f"$.@graph.SpdxDocument.comment.{key}", "message": "binding value is invalid"}]
    for key in ("canonical_sha256", "release_artifact_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", binding[key]):
            return None, [{"path": f"$.@graph.SpdxDocument.comment.{key}", "message": "binding hash is invalid"}]
    return binding, []


def _cyclonedx_source_binding(document: dict[str, Any]) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return None, [{"path": "$.metadata", "message": "source binding metadata is missing"}]
    values: dict[str, str] = {}
    for item in metadata.get("properties", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and name.startswith("sbom-workbench:") and isinstance(value, str):
            values[name.removeprefix("sbom-workbench:")] = value
    mapping = {
        "build_id": "build-id",
        "canonical_sha256": "canonical-sha256",
        "classification": "classification",
        "release_artifact_sha256": "release-artifact-sha256",
        "run_id": "run-id",
    }
    missing = [key for key, property_name in mapping.items() if property_name not in values]
    if missing:
        return None, [{"path": "$.metadata.properties", "message": f"source binding fields are missing: {missing}"}]
    binding = {key: values[property_name] for key, property_name in mapping.items()}
    for key in ("canonical_sha256", "release_artifact_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", binding[key]):
            return None, [{"path": f"$.metadata.properties.{key}", "message": "binding hash is invalid"}]
    return binding, []


def validate_spdx(document: dict[str, Any], spec_root: Path | None = None) -> dict[str, Any]:
    spec_root = spec_root or default_spec_root()
    schema_path = "spdx-3.0.1/spdx-json-schema.json"
    context_path = "spdx-3.0.1/spdx-context.jsonld"
    model_path = "spdx-3.0.1/spdx-model.ttl"
    schema = _load_frozen_json(spec_root, schema_path)
    if _remote_references(schema):
        raise SbomValidationError("SPDX structural schema contains a remote $ref")
    structure_errors = _schema_errors(schema, document)
    if document.get("@context") != SPDX_CONTEXT_URI:
        structure_errors.append(
            {"path": "$.@context", "message": f"workbench profile requires the SPDX 3.0.1 context URI {SPDX_CONTEXT_URI}"}
        )
    reference_errors = _spdx_reference_errors(document) if not structure_errors else []
    _, binding_errors = _spdx_source_binding(document) if not structure_errors else (None, [])

    shacl_errors: list[dict[str, str]] = []
    if not structure_errors and not reference_errors and not binding_errors:
        local_context = _load_frozen_json(spec_root, context_path)
        local_document = copy.deepcopy(document)
        local_document["@context"] = local_context["@context"]
        try:
            data_graph = Graph().parse(data=json.dumps(local_document), format="json-ld")
            model_payload = _load_frozen_bytes(spec_root, model_path).decode("utf-8")
            if "owl:imports" in model_payload:
                raise SbomValidationError("SPDX model declares owl:imports; offline closure is not self-contained")
            model_graph = Graph().parse(data=model_payload, format="turtle")
            conforms, _, report_text = validate_shacl(
                data_graph,
                shacl_graph=model_graph,
                ont_graph=model_graph,
                inference="none",
                abort_on_first=False,
                allow_infos=False,
                allow_warnings=False,
                advanced=True,
                do_owl_imports=False,
            )
            if not conforms:
                shacl_errors.append({"path": "$.@graph", "message": str(report_text)[:16000]})
        except SbomValidationError:
            raise
        except Exception as exc:  # rdflib/pySHACL expose multiple parser exception types
            shacl_errors.append({"path": "$.@graph", "message": f"offline JSON-LD/SHACL validation failed: {exc}"})
    valid = not structure_errors and not reference_errors and not binding_errors and not shacl_errors
    return {
        "format": "SPDX",
        "profile_version": "3.0.1 JSON-LD",
        "status": "MECHANICALLY_VALID" if valid else "INVALID",
        "structural_validation": {"passed": not structure_errors, "errors": structure_errors},
        "local_reference_validation": {"passed": not reference_errors, "errors": reference_errors},
        "source_binding_profile_validation": {"passed": not binding_errors, "errors": binding_errors},
        "semantic_validation": {"passed": not shacl_errors, "errors": shacl_errors},
        "frozen_artifacts": [
            {"relative_path": path, "sha256": SPEC_HASHES[path]}
            for path in (schema_path, context_path, model_path)
        ],
        "network_resolution": "DISABLED_LOCAL_CONTEXT_AND_ONTOLOGY",
        "boundary": VALIDATION_BOUNDARY,
    }


def validate_export_pair(
    cyclonedx_document: dict[str, Any],
    spdx_document: dict[str, Any],
    spec_root: Path | None = None,
    expected_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reports = [
        validate_cyclonedx(cyclonedx_document, spec_root),
        validate_spdx(spdx_document, spec_root),
    ]
    cyclonedx_binding, cyclonedx_binding_errors = _cyclonedx_source_binding(cyclonedx_document)
    spdx_binding, spdx_binding_errors = _spdx_source_binding(spdx_document)
    pair_errors = [*cyclonedx_binding_errors, *spdx_binding_errors]
    if not pair_errors and cyclonedx_binding != spdx_binding:
        pair_errors.append({"path": "$", "message": "CycloneDX and SPDX source bindings do not match"})
    if expected_graph is not None and not pair_errors:
        expected_binding = {
            "build_id": expected_graph["release"]["build_id"],
            "canonical_sha256": expected_graph["canonical_sha256"],
            "classification": expected_graph["classification"],
            "release_artifact_sha256": expected_graph["release"]["artifact_sha256"],
            "run_id": expected_graph["run_id"],
        }
        if cyclonedx_binding != expected_binding:
            pair_errors.append({"path": "$", "message": "serialized source binding does not match the expected graph"})
        else:
            try:
                from .exporters import export_pair

                expected_cyclonedx, expected_spdx = export_pair(expected_graph)
                if cyclonedx_document != expected_cyclonedx or spdx_document != expected_spdx:
                    pair_errors.append(
                        {
                            "path": "$",
                            "message": "serialized documents do not match deterministic regeneration from the expected graph",
                        }
                    )
            except Exception as exc:
                pair_errors.append(
                    {"path": "$", "message": f"expected graph is not independently exportable: {exc}"}
                )
    passed = all(report["status"] == "MECHANICALLY_VALID" for report in reports) and not pair_errors
    assurance = (
        "EXPECTED_GRAPH_AND_DETERMINISTIC_CONTENT_MATCHED"
        if expected_graph is not None and passed
        else "SELF_DECLARED_BINDINGS_MATCHED"
        if passed
        else "NOT_ESTABLISHED"
    )
    status = (
        "MECHANICALLY_VALID"
        if passed and expected_graph is not None
        else "SELF_DECLARED_BINDINGS_MATCHED"
        if passed
        else "INVALID"
    )
    return {
        "schema_version": "1.0",
        "status": status,
        "reports": reports,
        "source_binding_validation": {
            "passed": not pair_errors,
            "binding": cyclonedx_binding if not pair_errors else None,
            "assurance": assurance,
            "errors": pair_errors,
        },
        "boundary": (
            VALIDATION_BOUNDARY
            if expected_graph is not None
            else VALIDATION_BOUNDARY
            + "; without an expected graph, matching bindings are self-declarations and do not prove common origin"
        ),
    }
