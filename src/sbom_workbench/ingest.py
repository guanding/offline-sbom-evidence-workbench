"""Strict synthetic release and evidence adapters.

The two evidence adapters carry distinct lane, source, and adapter identities.
Neither adapter accepts a candidate SBOM or an oracle.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence import (
    MAX_COLLECTION_ITEMS,
    UNKNOWN,
    EvidenceError,
    make_component_claim,
    make_evidence_object,
    make_relationship_claim,
    read_file_identity,
    read_json_object,
    require_exact_keys,
    require_mapping,
    require_safe_id,
    require_sha256,
    require_string_list,
    require_text,
    stable_id,
    validate_claim_evidence_links,
    validate_safe_relative_path,
)


SCHEMA_VERSION = "1.0"
SYNTHETIC_CLASSIFICATION = "SYNTHETIC_NOT_EVIDENCE"
BUILD_LANE_ID = "build-manifest"
ARTIFACT_LANE_ID = "artifact-inventory"
BUILD_ADAPTER_ID = "yocto-like-build-manifest-adapter"
ARTIFACT_ADAPTER_ID = "artifact-inventory-adapter"
ADAPTER_VERSION = "1.0.0"

RELEASE_PATH = "release.json"
BUILD_MANIFEST_PATH = "evidence/build-manifest.json"
ARTIFACT_INVENTORY_PATH = "evidence/artifact-inventory.json"

_RELEASE_KEYS = {
    "schema_version",
    "classification",
    "release_id",
    "manufacturer",
    "product",
    "product_version",
    "build_id",
    "architecture",
    "hardware_revision",
    "artifact_relative_path",
    "artifact_sha256",
    "release_timestamp",
    "sbom_author",
    "sbom_version",
    "evidence_cutoff",
    "inputs",
}
_INPUT_KEYS = {"build_manifest", "artifact_inventory"}
_INPUT_REF_KEYS = {"relative_path", "sha256"}
_EVIDENCE_ROOT_KEYS = {
    "schema_version",
    "classification",
    "evidence_id",
    "release_id",
    "lane_id",
    "source_kind",
    "authorship",
    "origin",
    "subject",
    "artifact",
    "components",
    "relationships",
    "coverage",
    "blindspots",
}
_SUBJECT_KEYS = {"producer", "name", "version", "identifiers", "role"}
_ARTIFACT_KEYS = {"relative_path", "sha256"}
_ORIGIN_KEYS = {"kind", "relative_path", "sha256"}
_COMPONENT_KEYS = {
    "component_id",
    "component_role",
    "producer",
    "name",
    "version",
    "identifiers",
    "provenance",
    "observed_hash",
    "supplier_hash",
}
_PROVENANCE_KEYS = {"kind", "locator", "source_available"}
_HASH_KEYS = {"algorithm", "value"}
_RELATIONSHIP_KEYS = {"from", "type", "to"}
_RELATIONSHIPS = {
    "DEPENDS_ON",
    "CONTAINS",
    "GENERATED_FROM",
    "DYNAMICALLY_LINKS",
    UNKNOWN,
}
_EXPECTED_SOURCE_KINDS = {
    BUILD_LANE_ID: "SYNTHETIC_BUILD_MANIFEST",
    ARTIFACT_LANE_ID: "SYNTHETIC_ARTIFACT_INVENTORY",
}
_UTC_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


def _validate_schema_version(value: dict[str, Any], label: str) -> None:
    if require_text(value, "schema_version", label, allow_unknown=False) != SCHEMA_VERSION:
        raise EvidenceError(f"{label}.schema_version is unsupported")


def _require_utc_timestamp(value: dict[str, Any], key: str, label: str) -> tuple[str, datetime]:
    candidate = require_text(value, key, label, allow_unknown=False, max_length=32)
    if not _UTC_TIMESTAMP_RE.fullmatch(candidate):
        raise EvidenceError(f"{label}.{key} must be an ISO 8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(candidate[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{label}.{key} is not a valid timestamp") from exc
    return candidate, parsed


def _validate_release(value: dict[str, Any]) -> dict[str, Any]:
    label = RELEASE_PATH
    require_exact_keys(value, _RELEASE_KEYS, label)
    _validate_schema_version(value, label)
    classification = require_text(value, "classification", label, allow_unknown=False)
    if classification != SYNTHETIC_CLASSIFICATION:
        raise EvidenceError(
            f"{label}.classification must be {SYNTHETIC_CLASSIFICATION} for this synthetic slice"
        )
    artifact_relative_path = validate_safe_relative_path(
        value.get("artifact_relative_path"), f"{label}.artifact_relative_path"
    )
    if artifact_relative_path in {RELEASE_PATH, BUILD_MANIFEST_PATH, ARTIFACT_INVENTORY_PATH}:
        raise EvidenceError(f"{label}.artifact_relative_path must identify a distinct release artifact")
    release_timestamp, parsed_release_timestamp = _require_utc_timestamp(
        value, "release_timestamp", label
    )
    evidence_cutoff, parsed_evidence_cutoff = _require_utc_timestamp(value, "evidence_cutoff", label)
    if parsed_evidence_cutoff > parsed_release_timestamp:
        raise EvidenceError(f"{label}.evidence_cutoff must not be after release_timestamp")
    release = {
        "schema_version": SCHEMA_VERSION,
        "classification": classification,
        "release_id": require_safe_id(value, "release_id", label),
        "manufacturer": require_text(value, "manufacturer", label, allow_unknown=False),
        "product": require_text(value, "product", label, allow_unknown=False),
        "product_version": require_text(value, "product_version", label, allow_unknown=False),
        "build_id": require_safe_id(value, "build_id", label),
        "architecture": require_text(value, "architecture", label, allow_unknown=False),
        "hardware_revision": require_text(value, "hardware_revision", label, allow_unknown=False),
        "artifact_relative_path": artifact_relative_path,
        "artifact_sha256": require_sha256(value, "artifact_sha256", label),
        "release_timestamp": release_timestamp,
        "sbom_author": require_text(value, "sbom_author", label, allow_unknown=False),
        "sbom_version": require_text(value, "sbom_version", label, allow_unknown=False),
        "evidence_cutoff": evidence_cutoff,
    }

    inputs = require_mapping(value.get("inputs"), f"{label}.inputs")
    require_exact_keys(inputs, _INPUT_KEYS, f"{label}.inputs")
    normalized_inputs: dict[str, dict[str, str]] = {}
    expected_paths = {
        "build_manifest": BUILD_MANIFEST_PATH,
        "artifact_inventory": ARTIFACT_INVENTORY_PATH,
    }
    for input_name, expected_path in expected_paths.items():
        reference_label = f"{label}.inputs.{input_name}"
        reference = require_mapping(inputs.get(input_name), reference_label)
        require_exact_keys(reference, _INPUT_REF_KEYS, reference_label)
        relative_path = validate_safe_relative_path(reference.get("relative_path"), f"{reference_label}.relative_path")
        if relative_path != expected_path:
            raise EvidenceError(f"{reference_label}.relative_path must be {expected_path}")
        normalized_inputs[input_name] = {
            "relative_path": relative_path,
            "sha256": require_sha256(reference, "sha256", reference_label),
        }
    release["inputs"] = normalized_inputs
    return release


def _validate_hash(raw: object, label: str, *, allow_null: bool) -> dict[str, str]:
    if raw is None:
        if not allow_null:
            raise EvidenceError(f"{label} must be an object")
        return {"algorithm": UNKNOWN, "value": UNKNOWN}
    value = require_mapping(raw, label)
    require_exact_keys(value, _HASH_KEYS, label)
    algorithm_raw = value.get("algorithm")
    hash_raw = value.get("value")
    if algorithm_raw is None:
        algorithm = UNKNOWN
    elif isinstance(algorithm_raw, str) and algorithm_raw:
        algorithm = algorithm_raw
    else:
        raise EvidenceError(f"{label}.algorithm must be a string or null")
    if hash_raw is None:
        hash_value = UNKNOWN
    elif isinstance(hash_raw, str) and hash_raw:
        hash_value = hash_raw
    else:
        raise EvidenceError(f"{label}.value must be a string or null")
    if algorithm not in {"SHA-256", UNKNOWN}:
        raise EvidenceError(f"{label}.algorithm is unsupported in this synthetic profile")
    if hash_value != UNKNOWN and not re.fullmatch(r"[0-9a-f]{64}", hash_value):
        raise EvidenceError(f"{label}.value must be a lowercase SHA-256")
    if not allow_null and UNKNOWN in {algorithm, hash_value}:
        raise EvidenceError(f"{label} must contain algorithm and value")
    return {"algorithm": algorithm, "value": hash_value}


def _validate_provenance(raw: object, label: str) -> dict[str, Any]:
    value = require_mapping(raw, label)
    require_exact_keys(value, _PROVENANCE_KEYS, label)
    source_available = value.get("source_available")
    if type(source_available) is not bool:
        raise EvidenceError(f"{label}.source_available must be a boolean")
    return {
        "kind": require_text(value, "kind", label, allow_unknown=False),
        "locator": require_text(value, "locator", label, allow_unknown=False),
        "source_available": source_available,
    }


def _validate_subject(raw: object, label: str) -> dict[str, Any]:
    value = require_mapping(raw, label)
    require_exact_keys(value, _SUBJECT_KEYS, label)
    identifiers = require_string_list(value, "identifiers", label)
    if UNKNOWN in identifiers and identifiers != [UNKNOWN]:
        raise EvidenceError(f"{label}.identifiers cannot mix UNKNOWN with concrete identifiers")
    return {
        "producer": require_text(value, "producer", label, allow_unknown=False),
        "name": require_text(value, "name", label, allow_unknown=False),
        "version": require_text(value, "version", label, allow_unknown=False),
        "identifiers": sorted(identifiers, key=lambda entry: entry.encode("utf-8")),
        "role": require_text(value, "role", label, allow_unknown=False),
    }


def _validate_artifact_binding(raw: object, label: str) -> dict[str, str]:
    value = require_mapping(raw, label)
    require_exact_keys(value, _ARTIFACT_KEYS, label)
    return {
        "relative_path": validate_safe_relative_path(
            value.get("relative_path"), f"{label}.relative_path"
        ),
        "sha256": require_sha256(value, "sha256", label),
    }


def _validate_declared_origin(raw: object, label: str) -> dict[str, str]:
    """Validate but never dereference an external synthetic provenance locator."""

    value = require_mapping(raw, label)
    require_exact_keys(value, _ORIGIN_KEYS, label)
    relative_path = require_text(value, "relative_path", label, allow_unknown=False)
    if "\\" in relative_path or "\x00" in relative_path:
        raise EvidenceError(f"{label}.relative_path must use a POSIX locator")
    path = PurePosixPath(relative_path)
    if path.is_absolute() or path.as_posix() != relative_path:
        raise EvidenceError(f"{label}.relative_path must be a normalized relative locator")
    leading_parents = 0
    for part in path.parts:
        if part == ".." and leading_parents == path.parts.index(part):
            leading_parents += 1
        elif part in {"", ".", ".."}:
            raise EvidenceError(f"{label}.relative_path contains an unsafe segment")
    if leading_parents > 1:
        raise EvidenceError(f"{label}.relative_path may reference at most one declared parent root")
    return {
        "kind": require_text(value, "kind", label, allow_unknown=False),
        "relative_path": relative_path,
        "sha256": require_sha256(value, "sha256", label),
    }


def _validate_components(
    raw: object,
    label: str,
    *,
    subject: dict[str, Any],
    source_kind: str,
    artifact: dict[str, str],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise EvidenceError(f"{label} must be a non-empty array")
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise EvidenceError(f"{label} exceeds the component limit")
    components: list[dict[str, Any]] = [
        {
            "component_id": "orion-root",
            "component_role": subject["role"],
            "producer": subject["producer"],
            "name": subject["name"],
            "version": subject["version"],
            "identifiers": list(subject["identifiers"]),
            "provenance": {
                "kind": source_kind,
                "locator": "subject",
                "source_available": UNKNOWN,
            },
            "observed_hash": {"algorithm": "SHA-256", "value": artifact["sha256"]},
            "supplier_hash": {"algorithm": UNKNOWN, "value": UNKNOWN},
        }
    ]
    seen = {"orion-root"}
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        component = require_mapping(item, item_label)
        require_exact_keys(component, _COMPONENT_KEYS, item_label)
        component_id = require_safe_id(component, "component_id", item_label)
        if component_id in seen:
            raise EvidenceError(f"{label} contains duplicate component_id {component_id}")
        seen.add(component_id)
        identifiers = require_string_list(
            component, "identifiers", item_label, require_nonempty=False
        )
        identifiers = identifiers or [UNKNOWN]
        if UNKNOWN in identifiers and identifiers != [UNKNOWN]:
            raise EvidenceError(f"{item_label}.identifiers cannot mix UNKNOWN with concrete identifiers")
        components.append(
            {
                "component_id": component_id,
                "component_role": require_text(
                    component, "component_role", item_label, allow_unknown=False
                ),
                "producer": require_text(component, "producer", item_label),
                "name": require_text(component, "name", item_label),
                "version": require_text(component, "version", item_label),
                "identifiers": sorted(identifiers, key=lambda entry: entry.encode("utf-8")),
                "provenance": _validate_provenance(
                    component.get("provenance"), f"{item_label}.provenance"
                ),
                "observed_hash": _validate_hash(
                    component.get("observed_hash"), f"{item_label}.observed_hash", allow_null=False
                ),
                "supplier_hash": _validate_hash(
                    component.get("supplier_hash"), f"{item_label}.supplier_hash", allow_null=True
                ),
            }
        )
    return sorted(components, key=lambda component: component["component_id"].encode("utf-8"))


def _validate_relationships(
    raw: object,
    label: str,
    component_ids: set[str],
) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise EvidenceError(f"{label} must be an array")
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise EvidenceError(f"{label} exceeds the relationship limit")
    relationships: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        relationship = require_mapping(item, item_label)
        require_exact_keys(relationship, _RELATIONSHIP_KEYS, item_label)
        source = require_safe_id(relationship, "from", item_label)
        target = require_safe_id(relationship, "to", item_label)
        relation = require_text(relationship, "type", item_label)
        if relation not in _RELATIONSHIPS:
            raise EvidenceError(f"{item_label}.type is unsupported")
        if source not in component_ids or target not in component_ids:
            raise EvidenceError(f"{item_label} references an unknown component")
        identity = (source, relation, target)
        if identity in seen:
            raise EvidenceError(f"{label} contains a duplicate relationship")
        seen.add(identity)
        relationships.append(
            {
                "source_component_id": source,
                "relationship": relation,
                "target_component_id": target,
            }
        )
    return sorted(
        relationships,
        key=lambda item: (
            item["source_component_id"].encode("utf-8"),
            item["relationship"].encode("utf-8"),
            item["target_component_id"].encode("utf-8"),
        ),
    )


def _claim_value(value: object) -> str:
    if value is None or value == UNKNOWN:
        return UNKNOWN
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, str) and value:
        return value
    raise EvidenceError("component claim value is invalid")


def _claims_for_components(
    components: list[dict[str, Any]], lane_id: str, evidence_id: str
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for component in components:
        field_values: list[tuple[str, object]] = [
            ("producer", component["producer"]),
            ("name", component["name"]),
            ("version", component["version"]),
            ("component_role", component["component_role"]),
            ("provenance_kind", component["provenance"]["kind"]),
            ("provenance_locator", component["provenance"]["locator"]),
            ("provenance_source_available", component["provenance"]["source_available"]),
            ("observed_hash_algorithm", component["observed_hash"]["algorithm"]),
            ("observed_hash_value", component["observed_hash"]["value"]),
            ("supplier_hash_algorithm", component["supplier_hash"]["algorithm"]),
            ("supplier_hash_value", component["supplier_hash"]["value"]),
        ]
        for field, value in field_values:
            claims.append(
                make_component_claim(
                    lane_id=lane_id,
                    source_component_id=component["component_id"],
                    field=field,
                    value=_claim_value(value),
                    evidence_id=evidence_id,
                )
            )
        for identifier in component["identifiers"]:
            claims.append(
                make_component_claim(
                    lane_id=lane_id,
                    source_component_id=component["component_id"],
                    field="identifier",
                    value=identifier,
                    evidence_id=evidence_id,
                )
            )
    return sorted(claims, key=lambda claim: claim["claim_id"])


def _claims_for_relationships(
    relationships: list[dict[str, str]], lane_id: str, evidence_id: str
) -> list[dict[str, Any]]:
    return sorted(
        [
            make_relationship_claim(
                lane_id=lane_id,
                source_component_id=relationship["source_component_id"],
                relationship=relationship["relationship"],
                target_component_id=relationship["target_component_id"],
                evidence_id=evidence_id,
            )
            for relationship in relationships
        ],
        key=lambda claim: claim["claim_id"],
    )


def _adapt_evidence_document(
    value: dict[str, Any],
    input_identity: dict[str, Any],
    *,
    label: str,
    expected_lane_id: str,
    adapter_id: str,
) -> dict[str, Any]:
    require_exact_keys(value, _EVIDENCE_ROOT_KEYS, label)
    _validate_schema_version(value, label)
    classification = require_text(value, "classification", label, allow_unknown=False)
    if classification != SYNTHETIC_CLASSIFICATION:
        raise EvidenceError(f"{label}.classification must be {SYNTHETIC_CLASSIFICATION}")
    lane_id = require_text(value, "lane_id", label, allow_unknown=False)
    if lane_id != expected_lane_id:
        raise EvidenceError(f"{label}.lane_id must be {expected_lane_id}")
    source_kind = require_text(value, "source_kind", label, allow_unknown=False)
    if source_kind != _EXPECTED_SOURCE_KINDS[lane_id]:
        raise EvidenceError(f"{label}.source_kind does not match its lane")
    subject = _validate_subject(value.get("subject"), f"{label}.subject")
    origin = _validate_declared_origin(value.get("origin"), f"{label}.origin")
    artifact = _validate_artifact_binding(value.get("artifact"), f"{label}.artifact")
    components = _validate_components(
        value.get("components"),
        f"{label}.components",
        subject=subject,
        source_kind=source_kind,
        artifact=artifact,
    )
    relationships = _validate_relationships(
        value.get("relationships"),
        f"{label}.relationships",
        {component["component_id"] for component in components},
    )
    coverage = require_string_list(value, "coverage", label)
    blindspots = require_string_list(value, "blindspots", label)
    evidence_object = make_evidence_object(
        lane_id=lane_id,
        adapter_id=adapter_id,
        adapter_version=ADAPTER_VERSION,
        relative_path=input_identity["relative_path"],
        sha256=input_identity["sha256"],
        size=input_identity["size"],
    )
    evidence_object.update(
        {
            "declared_evidence_id": require_safe_id(value, "evidence_id", label),
            "release_id": require_safe_id(value, "release_id", label),
            "classification": classification,
            "source_kind": source_kind,
            "authorship": require_text(value, "authorship", label, allow_unknown=False),
            "origin": origin,
            "origin_verification_status": "DECLARED_NOT_CONSUMED",
            "artifact": artifact,
            "coverage": sorted(coverage),
            "blindspots": sorted(blindspots),
        }
    )
    evidence_id = evidence_object["evidence_id"]
    return {
        "lane_id": lane_id,
        "adapter_id": adapter_id,
        "adapter_version": ADAPTER_VERSION,
        "evidence_object": evidence_object,
        "subject": subject,
        "origin": origin,
        "artifact": artifact,
        "components": components,
        "component_claims": _claims_for_components(components, lane_id, evidence_id),
        "relationship_claims": _claims_for_relationships(relationships, lane_id, evidence_id),
    }


def adapt_build_manifest(
    value: dict[str, Any], input_identity: dict[str, Any]
) -> dict[str, Any]:
    """Adapt the Yocto-like build evidence lane."""

    return _adapt_evidence_document(
        value,
        input_identity,
        label=BUILD_MANIFEST_PATH,
        expected_lane_id=BUILD_LANE_ID,
        adapter_id=BUILD_ADAPTER_ID,
    )


def adapt_artifact_inventory(
    value: dict[str, Any], input_identity: dict[str, Any]
) -> dict[str, Any]:
    """Adapt the independently authored final-artifact inventory lane."""

    return _adapt_evidence_document(
        value,
        input_identity,
        label=ARTIFACT_INVENTORY_PATH,
        expected_lane_id=ARTIFACT_LANE_ID,
        adapter_id=ARTIFACT_ADAPTER_ID,
    )


def load_fixture(root: Path) -> dict[str, Any]:
    """Load only the three governed synthetic inputs from ``root``."""

    root = Path(root)
    raw_release, release_input = read_json_object(root, RELEASE_PATH)
    release = _validate_release(raw_release)

    build_ref = release["inputs"]["build_manifest"]
    artifact_ref = release["inputs"]["artifact_inventory"]
    raw_build, build_input = read_json_object(
        root,
        build_ref["relative_path"],
        expected_sha256=build_ref["sha256"],
    )
    raw_artifact, artifact_input = read_json_object(
        root,
        artifact_ref["relative_path"],
        expected_sha256=artifact_ref["sha256"],
    )
    release_artifact_input = read_file_identity(
        root,
        release["artifact_relative_path"],
        expected_sha256=release["artifact_sha256"],
    )

    build_lane = adapt_build_manifest(raw_build, build_input)
    artifact_lane = adapt_artifact_inventory(raw_artifact, artifact_input)
    lanes = sorted([build_lane, artifact_lane], key=lambda lane: lane["lane_id"])
    for lane in lanes:
        evidence_object = lane["evidence_object"]
        if evidence_object["release_id"] != release["release_id"]:
            raise EvidenceError("evidence release_id does not match release.json")
        if evidence_object["artifact"] != {
            "relative_path": release["artifact_relative_path"],
            "sha256": release["artifact_sha256"],
        }:
            raise EvidenceError("evidence artifact binding does not match release.json")
        subject = lane["subject"]
        if (
            subject["producer"] != release["manufacturer"]
            or subject["name"] != release["product"]
            or subject["version"] != release["product_version"]
        ):
            raise EvidenceError("evidence subject does not match the release identity")
    inputs = []
    for role, identity in (
        ("release", release_input),
        ("build_manifest", build_input),
        ("artifact_inventory", artifact_input),
        ("release_artifact", release_artifact_input),
    ):
        inputs.append({"input_role": role, **identity})
    inputs.sort(key=lambda item: item["relative_path"].encode("utf-8"))

    lane_identities = [
        {
            "lane_id": lane["lane_id"],
            "adapter_id": lane["adapter_id"],
            "adapter_version": lane["adapter_version"],
            "evidence_id": lane["evidence_object"]["evidence_id"],
            "declared_evidence_id": lane["evidence_object"]["declared_evidence_id"],
            "release_id": lane["evidence_object"]["release_id"],
            "source_kind": lane["evidence_object"]["source_kind"],
            "authorship": lane["evidence_object"]["authorship"],
            "origin": lane["evidence_object"]["origin"],
            "origin_verification_status": lane["evidence_object"]["origin_verification_status"],
            "coverage": lane["evidence_object"]["coverage"],
            "blindspots": lane["evidence_object"]["blindspots"],
        }
        for lane in lanes
    ]
    graph = {
        "schema_version": SCHEMA_VERSION,
        "classification": SYNTHETIC_CLASSIFICATION,
        "release": release,
        "inputs": inputs,
        "lane_identities": lane_identities,
        "lanes": [
            {
                "lane_id": lane["lane_id"],
                "adapter_id": lane["adapter_id"],
                "adapter_version": lane["adapter_version"],
                "evidence_id": lane["evidence_object"]["evidence_id"],
                "declared_evidence_id": lane["evidence_object"]["declared_evidence_id"],
                "source_kind": lane["evidence_object"]["source_kind"],
                "origin": lane["evidence_object"]["origin"],
                "origin_verification_status": lane["evidence_object"]["origin_verification_status"],
                "coverage": lane["evidence_object"]["coverage"],
                "blindspots": lane["evidence_object"]["blindspots"],
                "components": lane["components"],
            }
            for lane in lanes
        ],
        "evidence_objects": sorted(
            [lane["evidence_object"] for lane in lanes], key=lambda item: item["evidence_id"]
        ),
        "component_claims": sorted(
            [claim for lane in lanes for claim in lane["component_claims"]],
            key=lambda claim: claim["claim_id"],
        ),
        "relationship_claims": sorted(
            [claim for lane in lanes for claim in lane["relationship_claims"]],
            key=lambda claim: claim["claim_id"],
        ),
    }
    graph["ingest_run_id"] = stable_id(
        "ingest-run",
        {
            "classification": graph["classification"],
            "release": graph["release"],
            "inputs": graph["inputs"],
            "lane_identities": graph["lane_identities"],
        },
    )
    validate_claim_evidence_links(graph)
    return graph
