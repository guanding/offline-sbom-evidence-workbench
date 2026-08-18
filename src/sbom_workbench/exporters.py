"""Deterministic native CycloneDX 1.7 and SPDX 3.0.1 exporters.

Both serializers consume the same closed canonical evidence graph.  Neither
serializer consumes the other format, a model response, or an oracle.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections import defaultdict
from typing import Any

from .evidence import UNKNOWN, EvidenceError, canonical_graph_sha256
from .manifest import canonical_json_bytes
from .validation import SPDX_CONTEXT_URI
from .workflow import recompute_graph_reconciliation


class ExportError(EvidenceError):
    """Raised when an evidence graph is not eligible for deterministic export."""


_SPDX_RELATIONSHIPS = {
    "CONTAINS": "contains",
    "DEPENDS_ON": "dependsOn",
    "DYNAMICALLY_LINKS": "hasDynamicLink",
    "GENERATED_FROM": "packagedBy",
}
_SAFE_FRAGMENT = re.compile(r"[^A-Za-z0-9._~-]+")


def _require_closed_graph(graph: dict[str, Any]) -> None:
    if not isinstance(graph, dict):
        raise ExportError("canonical graph must be an object")
    if graph.get("classification") != "SYNTHETIC_NOT_EVIDENCE":
        raise ExportError("this MVP exporter accepts only SYNTHETIC_NOT_EVIDENCE runs")
    if graph.get("canonical_sha256") != canonical_graph_sha256(graph):
        raise ExportError("canonical graph hash does not match its content")
    reconciliation = graph.get("reconciliation")
    if not isinstance(reconciliation, dict) or reconciliation.get("state") != "CLOSED":
        raise ExportError("only a RECONCILIATION_CLOSED graph may be exported")
    try:
        expected_reconciliation = recompute_graph_reconciliation(graph)
    except (EvidenceError, KeyError, TypeError, ValueError) as exc:
        raise ExportError(f"reconciliation cannot be independently recomputed: {exc}") from exc
    if reconciliation != expected_reconciliation:
        raise ExportError("embedded reconciliation does not match independent semantic recomputation")
    findings = reconciliation.get("findings")
    if not isinstance(findings, list):
        raise ExportError("reconciliation findings are missing")
    statuses = ("MATCHED", "CONFLICT", "MISSING_FROM_SBOM", "NOT_IN_RELEASE", "UNKNOWN")
    observed_counts = {status: 0 for status in statuses}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or finding.get("status") not in observed_counts:
            raise ExportError(f"reconciliation finding {index} has an invalid status")
        observed_counts[finding["status"]] += 1
    counts = reconciliation.get("counts")
    if counts != observed_counts:
        raise ExportError("reconciliation counts do not match findings")
    observed_blocking = sorted(
        status for status, count in observed_counts.items() if status != "MATCHED" and count
    )
    if reconciliation.get("blocking_statuses") != observed_blocking or observed_blocking:
        raise ExportError("closed reconciliation contains an unresolved finding")
    population = graph.get("component_population")
    if not isinstance(population, list) or not population:
        raise ExportError("component population is missing")
    for index, component in enumerate(population):
        if not isinstance(component, dict):
            raise ExportError(f"component_population[{index}] is invalid")
        if component.get("conflict_fields") or component.get("critical_unknown_fields"):
            raise ExportError(f"component_population[{index}] is not exportable")
        for field in ("population_id", "producer", "name", "version"):
            if not isinstance(component.get(field), str) or component[field] in {"", UNKNOWN}:
                raise ExportError(f"component_population[{index}].{field} is not established")
        identifiers = component.get("identifiers")
        if not isinstance(identifiers, list) or not identifiers or UNKNOWN in identifiers:
            raise ExportError(f"component_population[{index}] has no established identifier")
    population_sha256 = hashlib.sha256(canonical_json_bytes(population)).hexdigest()
    if reconciliation.get("component_population_sha256") != population_sha256:
        raise ExportError("reconciliation does not bind the component population")
    candidate_input = graph.get("candidate_input")
    if not isinstance(candidate_input, dict) or not isinstance(candidate_input.get("components"), list):
        raise ExportError("candidate input is missing")
    candidate_sha256 = hashlib.sha256(canonical_json_bytes(candidate_input["components"])).hexdigest()
    if reconciliation.get("candidate_sha256") != candidate_sha256:
        raise ExportError("reconciliation does not bind the candidate component projection")


def _root_component(graph: dict[str, Any]) -> dict[str, Any]:
    release = graph["release"]
    matches = [
        component
        for component in graph["component_population"]
        if component["producer"] == release["manufacturer"]
        and component["name"] == release["product"]
        and component["version"] == release["product_version"]
        and "ROOT_PRODUCT" in component.get("roles", [])
    ]
    if len(matches) != 1:
        raise ExportError("component population must contain exactly one release-bound ROOT_PRODUCT")
    return matches[0]


def _bom_ref(graph: dict[str, Any], population_id: str) -> str:
    value = uuid.uuid5(uuid.NAMESPACE_URL, f"{graph['run_id']}:{population_id}")
    return f"urn:uuid:{value}"


def _purls(component: dict[str, Any]) -> list[str]:
    return sorted(
        {identifier for identifier in component["identifiers"] if identifier.startswith("pkg:")},
        key=lambda value: value.encode("utf-8"),
    )


_HASH_ALGORITHM_NAMES = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "blake3": "BLAKE3",
    "blake2b": "BLAKE2B",
}
_HASH_HEX_LENGTH = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-224": 56,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "BLAKE3": 64,
    "BLAKE2B": 128,
}


def _hashes(component: dict[str, Any]) -> list[dict[str, str]]:
    """Preserve every observed hash algorithm (EXP-3), normalized and hex-checked.

    Previously only SHA-256 survived; other algorithms (SHA-1/384/512, MD5,
    BLAKE3, ...) were silently dropped, starving downstream matchers of
    supplier-provided hashes. Each hash is normalized to its canonical
    CycloneDX/SPDX algorithm name and rejected when the hex length does not
    match the algorithm.
    """

    hashes: set[tuple[str, str]] = set()
    for raw_hash in component.get("observed_hashes", []):
        if not isinstance(raw_hash, dict):
            continue
        algorithm = raw_hash.get("algorithm")
        value = raw_hash.get("value")
        if not isinstance(algorithm, str) or not isinstance(value, str):
            continue
        normalized = _HASH_ALGORITHM_NAMES.get(algorithm.lower(), algorithm.upper())
        hex_value = value.lower()
        expected_length = _HASH_HEX_LENGTH.get(normalized)
        if expected_length is not None:
            if len(hex_value) != expected_length or not re.fullmatch(r"[0-9a-f]+", hex_value):
                continue
        elif not re.fullmatch(r"[0-9a-f]+", hex_value):
            continue
        hashes.add((normalized, hex_value))
    return [{"alg": algorithm, "content": value} for algorithm, value in sorted(hashes)]


def _component_type(component: dict[str, Any]) -> str:
    roles = set(component.get("roles", []))
    if "ROOT_PRODUCT" in roles or "TOP_LEVEL" in roles:
        return "application"
    if "BINARY_ONLY_FIRMWARE" in roles:
        return "firmware"
    return "library"


def _component_properties(component: dict[str, Any]) -> list[dict[str, str]]:
    properties: list[dict[str, str]] = []
    for identifier in sorted(component["identifiers"], key=lambda value: value.encode("utf-8")):
        properties.append({"name": "sbom-workbench:identifier", "value": identifier})
    for role in sorted(component.get("roles", []), key=lambda value: value.encode("utf-8")):
        properties.append({"name": "sbom-workbench:component-role", "value": role})
    for evidence_id in sorted(component.get("evidence_ids", []), key=lambda value: value.encode("utf-8")):
        properties.append({"name": "sbom-workbench:evidence-id", "value": evidence_id})
    for lane_id in sorted(component.get("discovery_lanes", []), key=lambda value: value.encode("utf-8")):
        properties.append({"name": "sbom-workbench:discovery-lane", "value": lane_id})
    for declared_hash in component.get("supplier_hashes", []):
        if not isinstance(declared_hash, dict):
            continue
        algorithm = declared_hash.get("algorithm")
        value = declared_hash.get("value")
        if value == UNKNOWN:
            continue
        properties.append(
            {
                "name": "sbom-workbench:supplier-declared-hash",
                "value": f"{algorithm}:{value}",
            }
        )
    return properties


def _cyclonedx_component(graph: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "type": _component_type(component),
        "bom-ref": _bom_ref(graph, component["population_id"]),
        "publisher": component["producer"],
        "name": component["name"],
        "version": component["version"],
        "properties": _component_properties(component),
    }
    purls = _purls(component)
    if purls:
        value["purl"] = purls[0]
    hashes = _hashes(component)
    if hashes:
        value["hashes"] = hashes
    return value


def export_cyclonedx(graph: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic CycloneDX 1.7 JSON document."""

    _require_closed_graph(graph)
    release = graph["release"]
    root = _root_component(graph)
    population_by_id = {item["population_id"]: item for item in graph["component_population"]}
    ref_by_id = {population_id: _bom_ref(graph, population_id) for population_id in population_by_id}

    dependency_targets: dict[str, set[str]] = defaultdict(set)
    relationship_properties: list[dict[str, str]] = []
    for relationship in graph.get("relationships", []):
        source = relationship["source_population_id"]
        target = relationship["target_population_id"]
        if source not in ref_by_id or target not in ref_by_id:
            raise ExportError("relationship endpoint is outside the component population")
        if relationship["relationship"] in {"DEPENDS_ON", "DYNAMICALLY_LINKS"}:
            dependency_targets[ref_by_id[source]].add(ref_by_id[target])
        relationship_properties.append(
            {
                "name": "sbom-workbench:relationship",
                "value": f"{ref_by_id[source]}|{relationship['relationship']}|{ref_by_id[target]}",
            }
        )
    all_refs = sorted(ref_by_id.values(), key=lambda value: value.encode("utf-8"))
    dependencies = [
        {
            "ref": reference,
            "dependsOn": sorted(dependency_targets.get(reference, set()), key=lambda value: value.encode("utf-8")),
        }
        for reference in all_refs
    ]
    components = [
        _cyclonedx_component(graph, component)
        for component in sorted(
            graph["component_population"],
            key=lambda value: value["population_id"].encode("utf-8"),
        )
        if component["population_id"] != root["population_id"]
    ]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, graph['run_id'])}",
        "version": 1,
        "metadata": {
            "timestamp": release["release_timestamp"],
            "authors": [{"name": release["sbom_author"]}],
            "component": _cyclonedx_component(graph, root),
            "properties": [
                {"name": "sbom-workbench:classification", "value": graph["classification"]},
                {"name": "sbom-workbench:run-id", "value": graph["run_id"]},
                {"name": "sbom-workbench:canonical-sha256", "value": graph["canonical_sha256"]},
                {"name": "sbom-workbench:build-id", "value": release["build_id"]},
                {"name": "sbom-workbench:release-artifact-sha256", "value": release["artifact_sha256"]},
                {"name": "sbom-workbench:technical-state", "value": "SYNTHETIC_RECONCILIATION_CLOSED"},
            ],
        },
        "components": components,
        "dependencies": dependencies,
        "properties": sorted(relationship_properties, key=lambda item: item["value"].encode("utf-8")),
    }


def _fragment(value: str) -> str:
    cleaned = _SAFE_FRAGMENT.sub("-", value).strip("-")[:48]
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{cleaned or 'id'}-{digest}"


def _spdx_id(graph: dict[str, Any], kind: str, identity: str) -> str:
    return f"https://example.invalid/sbom-workbench/{_fragment(graph['run_id'])}/{kind}/{_fragment(identity)}"


def _spdx_primary_purpose(component: dict[str, Any]) -> str:
    component_type = _component_type(component)
    return {"application": "application", "firmware": "firmware", "library": "library"}[component_type]


def _spdx_external_identifiers(component: dict[str, Any]) -> list[dict[str, str]]:
    identifiers = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl" if identifier.startswith("pkg:") else "other",
            "identifier": identifier,
        }
        for identifier in sorted(component["identifiers"], key=lambda value: value.encode("utf-8"))
    ]
    identifiers.extend(
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "other",
            "identifier": f"supplier-declared-hash:{item.get('algorithm')}:{item.get('value')}",
        }
        for item in component.get("supplier_hashes", [])
        if isinstance(item, dict) and item.get("value") != UNKNOWN
    )
    return identifiers


def _spdx_hashes(component: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"type": "Hash", "algorithm": "sha256", "hashValue": item["content"]}
        for item in _hashes(component)
    ]


def export_spdx(graph: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic SPDX 3.0.1 JSON-LD document."""

    _require_closed_graph(graph)
    release = graph["release"]
    root = _root_component(graph)
    creation_id = f"_:creation-{hashlib.sha256(graph['run_id'].encode('utf-8')).hexdigest()[:20]}"
    tool_id = _spdx_id(graph, "tool", "offline-sbom-evidence-workbench")
    document_id = _spdx_id(graph, "document", release["release_id"])
    sbom_id = _spdx_id(graph, "sbom", release["release_id"])

    producers = sorted(
        {component["producer"] for component in graph["component_population"]} | {release["sbom_author"]},
        key=lambda value: value.encode("utf-8"),
    )
    organization_ids = {producer: _spdx_id(graph, "organization", producer) for producer in producers}
    package_ids = {
        component["population_id"]: _spdx_id(graph, "package", component["population_id"])
        for component in graph["component_population"]
    }
    source_binding = {
        "build_id": release["build_id"],
        "canonical_sha256": graph["canonical_sha256"],
        "classification": graph["classification"],
        "release_artifact_sha256": release["artifact_sha256"],
        "run_id": graph["run_id"],
    }
    binding_comment = "sbom-workbench:binding=" + canonical_json_bytes(source_binding).decode("utf-8")

    graph_items: list[dict[str, Any]] = [
        {
            "@id": creation_id,
            "type": "CreationInfo",
            "specVersion": "3.0.1",
            "createdBy": [organization_ids[release["sbom_author"]]],
            "createdUsing": [tool_id],
            "created": release["release_timestamp"],
        }
    ]
    for producer in producers:
        graph_items.append(
            {
                "spdxId": organization_ids[producer],
                "type": "Organization",
                "name": producer,
                "creationInfo": creation_id,
            }
        )
    graph_items.append(
        {
            "spdxId": tool_id,
            "type": "Tool",
            "name": "Offline SBOM Evidence Workbench",
            "creationInfo": creation_id,
        }
    )

    relationship_items: list[dict[str, Any]] = []
    for relationship in sorted(
        graph.get("relationships", []), key=lambda item: item["relationship_id"].encode("utf-8")
    ):
        relation_type = _SPDX_RELATIONSHIPS.get(relationship["relationship"])
        if relation_type is None:
            raise ExportError(f"SPDX relationship mapping is undefined: {relationship['relationship']}")
        relation_id = _spdx_id(graph, "relationship", relationship["relationship_id"])
        relationship_items.append(
            {
                "spdxId": relation_id,
                "type": "Relationship",
                "relationshipType": relation_type,
                "from": package_ids[relationship["source_population_id"]],
                "to": [package_ids[relationship["target_population_id"]]],
                "comment": "evidence_ids=" + ",".join(relationship.get("evidence_ids", [])),
                "creationInfo": creation_id,
            }
        )

    package_items: list[dict[str, Any]] = []
    for component in sorted(
        graph["component_population"], key=lambda item: item["population_id"].encode("utf-8")
    ):
        package: dict[str, Any] = {
            "spdxId": package_ids[component["population_id"]],
            "type": "software_Package",
            "name": component["name"],
            "software_packageVersion": component["version"],
            "software_primaryPurpose": _spdx_primary_purpose(component),
            "suppliedBy": organization_ids[component["producer"]],
            "externalIdentifier": _spdx_external_identifiers(component),
            "comment": (
                "classification=SYNTHETIC_NOT_EVIDENCE; evidence_ids="
                + ",".join(component.get("evidence_ids", []))
            ),
            "creationInfo": creation_id,
        }
        purls = _purls(component)
        if purls:
            package["software_packageUrl"] = purls[0]
        verified_using = _spdx_hashes(component)
        if verified_using:
            package["verifiedUsing"] = verified_using
        package_items.append(package)

    element_ids = [item["spdxId"] for item in package_items + relationship_items]
    graph_items.extend(
        [
            {
                "spdxId": document_id,
                "type": "SpdxDocument",
                "name": f"{release['product']} {release['product_version']} SPDX document",
                "summary": (
                    "SYNTHETIC_NOT_EVIDENCE engineering fixture; mechanical validation does not establish "
                    "component completeness, manufacturer approval, CRA conformity, or certification."
                ),
                "comment": binding_comment,
                "creationInfo": creation_id,
                "profileConformance": ["core", "software"],
                "element": [sbom_id, *element_ids],
                "rootElement": [sbom_id],
            },
            {
                "spdxId": sbom_id,
                "type": "software_Sbom",
                "name": f"{release['product']} {release['product_version']} synthetic build SBOM",
                "creationInfo": creation_id,
                "profileConformance": ["core", "software"],
                "element": element_ids,
                "rootElement": [package_ids[root["population_id"]]],
                "software_sbomType": ["build"],
                "comment": binding_comment,
            },
        ]
    )
    graph_items.extend(package_items)
    graph_items.extend(relationship_items)
    return {"@context": SPDX_CONTEXT_URI, "@graph": graph_items}


def export_pair(graph: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return native CycloneDX and SPDX documents from one closed graph."""

    return export_cyclonedx(graph), export_spdx(graph)
