"""End-to-end deterministic synthetic analysis workflow."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .candidate import load_candidate
from .evidence import (
    UNKNOWN,
    EvidenceError,
    canonical_graph_sha256,
    require_exact_keys,
    require_mapping,
    require_safe_id,
    stable_id,
)
from .manifest import canonical_json_bytes
from .reconcile import (
    STATUSES,
    build_canonical_graph,
    build_component_population,
    build_relationship_projection,
    normalize_candidate_components,
    reconcile,
)


_EMBEDDED_CANDIDATE_KEYS = {
    "candidate_id",
    "producer",
    "name",
    "version",
    "identifiers",
    "roles",
    "provenances",
    "observed_hashes",
    "supplier_hashes",
}
_EMBEDDED_INPUT_KEYS = {
    "candidate_id",
    "components",
    "declared_technical_status",
    "document_identity",
    "relationships",
    "sha256",
}
_CANDIDATE_RELATIONSHIP_KEYS = {
    "source_candidate_id",
    "relationship",
    "target_candidate_id",
}
_CANDIDATE_RELATIONSHIPS = {"CONTAINS", "DEPENDS_ON", "GENERATED_FROM"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _embedded_candidate_components(raw: object) -> list[dict[str, Any]]:
    """Validate the normalized candidate projection by round-tripping it."""

    if not isinstance(raw, list):
        raise EvidenceError("candidate_input.components must be an array")
    projected: list[dict[str, Any]] = []
    for index, raw_item in enumerate(raw):
        label = f"candidate_input.components[{index}]"
        item = require_mapping(raw_item, label)
        require_exact_keys(item, _EMBEDDED_CANDIDATE_KEYS, label)
        provenances: list[str] = []
        for provenance_index, raw_provenance in enumerate(item["provenances"]):
            provenance = require_mapping(
                raw_provenance, f"{label}.provenances[{provenance_index}]"
            )
            require_exact_keys(
                provenance,
                {"kind", "locator", "source_available"},
                f"{label}.provenances[{provenance_index}]",
            )
            if provenance["source_available"] != UNKNOWN:
                raise EvidenceError(f"{label}.provenances source_available must remain UNKNOWN")
            if not isinstance(provenance["kind"], str) or not isinstance(
                provenance["locator"], str
            ):
                raise EvidenceError(f"{label}.provenances kind/locator must be strings")
            provenances.append(f"{provenance['kind']}:{provenance['locator']}")

        def hash_pairs(field: str) -> list[tuple[str, str]]:
            values = item[field]
            if not isinstance(values, list):
                raise EvidenceError(f"{label}.{field} must be an array")
            pairs: list[tuple[str, str]] = []
            for hash_index, raw_hash in enumerate(values):
                value = require_mapping(raw_hash, f"{label}.{field}[{hash_index}]")
                require_exact_keys(
                    value,
                    {"algorithm", "value"},
                    f"{label}.{field}[{hash_index}]",
                )
                pairs.append((value["algorithm"], value["value"]))
            return pairs

        projected.append(
            {
                "candidate_id": item["candidate_id"],
                "producer": item["producer"],
                "name": item["name"],
                "version": item["version"],
                "identifiers": item["identifiers"],
                "roles": item["roles"],
                "provenances": provenances,
                "observed_hashes": hash_pairs("observed_hashes"),
                "supplier_hashes": hash_pairs("supplier_hashes"),
            }
        )
    normalized = normalize_candidate_components(projected)
    if normalized != raw:
        raise EvidenceError("candidate_input.components is not the canonical normalized projection")
    return projected


def _candidate_relationships(raw: object, known_candidate_ids: set[str]) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise EvidenceError("candidate_input.relationships must be an array")
    relationships: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw_item in enumerate(raw):
        label = f"candidate_input.relationships[{index}]"
        item = require_mapping(raw_item, label)
        require_exact_keys(item, _CANDIDATE_RELATIONSHIP_KEYS, label)
        source = require_safe_id(item, "source_candidate_id", label)
        target = require_safe_id(item, "target_candidate_id", label)
        relation = item["relationship"]
        if relation not in _CANDIDATE_RELATIONSHIPS:
            raise EvidenceError(f"{label}.relationship is unsupported")
        if source not in known_candidate_ids or target not in known_candidate_ids:
            raise EvidenceError(f"{label} references an unknown candidate")
        key = (source, relation, target)
        if key in seen:
            raise EvidenceError("candidate_input.relationships contains a duplicate")
        seen.add(key)
        relationships.append(
            {
                "source_candidate_id": source,
                "relationship": relation,
                "target_candidate_id": target,
            }
        )
    canonical = sorted(
        relationships,
        key=lambda item: (
            item["source_candidate_id"].encode("utf-8"),
            item["relationship"].encode("utf-8"),
            item["target_candidate_id"].encode("utf-8"),
        ),
    )
    if canonical != raw:
        raise EvidenceError("candidate_input.relationships is not canonical")
    return canonical


def _candidate_relationship_findings(
    reconciliation: dict[str, Any],
    evidence_relationships: list[dict[str, Any]],
    candidate_relationships: list[dict[str, str]],
) -> list[dict[str, Any]]:
    candidate_to_population: dict[str, str] = {}
    for finding in reconciliation["findings"]:
        candidate_id = finding.get("candidate_id")
        population_id = finding.get("population_id")
        if isinstance(candidate_id, str) and isinstance(population_id, str):
            candidate_to_population[candidate_id] = population_id

    expected: dict[tuple[str, str, str], dict[str, Any]] = {}
    for relationship in evidence_relationships:
        key = (
            relationship["source_population_id"],
            relationship["relationship"],
            relationship["target_population_id"],
        )
        expected[key] = relationship

    declared: dict[tuple[str, str, str], dict[str, Any]] = {}
    unmapped: list[dict[str, Any]] = []
    for relationship in candidate_relationships:
        source = candidate_to_population.get(relationship["source_candidate_id"])
        target = candidate_to_population.get(relationship["target_candidate_id"])
        if source is None or target is None:
            unmapped.append(relationship)
            continue
        declared[(source, relationship["relationship"], target)] = relationship

    findings: list[dict[str, Any]] = []
    for key in sorted(set(expected) | set(declared)):
        evidence_relationship = expected.get(key)
        candidate_relationship = declared.get(key)
        if evidence_relationship is not None and candidate_relationship is not None:
            status = "MATCHED"
            details: list[str] = []
            evidence_ids = list(evidence_relationship["evidence_ids"])
            claim_ids = list(evidence_relationship["claim_ids"])
        elif evidence_relationship is not None:
            status = "MISSING_FROM_SBOM"
            details = ["candidate_relationship_missing"]
            evidence_ids = list(evidence_relationship["evidence_ids"])
            claim_ids = list(evidence_relationship["claim_ids"])
        else:
            status = "NOT_IN_RELEASE"
            details = ["candidate_relationship_not_supported_by_discovery"]
            evidence_ids = []
            claim_ids = []
        body = {
            "finding_type": "CANDIDATE_RELATIONSHIP",
            "source_population_id": key[0],
            "relationship": key[1],
            "target_population_id": key[2],
            "status": status,
            "details": details,
            "claim_ids": claim_ids,
            "evidence_ids": evidence_ids,
        }
        findings.append({"finding_id": stable_id("finding", body), **body})
    for relationship in unmapped:
        body = {
            "finding_type": "CANDIDATE_RELATIONSHIP",
            "source_candidate_id": relationship["source_candidate_id"],
            "relationship": relationship["relationship"],
            "target_candidate_id": relationship["target_candidate_id"],
            "status": "UNKNOWN",
            "details": ["candidate_relationship_endpoint_not_reconciled"],
            "claim_ids": [],
            "evidence_ids": [],
        }
        findings.append({"finding_id": stable_id("finding", body), **body})
    return sorted(findings, key=lambda item: item["finding_id"])


def recompute_graph_reconciliation(graph: dict[str, Any]) -> dict[str, Any]:
    """Rebuild all closure semantics from lane claims and candidate projections."""

    candidate_input = require_mapping(graph.get("candidate_input"), "candidate_input")
    require_exact_keys(candidate_input, _EMBEDDED_INPUT_KEYS, "candidate_input")
    raw_components = _embedded_candidate_components(candidate_input["components"])
    normalized_sha256 = hashlib.sha256(
        canonical_json_bytes(candidate_input["components"])
    ).hexdigest()
    if candidate_input["sha256"] != normalized_sha256:
        raise EvidenceError("candidate_input.sha256 does not bind candidate components")
    known_candidate_ids = {item["candidate_id"] for item in candidate_input["components"]}
    candidate_relationships = _candidate_relationships(
        candidate_input["relationships"], known_candidate_ids
    )

    expected_population = build_component_population(graph)
    if graph.get("component_population") != expected_population:
        raise EvidenceError("component population does not match independent discovery claims")
    expected_relationships = build_relationship_projection(graph, expected_population)
    if graph.get("relationships") != expected_relationships:
        raise EvidenceError("relationship projection does not match discovery claims")

    reconciliation = reconcile(graph, raw_components)
    findings = list(reconciliation["findings"])
    findings.extend(
        _candidate_relationship_findings(
            reconciliation, expected_relationships, candidate_relationships
        )
    )
    counts = {status: 0 for status in STATUSES}
    for finding in findings:
        counts[finding["status"]] += 1
    blocking_statuses = sorted(
        status for status, count in counts.items() if status != "MATCHED" and count
    )
    computed_state = "CLOSED" if not blocking_statuses else "OPEN"
    declared_status = candidate_input["declared_technical_status"]
    if declared_status not in {
        "SYNTHETIC_RECONCILED",
        "SYNTHETIC_RECONCILIATION_OPEN",
    }:
        raise EvidenceError("candidate declared technical status is invalid")
    expected_declared_status = (
        "SYNTHETIC_RECONCILED" if computed_state == "CLOSED" else "SYNTHETIC_RECONCILIATION_OPEN"
    )
    if declared_status != expected_declared_status:
        body = {
            "finding_type": "DECLARED_STATUS_MISMATCH",
            "status": "CONFLICT",
            "details": [f"declared={declared_status}", f"computed={expected_declared_status}"],
            "claim_ids": [],
            "evidence_ids": [],
        }
        findings.append({"finding_id": stable_id("finding", body), **body})
        counts["CONFLICT"] += 1
        blocking_statuses = sorted(set([*blocking_statuses, "CONFLICT"]))
        computed_state = "OPEN"
    document_identity = require_mapping(
        candidate_input["document_identity"], "candidate_input.document_identity"
    )
    document_sha256 = document_identity.get("sha256")
    if not isinstance(document_sha256, str) or not _SHA256_RE.fullmatch(document_sha256):
        raise EvidenceError("candidate document identity SHA-256 is invalid")
    reconciliation.update(
        {
            "state": computed_state,
            "counts": counts,
            "blocking_statuses": blocking_statuses,
            "findings": sorted(findings, key=lambda item: item["finding_id"]),
            "candidate_document_sha256": document_sha256,
            "candidate_declared_technical_status": declared_status,
        }
    )
    return reconciliation


def analyze_fixture(root: Path) -> dict[str, Any]:
    """Build a release-bound graph and reconcile candidate facts and relations."""

    root = Path(root)
    candidate = load_candidate(root)
    graph = build_canonical_graph(root, candidate["components"])
    graph["candidate_input"].update(
        {
            "candidate_id": candidate["document"]["candidate_id"],
            "declared_technical_status": candidate["document"]["technical_status"],
            "document_identity": candidate["input_identity"],
            "relationships": candidate["relationships"],
        }
    )
    graph["reconciliation"] = recompute_graph_reconciliation(graph)
    graph["run_id"] = stable_id(
        "analysis-run",
        {
            "ingest_run_id": graph["ingest_run_id"],
            "candidate_document_sha256": candidate["input_identity"]["sha256"],
            "reconciler_id": graph["reconciliation"]["reconciler_id"],
            "reconciler_version": graph["reconciliation"]["reconciler_version"],
        },
    )
    graph["canonical_sha256"] = canonical_graph_sha256(graph)
    if graph["classification"] != "SYNTHETIC_NOT_EVIDENCE":
        raise EvidenceError("synthetic workflow classification changed unexpectedly")
    return graph


def _logical_component_key(component: dict[str, Any]) -> tuple[str, ...]:
    source_ids = sorted(
        {item["source_component_id"] for item in component["source_components"]},
        key=lambda value: value.encode("utf-8"),
    )
    return tuple(source_ids)


def diff_graphs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic release-to-release fact diff."""

    if previous.get("classification") != "SYNTHETIC_NOT_EVIDENCE" or current.get(
        "classification"
    ) != "SYNTHETIC_NOT_EVIDENCE":
        raise EvidenceError("synthetic diff accepts only synthetic graphs")
    previous_components = {
        _logical_component_key(component): component
        for component in previous["component_population"]
    }
    current_components = {
        _logical_component_key(component): component
        for component in current["component_population"]
    }
    changes: list[dict[str, Any]] = []
    for key in sorted(set(previous_components) | set(current_components)):
        before = previous_components.get(key)
        after = current_components.get(key)
        if before is None:
            changes.append(
                {
                    "change": "ADDED",
                    "source_component_ids": list(key),
                    "current": {
                        field: after[field] for field in ("producer", "name", "version", "identifiers")
                    },
                }
            )
            continue
        if after is None:
            changes.append(
                {
                    "change": "REMOVED",
                    "source_component_ids": list(key),
                    "previous": {
                        field: before[field] for field in ("producer", "name", "version", "identifiers")
                    },
                }
            )
            continue
        changed_fields = [
            field
            for field in ("producer", "name", "version", "identifiers", "observed_hashes")
            if before[field] != after[field]
        ]
        if changed_fields:
            changes.append(
                {
                    "change": "MODIFIED",
                    "source_component_ids": list(key),
                    "changed_fields": changed_fields,
                    "previous": {field: before[field] for field in changed_fields},
                    "current": {field: after[field] for field in changed_fields},
                }
            )

    def relationship_keys(graph: dict[str, Any]) -> set[tuple[tuple[str, ...], str, tuple[str, ...]]]:
        population = {
            item["population_id"]: _logical_component_key(item)
            for item in graph["component_population"]
        }
        return {
            (
                population[item["source_population_id"]],
                item["relationship"],
                population[item["target_population_id"]],
            )
            for item in graph["relationships"]
        }

    previous_relationships = relationship_keys(previous)
    current_relationships = relationship_keys(current)
    return {
        "schema_version": "1.0",
        "classification": "SYNTHETIC_NOT_EVIDENCE",
        "previous_run_id": previous["run_id"],
        "current_run_id": current["run_id"],
        "previous_release_id": previous["release"]["release_id"],
        "current_release_id": current["release"]["release_id"],
        "component_changes": changes,
        "relationship_changes": {
            "removed": [
                {"from": list(item[0]), "relationship": item[1], "to": list(item[2])}
                for item in sorted(previous_relationships - current_relationships)
            ],
            "added": [
                {"from": list(item[0]), "relationship": item[1], "to": list(item[2])}
                for item in sorted(current_relationships - previous_relationships)
            ],
        },
    }
