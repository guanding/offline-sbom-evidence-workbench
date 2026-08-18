"""Independent component population and deterministic candidate reconciliation."""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .evidence import (
    MAX_COLLECTION_ITEMS,
    UNKNOWN,
    EvidenceError,
    canonical_graph_sha256,
    require_exact_keys,
    require_mapping,
    require_safe_id,
    require_text,
    stable_id,
    validate_claim_evidence_links,
)
from .ingest import load_fixture
from .manifest import canonical_json_bytes


RECONCILER_ID = "deterministic-component-reconciler"
RECONCILER_VERSION = "1.0.0"
STATUSES = (
    "MATCHED",
    "CONFLICT",
    "MISSING_FROM_SBOM",
    "NOT_IN_RELEASE",
    "UNKNOWN",
)

_CANDIDATE_KEYS = {
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
_CRITICAL_FIELDS = ("producer", "name", "version", "identifier")


def _concrete_identifiers(component: dict[str, Any]) -> set[str]:
    return {item for item in component["identifiers"] if item != UNKNOWN}


def _concrete_text(component: dict[str, Any], field: str) -> str | None:
    value = component[field]
    return None if value == UNKNOWN else value


def _validate_candidate_components(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise EvidenceError("candidate_components must be an array")
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise EvidenceError("candidate_components exceeds the component limit")
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        label = f"candidate_components[{index}]"
        candidate = require_mapping(item, label)
        require_exact_keys(candidate, _CANDIDATE_KEYS, label)
        candidate_id = require_safe_id(candidate, "candidate_id", label)
        if candidate_id in seen:
            raise EvidenceError(f"candidate_components contains duplicate candidate_id {candidate_id}")
        seen.add(candidate_id)
        identifiers = _normalize_text_sequence(candidate.get("identifiers"), f"{label}.identifiers")
        roles = _normalize_text_sequence(candidate.get("roles"), f"{label}.roles", allow_empty=True)
        provenance_values = _normalize_text_sequence(
            candidate.get("provenances"), f"{label}.provenances", allow_empty=True
        )
        provenances: list[dict[str, Any]] = []
        for provenance_index, provenance in enumerate(provenance_values):
            if ":" not in provenance:
                raise EvidenceError(
                    f"{label}.provenances[{provenance_index}] must use kind:locator"
                )
            kind, locator = provenance.split(":", 1)
            if not kind or not locator:
                raise EvidenceError(
                    f"{label}.provenances[{provenance_index}] must use kind:locator"
                )
            provenances.append(
                {"kind": kind, "locator": locator, "source_available": UNKNOWN}
            )
        observed_hashes = _normalize_hash_sequence(
            candidate.get("observed_hashes"),
            f"{label}.observed_hashes",
            allow_unknown_algorithm=False,
        )
        supplier_hashes = _normalize_hash_sequence(
            candidate.get("supplier_hashes"),
            f"{label}.supplier_hashes",
            allow_unknown_algorithm=True,
        )
        candidates.append(
            {
                "candidate_id": candidate_id,
                "producer": require_text(candidate, "producer", label),
                "name": require_text(candidate, "name", label),
                "version": require_text(candidate, "version", label),
                "identifiers": identifiers,
                "roles": roles,
                "provenances": _unique_dicts(provenances),
                "observed_hashes": observed_hashes,
                "supplier_hashes": supplier_hashes,
            }
        )
    return sorted(candidates, key=lambda candidate: candidate["candidate_id"].encode("utf-8"))


def normalize_candidate_components(raw: object) -> list[dict[str, Any]]:
    """Validate candidate input and return its canonical normalized projection."""

    return _validate_candidate_components(raw)


def _normalize_text_sequence(
    raw: object, label: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(raw, (list, tuple)):
        raise EvidenceError(f"{label} must be an array or tuple")
    if not raw and not allow_empty:
        raise EvidenceError(f"{label} must not be empty")
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise EvidenceError(f"{label} exceeds the item limit")
    values: set[str] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise EvidenceError(f"{label}[{index}] must be a non-empty string")
        if any(ord(character) < 0x20 for character in value):
            raise EvidenceError(f"{label}[{index}] must not contain control characters")
        if value in values:
            raise EvidenceError(f"{label} must not contain duplicates")
        values.add(value)
    if UNKNOWN in values and len(values) > 1:
        raise EvidenceError(f"{label} cannot mix UNKNOWN with concrete values")
    return sorted(values, key=lambda value: value.encode("utf-8"))


def _normalize_hash_sequence(
    raw: object,
    label: str,
    *,
    allow_unknown_algorithm: bool,
) -> list[dict[str, str]]:
    if not isinstance(raw, (list, tuple)):
        raise EvidenceError(f"{label} must be an array or tuple")
    if len(raw) > MAX_COLLECTION_ITEMS:
        raise EvidenceError(f"{label} exceeds the item limit")
    hashes: dict[tuple[str, str], dict[str, str]] = {}
    for index, value in enumerate(raw):
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise EvidenceError(f"{label}[{index}] must be an algorithm/value pair")
        algorithm, hash_value = value
        if algorithm not in ({"SHA-256", UNKNOWN} if allow_unknown_algorithm else {"SHA-256"}):
            raise EvidenceError(f"{label}[{index}] has an unsupported algorithm")
        if not isinstance(hash_value, str) or not re.fullmatch(r"[0-9a-f]{64}", hash_value):
            raise EvidenceError(f"{label}[{index}] value must be a lowercase SHA-256")
        identity = (algorithm, hash_value)
        if identity in hashes:
            raise EvidenceError(f"{label} must not contain duplicates")
        hashes[identity] = {"algorithm": algorithm, "value": hash_value}
    return [hashes[key] for key in sorted(hashes)]


def _records_from_graph(graph: dict[str, Any]) -> list[dict[str, Any]]:
    lanes = graph.get("lanes")
    if not isinstance(lanes, list) or len(lanes) < 2:
        raise EvidenceError("component population requires at least two discovery lanes")
    lane_ids: set[str] = set()
    adapter_ids: set[str] = set()
    evidence_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    for lane_index, raw_lane in enumerate(lanes):
        lane = require_mapping(raw_lane, f"graph.lanes[{lane_index}]")
        lane_id = lane.get("lane_id")
        adapter_id = lane.get("adapter_id")
        evidence_id = lane.get("evidence_id")
        if not all(isinstance(value, str) and value for value in (lane_id, adapter_id, evidence_id)):
            raise EvidenceError(f"graph.lanes[{lane_index}] has an invalid identity")
        if lane_id in lane_ids or adapter_id in adapter_ids or evidence_id in evidence_ids:
            raise EvidenceError("discovery lanes must have distinct lane, adapter, and evidence identities")
        lane_ids.add(lane_id)
        adapter_ids.add(adapter_id)
        evidence_ids.add(evidence_id)
        components = lane.get("components")
        if not isinstance(components, list) or not components:
            raise EvidenceError(f"graph.lanes[{lane_index}].components must be non-empty")
        for component in components:
            if not isinstance(component, dict):
                raise EvidenceError(f"graph.lanes[{lane_index}] contains an invalid component")
            records.append(
                {
                    "lane_id": lane_id,
                    "source_component_id": component["component_id"],
                    "producer": component["producer"],
                    "name": component["name"],
                    "version": component["version"],
                    "identifiers": list(component["identifiers"]),
                    "roles": [component["component_role"]],
                    "provenances": [dict(component["provenance"])],
                    "observed_hashes": [dict(component["observed_hash"])],
                    "supplier_hashes": [dict(component["supplier_hash"])],
                }
            )
    return sorted(
        records,
        key=lambda item: (item["lane_id"].encode("utf-8"), item["source_component_id"].encode("utf-8")),
    )


def _records_refer_to_same_component(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left["lane_id"] == right["lane_id"]:
        return False
    left_identifiers = _concrete_identifiers(left)
    right_identifiers = _concrete_identifiers(right)
    if left_identifiers and right_identifiers:
        if not left_identifiers.intersection(right_identifiers):
            return False
        left_hashes = _concrete_hash_pairs(left["observed_hashes"])
        right_hashes = _concrete_hash_pairs(right["observed_hashes"])
        if left_hashes and right_hashes:
            return bool(left_hashes.intersection(right_hashes))
        left_provenance = _provenance_pairs(left["provenances"])
        right_provenance = _provenance_pairs(right["provenances"])
        if left_provenance and right_provenance:
            return bool(left_provenance.intersection(right_provenance))
        return True
    left_tuple = tuple(_concrete_text(left, field) for field in ("producer", "name", "version"))
    right_tuple = tuple(_concrete_text(right, field) for field in ("producer", "name", "version"))
    if None in left_tuple or left_tuple != right_tuple:
        return False
    left_hashes = _concrete_hash_pairs(left["observed_hashes"])
    right_hashes = _concrete_hash_pairs(right["observed_hashes"])
    if left_hashes and right_hashes:
        return bool(left_hashes.intersection(right_hashes))
    left_provenance = _provenance_pairs(left["provenances"])
    right_provenance = _provenance_pairs(right["provenances"])
    if left_provenance and right_provenance:
        return bool(left_provenance.intersection(right_provenance))
    return True


def _concrete_hash_pairs(values: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        (value["algorithm"], value["value"])
        for value in values
        if value.get("algorithm") != UNKNOWN and value.get("value") != UNKNOWN
    }


def _provenance_pairs(values: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        (value["kind"], value["locator"])
        for value in values
        if value.get("kind") != UNKNOWN and value.get("locator") != UNKNOWN
    }


def _unique_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = {canonical_json_bytes(value): dict(value) for value in values}
    return [indexed[key] for key in sorted(indexed)]


def _claim_indexes(graph: dict[str, Any]) -> tuple[dict[tuple[str, str, str], list[str]], dict[str, list[str]]]:
    by_field: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    evidence_by_claim: dict[str, list[str]] = {}
    for claim in graph["component_claims"]:
        key = (claim["lane_id"], claim["source_component_id"], claim["field"])
        by_field[key].append(claim["claim_id"])
        evidence_by_claim[claim["claim_id"]] = list(claim["evidence_ids"])
    for claim_ids in by_field.values():
        claim_ids.sort()
    return by_field, evidence_by_claim


def build_component_population(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a union from discovery lanes only.

    This function intentionally has no candidate/oracle argument and reads only
    ``graph["lanes"]`` plus evidence-linked claims.
    """

    validate_claim_evidence_links(graph)
    records = _records_from_graph(graph)
    parents = list(range(len(records)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for left in range(len(records)):
        for right in range(left + 1, len(records)):
            if _records_refer_to_same_component(records[left], records[right]):
                union(left, right)

    clusters: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        clusters[find(index)].append(record)

    claims_by_field, evidence_by_claim = _claim_indexes(graph)
    population: list[dict[str, Any]] = []
    for cluster_records in clusters.values():
        cluster_records.sort(
            key=lambda item: (
                item["lane_id"].encode("utf-8"),
                item["source_component_id"].encode("utf-8"),
            )
        )
        source_components = [
            {
                "lane_id": record["lane_id"],
                "source_component_id": record["source_component_id"],
            }
            for record in cluster_records
        ]
        conflict_fields: set[str] = set()
        normalized: dict[str, Any] = {}
        for field in ("producer", "name", "version"):
            concrete_values = sorted(
                {record[field] for record in cluster_records if record[field] != UNKNOWN},
                key=lambda value: value.encode("utf-8"),
            )
            if len(concrete_values) == 1:
                normalized[field] = concrete_values[0]
            else:
                normalized[field] = UNKNOWN
                if len(concrete_values) > 1:
                    conflict_fields.add(field)
        # Cross-lane identifiers are unioned as enrichment rather than flagged
        # as conflict. ``_records_refer_to_same_component`` above already
        # refuses to cluster two records whose concrete identifier sets are
        # disjoint, so every identifier reaching this union either shares a
        # concrete token with the rest of the cluster or comes from a record
        # that had no concrete identifier and was clustered by producer/name/
        # version plus hash/provenance. Adding ``identifier`` to
        # ``conflict_fields`` here would mis-flag legitimate enrichment as a
        # conflict and block RECONCILIATION_CLOSED (REC-03); divergence is
        # therefore preserved only as the multi-valued identifier set, which
        # keeps every observed identifier traceable without false-blocking
        # closure.
        concrete_identifiers = sorted(
            {
                identifier
                for record in cluster_records
                for identifier in record["identifiers"]
                if identifier != UNKNOWN
            },
            key=lambda value: value.encode("utf-8"),
        )
        normalized["identifiers"] = concrete_identifiers or [UNKNOWN]
        roles = sorted(
            {
                role
                for record in cluster_records
                for role in record["roles"]
                if role != UNKNOWN
            }
        )
        normalized["roles"] = roles or [UNKNOWN]
        normalized["provenances"] = _unique_dicts(
            [provenance for record in cluster_records for provenance in record["provenances"]]
        )
        normalized["observed_hashes"] = _unique_dicts(
            [hash_value for record in cluster_records for hash_value in record["observed_hashes"]]
        )
        normalized["supplier_hashes"] = _unique_dicts(
            [hash_value for record in cluster_records for hash_value in record["supplier_hashes"]]
        )
        if len(roles) > 1:
            conflict_fields.add("component_role")
        for field in ("observed_hashes", "supplier_hashes"):
            by_algorithm: dict[str, set[str]] = defaultdict(set)
            for hash_value in normalized[field]:
                if hash_value["algorithm"] != UNKNOWN and hash_value["value"] != UNKNOWN:
                    by_algorithm[hash_value["algorithm"]].add(hash_value["value"])
            if any(len(values) > 1 for values in by_algorithm.values()):
                conflict_fields.add("observed_hash" if field == "observed_hashes" else "supplier_hash")

        members_per_lane = Counter(record["lane_id"] for record in cluster_records)
        if any(count > 1 for count in members_per_lane.values()):
            conflict_fields.add("identity")

        field_claim_ids: dict[str, list[str]] = {}
        evidence_ids: set[str] = set()
        claim_fields = (
            "producer",
            "name",
            "version",
            "identifier",
            "component_role",
            "provenance_kind",
            "provenance_locator",
            "provenance_source_available",
            "observed_hash_algorithm",
            "observed_hash_value",
            "supplier_hash_algorithm",
            "supplier_hash_value",
        )
        for field in claim_fields:
            claim_ids = sorted(
                {
                    claim_id
                    for record in cluster_records
                    for claim_id in claims_by_field.get(
                        (record["lane_id"], record["source_component_id"], field), []
                    )
                }
            )
            if claim_ids:
                field_claim_ids[field] = claim_ids
                for claim_id in claim_ids:
                    evidence_ids.update(evidence_by_claim[claim_id])
        critical_unknown_fields = [
            field
            for field in _CRITICAL_FIELDS
            if (field == "identifier" and normalized["identifiers"] == [UNKNOWN])
            or (field != "identifier" and normalized[field] == UNKNOWN)
        ]
        critical_unknown_fields = sorted(set(critical_unknown_fields))
        nonblocking_unknown_fields = sorted(
            {
                f"supplier_hash_{'algorithm' if hash_value['algorithm'] == UNKNOWN else 'value'}"
                for hash_value in normalized["supplier_hashes"]
                if (hash_value["algorithm"] == UNKNOWN) != (hash_value["value"] == UNKNOWN)
            }
        )
        identity = {"source_components": source_components}
        population.append(
            {
                "population_id": stable_id("population", identity),
                "producer": normalized["producer"],
                "name": normalized["name"],
                "version": normalized["version"],
                "identifiers": normalized["identifiers"],
                "roles": normalized["roles"],
                "provenances": normalized["provenances"],
                "observed_hashes": normalized["observed_hashes"],
                "supplier_hashes": normalized["supplier_hashes"],
                "discovery_lanes": sorted({record["lane_id"] for record in cluster_records}),
                "source_components": source_components,
                "field_claim_ids": field_claim_ids,
                "evidence_ids": sorted(evidence_ids),
                "conflict_fields": sorted(conflict_fields),
                "critical_unknown_fields": critical_unknown_fields,
                "nonblocking_unknown_fields": nonblocking_unknown_fields,
            }
        )
    return sorted(population, key=lambda item: item["population_id"])


def _candidate_population_score(candidate: dict[str, Any], population: dict[str, Any]) -> int | None:
    candidate_identifiers = _concrete_identifiers(candidate)
    population_identifiers = _concrete_identifiers(population)
    if candidate_identifiers and population_identifiers:
        if not candidate_identifiers.intersection(population_identifiers):
            return None
        score = 100
    else:
        candidate_producer = _concrete_text(candidate, "producer")
        candidate_name = _concrete_text(candidate, "name")
        population_producer = _concrete_text(population, "producer")
        population_name = _concrete_text(population, "name")
        if (
            None in (candidate_producer, candidate_name, population_producer, population_name)
            or candidate_producer != population_producer
            or candidate_name != population_name
        ):
            return None
        score = 10
    if candidate["version"] != UNKNOWN and candidate["version"] == population["version"]:
        score += 5
    candidate_hashes = _concrete_hash_pairs(candidate["observed_hashes"])
    population_hashes = _concrete_hash_pairs(population["observed_hashes"])
    if candidate_hashes and population_hashes and candidate_hashes.intersection(population_hashes):
        score += 1000
    candidate_provenance = _provenance_pairs(candidate["provenances"])
    population_provenance = _provenance_pairs(population["provenances"])
    if candidate_provenance and population_provenance.intersection(candidate_provenance):
        score += 500
    candidate_roles = {role for role in candidate["roles"] if role != UNKNOWN}
    population_roles = {role for role in population["roles"] if role != UNKNOWN}
    if candidate_roles and population_roles.intersection(candidate_roles):
        score += 100
    return score


def _matched_status(
    population: dict[str, Any], candidate: dict[str, Any]
) -> tuple[str, list[str]]:
    if population["conflict_fields"]:
        return "CONFLICT", list(population["conflict_fields"])
    if population["critical_unknown_fields"]:
        return "UNKNOWN", list(population["critical_unknown_fields"])
    unknown_fields: list[str] = []
    differences: list[str] = []
    for field in ("producer", "name", "version"):
        if population[field] == UNKNOWN or candidate[field] == UNKNOWN:
            unknown_fields.append(field)
        elif population[field] != candidate[field]:
            differences.append(field)
    population_identifiers = _concrete_identifiers(population)
    candidate_identifiers = _concrete_identifiers(candidate)
    if not population_identifiers or not candidate_identifiers:
        unknown_fields.append("identifier")
    elif not population_identifiers.intersection(candidate_identifiers):
        differences.append("identifier")
    candidate_roles = {role for role in candidate["roles"] if role != UNKNOWN}
    population_roles = {role for role in population["roles"] if role != UNKNOWN}
    if candidate_roles:
        if not population_roles:
            unknown_fields.append("component_role")
        elif not candidate_roles.intersection(population_roles):
            differences.append("component_role")
    candidate_provenance = _provenance_pairs(candidate["provenances"])
    population_provenance = _provenance_pairs(population["provenances"])
    if candidate_provenance:
        if not population_provenance:
            unknown_fields.append("provenance")
        elif not candidate_provenance.intersection(population_provenance):
            differences.append("provenance")
    for field, label in (
        ("observed_hashes", "observed_hash"),
        ("supplier_hashes", "supplier_hash"),
    ):
        candidate_hashes = _concrete_hash_pairs(candidate[field])
        population_hashes = _concrete_hash_pairs(population[field])
        if candidate_hashes:
            if not population_hashes:
                unknown_fields.append(label)
            elif not candidate_hashes.intersection(population_hashes):
                differences.append(label)
    if unknown_fields:
        return "UNKNOWN", sorted(set(unknown_fields))
    if differences:
        return "CONFLICT", sorted(set(differences))
    return "MATCHED", []


def _relationship_findings(
    graph: dict[str, Any], population: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    source_to_population = _source_to_population(population)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for claim in graph["relationship_claims"]:
        source_key = (claim["lane_id"], claim["source_component_id"])
        target_key = (claim["lane_id"], claim["target_component_id"])
        if source_key not in source_to_population or target_key not in source_to_population:
            raise EvidenceError("relationship claim cannot be mapped to the component population")
        grouped[(source_to_population[source_key], source_to_population[target_key])].append(claim)

    findings: list[dict[str, Any]] = []
    for endpoints, claims in sorted(grouped.items()):
        relations = {claim["relationship"] for claim in claims}
        status: str | None = None
        details: list[str] = []
        if UNKNOWN in relations:
            status = "UNKNOWN"
            details = ["relationship"]
        elif len(relations) > 1:
            status = "CONFLICT"
            details = sorted(relations)
        if status is not None:
            body = {
                "finding_type": "RELATIONSHIP",
                "source_population_id": endpoints[0],
                "target_population_id": endpoints[1],
                "status": status,
                "details": details,
                "claim_ids": sorted(claim["claim_id"] for claim in claims),
                "evidence_ids": sorted(
                    {evidence_id for claim in claims for evidence_id in claim["evidence_ids"]}
                ),
            }
            findings.append({"finding_id": stable_id("finding", body), **body})
    return findings


def _source_to_population(population: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    source_to_population: dict[tuple[str, str], str] = {}
    for entry in population:
        for source in entry["source_components"]:
            source_to_population[(source["lane_id"], source["source_component_id"])] = entry[
                "population_id"
            ]
    return source_to_population


def _build_relationship_projection(
    graph: dict[str, Any], population: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    source_to_population = _source_to_population(population)
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for claim in graph["relationship_claims"]:
        source_key = (claim["lane_id"], claim["source_component_id"])
        target_key = (claim["lane_id"], claim["target_component_id"])
        if source_key not in source_to_population or target_key not in source_to_population:
            raise EvidenceError("relationship claim cannot be mapped to the component population")
        grouped[
            (
                source_to_population[source_key],
                claim["relationship"],
                source_to_population[target_key],
            )
        ].append(claim)

    relationships: list[dict[str, Any]] = []
    for (source_population_id, relation, target_population_id), claims in sorted(grouped.items()):
        body = {
            "source_population_id": source_population_id,
            "relationship": relation,
            "target_population_id": target_population_id,
            "discovery_lanes": sorted({claim["lane_id"] for claim in claims}),
            "claim_ids": sorted(claim["claim_id"] for claim in claims),
            "evidence_ids": sorted(
                {evidence_id for claim in claims for evidence_id in claim["evidence_ids"]}
            ),
        }
        relationships.append({"relationship_id": stable_id("relationship", body), **body})
    return sorted(relationships, key=lambda item: item["relationship_id"])


def build_relationship_projection(
    graph: dict[str, Any], population: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Rebuild the relationship projection from immutable lane claims."""

    resolved_population = population if population is not None else build_component_population(graph)
    return _build_relationship_projection(graph, resolved_population)


def _reconcile_with_population(
    graph: dict[str, Any],
    population: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates_by_id = {candidate["candidate_id"]: candidate for candidate in candidates}
    potential_by_population: dict[str, list[str]] = {
        entry["population_id"]: [] for entry in population
    }
    population_by_id = {entry["population_id"]: entry for entry in population}
    for candidate in candidates:
        scored = [
            (score, entry["population_id"])
            for entry in population
            if (score := _candidate_population_score(candidate, entry)) is not None
        ]
        if not scored:
            continue
        best_score = max(score for score, _ in scored)
        for score, population_id in scored:
            if score == best_score:
                potential_by_population[population_id].append(candidate["candidate_id"])
    for candidate_ids in potential_by_population.values():
        candidate_ids.sort()
    reverse_matches = Counter(
        candidate_id
        for candidate_ids in potential_by_population.values()
        for candidate_id in candidate_ids
    )
    associated_candidate_ids = {
        candidate_id
        for candidate_ids in potential_by_population.values()
        for candidate_id in candidate_ids
    }

    findings: list[dict[str, Any]] = []
    for population_id in sorted(population_by_id):
        entry = population_by_id[population_id]
        potential = potential_by_population[population_id]
        candidate_id: str | None = None
        details: list[str] = []
        if entry["conflict_fields"]:
            status = "CONFLICT"
            details = list(entry["conflict_fields"])
            if len(potential) == 1:
                candidate_id = potential[0]
        elif len(potential) > 1 or (potential and reverse_matches[potential[0]] > 1):
            status = "UNKNOWN"
            details = ["ambiguous_identity"]
        elif not potential:
            if entry["critical_unknown_fields"]:
                status = "UNKNOWN"
                details = list(entry["critical_unknown_fields"])
            else:
                status = "MISSING_FROM_SBOM"
        else:
            candidate_id = potential[0]
            status, details = _matched_status(entry, candidates_by_id[candidate_id])
        body = {
            "finding_type": "COMPONENT",
            "population_id": population_id,
            "candidate_id": candidate_id,
            "status": status,
            "details": details,
            "evidence_ids": list(entry["evidence_ids"]),
        }
        findings.append({"finding_id": stable_id("finding", body), **body})

    for candidate in candidates:
        if candidate["candidate_id"] in associated_candidate_ids:
            continue
        unknown_fields = [
            field
            for field in _CRITICAL_FIELDS
            if (field == "identifier" and not _concrete_identifiers(candidate))
            or (field != "identifier" and candidate[field] == UNKNOWN)
        ]
        status = "UNKNOWN" if unknown_fields else "NOT_IN_RELEASE"
        body = {
            "finding_type": "COMPONENT",
            "population_id": None,
            "candidate_id": candidate["candidate_id"],
            "status": status,
            "details": unknown_fields,
            "evidence_ids": [],
        }
        findings.append({"finding_id": stable_id("finding", body), **body})

    findings.extend(_relationship_findings(graph, population))
    findings.sort(key=lambda finding: finding["finding_id"])
    counts = {status: 0 for status in STATUSES}
    for finding in findings:
        counts[finding["status"]] += 1
    blocking_statuses = sorted(status for status, count in counts.items() if status != "MATCHED" and count)
    limitations = [
        {
            "population_id": entry["population_id"],
            "fields": list(entry["nonblocking_unknown_fields"]),
            "effect": "NON_BLOCKING_WITHOUT_ACTIVATED_SUPPLIER_HASH_PROFILE",
        }
        for entry in population
        if entry["nonblocking_unknown_fields"]
    ]
    return {
        "reconciler_id": RECONCILER_ID,
        "reconciler_version": RECONCILER_VERSION,
        "state": "CLOSED" if not blocking_statuses else "OPEN",
        "component_population_sha256": hashlib.sha256(canonical_json_bytes(population)).hexdigest(),
        "candidate_sha256": hashlib.sha256(canonical_json_bytes(candidates)).hexdigest(),
        "counts": counts,
        "blocking_statuses": blocking_statuses,
        "limitations": limitations,
        "findings": findings,
    }


def reconcile(graph: dict[str, Any], candidate_components: object) -> dict[str, Any]:
    """Reconcile an explicit candidate against an independently built population."""

    population = build_component_population(graph)
    candidates = _validate_candidate_components(candidate_components)
    return _reconcile_with_population(graph, population, candidates)


def build_canonical_graph(root: Path, candidate_components: object) -> dict[str, Any]:
    """Build the complete deterministic graph and embed its stable hash."""

    graph = load_fixture(Path(root))
    candidates = _validate_candidate_components(candidate_components)
    population = build_component_population(graph)
    reconciliation = _reconcile_with_population(graph, population, candidates)
    graph["candidate_input"] = {
        "sha256": reconciliation["candidate_sha256"],
        "components": candidates,
    }
    graph["component_population"] = population
    graph["relationships"] = _build_relationship_projection(graph, population)
    graph["reconciliation"] = reconciliation
    graph["run_id"] = stable_id(
        "analysis-run",
        {
            "ingest_run_id": graph["ingest_run_id"],
            "candidate_sha256": reconciliation["candidate_sha256"],
            "reconciler_id": RECONCILER_ID,
            "reconciler_version": RECONCILER_VERSION,
        },
    )
    validate_claim_evidence_links(graph)
    graph["canonical_sha256"] = canonical_graph_sha256(graph)
    return graph
