"""Strict adapter for project-owned synthetic SBOM candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .evidence import EvidenceError, read_json_object
from .resources import resource_path


CANDIDATE_PATH = "candidate-sbom.json"


def default_candidate_schema() -> Path:
    return resource_path("schemas/synthetic-candidate.schema.json")


def _schema_errors(document: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    return [
        "$" + "".join(f"[{item}]" if isinstance(item, int) else f".{item}" for item in error.absolute_path)
        + ": "
        + error.message
        for error in errors
    ]


def _primary_identifiers(items: list[dict[str, Any]]) -> list[str]:
    values = sorted(
        {
            item["value"]
            for item in items
            if item["type"] in {"PURL", "SYNTHETIC_URN"}
        },
        key=lambda value: value.encode("utf-8"),
    )
    return values or ["UNKNOWN"]


def _enrichment(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "roles": sorted(
            {item["value"] for item in items if item["type"] == "COMPONENT_ROLE"}
        ),
        "provenances": sorted(
            {item["value"] for item in items if item["type"] == "PROVENANCE"}
        ),
        "observed_hashes": sorted(
            {
                (item["algorithm"], item["value"])
                for item in items
                if item["type"] == "OBSERVED_HASH"
            }
        ),
        "supplier_hashes": sorted(
            {
                (item["algorithm"] or "UNKNOWN", item["value"])
                for item in items
                if item["type"] == "SUPPLIER_HASH"
            }
        ),
    }


def load_candidate(root: Path) -> dict[str, Any]:
    """Load, schema-check, and release-bind one synthetic candidate."""

    root = Path(root)
    document, identity = read_json_object(root, CANDIDATE_PATH)
    schema_root = default_candidate_schema().parent
    schema, _ = read_json_object(schema_root, default_candidate_schema().name)
    errors = _schema_errors(document, schema)
    if errors:
        raise EvidenceError("candidate schema validation failed: " + " | ".join(errors[:20]))

    release, _ = read_json_object(root, "release.json")
    required_bindings = {
        "classification": release.get("classification"),
        "release_id": release.get("release_id"),
        "producer": release.get("manufacturer"),
        "name": release.get("product"),
        "version": release.get("product_version"),
        "artifact_sha256": release.get("artifact_sha256"),
    }
    for field, expected in required_bindings.items():
        if document.get(field) != expected:
            raise EvidenceError(f"candidate.{field} does not match release.json")
    if document["manufacturer_release_authority"] is not False or document["cab_conclusion"] is not False:
        raise EvidenceError("synthetic candidate cannot carry manufacturer or CAB authority")
    if document["product_conformity_status"] != "NO_PRODUCT_CONFORMITY_STATUS":
        raise EvidenceError("synthetic candidate cannot carry product conformity status")

    root_items = document["identifiers"]
    components: list[dict[str, Any]] = [
        {
            "candidate_id": "orion-root",
            "producer": document["producer"],
            "name": document["name"],
            "version": document["version"],
            "identifiers": _primary_identifiers(root_items),
            "roles": ["ROOT_PRODUCT"],
            "provenances": [],
            "observed_hashes": [("SHA-256", document["artifact_sha256"])],
            "supplier_hashes": [],
        }
    ]
    for component in document["components"]:
        items = component["identifiers"]
        enriched = _enrichment(items)
        components.append(
            {
                "candidate_id": component["candidate_id"],
                "producer": component["producer"] if component["producer"] is not None else "UNKNOWN",
                "name": component["name"] if component["name"] is not None else "UNKNOWN",
                "version": component["version"] if component["version"] is not None else "UNKNOWN",
                "identifiers": _primary_identifiers(items),
                **enriched,
            }
        )
    components.sort(key=lambda item: item["candidate_id"].encode("utf-8"))
    relationships = sorted(
        [
            {
                "source_candidate_id": item["from"],
                "relationship": item["type"],
                "target_candidate_id": item["to"],
            }
            for item in document["relationships"]
        ],
        key=lambda item: (
            item["source_candidate_id"].encode("utf-8"),
            item["relationship"].encode("utf-8"),
            item["target_candidate_id"].encode("utf-8"),
        ),
    )
    known_ids = {component["candidate_id"] for component in components}
    for relationship in relationships:
        if relationship["source_candidate_id"] not in known_ids or relationship["target_candidate_id"] not in known_ids:
            raise EvidenceError("candidate relationship references an unknown component")
    return {
        "document": document,
        "input_identity": identity,
        "components": components,
        "relationships": relationships,
    }
