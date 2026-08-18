"""Deterministic primitives for the M3A self-hosted SBOM evidence profile.

This module intentionally stops before process execution and release authority.
It validates one CycloneDX document at a time, binds it to one isolated scan
profile, and compares observations without constructing a cross-profile
component population.  A caller may execute the returned Syft command contract,
but this module never scans a live source tree and never performs network I/O.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping

from .evidence import EvidenceError, stable_id
from .manifest import canonical_json_bytes


class SelfTestError(EvidenceError):
    """Raised when M3A evidence cannot be accepted without weakening a gate."""


SCHEMA_VERSION = "1.0"
PROJECTION_VERSION = "1.0"
CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
GENERATOR_STATUS = "GENERATOR_OUTPUT_CANDIDATE"
RELEASE_STATUS = "NOT_RELEASED"
PRODUCT_STATUS = "NO_PRODUCT_CONFORMITY_STATUS"
MANUFACTURER_STATUS = "NOT_PROVIDED"
MILESTONE_SCOPE = "M3A_NOT_YOCTO_M3B"

PROFILE_DOMAINS = {
    "SOURCE_DIRECTORY": "SOURCE_DECLARATION",
    "OCI_ARCHIVE": "BUILT_OCI_ARTIFACT",
    "PORTABLE_RUNTIME": "PORTABLE_RUNTIME_OBSERVATION",
}
PROFILE_TARGETS = {
    "SOURCE_DIRECTORY": "dir",
    "OCI_ARCHIVE": "docker-archive",
    "PORTABLE_RUNTIME": "dir",
}
REQUIRED_BLINDSPOTS = frozenset(
    {
        "NO_CUSTOMER_OR_MANUFACTURER_CONTEXT",
        "NO_CRA_OR_PRE7_CONFORMITY_CLAIM",
        "NOT_YOCTO_M3B",
    }
)
OUTPUT_FORMATS = (
    ("syft-json", "raw.syft.json"),
    ("cyclonedx-json", "raw.cyclonedx.json"),
    ("spdx-json", "raw.spdx.json"),
)
SANDBOX_NETWORK_DENY_PROFILE = "(version 1) (allow default) (deny network*)"

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_COMPONENTS = 100_000
MAX_TEXT = 4096
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+~-]{0,255}")
_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
HASH_HEX_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}
CYCLONEDX_COMPONENT_TYPES = frozenset(
    {
        "application",
        "container",
        "cryptographic-asset",
        "data",
        "device",
        "device-driver",
        "file",
        "firmware",
        "framework",
        "library",
        "machine-learning-model",
        "operating-system",
        "platform",
    }
)

_PROFILE_KEYS = {
    "schema_version",
    "profile_id",
    "classification",
    "profile_kind",
    "independence_domain",
    "subject",
    "scanner",
    "scan",
    "limits",
    "blindspots",
}
_SUBJECT_KEYS = {"comparison_namespace", "product_name", "declared_version"}
_SCANNER_KEYS = {"name", "version", "binary_sha256", "config_sha256"}
_SCAN_KEYS = {"target_kind", "target_label"}
_LIMIT_KEYS = {"timeout_seconds", "max_json_bytes", "max_components"}
_INPUT_IDENTITY_KEYS = {"root_id", "sha256", "file_count", "total_bytes"}
_PROJECTION_KEYS = {
    "projection_version",
    "document",
    "metadata",
    "components",
    "services",
    "dependencies",
    "semantic_sha256",
    "source_sha256",
}
_PROJECTED_COMPONENT_KEYS = {
    "bom_ref", "type", "group", "name", "version", "purl", "cpe", "hashes"
}
_PROJECTED_SERVICE_KEYS = {"bom_ref", "group", "name", "version"}
_PROJECTED_TOOL_KEYS = {"vendor", "name", "version", "hashes"}
_PROJECTED_HASH_KEYS = {"algorithm", "content"}
_DEPENDENCY_KEYS = {"ref", "depends_on", "provides"}
_OBSERVATION_KEYS = {
    "schema_version",
    "classification",
    "generator_output_status",
    "release_status",
    "product_conformity_status",
    "manufacturer_approval_status",
    "milestone_scope",
    "profile_id",
    "profile_kind",
    "independence_domain",
    "subject",
    "scan_contract",
    "blindspots",
    "input_identity",
    "scanner_identity",
    "cyclonedx_evidence",
    "canonical_sha256",
    "run_id",
}


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SelfTestError(f"{label} must be an object")
    return value


def _exact(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual_set = set(value)
    if actual_set != expected_set:
        raise SelfTestError(
            f"{label} fields mismatch; missing={sorted(expected_set - actual_set)}, "
            f"extra={sorted(actual_set - expected_set)}"
        )


def _text(value: object, label: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SelfTestError(f"{label} must be non-empty bounded text")
    if any(ord(character) < 0x20 for character in value):
        raise SelfTestError(f"{label} contains control characters")
    return value


def _optional_text(value: object, label: str, *, maximum: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=maximum)


def _safe_id(value: object, label: str) -> str:
    result = _text(value, label, maximum=256)
    if not _SAFE_ID_RE.fullmatch(result):
        raise SelfTestError(f"{label} is not a safe identifier")
    return result


def _sha256(value: object, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not _SHA256_RE.fullmatch(result):
        raise SelfTestError(f"{label} must be a lowercase SHA-256")
    return result


def _bounded_int(value: object, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise SelfTestError(f"{label} must be an integer in [{low}, {high}]")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise SelfTestError(f"{label} must be a{' non-empty' if not allow_empty else ''} string array")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        text = _text(item, f"{label}[{index}]")
        if text in seen:
            raise SelfTestError(f"{label} must not contain duplicates")
        seen.add(text)
        result.append(text)
    return result


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SelfTestError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SelfTestError(f"non-standard JSON constant is forbidden: {value}")


def _strict_json(payload: bytes, label: str, *, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if len(payload) > maximum:
        raise SelfTestError(f"{label} exceeds the JSON byte limit")
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except SelfTestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelfTestError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    return _mapping(value, label)


def validate_selftest_profile(value: object) -> dict[str, Any]:
    """Validate and normalize one isolated M3A scan profile."""

    profile = _mapping(value, "profile")
    _exact(profile, _PROFILE_KEYS, "profile")
    if profile["schema_version"] != SCHEMA_VERSION:
        raise SelfTestError("profile.schema_version is unsupported")
    if profile["classification"] != CLASSIFICATION:
        raise SelfTestError("profile.classification cannot grant customer-evidence status")
    profile_kind = _text(profile["profile_kind"], "profile.profile_kind", maximum=32)
    if profile_kind not in PROFILE_DOMAINS:
        raise SelfTestError("profile.profile_kind is unsupported")
    if profile["independence_domain"] != PROFILE_DOMAINS[profile_kind]:
        raise SelfTestError("profile independence domain is inconsistent with profile kind")

    subject = _mapping(profile["subject"], "profile.subject")
    _exact(subject, _SUBJECT_KEYS, "profile.subject")
    normalized_subject = {
        "comparison_namespace": _safe_id(
            subject["comparison_namespace"], "profile.subject.comparison_namespace"
        ),
        "product_name": _text(subject["product_name"], "profile.subject.product_name"),
        "declared_version": _text(
            subject["declared_version"], "profile.subject.declared_version"
        ),
    }

    scanner = _mapping(profile["scanner"], "profile.scanner")
    _exact(scanner, _SCANNER_KEYS, "profile.scanner")
    if scanner["name"] != "syft" or scanner["version"] != "1.50.0":
        raise SelfTestError("M3A requires the pinned Syft 1.50.0 scanner")
    normalized_scanner = {
        "name": "syft",
        "version": "1.50.0",
        "binary_sha256": _sha256(scanner["binary_sha256"], "profile.scanner.binary_sha256"),
        "config_sha256": _sha256(scanner["config_sha256"], "profile.scanner.config_sha256"),
    }

    scan = _mapping(profile["scan"], "profile.scan")
    _exact(scan, _SCAN_KEYS, "profile.scan")
    target_kind = _text(scan["target_kind"], "profile.scan.target_kind", maximum=32)
    if target_kind != PROFILE_TARGETS[profile_kind]:
        raise SelfTestError("scan target kind is inconsistent with the isolated profile")
    normalized_scan = {
        "target_kind": target_kind,
        "target_label": _safe_id(scan["target_label"], "profile.scan.target_label"),
    }

    limits = _mapping(profile["limits"], "profile.limits")
    _exact(limits, _LIMIT_KEYS, "profile.limits")
    normalized_limits = {
        "timeout_seconds": _bounded_int(
            limits["timeout_seconds"], "profile.limits.timeout_seconds", 1, 3600
        ),
        "max_json_bytes": _bounded_int(
            limits["max_json_bytes"], "profile.limits.max_json_bytes", 1024, MAX_JSON_BYTES
        ),
        "max_components": _bounded_int(
            limits["max_components"], "profile.limits.max_components", 1, MAX_COMPONENTS
        ),
    }
    blindspots = _string_list(profile["blindspots"], "profile.blindspots")
    if not REQUIRED_BLINDSPOTS.issubset(blindspots):
        raise SelfTestError("profile.blindspots omits a mandatory M3A boundary")

    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": _safe_id(profile["profile_id"], "profile.profile_id"),
        "classification": CLASSIFICATION,
        "profile_kind": profile_kind,
        "independence_domain": PROFILE_DOMAINS[profile_kind],
        "subject": normalized_subject,
        "scanner": normalized_scanner,
        "scan": normalized_scan,
        "limits": normalized_limits,
        "blindspots": sorted(blindspots, key=lambda item: item.encode("utf-8")),
    }


def load_selftest_profile(path: Path | str) -> dict[str, Any]:
    """Load one bounded single-link profile with duplicate-key rejection."""

    source = Path(path)
    try:
        info = source.lstat()
    except OSError as exc:
        raise SelfTestError(f"cannot access self-test profile: {exc}") from exc
    if source.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SelfTestError("self-test profile must be a single-link regular file")
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise SelfTestError(f"cannot read self-test profile: {exc}") from exc
    return validate_selftest_profile(_strict_json(payload, "self-test profile", maximum=8 * 1024**2))


def _hashes(value: object, label: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SelfTestError(f"{label} must be an array")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        entry = _mapping(item, f"{label}[{index}]")
        algorithm = _text(entry.get("alg"), f"{label}[{index}].alg", maximum=32)
        content = _text(entry.get("content"), f"{label}[{index}].content", maximum=256)
        if algorithm not in HASH_HEX_LENGTHS:
            raise SelfTestError(f"{label}[{index}] uses an unsupported CycloneDX hash algorithm")
        if not _HEX_RE.fullmatch(content) or len(content) != HASH_HEX_LENGTHS[algorithm]:
            raise SelfTestError(
                f"{label}[{index}].content length does not match its CycloneDX hash algorithm"
            )
        pair = (algorithm, content.lower())
        if pair in seen:
            raise SelfTestError(f"{label} contains a duplicate hash")
        seen.add(pair)
        result.append({"algorithm": algorithm, "content": content.lower()})
    return sorted(result, key=lambda item: (item["algorithm"].encode(), item["content"].encode()))


def _component_projection(
    value: object,
    label: str,
    *,
    allow_missing_bom_ref: bool = False,
) -> dict[str, Any]:
    component = _mapping(value, label)
    bom_ref = _optional_text(component.get("bom-ref"), f"{label}.bom-ref")
    if bom_ref is None and not allow_missing_bom_ref:
        raise SelfTestError(f"{label}.bom-ref must be non-empty bounded text")
    name = _text(component.get("name"), f"{label}.name")
    component_type = _text(component.get("type"), f"{label}.type", maximum=64)
    if component_type not in CYCLONEDX_COMPONENT_TYPES:
        raise SelfTestError(f"{label}.type is not a recognized CycloneDX component type")
    purl = _optional_text(component.get("purl"), f"{label}.purl")
    if purl is not None and (
        not purl.startswith("pkg:") or any(character.isspace() for character in purl)
    ):
        raise SelfTestError(f"{label}.purl is outside the bounded package-url profile")
    cpe = _optional_text(component.get("cpe"), f"{label}.cpe")
    if cpe is not None and (
        not (cpe.startswith("cpe:2.3:") or cpe.startswith("cpe:/"))
        or any(character.isspace() for character in cpe)
    ):
        raise SelfTestError(f"{label}.cpe is outside the bounded CPE 2.2/2.3 profile")
    return {
        "bom_ref": bom_ref,
        "type": component_type,
        "group": _optional_text(component.get("group"), f"{label}.group"),
        "name": name,
        "version": _optional_text(component.get("version"), f"{label}.version"),
        "purl": purl,
        "cpe": cpe,
        "hashes": _hashes(component.get("hashes"), f"{label}.hashes"),
    }


def _service_projection(value: object, label: str) -> dict[str, Any]:
    service = _mapping(value, label)
    return {
        "bom_ref": _text(service.get("bom-ref"), f"{label}.bom-ref"),
        "group": _optional_text(service.get("group"), f"{label}.group"),
        "name": _text(service.get("name"), f"{label}.name"),
        "version": _optional_text(service.get("version"), f"{label}.version"),
    }


def _tool_projection(value: object, label: str) -> dict[str, Any]:
    tool = _mapping(value, label)
    return {
        "vendor": _optional_text(tool.get("vendor"), f"{label}.vendor"),
        "name": _text(tool.get("name"), f"{label}.name"),
        "version": _optional_text(tool.get("version"), f"{label}.version"),
        "hashes": _hashes(tool.get("hashes"), f"{label}.hashes"),
    }


def _walk_components(
    raw_components: object,
    label: str,
    *,
    projections: list[dict[str, Any]],
    references: set[str],
    maximum: int,
) -> None:
    if raw_components is None:
        return
    if not isinstance(raw_components, list):
        raise SelfTestError(f"{label} must be an array")
    stack: list[tuple[object, str, int]] = [
        (item, f"{label}[{index}]", 0) for index, item in reversed(list(enumerate(raw_components)))
    ]
    while stack:
        raw, item_label, depth = stack.pop()
        if depth > 32:
            raise SelfTestError("CycloneDX component nesting exceeds the depth limit")
        projection = _component_projection(raw, item_label)
        if projection["bom_ref"] in references:
            raise SelfTestError(f"duplicate bom-ref is forbidden: {projection['bom_ref']}")
        references.add(projection["bom_ref"])
        projections.append(projection)
        if len(projections) > maximum:
            raise SelfTestError("CycloneDX component count exceeds the profile limit")
        children = _mapping(raw, item_label).get("components")
        if children is not None:
            if not isinstance(children, list):
                raise SelfTestError(f"{item_label}.components must be an array")
            for index, child in reversed(list(enumerate(children))):
                stack.append((child, f"{item_label}.components[{index}]", depth + 1))


def _metadata_tools(value: object, references: set[str]) -> dict[str, Any]:
    if value is None:
        return {"legacy_tools": [], "components": [], "services": []}
    if isinstance(value, list):
        return {
            "legacy_tools": sorted(
                [_tool_projection(item, f"metadata.tools[{index}]") for index, item in enumerate(value)],
                key=lambda item: canonical_json_bytes(item),
            ),
            "components": [],
            "services": [],
        }
    tools = _mapping(value, "metadata.tools")
    components: list[dict[str, Any]] = []
    raw_components = tools.get("components", [])
    if not isinstance(raw_components, list):
        raise SelfTestError("metadata.tools.components must be an array")
    for index, raw in enumerate(raw_components):
        projection = _component_projection(
            raw,
            f"metadata.tools.components[{index}]",
            allow_missing_bom_ref=True,
        )
        if projection["bom_ref"] is not None:
            if projection["bom_ref"] in references:
                raise SelfTestError(f"duplicate bom-ref is forbidden: {projection['bom_ref']}")
            references.add(projection["bom_ref"])
        components.append(projection)
    services: list[dict[str, Any]] = []
    raw_services = tools.get("services", [])
    if not isinstance(raw_services, list):
        raise SelfTestError("metadata.tools.services must be an array")
    for index, raw in enumerate(raw_services):
        projection = _service_projection(raw, f"metadata.tools.services[{index}]")
        if projection["bom_ref"] in references:
            raise SelfTestError(f"duplicate bom-ref is forbidden: {projection['bom_ref']}")
        references.add(projection["bom_ref"])
        services.append(projection)
    return {
        "legacy_tools": [],
        "components": sorted(components, key=canonical_json_bytes),
        "services": sorted(services, key=lambda item: item["bom_ref"].encode()),
    }


def validate_cyclonedx(value: object, *, max_components: int = MAX_COMPONENTS) -> dict[str, Any]:
    """Create a strict, deterministic evidence projection of CycloneDX JSON.

    The parser allows CycloneDX extension fields but validates all fields used by
    M3A.  All component/service references are globally unique; every dependency
    endpoint resolves; and repeated dependency edges are rejected.
    """

    document = _mapping(value, "CycloneDX document")
    if document.get("bomFormat") != "CycloneDX":
        raise SelfTestError("CycloneDX document.bomFormat must be CycloneDX")
    spec_version = _text(document.get("specVersion"), "CycloneDX document.specVersion", maximum=16)
    if spec_version not in {"1.4", "1.5", "1.6", "1.7"}:
        raise SelfTestError("CycloneDX specVersion is unsupported")
    document_version = _bounded_int(document.get("version"), "CycloneDX document.version", 1, 2**31 - 1)
    serial_number = _optional_text(document.get("serialNumber"), "CycloneDX document.serialNumber")
    maximum = _bounded_int(max_components, "max_components", 1, MAX_COMPONENTS)

    metadata = _mapping(document.get("metadata"), "CycloneDX document.metadata")
    root_raw = _mapping(metadata.get("component"), "CycloneDX document.metadata.component")
    root_component = _component_projection(root_raw, "CycloneDX document.metadata.component")
    references = {root_component["bom_ref"]}
    components: list[dict[str, Any]] = []
    root_children = root_raw.get("components")
    _walk_components(
        root_children,
        "CycloneDX document.metadata.component.components",
        projections=components,
        references=references,
        maximum=maximum,
    )
    _walk_components(
        document.get("components"),
        "CycloneDX document.components",
        projections=components,
        references=references,
        maximum=maximum,
    )

    services: list[dict[str, Any]] = []
    raw_services = document.get("services")
    if raw_services is None:
        raw_services = []
    if not isinstance(raw_services, list):
        raise SelfTestError("CycloneDX document.services must be an array")
    for index, raw in enumerate(raw_services):
        service = _service_projection(raw, f"CycloneDX document.services[{index}]")
        if service["bom_ref"] in references:
            raise SelfTestError(f"duplicate bom-ref is forbidden: {service['bom_ref']}")
        references.add(service["bom_ref"])
        services.append(service)

    tools = _metadata_tools(metadata.get("tools"), references)
    dependency_references = references - {
        item["bom_ref"] for item in tools["components"] + tools["services"]
    }
    raw_dependencies = document.get("dependencies")
    if raw_dependencies is None:
        raw_dependencies = []
    if not isinstance(raw_dependencies, list):
        raise SelfTestError("CycloneDX document.dependencies must be an array")
    dependencies: list[dict[str, Any]] = []
    seen_dependency_refs: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_dependencies):
        label = f"CycloneDX document.dependencies[{index}]"
        dependency = _mapping(raw, label)
        reference = _text(dependency.get("ref"), f"{label}.ref")
        if reference in seen_dependency_refs:
            raise SelfTestError(f"duplicate dependency ref is forbidden: {reference}")
        seen_dependency_refs.add(reference)
        if reference not in dependency_references:
            raise SelfTestError(f"dangling dependency ref is forbidden: {reference}")
        normalized: dict[str, Any] = {"ref": reference, "depends_on": [], "provides": []}
        for source_key, target_key in (("dependsOn", "depends_on"), ("provides", "provides")):
            values = dependency.get(source_key, [])
            if not isinstance(values, list):
                raise SelfTestError(f"{label}.{source_key} must be an array")
            local_seen: set[str] = set()
            for target_index, target in enumerate(values):
                endpoint = _text(target, f"{label}.{source_key}[{target_index}]")
                if endpoint not in dependency_references:
                    raise SelfTestError(f"dangling dependency endpoint is forbidden: {endpoint}")
                if endpoint == reference:
                    raise SelfTestError(f"self dependency edge is forbidden: {reference}")
                edge = (reference, source_key, endpoint)
                if endpoint in local_seen or edge in seen_edges:
                    raise SelfTestError(
                        f"duplicate dependency edge is forbidden: {reference} {source_key} {endpoint}"
                    )
                local_seen.add(endpoint)
                seen_edges.add(edge)
                normalized[target_key].append(endpoint)
            normalized[target_key].sort(key=lambda item: item.encode("utf-8"))
        dependencies.append(normalized)

    projection_body = {
        "projection_version": PROJECTION_VERSION,
        "document": {
            "bom_format": "CycloneDX",
            "spec_version": spec_version,
            "document_version": document_version,
            "serial_number": serial_number,
        },
        "metadata": {"component": root_component, "tools": tools},
        "components": sorted(components, key=lambda item: item["bom_ref"].encode("utf-8")),
        "services": sorted(services, key=lambda item: item["bom_ref"].encode("utf-8")),
        "dependencies": sorted(dependencies, key=lambda item: item["ref"].encode("utf-8")),
    }
    semantic_body = copy.deepcopy(projection_body)
    # Syft intentionally generates a fresh CycloneDX UUID (and timestamp,
    # which is not projected) on each invocation.  Preserve that UUID in the
    # raw-bound projection, but exclude it from the component/dependency
    # semantic identity so identical inputs have an identical semantic hash.
    semantic_body["document"]["serial_number"] = None
    projection_body["semantic_sha256"] = hashlib.sha256(
        canonical_json_bytes(semantic_body)
    ).hexdigest()
    projection_body["source_sha256"] = None
    return projection_body


def parse_cyclonedx_json(payload: bytes | str, *, max_components: int = MAX_COMPONENTS) -> dict[str, Any]:
    """Parse strict UTF-8 CycloneDX JSON and retain its raw byte identity."""

    encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
    if not isinstance(encoded, bytes):
        raise SelfTestError("CycloneDX payload must be bytes or text")
    document = _strict_json(encoded, "CycloneDX document")
    projection = validate_cyclonedx(document, max_components=max_components)
    projection["source_sha256"] = hashlib.sha256(encoded).hexdigest()
    return projection


def load_cyclonedx(
    path: Path | str,
    *,
    expected_sha256: str | None = None,
    max_json_bytes: int = MAX_JSON_BYTES,
    max_components: int = MAX_COMPONENTS,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read one immutable CycloneDX file and return projection plus file identity."""

    source = Path(path)
    try:
        info = source.lstat()
    except OSError as exc:
        raise SelfTestError(f"cannot access CycloneDX input: {exc}") from exc
    if source.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SelfTestError("CycloneDX input must be a single-link regular file")
    maximum = _bounded_int(max_json_bytes, "max_json_bytes", 1024, MAX_JSON_BYTES)
    if info.st_size > maximum:
        raise SelfTestError("CycloneDX input exceeds the JSON byte limit")
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise SelfTestError(f"cannot read CycloneDX input: {exc}") from exc
    actual = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and actual != _sha256(expected_sha256, "expected_sha256"):
        raise SelfTestError(
            f"CycloneDX input SHA-256 mismatch; expected {expected_sha256}, got {actual}"
        )
    projection = parse_cyclonedx_json(payload, max_components=max_components)
    return projection, {"sha256": actual, "size": len(payload)}


def _absolute_path(value: Path | str, label: str) -> str:
    text = str(value)
    if not text or any(ord(character) < 0x20 for character in text):
        raise SelfTestError(f"{label} must be a non-empty path without control characters")
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise SelfTestError(f"{label} must be an absolute normalized path")
    return path.as_posix()


def build_syft_command(
    scanner: Path | str,
    target_kind: str,
    target: Path | str,
    output_path: Path | str,
    *,
    config_path: Path | str | None = None,
    sandbox_exec: Path | str | None = None,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Build one explicit, offline Syft multi-format command contract.

    ``output_path`` is a directory.  The caller owns directory creation and
    process timeout enforcement.  The returned environment values must overlay
    the caller's minimal environment.  No update check or enrichment argument is
    present; a supplied macOS ``sandbox-exec`` path adds an OS-level network deny.
    """

    scanner_path = _absolute_path(scanner, "scanner")
    normalized_target = _text(target_kind, "target_kind", maximum=32)
    aliases = {
        "SOURCE_DIRECTORY": "dir",
        "PORTABLE_RUNTIME": "dir",
        "OCI_ARCHIVE": "docker-archive",
        "dir": "dir",
        "docker-archive": "docker-archive",
    }
    if normalized_target not in aliases:
        raise SelfTestError("target_kind must resolve to dir or docker-archive")
    scheme = aliases[normalized_target]
    target_path = _absolute_path(target, "target")
    output_root = _absolute_path(output_path, "output_path")
    timeout = _bounded_int(timeout_seconds, "timeout_seconds", 1, 3600)

    outputs = {
        format_name: f"{output_root}/{filename}" for format_name, filename in OUTPUT_FORMATS
    }
    argv = [scanner_path, "scan", f"{scheme}:{target_path}"]
    if config_path is not None:
        argv.extend(["--config", _absolute_path(config_path, "config_path")])
    for format_name, _ in OUTPUT_FORMATS:
        argv.extend(["--output", f"{format_name}={outputs[format_name]}"])
    if any("enrich" in argument.lower() for argument in argv):
        raise SelfTestError("Syft enrichment is forbidden in the M3A command")

    network_policy = "CALLER_MUST_PROVIDE_EQUIVALENT_NETWORK_DENY"
    if sandbox_exec is not None:
        sandbox_path = _absolute_path(sandbox_exec, "sandbox_exec")
        argv = [sandbox_path, "-p", SANDBOX_NETWORK_DENY_PROFILE, *argv]
        network_policy = "MACOS_SANDBOX_EXEC_DENY_NETWORK"
    return {
        "argv": argv,
        "environment_overrides": {
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
        },
        "timeout_seconds": timeout,
        "timeout_enforced_by": "CALLER",
        "network_policy": network_policy,
        "outputs": outputs,
    }


def _normalize_input_identity(value: object) -> dict[str, Any]:
    identity = _mapping(value, "input_identity")
    _exact(identity, _INPUT_IDENTITY_KEYS, "input_identity")
    return {
        "root_id": _safe_id(identity["root_id"], "input_identity.root_id"),
        "sha256": _sha256(identity["sha256"], "input_identity.sha256"),
        "file_count": _bounded_int(identity["file_count"], "input_identity.file_count", 1, 10_000_000),
        "total_bytes": _bounded_int(identity["total_bytes"], "input_identity.total_bytes", 1, 2**63 - 1),
    }


def _normalize_scanner_identity(value: object) -> dict[str, str]:
    scanner = _mapping(value, "scanner_identity")
    _exact(scanner, _SCANNER_KEYS, "scanner_identity")
    return {
        "name": _text(scanner["name"], "scanner_identity.name", maximum=64),
        "version": _text(scanner["version"], "scanner_identity.version", maximum=64),
        "binary_sha256": _sha256(scanner["binary_sha256"], "scanner_identity.binary_sha256"),
        "config_sha256": _sha256(scanner["config_sha256"], "scanner_identity.config_sha256"),
    }


def _validate_projected_hashes(value: object, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise SelfTestError(f"{label} must be an array")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _mapping(raw, item_label)
        _exact(item, _PROJECTED_HASH_KEYS, item_label)
        algorithm = _text(item["algorithm"], f"{item_label}.algorithm", maximum=32)
        content = _text(item["content"], f"{item_label}.content", maximum=256)
        if algorithm not in HASH_HEX_LENGTHS:
            raise SelfTestError(f"{item_label}.algorithm is unsupported")
        if (
            not _HEX_RE.fullmatch(content)
            or len(content) != HASH_HEX_LENGTHS[algorithm]
            or content != content.lower()
        ):
            raise SelfTestError(
                f"{item_label}.content must be lowercase hexadecimal of the algorithm length"
            )
        pair = (algorithm, content)
        if pair in seen:
            raise SelfTestError(f"{label} contains a duplicate hash")
        seen.add(pair)
        normalized.append({"algorithm": algorithm, "content": content})
    expected = sorted(normalized, key=lambda item: (item["algorithm"].encode(), item["content"].encode()))
    if normalized != expected:
        raise SelfTestError(f"{label} is not in canonical order")
    return normalized


def _validate_projected_component(value: object, label: str) -> dict[str, Any]:
    component = _mapping(value, label)
    _exact(component, _PROJECTED_COMPONENT_KEYS, label)
    return {
        "bom_ref": _text(component["bom_ref"], f"{label}.bom_ref"),
        "type": _text(component["type"], f"{label}.type", maximum=64),
        "group": _optional_text(component["group"], f"{label}.group"),
        "name": _text(component["name"], f"{label}.name"),
        "version": _optional_text(component["version"], f"{label}.version"),
        "purl": _optional_text(component["purl"], f"{label}.purl"),
        "cpe": _optional_text(component["cpe"], f"{label}.cpe"),
        "hashes": _validate_projected_hashes(component["hashes"], f"{label}.hashes"),
    }


def _validate_projected_tool_component(value: object, label: str) -> dict[str, Any]:
    component = _mapping(value, label)
    _exact(component, _PROJECTED_COMPONENT_KEYS, label)
    return {
        "bom_ref": _optional_text(component["bom_ref"], f"{label}.bom_ref"),
        "type": _text(component["type"], f"{label}.type", maximum=64),
        "group": _optional_text(component["group"], f"{label}.group"),
        "name": _text(component["name"], f"{label}.name"),
        "version": _optional_text(component["version"], f"{label}.version"),
        "purl": _optional_text(component["purl"], f"{label}.purl"),
        "cpe": _optional_text(component["cpe"], f"{label}.cpe"),
        "hashes": _validate_projected_hashes(component["hashes"], f"{label}.hashes"),
    }


def _validate_projected_service(value: object, label: str) -> dict[str, Any]:
    service = _mapping(value, label)
    _exact(service, _PROJECTED_SERVICE_KEYS, label)
    return {
        "bom_ref": _text(service["bom_ref"], f"{label}.bom_ref"),
        "group": _optional_text(service["group"], f"{label}.group"),
        "name": _text(service["name"], f"{label}.name"),
        "version": _optional_text(service["version"], f"{label}.version"),
    }


def _validate_projection(value: object) -> dict[str, Any]:
    projection = _mapping(value, "CycloneDX projection")
    _exact(projection, _PROJECTION_KEYS, "CycloneDX projection")
    if projection["projection_version"] != PROJECTION_VERSION:
        raise SelfTestError("CycloneDX projection version is unsupported")

    document = _mapping(projection["document"], "CycloneDX projection.document")
    _exact(
        document,
        {"bom_format", "spec_version", "document_version", "serial_number"},
        "CycloneDX projection.document",
    )
    if document["bom_format"] != "CycloneDX" or document["spec_version"] not in {
        "1.4", "1.5", "1.6", "1.7"
    }:
        raise SelfTestError("CycloneDX projection document identity is unsupported")
    _bounded_int(document["document_version"], "CycloneDX projection.document.document_version", 1, 2**31 - 1)
    _optional_text(document["serial_number"], "CycloneDX projection.document.serial_number")

    metadata = _mapping(projection["metadata"], "CycloneDX projection.metadata")
    _exact(metadata, {"component", "tools"}, "CycloneDX projection.metadata")
    root = _validate_projected_component(metadata["component"], "CycloneDX projection.metadata.component")
    references = {root["bom_ref"]}
    tools = _mapping(metadata["tools"], "CycloneDX projection.metadata.tools")
    _exact(tools, {"legacy_tools", "components", "services"}, "CycloneDX projection.metadata.tools")
    legacy_tools = tools["legacy_tools"]
    if not isinstance(legacy_tools, list):
        raise SelfTestError("CycloneDX projection.metadata.tools.legacy_tools must be an array")
    for index, raw in enumerate(legacy_tools):
        label = f"CycloneDX projection.metadata.tools.legacy_tools[{index}]"
        tool = _mapping(raw, label)
        _exact(tool, _PROJECTED_TOOL_KEYS, label)
        _optional_text(tool["vendor"], f"{label}.vendor")
        _text(tool["name"], f"{label}.name")
        _optional_text(tool["version"], f"{label}.version")
        _validate_projected_hashes(tool["hashes"], f"{label}.hashes")

    tool_references: set[str] = set()
    for collection_name, validator in (
        ("components", _validate_projected_tool_component),
        ("services", _validate_projected_service),
    ):
        collection = tools[collection_name]
        if not isinstance(collection, list):
            raise SelfTestError(f"CycloneDX projection.metadata.tools.{collection_name} must be an array")
        previous: bytes | None = None
        for index, raw in enumerate(collection):
            normalized = validator(raw, f"CycloneDX projection.metadata.tools.{collection_name}[{index}]")
            reference = normalized["bom_ref"]
            if reference is not None:
                if reference in references:
                    raise SelfTestError(f"duplicate projected bom-ref is forbidden: {reference}")
                references.add(reference)
                tool_references.add(reference)
            current = canonical_json_bytes(normalized)
            if previous is not None and current <= previous:
                raise SelfTestError(f"CycloneDX projection.metadata.tools.{collection_name} is not canonical")
            previous = current

    for collection_name, validator in (
        ("components", _validate_projected_component),
        ("services", _validate_projected_service),
    ):
        collection = projection[collection_name]
        if not isinstance(collection, list):
            raise SelfTestError(f"CycloneDX projection.{collection_name} must be an array")
        previous = None
        for index, raw in enumerate(collection):
            normalized = validator(raw, f"CycloneDX projection.{collection_name}[{index}]")
            reference = normalized["bom_ref"]
            if reference in references:
                raise SelfTestError(f"duplicate projected bom-ref is forbidden: {reference}")
            references.add(reference)
            current = reference.encode("utf-8")
            if previous is not None and current <= previous:
                raise SelfTestError(f"CycloneDX projection.{collection_name} is not canonical")
            previous = current

    dependencies = projection["dependencies"]
    if not isinstance(dependencies, list):
        raise SelfTestError("CycloneDX projection.dependencies must be an array")
    dependency_references = references - tool_references
    seen_refs: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()
    previous_ref: bytes | None = None
    for index, raw in enumerate(dependencies):
        label = f"CycloneDX projection.dependencies[{index}]"
        dependency = _mapping(raw, label)
        _exact(dependency, _DEPENDENCY_KEYS, label)
        reference = _text(dependency["ref"], f"{label}.ref")
        if reference not in dependency_references or reference in seen_refs:
            raise SelfTestError(f"invalid or duplicate projected dependency ref: {reference}")
        seen_refs.add(reference)
        current_ref = reference.encode("utf-8")
        if previous_ref is not None and current_ref <= previous_ref:
            raise SelfTestError("CycloneDX projection.dependencies is not canonical")
        previous_ref = current_ref
        for edge_name in ("depends_on", "provides"):
            endpoints = dependency[edge_name]
            if not isinstance(endpoints, list):
                raise SelfTestError(f"{label}.{edge_name} must be an array")
            normalized_endpoints = [_text(item, f"{label}.{edge_name}") for item in endpoints]
            if normalized_endpoints != sorted(set(normalized_endpoints), key=lambda item: item.encode("utf-8")):
                raise SelfTestError(f"{label}.{edge_name} is duplicated or not canonical")
            for endpoint in normalized_endpoints:
                edge = (reference, edge_name, endpoint)
                if endpoint not in dependency_references or endpoint == reference or edge in seen_edges:
                    raise SelfTestError(f"invalid projected dependency edge: {edge}")
                seen_edges.add(edge)

    expected = dict(projection)
    semantic = expected.pop("semantic_sha256")
    expected.pop("source_sha256")
    expected = copy.deepcopy(expected)
    expected["document"]["serial_number"] = None
    actual = hashlib.sha256(canonical_json_bytes(expected)).hexdigest()
    if semantic != actual:
        raise SelfTestError("CycloneDX semantic projection SHA-256 mismatch")
    source_sha256 = projection["source_sha256"]
    if source_sha256 is not None:
        _sha256(source_sha256, "CycloneDX projection.source_sha256")
    return copy.deepcopy(projection)


def canonical_selftest_sha256(value: object) -> str:
    """Hash a self-test object excluding its two self-reference fields.

    The result is the artifact-bound hash: it is stable across re-runs that
    preserve canonical content (``serialNumber``/``run_id`` are excluded), but
    it is NOT the cross-run stable identity when a generator emits a fresh UUID
    into other fields. The stable identity is ``run_id`` (M3-2): callers that
    need a value that never changes across equivalent re-derivations must use
    ``run_id``, not ``canonical_sha256``.
    """

    body = _mapping(value, "self-test object")
    projection = copy.deepcopy(body)
    projection.pop("canonical_sha256", None)
    projection.pop("run_id", None)
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def selftest_run_id(value: object) -> str:
    """Return the deterministic semantic run identity for a self-test object.

    Raw CycloneDX bytes and generated serial numbers remain bound by the
    canonical SHA and package manifest, but are intentionally excluded here so
    a repeated scan of the same frozen inputs receives the same run identity.
    """

    body = _mapping(value, "self-test object")
    def stable(item: object) -> object:
        if isinstance(item, dict):
            normalized: dict[str, object] = {}
            for key, child in item.items():
                if key in {"canonical_sha256", "run_id", "source_sha256"}:
                    continue
                normalized[key] = None if key == "serial_number" else stable(child)
            return normalized
        if isinstance(item, list):
            return [stable(child) for child in item]
        return copy.deepcopy(item)

    projection = stable(body)
    return stable_id("selftest-run", projection)


def build_profile_observation(
    profile: object,
    cyclonedx: object,
    input_identity: object,
    scanner_identity: object,
) -> dict[str, Any]:
    """Bind one validated CycloneDX projection to exactly one scan profile."""

    normalized_profile = validate_selftest_profile(profile)
    normalized_cyclonedx = _validate_projection(cyclonedx)
    normalized_input = _normalize_input_identity(input_identity)
    normalized_scanner = _normalize_scanner_identity(scanner_identity)
    if normalized_scanner != normalized_profile["scanner"]:
        raise SelfTestError("scanner identity does not match the frozen profile")
    if len(normalized_cyclonedx["components"]) > normalized_profile["limits"]["max_components"]:
        raise SelfTestError("CycloneDX projection exceeds the profile component limit")

    observation: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "generator_output_status": GENERATOR_STATUS,
        "release_status": RELEASE_STATUS,
        "product_conformity_status": PRODUCT_STATUS,
        "manufacturer_approval_status": MANUFACTURER_STATUS,
        "milestone_scope": MILESTONE_SCOPE,
        "profile_id": normalized_profile["profile_id"],
        "profile_kind": normalized_profile["profile_kind"],
        "independence_domain": normalized_profile["independence_domain"],
        "subject": normalized_profile["subject"],
        "scan_contract": normalized_profile["scan"],
        "blindspots": normalized_profile["blindspots"],
        "input_identity": normalized_input,
        "scanner_identity": normalized_scanner,
        "cyclonedx_evidence": normalized_cyclonedx,
    }
    observation["canonical_sha256"] = canonical_selftest_sha256(observation)
    observation["run_id"] = selftest_run_id(observation)
    return observation


def _verify_observation(value: object) -> dict[str, Any]:
    observation = _mapping(value, "profile observation")
    _exact(observation, _OBSERVATION_KEYS, "profile observation")
    if observation.get("schema_version") != SCHEMA_VERSION:
        raise SelfTestError("profile observation schema version is unsupported")
    if observation.get("classification") != CLASSIFICATION:
        raise SelfTestError("profile observation has an unsafe classification")
    if observation.get("generator_output_status") != GENERATOR_STATUS:
        raise SelfTestError("profile observation has an unsafe generator status")
    if observation.get("release_status") != RELEASE_STATUS:
        raise SelfTestError("profile observation cannot be released")
    if observation.get("product_conformity_status") != PRODUCT_STATUS:
        raise SelfTestError("profile observation cannot claim product conformity")
    if observation.get("manufacturer_approval_status") != MANUFACTURER_STATUS:
        raise SelfTestError("profile observation cannot claim manufacturer approval")
    if observation.get("milestone_scope") != MILESTONE_SCOPE:
        raise SelfTestError("profile observation cannot claim Yocto M3B completion")
    if observation.get("profile_kind") not in PROFILE_DOMAINS:
        raise SelfTestError("profile observation kind is unsupported")
    if observation.get("independence_domain") != PROFILE_DOMAINS[observation["profile_kind"]]:
        raise SelfTestError("profile observation independence domain was spoofed")
    _safe_id(observation.get("profile_id"), "profile observation.profile_id")
    subject = _mapping(observation.get("subject"), "profile observation.subject")
    _exact(subject, _SUBJECT_KEYS, "profile observation.subject")
    _safe_id(subject.get("comparison_namespace"), "profile observation.subject.comparison_namespace")
    _text(subject.get("product_name"), "profile observation.subject.product_name")
    _text(subject.get("declared_version"), "profile observation.subject.declared_version")
    scan = _mapping(observation.get("scan_contract"), "profile observation.scan_contract")
    _exact(scan, _SCAN_KEYS, "profile observation.scan_contract")
    if scan.get("target_kind") != PROFILE_TARGETS[observation["profile_kind"]]:
        raise SelfTestError("profile observation target kind is inconsistent")
    _safe_id(scan.get("target_label"), "profile observation.scan_contract.target_label")
    blindspots = _string_list(observation.get("blindspots"), "profile observation.blindspots")
    if not REQUIRED_BLINDSPOTS.issubset(blindspots):
        raise SelfTestError("profile observation omits a mandatory M3A boundary")
    _normalize_input_identity(observation.get("input_identity"))
    scanner = _normalize_scanner_identity(observation.get("scanner_identity"))
    if scanner["name"] != "syft" or scanner["version"] != "1.50.0":
        raise SelfTestError("profile observation scanner is not the pinned Syft runtime")
    if observation.get("canonical_sha256") != canonical_selftest_sha256(observation):
        raise SelfTestError("profile observation canonical SHA-256 mismatch")
    if observation.get("run_id") != selftest_run_id(observation):
        raise SelfTestError("profile observation run identity mismatch")
    _validate_projection(observation.get("cyclonedx_evidence"))
    return copy.deepcopy(observation)


def _purl_key(purl: str | None) -> str | None:
    if purl is None or not purl.startswith("pkg:"):
        return None
    base = purl.split("#", 1)[0].split("?", 1)[0]
    at = base.rfind("@")
    slash = base.rfind("/")
    if at > slash:
        base = base[:at]
    return f"purl:{base}"


def _cpe_key(cpe: str | None) -> str | None:
    if cpe is None or not cpe.startswith("cpe:2.3:") or "\\:" in cpe:
        return None
    parts = cpe.split(":")
    if len(parts) != 13:
        return None
    parts[5] = "*"
    return ":".join(parts)


def _comparison_records(
    observation: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence = observation["cyclonedx_evidence"]
    components = [evidence["metadata"]["component"], *evidence["components"]]
    records: list[dict[str, Any]] = []
    unidentified: list[dict[str, Any]] = []
    for component in components:
        logical_key = _purl_key(component["purl"]) or _cpe_key(component["cpe"])
        if logical_key is None:
            unidentified.append(
                {
                    "profile_id": observation["profile_id"],
                    "profile_kind": observation["profile_kind"],
                    "bom_ref": component["bom_ref"],
                    "name": component["name"],
                    "version": component["version"],
                }
            )
            continue
        records.append(
            {
                "logical_key": logical_key,
                "profile_id": observation["profile_id"],
                "profile_kind": observation["profile_kind"],
                "observation_run_id": observation["run_id"],
                "bom_ref": component["bom_ref"],
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "cpe": component["cpe"],
                "hashes": component["hashes"],
            }
        )
    return records, unidentified


def _finding(code: str, logical_key: str, records: list[dict[str, Any]], explanation: str) -> dict[str, Any]:
    evidence = sorted(
        records,
        key=lambda item: (
            item["profile_kind"].encode(),
            item["profile_id"].encode(),
            item["bom_ref"].encode(),
        ),
    )
    body = {
        "code": code,
        "state": "OPEN",
        "logical_key": logical_key,
        "explanation": explanation,
        "evidence": evidence,
    }
    return {"finding_id": stable_id("selftest-finding", body), **body}


def reconcile_profile_observations(observations: list[object]) -> dict[str, Any]:
    """Compare isolated observations and emit findings without merging populations."""

    if not isinstance(observations, list) or len(observations) < 2:
        raise SelfTestError("at least two profile observations are required")
    verified = [_verify_observation(item) for item in observations]
    profile_ids = [item["profile_id"] for item in verified]
    profile_kinds = [item["profile_kind"] for item in verified]
    if len(profile_ids) != len(set(profile_ids)):
        raise SelfTestError("profile observations must have unique profile IDs")
    if len(profile_kinds) != len(set(profile_kinds)):
        raise SelfTestError("profile observations must remain one-per-profile-kind")
    namespaces = {item["subject"]["comparison_namespace"] for item in verified}
    if len(namespaces) != 1:
        raise SelfTestError("profile observations do not share a comparison namespace")

    grouped: dict[str, list[dict[str, Any]]] = {}
    unidentified_by_profile: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for observation in verified:
        records, unidentified = _comparison_records(observation)
        for record in records:
            grouped.setdefault(record["logical_key"], []).append(record)
        for entry in unidentified:
            key = (entry["profile_id"], entry["profile_kind"])
            unidentified_by_profile.setdefault(key, []).append(entry)

    findings: list[dict[str, Any]] = []
    for logical_key, records in sorted(grouped.items(), key=lambda item: item[0].encode("utf-8")):
        versions = {record["version"] for record in records if record["version"] is not None}
        profile_set = {record["profile_kind"] for record in records}
        if len(versions) > 1 and len(profile_set) > 1:
            findings.append(
                _finding(
                    "VERSION_CONFLICT",
                    logical_key,
                    records,
                    "version strings differ across isolated evidence profiles; no version ordering is inferred",
                )
            )
        portable = [record for record in records if record["profile_kind"] == "PORTABLE_RUNTIME"]
        reference = [record for record in records if record["profile_kind"] != "PORTABLE_RUNTIME"]
        reference_versions = {record["version"] for record in reference if record["version"] is not None}
        stale_records = [
            record
            for record in portable
            if record["version"] is not None
            and reference_versions
            and record["version"] not in reference_versions
        ]
        if stale_records:
            findings.append(
                _finding(
                    "STALE_PORTABLE_RUNTIME",
                    logical_key,
                    [*reference, *stale_records],
                    "portable runtime version differs from source/OCI observations; stale is a review label, not semantic version ordering",
                )
            )

    comparison: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "generator_output_status": GENERATOR_STATUS,
        "release_status": RELEASE_STATUS,
        "product_conformity_status": PRODUCT_STATUS,
        "manufacturer_approval_status": MANUFACTURER_STATUS,
        "milestone_scope": MILESTONE_SCOPE,
        "state": "OPEN",
        "comparison_namespace": next(iter(namespaces)),
        "profile_evidence": sorted(
            [
                {
                    "profile_id": item["profile_id"],
                    "profile_kind": item["profile_kind"],
                    "independence_domain": item["independence_domain"],
                    "run_id": item["run_id"],
                    "canonical_sha256": item["canonical_sha256"],
                }
                for item in verified
            ],
            key=lambda item: item["profile_kind"].encode("utf-8"),
        ),
        "comparison_findings": sorted(findings, key=lambda item: item["finding_id"].encode("utf-8")),
        "unidentified_component_summary": sorted(
            [
                {
                    "profile_id": profile_id,
                    "profile_kind": profile_kind,
                    "count": len(items),
                    "components": sorted(
                        [
                            {
                                "bom_ref": item["bom_ref"],
                                "name": item["name"],
                                "version": item["version"],
                            }
                            for item in items
                        ],
                        key=canonical_json_bytes,
                    ),
                }
                for (profile_id, profile_kind), items in unidentified_by_profile.items()
            ],
            key=lambda entry: (
                entry["profile_kind"].encode("utf-8"),
                entry["profile_id"].encode("utf-8"),
            ),
        ),
        "population_policy": "NO_CROSS_PROFILE_COMPONENT_POPULATION",
    }
    comparison["canonical_sha256"] = canonical_selftest_sha256(comparison)
    comparison["run_id"] = selftest_run_id(comparison)
    return comparison
