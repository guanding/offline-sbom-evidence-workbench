"""Bounded, advisory source-manifest reconciliation for source-only scans.

This module never adds components to an SBOM.  It separates package-like
product candidates from CI/file observations and compares the resulting
projection with dependency manifests that are already inside the frozen
source exact-set.  Every result remains heuristic and review-only.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


BOUNDARY = (
    "AUXILIARY_NOT_SBOM: manifest reconciliation and component-scope classification "
    "are review aids only. They do not add facts, establish completeness, authorize "
    "release, or support a CRA/prEN conformity conclusion."
)

_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "target",
        "dist",
        "build",
        "__pycache__",
    }
)


def _eligible(relative_path: str) -> bool:
    return not any(part in _EXCLUDED_PARTS for part in Path(relative_path).parts[:-1])


def _ecosystem_for(relative_path: str) -> str | None:
    name = Path(relative_path).name
    lower = name.lower()
    if name == "go.mod":
        return "go"
    if name in {"Cargo.toml", "Cargo.lock"}:
        return "rust"
    if lower == "pom.xml":
        return "maven"
    if name in {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
    }:
        return "node"
    if name in {"composer.json", "composer.lock"}:
        return "composer"
    if lower.endswith((".csproj", ".fsproj", ".vbproj")) or name in {
        "packages.lock.json",
        "project.assets.json",
    }:
        return "dotnet"
    if name == "west.yml":
        return "zephyr-west"
    if name in {
        "requirements.txt",
        "requirements.in",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
    }:
        return "python"
    if name in {
        "platformio.ini",
        "library.json",
        "library.properties",
        "conanfile.txt",
        "conanfile.py",
        "vcpkg.json",
    }:
        return "c-cpp"
    return None


def _read_text(root: Path, relative_path: str, *, maximum: int = 8 * 1024 * 1024) -> str:
    path = root / relative_path
    if path.stat().st_size > maximum:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _json_dependency_names(root: Path, relative_path: str, keys: tuple[str, ...]) -> set[str]:
    try:
        value = json.loads(_read_text(root, relative_path))
    except (OSError, ValueError):
        return set()
    if not isinstance(value, dict):
        return set()
    names: set[str] = set()
    for key in keys:
        collection = value.get(key)
        if isinstance(collection, dict):
            names.update(str(name) for name in collection if isinstance(name, str) and name)
    return names


def _go_dependencies(text: str) -> set[str]:
    names: set[str] = set()
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            value = line[len("require ") :].strip()
        elif in_block:
            value = line
        else:
            continue
        if value:
            names.add(value.split()[0])
    return names


def _cargo_lock_dependencies(text: str) -> set[str]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    packages = value.get("package", []) if isinstance(value, dict) else []
    if not isinstance(packages, list):
        return set()
    return {
        str(item["name"])
        for item in packages
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
    }


def _xml_dependencies(root: Path, relative_path: str, local_name: str) -> set[str]:
    try:
        document = ET.fromstring(_read_text(root, relative_path))
    except (OSError, ET.ParseError):
        return set()
    names: set[str] = set()
    for element in document.iter():
        if element.tag.rsplit("}", 1)[-1] != local_name:
            continue
        if local_name == "PackageReference":
            name = element.attrib.get("Include") or element.attrib.get("Update")
        else:
            group = None
            artifact = None
            for child in element:
                child_name = child.tag.rsplit("}", 1)[-1]
                if child_name == "groupId":
                    group = (child.text or "").strip()
                elif child_name == "artifactId":
                    artifact = (child.text or "").strip()
            name = f"{group}:{artifact}" if group and artifact else artifact
        if name:
            names.add(name)
    return names


def _west_dependencies(text: str) -> set[str]:
    """Extract project names from the bounded, conventional west.yml shape.

    YAML anchors and unusual indentation are deliberately not interpreted; this
    is advisory evidence and an empty result never becomes proof of absence.
    """

    names: set[str] = set()
    in_projects = False
    projects_indent = 0
    in_name_allowlist = False
    allowlist_indent = 0
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if stripped == "projects:":
            in_projects = True
            projects_indent = indent
            continue
        if in_projects and stripped == "name-allowlist:":
            in_name_allowlist = True
            allowlist_indent = indent
            continue
        if in_name_allowlist and indent <= allowlist_indent:
            in_name_allowlist = False
        if in_projects and indent <= projects_indent and not stripped.startswith("-"):
            in_projects = False
        if in_projects:
            match = re.match(r"-\s+name:\s*['\"]?([^'\"#\s]+)", stripped)
            if match:
                names.add(match.group(1))
            elif in_name_allowlist:
                allowlist = re.match(r"-\s+['\"]?([^'\"#\s]+)", stripped)
                if allowlist:
                    names.add(allowlist.group(1))
    return names


def _declared_dependencies(
    root: Path, manifests: dict[str, list[str]]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for ecosystem, paths in manifests.items():
        names: set[str] = set()
        for relative_path in paths:
            name = Path(relative_path).name
            try:
                text = _read_text(root, relative_path)
            except OSError:
                continue
            if ecosystem == "go" and name == "go.mod":
                names.update(_go_dependencies(text))
            elif ecosystem == "rust" and name == "Cargo.lock":
                names.update(_cargo_lock_dependencies(text))
            elif ecosystem == "maven" and name.lower() == "pom.xml":
                names.update(_xml_dependencies(root, relative_path, "dependency"))
            elif ecosystem == "node" and name == "package.json":
                names.update(
                    _json_dependency_names(
                        root,
                        relative_path,
                        ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"),
                    )
                )
            elif ecosystem == "composer" and name == "composer.json":
                names.update(
                    _json_dependency_names(root, relative_path, ("require", "require-dev"))
                )
            elif ecosystem == "dotnet" and name.lower().endswith(
                (".csproj", ".fsproj", ".vbproj")
            ):
                names.update(_xml_dependencies(root, relative_path, "PackageReference"))
            elif ecosystem == "zephyr-west" and name == "west.yml":
                names.update(_west_dependencies(text))
        result[ecosystem] = {
            "manifest_paths": paths,
            "declared_dependency_count": len(names),
            "declared_dependency_names": sorted(names, key=lambda value: value.encode("utf-8")),
        }
    return result


def _purl_type(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None
    body = value[4:]
    separator = body.find("/")
    if separator <= 0:
        return None
    return body[:separator].lower()


def analyze_source_ecosystems(
    source_root: Path,
    source_manifest: dict[str, Any],
    cyclonedx_projection: dict[str, Any],
    raw_cyclonedx_path: Path,
) -> dict[str, Any]:
    """Return a deterministic, fail-safe advisory assessment for one scan."""

    manifests: dict[str, list[str]] = {}
    for item in source_manifest.get("files", []):
        relative_path = item.get("relative_path") if isinstance(item, dict) else None
        if not isinstance(relative_path, str) or not _eligible(relative_path):
            continue
        ecosystem = _ecosystem_for(relative_path)
        if ecosystem is not None:
            manifests.setdefault(ecosystem, []).append(relative_path)
    for paths in manifests.values():
        paths.sort(key=lambda value: value.encode("utf-8"))

    components = cyclonedx_projection.get("components", [])
    product_packages: list[dict[str, Any]] = []
    ci_packages: list[dict[str, Any]] = []
    file_components: list[dict[str, Any]] = []
    unscoped_nonfile: list[dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        purl_type = _purl_type(component.get("purl"))
        if component.get("type") == "file":
            file_components.append(component)
        elif purl_type == "github":
            ci_packages.append(component)
        elif purl_type is not None:
            product_packages.append(component)
        else:
            unscoped_nonfile.append(component)

    dependencies = cyclonedx_projection.get("dependencies", [])
    dependency_edges = sum(
        len(item.get("depends_on", [])) + len(item.get("provides", []))
        for item in dependencies
        if isinstance(item, dict)
    )
    unresolved_versions = sum(
        component.get("version") in {None, "", "UNKNOWN", "unknown"}
        for component in product_packages
    )
    purls = [component.get("purl") for component in product_packages]
    duplicate_purl_occurrences = len(purls) - len(set(purls))
    declaration = _declared_dependencies(source_root, manifests)
    declared_dependency_count = sum(
        item["declared_dependency_count"] for item in declaration.values()
    )

    findings: set[str] = set()
    if manifests and not product_packages:
        findings.add("NO_PRODUCT_PACKAGE_COMPONENTS_FOR_DECLARED_ECOSYSTEM_REVIEW")
    if manifests and components and not product_packages and len(components) == (
        len(ci_packages) + len(file_components) + len(unscoped_nonfile)
    ):
        findings.add("NONZERO_TOTAL_MASKS_ZERO_PRODUCT_PACKAGE_COMPONENTS_REVIEW")
    if declared_dependency_count > 0 and not product_packages:
        findings.add("DECLARED_DEPENDENCIES_NOT_REPRESENTED_REVIEW")
    if product_packages and dependency_edges == 0:
        findings.add("DEPENDENCY_RELATIONSHIPS_ABSENT_REVIEW")
    if unresolved_versions:
        findings.add("UNRESOLVED_PRODUCT_COMPONENT_VERSIONS_REVIEW")
    if duplicate_purl_occurrences:
        findings.add("DUPLICATE_PRODUCT_PURL_OCCURRENCES_REVIEW")

    try:
        raw_text = raw_cyclonedx_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raw_text = ""
    source_path_spellings = {
        source_root.absolute().as_posix(),
        source_root.resolve(strict=True).as_posix(),
    }
    absolute_path_occurrences = sum(
        raw_text.count(spelling) for spelling in source_path_spellings if spelling
    )
    if absolute_path_occurrences:
        findings.add("ABSOLUTE_LOCAL_PATH_IN_RAW_SBOM_REVIEW")

    coverage_hold = any(
        finding
        in {
            "NO_PRODUCT_PACKAGE_COMPONENTS_FOR_DECLARED_ECOSYSTEM_REVIEW",
            "DECLARED_DEPENDENCIES_NOT_REPRESENTED_REVIEW",
            "DEPENDENCY_RELATIONSHIPS_ABSENT_REVIEW",
            "UNRESOLVED_PRODUCT_COMPONENT_VERSIONS_REVIEW",
        }
        for finding in findings
    )
    return {
        "schema_version": "1.0",
        "component_scope": {
            "total_component_count": len(components),
            "product_package_candidate_count": len(product_packages),
            "ci_github_action_candidate_count": len(ci_packages),
            "file_component_count": len(file_components),
            "unscoped_nonfile_component_count": len(unscoped_nonfile),
            "classification_rule": (
                "purl type github => CI candidate; type file => file observation; "
                "other purl types => product package candidate; no-purl non-file => unscoped"
            ),
        },
        "manifest_evidence": declaration,
        "declared_dependency_count": declared_dependency_count,
        "relationship_node_count": len(dependencies),
        "relationship_edge_count": dependency_edges,
        "unresolved_product_version_count": unresolved_versions,
        "duplicate_product_purl_occurrences": duplicate_purl_occurrences,
        "absolute_source_path_occurrences_in_raw_cyclonedx": absolute_path_occurrences,
        "findings": sorted(findings, key=lambda value: value.encode("utf-8")),
        "coverage_gate": "HOLD" if coverage_hold else "OPEN_REVIEW",
        "release_quality_handoff": "BLOCKED" if coverage_hold else "NOT_ASSESSED",
        "candidate_vulnerability_handoff": "ALLOWED_WITH_COVERAGE_WARNING",
        "boundary": BOUNDARY,
    }
