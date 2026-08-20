"""Independent, bounded source-declaration population and SBOM reconciliation.

The generated population is deliberately separate from the scanner output.  It
never inserts components into CycloneDX.  Its purpose is to make declaration
coverage gaps explicit and reproducible while preserving the single-source
boundary of ``scan-source-only``.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .manifest import canonical_json_bytes


CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
POPULATION_PROFILE = "SOURCE_DECLARATION_POPULATION_1.1"
MAX_DISCOVERY_MANIFESTS = 4096
MAX_DISCOVERY_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SINGLE_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_POPULATION_ITEMS = 100_000
MAX_EVIDENCE_RECORDS = 500_000
BOUNDARY = (
    "AUXILIARY_NOT_SBOM: independently derived source-declaration population and "
    "name-based reconciliation only. It does not modify the scanner SBOM, prove "
    "transitive completeness, establish release/build identity, or support a "
    "PRE-7/CRA conformity or certification conclusion."
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
_PURL_ECOSYSTEM = {
    "golang": "go",
    "cargo": "rust",
    "maven": "maven",
    "npm": "node",
    "composer": "composer",
    "nuget": "dotnet",
    "pypi": "python",
    "gem": "ruby",
    "swift": "swift",
    "conan": "c-cpp",
    "vcpkg": "c-cpp",
}
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RELATIONSHIPS = frozenset(
    {"PROJECT_DECLARED", "TOP_LEVEL_DECLARED", "TRANSITIVE_RESOLVED"}
)
_SCOPES = frozenset(
    {
        "product",
        "runtime",
        "development",
        "build",
        "optional",
        "peer",
        "compile",
        "test",
        "provided",
        "system",
        "import",
        "platform",
        "unknown",
    }
)


class ComponentPopulationError(ValueError):
    """Raised when a component-population contract is invalid."""


def _eligible(relative_path: str) -> bool:
    return not any(part in _EXCLUDED_PARTS for part in Path(relative_path).parts[:-1])


def _manifest_kind(relative_path: str) -> tuple[str, str] | None:
    path = Path(relative_path)
    name = path.name
    lower = name.lower()
    if name == "go.mod":
        return "go", "go-mod"
    if name == "Cargo.toml":
        return "rust", "cargo-toml"
    if name == "Cargo.lock":
        return "rust", "cargo-lock"
    if lower == "pom.xml":
        return "maven", "maven-pom"
    if name == "package.json":
        return "node", "node-package-json"
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "node", "node-lock"
    if name == "pnpm-lock.yaml":
        return "node", "pnpm-lock"
    if name == "composer.json":
        return "composer", "composer-json"
    if name == "composer.lock":
        return "composer", "composer-lock"
    if lower.endswith((".csproj", ".fsproj", ".vbproj")):
        return "dotnet", "dotnet-project"
    if name == "Directory.Packages.props":
        return "dotnet", "dotnet-central-packages"
    if name in {"Directory.Build.props", "Directory.Build.targets"}:
        return "dotnet", "dotnet-shared-project"
    if name == "packages.lock.json":
        return "dotnet", "dotnet-lock"
    if name in {"build.gradle", "build.gradle.kts"}:
        return "gradle", "gradle-build"
    if name in {"settings.gradle", "settings.gradle.kts"}:
        return "gradle", "gradle-settings"
    if name == "libs.versions.toml":
        return "gradle", "gradle-version-catalog"
    if name == "gradle.lockfile" or (
        path.suffix == ".lockfile" and "dependency-locks" in path.parts
    ):
        return "gradle", "gradle-lock"
    if name == "MODULE.bazel":
        return "bazel", "bazel-module"
    if name == "MODULE.bazel.lock":
        return "bazel", "bazel-lock"
    if name in {"WORKSPACE", "WORKSPACE.bazel"}:
        return "bazel", "bazel-workspace"
    if name == "Gemfile":
        return "ruby", "bundler-gemfile"
    if name == "Gemfile.lock":
        return "ruby", "bundler-lock"
    if lower.endswith(".gemspec"):
        return "ruby", "ruby-gemspec"
    if name == "Package.swift":
        return "swift", "swift-package"
    if name == "Package.resolved":
        return "swift", "swift-resolved"
    if name in {"idf_component.yml", "idf_component.yaml"}:
        return "esp-idf", "esp-idf-component"
    if name == "dependencies.lock":
        return "esp-idf", "esp-idf-lock"
    if name == "west.yml":
        return "zephyr-west", "west-manifest"
    if (
        lower in {"pyproject.toml", "pipfile", "setup.cfg"}
        or (lower.startswith("requirements") and Path(lower).suffix in {".txt", ".in"})
        or (Path(relative_path).parent.name.lower() == "requirements" and Path(lower).suffix in {".txt", ".in"})
    ):
        return "python", "python-declaration"
    if lower == "vcpkg.json":
        return "c-cpp", "vcpkg-json"
    if lower == "conanfile.txt":
        return "c-cpp", "conanfile-txt"
    if lower == "platformio.ini":
        return "c-cpp", "platformio-ini"
    if lower == "library.json":
        return "c-cpp", "platformio-library-json"
    if lower == "library.properties":
        return "c-cpp", "arduino-library-properties"
    if lower == "manifest.json":
        return "python", "possible-home-assistant-manifest"
    return None


def _normal_name(ecosystem: str, name: str) -> str:
    value = unquote(name.strip())
    if ecosystem == "python":
        return re.sub(r"[-_.]+", "-", value).casefold()
    if ecosystem == "go":
        return value
    return value.casefold()


def _bounded_text(value: object, *, maximum: int = 2048) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip()
    if not result or len(result) > maximum or any(ord(character) < 0x20 for character in result):
        return None
    return result


def _read_manifest(
    source_root: Path,
    relative_path: str,
    expected_size: int,
) -> tuple[str | None, str | None]:
    if expected_size > MAX_SINGLE_MANIFEST_BYTES:
        return None, "MANIFEST_SINGLE_FILE_BUDGET_EXCEEDED"
    try:
        path = source_root / relative_path
        payload = path.read_bytes()
    except OSError:
        return None, "MANIFEST_READ_FAILED"
    if len(payload) != expected_size:
        return None, "MANIFEST_SIZE_CHANGED_DURING_DISCOVERY"
    try:
        return payload.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "MANIFEST_NOT_UTF8"


def _version_from_requirement(text: str) -> tuple[str | None, str | None]:
    match = _REQUIREMENT_NAME.match(text)
    if match is None:
        return None, None
    name = match.group(1)
    remainder = text[match.end() :].strip()
    if remainder.startswith("["):
        closing = remainder.find("]")
        remainder = remainder[closing + 1 :].strip() if closing >= 0 else remainder
    marker = remainder.find(";")
    if marker >= 0:
        remainder = remainder[:marker].strip()
    return name, remainder or None


def _purl_parts(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None, None
    body = value[4:]
    separator = body.find("/")
    if separator <= 0:
        return None, None
    purl_type = body[:separator].lower()
    package = body[separator + 1 :].split("?", 1)[0].split("#", 1)[0]
    if "@" in package:
        package = package.rsplit("@", 1)[0]
    return purl_type, unquote(package)


def _xml_name(element: ET.Element, child_name: str) -> str | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == child_name:
            return _bounded_text(child.text)
    return None


class _PopulationCollector:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str, str | None], dict[str, Any]] = {}
        self.issues: set[str] = set()
        self.evidence_count = 0

    def issue(self, code: str, relative_path: str | None = None) -> None:
        self.issues.add(f"{code}:{relative_path}" if relative_path else code)

    def add(
        self,
        ecosystem: str,
        name: object,
        *,
        relative_path: str,
        evidence_kind: str,
        relationship: str,
        scope: str,
        version_specifier: object = None,
    ) -> None:
        if name is None:
            return
        bounded_name = _bounded_text(name, maximum=1024)
        if bounded_name is None:
            self.issue("INVALID_OR_UNBOUNDED_COMPONENT_NAME", relative_path)
            return
        normalized = _normal_name(ecosystem, bounded_name)
        if not normalized:
            self.issue("EMPTY_NORMALIZED_COMPONENT_NAME", relative_path)
            return
        population_role = {
            "PROJECT_DECLARED": "PROJECT_COMPONENT",
            "TOP_LEVEL_DECLARED": "DECLARED_DEPENDENCY",
            "TRANSITIVE_RESOLVED": "RESOLVED_COMPONENT",
        }.get(relationship)
        if population_role is None:
            raise ComponentPopulationError("unsupported population relationship")
        version = _bounded_text(version_specifier)
        identity_version = version if population_role != "DECLARED_DEPENDENCY" else None
        key = ecosystem, normalized, population_role, identity_version
        if key not in self._items:
            if len(self._items) >= MAX_POPULATION_ITEMS:
                raise ComponentPopulationError("component population exceeds item budget")
            identity = {
                "ecosystem": ecosystem,
                "normalized_name": normalized,
                "population_role": population_role,
                "identity_version": identity_version,
            }
            self._items[key] = {
                "population_id": "pop-" + hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
                "ecosystem": ecosystem,
                "name": bounded_name,
                "normalized_name": normalized,
                "population_role": population_role,
                "identity_version": identity_version,
                "relationships": set(),
                "dependency_scopes": set(),
                "version_specifiers": set(),
                "source_evidence": set(),
            }
        item = self._items[key]
        item["relationships"].add(relationship)
        item["dependency_scopes"].add(scope)
        if version is not None:
            item["version_specifiers"].add(version)
        evidence = (relative_path, evidence_kind, relationship, scope, version)
        if evidence not in item["source_evidence"]:
            self.evidence_count += 1
            if self.evidence_count > MAX_EVIDENCE_RECORDS:
                raise ComponentPopulationError("component population exceeds evidence budget")
            item["source_evidence"].add(evidence)

    def values(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in self._items.values():
            result.append(
                {
                    "population_id": item["population_id"],
                    "ecosystem": item["ecosystem"],
                    "name": item["name"],
                    "normalized_name": item["normalized_name"],
                    "population_role": item["population_role"],
                    "identity_version": item["identity_version"],
                    "relationships": sorted(item["relationships"], key=lambda value: value.encode()),
                    "dependency_scopes": sorted(item["dependency_scopes"], key=lambda value: value.encode()),
                    "version_specifiers": sorted(item["version_specifiers"], key=lambda value: value.encode()),
                    "source_evidence": sorted(
                        [
                            {
                                "relative_path": evidence[0],
                                "evidence_kind": evidence[1],
                                "relationship": evidence[2],
                                "dependency_scope": evidence[3],
                                "version_specifier": evidence[4],
                            }
                            for evidence in item["source_evidence"]
                        ],
                        key=canonical_json_bytes,
                    ),
                }
            )
        return sorted(result, key=lambda item: item["population_id"].encode())


def _add_json_mapping(
    collector: _PopulationCollector,
    ecosystem: str,
    mapping: object,
    *,
    relative_path: str,
    evidence_kind: str,
    relationship: str,
    scope: str,
) -> None:
    if not isinstance(mapping, dict):
        return
    for name, version in mapping.items():
        collector.add(
            ecosystem,
            name,
            relative_path=relative_path,
            evidence_kind=evidence_kind,
            relationship=relationship,
            scope=scope,
            version_specifier=version if isinstance(version, str) else None,
        )


def _parse_go(collector: _PopulationCollector, text: str, path: str) -> None:
    in_block = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("module "):
            collector.add(
                "go",
                stripped[len("module ") :].strip(),
                relative_path=path,
                evidence_kind="go-module",
                relationship="PROJECT_DECLARED",
                scope="product",
            )
        if stripped == "require (":
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            value = stripped[len("require ") :].strip()
        elif in_block:
            value = stripped
        else:
            continue
        indirect = "// indirect" in value
        value = value.split("//", 1)[0].strip()
        parts = value.split()
        if parts:
            collector.add(
                "go",
                parts[0],
                relative_path=path,
                evidence_kind="go-require",
                relationship="TRANSITIVE_RESOLVED" if indirect else "TOP_LEVEL_DECLARED",
                scope="runtime",
                version_specifier=parts[1] if len(parts) > 1 else None,
            )


def _parse_cargo_toml(collector: _PopulationCollector, text: str, path: str) -> None:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    package = document.get("package") if isinstance(document, dict) else None
    if isinstance(package, dict):
        collector.add(
            "rust",
            package.get("name"),
            relative_path=path,
            evidence_kind="cargo-package",
            relationship="PROJECT_DECLARED",
            scope="product",
            version_specifier=package.get("version"),
        )

    def add_table(table: object, scope: str, kind: str) -> None:
        if not isinstance(table, dict):
            return
        for alias, detail in table.items():
            actual = detail.get("package") if isinstance(detail, dict) else alias
            version = detail if isinstance(detail, str) else detail.get("version") if isinstance(detail, dict) else None
            collector.add(
                "rust",
                actual,
                relative_path=path,
                evidence_kind=kind,
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
                version_specifier=version,
            )

    for table_name, scope in (
        ("dependencies", "runtime"),
        ("dev-dependencies", "development"),
        ("build-dependencies", "build"),
    ):
        add_table(document.get(table_name), scope, f"cargo-{table_name}")
    workspace = document.get("workspace")
    if isinstance(workspace, dict):
        add_table(workspace.get("dependencies"), "runtime", "cargo-workspace-dependencies")
    targets = document.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for table_name, scope in (
                ("dependencies", "runtime"),
                ("dev-dependencies", "development"),
                ("build-dependencies", "build"),
            ):
                add_table(target.get(table_name), scope, f"cargo-target-{table_name}")


def _parse_cargo_lock(collector: _PopulationCollector, text: str, path: str) -> None:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    packages = document.get("package", []) if isinstance(document, dict) else []
    if not isinstance(packages, list):
        collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
        return
    for package in packages:
        if isinstance(package, dict):
            collector.add(
                "rust",
                package.get("name"),
                relative_path=path,
                evidence_kind="cargo-lock-package",
                relationship="TRANSITIVE_RESOLVED",
                scope="runtime",
                version_specifier=package.get("version"),
            )


def _parse_maven(collector: _PopulationCollector, text: str, path: str) -> None:
    try:
        document = ET.fromstring(text)
    except ET.ParseError:
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    parent = next(
        (
            child
            for child in document
            if child.tag.rsplit("}", 1)[-1] == "parent"
        ),
        None,
    )
    parent_group = _xml_name(parent, "groupId") if parent is not None else None
    parent_artifact = _xml_name(parent, "artifactId") if parent is not None else None
    parent_version = _xml_name(parent, "version") if parent is not None else None
    group = _xml_name(document, "groupId") or parent_group
    artifact = _xml_name(document, "artifactId")
    version = _xml_name(document, "version") or parent_version
    properties: dict[str, str] = {}
    property_element = next(
        (
            child
            for child in document
            if child.tag.rsplit("}", 1)[-1] == "properties"
        ),
        None,
    )
    if property_element is not None:
        for child in property_element:
            key = child.tag.rsplit("}", 1)[-1]
            value = _bounded_text(child.text)
            if key and value:
                properties[key] = value
    builtins = {
        "project.groupId": group,
        "pom.groupId": group,
        "project.artifactId": artifact,
        "pom.artifactId": artifact,
        "project.version": version,
        "pom.version": version,
        "project.parent.groupId": parent_group,
        "project.parent.artifactId": parent_artifact,
        "project.parent.version": parent_version,
    }
    properties.update({key: value for key, value in builtins.items() if value is not None})

    def resolve(value: str | None) -> str | None:
        if value is None:
            return None
        current = value
        for _ in range(8):
            updated = re.sub(
                r"\$\{([^}]+)\}",
                lambda match: properties.get(match.group(1), match.group(0)),
                current,
            )
            if updated == current:
                break
            current = updated
        return current

    group = resolve(group)
    artifact = resolve(artifact)
    version = resolve(version)
    if artifact:
        collector.add(
            "maven",
            f"{group}:{artifact}" if group else artifact,
            relative_path=path,
            evidence_kind="maven-project",
            relationship="PROJECT_DECLARED",
            scope="product",
            version_specifier=version,
        )
    parents = {child: parent for parent in document.iter() for child in parent}
    for dependency in document.iter():
        if dependency.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        ancestors: list[str] = []
        parent = parents.get(dependency)
        while parent is not None:
            ancestors.append(parent.tag.rsplit("}", 1)[-1])
            parent = parents.get(parent)
        if "dependencyManagement" in ancestors or "plugin" in ancestors:
            continue
        dep_group = resolve(_xml_name(dependency, "groupId"))
        dep_artifact = resolve(_xml_name(dependency, "artifactId"))
        dep_scope = resolve(_xml_name(dependency, "scope")) or "compile"
        if dep_artifact:
            collector.add(
                "maven",
                f"{dep_group}:{dep_artifact}" if dep_group else dep_artifact,
                relative_path=path,
                evidence_kind="maven-dependency",
                relationship="TOP_LEVEL_DECLARED",
                scope=dep_scope,
                version_specifier=resolve(_xml_name(dependency, "version")),
            )


def _parse_node(collector: _PopulationCollector, text: str, path: str, kind: str) -> None:
    if kind == "pnpm-lock":
        in_packages = False
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            stripped = raw.strip()
            if indent == 0:
                in_packages = stripped == "packages:"
                continue
            if not in_packages or indent != 2 or not stripped.endswith(":"):
                continue
            package_key = stripped[:-1].strip()
            if (
                len(package_key) >= 2
                and package_key[0] == package_key[-1]
                and package_key[0] in {"'", '"'}
            ):
                package_key = package_key[1:-1]
            if package_key.startswith(("file:", "link:", "http:", "https:", ".")):
                continue
            package_identity = package_key.split("(", 1)[0]
            separator = package_identity.rfind("@")
            if separator <= 0:
                collector.issue("PNPM_PACKAGE_KEY_UNSUPPORTED", path)
                continue
            package_name = package_identity[:separator]
            version = package_identity[separator + 1 :]
            collector.add(
                "node",
                package_name,
                relative_path=path,
                evidence_kind="pnpm-lock-package",
                relationship="TRANSITIVE_RESOLVED",
                scope="unknown",
                version_specifier=version,
            )
        return
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    if not isinstance(document, dict):
        collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
        return
    if kind == "node-package-json":
        collector.add(
            "node",
            document.get("name"),
            relative_path=path,
            evidence_kind="node-package",
            relationship="PROJECT_DECLARED",
            scope="product",
            version_specifier=document.get("version"),
        )
        for key, scope in (
            ("dependencies", "runtime"),
            ("devDependencies", "development"),
            ("peerDependencies", "peer"),
            ("optionalDependencies", "optional"),
        ):
            _add_json_mapping(
                collector,
                "node",
                document.get(key),
                relative_path=path,
                evidence_kind=f"node-{key}",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
            )
        return
    packages = document.get("packages")
    if isinstance(packages, dict):
        for location, detail in packages.items():
            if not location or not isinstance(detail, dict):
                continue
            name = detail.get("name")
            if name is None and "node_modules/" in location:
                name = location.rsplit("node_modules/", 1)[-1]
            collector.add(
                "node",
                name,
                relative_path=path,
                evidence_kind="node-lock-package",
                relationship="TRANSITIVE_RESOLVED",
                scope="development" if detail.get("dev") is True else "runtime",
                version_specifier=detail.get("version"),
            )
    elif isinstance(document.get("dependencies"), dict):
        for name, detail in document["dependencies"].items():
            collector.add(
                "node",
                name,
                relative_path=path,
                evidence_kind="node-lock-dependency",
                relationship="TRANSITIVE_RESOLVED",
                scope="runtime",
                version_specifier=detail.get("version") if isinstance(detail, dict) else None,
            )


def _parse_composer(collector: _PopulationCollector, text: str, path: str, kind: str) -> None:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    if not isinstance(document, dict):
        collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
        return
    if kind == "composer-json":
        collector.add(
            "composer",
            document.get("name"),
            relative_path=path,
            evidence_kind="composer-project",
            relationship="PROJECT_DECLARED",
            scope="product",
            version_specifier=document.get("version"),
        )
        requirements = document.get("require")
        if isinstance(requirements, dict):
            for dependency, version in requirements.items():
                dependency_scope = (
                    "platform"
                    if dependency == "php"
                    or dependency.startswith(("ext-", "lib-"))
                    or dependency in {"composer", "composer-runtime-api", "composer-plugin-api"}
                    else "runtime"
                )
                collector.add(
                    "composer",
                    dependency,
                    relative_path=path,
                    evidence_kind="composer-require",
                    relationship="TOP_LEVEL_DECLARED",
                    scope=dependency_scope,
                    version_specifier=version,
                )
        _add_json_mapping(
            collector, "composer", document.get("require-dev"), relative_path=path,
            evidence_kind="composer-require-dev", relationship="TOP_LEVEL_DECLARED", scope="development"
        )
        return
    for key, scope in (("packages", "runtime"), ("packages-dev", "development")):
        packages = document.get(key, [])
        if not isinstance(packages, list):
            continue
        for package in packages:
            if isinstance(package, dict):
                collector.add(
                    "composer",
                    package.get("name"),
                    relative_path=path,
                    evidence_kind="composer-lock-package",
                    relationship="TRANSITIVE_RESOLVED",
                    scope=scope,
                    version_specifier=package.get("version"),
                )


def _catalog_alias(value: str) -> str:
    return re.sub(r"[-_.]+", "", value).casefold()


def _gradle_catalog(
    collector: _PopulationCollector,
    text: str,
    path: str,
) -> dict[str, dict[str, Any]]:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return {"libraries": {}, "plugins": {}, "bundles": {}}
    if not isinstance(document, dict):
        collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
        return {"libraries": {}, "plugins": {}, "bundles": {}}
    versions = document.get("versions")
    version_map = versions if isinstance(versions, dict) else {}
    result: dict[str, dict[str, Any]] = {
        "libraries": {},
        "plugins": {},
        "bundles": {},
    }

    def version_for(detail: object) -> str | None:
        if isinstance(detail, str):
            return _bounded_text(detail)
        if not isinstance(detail, dict):
            return None
        version_detail = detail.get("version")
        if isinstance(version_detail, str):
            return _bounded_text(version_detail)
        if not isinstance(version_detail, dict):
            version_detail = {}
        reference = detail.get("version.ref") or version_detail.get("ref")
        if isinstance(reference, str):
            resolved = version_map.get(reference)
            if isinstance(resolved, str):
                return _bounded_text(resolved)
            if isinstance(resolved, dict):
                for key in ("strictly", "require", "required", "prefer"):
                    value = _bounded_text(resolved.get(key))
                    if value:
                        return value
            collector.issue("GRADLE_VERSION_REFERENCE_UNRESOLVED", path)
            return None
        for key in ("strictly", "require", "required", "prefer"):
            value = _bounded_text(version_detail.get(key))
            if value:
                return value
        return None

    def insert(bucket: str, alias: object, value: Any) -> None:
        bounded_alias = _bounded_text(alias, maximum=512)
        if bounded_alias is None:
            collector.issue("GRADLE_CATALOG_ALIAS_INVALID", path)
            return
        canonical = _catalog_alias(bounded_alias)
        existing = result[bucket].get(canonical)
        if existing is not None and existing != value:
            collector.issue("GRADLE_CATALOG_ALIAS_COLLISION", path)
            result[bucket].pop(canonical, None)
            return
        result[bucket][canonical] = value

    libraries = document.get("libraries")
    if isinstance(libraries, dict):
        for alias, detail in libraries.items():
            module = None
            version = None
            if isinstance(detail, str):
                parts = detail.split(":", 2)
                if len(parts) >= 2:
                    module = ":".join(parts[:2])
                    version = parts[2] if len(parts) == 3 else None
            elif isinstance(detail, dict):
                module = _bounded_text(detail.get("module"))
                if module is None:
                    group = _bounded_text(detail.get("group"))
                    name = _bounded_text(detail.get("name"))
                    if group and name:
                        module = f"{group}:{name}"
                version = version_for(detail)
            if module and module.count(":") == 1:
                insert("libraries", alias, (module, version))
            else:
                collector.issue("GRADLE_CATALOG_LIBRARY_UNSUPPORTED", path)
    plugins = document.get("plugins")
    if isinstance(plugins, dict):
        for alias, detail in plugins.items():
            plugin_id = _bounded_text(detail.get("id")) if isinstance(detail, dict) else None
            if plugin_id:
                insert("plugins", alias, (plugin_id, version_for(detail)))
            else:
                collector.issue("GRADLE_CATALOG_PLUGIN_UNSUPPORTED", path)
    bundles = document.get("bundles")
    if isinstance(bundles, dict):
        for alias, members in bundles.items():
            if isinstance(members, list) and all(isinstance(item, str) for item in members):
                insert("bundles", alias, [_catalog_alias(item) for item in members])
            else:
                collector.issue("GRADLE_CATALOG_BUNDLE_UNSUPPORTED", path)
    return result


def _gradle_scope(configuration: str) -> str | None:
    lowered = configuration.casefold()
    if lowered in {"classpath", "kapt", "ksp", "annotationprocessor"}:
        return "build"
    if "test" in lowered:
        return "test"
    if lowered.endswith("implementation") or lowered in {"api", "implementation"}:
        return "runtime"
    if lowered in {"compileonly", "compile", "compileonlyapi"}:
        return "compile"
    if lowered in {"runtimeonly", "runtime"}:
        return "runtime"
    return None


def _parse_gradle(
    collector: _PopulationCollector,
    text: str,
    path: str,
    kind: str,
    catalog: dict[str, dict[str, Any]] | None,
) -> None:
    if kind == "gradle-version-catalog":
        if catalog is not None and not any(catalog.values()):
            collector.issue("GRADLE_CATALOG_EMPTY_OR_UNSUPPORTED", path)
        return
    if kind == "gradle-settings":
        root_match = re.search(
            r"\brootProject\.name\s*=\s*['\"]([^'\"]+)['\"]", text
        )
        if root_match:
            collector.add(
                "gradle-project",
                root_match.group(1),
                relative_path=path,
                evidence_kind="gradle-root-project",
                relationship="PROJECT_DECLARED",
                scope="product",
            )
        for include_match in re.finditer(
            r"\binclude\s*(?:\((.*?)\)|([^\n]+))", text, flags=re.DOTALL
        ):
            body = include_match.group(1) or include_match.group(2) or ""
            for project in re.findall(r"['\"](:[^'\"]+)['\"]", body):
                collector.add(
                    "gradle-project",
                    project.lstrip(":"),
                    relative_path=path,
                    evidence_kind="gradle-included-project",
                    relationship="PROJECT_DECLARED",
                    scope="product",
                )
        return
    if kind == "gradle-lock":
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "empty=")):
                continue
            coordinate = line.split("=", 1)[0]
            parts = coordinate.split(":")
            if len(parts) < 3 or not all(parts[:3]):
                collector.issue("GRADLE_LOCK_ENTRY_UNSUPPORTED", path)
                continue
            collector.add(
                "maven",
                f"{parts[0]}:{parts[1]}",
                relative_path=path,
                evidence_kind="gradle-lock-component",
                relationship="TRANSITIVE_RESOLVED",
                scope="unknown",
                version_specifier=parts[2],
            )
        return

    catalog = catalog or {"libraries": {}, "plugins": {}, "bundles": {}}

    def add_catalog_library(alias: str, scope: str) -> bool:
        canonical = _catalog_alias(alias)
        bundle = catalog["bundles"].get(canonical)
        aliases = bundle if isinstance(bundle, list) else [canonical]
        found = False
        for member in aliases:
            detail = catalog["libraries"].get(member)
            if not isinstance(detail, tuple) or len(detail) != 2:
                continue
            collector.add(
                "maven",
                detail[0],
                relative_path=path,
                evidence_kind="gradle-version-catalog-use",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
                version_specifier=detail[1],
            )
            found = True
        return found

    for plugin_match in re.finditer(
        r"\bid\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
        r"(?:\s*version\s*['\"]([^'\"]+)['\"])?",
        text,
    ):
        collector.add(
            "gradle-plugin",
            plugin_match.group(1),
            relative_path=path,
            evidence_kind="gradle-plugin",
            relationship="TOP_LEVEL_DECLARED",
            scope="build",
            version_specifier=plugin_match.group(2),
        )
    for alias_match in re.finditer(
        r"\balias\s*\(\s*libs\.plugins((?:\.[A-Za-z0-9_]+)+)\s*\)", text
    ):
        alias = alias_match.group(1).lstrip(".")
        detail = catalog["plugins"].get(_catalog_alias(alias))
        if isinstance(detail, tuple) and len(detail) == 2:
            collector.add(
                "gradle-plugin",
                detail[0],
                relative_path=path,
                evidence_kind="gradle-version-catalog-plugin-use",
                relationship="TOP_LEVEL_DECLARED",
                scope="build",
                version_specifier=detail[1],
            )
        else:
            collector.issue("GRADLE_PLUGIN_ALIAS_UNRESOLVED", path)

    configuration_call = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\s*(?:\(|\s)")
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        call = configuration_call.search(line)
        if call is None:
            continue
        scope = _gradle_scope(call.group(1))
        if scope is None:
            continue
        tail = line[call.end() :]
        named = re.search(
            r"\bgroup\s*[=:]\s*['\"]([^'\"]+)['\"].*?"
            r"\bname\s*[=:]\s*['\"]([^'\"]+)['\"]"
            r"(?:.*?\bversion\s*[=:]\s*['\"]([^'\"]+)['\"])?",
            tail,
        )
        if named:
            collector.add(
                "maven",
                f"{named.group(1)}:{named.group(2)}",
                relative_path=path,
                evidence_kind="gradle-literal-dependency",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
                version_specifier=named.group(3),
            )
            continue
        accessor = re.search(
            r"\blibs((?:\.[A-Za-z0-9_]+)+)", tail
        )
        if accessor:
            parts = accessor.group(1).lstrip(".").split(".")
            if parts and parts[0] == "bundles":
                parts = parts[1:]
            if parts and add_catalog_library(".".join(parts), scope):
                continue
            collector.issue("GRADLE_LIBRARY_ALIAS_UNRESOLVED", path)
            continue
        project = re.search(r"\bproject\s*\(\s*['\"](:[^'\"]+)['\"]", tail)
        if project:
            collector.add(
                "gradle-project",
                project.group(1).lstrip(":"),
                relative_path=path,
                evidence_kind="gradle-project-dependency",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
            )
            continue
        literal = re.search(r"['\"]([^'\"]+)['\"]", tail)
        if literal:
            coordinate = literal.group(1)
            parts = coordinate.split(":", 2)
            if len(parts) >= 2 and parts[0] and parts[1]:
                version = parts[2] if len(parts) == 3 else None
                if version and ("$" in version or "{" in version):
                    version = None
                    collector.issue("GRADLE_DYNAMIC_VERSION_UNRESOLVED", path)
                collector.add(
                    "maven",
                    f"{parts[0]}:{parts[1]}",
                    relative_path=path,
                    evidence_kind="gradle-literal-dependency",
                    relationship="TOP_LEVEL_DECLARED",
                    scope=scope,
                    version_specifier=version,
                )
                continue
        if "files(" in tail or "fileTree(" in tail:
            collector.issue("GRADLE_LOCAL_FILE_DEPENDENCY_UNRESOLVED", path)
        else:
            collector.issue("GRADLE_DYNAMIC_DECLARATION_UNRESOLVED", path)


def _starlark_value(body: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]", body)
    return _bounded_text(match.group(1)) if match else None


def _parse_bazel(
    collector: _PopulationCollector,
    text: str,
    path: str,
    kind: str,
) -> None:
    if kind == "bazel-lock":
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            collector.issue("MANIFEST_PARSE_FAILED", path)
            return
        if not isinstance(document, dict):
            collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
            return
        observed: set[tuple[str, str]] = set()
        registry_hashes = document.get("registryFileHashes")
        if isinstance(registry_hashes, dict):
            for location in registry_hashes:
                match = re.search(r"/modules/([^/]+)/([^/]+)/MODULE\.bazel$", location)
                if match:
                    observed.add((unquote(match.group(1)), unquote(match.group(2))))
        selected_yanked = document.get("selectedYankedVersions")
        if isinstance(selected_yanked, dict):
            for key in selected_yanked:
                name, separator, version = key.rpartition("@")
                if separator and name and version:
                    observed.add((name, version))
        for name, version in sorted(observed, key=lambda item: item[0].encode()):
            collector.add(
                "bazel",
                name,
                relative_path=path,
                evidence_kind="bazel-lock-module",
                relationship="TRANSITIVE_RESOLVED",
                scope="build",
                version_specifier=version,
            )
        if not observed:
            collector.issue("BAZEL_LOCK_NO_RESOLVED_MODULE_IDENTITIES", path)
        return
    if kind == "bazel-module":
        module_call = re.search(r"\bmodule\s*\((.*?)\)", text, flags=re.DOTALL)
        if module_call:
            collector.add(
                "bazel",
                _starlark_value(module_call.group(1), "name"),
                relative_path=path,
                evidence_kind="bazel-root-module",
                relationship="PROJECT_DECLARED",
                scope="product",
                version_specifier=_starlark_value(module_call.group(1), "version"),
            )
        for dependency in re.finditer(r"\bbazel_dep\s*\((.*?)\)", text, flags=re.DOTALL):
            collector.add(
                "bazel",
                _starlark_value(dependency.group(1), "name"),
                relative_path=path,
                evidence_kind="bazel-direct-module",
                relationship="TOP_LEVEL_DECLARED",
                scope="build",
                version_specifier=_starlark_value(dependency.group(1), "version"),
            )
        if re.search(r"\b(?:archive|git|local_path|single_version)_override\s*\(", text):
            collector.issue("BAZEL_OVERRIDE_REQUIRES_REVIEW", path)
        return
    for repository in re.finditer(
        r"\b(?:http_archive|git_repository|new_git_repository)\s*\((.*?)\)",
        text,
        flags=re.DOTALL,
    ):
        body = repository.group(1)
        collector.add(
            "bazel",
            _starlark_value(body, "name"),
            relative_path=path,
            evidence_kind="bazel-workspace-repository",
            relationship="TOP_LEVEL_DECLARED",
            scope="build",
            version_specifier=_starlark_value(body, "commit")
            or _starlark_value(body, "tag")
            or _starlark_value(body, "sha256"),
        )


def _ruby_scopes(value: str) -> list[str]:
    lowered = value.casefold()
    scopes: list[str] = []
    if "development" in lowered or "doc" in lowered:
        scopes.append("development")
    if "test" in lowered:
        scopes.append("test")
    return scopes or ["runtime"]


def _parse_ruby(
    collector: _PopulationCollector,
    text: str,
    path: str,
    kind: str,
) -> None:
    if kind == "bundler-lock":
        section = ""
        in_specs = False
        for raw in text.splitlines():
            if raw and not raw.startswith(" "):
                section = raw.strip()
                in_specs = False
                continue
            stripped = raw.strip()
            if stripped == "specs:" and section in {"GEM", "GIT", "PATH", "PLUGIN"}:
                in_specs = True
                continue
            if section == "DEPENDENCIES":
                match = re.match(r"^\s{2}([A-Za-z0-9_.-]+)(?:\s+\(([^)]+)\))?!?", raw)
                if match:
                    collector.add(
                        "ruby",
                        match.group(1),
                        relative_path=path,
                        evidence_kind="bundler-direct-dependency",
                        relationship="TOP_LEVEL_DECLARED",
                        scope="runtime",
                        version_specifier=match.group(2),
                    )
                continue
            if in_specs:
                match = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", raw)
                if match:
                    collector.add(
                        "ruby",
                        match.group(1),
                        relative_path=path,
                        evidence_kind="bundler-locked-gem",
                        relationship="TRANSITIVE_RESOLVED",
                        scope="runtime",
                        version_specifier=match.group(2),
                    )
        return
    if kind == "ruby-gemspec":
        project_name = re.search(r"\b(?:spec|s)\.name\s*=\s*['\"]([^'\"]+)['\"]", text)
        project_version = re.search(
            r"\b(?:spec|s)\.version\s*=\s*['\"]([^'\"]+)['\"]", text
        )
        if project_name:
            collector.add(
                "ruby",
                project_name.group(1),
                relative_path=path,
                evidence_kind="ruby-gemspec-project",
                relationship="PROJECT_DECLARED",
                scope="product",
                version_specifier=project_version.group(1) if project_version else None,
            )
        for dependency in re.finditer(
            r"\b(?:spec|s)\.(add_(?:runtime_)?dependency|add_development_dependency)"
            r"\s*\(?\s*['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
            text,
        ):
            collector.add(
                "ruby",
                dependency.group(2),
                relative_path=path,
                evidence_kind="ruby-gemspec-dependency",
                relationship="TOP_LEVEL_DECLARED",
                scope="development"
                if dependency.group(1) == "add_development_dependency"
                else "runtime",
                version_specifier=dependency.group(3),
            )
        return
    active_scopes = ["runtime"]
    for raw in text.splitlines():
        line = raw.strip()
        group = re.match(r"group\s+(.+?)\s+do\s*(?:#.*)?$", line)
        if group:
            active_scopes = _ruby_scopes(group.group(1))
            continue
        if line == "end":
            active_scopes = ["runtime"]
            continue
        dependency = re.match(
            r"gem\s*\(?\s*['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
            line,
        )
        if not dependency:
            if line.startswith("gem "):
                collector.issue("BUNDLER_DYNAMIC_DECLARATION_UNRESOLVED", path)
            continue
        scopes = (
            _ruby_scopes(line)
            if "group:" in line or "groups:" in line
            else active_scopes
        )
        for scope in scopes:
            collector.add(
                "ruby",
                dependency.group(1),
                relative_path=path,
                evidence_kind="bundler-gem-declaration",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
                version_specifier=dependency.group(2),
            )


def _swift_dependency_name(location: str) -> str | None:
    tail = location.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return _bounded_text(tail, maximum=1024)


def _parse_swift(
    collector: _PopulationCollector,
    text: str,
    path: str,
    kind: str,
) -> None:
    if kind == "swift-resolved":
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            collector.issue("MANIFEST_PARSE_FAILED", path)
            return
        if not isinstance(document, dict):
            collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
            return
        pins = document.get("pins")
        if not isinstance(pins, list) and isinstance(document.get("object"), dict):
            pins = document["object"].get("pins")
        if not isinstance(pins, list):
            collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
            return
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            location = pin.get("location") or pin.get("repositoryURL")
            name = pin.get("identity") or pin.get("package")
            if name is None and isinstance(location, str):
                name = _swift_dependency_name(location)
            state = pin.get("state")
            state = state if isinstance(state, dict) else {}
            collector.add(
                "swift",
                name,
                relative_path=path,
                evidence_kind="swift-resolved-pin",
                relationship="TRANSITIVE_RESOLVED",
                scope="runtime",
                version_specifier=state.get("version")
                or state.get("revision")
                or state.get("branch"),
            )
        return
    package = re.search(r"\bPackage\s*\(\s*name\s*:\s*['\"]([^'\"]+)['\"]", text)
    if package:
        collector.add(
            "swift",
            package.group(1),
            relative_path=path,
            evidence_kind="swift-package-project",
            relationship="PROJECT_DECLARED",
            scope="product",
        )
    for dependency in re.finditer(r"\.package\s*\((.*?)\)", text, flags=re.DOTALL):
        body = dependency.group(1)
        location_match = re.search(
            r"\b(?:url|id)\s*:\s*['\"]([^'\"]+)['\"]", body
        )
        explicit_name = re.search(r"\bname\s*:\s*['\"]([^'\"]+)['\"]", body)
        if location_match is None:
            if re.search(r"\bpath\s*:", body):
                collector.issue("SWIFTPM_LOCAL_PATH_DEPENDENCY_UNRESOLVED", path)
            else:
                collector.issue("SWIFTPM_DYNAMIC_DECLARATION_UNRESOLVED", path)
            continue
        location = location_match.group(1)
        name = explicit_name.group(1) if explicit_name else _swift_dependency_name(location)
        version_match = re.search(
            r"\b(?:from|exact|revision|branch)\s*:\s*['\"]([^'\"]+)['\"]", body
        )
        collector.add(
            "swift",
            name,
            relative_path=path,
            evidence_kind="swift-package-dependency",
            relationship="TOP_LEVEL_DECLARED",
            scope="runtime",
            version_specifier=version_match.group(1) if version_match else None,
        )


def _dotnet_properties(document: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    for element in document.iter():
        if len(element) != 0:
            continue
        name = element.tag.rsplit("}", 1)[-1]
        value = _bounded_text(element.text)
        if name and value:
            properties[name] = value
    return properties


def _resolve_dotnet_value(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None
    current = value
    for _ in range(8):
        updated = re.sub(
            r"\$\(([^)]+)\)",
            lambda match: properties.get(match.group(1), match.group(0)),
            current,
        )
        if updated == current:
            break
        current = updated
    return current


def _dotnet_central_versions(
    collector: _PopulationCollector,
    text: str,
    path: str,
) -> tuple[ET.Element | None, dict[str, str]]:
    try:
        document = ET.fromstring(text)
    except ET.ParseError:
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return None, {}
    properties = _dotnet_properties(document)
    versions: dict[str, str] = {}
    for element in document.iter():
        if element.tag.rsplit("}", 1)[-1] != "PackageVersion":
            continue
        name = _bounded_text(element.attrib.get("Include") or element.attrib.get("Update"))
        version = element.attrib.get("Version") or _xml_name(element, "Version")
        version = _resolve_dotnet_value(_bounded_text(version), properties)
        if name and version:
            versions[_normal_name("dotnet", name)] = version
        elif name:
            collector.issue("DOTNET_CENTRAL_VERSION_UNRESOLVED", path)
    return document, versions


def _parse_dotnet_project(
    collector: _PopulationCollector,
    document: ET.Element,
    path: str,
    *,
    central_versions: dict[str, str],
    add_project: bool,
) -> None:
    properties = _dotnet_properties(document)
    assembly_name = next(
        (
            _bounded_text(element.text)
            for element in document.iter()
            if element.tag.rsplit("}", 1)[-1] == "AssemblyName" and _bounded_text(element.text)
        ),
        Path(path).stem,
    )
    if add_project:
        collector.add(
            "dotnet",
            assembly_name,
            relative_path=path,
            evidence_kind="dotnet-project",
            relationship="PROJECT_DECLARED",
            scope="product",
        )
    for element in document.iter():
        element_kind = element.tag.rsplit("}", 1)[-1]
        if element_kind not in {"PackageReference", "GlobalPackageReference"}:
            continue
        name = element.attrib.get("Include") or element.attrib.get("Update")
        version = (
            element.attrib.get("VersionOverride")
            or _xml_name(element, "VersionOverride")
            or element.attrib.get("Version")
            or _xml_name(element, "Version")
        )
        version = _resolve_dotnet_value(_bounded_text(version), properties)
        if version is None and name:
            version = central_versions.get(_normal_name("dotnet", name))
        if version and "$(" in version:
            collector.issue("DOTNET_DYNAMIC_VERSION_UNRESOLVED", path)
            version = None
        private_assets = _xml_name(element, "PrivateAssets")
        path_parts = {part.casefold() for part in Path(path).parts}
        if element_kind == "GlobalPackageReference":
            dependency_scope = "build"
        elif private_assets == "all":
            dependency_scope = "development"
        elif any("test" in part for part in path_parts):
            dependency_scope = "test"
        else:
            dependency_scope = "runtime"
        collector.add(
            "dotnet",
            name,
            relative_path=path,
            evidence_kind="dotnet-package-reference",
            relationship="TOP_LEVEL_DECLARED",
            scope=dependency_scope,
            version_specifier=version,
        )


def _parse_dotnet_lock(collector: _PopulationCollector, text: str, path: str) -> None:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    dependencies = document.get("dependencies") if isinstance(document, dict) else None
    if not isinstance(dependencies, dict):
        collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
        return
    for framework in dependencies.values():
        if not isinstance(framework, dict):
            continue
        for name, detail in framework.items():
            if not isinstance(detail, dict) or detail.get("type") == "Project":
                continue
            if detail.get("type") == "Direct":
                collector.add(
                    "dotnet",
                    name,
                    relative_path=path,
                    evidence_kind="dotnet-lock-direct",
                    relationship="TOP_LEVEL_DECLARED",
                    scope="runtime",
                    version_specifier=detail.get("requested"),
                )
            collector.add(
                "dotnet",
                name,
                relative_path=path,
                evidence_kind="dotnet-lock-resolved",
                relationship="TRANSITIVE_RESOLVED",
                scope="runtime",
                version_specifier=detail.get("resolved"),
            )


def _parse_dotnet(
    collector: _PopulationCollector,
    text: str,
    path: str,
    kind: str,
    central_versions: dict[str, str],
    central_document: ET.Element | None = None,
) -> None:
    if kind == "dotnet-lock":
        _parse_dotnet_lock(collector, text, path)
        return
    if kind == "dotnet-central-packages":
        if central_document is not None:
            _parse_dotnet_project(
                collector,
                central_document,
                path,
                central_versions=central_versions,
                add_project=False,
            )
        return
    try:
        document = ET.fromstring(text)
    except ET.ParseError:
        collector.issue("MANIFEST_PARSE_FAILED", path)
        return
    _parse_dotnet_project(
        collector,
        document,
        path,
        central_versions=central_versions,
        add_project=kind == "dotnet-project",
    )


def _yaml_scalar(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or candidate in {"{}", "[]", "null", "~"}:
        return None
    if candidate[0:1] in {"'", '"'} and candidate[-1:] == candidate[0]:
        candidate = candidate[1:-1]
    elif " #" in candidate:
        candidate = candidate.split(" #", 1)[0].rstrip()
    return _bounded_text(candidate)


def _parse_esp_idf_component(
    collector: _PopulationCollector,
    text: str,
    path: str,
) -> None:
    parent_name = Path(path).parent.name
    if parent_name and parent_name not in {"main", "components"}:
        collector.add(
            "esp-idf",
            parent_name,
            relative_path=path,
            evidence_kind="esp-idf-project-component",
            relationship="PROJECT_DECLARED",
            scope="product",
        )
    dependencies: dict[str, dict[str, Any]] = {}
    dependencies_indent: int | None = None
    entry_indent: int | None = None
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if dependencies_indent is None:
            if stripped == "dependencies:":
                dependencies_indent = indent
            continue
        if indent <= dependencies_indent:
            break
        match = re.match(r"['\"]?([^'\":]+(?:/[^'\":]+)?)['\"]?\s*:\s*(.*)$", stripped)
        if match and (entry_indent is None or indent == entry_indent):
            entry_indent = indent if entry_indent is None else entry_indent
            current = match.group(1).strip()
            dependencies[current] = {
                "version": _yaml_scalar(match.group(2)),
                "local": False,
                "git": False,
            }
            inline = match.group(2)
            inline_version = re.search(r"\bversion\s*:\s*([^,}]+)", inline)
            if inline_version:
                dependencies[current]["version"] = _yaml_scalar(inline_version.group(1))
            dependencies[current]["local"] = bool(re.search(r"\bpath\s*:", inline))
            dependencies[current]["git"] = bool(re.search(r"\bgit\s*:", inline))
            continue
        if current and entry_indent is not None and indent > entry_indent:
            nested = re.match(r"(version|path|git)\s*:\s*(.*)$", stripped)
            if nested:
                if nested.group(1) == "version":
                    dependencies[current]["version"] = _yaml_scalar(nested.group(2))
                elif nested.group(1) == "path":
                    dependencies[current]["local"] = True
                else:
                    dependencies[current][nested.group(1)] = True
    for name, detail in dependencies.items():
        scope = "platform" if name == "idf" else "runtime"
        collector.add(
            "esp-idf",
            name,
            relative_path=path,
            evidence_kind="esp-idf-component-dependency",
            relationship="TOP_LEVEL_DECLARED",
            scope=scope,
            version_specifier=detail["version"],
        )
        if detail["local"]:
            collector.issue("ESP_IDF_LOCAL_DEPENDENCY_REQUIRES_REVIEW", path)
        if detail["git"]:
            collector.issue("ESP_IDF_GIT_DEPENDENCY_REQUIRES_REVIEW", path)


def _parse_esp_idf_lock(
    collector: _PopulationCollector,
    text: str,
    path: str,
) -> None:
    dependencies: dict[str, str | None] = {}
    direct: set[str] = set()
    section: str | None = None
    section_indent = 0
    entry_indent: int | None = None
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0 and stripped in {"dependencies:", "direct_dependencies:"}:
            section = stripped[:-1]
            section_indent = indent
            entry_indent = None
            current = None
            continue
        if section == "dependencies":
            match = re.match(r"['\"]?([^'\":]+(?:/[^'\":]+)?)['\"]?\s*:\s*$", stripped)
            if match and indent > section_indent and (entry_indent is None or indent == entry_indent):
                entry_indent = indent if entry_indent is None else entry_indent
                current = match.group(1).strip()
                dependencies[current] = None
                continue
            if current and entry_indent is not None and indent > entry_indent:
                version = re.match(r"version\s*:\s*(.*)$", stripped)
                if version:
                    dependencies[current] = _yaml_scalar(version.group(1))
        elif section == "direct_dependencies":
            match = re.match(r"-\s*['\"]?([^'\"#\s]+)", stripped)
            if match:
                direct.add(match.group(1))
    if not dependencies:
        collector.issue("ESP_IDF_LOCK_NO_COMPONENT_IDENTITIES", path)
        return
    for name, version in dependencies.items():
        scope = "platform" if name == "idf" else "runtime"
        if name in direct:
            collector.add(
                "esp-idf",
                name,
                relative_path=path,
                evidence_kind="esp-idf-lock-direct",
                relationship="TOP_LEVEL_DECLARED",
                scope=scope,
                version_specifier=version,
            )
        collector.add(
            "esp-idf",
            name,
            relative_path=path,
            evidence_kind="esp-idf-lock-resolved",
            relationship="TRANSITIVE_RESOLVED",
            scope=scope,
            version_specifier=version,
        )


def _parse_west(collector: _PopulationCollector, text: str, path: str) -> None:
    in_projects = False
    projects_indent = 0
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if stripped == "projects:":
            in_projects = True
            projects_indent = indent
            continue
        if in_projects and indent <= projects_indent and not stripped.startswith("-"):
            in_projects = False
        if not in_projects:
            continue
        match = re.match(r"-\s+(?:name:\s*)?['\"]?([^'\"#\s]+)", stripped)
        if match:
            collector.add(
                "zephyr-west",
                match.group(1),
                relative_path=path,
                evidence_kind="west-project",
                relationship="TOP_LEVEL_DECLARED",
                scope="runtime",
            )


def _parse_python(collector: _PopulationCollector, text: str, path: str) -> bool:
    name = Path(path).name.lower()
    if name == "pyproject.toml" or name == "pipfile":
        try:
            document = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            collector.issue("MANIFEST_PARSE_FAILED", path)
            return True
        project = document.get("project") if isinstance(document, dict) else None
        if isinstance(project, dict):
            collector.add(
                "python", project.get("name"), relative_path=path,
                evidence_kind="python-project", relationship="PROJECT_DECLARED", scope="product",
                version_specifier=project.get("version")
            )
            for requirement in project.get("dependencies", []):
                dependency, version = _version_from_requirement(requirement) if isinstance(requirement, str) else (None, None)
                collector.add(
                    "python", dependency, relative_path=path, evidence_kind="python-project-dependency",
                    relationship="TOP_LEVEL_DECLARED", scope="runtime", version_specifier=version
                )
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                for requirements in optional.values():
                    if isinstance(requirements, list):
                        for requirement in requirements:
                            dependency, version = _version_from_requirement(requirement) if isinstance(requirement, str) else (None, None)
                            collector.add(
                                "python", dependency, relative_path=path,
                                evidence_kind="python-optional-dependency", relationship="TOP_LEVEL_DECLARED",
                                scope="optional", version_specifier=version
                            )
        build_system = document.get("build-system") if isinstance(document, dict) else None
        if isinstance(build_system, dict):
            for requirement in build_system.get("requires", []):
                dependency, version = _version_from_requirement(requirement) if isinstance(requirement, str) else (None, None)
                collector.add(
                    "python", dependency, relative_path=path, evidence_kind="python-build-requirement",
                    relationship="TOP_LEVEL_DECLARED", scope="build", version_specifier=version
                )
        tool = document.get("tool") if isinstance(document, dict) else None
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        if isinstance(poetry, dict):
            collector.add(
                "python", poetry.get("name"), relative_path=path, evidence_kind="poetry-project",
                relationship="PROJECT_DECLARED", scope="product", version_specifier=poetry.get("version")
            )
            for dependency, detail in (poetry.get("dependencies") or {}).items():
                if dependency.casefold() == "python":
                    continue
                collector.add(
                    "python", dependency, relative_path=path, evidence_kind="poetry-dependency",
                    relationship="TOP_LEVEL_DECLARED", scope="runtime",
                    version_specifier=detail if isinstance(detail, str) else detail.get("version") if isinstance(detail, dict) else None
                )
        if name == "pipfile":
            for key, scope in (("packages", "runtime"), ("dev-packages", "development")):
                _add_json_mapping(
                    collector, "python", document.get(key), relative_path=path,
                    evidence_kind=f"pipfile-{key}", relationship="TOP_LEVEL_DECLARED", scope=scope
                )
        return True
    if name == "setup.cfg":
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except configparser.Error:
            collector.issue("MANIFEST_PARSE_FAILED", path)
            return True
        if parser.has_option("metadata", "name"):
            collector.add(
                "python", parser.get("metadata", "name"), relative_path=path,
                evidence_kind="setup-cfg-project", relationship="PROJECT_DECLARED", scope="product",
                version_specifier=parser.get("metadata", "version", fallback=None)
            )
        requirements = parser.get("options", "install_requires", fallback="")
        for requirement in requirements.splitlines():
            dependency, version = _version_from_requirement(requirement)
            collector.add(
                "python", dependency, relative_path=path, evidence_kind="setup-cfg-install-requires",
                relationship="TOP_LEVEL_DECLARED", scope="runtime", version_specifier=version
            )
        return True
    path_parts = {part.casefold() for part in Path(path).parts}
    if path_parts & {"test", "tests", "testing"}:
        requirement_scope = "test"
    elif path_parts & {"doc", "docs", "documentation"}:
        requirement_scope = "development"
    else:
        requirement_scope = "runtime"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "http://", "https://", "git+")):
            continue
        dependency, version = _version_from_requirement(line)
        collector.add(
            "python", dependency, relative_path=path, evidence_kind="requirements-entry",
            relationship="TOP_LEVEL_DECLARED", scope=requirement_scope, version_specifier=version
        )
    return True


def _parse_c_cpp(collector: _PopulationCollector, text: str, path: str, kind: str) -> None:
    if kind in {"vcpkg-json", "platformio-library-json"}:
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            collector.issue("MANIFEST_PARSE_FAILED", path)
            return
        if not isinstance(document, dict):
            collector.issue("MANIFEST_STRUCTURE_UNSUPPORTED", path)
            return
        collector.add(
            "c-cpp", document.get("name"), relative_path=path,
            evidence_kind=f"{kind}-project", relationship="PROJECT_DECLARED", scope="product",
            version_specifier=document.get("version-string") or document.get("version")
        )
        dependencies = document.get("dependencies")
        if isinstance(dependencies, dict):
            dependencies = [{"name": name, "version": version} for name, version in dependencies.items()]
        if isinstance(dependencies, list):
            for dependency in dependencies:
                name = dependency if isinstance(dependency, str) else dependency.get("name") if isinstance(dependency, dict) else None
                version = dependency.get("version>=") or dependency.get("version") if isinstance(dependency, dict) else None
                collector.add(
                    "c-cpp", name, relative_path=path, evidence_kind=f"{kind}-dependency",
                    relationship="TOP_LEVEL_DECLARED", scope="runtime", version_specifier=version
                )
        return
    if kind == "conanfile-txt":
        in_requires = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                in_requires = line.casefold() == "[requires]"
                continue
            if in_requires and line and not line.startswith("#"):
                package = line.split("@", 1)[0]
                name, separator, version = package.partition("/")
                collector.add(
                    "c-cpp", name, relative_path=path, evidence_kind="conan-require",
                    relationship="TOP_LEVEL_DECLARED", scope="runtime",
                    version_specifier=version if separator else None
                )
        return
    if kind == "arduino-library-properties":
        for raw in text.splitlines():
            if not raw.casefold().startswith("depends="):
                continue
            for dependency in raw.split("=", 1)[1].split(","):
                match = re.match(r"\s*([^()]+?)(?:\s*\(([^)]+)\))?\s*$", dependency)
                if match:
                    collector.add(
                        "c-cpp", match.group(1), relative_path=path,
                        evidence_kind="arduino-dependency", relationship="TOP_LEVEL_DECLARED",
                        scope="runtime", version_specifier=match.group(2)
                    )
        return
    in_lib_deps = False
    base_indent = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith((";", "#")):
            continue
        if re.match(r"lib_deps\s*=", stripped, flags=re.IGNORECASE):
            in_lib_deps = True
            base_indent = len(raw) - len(raw.lstrip())
            value = stripped.split("=", 1)[1].strip()
        elif in_lib_deps and len(raw) - len(raw.lstrip()) > base_indent:
            value = stripped
        else:
            in_lib_deps = False
            continue
        if not value or "://" in value or value.startswith("git+"):
            continue
        package, separator, version = value.partition("@")
        collector.add(
            "c-cpp", package, relative_path=path, evidence_kind="platformio-lib-dep",
            relationship="TOP_LEVEL_DECLARED", scope="runtime",
            version_specifier=version if separator else None
        )


def _parse_home_assistant(collector: _PopulationCollector, text: str, path: str) -> bool:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(document, dict) or not isinstance(document.get("requirements"), list):
        return False
    for requirement in document["requirements"]:
        dependency, version = _version_from_requirement(requirement) if isinstance(requirement, str) else (None, None)
        collector.add(
            "python", dependency, relative_path=path, evidence_kind="home-assistant-requirement",
            relationship="TOP_LEVEL_DECLARED", scope="runtime", version_specifier=version
        )
    return True


def _nearest_context(
    relative_path: str,
    contexts: list[tuple[Path, Any]],
    default: Any,
) -> Any:
    path = Path(relative_path)
    matches = [
        (root, value)
        for root, value in contexts
        if path == root or path.is_relative_to(root)
    ]
    if not matches:
        return default
    return max(matches, key=lambda item: len(item[0].parts))[1]


def discover_declared_component_population(
    source_root: Path,
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Derive an item-level population from only the frozen source exact-set."""

    collector = _PopulationCollector()
    candidates: list[tuple[str, int, str, str]] = []
    for entry in source_manifest.get("files", []):
        if not isinstance(entry, dict):
            continue
        relative_path = entry.get("relative_path")
        size = entry.get("size")
        if not isinstance(relative_path, str) or type(size) is not int or not _eligible(relative_path):
            continue
        kind = _manifest_kind(relative_path)
        if kind is not None:
            candidates.append((relative_path, size, kind[0], kind[1]))
    candidates.sort(key=lambda item: item[0].encode("utf-8"))
    selected = candidates[:MAX_DISCOVERY_MANIFESTS]
    if len(candidates) > MAX_DISCOVERY_MANIFESTS:
        collector.issue("MANIFEST_COUNT_BUDGET_EXCEEDED")
    consumed_bytes = 0
    processed_paths: list[str] = []
    skipped_paths: list[str] = []
    loaded: list[tuple[str, str, str, str]] = []
    for path, size, ecosystem, kind in selected:
        if consumed_bytes + size > MAX_DISCOVERY_TOTAL_BYTES:
            collector.issue("MANIFEST_TOTAL_BYTE_BUDGET_EXCEEDED")
            skipped_paths.append(path)
            continue
        consumed_bytes += size
        text, read_issue = _read_manifest(source_root, path, size)
        if read_issue is not None:
            collector.issue(read_issue, path)
            skipped_paths.append(path)
            continue
        assert text is not None
        loaded.append((path, ecosystem, kind, text))
        if kind != "possible-home-assistant-manifest":
            processed_paths.append(path)

    gradle_contexts: list[tuple[Path, dict[str, dict[str, Any]]]] = []
    gradle_catalogs_by_path: dict[str, dict[str, dict[str, Any]]] = {}
    dotnet_contexts: list[
        tuple[Path, tuple[ET.Element | None, dict[str, str]]]
    ] = []
    dotnet_central_by_path: dict[
        str, tuple[ET.Element | None, dict[str, str]]
    ] = {}
    for path, _ecosystem, kind, text in loaded:
        if kind == "gradle-version-catalog":
            catalog = _gradle_catalog(collector, text, path)
            gradle_catalogs_by_path[path] = catalog
            catalog_path = Path(path)
            root = (
                catalog_path.parent.parent
                if catalog_path.parent.name == "gradle"
                else catalog_path.parent
            )
            gradle_contexts.append((root, catalog))
        elif kind == "dotnet-central-packages":
            context = _dotnet_central_versions(collector, text, path)
            dotnet_central_by_path[path] = context
            dotnet_contexts.append((Path(path).parent, context))

    for path, ecosystem, kind, text in loaded:
        if kind == "possible-home-assistant-manifest":
            if _parse_home_assistant(collector, text, path):
                processed_paths.append(path)
            continue
        if ecosystem == "go":
            _parse_go(collector, text, path)
        elif kind == "cargo-toml":
            _parse_cargo_toml(collector, text, path)
        elif kind == "cargo-lock":
            _parse_cargo_lock(collector, text, path)
        elif ecosystem == "maven":
            _parse_maven(collector, text, path)
        elif ecosystem == "node":
            _parse_node(collector, text, path, kind)
        elif ecosystem == "composer":
            _parse_composer(collector, text, path, kind)
        elif ecosystem == "dotnet":
            central_document, central_versions = _nearest_context(
                path, dotnet_contexts, (None, {})
            )
            if kind == "dotnet-central-packages":
                central_document, central_versions = dotnet_central_by_path[path]
            _parse_dotnet(
                collector,
                text,
                path,
                kind,
                central_versions,
                central_document,
            )
        elif ecosystem == "gradle":
            catalog = _nearest_context(path, gradle_contexts, None)
            if kind == "gradle-version-catalog":
                catalog = gradle_catalogs_by_path[path]
            _parse_gradle(collector, text, path, kind, catalog)
        elif ecosystem == "bazel":
            _parse_bazel(collector, text, path, kind)
        elif ecosystem == "ruby":
            _parse_ruby(collector, text, path, kind)
        elif ecosystem == "swift":
            _parse_swift(collector, text, path, kind)
        elif ecosystem == "esp-idf":
            if kind == "esp-idf-component":
                _parse_esp_idf_component(collector, text, path)
            else:
                _parse_esp_idf_lock(collector, text, path)
        elif ecosystem == "zephyr-west":
            _parse_west(collector, text, path)
        elif ecosystem == "python":
            _parse_python(collector, text, path)
        elif ecosystem == "c-cpp":
            _parse_c_cpp(collector, text, path, kind)
    items = collector.values()
    by_ecosystem: dict[str, dict[str, Any]] = {}
    for item in items:
        ecosystem = item["ecosystem"]
        summary = by_ecosystem.setdefault(ecosystem, {"item_count": 0, "population_ids": []})
        summary["item_count"] += 1
        summary["population_ids"].append(item["population_id"])
    for summary in by_ecosystem.values():
        summary["population_ids"].sort(key=lambda value: value.encode())
    return {
        "profile": POPULATION_PROFILE,
        "recognized_manifest_count": len(candidates),
        "processed_manifest_count": len(processed_paths),
        "processed_manifest_bytes": consumed_bytes,
        "processed_manifest_paths": sorted(
            processed_paths, key=lambda value: value.encode("utf-8")
        ),
        "skipped_manifest_paths": sorted(
            skipped_paths, key=lambda value: value.encode("utf-8")
        ),
        "discovery_issues": sorted(collector.issues, key=lambda value: value.encode()),
        "item_count": len(items),
        "evidence_count": collector.evidence_count,
        "by_ecosystem": dict(sorted(by_ecosystem.items(), key=lambda item: item[0].encode())),
        "items": items,
        "resource_budgets": {
            "max_manifests": MAX_DISCOVERY_MANIFESTS,
            "max_total_manifest_bytes": MAX_DISCOVERY_TOTAL_BYTES,
            "max_single_manifest_bytes": MAX_SINGLE_MANIFEST_BYTES,
            "max_population_items": MAX_POPULATION_ITEMS,
            "max_evidence_records": MAX_EVIDENCE_RECORDS,
        },
    }


def _component_aliases(component: dict[str, Any], ecosystem: str) -> set[str]:
    aliases: set[str] = set()
    name = _bounded_text(component.get("name"), maximum=1024)
    group = _bounded_text(component.get("group"), maximum=1024)
    if name:
        aliases.add(_normal_name(ecosystem, name))
        if group:
            separator = ":" if ecosystem == "maven" else "/"
            aliases.add(_normal_name(ecosystem, f"{group}{separator}{name}"))
    purl_type, package = _purl_parts(component.get("purl"))
    if purl_type in _PURL_ECOSYSTEM and package:
        if ecosystem == "maven" and "/" in package:
            package = package.replace("/", ":", 1)
        aliases.add(_normal_name(ecosystem, package))
    return {alias for alias in aliases if alias}


def reconcile_component_population(
    population_items: list[dict[str, Any]],
    cyclonedx_projection: dict[str, Any],
    discovery_issues: list[str],
    declared_product_name: str | None = None,
) -> dict[str, Any]:
    """Name-reconcile an independent population against the strict CDX projection."""

    candidates: list[dict[str, Any]] = []
    root = cyclonedx_projection.get("metadata", {}).get("component")
    if isinstance(root, dict):
        candidates.append({**root, "sbom_location": "metadata.component"})
    for component in cyclonedx_projection.get("components", []):
        if isinstance(component, dict):
            candidates.append({**component, "sbom_location": "components"})

    index: dict[tuple[str, str], set[str]] = {}
    candidates_by_ref: dict[str, dict[str, Any]] = {}
    supported_refs: set[str] = set()
    root_ref = root.get("bom_ref") if isinstance(root, dict) else None
    for component in candidates:
        purl_type, _ = _purl_parts(component.get("purl"))
        ecosystem = _PURL_ECOSYSTEM.get(purl_type or "")
        reference = component.get("bom_ref")
        if not isinstance(reference, str):
            continue
        candidates_by_ref[reference] = component
        if ecosystem is None:
            continue
        supported_refs.add(reference)
        for alias in _component_aliases(component, ecosystem):
            index.setdefault((ecosystem, alias), set()).add(reference)

    results: list[dict[str, Any]] = []
    matched_refs: set[str] = set()
    matched = 0
    unmatched = 0
    ambiguous = 0
    root_identity_hold = 0
    for item in population_items:
        refs = set(index.get((item["ecosystem"], item["normalized_name"]), set()))
        if (
            not refs
            and "PROJECT_DECLARED" in item.get("relationships", [])
            and isinstance(root, dict)
            and isinstance(root_ref, str)
        ):
            root_name = _bounded_text(root.get("name"), maximum=1024)
            if root_name and _normal_name(item["ecosystem"], root_name) == item["normalized_name"]:
                refs.add(root_ref)
        name_candidate_refs = set(refs)
        identity_version = item.get("identity_version")
        version_required = (
            identity_version is not None
            and item.get("population_role") in {"PROJECT_COMPONENT", "RESOLVED_COMPONENT"}
        )
        version_mismatch = False
        if version_required and refs:
            version_refs = {
                reference
                for reference in refs
                if candidates_by_ref.get(reference, {}).get("version") == identity_version
            }
            if version_refs:
                refs = version_refs
            else:
                refs = set()
                version_mismatch = True
        declared_product_match = (
            item.get("population_role") == "PROJECT_COMPONENT"
            and declared_product_name is not None
            and _normal_name(item["ecosystem"], declared_product_name)
            == item["normalized_name"]
        )
        unstable_scanner_root = (
            declared_product_match
            and isinstance(root, dict)
            and isinstance(root_ref, str)
            and (
                root.get("type") == "file"
                or not _bounded_text(root.get("purl"), maximum=4096)
            )
        )
        if not refs and unstable_scanner_root:
            status = "SBOM_ROOT_IDENTITY_NOT_STABLE"
            root_identity_hold += 1
            refs = {root_ref}
            name_candidate_refs = set(refs)
        elif not refs:
            status = "NOT_FOUND_AT_IDENTITY_VERSION" if version_mismatch else "NOT_FOUND"
            unmatched += 1
        elif len(refs) == 1:
            status = (
                "MATCHED_NAME_ECOSYSTEM_AND_VERSION"
                if version_required
                else "MATCHED_NAME_AND_ECOSYSTEM"
            )
            matched += 1
            matched_refs.update(refs)
        else:
            status = "AMBIGUOUS_MULTIPLE_SBOM_CANDIDATES"
            ambiguous += 1
            matched_refs.update(refs)
        results.append(
            {
                "population_id": item["population_id"],
                "ecosystem": item["ecosystem"],
                "normalized_name": item["normalized_name"],
                "population_role": item["population_role"],
                "identity_version": identity_version,
                "match_status": status,
                "candidate_bom_refs": sorted(
                    refs if refs else name_candidate_refs,
                    key=lambda value: value.encode(),
                ),
            }
        )
    if discovery_issues:
        gate = "HOLD_DISCOVERY_INCOMPLETE"
    elif root_identity_hold:
        gate = "HOLD_SBOM_ROOT_IDENTITY"
    elif unmatched:
        gate = "HOLD_UNMATCHED_DECLARATIONS"
    elif ambiguous:
        gate = "HOLD_AMBIGUOUS_MATCHES"
    elif population_items:
        gate = "OPEN_REVIEW_SINGLE_SOURCE_DECLARATION_SCOPE"
    else:
        gate = "NOT_ASSESSED_NO_DECLARED_COMPONENTS"
    return {
        "matching_method": (
            "EXACT_NORMALIZED_NAME_WITHIN_PURL_ECOSYSTEM; exact identity version "
            "required for project and resolved-component records"
        ),
        "population_item_count": len(population_items),
        "matched_item_count": matched,
        "unmatched_item_count": unmatched,
        "ambiguous_item_count": ambiguous,
        "root_identity_hold_item_count": root_identity_hold,
        "supported_sbom_candidate_count": len(supported_refs),
        "sbom_only_supported_candidate_count": len(supported_refs - matched_refs),
        "items": sorted(results, key=lambda item: item["population_id"].encode()),
        "gate": gate,
        "release_quality_handoff": "BLOCKED_SINGLE_SOURCE_ONLY",
        "candidate_vulnerability_handoff": "ALLOWED_WITH_COVERAGE_WARNING",
        "boundary": (
            "Name/version reconciliation is not identity proof. A declared product name "
            "never repairs a path-only scanner root; that condition remains an explicit "
            "root-identity HOLD. A match does not establish supplier, hash, relationship, "
            "transitive completeness, or product inclusion."
        ),
    }


def _validate_build_binding(
    build_id: str | None,
    release_artifact_sha256: str | None,
) -> tuple[str | None, str | None, str]:
    if (build_id is None) != (release_artifact_sha256 is None):
        raise ComponentPopulationError(
            "build_id and release_artifact_sha256 must be declared together"
        )
    if build_id is None:
        return None, None, "SOURCE_ONLY_NO_BUILD_OR_RELEASE_ARTIFACT_BINDING"
    bounded = _bounded_text(build_id, maximum=512)
    if bounded is None:
        raise ComponentPopulationError("build_id must be bounded printable text")
    if not isinstance(release_artifact_sha256, str) or not _SHA256.fullmatch(release_artifact_sha256):
        raise ComponentPopulationError("release_artifact_sha256 must be lowercase SHA-256")
    return (
        bounded,
        release_artifact_sha256,
        "OPERATOR_DECLARED_BUILD_ARTIFACT_BINDING_NOT_INDEPENDENTLY_VERIFIED",
    )


def build_component_population(
    source_root: Path,
    source_manifest: dict[str, Any],
    cyclonedx_projection: dict[str, Any],
    *,
    product_name: str,
    declared_version: str,
    build_id: str | None = None,
    release_artifact_sha256: str | None = None,
) -> dict[str, Any]:
    """Build one deterministic auxiliary population bound to source and SBOM."""

    bounded_product = _bounded_text(product_name, maximum=1024)
    bounded_version = _bounded_text(declared_version, maximum=1024)
    if bounded_product is None or bounded_version is None:
        raise ComponentPopulationError("product_name and declared_version must be bounded text")
    resolved_build_id, artifact_sha256, binding_status = _validate_build_binding(
        build_id, release_artifact_sha256
    )
    discovery = discover_declared_component_population(source_root, source_manifest)
    reconciliation = reconcile_component_population(
        discovery["items"],
        cyclonedx_projection,
        discovery["discovery_issues"],
        bounded_product,
    )
    identity = {
        "population_profile": POPULATION_PROFILE,
        "source_binding": {
            "root_id": source_manifest.get("root_id"),
            "exact_set_sha256": source_manifest.get("exact_set_sha256"),
            "file_count": source_manifest.get("file_count"),
            "total_bytes": source_manifest.get("total_bytes"),
        },
        "sbom_binding": {
            "format": cyclonedx_projection.get("document", {}).get("bom_format"),
            "spec_version": cyclonedx_projection.get("document", {}).get("spec_version"),
            "raw_sha256": cyclonedx_projection.get("source_sha256"),
            "semantic_sha256": cyclonedx_projection.get("semantic_sha256"),
        },
        "product_build_binding": {
            "product_name": bounded_product,
            "declared_version": bounded_version,
            "build_id": resolved_build_id,
            "release_artifact_sha256": artifact_sha256,
            "status": binding_status,
        },
        "discovery": discovery,
        "reconciliation": reconciliation,
    }
    return {
        "schema_version": "1.0",
        "classification": CLASSIFICATION,
        **identity,
        "population_sha256": hashlib.sha256(canonical_json_bytes(identity)).hexdigest(),
        "boundary": BOUNDARY,
    }


def _canonical_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ComponentPopulationError(f"{label} must be an array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ComponentPopulationError(f"{label} contains invalid text")
    if value != sorted(set(value), key=lambda item: item.encode("utf-8")):
        raise ComponentPopulationError(f"{label} is duplicated or not canonical")
    return value


def _safe_relative_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or Path(value).is_absolute()
        or ".." in Path(value).parts
        or "\\" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ComponentPopulationError(f"{label} is not a safe relative path")
    return value


def _validate_discovery(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "profile",
        "recognized_manifest_count",
        "processed_manifest_count",
        "processed_manifest_bytes",
        "processed_manifest_paths",
        "skipped_manifest_paths",
        "discovery_issues",
        "item_count",
        "evidence_count",
        "by_ecosystem",
        "items",
        "resource_budgets",
    }:
        raise ComponentPopulationError("component discovery fields do not match")
    if value["profile"] != POPULATION_PROFILE:
        raise ComponentPopulationError("component discovery profile is invalid")
    budgets = value["resource_budgets"]
    expected_budgets = {
        "max_manifests": MAX_DISCOVERY_MANIFESTS,
        "max_total_manifest_bytes": MAX_DISCOVERY_TOTAL_BYTES,
        "max_single_manifest_bytes": MAX_SINGLE_MANIFEST_BYTES,
        "max_population_items": MAX_POPULATION_ITEMS,
        "max_evidence_records": MAX_EVIDENCE_RECORDS,
    }
    if budgets != expected_budgets:
        raise ComponentPopulationError("component discovery budgets changed")
    processed = _canonical_string_list(
        value["processed_manifest_paths"], "processed manifest paths"
    )
    skipped = _canonical_string_list(
        value["skipped_manifest_paths"], "skipped manifest paths"
    )
    for index, path in enumerate(processed):
        _safe_relative_path(path, f"processed manifest path[{index}]")
    for index, path in enumerate(skipped):
        _safe_relative_path(path, f"skipped manifest path[{index}]")
    if set(processed) & set(skipped):
        raise ComponentPopulationError("processed and skipped manifest paths overlap")
    issues = _canonical_string_list(value["discovery_issues"], "discovery issues")
    if any(len(issue) > 8192 or any(ord(character) < 0x20 for character in issue) for issue in issues):
        raise ComponentPopulationError("discovery issue text is invalid")
    counters = (
        "recognized_manifest_count",
        "processed_manifest_count",
        "processed_manifest_bytes",
        "item_count",
        "evidence_count",
    )
    if any(type(value[counter]) is not int or value[counter] < 0 for counter in counters):
        raise ComponentPopulationError("component discovery counters are invalid")
    if (
        value["processed_manifest_count"] != len(processed)
        or value["recognized_manifest_count"] < len(processed) + len(skipped)
        or value["processed_manifest_bytes"] > MAX_DISCOVERY_TOTAL_BYTES
    ):
        raise ComponentPopulationError("component discovery manifest counts do not rederive")
    items = value["items"]
    if not isinstance(items, list) or len(items) > MAX_POPULATION_ITEMS:
        raise ComponentPopulationError("component population items are invalid")
    expected_order: list[str] = []
    observed_ecosystems: dict[str, list[str]] = {}
    evidence_count = 0
    seen_identity: set[tuple[str, str, str, str | None]] = set()
    for index, item in enumerate(items):
        label = f"component population items[{index}]"
        if not isinstance(item, dict) or set(item) != {
            "population_id",
            "ecosystem",
            "name",
            "normalized_name",
            "population_role",
            "identity_version",
            "relationships",
            "dependency_scopes",
            "version_specifiers",
            "source_evidence",
        }:
            raise ComponentPopulationError(f"{label} fields do not match")
        ecosystem = _bounded_text(item["ecosystem"], maximum=64)
        name = _bounded_text(item["name"], maximum=1024)
        normalized = _bounded_text(item["normalized_name"], maximum=1024)
        population_role = item["population_role"]
        identity_version = item["identity_version"]
        if (
            ecosystem is None
            or name is None
            or normalized is None
            or population_role
            not in {"PROJECT_COMPONENT", "DECLARED_DEPENDENCY", "RESOLVED_COMPONENT"}
            or (
                identity_version is not None
                and _bounded_text(identity_version) != identity_version
            )
            or (population_role == "DECLARED_DEPENDENCY" and identity_version is not None)
        ):
            raise ComponentPopulationError(f"{label} identity is invalid")
        if _normal_name(ecosystem, name) != normalized:
            raise ComponentPopulationError(f"{label} normalized name does not rederive")
        identity = (ecosystem, normalized, population_role, identity_version)
        if identity in seen_identity:
            raise ComponentPopulationError("component population identity is duplicated")
        seen_identity.add(identity)
        expected_id = "pop-" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "ecosystem": ecosystem,
                    "normalized_name": normalized,
                    "population_role": population_role,
                    "identity_version": identity_version,
                }
            )
        ).hexdigest()
        if item["population_id"] != expected_id:
            raise ComponentPopulationError(f"{label} population ID does not rederive")
        expected_order.append(expected_id)
        relationships = _canonical_string_list(item["relationships"], f"{label} relationships")
        scopes = _canonical_string_list(item["dependency_scopes"], f"{label} dependency scopes")
        versions = _canonical_string_list(item["version_specifiers"], f"{label} versions")
        if not relationships or not set(relationships) <= _RELATIONSHIPS:
            raise ComponentPopulationError(f"{label} relationships are invalid")
        expected_relationship = {
            "PROJECT_COMPONENT": "PROJECT_DECLARED",
            "DECLARED_DEPENDENCY": "TOP_LEVEL_DECLARED",
            "RESOLVED_COMPONENT": "TRANSITIVE_RESOLVED",
        }[population_role]
        if relationships != [expected_relationship]:
            raise ComponentPopulationError(f"{label} role and relationship differ")
        if not scopes or not set(scopes) <= _SCOPES:
            raise ComponentPopulationError(f"{label} scopes are invalid")
        if any(_bounded_text(version) != version for version in versions):
            raise ComponentPopulationError(f"{label} version text is invalid")
        evidence = item["source_evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise ComponentPopulationError(f"{label} source evidence is invalid")
        if evidence != sorted(evidence, key=canonical_json_bytes):
            raise ComponentPopulationError(f"{label} source evidence is not canonical")
        seen_evidence: set[bytes] = set()
        for evidence_index, record in enumerate(evidence):
            evidence_label = f"{label} source_evidence[{evidence_index}]"
            if not isinstance(record, dict) or set(record) != {
                "relative_path",
                "evidence_kind",
                "relationship",
                "dependency_scope",
                "version_specifier",
            }:
                raise ComponentPopulationError(f"{evidence_label} fields do not match")
            path = _safe_relative_path(record["relative_path"], evidence_label)
            if path not in processed:
                raise ComponentPopulationError(f"{evidence_label} path was not processed")
            if (
                _bounded_text(record["evidence_kind"], maximum=128) is None
                or record["relationship"] not in relationships
                or record["dependency_scope"] not in scopes
            ):
                raise ComponentPopulationError(f"{evidence_label} classification is invalid")
            version = record["version_specifier"]
            if version is not None and (
                _bounded_text(version) != version or version not in versions
            ):
                raise ComponentPopulationError(f"{evidence_label} version is invalid")
            encoded = canonical_json_bytes(record)
            if encoded in seen_evidence:
                raise ComponentPopulationError(f"{evidence_label} is duplicated")
            seen_evidence.add(encoded)
        evidence_count += len(evidence)
        observed_ecosystems.setdefault(ecosystem, []).append(expected_id)
    if expected_order != sorted(expected_order, key=lambda item: item.encode("utf-8")):
        raise ComponentPopulationError("component population items are not canonical")
    if value["item_count"] != len(items) or value["evidence_count"] != evidence_count:
        raise ComponentPopulationError("component population counts do not rederive")
    expected_ecosystems = {
        ecosystem: {
            "item_count": len(population_ids),
            "population_ids": sorted(population_ids, key=lambda item: item.encode("utf-8")),
        }
        for ecosystem, population_ids in sorted(
            observed_ecosystems.items(), key=lambda item: item[0].encode("utf-8")
        )
    }
    if value["by_ecosystem"] != expected_ecosystems:
        raise ComponentPopulationError("component ecosystem summary does not rederive")
    return value


def validate_component_population(
    value: object,
    *,
    source_manifest: dict[str, Any],
    cyclonedx_projection: dict[str, Any],
) -> dict[str, Any]:
    """Validate internal hashes and bindings without trusting summary counts."""

    if not isinstance(value, dict):
        raise ComponentPopulationError("component population must be an object")
    expected_keys = {
        "schema_version", "classification", "population_profile", "source_binding",
        "sbom_binding", "product_build_binding", "discovery", "reconciliation",
        "population_sha256", "boundary"
    }
    if set(value) != expected_keys:
        raise ComponentPopulationError("component population fields do not match")
    if value["schema_version"] != "1.0" or value["classification"] != CLASSIFICATION:
        raise ComponentPopulationError("component population boundary is invalid")
    if value["population_profile"] != POPULATION_PROFILE or value["boundary"] != BOUNDARY:
        raise ComponentPopulationError("component population profile is invalid")
    expected_source = {
        "root_id": source_manifest.get("root_id"),
        "exact_set_sha256": source_manifest.get("exact_set_sha256"),
        "file_count": source_manifest.get("file_count"),
        "total_bytes": source_manifest.get("total_bytes"),
    }
    if value["source_binding"] != expected_source:
        raise ComponentPopulationError("component population source binding mismatch")
    expected_sbom = {
        "format": cyclonedx_projection.get("document", {}).get("bom_format"),
        "spec_version": cyclonedx_projection.get("document", {}).get("spec_version"),
        "raw_sha256": cyclonedx_projection.get("source_sha256"),
        "semantic_sha256": cyclonedx_projection.get("semantic_sha256"),
    }
    if value["sbom_binding"] != expected_sbom:
        raise ComponentPopulationError("component population SBOM binding mismatch")
    product_binding = value["product_build_binding"]
    if not isinstance(product_binding, dict) or set(product_binding) != {
        "product_name",
        "declared_version",
        "build_id",
        "release_artifact_sha256",
        "status",
    }:
        raise ComponentPopulationError("product/build binding fields do not match")
    if (
        _bounded_text(product_binding["product_name"], maximum=1024) is None
        or _bounded_text(product_binding["declared_version"], maximum=1024) is None
    ):
        raise ComponentPopulationError("product/build binding identity is invalid")
    build_id, artifact_sha256, status = _validate_build_binding(
        product_binding["build_id"], product_binding["release_artifact_sha256"]
    )
    if (
        product_binding["build_id"] != build_id
        or product_binding["release_artifact_sha256"] != artifact_sha256
        or product_binding["status"] != status
    ):
        raise ComponentPopulationError("product/build binding status is invalid")
    discovery = _validate_discovery(value["discovery"])
    reconciliation = value["reconciliation"]
    if not isinstance(reconciliation, dict) or reconciliation.get("population_item_count") != len(discovery["items"]):
        raise ComponentPopulationError("component reconciliation count mismatch")
    recomputed = reconcile_component_population(
        discovery["items"],
        cyclonedx_projection,
        discovery.get("discovery_issues", []),
        product_binding["product_name"],
    )
    if reconciliation != recomputed:
        raise ComponentPopulationError("component reconciliation does not rederive")
    identity = {
        "population_profile": value["population_profile"],
        "source_binding": value["source_binding"],
        "sbom_binding": value["sbom_binding"],
        "product_build_binding": product_binding,
        "discovery": discovery,
        "reconciliation": reconciliation,
    }
    digest = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    if value["population_sha256"] != digest:
        raise ComponentPopulationError("component population SHA-256 mismatch")
    return {
        "population_sha256": digest,
        "item_count": len(discovery["items"]),
        "matched_item_count": reconciliation["matched_item_count"],
        "unmatched_item_count": reconciliation["unmatched_item_count"],
        "ambiguous_item_count": reconciliation["ambiguous_item_count"],
        "root_identity_hold_item_count": reconciliation[
            "root_identity_hold_item_count"
        ],
        "gate": reconciliation["gate"],
        "build_binding_status": value["product_build_binding"]["status"],
    }
