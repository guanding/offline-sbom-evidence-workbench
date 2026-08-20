from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.component_population import (
    ComponentPopulationError,
    build_component_population,
    validate_component_population,
)
from sbom_workbench.manifest import build_bounded_exact_set_manifest


def _manifest(root: Path) -> dict[str, object]:
    return build_bounded_exact_set_manifest(
        root,
        "euvd-source-snapshot",
        max_files=1000,
        max_total_bytes=16 * 1024 * 1024,
        max_single_file_bytes=8 * 1024 * 1024,
        max_depth=16,
    )


def _projection(
    components: list[dict[str, object]],
    *,
    root_name: str = "demo-product",
) -> dict[str, object]:
    return {
        "document": {"bom_format": "CycloneDX", "spec_version": "1.6"},
        "metadata": {
            "component": {
                "bom_ref": "pkg:generic/demo-product@1.0.0",
                "type": "application",
                "group": None,
                "name": root_name,
                "version": "1.0.0",
                "purl": "pkg:generic/demo-product@1.0.0",
            }
        },
        "components": components,
        "semantic_sha256": "1" * 64,
        "source_sha256": "2" * 64,
    }


class ComponentPopulationTests(unittest.TestCase):
    def test_python_names_are_normalized_and_reconciled_without_claiming_completeness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[project]\nname="demo-product"\nversion="1.0.0"\n'
                'dependencies=["Requests==2.32.4"]\n',
                encoding="utf-8",
            )
            population = build_component_population(
                root,
                _manifest(root),
                _projection(
                    [
                        {
                            "bom_ref": "pkg:pypi/requests@2.32.4",
                            "type": "library",
                            "group": None,
                            "name": "requests",
                            "version": "2.32.4",
                            "purl": "pkg:pypi/requests@2.32.4",
                        }
                    ]
                ),
                product_name="demo-product",
                declared_version="1.0.0",
            )
        self.assertEqual(population["discovery"]["item_count"], 2)
        self.assertEqual(population["reconciliation"]["matched_item_count"], 2)
        self.assertEqual(
            population["reconciliation"]["gate"],
            "OPEN_REVIEW_SINGLE_SOURCE_DECLARATION_SCOPE",
        )
        self.assertEqual(
            population["reconciliation"]["release_quality_handoff"],
            "BLOCKED_SINGLE_SOURCE_ONLY",
        )
        self.assertEqual(
            population["product_build_binding"]["status"],
            "SOURCE_ONLY_NO_BUILD_OR_RELEASE_ARTIFACT_BINDING",
        )

    def test_nested_multi_ecosystem_manifests_form_one_item_level_population(self) -> None:
        files = {
            "go/go.mod": "module example.test/app\nrequire example.test/dep v1.2.3\n",
            "rust/Cargo.toml": '[package]\nname="rust-app"\nversion="1.0.0"\n'
            '[dependencies]\nserde="1"\n',
            "web/package.json": '{"name":"web-app","dependencies":{"react":"19.0.0"}}',
            "php/composer.json": '{"name":"acme/app","require":{"slim/slim":"^4"}}',
            "java/pom.xml": (
                "<project><groupId>org.example</groupId><artifactId>java-app</artifactId>"
                "<version>1</version><dependencies><dependency><groupId>org.slf4j</groupId>"
                "<artifactId>slf4j-api</artifactId><version>2</version></dependency>"
                "</dependencies></project>"
            ),
            "dotnet/App.csproj": (
                '<Project><ItemGroup><PackageReference Include="Serilog" Version="4.0.0" />'
                "</ItemGroup></Project>"
            ),
            "python/requirements-prod.txt": "Flask==3.1.2\n",
            "cpp/vcpkg.json": '{"name":"cpp-app","dependencies":["fmt"]}',
            "zephyr/west.yml": "manifest:\n  projects:\n    - name: zephyr\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="multi",
                declared_version="1",
            )
        observed = {
            (item["ecosystem"], item["normalized_name"])
            for item in population["discovery"]["items"]
        }
        for expected in {
            ("go", "example.test/dep"),
            ("rust", "serde"),
            ("node", "react"),
            ("composer", "slim/slim"),
            ("maven", "org.slf4j:slf4j-api"),
            ("dotnet", "serilog"),
            ("python", "flask"),
            ("c-cpp", "fmt"),
            ("zephyr-west", "zephyr"),
        }:
            self.assertIn(expected, observed)
        self.assertEqual(population["discovery"]["discovery_issues"], [])
        self.assertEqual(
            population["reconciliation"]["gate"], "HOLD_UNMATCHED_DECLARATIONS"
        )

    def test_same_name_in_different_ecosystem_does_not_cross_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "package.json").write_text(
                '{"dependencies":{"requests":"1.0.0"}}', encoding="utf-8"
            )
            population = build_component_population(
                root,
                _manifest(root),
                _projection(
                    [
                        {
                            "bom_ref": "pkg:pypi/requests@1.0.0",
                            "type": "library",
                            "group": None,
                            "name": "requests",
                            "version": "1.0.0",
                            "purl": "pkg:pypi/requests@1.0.0",
                        }
                    ]
                ),
                product_name="demo",
                declared_version="1",
            )
        self.assertEqual(population["reconciliation"]["matched_item_count"], 0)
        self.assertEqual(population["reconciliation"]["unmatched_item_count"], 1)

    def test_maven_project_properties_are_resolved_before_matching(self) -> None:
        pom = (
            "<project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId>"
            "<version>1</version></parent><artifactId>app</artifactId>"
            "<properties><core.version>2.0.0</core.version></properties><dependencies>"
            "<dependency><groupId>${project.groupId}</groupId><artifactId>core</artifactId>"
            "<version>${core.version}</version></dependency></dependencies></project>"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pom.xml").write_text(pom, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection(
                    [
                        {
                            "bom_ref": "pkg:maven/com.acme/core@2.0.0",
                            "type": "library",
                            "group": "com.acme",
                            "name": "core",
                            "version": "2.0.0",
                            "purl": "pkg:maven/com.acme/core@2.0.0",
                        }
                    ],
                    root_name="app",
                ),
                product_name="app",
                declared_version="1",
            )
        dependency = next(
            item
            for item in population["discovery"]["items"]
            if item["normalized_name"] == "com.acme:core"
        )
        reconciliation = next(
            item
            for item in population["reconciliation"]["items"]
            if item["population_id"] == dependency["population_id"]
        )
        self.assertEqual(dependency["version_specifiers"], ["2.0.0"])
        self.assertEqual(reconciliation["match_status"], "MATCHED_NAME_AND_ECOSYSTEM")

    def test_contextual_scopes_distinguish_platform_test_and_documentation_inputs(self) -> None:
        files = {
            "composer.json": '{"require":{"php":"^8.3","ext-json":"*"}}',
            "tests/App.Tests.csproj": (
                '<Project><ItemGroup><PackageReference Include="xunit" Version="2.9.0" />'
                "</ItemGroup></Project>"
            ),
            "docs/requirements.txt": "Sphinx==8.0.0\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="demo",
                declared_version="1",
            )
        scopes = {
            (item["ecosystem"], item["normalized_name"]): item["dependency_scopes"]
            for item in population["discovery"]["items"]
        }
        self.assertEqual(scopes[("composer", "php")], ["platform"])
        self.assertEqual(scopes[("composer", "ext-json")], ["platform"])
        self.assertEqual(scopes[("dotnet", "xunit")], ["test"])
        self.assertEqual(scopes[("python", "sphinx")], ["development"])

    def test_pnpm_lock_keeps_multiple_resolved_versions_as_distinct_items(self) -> None:
        lock = (
            "lockfileVersion: '9.0'\npackages:\n\n"
            "  'ansi-styles@4.3.0':\n    resolution: {integrity: one}\n"
            "  'ansi-styles@6.2.1(peer-lib@3.0.0)':\n    resolution: {integrity: two}\n"
        )
        components = [
            {
                "bom_ref": f"pkg:npm/ansi-styles@{version}",
                "type": "library",
                "group": None,
                "name": "ansi-styles",
                "version": version,
                "purl": f"pkg:npm/ansi-styles@{version}",
            }
            for version in ("4.3.0", "6.2.1")
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pnpm-lock.yaml").write_text(lock, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection(components),
                product_name="demo",
                declared_version="1",
            )
        items = population["discovery"]["items"]
        self.assertEqual(len(items), 2)
        self.assertEqual(
            {item["identity_version"] for item in items}, {"4.3.0", "6.2.1"}
        )
        self.assertEqual(
            {item["population_role"] for item in items}, {"RESOLVED_COMPONENT"}
        )
        self.assertEqual(population["reconciliation"]["matched_item_count"], 2)
        self.assertEqual(population["reconciliation"]["ambiguous_item_count"], 0)

    def test_gradle_catalog_is_usage_bound_and_dynamic_dsl_is_held(self) -> None:
        files = {
            "settings.gradle.kts": (
                'rootProject.name = "gradle-demo"\ninclude(":app", ":core")\n'
            ),
            "gradle/libs.versions.toml": (
                '[versions]\nokhttp = "4.12.0"\n'
                '[libraries]\nokhttp = { module = "com.squareup.okhttp3:okhttp", '
                'version.ref = "okhttp" }\njunit = "org.junit.jupiter:junit-jupiter:5.11.0"\n'
                'unused = "org.example:unused:1.0"\n'
                '[bundles]\ntesting = ["junit"]\n'
                '[plugins]\nandroid = { id = "com.android.application", version = "8.8.0" }\n'
            ),
            "app/build.gradle.kts": (
                "plugins { alias(libs.plugins.android) }\n"
                "dependencies {\n"
                "  implementation(libs.okhttp)\n"
                "  testImplementation(libs.bundles.testing)\n"
                '  implementation(project(":core"))\n'
                '  implementation("org.slf4j:slf4j-api:$slf4jVersion")\n'
                '  implementation(files("libs/local.jar"))\n'
                "}\n"
            ),
            "gradle.lockfile": "com.squareup.okhttp3:okhttp:4.12.0=runtimeClasspath\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="gradle-demo",
                declared_version="1",
            )
        items = population["discovery"]["items"]
        names = {(item["ecosystem"], item["normalized_name"]) for item in items}
        self.assertIn(("maven", "com.squareup.okhttp3:okhttp"), names)
        self.assertIn(("maven", "org.junit.jupiter:junit-jupiter"), names)
        self.assertIn(("maven", "org.slf4j:slf4j-api"), names)
        self.assertIn(("gradle-plugin", "com.android.application"), names)
        self.assertIn(("gradle-project", "core"), names)
        self.assertNotIn(("maven", "org.example:unused"), names)
        issues = population["discovery"]["discovery_issues"]
        self.assertIn(
            "GRADLE_DYNAMIC_VERSION_UNRESOLVED:app/build.gradle.kts", issues
        )
        self.assertIn(
            "GRADLE_LOCAL_FILE_DEPENDENCY_UNRESOLVED:app/build.gradle.kts", issues
        )

    def test_bazel_module_and_lock_are_parsed_without_executing_starlark(self) -> None:
        files = {
            "MODULE.bazel": (
                'module(name = "demo", version = "1.0.0")\n'
                'bazel_dep(name = "rules_python", version = "1.5.0")\n'
                'archive_override(module_name = "rules_python", urls = ["https://example.invalid/a"])\n'
            ),
            "MODULE.bazel.lock": (
                '{"lockFileVersion":21,"registryFileHashes":{'
                '"https://bcr.bazel.build/modules/rules_cc/0.0.9/MODULE.bazel":"abc"},'
                '"selectedYankedVersions":{"rules_java@7.12.0":"reason"}}'
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                (root / relative).write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="demo",
                declared_version="1",
            )
        names = {
            (item["normalized_name"], item["population_role"])
            for item in population["discovery"]["items"]
            if item["ecosystem"] == "bazel"
        }
        self.assertIn(("demo", "PROJECT_COMPONENT"), names)
        self.assertIn(("rules_python", "DECLARED_DEPENDENCY"), names)
        self.assertIn(("rules_cc", "RESOLVED_COMPONENT"), names)
        self.assertIn(("rules_java", "RESOLVED_COMPONENT"), names)
        self.assertIn(
            "BAZEL_OVERRIDE_REQUIRES_REVIEW:MODULE.bazel",
            population["discovery"]["discovery_issues"],
        )

    def test_bundler_distinguishes_direct_resolved_and_development_gems(self) -> None:
        files = {
            "Gemfile": (
                'gem "rails", "~> 8.0"\n'
                "group :development, :test do\n"
                '  gem "rspec", "~> 3.13"\n'
                "end\n"
            ),
            "demo.gemspec": (
                'spec.name = "demo"\nspec.version = "1.2.0"\n'
                'spec.add_dependency "rack", ">= 3"\n'
                'spec.add_development_dependency "rake", "~> 13"\n'
            ),
            "Gemfile.lock": (
                "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rails (8.0.2)\n      rack (>= 3.0.0)\n    rack (3.1.0)\n"
                "\nDEPENDENCIES\n  rails (~> 8.0)\n"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                (root / relative).write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="demo",
                declared_version="1.2.0",
            )
        items = population["discovery"]["items"]
        rspec = next(item for item in items if item["normalized_name"] == "rspec")
        rake = next(item for item in items if item["normalized_name"] == "rake")
        self.assertEqual(rspec["dependency_scopes"], ["development", "test"])
        self.assertEqual(rake["dependency_scopes"], ["development"])
        self.assertTrue(
            any(
                item["normalized_name"] == "rails"
                and item["population_role"] == "RESOLVED_COMPONENT"
                and item["identity_version"] == "8.0.2"
                for item in items
            )
        )

    def test_swiftpm_manifest_and_resolved_pins_form_separate_roles(self) -> None:
        files = {
            "Package.swift": (
                'let package = Package(name: "swift-demo", dependencies: [\n'
                '  .package(url: "https://github.com/apple/swift-log.git", from: "1.6.2"),\n'
                '  .package(path: "../local-package")\n])\n'
            ),
            "Package.resolved": (
                '{"version":3,"pins":[{"identity":"swift-log",'
                '"location":"https://github.com/apple/swift-log.git",'
                '"state":{"version":"1.6.3","revision":"abc"}}]}'
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                (root / relative).write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="swift-demo",
                declared_version="1",
            )
        swift_log = [
            item
            for item in population["discovery"]["items"]
            if item["normalized_name"] == "swift-log"
        ]
        self.assertEqual(
            {item["population_role"] for item in swift_log},
            {"DECLARED_DEPENDENCY", "RESOLVED_COMPONENT"},
        )
        self.assertIn(
            "SWIFTPM_LOCAL_PATH_DEPENDENCY_UNRESOLVED:Package.swift",
            population["discovery"]["discovery_issues"],
        )

    def test_path_only_scanner_root_is_a_distinct_product_identity_hold(self) -> None:
        projection = _projection([])
        projection["metadata"]["component"] = {
            "bom_ref": "scanner-path-root",
            "type": "file",
            "group": None,
            "name": "/private/tmp/acquired/tree",
            "version": None,
            "purl": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Package.swift").write_text(
                'let package = Package(name: "container", dependencies: [])\n',
                encoding="utf-8",
            )
            population = build_component_population(
                root,
                _manifest(root),
                projection,
                product_name="container",
                declared_version="1",
            )
        reconciliation = population["reconciliation"]
        self.assertEqual(reconciliation["unmatched_item_count"], 0)
        self.assertEqual(reconciliation["root_identity_hold_item_count"], 1)
        self.assertEqual(reconciliation["gate"], "HOLD_SBOM_ROOT_IDENTITY")
        project = next(
            item
            for item in reconciliation["items"]
            if item["population_role"] == "PROJECT_COMPONENT"
        )
        self.assertEqual(project["match_status"], "SBOM_ROOT_IDENTITY_NOT_STABLE")

    def test_dotnet_central_versions_bind_only_actual_project_references(self) -> None:
        files = {
            "Directory.Packages.props": (
                "<Project><PropertyGroup><SerilogVersion>4.1.0</SerilogVersion></PropertyGroup>"
                '<ItemGroup><PackageVersion Include="Serilog" Version="$(SerilogVersion)" />'
                '<PackageVersion Include="Unused.Package" Version="9.9.9" />'
                '<GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.7.115" />'
                "</ItemGroup></Project>"
            ),
            "src/App.csproj": (
                '<Project><PropertyGroup><AssemblyName>App</AssemblyName></PropertyGroup>'
                '<ItemGroup><PackageReference Include="Serilog" /></ItemGroup></Project>'
            ),
            "src/packages.lock.json": (
                '{"version":2,"dependencies":{"net9.0":{'
                '"Serilog":{"type":"Direct","requested":"[4.1.0, )","resolved":"4.1.0"},'
                '"System.Memory":{"type":"Transitive","resolved":"4.6.0"}}}}'
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="App",
                declared_version="1",
            )
        items = population["discovery"]["items"]
        names = {(item["normalized_name"], item["population_role"]) for item in items}
        self.assertIn(("serilog", "DECLARED_DEPENDENCY"), names)
        self.assertIn(("serilog", "RESOLVED_COMPONENT"), names)
        self.assertIn(("system.memory", "RESOLVED_COMPONENT"), names)
        self.assertIn(("nerdbank.gitversioning", "DECLARED_DEPENDENCY"), names)
        self.assertFalse(any(item["normalized_name"] == "unused.package" for item in items))
        serilog_declared = next(
            item
            for item in items
            if item["normalized_name"] == "serilog"
            and item["population_role"] == "DECLARED_DEPENDENCY"
        )
        self.assertIn("4.1.0", serilog_declared["version_specifiers"])

    def test_esp_idf_manifests_preserve_direct_resolved_and_local_review(self) -> None:
        files = {
            "components/demo/idf_component.yml": (
                "dependencies:\n"
                '  idf: ">=5.2"\n'
                "  espressif/esp_lcd_touch:\n    version: \"^1.1.0\"\n"
                "  local/component:\n    path: ../local\n"
            ),
            "dependencies.lock": (
                "dependencies:\n"
                "  espressif/esp_lcd_touch:\n    version: 1.1.2\n"
                "  idf:\n    version: 5.3.0\n"
                "direct_dependencies:\n  - espressif/esp_lcd_touch\n"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="demo",
                declared_version="1",
            )
        items = population["discovery"]["items"]
        touch = [
            item
            for item in items
            if item["normalized_name"] == "espressif/esp_lcd_touch"
        ]
        self.assertEqual(
            {item["population_role"] for item in touch},
            {"DECLARED_DEPENDENCY", "RESOLVED_COMPONENT"},
        )
        idf_items = [item for item in items if item["normalized_name"] == "idf"]
        self.assertTrue(all(item["dependency_scopes"] == ["platform"] for item in idf_items))
        self.assertIn(
            "ESP_IDF_LOCAL_DEPENDENCY_REQUIRES_REVIEW:components/demo/idf_component.yml",
            population["discovery"]["discovery_issues"],
        )

    def test_invalid_new_ecosystem_locks_fail_closed_without_code_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "MODULE.bazel.lock").write_text("not-json", encoding="utf-8")
            (root / "build.gradle.kts").write_text(
                "implementation(project.findProperty(\"dependency\"))\n",
                encoding="utf-8",
            )
            population = build_component_population(
                root,
                _manifest(root),
                _projection([]),
                product_name="invalid",
                declared_version="1",
            )
        self.assertEqual(
            population["reconciliation"]["gate"], "HOLD_DISCOVERY_INCOMPLETE"
        )
        self.assertIn(
            "MANIFEST_PARSE_FAILED:MODULE.bazel.lock",
            population["discovery"]["discovery_issues"],
        )
        self.assertIn(
            "GRADLE_DYNAMIC_DECLARATION_UNRESOLVED:build.gradle.kts",
            population["discovery"]["discovery_issues"],
        )

    def test_build_id_and_release_hash_are_an_atomic_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ComponentPopulationError,
                "must be declared together",
            ):
                build_component_population(
                    root,
                    _manifest(root),
                    _projection([]),
                    product_name="demo",
                    declared_version="1",
                    build_id="build-1",
                )

    def test_validation_rederives_reconciliation_and_population_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
            manifest = _manifest(root)
            projection = _projection([])
            population = build_component_population(
                root,
                manifest,
                projection,
                product_name="demo",
                declared_version="1",
            )
        validation = validate_component_population(
            population,
            source_manifest=manifest,
            cyclonedx_projection=projection,
        )
        self.assertEqual(validation["unmatched_item_count"], 1)
        forged = copy.deepcopy(population)
        forged["reconciliation"]["matched_item_count"] = 1
        with self.assertRaisesRegex(
            ComponentPopulationError,
            "reconciliation does not rederive",
        ):
            validate_component_population(
                forged,
                source_manifest=manifest,
                cyclonedx_projection=projection,
            )


if __name__ == "__main__":
    unittest.main()
