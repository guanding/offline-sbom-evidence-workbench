from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sbom_workbench.yocto as yocto_module
from sbom_workbench.manifest import canonical_json_bytes
from sbom_workbench.validation import SPDX_CONTEXT_URI
from sbom_workbench.yocto import (
    CLASSIFICATION,
    PRODUCT_STATUS,
    YoctoReferenceError,
    analyze_reference,
    diff_references,
    export_reference_pair,
    load_profile_registry,
    validate_reference_profile,
    verify_reference_graph,
)


PROJECT = Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_rootfs_identity(profile: dict[str, object], root: Path) -> None:
    payload = next(item for item in profile["payloads"] if item["role"] == "rootfs_archive")
    payload["sha256"] = _sha(root / "rootfs.tar")
    payload["max_bytes"] = max(1024, (root / "rootfs.tar").stat().st_size + 32)


def _make_tar(path: Path, content: bytes, *, traversal: bool = False) -> None:
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("../escape" if traversal else "usr/bin/demo")
        member.size = len(content)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(content))
        if not traversal:
            link = tarfile.TarInfo("usr/bin/demo-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/usr/bin/demo"
            archive.addfile(link)


def _fixture(root: Path, *, version: str = "1.0-r0", build_timestamp: str = "20260102030405", traversal: bool = False) -> dict[str, object]:
    content = f"demo-{version}\n".encode()
    content_sha = hashlib.sha256(content).hexdigest()
    archive_path = root / "rootfs.tar"
    _make_tar(archive_path, content, traversal=traversal)

    spdx = {
        "@context": SPDX_CONTEXT_URI,
        "@graph": [
            {
                "spdxId": "urn:spdx:root-archive",
                "type": "software_Package",
                "name": "core-image-minimal",
                "software_primaryPurpose": "archive",
                "software_packageVersion": "1.0",
            },
            {
                "spdxId": "urn:spdx:demo",
                "type": "software_Package",
                "name": "demo",
                "software_primaryPurpose": "install",
                "software_packageVersion": version.split("-", 1)[0],
                "software_packageUrl": f"pkg:yocto/core/demo@{version.split('-', 1)[0]}",
            },
            {
                "spdxId": "urn:spdx:file-demo",
                "type": "software_File",
                "name": "usr/bin/demo",
                "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": content_sha}],
            },
            {
                "spdxId": "urn:spdx:root-files",
                "type": "Relationship",
                "relationshipType": "contains",
                "from": "urn:spdx:root-archive",
                "to": ["urn:spdx:file-demo"],
            },
            {
                "spdxId": "urn:spdx:package-files",
                "type": "Relationship",
                "relationshipType": "contains",
                "from": "urn:spdx:demo",
                "to": ["urn:spdx:file-demo"],
            },
        ],
    }
    _write_json(root / "build.spdx.json", spdx)
    (root / "image.manifest").write_text(f"demo cortexa57 {version}\n", encoding="utf-8")
    release_timestamp = (
        f"{build_timestamp[0:4]}-{build_timestamp[4:6]}-{build_timestamp[6:8]}T"
        f"{build_timestamp[8:10]}:{build_timestamp[10:12]}:{build_timestamp[12:14]}Z"
    )
    build_id = f"core-image-minimal-qemuarm64.rootfs-{build_timestamp}"
    testdata = {
        "MACHINE": "qemuarm64",
        "TARGET_SYS": "aarch64-poky-linux",
        "IMAGE_BASENAME": "core-image-minimal",
        "BUILDNAME": build_timestamp,
        "DATETIME": build_timestamp,
        "DISTRO_VERSION": "6.0.2",
        "IMAGE_NAME": build_id,
        "METADATA_REVISION": "1" * 40,
    }
    _write_json(root / "image.testdata.json", testdata)
    (root / "image.qemuboot.conf").write_text(
        "[config_bsp]\n"
        "machine = qemuarm64\n"
        f"image_name = {build_id}\n"
        "image_link_name = core-image-minimal-qemuarm64.rootfs\n"
        "tune_arch = aarch64\n",
        encoding="utf-8",
    )

    role_files = {
        "build_spdx": ("build.spdx.json", "application/ld+json"),
        "rootfs_archive": ("rootfs.tar", "application/x-tar"),
        "image_manifest": ("image.manifest", "text/plain"),
        "testdata": ("image.testdata.json", "application/json"),
        "qemuboot": ("image.qemuboot.conf", "text/plain"),
    }
    payloads = []
    for role, (filename, media_type) in role_files.items():
        payloads.append(
            {
                "role": role,
                "url": f"https://downloads.yoctoproject.org/test/{filename}",
                "relative_path": filename,
                "sha256": _sha(root / filename),
                "max_bytes": max(1024, (root / filename).stat().st_size + 32),
                "media_type": media_type,
            }
        )
    return {
        "profile_id": f"test-{build_timestamp}",
        "classification": CLASSIFICATION,
        "reference": {
            "upstream_release": "yocto-6.0.2",
            "release_notes_url": "https://downloads.yoctoproject.org/releases/yocto/yocto-6.0.2/RELEASENOTES",
            "source_revisions": {
                "openembedded_core": "1" * 40,
                "bitbake": "2" * 40,
                "meta_yocto": "3" * 40,
            },
            "image_name": "core-image-minimal",
            "machine": "qemuarm64",
            "architecture": "aarch64-poky-linux",
            "build_timestamp": build_timestamp,
            "build_id": build_id,
            "reference_builder": "Public reference builder",
            "release_timestamp": release_timestamp,
        },
        "lanes": {
            "build_metadata": {
                "lane_id": "build-lane",
                "adapter_id": "yocto-spdx-3.0.1-build-metadata",
                "independence_domain": "BUILD_METADATA",
            },
            "artifact_observation": {
                "lane_id": "artifact-lane",
                "adapter_id": "rootfs-tar-artifact-observation",
                "independence_domain": "ARTIFACT_OBSERVATION",
            },
        },
        "payloads": payloads,
        "scope": {
            "included": ["INSTALLED_PACKAGES", "ROOTFS_REGULAR_FILES", "ROOTFS_SYMLINKS"],
            "declared_exclusions": ["SEPARATE_KERNEL_AND_MODULE_ARTIFACTS"],
            "blindspots": ["NO_CUSTOMER_OR_MANUFACTURER_CONTEXT"],
        },
        "limits": {
            "max_json_bytes": 1024 * 1024,
            "max_rootfs_files": 100,
            "max_rootfs_expanded_bytes": 1024 * 1024,
            "max_path_bytes": 4096,
            "zstd_timeout_seconds": 30,
        },
    }


class YoctoReferenceTests(unittest.TestCase):
    def test_actual_profile_registry_is_strictly_accepted(self) -> None:
        profiles = load_profile_registry(PROJECT / "datasets" / "yocto_reference_profiles.json")
        self.assertEqual(len(profiles), 2)
        self.assertEqual({item["profile_id"] for item in profiles}, {
            "yocto-6.0-core-image-minimal-qemuarm64",
            "yocto-6.0.2-core-image-minimal-qemuarm64",
        })

    def test_positive_graph_is_deterministic_and_producer_stays_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            first = analyze_reference(profile, root)
            second = analyze_reference(copy.deepcopy(profile), root)
            verification = verify_reference_graph(first, profile=profile, input_root=root)

        self.assertEqual(first, second)
        self.assertEqual(first["canonical_sha256"], second["canonical_sha256"])
        self.assertEqual(first["reconciliation"]["state"], "OPEN")
        package = next(item for item in first["component_population"] if item["kind"] == "RUNTIME_PACKAGE")
        self.assertEqual(package["producer"], "UNKNOWN")
        self.assertEqual(package["critical_unknown_fields"], ["producer"])
        self.assertEqual(first["file_reconciliation"]["counts"]["MATCHED"], 1)
        self.assertEqual(first["pre7_app1_status"]["PRE-7-RQ-03-RE"], "Not Assessed")
        self.assertEqual(
            verification["status"],
            "VERIFIED_REFERENCE_GRAPH_FROM_TRUSTED_RAW_INPUTS",
        )

    def test_payload_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            (root / "image.manifest").write_text("demo cortexa57 forged\n", encoding="utf-8")
            with self.assertRaisesRegex(YoctoReferenceError, "SHA-256 mismatch"):
                analyze_reference(profile, root)

    def test_rootfs_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root, traversal=True)
            with self.assertRaisesRegex(YoctoReferenceError, "path traversal"):
                analyze_reference(profile, root)

    def test_rootfs_scan_uses_the_same_hash_verified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            replacement = root / "replacement.tar"
            with tarfile.open(replacement, "w") as archive:
                payload = b"changed\n"
                member = tarfile.TarInfo("usr/bin/demo")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
                injected = tarfile.TarInfo("etc/injected-link")
                injected.type = tarfile.SYMTYPE
                injected.linkname = "/attacker"
                archive.addfile(injected)

            original_observer = yocto_module._observe_rootfs

            def replace_after_hash(snapshot: Path, relative_path: str, limits: dict[str, int]):
                self.assertNotEqual(snapshot.resolve(), (root / "rootfs.tar").resolve())
                replacement.replace(root / "rootfs.tar")
                return original_observer(snapshot, relative_path, limits)

            with mock.patch.object(yocto_module, "_observe_rootfs", side_effect=replace_after_hash):
                graph = analyze_reference(profile, root)

        artifact_lane = next(
            lane for lane in graph["lanes"] if lane["independence_domain"] == "ARTIFACT_OBSERVATION"
        )
        self.assertEqual(
            artifact_lane["symlinks"],
            [{"path": "usr/bin/demo-link", "target": "/usr/bin/demo"}],
        )

    def test_rootfs_duplicate_hardlink_and_expansion_limit_fail_closed(self) -> None:
        with self.subTest("duplicate path"), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            with tarfile.open(root / "rootfs.tar", "w") as archive:
                for payload in (b"one", b"two"):
                    member = tarfile.TarInfo("usr/bin/demo")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            _refresh_rootfs_identity(profile, root)
            with self.assertRaisesRegex(YoctoReferenceError, "duplicate rootfs member path"):
                analyze_reference(profile, root)

        with self.subTest("hardlink"), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            with tarfile.open(root / "rootfs.tar", "w") as archive:
                payload = b"demo"
                member = tarfile.TarInfo("usr/bin/demo")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
                hardlink = tarfile.TarInfo("usr/bin/demo-hardlink")
                hardlink.type = tarfile.LNKTYPE
                hardlink.linkname = "usr/bin/demo"
                archive.addfile(hardlink)
            _refresh_rootfs_identity(profile, root)
            with self.assertRaisesRegex(YoctoReferenceError, "hardlink or special"):
                analyze_reference(profile, root)

        with self.subTest("expanded byte limit"), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            profile["limits"]["max_rootfs_expanded_bytes"] = 1
            with self.assertRaisesRegex(YoctoReferenceError, "expanded regular-file bytes"):
                analyze_reference(profile, root)

    def test_lane_domain_spoof_and_wrong_classification_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = _fixture(Path(directory))
            spoof = copy.deepcopy(profile)
            spoof["lanes"]["artifact_observation"]["independence_domain"] = "BUILD_METADATA"
            with self.assertRaisesRegex(YoctoReferenceError, "adapter/domain"):
                validate_reference_profile(spoof)
            wrong = copy.deepcopy(profile)
            wrong["classification"] = "CUSTOMER_EVIDENCE"
            with self.assertRaisesRegex(YoctoReferenceError, "classification"):
                validate_reference_profile(wrong)

    def test_tamper_breaks_canonical_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            graph = analyze_reference(profile, root)
            tampered = copy.deepcopy(graph)
            next(item for item in tampered["component_population"] if item["kind"] == "RUNTIME_PACKAGE")["version"] = "forged"
            with self.assertRaisesRegex(YoctoReferenceError, "source-derived|canonical hash"):
                verify_reference_graph(tampered, profile=profile, input_root=root)

            tampered["canonical_sha256"] = hashlib.sha256(
                canonical_json_bytes({key: value for key, value in tampered.items() if key != "canonical_sha256"})
            ).hexdigest()
            with self.assertRaisesRegex(YoctoReferenceError, "source-derived|trusted raw inputs"):
                verify_reference_graph(tampered, profile=profile, input_root=root)

    def test_candidate_exporters_preserve_binding_and_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            graph = analyze_reference(profile, root)
            pair = export_reference_pair(graph, profile=profile, input_root=root)
        self.assertEqual(pair["status"], "GENERATOR_OUTPUT_CANDIDATE")
        self.assertEqual(pair["product_conformity_status"], PRODUCT_STATUS)
        self.assertEqual(len(pair["cyclonedx"]["dependencies"]), len(graph["component_population"]))
        properties = {item["name"]: item["value"] for item in pair["cyclonedx"]["metadata"]["properties"]}
        self.assertEqual(properties["sbom-workbench:canonical-sha256"], graph["canonical_sha256"])
        document = next(item for item in pair["spdx"]["@graph"] if item.get("type") == "SpdxDocument")
        self.assertTrue(document["comment"].startswith("sbom-workbench:binding="))
        serialized = canonical_json_bytes(pair).decode("utf-8")
        self.assertIn("GENERATOR_ONLY_NOT_MANUFACTURER", serialized)
        self.assertNotIn('"manufacturer_role":', serialized)
        unknown_packages = [
            item
            for item in pair["spdx"]["@graph"]
            if item.get("type") == "software_Package" and "producer=UNKNOWN" in item.get("comment", "")
        ]
        self.assertTrue(unknown_packages)
        self.assertTrue(all("suppliedBy" not in item for item in unknown_packages))
        cdx_components = [pair["cyclonedx"]["metadata"]["component"], *pair["cyclonedx"]["components"]]
        self.assertTrue(all("publisher" not in item for item in cdx_components))

    def test_multiple_purls_keep_primary_and_alternate_in_properties(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = _fixture(root)
            graph = analyze_reference(profile, root)
            component = next(
                item
                for item in graph["component_population"]
                if any(identifier.startswith("pkg:") for identifier in item["identifiers"])
            )
            original_purl = next(
                identifier
                for identifier in component["identifiers"]
                if identifier.startswith("pkg:")
            )
            alternate_purl = "pkg:generic/multi-purl-demo@1.0"
            component["identifiers"] = [*component["identifiers"], alternate_purl]
            graph["canonical_sha256"] = yocto_module._canonical_graph_sha256(graph)
            # Exercise the export layer directly. export_reference_pair runs a
            # source-derived integrity check that (correctly) rejects any
            # post-analyze mutation; this test only validates the component_record
            # serialization of multiple purls, not graph integrity.
            cyclonedx = yocto_module._export_cyclonedx_reference(graph)

        cdx_components = [
            cyclonedx["metadata"]["component"],
            *cyclonedx["components"],
        ]
        expected_primary = min(original_purl, alternate_purl)
        target = next(
            item for item in cdx_components if item.get("purl") == expected_primary
        )
        identifier_values = [
            prop["value"]
            for prop in target["properties"]
            if prop["name"] == "sbom-workbench:identifier"
        ]
        # Both the primary purl (in the purl field) and the alternate purl
        # must survive in properties; previously sorted(purls)[0] dropped the
        # alternate, which starved downstream EUVD identity matching.
        self.assertIn(original_purl, identifier_values)
        self.assertIn(alternate_purl, identifier_values)
        self.assertEqual(target["purl"], expected_primary)

    def test_ab_diff_reflects_installed_version_update(self) -> None:
        with tempfile.TemporaryDirectory() as left_directory, tempfile.TemporaryDirectory() as right_directory:
            left_root = Path(left_directory)
            right_root = Path(right_directory)
            left = analyze_reference(_fixture(left_root, version="1.0-r0", build_timestamp="20260102030405"), left_root)
            right = analyze_reference(_fixture(right_root, version="2.0-r0", build_timestamp="20260203040506"), right_root)
        result = diff_references(left, right)
        self.assertTrue(result["update_reflected"])
        self.assertEqual(result["components"]["updated"], [{
            "logical_key": "cortexa57:demo",
            "name": "demo",
            "from_version": "1.0-r0",
            "to_version": "2.0-r0",
        }])
        self.assertEqual(len(result["files"]["modified"]), 1)


if __name__ == "__main__":
    unittest.main()
