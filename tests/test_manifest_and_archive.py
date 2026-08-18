from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.acquire import (
    AcquisitionError,
    _reject_lfs_pointers,
    registry_entry_hash,
    safe_extract_tar,
    verify_acquisition,
)
from sbom_workbench.manifest import (
    ManifestError,
    build_exact_set_manifest,
    canonical_json_bytes,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]


class ManifestTests(unittest.TestCase):
    def test_manifest_is_deterministic_across_roots(self) -> None:
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = Path(first_name)
            second = Path(second_name)
            for root in (first, second):
                (root / "nested").mkdir()
                (root / "nested" / "b.txt").write_text("beta\n", encoding="utf-8")
                (root / "a.txt").write_text("alpha\n", encoding="utf-8")
            first_manifest = build_exact_set_manifest(first, "fixture@1")
            second_manifest = build_exact_set_manifest(second, "fixture@1")
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual([item["relative_path"] for item in first_manifest["files"]], ["a.txt", "nested/b.txt"])

    def test_manifest_rejects_symlink(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unsupported")
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "inside.txt").write_text("value", encoding="utf-8")
            (root / "link.txt").symlink_to("inside.txt")
            with self.assertRaisesRegex(ManifestError, "non-regular file"):
                build_exact_set_manifest(root, "fixture@1")

    def test_manifest_rejects_symlink_root(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unsupported")
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            real_root = root / "real"
            real_root.mkdir()
            symlink_root = root / "root-link"
            symlink_root.symlink_to(real_root, target_is_directory=True)
            with self.assertRaisesRegex(ManifestError, "manifest root must not be a symlink"):
                build_exact_set_manifest(symlink_root, "fixture@1")

    def test_manifest_rejects_hard_linked_file(self) -> None:
        if not hasattr(os, "link"):
            self.skipTest("hard links unsupported")
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "first.txt").write_text("same inode\n", encoding="utf-8")
            os.link(root / "first.txt", root / "second.txt")
            with self.assertRaisesRegex(ManifestError, "hard-linked file"):
                build_exact_set_manifest(root, "fixture@1")


class SafeArchiveTests(unittest.TestCase):
    def _archive(self, path: Path, member: tarfile.TarInfo, payload: bytes = b"") -> None:
        with tarfile.open(path, "w") as bundle:
            bundle.addfile(member, io.BytesIO(payload) if member.isreg() else None)

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "bad.tar"
            member = tarfile.TarInfo("../escape.txt")
            member.size = 4
            self._archive(archive, member, b"nope")
            with self.assertRaisesRegex(AcquisitionError, "unsafe archive path"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=100)
            self.assertFalse((root / "out").exists())

    def test_rejects_symlink_entry(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "link.tar"
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            self._archive(archive, member)
            with self.assertRaisesRegex(AcquisitionError, "unsupported archive entry type"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=100)

    def test_rejects_hardlink_entry(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "hardlink.tar"
            member = tarfile.TarInfo("hardlink")
            member.type = tarfile.LNKTYPE
            member.linkname = "target"
            self._archive(archive, member)
            with self.assertRaisesRegex(AcquisitionError, "unsupported archive entry type"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=100)

    def test_rejects_duplicate_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "duplicate.tar"
            with tarfile.open(archive, "w") as bundle:
                for payload in (b"first", b"second"):
                    member = tarfile.TarInfo("duplicate.txt")
                    member.size = len(payload)
                    bundle.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(AcquisitionError, "duplicate archive path"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=100)

    def test_rejects_noncanonical_archive_paths(self) -> None:
        for index, member_name in enumerate(("a//b.txt", "a/./b.txt", "a\\b.txt")):
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as root_name:
                root = Path(root_name)
                archive = root / f"noncanonical-{index}.tar"
                member = tarfile.TarInfo(member_name)
                member.size = 1
                self._archive(archive, member, b"x")
                with self.assertRaisesRegex(AcquisitionError, "unsafe archive path"):
                    safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=100)

    def test_rejects_truncated_archive(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "truncated.tar"
            member = tarfile.TarInfo("payload.bin")
            member.size = 4096
            self._archive(archive, member, b"x" * member.size)
            archive.write_bytes(archive.read_bytes()[:600])
            with self.assertRaisesRegex(AcquisitionError, "archive extraction failed"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=10_000)

    def test_enforces_expanded_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            archive = root / "large.tar"
            member = tarfile.TarInfo("large.bin")
            member.size = 5
            self._archive(archive, member, b"12345")
            with self.assertRaisesRegex(AcquisitionError, "expanded-size"):
                safe_extract_tar(archive, root / "out", max_files=10, max_total_bytes=4)

    def test_rejects_crlf_git_lfs_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            pointer = (
                b"version https://git-lfs.github.com/spec/v1\r\n"
                b"oid sha256:" + b"a" * 64 + b"\r\nsize 123\r\n"
            )
            (root / "large.bin").write_bytes(pointer)
            manifest = build_exact_set_manifest(root, "fixture@1")
            with self.assertRaisesRegex(AcquisitionError, "Git LFS pointer"):
                _reject_lfs_pointers(root, manifest)


class AcquisitionVerificationTests(unittest.TestCase):
    def _write_json(self, path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def _make_package(self, root: Path) -> tuple[Path, dict[str, object], str, str]:
        registry = json.loads((ROOT / "datasets" / "source_registry.json").read_text(encoding="utf-8"))
        source = copy.deepcopy(registry["sources"][0])
        commit = "1" * 40
        source["dataset_id"] = "verification-fixture"
        source["root_id"] = f"verification-fixture@{commit}"
        source["name"] = "Consumer verification fixture"
        source["lineage_group"] = "verification-fixture"
        source["pin"].update(
            {
                "ref_type": "commit",
                "ref_name": commit,
                "resolved_commit": commit,
                "tag_object": None,
                "acquisition_artifact_sha256": None,
            }
        )

        target = root / "package"
        tree = target / "tree"
        tree.mkdir(parents=True)
        license_payload = b"test-only license evidence\n"
        (tree / "LICENSE").write_bytes(license_payload)
        license_sha256 = hashlib.sha256(license_payload).hexdigest()
        source["license"]["evidence_paths"] = ["LICENSE"]
        source["license"]["evidence_hashes"] = {"LICENSE": license_sha256}
        source["governance"]["acquisition_status"] = "ACQUIRED_UNSEALED"

        registry_sha256 = "2" * 64
        tree_manifest = build_exact_set_manifest(tree, source["root_id"])
        report = {
            "schema_version": "1.1",
            "acquisition_status": "ACQUIRED_UNSEALED",
            "acquired_at_utc": "2026-08-02T00:00:00Z",
            "dataset_id": source["dataset_id"],
            "source_url": source["upstream_url"],
            "resolved_source_ips": ["8.8.8.8"],
            "registry_sha256": registry_sha256,
            "registry_entry_sha256": registry_entry_hash(source),
            "resolved_commit": commit,
            "annotated_tag_object": None,
            "git_tree_sha": "3" * 40,
            "git_archive_sha256": "4" * 64,
            "license_expression": source["license"]["expression"],
            "license_review_status": source["license"]["review_status"],
            "license_evidence": [{"relative_path": "LICENSE", "sha256": license_sha256}],
            "tool_runtime": {
                "git": {"path": "/usr/bin/git", "version": "git version test", "sha256": "5" * 64},
                "python": {"path": "/usr/bin/python3", "version": "3.test", "sha256": "6" * 64},
            },
            "tree_manifest": tree_manifest,
        }
        manifest_path = target / "acquisition_manifest.json"
        self._write_json(manifest_path, report)
        self._write_json(
            target / "COMPLETE.json",
            {"acquisition_manifest_sha256": sha256_file(manifest_path)},
        )
        return target, source, registry_sha256, sha256_file(manifest_path)

    def test_consumer_verify_rejects_tree_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            target, source, registry_sha256, manifest_sha256 = self._make_package(Path(root_name))
            verified = verify_acquisition(
                target,
                source,
                registry_sha256=registry_sha256,
                trusted_manifest_sha256=manifest_sha256,
            )
            self.assertEqual(verified["dataset_id"], source["dataset_id"])
            (target / "tree" / "LICENSE").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(AcquisitionError, "tree no longer matches"):
                verify_acquisition(
                    target,
                    source,
                    registry_sha256=registry_sha256,
                    trusted_manifest_sha256=manifest_sha256,
                )

    def test_consumer_verify_rejects_extra_top_level_file(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            target, source, registry_sha256, manifest_sha256 = self._make_package(Path(root_name))
            verify_acquisition(
                target,
                source,
                registry_sha256=registry_sha256,
                trusted_manifest_sha256=manifest_sha256,
            )
            (target / "unexpected.txt").write_text("not sealed", encoding="utf-8")
            with self.assertRaisesRegex(AcquisitionError, "unexpected top-level entry"):
                verify_acquisition(
                    target,
                    source,
                    registry_sha256=registry_sha256,
                    trusted_manifest_sha256=manifest_sha256,
                )

    def test_consumer_verify_rejects_unknown_manifest_field_even_if_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            target, source, registry_sha256, manifest_sha256 = self._make_package(Path(root_name))
            verify_acquisition(
                target,
                source,
                registry_sha256=registry_sha256,
                trusted_manifest_sha256=manifest_sha256,
            )
            manifest_path = target / "acquisition_manifest.json"
            report = json.loads(manifest_path.read_text(encoding="utf-8"))
            report["unreviewed_override"] = True
            self._write_json(manifest_path, report)
            self._write_json(
                target / "COMPLETE.json",
                {"acquisition_manifest_sha256": sha256_file(manifest_path)},
            )
            with self.assertRaisesRegex(AcquisitionError, "manifest fields do not match schema 1.1"):
                verify_acquisition(
                    target,
                    source,
                    registry_sha256=registry_sha256,
                    trusted_manifest_sha256=sha256_file(manifest_path),
                )

    def test_consumer_verify_rejects_malicious_reseal_without_external_anchor_update(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            target, source, registry_sha256, trusted_manifest_sha256 = self._make_package(Path(root_name))
            manifest_path = target / "acquisition_manifest.json"
            (target / "tree" / "LICENSE").write_text("attacker replacement\n", encoding="utf-8")
            report = json.loads(manifest_path.read_text(encoding="utf-8"))
            report["tree_manifest"] = build_exact_set_manifest(target / "tree", source["root_id"])
            report["license_evidence"][0]["sha256"] = sha256_file(target / "tree" / "LICENSE")
            self._write_json(manifest_path, report)
            self._write_json(
                target / "COMPLETE.json",
                {"acquisition_manifest_sha256": sha256_file(manifest_path)},
            )
            with self.assertRaisesRegex(AcquisitionError, "external trust anchor"):
                verify_acquisition(
                    target,
                    source,
                    registry_sha256=registry_sha256,
                    trusted_manifest_sha256=trusted_manifest_sha256,
                )


    def test_canonical_json_rejects_non_finite_numbers(self) -> None:
        # allow_nan=False keeps the canonical primitive deterministic across
        # JSON implementations that disagree on NaN/Infinity spelling (EVD-1).
        with self.assertRaises(ValueError):
            canonical_json_bytes({"bad": float("nan")})
        with self.assertRaises(ValueError):
            canonical_json_bytes({"bad": float("inf")})
        with self.assertRaises(ValueError):
            canonical_json_bytes({"bad": float("-inf")})


if __name__ == "__main__":
    unittest.main()
