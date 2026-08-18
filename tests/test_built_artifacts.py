from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


WHEEL_ENV = "SBOM_WORKBENCH_BUILT_WHEEL"
SDIST_ENV = "SBOM_WORKBENCH_BUILT_SDIST"
ASSET_PREFIXES = ("schemas/", "datasets/", "fixtures/synthetic_orion/")
REPRODUCIBLE_EPOCH = 315532800
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _approved_assets() -> tuple[bytes, dict[str, str]]:
    manifest_path = Path(__file__).resolve().parents[1] / "release" / "project_owned_assets.sha256"
    payload = manifest_path.read_bytes()
    approved: dict[str, str] = {}
    for line in payload.decode("utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        approved[relative] = digest
    return payload, approved


def _configured_artifact(environment_name: str) -> Path | None:
    value = os.environ.get(environment_name)
    return Path(value).resolve(strict=True) if value else None


class BuiltArtifactTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get(WHEEL_ENV), f"set {WHEEL_ENV} to test an already-built wheel")
    def test_installed_wheel_smoke_and_public_data_boundary(self) -> None:
        wheel = _configured_artifact(WHEEL_ENV)
        assert wheel is not None
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            self.assertTrue(all(item.date_time == ZIP_EPOCH for item in archive.infolist()))
            approved_manifest, approved_assets = _approved_assets()
            manifest_members = [
                name
                for name in names
                if name.endswith(
                    "share/offline-sbom-evidence-workbench/release/project_owned_assets.sha256"
                )
            ]
            self.assertEqual(len(manifest_members), 1)
            self.assertEqual(archive.read(manifest_members[0]), approved_manifest)
            marker = "share/offline-sbom-evidence-workbench/"
            actual_assets = {
                name.split(marker, 1)[1]: hashlib.sha256(archive.read(name)).hexdigest()
                for name in names
                if marker in name
                and name.split(marker, 1)[1].startswith(ASSET_PREFIXES)
            }
            self.assertEqual(actual_assets, approved_assets)
        required_suffixes = {
            "share/offline-sbom-evidence-workbench/schemas/synthetic-candidate.schema.json",
            "share/offline-sbom-evidence-workbench/datasets/runtime_registry.json",
            "share/offline-sbom-evidence-workbench/fixtures/synthetic_orion/release-a/artifacts/orion-bundle.tar",
        }
        for suffix in required_suffixes:
            self.assertTrue(any(name.endswith(suffix) for name in names), suffix)
        self.assertFalse(any("vendor/specs" in name or name.endswith("SOURCE_MANIFEST.json") for name in names))
        self.assertTrue(any(name.endswith(".dist-info/licenses/LICENSE") for name in names))
        self.assertTrue(any(name.endswith(".dist-info/licenses/NOTICE") for name in names))
        self.assertTrue(
            any(name.endswith(".dist-info/licenses/THIRD_PARTY_NOTICES.md") for name in names)
        )
        self.assertEqual(
            sum(
                name.endswith(
                    "share/offline-sbom-evidence-workbench/release/rights_review.json"
                )
                for name in names
            ),
            1,
        )

        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            target = root / "installed"
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["UV_CACHE_DIR"] = str(root / "uv-cache")
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--offline",
                    "--no-deps",
                    "--python",
                    sys.executable,
                    "--target",
                    str(target),
                    str(wheel),
                ],
                check=True,
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            smoke_environment = environment.copy()
            smoke_environment["PYTHONPATH"] = str(target)
            for name in (
                "SBOM_WORKBENCH_PROJECT_ROOT",
                "SBOM_WORKBENCH_DATA_ROOT",
                "SBOM_WORKBENCH_VENDOR_SPECS_ROOT",
            ):
                smoke_environment.pop(name, None)
            smoke = """
import json
from pathlib import Path
import sbom_workbench
from sbom_workbench.candidate import default_candidate_schema
from sbom_workbench.resources import data_root
from sbom_workbench.validation import SbomValidationError, default_spec_root

target = Path(__import__('os').environ['PYTHONPATH']).resolve()
assert Path(sbom_workbench.__file__).resolve().is_relative_to(target)
assert sbom_workbench.__version__ == '0.5.0-rc.1'
root = data_root()
assert (root / 'datasets' / 'runtime_registry.json').is_file()
assert default_candidate_schema().is_file()
try:
    default_spec_root()
except SbomValidationError as exc:
    assert 'not distributed' in str(exc) and 'BYO' in str(exc)
else:
    raise AssertionError('installed public wheel silently found vendor specs')
print(json.dumps({'version': sbom_workbench.__version__, 'data_root': str(root)}))
"""
            completed = subprocess.run(
                [sys.executable, "-B", "-c", smoke],
                check=True,
                cwd=root,
                env=smoke_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertIn('"version": "0.5.0-rc.1"', completed.stdout)

    @unittest.skipUnless(os.environ.get(SDIST_ENV), f"set {SDIST_ENV} to test an already-built sdist")
    def test_sdist_contains_public_data_and_excludes_vendor_specs(self) -> None:
        sdist = _configured_artifact(SDIST_ENV)
        assert sdist is not None
        gzip_header = sdist.read_bytes()[:10]
        self.assertEqual(gzip_header[:2], b"\x1f\x8b")
        self.assertEqual(struct.unpack("<I", gzip_header[4:8])[0], REPRODUCIBLE_EPOCH)
        with tarfile.open(sdist, "r:gz") as archive:
            names = set(archive.getnames())
            for member in archive.getmembers():
                self.assertEqual((member.uid, member.gid), (0, 0), member.name)
                self.assertEqual((member.uname, member.gname), ("", ""), member.name)
                self.assertEqual(member.mtime, REPRODUCIBLE_EPOCH, member.name)
            approved_manifest, approved_assets = _approved_assets()
            manifest_members = [
                name for name in names if name.endswith("/release/project_owned_assets.sha256")
            ]
            self.assertEqual(len(manifest_members), 1)
            manifest_handle = archive.extractfile(manifest_members[0])
            assert manifest_handle is not None
            self.assertEqual(manifest_handle.read(), approved_manifest)
            actual_assets: dict[str, str] = {}
            for member in archive.getmembers():
                relative = member.name.split("/", 1)[1] if "/" in member.name else ""
                if not member.isfile() or not relative.startswith(ASSET_PREFIXES):
                    continue
                handle = archive.extractfile(member)
                assert handle is not None
                actual_assets[relative] = hashlib.sha256(handle.read()).hexdigest()
            self.assertEqual(actual_assets, approved_assets)
        required_suffixes = {
            "/schemas/synthetic-candidate.schema.json",
            "/datasets/runtime_registry.json",
            "/fixtures/synthetic_orion/release-a/artifacts/orion-bundle.tar",
        }
        for suffix in required_suffixes:
            self.assertTrue(any(name.endswith(suffix) for name in names), suffix)
        self.assertFalse(any("/vendor/specs/" in name or name.endswith("/vendor/specs") for name in names))
        required_docs = {
            "/CHANGELOG.md",
            "/LICENSE",
            "/NOTICE",
            "/THIRD_PARTY_NOTICES.md",
            "/PUBLIC_RELEASE_CHECKLIST.md",
            "/RELEASE_PROCESS.md",
            "/SECURITY.md",
            "/docs/SYNTHETIC_MVP_ACCEPTANCE.md",
            "/docs/USER_GUIDE.md",
            "/release/check_public_links.py",
            "/release/project_owned_assets.sha256",
            "/release/rights_review.json",
        }
        for suffix in required_docs:
            self.assertTrue(any(name.endswith(suffix) for name in names), suffix)

        checker = Path(__file__).resolve().parents[1] / "release" / "check_public_links.py"
        with tempfile.TemporaryDirectory() as directory_name:
            extraction_root = Path(directory_name)
            with tarfile.open(sdist, "r:gz") as archive:
                archive.extractall(extraction_root, filter="data")
            roots = [path for path in extraction_root.iterdir() if path.is_dir()]
            self.assertEqual(len(roots), 1)
            subprocess.run(
                [sys.executable, "-B", str(checker), str(roots[0])],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
