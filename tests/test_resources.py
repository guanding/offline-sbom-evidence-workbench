from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from release.build_public_candidate import (
    INTERNAL_OBSERVATION_DATASETS,
    _license_gate,
    _project_owned_asset_gate,
    _selected_paths,
)
from release.verify_public_candidate import (
    CandidateVerificationError,
    EXPECTED_BOUNDARY,
    verify_candidate,
)
from sbom_workbench.resources import (
    DATA_ROOT_ENV,
    VENDOR_SPECS_ROOT_ENV,
    ResourceError,
    data_root,
    resource_path,
    vendor_specs_root,
)


class ResourceResolutionTests(unittest.TestCase):
    def test_checkout_public_closure_contains_runtime_and_license(self) -> None:
        root = data_root()
        self.assertTrue((root / "schemas" / "synthetic-candidate.schema.json").is_file())
        self.assertTrue((root / "datasets" / "runtime_registry.json").is_file())
        self.assertTrue(
            (root / "fixtures" / "synthetic_orion" / "release-a" / "artifacts" / "orion-bundle.tar").is_file()
        )
        project_root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            hashlib.sha256((project_root / "LICENSE").read_bytes()).hexdigest(),
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        )
        self.assertIn(
            "Copyright 2026 Ding Guan",
            (project_root / "NOTICE").read_text(encoding="utf-8").splitlines(),
        )
        metadata = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(metadata["build-system"]["requires"], ["setuptools==84.0.0"])
        self.assertEqual(metadata["project"]["license"], "Apache-2.0")
        self.assertEqual(
            metadata["project"]["license-files"],
            ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"],
        )
        review = json.loads(
            (project_root / "release" / "rights_review.json").read_text(encoding="utf-8")
        )
        project = next(item for item in review["items"] if item["id"] == "project-source-code")
        self.assertEqual(project["status"], "APPROVED")
        self.assertEqual(project["license_expression"], "Apache-2.0")
        self.assertEqual(project["copyright_holder"], "Ding Guan")
        declaration = review["project_content_declaration"]
        self.assertEqual(declaration["declarant"], "Ding Guan")
        self.assertEqual(declaration["status"], "AUTHOR_DECLARED")
        assets = next(
            item for item in review["items"] if item["id"] == "project-owned-release-assets"
        )
        self.assertEqual(assets["status"], "APPROVED")
        self.assertEqual(assets["license_expression"], "Apache-2.0")
        self.assertEqual(assets["copyright_holder"], "Ding Guan")
        self.assertEqual(
            assets["source_paths"],
            ["schemas/", "datasets/", "fixtures/synthetic_orion/"],
        )
        self.assertEqual(
            assets["asset_manifest_sha256"],
            hashlib.sha256(
                (project_root / assets["asset_manifest"]).read_bytes()
            ).hexdigest(),
        )
        self.assertIn("no customer or third-party work", assets["decision_scope"])
        self.assertIn("does not relicense referenced third-party", assets["decision_scope"])
        dependency_review = next(
            item
            for item in review["items"]
            if item["id"] == "python-build-and-actions-dependencies"
        )
        self.assertEqual(review["overall_status"], "PENDING_NAMED_REVIEW")
        self.assertEqual(dependency_review["status"], "PENDING_LICENSE_REVIEW")
        with tempfile.TemporaryDirectory() as directory_name:
            candidate = Path(directory_name)
            for name in (
                "LICENSE",
                "NOTICE",
                "THIRD_PARTY_NOTICES.md",
                "pyproject.toml",
            ):
                shutil.copy2(project_root / name, candidate / name)
            self.assertEqual(_license_gate(candidate), (True, None))
            metadata_path = candidate / "pyproject.toml"
            metadata_path.write_text(
                metadata_path.read_text(encoding="utf-8").replace(
                    'license = "Apache-2.0"',
                    'license = "MIT"',
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                _license_gate(candidate),
                (False, "LICENSE_METADATA_MISMATCH"),
            )

    def test_ci_tool_graph_is_hash_locked_and_isolated(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        direct = {
            line.strip()
            for line in (project_root / "requirements-ci.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        lock = (project_root / "requirements-ci.lock").read_text(encoding="utf-8")
        for requirement in direct:
            self.assertRegex(lock, rf"(?m)^{re.escape(requirement)}(?:\s|\\)")
        self.assertIn("--hash=sha256:", lock)
        ci = (project_root / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        security = (
            project_root / ".github" / "workflows" / "security.yml"
        ).read_text(encoding="utf-8")
        for workflow in (ci, security):
            self.assertIn("requirements-ci.lock", workflow)
            self.assertIn("--require-hashes", workflow)
            self.assertIn("${RUNNER_TEMP}/ci-tools", workflow)
        self.assertIn('uv" lock --check', ci)
        build_step = "- name: Build and scan the explicit public-source candidate"
        public_test_step = (
            "- name: Run public-source unit tests from the explicit candidate"
        )
        self.assertIn(build_step, ci)
        self.assertIn(public_test_step, ci)
        self.assertLess(ci.index(build_step), ci.index(public_test_step))
        self.assertIn(
            "working-directory: ${{ runner.temp }}/public-candidate",
            ci,
        )
        self.assertIn(
            "UV_PROJECT_ENVIRONMENT: ${{ runner.temp }}/public-candidate-venv",
            ci,
        )
        self.assertIn('uv" sync --frozen --no-install-project', ci)
        self.assertIn(
            "PYTHONPATH: ${{ runner.temp }}/public-candidate/src:"
            "${{ runner.temp }}/public-candidate",
            ci,
        )
        self.assertEqual(ci.count("release/verify_public_candidate.py"), 2)
        self.assertIn(
            'expected_license_files = ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"]',
            security,
        )

    def test_public_candidate_manifest_verification_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            candidate = Path(directory_name)
            payload = candidate / "payload.txt"
            payload.write_text("controlled payload\n", encoding="utf-8")
            status = candidate / "PUBLIC_RELEASE_STATUS.json"
            status.write_text(
                json.dumps(
                    {
                        "candidate_status": "BLOCKED_RELEASE_GATES",
                        "release_eligible": False,
                        "blocking_reasons": ["THIRD_PARTY_RIGHTS_PENDING"],
                        "source_head": "0" * 40,
                        "file_count_before_generated_metadata": 1,
                        "boundary": EXPECTED_BOUNDARY,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = candidate / "PUBLIC_RELEASE_MANIFEST.sha256"

            def write_manifest() -> None:
                rows = [
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
                    for path in (status, payload)
                ]
                manifest.write_text(
                    "\n".join(sorted(rows, key=lambda row: row.split("  ", 1)[1]))
                    + "\n",
                    encoding="utf-8",
                )

            write_manifest()
            summary = verify_candidate(candidate)
            self.assertEqual(summary["verified_file_count"], 2)
            self.assertFalse(summary["release_eligible"])

            payload.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(CandidateVerificationError, "hash mismatch"):
                verify_candidate(candidate)
            payload.write_text("controlled payload\n", encoding="utf-8")
            (candidate / "unexpected.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(CandidateVerificationError, "exact set mismatch"):
                verify_candidate(candidate)
            (candidate / "unexpected.txt").unlink()

            status_payload = status.read_text(encoding="utf-8").lstrip()
            status.write_text(
                '{"boundary": "NOT_CUSTOMER_EVIDENCE_NOT_CONFORMITY_NOT_RELEASE_APPROVAL",'
                + status_payload[1:],
                encoding="utf-8",
            )
            write_manifest()
            with self.assertRaisesRegex(CandidateVerificationError, "duplicate JSON key"):
                verify_candidate(candidate)

    def test_project_owned_asset_manifest_is_exact_and_fail_closed(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self.assertEqual(_project_owned_asset_gate(project_root), (True, None))
        with tempfile.TemporaryDirectory() as directory_name:
            candidate = Path(directory_name)
            for name in ("schemas", "datasets", "fixtures"):
                shutil.copytree(project_root / name, candidate / name)
            (candidate / "release").mkdir()
            for name in ("project_owned_assets.sha256", "rights_review.json"):
                shutil.copy2(project_root / "release" / name, candidate / "release" / name)
            registry = candidate / "datasets" / "runtime_registry.json"
            registry.write_bytes(registry.read_bytes() + b"\n")
            self.assertEqual(
                _project_owned_asset_gate(candidate),
                (False, "OWNED_ASSET_HASH_MISMATCH"),
            )
            shutil.copy2(project_root / "datasets" / registry.name, registry)
            (candidate / "datasets" / "unapproved.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                _project_owned_asset_gate(candidate),
                (False, "OWNED_ASSET_SET_MISMATCH"),
            )
            (candidate / "datasets" / "unapproved.json").unlink()
            registry.unlink()
            self.assertEqual(
                _project_owned_asset_gate(candidate),
                (False, "OWNED_ASSET_SET_MISMATCH"),
            )

    def test_internal_observation_datasets_are_excluded_from_public_artifacts(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        present = {
            relative
            for relative in INTERNAL_OBSERVATION_DATASETS
            if (project_root / relative).is_file()
        }
        self.assertIn(
            len(present),
            {0, len(INTERNAL_OBSERVATION_DATASETS)},
            "internal observation datasets must be entirely present in a developer "
            "checkout or entirely absent from a public candidate",
        )
        if present:
            self.assertTrue(present.isdisjoint(_selected_paths()))
        else:
            public_manifest = project_root / "PUBLIC_RELEASE_MANIFEST.sha256"
            self.assertTrue(public_manifest.is_file())
            public_paths = {
                PurePosixPath(line.split("  ", 1)[1])
                for line in public_manifest.read_text(encoding="utf-8").splitlines()
                if "  " in line
            }
            self.assertTrue(
                set(INTERNAL_OBSERVATION_DATASETS).isdisjoint(public_paths)
            )

        metadata = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
        packaged = set(
            metadata["tool"]["setuptools"]["data-files"][
                "share/offline-sbom-evidence-workbench/datasets"
            ]
        )
        approved = {
            relative
            for line in (project_root / "release/project_owned_assets.sha256")
            .read_text(encoding="utf-8")
            .splitlines()
            if (relative := line.split("  ", 1)[1]).startswith("datasets/")
        }
        self.assertEqual(packaged, approved)

    def test_resource_path_rejects_traversal(self) -> None:
        with self.assertRaisesRegex(ResourceError, "unsafe workbench resource path"):
            resource_path("../vendor/specs/SOURCE_MANIFEST.json")

    def test_invalid_explicit_data_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name, patch.dict(
            os.environ, {DATA_ROOT_ENV: directory_name}
        ):
            with self.assertRaisesRegex(ResourceError, "missing required"):
                data_root()

    def test_installed_mode_requires_byo_vendor_specs(self) -> None:
        with (
            patch.dict(os.environ, {VENDOR_SPECS_ROOT_ENV: ""}),
            patch("sbom_workbench.resources.source_checkout_root", return_value=None),
        ):
            with self.assertRaisesRegex(ResourceError, "not distributed.*BYO"):
                vendor_specs_root()


if __name__ == "__main__":
    unittest.main()
