from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.evidence import canonical_graph_sha256
from sbom_workbench.reference_pack import (
    ReferencePackError,
    verify_reference_package,
    write_reference_package,
)
from sbom_workbench.resources import ResourceError, vendor_specs_root
from sbom_workbench.webapp import RegisteredRunStore
from sbom_workbench.yocto import analyze_reference
from tests.test_yocto_reference import _fixture


def _has_byo_vendor_specs() -> bool:
    try:
        vendor_specs_root()
    except ResourceError:
        return False
    return True


requires_byo_vendor_specs = unittest.skipUnless(
    _has_byo_vendor_specs(),
    "BYO CycloneDX/SPDX validation specs are unavailable in the public source set",
)


class YoctoReferencePackTests(unittest.TestCase):
    @requires_byo_vendor_specs
    def test_package_contains_inputs_and_rederives_graph_from_trusted_profile(self) -> None:
        with tempfile.TemporaryDirectory() as input_directory, tempfile.TemporaryDirectory() as data_directory:
            input_root = Path(input_directory)
            data_root = Path(data_directory)
            profile = _fixture(input_root)
            graph = analyze_reference(profile, input_root)

            result = write_reference_package(
                data_root,
                graph,
                profile=profile,
                input_root=input_root,
            )
            run_directory = data_root / "runs" / graph["run_id"]
            repeated = verify_reference_package(
                run_directory,
                trusted_profiles=[profile],
            )
            dashboard = RegisteredRunStore(data_root).get_run(graph["run_id"])

        self.assertEqual(result, repeated)
        self.assertEqual(result["validation_status"], "MECHANICALLY_VALID")
        self.assertEqual(result["technical_status"], "REFERENCE_RECONCILIATION_OPEN")
        self.assertEqual(result["file_count"], 15)
        self.assertEqual(dashboard["release"]["manufacturer_role"], None)
        self.assertEqual(
            dashboard["release"]["product_conformity_status"],
            "NO_PRODUCT_CONFORMITY_STATUS",
        )

    def test_forged_component_with_refreshed_self_hash_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as input_directory, tempfile.TemporaryDirectory() as data_directory:
            input_root = Path(input_directory)
            profile = _fixture(input_root)
            graph = analyze_reference(profile, input_root)
            forged = copy.deepcopy(graph)
            component = next(
                item for item in forged["component_population"] if item["kind"] == "RUNTIME_PACKAGE"
            )
            component["producer"] = "Forged Manufacturer Inc."
            component["producer_evidence_ids"] = [component["evidence_ids"][0]]
            component["critical_unknown_fields"] = []
            forged["canonical_sha256"] = canonical_graph_sha256(forged)

            with self.assertRaisesRegex(ReferencePackError, "source-derived|trusted inputs"):
                write_reference_package(
                    Path(data_directory),
                    forged,
                    profile=profile,
                    input_root=input_root,
                )

    @requires_byo_vendor_specs
    def test_wrong_profile_and_input_tamper_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as input_directory, tempfile.TemporaryDirectory() as data_directory:
            input_root = Path(input_directory)
            data_root = Path(data_directory)
            profile = _fixture(input_root)
            graph = analyze_reference(profile, input_root)
            write_reference_package(
                data_root,
                graph,
                profile=profile,
                input_root=input_root,
            )
            run_directory = data_root / "runs" / graph["run_id"]

            wrong_profile = copy.deepcopy(profile)
            wrong_profile["profile_id"] = "different-profile"
            with self.assertRaisesRegex(ReferencePackError, "trusted profile"):
                verify_reference_package(run_directory, trusted_profiles=[wrong_profile])

            manifest_path = run_directory / "inputs" / "image.manifest"
            manifest_path.chmod(0o600)
            manifest_path.write_text("demo cortexa57 forged\n", encoding="utf-8")
            with self.assertRaisesRegex(ReferencePackError, "MANIFEST|payload"):
                verify_reference_package(run_directory, trusted_profiles=[profile])

    @requires_byo_vendor_specs
    def test_package_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as input_directory, tempfile.TemporaryDirectory() as data_directory:
            input_root = Path(input_directory)
            data_root = Path(data_directory)
            profile = _fixture(input_root)
            graph = analyze_reference(profile, input_root)
            write_reference_package(
                data_root,
                graph,
                profile=profile,
                input_root=input_root,
            )
            with self.assertRaisesRegex(ReferencePackError, "refusing overwrite"):
                write_reference_package(
                    data_root,
                    graph,
                    profile=profile,
                    input_root=input_root,
                )


if __name__ == "__main__":
    unittest.main()
