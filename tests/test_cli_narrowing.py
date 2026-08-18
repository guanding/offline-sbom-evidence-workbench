"""CLI integration tests for intake-narrowed (M8-2).

Mock validate_euvd_handoff + verify_vex_intake_binding so the tests focus on
the narrowing reconcile execution chain (parse_matcher_hits + purl-presence +
narrow_one_hit + build/validate receipt + write), not on VEX parsing or full
handoff construction.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbom_workbench.cli import main
from sbom_workbench.vex_consume import VexConsumeError


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _cyclonedx(components: list[str]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "pkg:generic/app@1.0",
                "type": "application",
                "name": "app",
                "version": "1.0",
                "purl": "pkg:generic/app@1.0",
            }
        },
        "components": [
            {"type": "library", "name": p, "purl": p, "bom-ref": p} for p in components
        ],
        "dependencies": [],
    }


def _vex_receipt() -> dict:
    return {
        "schema_version": "vex-intake-receipt-1.0",
        "vex_format": "cyclonedx",
        "vex_document_sha256": "c" * 64,
        "signature_sha256": "d" * 64,
        "issuer_id": "psirt-1",
        "cosign_tool_identity": {"name": "cosign", "version": "3.1.2", "binary_sha256": "a" * 64},
        "statements_canonical_sha256": "e" * 64,
        "statement_count": 1,
        "narrowing_eligible_count": 1,
        "boundary": "test boundary",
    }


_HANDOFF_ID = "euvd-" + "a" * 64
_CYCLONEDX_SHA = "b" * 64
_HANDOFF_INFO = {
    "handoff_id": _HANDOFF_ID,
    "cyclonedx_sha256": _CYCLONEDX_SHA,
    "source_binding_status": "VERIFIED_SELFTEST_BINDING",
}


class IntakeNarrowedCliTests(unittest.TestCase):
    def _setup_inputs(
        self,
        root: Path,
        components: list[str],
        hits: list[dict],
        handoff_id: str = _HANDOFF_ID,
    ) -> tuple[Path, Path, Path, Path]:
        handoff_dir = root / "handoff"
        handoff_dir.mkdir()
        _write_json(handoff_dir / "cyclonedx-input.json", _cyclonedx(components))
        vex_receipt_path = root / "vex-receipt.json"
        _write_json(vex_receipt_path, _vex_receipt())
        vex_doc = root / "vex.json"
        vex_doc.write_bytes(b"{}")
        matcher_hits_path = root / "matcher-hits.json"
        matcher_hits_path.write_bytes(
            json.dumps(
                {
                    "source": {
                        "matcher_name": "m",
                        "matcher_version": "1",
                        "handoff_id": handoff_id,
                        "cyclonedx_sha256": _CYCLONEDX_SHA,
                    },
                    "hits": hits,
                }
            ).encode("utf-8")
        )
        return handoff_dir, vex_receipt_path, vex_doc, matcher_hits_path

    def _args(self, handoff_dir, vex_receipt, vex_doc, matcher_hits, output):
        return [
            "intake-narrowed",
            "--matcher-hits", str(matcher_hits),
            "--euvd-handoff", str(handoff_dir),
            "--vex-intake-receipt", str(vex_receipt),
            "--vex-document", str(vex_doc),
            "--issuer-id", "psirt-1",
            "--output", str(output),
        ]

    def test_partial_narrowing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff_dir, vex_receipt, vex_doc, matcher_hits = self._setup_inputs(
                root,
                components=["pkg:pypi/a", "pkg:pypi/b"],
                hits=[
                    {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a", "original_status": "AFFECTED"},
                    {"vulnerability_id": "CVE-2", "product_purl": "pkg:pypi/b", "original_status": "AFFECTED"},
                ],
            )
            output = root / "output"
            validated = [
                {
                    "vulnerability_id": "CVE-1",
                    "status": "not_affected",
                    "justification": "code_not_present",
                    "product_purls": ["pkg:pypi/a"],
                    "narrowing_eligible": True,
                }
            ]
            stdout = io.StringIO()
            with (
                patch("sbom_workbench.cli.validate_euvd_handoff", return_value=_HANDOFF_INFO),
                patch("sbom_workbench.cli.verify_vex_intake_binding", return_value=validated),
                contextlib.redirect_stdout(stdout),
            ):
                rc = main(self._args(handoff_dir, vex_receipt, vex_doc, matcher_hits, output))
            self.assertEqual(rc, 0)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "NARROWING_RECONCILE_RECORDED")
            self.assertEqual(report["narrowed_count"], 1)
            self.assertEqual(report["not_narrowed_count"], 1)
            self.assertFalse(report["vex_intake_binding_failed"])
            decisions = json.loads(
                (output / "narrowed" / report["reconcile_id"] / "decisions.json").read_text("utf-8")
            )
            self.assertTrue(decisions[0]["narrowed_by_trusted_vex"])  # CVE-1/a narrowed
            self.assertFalse(decisions[1]["narrowed_by_trusted_vex"])  # CVE-2/b no VEX match

    def test_vex_binding_failed_completes_not_abort(self) -> None:
        # A corrupt/tampered VEX must NOT abort evidence recording: the command
        # COMPLEtes with a receipt where every hit is not_narrowed with
        # rejection_reason=VEX_INTAKE_BINDING_FAILED (hits preserved).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff_dir, vex_receipt, vex_doc, matcher_hits = self._setup_inputs(
                root,
                components=["pkg:pypi/a"],
                hits=[
                    {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a", "original_status": "AFFECTED"}
                ],
            )
            output = root / "output"
            stdout = io.StringIO()
            with (
                patch("sbom_workbench.cli.validate_euvd_handoff", return_value=_HANDOFF_INFO),
                patch("sbom_workbench.cli.verify_vex_intake_binding", side_effect=VexConsumeError("tampered")),
                contextlib.redirect_stdout(stdout),
            ):
                rc = main(self._args(handoff_dir, vex_receipt, vex_doc, matcher_hits, output))
            self.assertEqual(rc, 0)  # COMPLETE, not ABORT
            report = json.loads(stdout.getvalue())
            self.assertTrue(report["vex_intake_binding_failed"])
            self.assertEqual(report["narrowed_count"], 0)
            decisions = json.loads(
                (output / "narrowed" / report["reconcile_id"] / "decisions.json").read_text("utf-8")
            )
            self.assertEqual(decisions[0]["rejection_reason"], "VEX_INTAKE_BINDING_FAILED")
            self.assertTrue(decisions[0]["original_hit_preserved"])

    def test_phantom_purl_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff_dir, vex_receipt, vex_doc, matcher_hits = self._setup_inputs(
                root,
                components=["pkg:pypi/a"],
                hits=[
                    {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/ghost", "original_status": "AFFECTED"}
                ],
            )
            output = root / "output"
            with (
                patch("sbom_workbench.cli.validate_euvd_handoff", return_value=_HANDOFF_INFO),
                patch("sbom_workbench.cli.verify_vex_intake_binding", return_value=[]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = main(self._args(handoff_dir, vex_receipt, vex_doc, matcher_hits, output))
            self.assertEqual(rc, 2)  # BLOCKED — phantom purl rejected

    def test_handoff_id_mismatch_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff_dir, vex_receipt, vex_doc, matcher_hits = self._setup_inputs(
                root,
                components=["pkg:pypi/a"],
                hits=[
                    {"vulnerability_id": "CVE-1", "product_purl": "pkg:pypi/a", "original_status": "AFFECTED"}
                ],
                handoff_id="euvd-" + "f" * 64,  # mismatches the validated handoff_id
            )
            output = root / "output"
            with (
                patch("sbom_workbench.cli.validate_euvd_handoff", return_value=_HANDOFF_INFO),
                patch("sbom_workbench.cli.verify_vex_intake_binding", return_value=[]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = main(self._args(handoff_dir, vex_receipt, vex_doc, matcher_hits, output))
            self.assertEqual(rc, 2)  # BLOCKED — source handoff_id mismatch


if __name__ == "__main__":
    unittest.main()
