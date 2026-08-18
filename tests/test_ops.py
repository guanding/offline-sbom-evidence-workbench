from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.manifest import build_exact_set_manifest
from sbom_workbench.ops import (
    CLEAR_MARKER,
    CLEAR_MARKER_VALUE,
    OperationsError,
    clear_selftest_sandbox_run,
    create_selftest_backup,
    restore_selftest_backup,
    validate_selftest_backup,
)


class OperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "evidence.json").write_text('{"value":1}\n', encoding="utf-8")
        (self.source / "nested").mkdir()
        (self.source / "nested" / "sbom.json").write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_backup_restore_and_no_overwrite(self) -> None:
        backup = self.root / "backup"
        created = create_selftest_backup(self.source, backup, root_id="run-1")
        self.assertEqual(
            created["status"], "SELFTEST_BACKUP_CREATED_EXTERNAL_ANCHOR_REQUIRED"
        )
        self.assertEqual(
            validate_selftest_backup(backup)["status"],
            "SELF_CONSISTENCY_ONLY_NOT_EXTERNALLY_ANCHORED",
        )
        self.assertEqual(
            validate_selftest_backup(
                backup,
                trusted_manifest_sha256=created["manifest_sha256"],
            )["status"],
            "VALIDATED_SELFTEST_BACKUP_WITH_EXTERNAL_ANCHOR",
        )
        restored_path = self.root / "restored"
        restored = restore_selftest_backup(
            backup,
            restored_path,
            trusted_manifest_sha256=created["manifest_sha256"],
        )
        self.assertEqual(restored["status"], "SELFTEST_RESTORE_VERIFIED")
        self.assertEqual((restored_path / "evidence.json").read_bytes(), (self.source / "evidence.json").read_bytes())
        with self.assertRaisesRegex(OperationsError, "exists"):
            create_selftest_backup(self.source, backup, root_id="run-1")
        with self.assertRaisesRegex(OperationsError, "exists"):
            restore_selftest_backup(
                backup,
                restored_path,
                trusted_manifest_sha256=created["manifest_sha256"],
            )

    def test_backup_tamper_and_addition_fail_closed(self) -> None:
        backup = self.root / "backup"
        create_selftest_backup(self.source, backup, root_id="run-1")
        (backup / "payload" / "evidence.json").write_text("tampered")
        with self.assertRaisesRegex(OperationsError, "does not match"):
            validate_selftest_backup(backup)
        (backup / "payload" / "evidence.json").write_text('{"value":1}\n')
        (backup / "extra.txt").write_text("extra")
        with self.assertRaisesRegex(OperationsError, "top-level exact-set"):
            validate_selftest_backup(backup)

    def test_backup_external_anchor_blocks_whole_package_rewrite(self) -> None:
        backup = self.root / "backup"
        created = create_selftest_backup(self.source, backup, root_id="run-1")
        manifest_path = backup / "BACKUP_MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["root_id"] = "attacker-rewritten-run"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        complete_path = backup / "COMPLETE.json"
        complete = json.loads(complete_path.read_text(encoding="utf-8"))
        complete["root_id"] = "attacker-rewritten-run"
        complete["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        complete_path.write_text(json.dumps(complete), encoding="utf-8")
        with self.assertRaisesRegex(OperationsError, "external trust anchor"):
            validate_selftest_backup(
                backup,
                trusted_manifest_sha256=created["manifest_sha256"],
            )

    def test_backup_completion_rejects_authority_claim_injection(self) -> None:
        backup = self.root / "backup"
        created = create_selftest_backup(self.source, backup, root_id="run-1")
        complete_path = backup / "COMPLETE.json"
        complete = json.loads(complete_path.read_text(encoding="utf-8"))
        complete["release_authority"] = "CRA_CONFORMANT_CERTIFIED"
        complete_path.write_text(json.dumps(complete), encoding="utf-8")

        with self.assertRaisesRegex(OperationsError, "completion binding"):
            validate_selftest_backup(
                backup,
                trusted_manifest_sha256=created["manifest_sha256"],
            )

    def test_clear_requires_direct_marked_selftest_child_and_writes_receipt(self) -> None:
        sandbox = self.root / "clear-sandbox"
        sandbox.mkdir()
        (sandbox / CLEAR_MARKER).write_text(CLEAR_MARKER_VALUE)
        run = sandbox / "run-1"
        run.mkdir()
        (run / "run.json").write_text(json.dumps({"classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE", "run_id": "run-1"}))
        (run / "COMPLETE.json").write_text(json.dumps({"status": "complete"}))
        receipt = self.root / "clear-receipt.json"
        result = clear_selftest_sandbox_run(run, allowed_parent=sandbox, receipt_path=receipt)
        self.assertFalse(run.exists())
        self.assertTrue(receipt.is_file())
        self.assertEqual(
            result["status"], "SELFTEST_DIRECTORY_QUARANTINED_RECOVERABLE_NOT_ERASED"
        )
        self.assertTrue(Path(result["recoverable_quarantine_path"]).is_dir())
        self.assertEqual(result["customer_volume_erasure"], "NOT_ASSESSED")

    def test_clear_receipt_failure_restores_the_original_run(self) -> None:
        sandbox = self.root / "clear-sandbox"
        sandbox.mkdir()
        (sandbox / CLEAR_MARKER).write_text(CLEAR_MARKER_VALUE)
        run = sandbox / "run-1"
        run.mkdir()
        (run / "run.json").write_text(
            json.dumps(
                {"classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE", "run_id": "run-1"}
            )
        )
        (run / "COMPLETE.json").write_text(json.dumps({"status": "complete"}))
        blocked_parent = self.root / "not-a-directory"
        blocked_parent.write_text("file")
        with self.assertRaises(OSError):
            clear_selftest_sandbox_run(
                run,
                allowed_parent=sandbox,
                receipt_path=blocked_parent / "receipt.json",
            )
        self.assertTrue(run.is_dir())

    def test_clear_rejects_receipt_inside_future_quarantine_payload(self) -> None:
        sandbox = self.root / "clear-sandbox"
        sandbox.mkdir()
        (sandbox / CLEAR_MARKER).write_text(CLEAR_MARKER_VALUE)
        run = sandbox / "run-1"
        run.mkdir()
        (run / "run.json").write_text(
            json.dumps(
                {"classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE", "run_id": "run-1"}
            )
        )
        (run / "COMPLETE.json").write_text(json.dumps({"status": "complete"}))
        exact_set = build_exact_set_manifest(run, "run-1")["exact_set_sha256"]
        receipt = (
            sandbox
            / ".selftest-clear-quarantine"
            / f"run-1-{exact_set}"
            / "receipt.json"
        )

        with self.assertRaisesRegex(OperationsError, "outside the entire allowed sandbox"):
            clear_selftest_sandbox_run(
                run,
                allowed_parent=sandbox,
                receipt_path=receipt,
            )
        self.assertTrue(run.is_dir())
        self.assertFalse(receipt.exists())

    def test_clear_rejects_unmarked_nonselftest_or_nested_target(self) -> None:
        sandbox = self.root / "clear-sandbox"
        sandbox.mkdir()
        run = sandbox / "run-1"
        run.mkdir()
        (run / "run.json").write_text(json.dumps({"classification": "CUSTOMER", "run_id": "run-1"}))
        (run / "COMPLETE.json").write_text("{}")
        with self.assertRaisesRegex(OperationsError, "marker"):
            clear_selftest_sandbox_run(run, allowed_parent=sandbox, receipt_path=self.root / "receipt.json")
        (sandbox / CLEAR_MARKER).write_text(CLEAR_MARKER_VALUE)
        with self.assertRaisesRegex(OperationsError, "not classified"):
            clear_selftest_sandbox_run(run, allowed_parent=sandbox, receipt_path=self.root / "receipt.json")
        nested = run / "nested"
        nested.mkdir()
        (nested / "run.json").write_text(json.dumps({"classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE", "run_id": "nested"}))
        (nested / "COMPLETE.json").write_text("{}")
        with self.assertRaisesRegex(OperationsError, "direct sandbox child"):
            clear_selftest_sandbox_run(nested, allowed_parent=sandbox, receipt_path=self.root / "receipt.json")


if __name__ == "__main__":
    unittest.main()
