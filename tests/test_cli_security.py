from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbom_workbench.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CliSecurityTests(unittest.TestCase):
    def test_acquire_blocks_trusted_registry_hash_mismatch_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            output = io.StringIO()
            with patch("sbom_workbench.cli.acquire_git_source") as acquire, contextlib.redirect_stdout(output):
                result = main(
                    [
                        "acquire",
                        "--registry",
                        str(ROOT / "datasets" / "source_registry.json"),
                        "--dataset-id",
                        "cyclonedx-bom-examples",
                        "--destination",
                        str(Path(root_name) / "sources"),
                        "--trusted-registry-sha256",
                        "0" * 64,
                    ]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(result, 2)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["error_type"], "RegistryError")
        self.assertIn("does not match the out-of-band trust anchor", payload["message"])
        acquire.assert_not_called()

    def test_model_status_reports_both_local_families_blocked(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["model-status", str(ROOT / "datasets" / "model_runtime_intake.json")])
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["status"], "MODEL_PATH_BLOCKED")
        self.assertEqual(
            {item["family_hint"] for item in payload["models"]},
            {"Qwen", "Gemma"},
        )
        self.assertTrue(all(item["status"] == "BLOCKED_PENDING_EXACT_MODEL_ID" for item in payload["models"]))

    def test_model_status_cannot_self_authorize_with_a_new_hash(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            candidate = json.loads(
                (ROOT / "datasets" / "model_runtime_intake.json").read_text(encoding="utf-8")
            )
            candidate["models"][0]["rights_decision"]["permissions"]["local_execution"] = "AUTHORIZED"
            path = Path(root_name) / "model-intake.json"
            payload_bytes = (json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            path.write_bytes(payload_bytes)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "model-status",
                        str(path),
                        "--trusted-model-intake-sha256",
                        hashlib.sha256(payload_bytes).hexdigest(),
                    ]
                )
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 2)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertIn("permissions must all be NOT_AUTHORIZED", payload["message"])


if __name__ == "__main__":
    unittest.main()
