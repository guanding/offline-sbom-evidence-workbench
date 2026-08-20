from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sbom_workbench.model import OmlxModelAdapter, build_minimal_conflict_card
from sbom_workbench.model_candidate import (
    observe_candidate_profile,
    run_candidate_evaluation,
    validate_candidate_evaluation,
    validate_candidate_profile,
)
from sbom_workbench.model_eval import ModelEvaluationError, rule_only_advice


MODEL_ID = "Qwen3.8-test-candidate"


def _card() -> dict[str, object]:
    return build_minimal_conflict_card(
        "candidate-run",
        {
            "conflict_id": "candidate-version-drift",
            "field": "version",
            "claims": [
                {"claim_id": "a", "value": "1.0", "evidence_ids": ["ea"]},
                {"claim_id": "b", "value": "2.0", "evidence_ids": ["eb"]},
            ],
        },
    )


class ModelCandidateEvaluationTests(unittest.TestCase):
    def _profile(self, root: Path) -> dict[str, object]:
        model = root / "model"
        model.mkdir()
        for name, content in (
            ("config.json", "{}"),
            ("tokenizer_config.json", "{}"),
            ("README.md", "test model"),
            ("model.safetensors.index.json", "{}"),
            ("model.safetensors", "weights"),
        ):
            (model / name).write_text(content, encoding="utf-8")
        runtime = root / "omlx-cli"
        runtime.write_text("binary", encoding="utf-8")
        return observe_candidate_profile(
            model_directory=model,
            runtime_binary=runtime,
            runtime_version="0.5.7",
            endpoint="http://127.0.0.1:18000/v1/responses",
            model_id=MODEL_ID,
            observed_at="2026-08-20",
            upstream_revision="1" * 40,
            quantization_observation="MLX_4BIT_TEST_DECLARATION",
        )

    def _runner(self):
        def transport(endpoint, headers, request_payload, timeout):
            request = json.loads(request_payload)
            card = json.loads(request["input"])
            suggestion = rule_only_advice(card)["suggestion"]
            return json.dumps(
                {
                    "object": "response",
                    "status": "completed",
                    "model": MODEL_ID,
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": json.dumps(suggestion),
                                }
                            ],
                        }
                    ],
                }
            ).encode("utf-8")

        return OmlxModelAdapter(
            enabled=True,
            endpoint="http://127.0.0.1:18000/v1/responses",
            model_id=MODEL_ID,
            allowed_model_ids=frozenset({MODEL_ID}),
            api_key="unit-test-candidate-key-value",
            transport=transport,
        ).advise

    def test_new_candidate_is_separate_and_always_shadow_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = self._profile(Path(temporary))
            record = run_candidate_evaluation([_card()], self._runner(), candidate_profile=profile)
        validation = validate_candidate_evaluation(record)
        self.assertEqual(validation["schema_evidence_gate"], "PASS")
        self.assertEqual(validation["decision"], "SHADOW_ONLY_CANDIDATE_HOLD")
        self.assertEqual(validation["rights_gate"], "HOLD_PENDING_NAMED_REVIEW")
        self.assertEqual(record["evaluation_profile"], "M5B_SINGLE_MODEL_SHADOW_CANDIDATE_1.0")

    def test_profile_byte_identity_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = self._profile(Path(temporary))
            record = run_candidate_evaluation([_card()], self._runner(), candidate_profile=profile)
        record["candidate_profile"]["model"]["directory_manifest"]["files"][0][
            "sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(ModelEvaluationError, "exact-set SHA-256"):
            validate_candidate_evaluation(record)

    def test_candidate_endpoint_rejects_out_of_range_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = self._profile(root)
            profile["runtime"]["endpoint"] = "http://127.0.0.1:99999/v1/responses"
            with self.assertRaisesRegex(ModelEvaluationError, "runtime profile"):
                validate_candidate_profile(profile)


if __name__ == "__main__":
    unittest.main()
