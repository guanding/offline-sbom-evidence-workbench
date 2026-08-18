from __future__ import annotations

import base64
import hashlib
import json
import unittest

from sbom_workbench.model import (
    ModelAdapterError,
    ModelDisabledError,
    OmlxModelAdapter,
    build_minimal_conflict_card,
)


MODEL_ID = "approved-local-model"
API_KEY = "test-key-0123456789abcdef"


def conflict_card() -> dict[str, object]:
    return build_minimal_conflict_card(
        "run-1",
        {
            "conflict_id": "conflict-1",
            "field": "version",
            "claims": [
                {
                    "claim_id": "claim-a",
                    "value": "1.0.0",
                    "evidence_ids": ["evidence-a"],
                },
                {
                    "claim_id": "claim-b",
                    "value": "1.0.1",
                    "evidence_ids": ["evidence-b"],
                },
            ],
        },
    )


def response_bytes(suggestion: object) -> bytes:
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
                            "text": json.dumps(suggestion, ensure_ascii=False),
                        }
                    ],
                }
            ],
        },
        ensure_ascii=False,
    ).encode("utf-8")


def valid_suggestion() -> dict[str, object]:
    return {
        "action": "explain_conflict",
        "claim_refs": ["claim-a", "claim-b"],
        "evidence_refs": ["evidence-a", "evidence-b"],
        "explanation": "两个现存证据记录了不同版本，需要人工核对发布绑定。",
        "questions": [],
    }


class ModelAdapterTests(unittest.TestCase):
    def adapter(self, transport) -> OmlxModelAdapter:
        return OmlxModelAdapter(
            enabled=True,
            endpoint="http://127.0.0.1:18000/v1/responses",
            model_id=MODEL_ID,
            allowed_model_ids=frozenset({MODEL_ID}),
            api_key=API_KEY,
            transport=transport,
        )

    def test_default_adapter_is_disabled_and_never_calls_transport(self) -> None:
        called = False

        def transport(endpoint, headers, payload, timeout):
            nonlocal called
            called = True
            return b"{}"

        adapter = OmlxModelAdapter(transport=transport)
        self.assertEqual(adapter.status()["mode"], "DISABLED")
        with self.assertRaises(ModelDisabledError):
            adapter.advise(conflict_card())
        self.assertFalse(called)

    def test_enabled_adapter_requires_one_fixed_allowlisted_model(self) -> None:
        with self.assertRaisesRegex(ModelAdapterError, "exactly one allowlisted"):
            OmlxModelAdapter(
                enabled=True,
                model_id=MODEL_ID,
                allowed_model_ids=frozenset(),
                api_key=API_KEY,
            )
        with self.assertRaisesRegex(ModelAdapterError, "not the fixed allowlisted"):
            OmlxModelAdapter(
                enabled=True,
                model_id="other-model",
                allowed_model_ids=frozenset({MODEL_ID}),
                api_key=API_KEY,
            )

    def test_endpoint_must_be_exact_loopback_responses_api(self) -> None:
        for endpoint in (
            "http://localhost:18000/v1/responses",
            "http://192.168.1.5:18000/v1/responses",
            "https://127.0.0.1:18000/v1/responses",
            "http://127.0.0.1:18000/v1/chat/completions",
            "http://127.0.0.1:18000/v1/responses?target=remote",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ModelAdapterError):
                OmlxModelAdapter(endpoint=endpoint)

    def test_request_is_minimal_stateless_toolless_and_deterministic(self) -> None:
        observed: dict[str, object] = {}

        def transport(endpoint, headers, payload, timeout):
            observed.update(
                {
                    "endpoint": endpoint,
                    "headers": dict(headers),
                    "request": json.loads(payload),
                    "timeout": timeout,
                }
            )
            return response_bytes(valid_suggestion())

        result = self.adapter(transport).advise(conflict_card())
        request = observed["request"]
        self.assertEqual(observed["endpoint"], "http://127.0.0.1:18000/v1/responses")
        self.assertEqual(observed["headers"]["Authorization"], f"Bearer {API_KEY}")
        self.assertEqual(request["model"], MODEL_ID)
        self.assertEqual(request["temperature"], 0)
        self.assertFalse(request["store"])
        self.assertFalse(request["stream"])
        self.assertEqual(request["tools"], [])
        self.assertFalse(request["parallel_tool_calls"])
        self.assertNotIn("previous_response_id", request)
        sent_card = json.loads(request["input"])
        self.assertEqual(
            set(sent_card),
            {
                "schema_version",
                "run_id",
                "conflict_id",
                "field",
                "claims",
                "untrusted_content_notice",
            },
        )
        self.assertEqual(result["status"], "MODEL_SHADOW_SUGGESTION")
        self.assertIn("NO_FACT_WRITE", result["authority_boundary"])

    def test_raw_response_receipt_is_hash_bound_and_single_consume(self) -> None:
        response = response_bytes(valid_suggestion())
        adapter = self.adapter(lambda *args: response)

        adapter.advise(conflict_card())
        receipt = adapter.consume_last_response_receipt()

        self.assertEqual(receipt["encoding"], "base64")
        self.assertEqual(receipt["byte_count"], len(response))
        self.assertEqual(receipt["sha256"], hashlib.sha256(response).hexdigest())
        self.assertEqual(base64.b64decode(receipt["payload"]), response)
        self.assertIsNone(adapter.consume_last_response_receipt())

    def test_rejects_bad_action_and_extra_fact_field(self) -> None:
        bad_action = valid_suggestion()
        bad_action["action"] = "approve_release"
        with self.assertRaisesRegex(ModelAdapterError, "action is not allowed"):
            self.adapter(lambda *args: response_bytes(bad_action)).advise(conflict_card())

        extra_fact = valid_suggestion()
        extra_fact["component_version"] = "9.9.9"
        with self.assertRaisesRegex(ModelAdapterError, "fields do not match"):
            self.adapter(lambda *args: response_bytes(extra_fact)).advise(conflict_card())

    def test_rejects_invented_evidence_or_claim_reference(self) -> None:
        invented_evidence = valid_suggestion()
        invented_evidence["evidence_refs"] = ["evidence-not-in-card"]
        with self.assertRaisesRegex(ModelAdapterError, "invented or escaped an evidence"):
            self.adapter(lambda *args: response_bytes(invented_evidence)).advise(conflict_card())

        invented_claim = valid_suggestion()
        invented_claim["claim_refs"] = ["claim-not-in-card"]
        with self.assertRaisesRegex(ModelAdapterError, "invented or escaped a claim"):
            self.adapter(lambda *args: response_bytes(invented_claim)).advise(conflict_card())

    def test_rejects_non_json_or_multi_output_response(self) -> None:
        non_json = {
            "object": "response",
            "status": "completed",
            "model": MODEL_ID,
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "```json\n{}\n```"}],
                }
            ],
        }
        with self.assertRaisesRegex(ModelAdapterError, "control characters|not strict UTF-8 JSON"):
            self.adapter(lambda *args: json.dumps(non_json).encode()).advise(conflict_card())

        multiple = json.loads(response_bytes(valid_suggestion()))
        multiple["output"].append(multiple["output"][0])
        with self.assertRaisesRegex(ModelAdapterError, "exactly one output"):
            self.adapter(lambda *args: json.dumps(multiple).encode()).advise(conflict_card())

        wrong_model = json.loads(response_bytes(valid_suggestion()))
        wrong_model["model"] = "different-model"
        with self.assertRaisesRegex(ModelAdapterError, "not a completed response"):
            self.adapter(lambda *args: json.dumps(wrong_model).encode()).advise(conflict_card())

    def test_accepts_pretty_printed_outer_json_but_rejects_controls_in_fields(self) -> None:
        pretty = response_bytes(valid_suggestion())
        envelope = json.loads(pretty)
        envelope["output"][0]["content"][0]["text"] = json.dumps(
            valid_suggestion(), ensure_ascii=False, indent=2
        )
        result = self.adapter(lambda *args: json.dumps(envelope).encode()).advise(conflict_card())
        self.assertEqual(result["suggestion"]["action"], "explain_conflict")

        bad_field = valid_suggestion()
        bad_field["explanation"] = "line one\nline two"
        envelope["output"][0]["content"][0]["text"] = json.dumps(bad_field)
        with self.assertRaisesRegex(ModelAdapterError, "control characters"):
            self.adapter(lambda *args: json.dumps(envelope).encode()).advise(conflict_card())


if __name__ == "__main__":
    unittest.main()
