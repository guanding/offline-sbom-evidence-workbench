"""Sealed, shadow-only evaluation for local SBOM conflict assistants.

The harness never receives a source tree or a complete SBOM.  It evaluates
already-canonical minimal conflict cards and accepts only the same bounded
advice vocabulary as :mod:`sbom_workbench.model`.  Evaluation output has no
API for writing facts, reconciliation state, release state, or conformity
status.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .manifest import canonical_json_bytes
from .model import (
    ALLOWED_ACTIONS,
    MAX_RESPONSE_BYTES,
    ModelAdapterError,
    build_minimal_conflict_card,
    replay_omlx_response,
)


SCHEMA_VERSION = "1.0"
CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"
DECISION = "SHADOW_ONLY_HOLD"
AUTHORITY_BOUNDARY = "NO_FACT_WRITE_NO_STATE_CHANGE_NO_RELEASE_OR_CONFORMITY_AUTHORITY"
MAX_CARDS = 128
PRE_REGISTRATION = {
    "profile": "M5_SBOM_CONFLICT_SHADOW_AB_1.0",
    "seed": 20260804,
    "required_schema_and_evidence_rate": 1.0,
    "allowed_fact_escalation_count": 0,
    "human_time_benefit_threshold": "PRE_REGISTERED_BUT_NOT_MEASURED",
}
QWEN_MODEL_ID = "Qwen3.6-35B-A3B-Uncensored-Heretic-MLX-4bit"
GEMMA_MODEL_ID = "gemma-4-26b-a4b-it-6bit"
MODEL_IDS = (QWEN_MODEL_ID, GEMMA_MODEL_ID)
RUNTIME_CLASSIFICATION = "LOCAL_RUNTIME_OBSERVATION_NOT_RIGHTS_APPROVAL"
RUNTIME_ENDPOINT = "http://127.0.0.1:8000/v1/responses"
RUNTIME_EXECUTION_BOUNDARY = (
    "Internal self-test used only public minimal conflict cards under the user's direct "
    "instruction. This observation is not a license, rights, privacy, model-quality, "
    "conformity, or release approval."
)
RUNTIME_SECURITY_CONTROLS = {
    "bind_host": "127.0.0.1",
    "cors": "WILDCARD",
    "api_key_verification": "SKIPPED",
    "persistent_ssd_cache": "ENABLED",
    "cache_directory": "USER_HOME_PERSISTENT",
    "log_retention_days": 7,
    "huggingface_cache_discovery": "ENABLED",
    "technical_zero_egress": "NOT_DEMONSTRATED",
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# OmlxModelAdapter.advise() clears the receipt on entry and only sets it after
# the transport returns bytes; every failure before that point (disabled
# adapter, invalid card context, or URLError/TimeoutError/OSError wrapped by
# the transport) is raised as ModelAdapterError or its ModelDisabledError
# subclass, leaving raw_response=None. A FAIL_CLOSED result with no receipt
# therefore must declare one of these transport-layer error types; arbitrary
# error strings are rejected so an externally forged FAIL_CLOSED cannot bypass
# the raw-response replay check that binds HTTP failures.
TRANSPORT_FAILURE_TYPES = frozenset({"ModelAdapterError", "ModelDisabledError"})

Runner = Callable[[dict[str, Any]], dict[str, Any]]
Clock = Callable[[], float]


class ModelEvaluationError(ValueError):
    """Raised when an evaluation would weaken the sealed comparison."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def normalize_runtime_observations(value: object) -> dict[str, Any]:
    """Validate the exact, privacy-HOLD local runtime evidence envelope."""

    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "classification",
        "observed_at",
        "runtime",
        "models",
        "execution_boundary",
    }:
        raise ModelEvaluationError("runtime observation fields do not match")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("classification") != RUNTIME_CLASSIFICATION
        or value.get("execution_boundary") != RUNTIME_EXECUTION_BOUNDARY
        or not isinstance(value.get("observed_at"), str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value["observed_at"])
    ):
        raise ModelEvaluationError("runtime observation boundary is invalid")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {
        "runtime_id",
        "version",
        "binary_sha256",
        "endpoint",
        "redacted_settings_sha256",
        "credential_values_captured",
        "observed_security_controls",
        "privacy_gate",
    }:
        raise ModelEvaluationError("runtime identity fields do not match")
    if (
        runtime.get("runtime_id") != "omlx-0.5.1-local"
        or runtime.get("version") != "0.5.1"
        or runtime.get("endpoint") != RUNTIME_ENDPOINT
        or runtime.get("credential_values_captured") is not False
        or runtime.get("privacy_gate") != "HOLD_NOT_TECHNICALLY_DEMONSTRATED"
        or runtime.get("observed_security_controls") != RUNTIME_SECURITY_CONTROLS
        or not isinstance(runtime.get("binary_sha256"), str)
        or not _SHA256_RE.fullmatch(runtime["binary_sha256"])
        or not isinstance(runtime.get("redacted_settings_sha256"), str)
        or not _SHA256_RE.fullmatch(runtime["redacted_settings_sha256"])
    ):
        raise ModelEvaluationError("runtime identity or privacy-HOLD evidence is invalid")
    models = value.get("models")
    if not isinstance(models, list) or len(models) != 2:
        raise ModelEvaluationError("runtime observations require exactly two model records")
    model_keys = {
        "server_model_id",
        "locally_observed_repository_hint",
        "model_directory_exact_set_sha256",
        "file_count",
        "total_bytes",
        "model_config_sha256",
        "tokenizer_config_sha256",
        "model_card_sha256",
        "quantization_observation",
        "upstream_identity_verification",
        "rights_status",
    }
    quantization = {QWEN_MODEL_ID: "MLX_4BIT", GEMMA_MODEL_ID: "MLX_6BIT"}
    normalized_models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model in models:
        if not isinstance(model, dict) or set(model) != model_keys:
            raise ModelEvaluationError("runtime model observation fields do not match")
        model_id = model.get("server_model_id")
        if model_id not in quantization or model_id in seen:
            raise ModelEvaluationError("runtime model identity is invalid")
        seen.add(model_id)
        if (
            model.get("quantization_observation") != quantization[model_id]
            or model.get("upstream_identity_verification") != "NOT_INDEPENDENTLY_VERIFIED"
            or model.get("rights_status") != "BLOCKED_PENDING_NAMED_REVIEW"
            or not isinstance(model.get("locally_observed_repository_hint"), str)
            or not model["locally_observed_repository_hint"]
            or type(model.get("file_count")) is not int
            or model["file_count"] < 1
            or type(model.get("total_bytes")) is not int
            or model["total_bytes"] < 1
            or any(
                not isinstance(model.get(key), str)
                or not _SHA256_RE.fullmatch(model[key])
                for key in (
                    "model_directory_exact_set_sha256",
                    "model_config_sha256",
                    "tokenizer_config_sha256",
                    "model_card_sha256",
                )
            )
        ):
            raise ModelEvaluationError("runtime model evidence or rights boundary is invalid")
        normalized_models.append(dict(model))
    if seen != set(MODEL_IDS):
        raise ModelEvaluationError("runtime observations do not bind the exact model arms")
    normalized_models.sort(key=lambda item: item["server_model_id"].encode("utf-8"))
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": RUNTIME_CLASSIFICATION,
        "observed_at": value["observed_at"],
        "runtime": dict(runtime),
        "models": normalized_models,
        "execution_boundary": RUNTIME_EXECUTION_BOUNDARY,
    }


def _canonical_card(card: object) -> dict[str, Any]:
    if not isinstance(card, dict):
        raise ModelEvaluationError("each evaluation card must be an object")
    try:
        canonical = build_minimal_conflict_card(
            card.get("run_id"),
            {
                "conflict_id": card.get("conflict_id"),
                "field": card.get("field"),
                "claims": card.get("claims"),
            },
        )
    except ModelAdapterError as exc:
        raise ModelEvaluationError(f"invalid evaluation card: {exc}") from exc
    if card != canonical:
        raise ModelEvaluationError("evaluation card is not the canonical minimal projection")
    return canonical


def seal_card_set(cards: Iterable[object]) -> dict[str, Any]:
    values = list(cards)
    if not values or len(values) > MAX_CARDS:
        raise ModelEvaluationError("card set must be non-empty and bounded")
    canonical = [_canonical_card(card) for card in values]
    ids = [card["conflict_id"] for card in canonical]
    if len(ids) != len(set(ids)):
        raise ModelEvaluationError("card set contains duplicate conflict IDs")
    canonical.sort(key=lambda item: item["conflict_id"].encode("utf-8"))
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "cards": canonical,
        "card_count": len(canonical),
        "card_set_sha256": _sha256(canonical),
    }


def cards_from_selftest_comparison(comparison: object) -> list[dict[str, Any]]:
    """Project verified M3A/M4A findings into the sealed minimal-card boundary."""

    comparison_keys = {
        "schema_version",
        "classification",
        "generator_output_status",
        "release_status",
        "product_conformity_status",
        "manufacturer_approval_status",
        "milestone_scope",
        "state",
        "comparison_namespace",
        "profile_evidence",
        "comparison_findings",
        "unidentified_component_summary",
        "population_policy",
        "canonical_sha256",
        "run_id",
    }
    if not isinstance(comparison, dict) or set(comparison) != comparison_keys:
        raise ModelEvaluationError("self-test comparison fields do not match the M4A contract")
    if (
        comparison.get("schema_version") != "1.0"
        or comparison.get("classification") != CLASSIFICATION
        or comparison.get("state") != "OPEN"
        or comparison.get("population_policy") != "NO_CROSS_PROFILE_COMPONENT_POPULATION"
        or not isinstance(comparison.get("run_id"), str)
    ):
        raise ModelEvaluationError("self-test comparison boundary is invalid")
    findings = comparison.get("comparison_findings")
    if not isinstance(findings, list) or not findings:
        raise ModelEvaluationError("M5 requires at least one real OPEN self-test finding")
    finding_keys = {
        "finding_id",
        "code",
        "state",
        "logical_key",
        "explanation",
        "evidence",
    }
    evidence_keys = {
        "logical_key",
        "profile_id",
        "profile_kind",
        "observation_run_id",
        "bom_ref",
        "name",
        "version",
        "purl",
        "cpe",
        "hashes",
    }
    cards: list[dict[str, Any]] = []
    seen_findings: set[str] = set()
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != finding_keys
            or finding.get("state") != "OPEN"
            or finding.get("code") not in {"VERSION_CONFLICT", "STALE_PORTABLE_RUNTIME"}
            or not isinstance(finding.get("finding_id"), str)
            or finding["finding_id"] in seen_findings
            or not isinstance(finding.get("evidence"), list)
            or len(finding["evidence"]) < 2
        ):
            raise ModelEvaluationError("self-test finding is outside the M5 projection profile")
        seen_findings.add(finding["finding_id"])
        claims: list[dict[str, Any]] = []
        seen_claims: set[str] = set()
        for record in finding["evidence"]:
            if not isinstance(record, dict) or set(record) != evidence_keys:
                raise ModelEvaluationError("self-test finding evidence fields do not match")
            version = record.get("version")
            observation_run_id = record.get("observation_run_id")
            if not isinstance(version, str) or not version or not isinstance(
                observation_run_id, str
            ):
                raise ModelEvaluationError("M5 version evidence must be explicit and run-bound")
            claim_identity = {
                "finding_id": finding["finding_id"],
                "profile_id": record.get("profile_id"),
                "bom_ref": record.get("bom_ref"),
                "version": version,
            }
            claim_id = f"claim-{_sha256(claim_identity)}"
            if claim_id in seen_claims:
                raise ModelEvaluationError("self-test finding contains duplicate projected claims")
            seen_claims.add(claim_id)
            claims.append(
                {
                    "claim_id": claim_id,
                    "value": version,
                    "evidence_refs": [observation_run_id],
                }
            )
        try:
            cards.append(
                build_minimal_conflict_card(
                    comparison["run_id"],
                    {
                        "conflict_id": finding["finding_id"],
                        "field": "version",
                        "claims": claims,
                    },
                )
            )
        except ModelAdapterError as exc:
            raise ModelEvaluationError(f"cannot project self-test finding: {exc}") from exc
    return seal_card_set(cards)["cards"]


def rule_only_advice(card: dict[str, Any]) -> dict[str, Any]:
    """Deterministic baseline: cite all evidence and request build binding."""

    canonical = _canonical_card(card)
    claim_refs = [claim["claim_id"] for claim in canonical["claims"]]
    evidence_refs = sorted(
        {
            evidence
            for claim in canonical["claims"]
            for evidence in claim["evidence_refs"]
        },
        key=lambda value: value.encode("utf-8"),
    )
    return {
        "status": "RULE_ONLY_SHADOW_SUGGESTION",
        "model_id": None,
        "suggestion": {
            "action": "ask_for_evidence",
            "claim_refs": claim_refs,
            "evidence_refs": evidence_refs,
            "explanation": "Conflicting evidence remains unresolved; obtain release-bound evidence.",
            "questions": ["Which claim is bound to the intended build and release artifact?"],
        },
        "authority_boundary": AUTHORITY_BOUNDARY,
    }


def _validate_advice(card: dict[str, Any], advice: object) -> dict[str, Any]:
    if not isinstance(advice, dict) or set(advice) != {
        "status",
        "model_id",
        "suggestion",
        "authority_boundary",
    }:
        raise ModelEvaluationError("advice envelope fields do not match the shadow contract")
    if advice.get("authority_boundary") not in {
        AUTHORITY_BOUNDARY,
        "NO_FACT_WRITE_NO_STATE_CHANGE_HUMAN_REVIEW_REQUIRED",
    }:
        raise ModelEvaluationError("advice authority boundary is invalid")
    suggestion = advice.get("suggestion")
    if not isinstance(suggestion, dict) or set(suggestion) != {
        "action",
        "claim_refs",
        "evidence_refs",
        "explanation",
        "questions",
    }:
        raise ModelEvaluationError("suggestion fields do not match the shadow contract")
    action = suggestion.get("action")
    if action not in ALLOWED_ACTIONS:
        raise ModelEvaluationError("suggestion action escaped the allowlist")
    claims = {
        claim["claim_id"]: set(claim["evidence_refs"])
        for claim in card["claims"]
    }
    claim_refs = suggestion.get("claim_refs")
    evidence_refs = suggestion.get("evidence_refs")
    if (
        not isinstance(claim_refs, list)
        or len(claim_refs) != len(set(claim_refs))
        or any(item not in claims for item in claim_refs)
    ):
        raise ModelEvaluationError("suggestion invented or duplicated a claim reference")
    allowed_evidence = set().union(*claims.values())
    if (
        not isinstance(evidence_refs, list)
        or len(evidence_refs) != len(set(evidence_refs))
        or any(item not in allowed_evidence for item in evidence_refs)
    ):
        raise ModelEvaluationError("suggestion invented or duplicated an evidence reference")
    if action != "abstain" and not evidence_refs:
        raise ModelEvaluationError("non-abstaining advice must cite existing evidence")
    explanation = suggestion.get("explanation")
    questions = suggestion.get("questions")
    if not isinstance(explanation, str) or not explanation or any(
        ord(character) < 0x20 for character in explanation
    ):
        raise ModelEvaluationError("suggestion explanation is invalid")
    if (
        not isinstance(questions, list)
        or len(questions) > 16
        or len(questions) != len(set(questions))
        or any(
            not isinstance(question, str)
            or not question
            or any(ord(character) < 0x20 for character in question)
            for question in questions
        )
    ):
        raise ModelEvaluationError("suggestion questions are invalid")
    return advice


def _evaluation_id(card_set_sha256: str, runtime_observations_sha256: str) -> str:
    identity = {
        "card_set_sha256": card_set_sha256,
        "runtime_observations_sha256": runtime_observations_sha256,
        "model_ids": sorted(MODEL_IDS),
        "seed": PRE_REGISTRATION["seed"],
        "pre_registration": PRE_REGISTRATION["profile"],
    }
    return f"m5-{_sha256(identity)}"


def _validate_arm(
    arm: object,
    *,
    arm_id: str,
    model_id: str | None,
    cards: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(arm, dict) or set(arm) != {
        "arm_id",
        "model_id",
        "result_count",
        "valid_result_count",
        "schema_and_evidence_rate",
        "fact_escalation_count",
        "results",
    }:
        raise ModelEvaluationError("evaluation arm fields do not match")
    if arm.get("arm_id") != arm_id or arm.get("model_id") != model_id:
        raise ModelEvaluationError("evaluation arm identity does not match the sealed profile")
    results = arm.get("results")
    if not isinstance(results, list) or len(results) != len(cards):
        raise ModelEvaluationError("evaluation arm result count does not match the card set")
    card_map = {card["conflict_id"]: card for card in cards}
    seen: set[str] = set()
    valid_count = 0
    normalized_results: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict) or set(result) != {
            "conflict_id",
            "status",
            "elapsed_ms",
            "advice",
            "advice_sha256",
            "raw_response",
            "error_type",
            "error",
        }:
            raise ModelEvaluationError("evaluation result fields do not match")
        conflict_id = result.get("conflict_id")
        if conflict_id not in card_map or conflict_id in seen:
            raise ModelEvaluationError("evaluation result card binding is invalid")
        seen.add(conflict_id)
        elapsed_ms = result.get("elapsed_ms")
        if type(elapsed_ms) is not int or elapsed_ms < 0:
            raise ModelEvaluationError("evaluation timing is invalid")
        status = result.get("status")
        raw_response = result.get("raw_response")
        decoded_response: bytes | None = None
        if raw_response is not None:
            if model_id is None or not isinstance(raw_response, dict) or set(raw_response) != {
                "encoding",
                "byte_count",
                "sha256",
                "payload",
            }:
                raise ModelEvaluationError("raw model response receipt fields do not match")
            if (
                raw_response.get("encoding") != "base64"
                or type(raw_response.get("byte_count")) is not int
                or not 0 <= raw_response["byte_count"] <= MAX_RESPONSE_BYTES
                or not isinstance(raw_response.get("sha256"), str)
                or not _SHA256_RE.fullmatch(raw_response["sha256"])
                or not isinstance(raw_response.get("payload"), str)
            ):
                raise ModelEvaluationError("raw model response receipt is invalid")
            try:
                decoded_response = base64.b64decode(
                    raw_response["payload"], validate=True
                )
            except (binascii.Error, ValueError, TypeError) as exc:
                raise ModelEvaluationError("raw model response is not strict base64") from exc
            if (
                len(decoded_response) != raw_response["byte_count"]
                or hashlib.sha256(decoded_response).hexdigest() != raw_response["sha256"]
            ):
                raise ModelEvaluationError("raw model response hash or byte count mismatch")
        if model_id is None and raw_response is not None:
            raise ModelEvaluationError("rule-only result cannot carry a model response")

        replayed_advice: dict[str, Any] | None = None
        replay_error: tuple[str, str] | None = None
        if model_id is not None and decoded_response is not None:
            try:
                replayed_advice = _validate_advice(
                    card_map[conflict_id],
                    replay_omlx_response(
                        card_map[conflict_id],
                        model_id=model_id,
                        response_payload=decoded_response,
                    ),
                )
            except Exception as exc:
                replay_error = (type(exc).__name__, str(exc)[:1024])
        if status == "VALID_SHADOW_ADVICE":
            advice = _validate_advice(card_map[conflict_id], result.get("advice"))
            expected_status = (
                "RULE_ONLY_SHADOW_SUGGESTION"
                if model_id is None
                else "MODEL_SHADOW_SUGGESTION"
            )
            if advice.get("status") != expected_status or advice.get("model_id") != model_id:
                raise ModelEvaluationError("validated advice attempted identity or status escalation")
            if result.get("advice_sha256") != _sha256(advice):
                raise ModelEvaluationError("evaluation advice hash mismatch")
            if result.get("error_type") is not None or result.get("error") is not None:
                raise ModelEvaluationError("valid advice cannot carry an error")
            if model_id is not None:
                if decoded_response is None:
                    raise ModelEvaluationError(
                        "valid model advice requires a hash-bound raw response"
                    )
                if replay_error is not None or replayed_advice != advice:
                    raise ModelEvaluationError(
                        "accepted model advice does not rederive from its raw response"
                    )
            valid_count += 1
        elif status == "FAIL_CLOSED":
            if result.get("advice") is not None or result.get("advice_sha256") is not None:
                raise ModelEvaluationError("failed advice cannot carry accepted output")
            error_type = result.get("error_type")
            error = result.get("error")
            if (
                not isinstance(error_type, str)
                or not error_type
                or len(error_type) > 256
                or not isinstance(error, str)
                or not error
                or len(error) > 1024
                or any(ord(character) < 0x20 for character in error_type + error)
            ):
                raise ModelEvaluationError("failed advice error evidence is invalid")
            if model_id is not None:
                if decoded_response is not None:
                    if replay_error is None:
                        raise ModelEvaluationError(
                            "failed model result carries a raw response that validates"
                        )
                    if replay_error != (error_type, error):
                        raise ModelEvaluationError(
                            "failed model error does not rederive from its raw response"
                        )
                elif error_type not in TRANSPORT_FAILURE_TYPES:
                    raise ModelEvaluationError(
                        "transport-layer model failure must declare a recognized "
                        "transport error type"
                    )
        else:
            raise ModelEvaluationError("evaluation result status is unsupported")
        normalized_results.append(dict(result))
    if seen != set(card_map):
        raise ModelEvaluationError("evaluation arm omits a sealed conflict card")
    expected_rate = valid_count / len(cards)
    if (
        arm.get("result_count") != len(cards)
        or arm.get("valid_result_count") != valid_count
        or arm.get("schema_and_evidence_rate") != expected_rate
        or arm.get("fact_escalation_count") != 0
    ):
        raise ModelEvaluationError("evaluation arm metrics do not rederive from its results")
    return {**arm, "results": normalized_results}


def _run_arm(
    arm_id: str,
    model_id: str | None,
    cards: list[dict[str, Any]],
    runner: Runner,
    *,
    clock: Clock,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for card in cards:
        started = clock()
        raw_response: dict[str, Any] | None = None
        try:
            advice = _validate_advice(card, runner(card))
            owner = getattr(runner, "__self__", runner)
            consumer = getattr(owner, "consume_last_response_receipt", None)
            if callable(consumer):
                raw_response = consumer()
            if model_id is not None and raw_response is None:
                raise ModelEvaluationError(
                    "model result is missing its raw response receipt"
                )
            expected_status = (
                "RULE_ONLY_SHADOW_SUGGESTION"
                if model_id is None
                else "MODEL_SHADOW_SUGGESTION"
            )
            if advice.get("model_id") != model_id or advice.get("status") != expected_status:
                raise ModelEvaluationError(
                    "advice identity or status does not match its sealed arm"
                )
            elapsed_ms = max(0, round((clock() - started) * 1000))
            results.append(
                {
                    "conflict_id": card["conflict_id"],
                    "status": "VALID_SHADOW_ADVICE",
                    "elapsed_ms": elapsed_ms,
                    "advice": advice,
                    "advice_sha256": _sha256(advice),
                    "raw_response": raw_response,
                    "error_type": None,
                    "error": None,
                }
            )
        except Exception as exc:  # preserve every failure without weakening the main path
            if raw_response is None:
                owner = getattr(runner, "__self__", runner)
                consumer = getattr(owner, "consume_last_response_receipt", None)
                if callable(consumer):
                    raw_response = consumer()
            elapsed_ms = max(0, round((clock() - started) * 1000))
            results.append(
                {
                    "conflict_id": card["conflict_id"],
                    "status": "FAIL_CLOSED",
                    "elapsed_ms": elapsed_ms,
                    "advice": None,
                    "advice_sha256": None,
                    "raw_response": raw_response,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:1024],
                }
            )
    passed = sum(item["status"] == "VALID_SHADOW_ADVICE" for item in results)
    return {
        "arm_id": arm_id,
        "model_id": model_id,
        "result_count": len(results),
        "valid_result_count": passed,
        "schema_and_evidence_rate": passed / len(results),
        "fact_escalation_count": 0,
        "results": results,
    }


def run_sealed_evaluation(
    cards: Iterable[object],
    model_runners: Mapping[str, Runner],
    *,
    runtime_observations: Mapping[str, Any],
    clock: Clock = time.monotonic,
) -> dict[str, Any]:
    """Evaluate rule-only plus fixed model arms and return a HOLD-safe record."""

    sealed = seal_card_set(cards)
    normalized_runtime = normalize_runtime_observations(dict(runtime_observations))
    expected_models = set(MODEL_IDS)
    if set(model_runners) != expected_models:
        raise ModelEvaluationError("evaluation requires the exact Qwen and Gemma arms")
    values = sealed["cards"]
    arms = [
        _run_arm("rule-only", None, values, rule_only_advice, clock=clock),
        *[
            _run_arm(
                f"model:{model_id}",
                model_id,
                values,
                model_runners[model_id],
                clock=clock,
            )
            for model_id in sorted(model_runners, key=lambda value: value.encode("utf-8"))
        ],
    ]
    all_model_results_valid = all(
        arm["schema_and_evidence_rate"] == 1.0 for arm in arms if arm["model_id"] is not None
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "evaluation_id": _evaluation_id(
            sealed["card_set_sha256"], _sha256(normalized_runtime)
        ),
        "pre_registration": dict(PRE_REGISTRATION),
        "card_set_sha256": sealed["card_set_sha256"],
        "cards": values,
        "runtime_observations": normalized_runtime,
        "arms": arms,
        "safety_gate": "PASS" if all_model_results_valid else "HOLD",
        "privacy_gate": "HOLD_NOT_TECHNICALLY_DEMONSTRATED",
        "benefit_gate": "NOT_ASSESSED_NO_INDEPENDENT_HUMAN_TIMING",
        "decision": DECISION,
        "authority_boundary": AUTHORITY_BOUNDARY,
    }
    # evaluation_payload_sha256 covers the full record including per-card
    # elapsed_ms, so it changes on every run even for identical card/runtime
    # inputs (M5M6-6). It is a single-run integrity/transport anchor, NOT a
    # stable cross-run identity; card_set_sha256 is the stable identity for
    # cross-run comparison, and operators comparing two evaluations should
    # match on card_set_sha256, not this payload hash.
    return {**record, "evaluation_payload_sha256": _sha256(record)}


def validate_evaluation(
    record: object,
    *,
    trusted_evaluation_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ModelEvaluationError("evaluation must be an object")
    required = {
        "schema_version",
        "classification",
        "evaluation_id",
        "pre_registration",
        "card_set_sha256",
        "cards",
        "runtime_observations",
        "arms",
        "safety_gate",
        "privacy_gate",
        "benefit_gate",
        "decision",
        "authority_boundary",
        "evaluation_payload_sha256",
    }
    if set(record) != required:
        raise ModelEvaluationError("evaluation fields do not match")
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("classification") != CLASSIFICATION
        or record.get("decision") != DECISION
        or record.get("authority_boundary") != AUTHORITY_BOUNDARY
    ):
        raise ModelEvaluationError("evaluation boundary changed")
    sealed = seal_card_set(record.get("cards", []))
    if sealed["card_set_sha256"] != record.get("card_set_sha256"):
        raise ModelEvaluationError("evaluation card set hash mismatch")
    normalized_runtime = normalize_runtime_observations(record.get("runtime_observations"))
    if record.get("runtime_observations") != normalized_runtime:
        raise ModelEvaluationError("runtime observations are not in canonical order")
    if record.get("evaluation_id") != _evaluation_id(
        sealed["card_set_sha256"], _sha256(normalized_runtime)
    ):
        raise ModelEvaluationError("evaluation identity does not match the sealed inputs")
    if record.get("pre_registration") != PRE_REGISTRATION:
        raise ModelEvaluationError("evaluation pre-registration changed")
    if record.get("privacy_gate") != "HOLD_NOT_TECHNICALLY_DEMONSTRATED" or record.get(
        "benefit_gate"
    ) != "NOT_ASSESSED_NO_INDEPENDENT_HUMAN_TIMING":
        raise ModelEvaluationError("evaluation cannot escalate privacy or benefit status")
    arms = record.get("arms")
    if not isinstance(arms, list) or len(arms) != 3:
        raise ModelEvaluationError("evaluation must contain rule, Qwen and Gemma arms")
    expected_arms = (
        ("rule-only", None),
        (f"model:{QWEN_MODEL_ID}", QWEN_MODEL_ID),
        (f"model:{GEMMA_MODEL_ID}", GEMMA_MODEL_ID),
    )
    verified_arms = [
        _validate_arm(arm, arm_id=arm_id, model_id=model_id, cards=sealed["cards"])
        for arm, (arm_id, model_id) in zip(arms, expected_arms, strict=True)
    ]
    expected_safety = (
        "PASS"
        if all(arm["schema_and_evidence_rate"] == 1.0 for arm in verified_arms)
        else "HOLD"
    )
    if record.get("safety_gate") != expected_safety:
        raise ModelEvaluationError("evaluation safety gate does not rederive from model results")
    payload = {
        key: value
        for key, value in record.items()
        if key != "evaluation_payload_sha256"
    }
    observed_payload_sha256 = _sha256(payload)
    if record.get("evaluation_payload_sha256") != observed_payload_sha256:
        raise ModelEvaluationError("evaluation payload hash does not match the full record")
    if trusted_evaluation_sha256 is not None:
        if (
            not isinstance(trusted_evaluation_sha256, str)
            or not _SHA256_RE.fullmatch(trusted_evaluation_sha256)
        ):
            raise ModelEvaluationError("trusted evaluation SHA-256 is invalid")
        if trusted_evaluation_sha256 != observed_payload_sha256:
            raise ModelEvaluationError("evaluation does not match the external trust anchor")
    return {
        "status": (
            "VALIDATED_SHADOW_EVALUATION_WITH_EXTERNAL_ANCHOR"
            if trusted_evaluation_sha256 is not None
            else "SELF_CONSISTENCY_ONLY_SHADOW_EVALUATION"
        ),
        "evaluation_id": record["evaluation_id"],
        "evaluation_payload_sha256": observed_payload_sha256,
        "decision": DECISION,
    }
