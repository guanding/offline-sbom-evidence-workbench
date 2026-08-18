from __future__ import annotations

import unittest

from sbom_workbench.in_toto import (
    STATEMENT_TYPE,
    InTotoError,
    validate_statement,
    wrap_statement,
)


_SHA = "a" * 64


class InTotoStatementTests(unittest.TestCase):
    def test_wrap_produces_valid_statement_v1_envelope(self) -> None:
        statement = wrap_statement(
            predicate_type="sbom-workbench.selftest-pack/v1",
            subject_name="MANIFEST.json",
            subject_sha256=_SHA,
            predicate={"run_id": "r1", "boundary": "SELF_TEST_NOT_CUSTOMER_EVIDENCE"},
        )
        self.assertEqual(statement["_type"], STATEMENT_TYPE)
        self.assertEqual(statement["predicateType"], "sbom-workbench.selftest-pack/v1")
        self.assertEqual(
            statement["subject"],
            [{"name": "MANIFEST.json", "digest": {"sha256": _SHA}}],
        )
        self.assertEqual(statement["predicate"]["run_id"], "r1")
        # validate is idempotent on a well-formed envelope
        self.assertIs(validate_statement(statement), statement)

    def test_wrap_rejects_malformed_inputs(self) -> None:
        cases = [
            (dict(predicate_type="", subject_name="x", subject_sha256=_SHA, predicate={}), "predicate_type"),
            (dict(predicate_type="p", subject_name="", subject_sha256=_SHA, predicate={}), "subject_name"),
            (dict(predicate_type="p", subject_name="x", subject_sha256="short", predicate={}), "subject_sha256"),
            (dict(predicate_type="p", subject_name="x", subject_sha256=_SHA, predicate=None), "predicate"),  # type: ignore[dict-item]
        ]
        for kwargs, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(InTotoError):
                    wrap_statement(**kwargs)

    def test_validate_rejects_wrong_statement_type(self) -> None:
        bad = wrap_statement(
            predicate_type="p", subject_name="x", subject_sha256=_SHA, predicate={}
        )
        bad["_type"] = "https://example.invalid/Other/v1"
        with self.assertRaises(InTotoError):
            validate_statement(bad)

    def test_validate_rejects_multi_or_digestless_subject(self) -> None:
        with self.subTest("multi-subject"):
            statement = wrap_statement(
                predicate_type="p", subject_name="x", subject_sha256=_SHA, predicate={}
            )
            statement["subject"].append(statement["subject"][0])
            with self.assertRaises(InTotoError):
                validate_statement(statement)
        with self.subTest("digest missing sha256"):
            statement = wrap_statement(
                predicate_type="p", subject_name="x", subject_sha256=_SHA, predicate={}
            )
            statement["subject"][0]["digest"] = {}
            with self.assertRaises(InTotoError):
                validate_statement(statement)
        with self.subTest("predicate not dict"):
            statement = wrap_statement(
                predicate_type="p", subject_name="x", subject_sha256=_SHA, predicate={}
            )
            statement["predicate"] = "not-a-dict"
            with self.assertRaises(InTotoError):
                validate_statement(statement)


if __name__ == "__main__":
    unittest.main()
