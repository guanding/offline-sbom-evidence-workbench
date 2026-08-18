from __future__ import annotations

import unittest

from sbom_workbench.signing import (
    SIGNING_SCHEMA_VERSION,
    SUPPORTED_SIGNATURE_SCHEME,
    SigningError,
    _assert_offline,
    build_cosign_sign_command,
    build_cosign_verify_command,
    build_receipt,
    validate_receipt,
)


_SHA = "a" * 64


class SigningCommandTests(unittest.TestCase):
    def test_sign_command_is_offline_key_based(self) -> None:
        argv = build_cosign_sign_command(
            "/runtime/cosign", "/keys/cosign.key", "MANIFEST.json", "MANIFEST.json.sig"
        )
        self.assertEqual(argv[1], "sign-blob")
        self.assertIn("--key", argv)
        self.assertIn("--output-signature", argv)
        # M7-3 review-hardened: cosign 2.x defaults to Rekor upload, force offline
        self.assertIn("--tlog-upload=false", argv)
        # separator prevents a "--"-prefixed artefact path being parsed as a flag
        self.assertIn("--", argv)
        for argument in argv:
            self.assertFalse(
                any(
                    flag in argument
                    for flag in ("--upload", "--rekor-url", "--oidc", "--identity-token")
                )
            )

    def test_verify_command_is_offline_key_based(self) -> None:
        argv = build_cosign_verify_command(
            "/runtime/cosign", "/keys/cosign.pub", "MANIFEST.json", "MANIFEST.json.sig"
        )
        self.assertEqual(argv[1], "verify-blob")
        self.assertIn("--signature", argv)
        self.assertIn("--key", argv)
        self.assertIn("--", argv)


class OfflineGuardTests(unittest.TestCase):
    """_assert_offline allowlist + denylist (M7-3 review-hardened)."""

    def test_rejects_keyless_missing_key(self) -> None:
        with self.assertRaises(SigningError):
            _assert_offline(
                ["cosign", "sign-blob", "--tlog-upload=false", "--output-signature", "x", "--", "a"]
            )

    def test_rejects_online_flags(self) -> None:
        for forbidden in (
            "--identity-token=jwt",
            "--certificate=c",
            "--bundle=b",
            "--rekor-url=u",
            "--fulcio-url=f",
            "--oidc=o",
            "--cert-email=e",
        ):
            with self.subTest(flag=forbidden):
                with self.assertRaises(SigningError):
                    _assert_offline(
                        [
                            "cosign",
                            "sign-blob",
                            "--key",
                            "k",
                            "--tlog-upload=false",
                            "--output-signature",
                            "x",
                            forbidden,
                            "--",
                            "a",
                        ]
                    )

    def test_sign_blob_requires_tlog_upload_false(self) -> None:
        with self.subTest("missing"):
            with self.assertRaises(SigningError):
                _assert_offline(
                    ["cosign", "sign-blob", "--key", "k", "--output-signature", "x", "--", "a"]
                )
        with self.subTest("explicit true"):
            with self.assertRaises(SigningError):
                _assert_offline(
                    [
                        "cosign",
                        "sign-blob",
                        "--key",
                        "k",
                        "--tlog-upload=true",
                        "--output-signature",
                        "x",
                        "--",
                        "a",
                    ]
                )

    def test_rejects_keyless_verbs(self) -> None:
        with self.assertRaises(SigningError):
            _assert_offline(["cosign", "sign", "--key", "k", "--", "a"])
        with self.assertRaises(SigningError):
            _assert_offline(["cosign", "attach-blob", "--key", "k", "--", "a"])

    def test_verify_blob_requires_signature_flag(self) -> None:
        with self.assertRaises(SigningError):
            _assert_offline(["cosign", "verify-blob", "--key", "k", "--", "a"])


class SigningReceiptTests(unittest.TestCase):
    def _tool_identity(self) -> dict:
        return {"name": "cosign", "version": "2.5.0", "binary_sha256": _SHA}

    def test_build_and_validate_roundtrip(self) -> None:
        receipt = build_receipt(
            subject_name="canonical-ite6-statement",
            subject_sha256=_SHA,
            signature_path="ite6-statement.json.sig",
            signature_sha256=_SHA,
            key_id="cosign-key-1",
            signed_at_utc="2026-08-05T00:00:00Z",
            tool_identity=self._tool_identity(),
        )
        self.assertEqual(receipt["schema_version"], SIGNING_SCHEMA_VERSION)
        self.assertEqual(receipt["scheme"], SUPPORTED_SIGNATURE_SCHEME)
        self.assertEqual(receipt["subject"]["digest"]["sha256"], _SHA)
        self.assertIs(validate_receipt(receipt), receipt)
        # M7-3 review-hardened boundary: receipt must disclaim standalone crypto force
        self.assertIn("cosign verify-blob", receipt["boundary"])

    def test_build_rejects_bad_inputs(self) -> None:
        base = dict(
            subject_name="x",
            subject_sha256=_SHA,
            signature_path="x.sig",
            signature_sha256=_SHA,
            key_id="k",
            signed_at_utc="2026-08-05T00:00:00Z",
            tool_identity=self._tool_identity(),
        )
        with self.subTest("short subject sha"):
            with self.assertRaises(SigningError):
                build_receipt(**{**base, "subject_sha256": "short"})
        with self.subTest("tool missing binary_sha256"):
            bad_tool = {"name": "cosign", "version": "2.5.0"}
            with self.assertRaises(SigningError):
                build_receipt(**{**base, "tool_identity": bad_tool})

    def test_validate_rejects_wrong_scheme_and_missing_fields(self) -> None:
        receipt = build_receipt(
            subject_name="x",
            subject_sha256=_SHA,
            signature_path="x.sig",
            signature_sha256=_SHA,
            key_id="k",
            signed_at_utc="2026-08-05T00:00:00Z",
            tool_identity=self._tool_identity(),
        )
        with self.subTest("wrong scheme"):
            bad = dict(receipt)
            bad["scheme"] = "sigstore-keyless-online"
            with self.assertRaises(SigningError):
                validate_receipt(bad)
        with self.subTest("missing field"):
            bad = dict(receipt)
            del bad["key_id"]
            with self.assertRaises(SigningError):
                validate_receipt(bad)
        with self.subTest("extra field"):
            bad = dict(receipt)
            bad["cabinet_conclusion"] = "forged"
            with self.assertRaises(SigningError):
                validate_receipt(bad)
        with self.subTest("bad digest"):
            bad = dict(receipt)
            bad["subject"] = {"name": "x", "digest": {"sha256": "short"}}
            with self.assertRaises(SigningError):
                validate_receipt(bad)


if __name__ == "__main__":
    unittest.main()
