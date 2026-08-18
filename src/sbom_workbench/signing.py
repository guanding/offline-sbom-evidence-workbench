"""Offline signature framework for sealed evidence packs (M7-3).

Wraps cosign offline key-based signing so sealed packs gain non-repudiation.
Hard rules (enforced by the command builders and the receipt schema):

* **Offline only**: ``cosign sign-blob --key --tlog-upload=false`` /
  ``verify-blob --key`` are used. cosign 2.x defaults to Rekor upload, so the
  sign builder MUST emit ``--tlog-upload=false`` explicitly. Keyless mode,
  Fulcio certificates, OIDC identity tokens, and Rekor URLs are forbidden
  because they require online interaction (the workbench is OS-level
  network-denied). A Rekor inclusion-proof *bundle* may be attached as optional
  offline evidence later, but is never required.
* **Allowlist + denylist**: ``_assert_offline`` requires ``--key`` (key-based,
  not keyless), pins the verb to ``sign-blob``/``verify-blob``, requires the
  sign-specific ``--tlog-upload=false`` + ``--output-signature``, and rejects a
  denylist of online flags. A ``--`` separator precedes the artefact path so a
  ``--``-prefixed path cannot be parsed as a flag.
* **Signature is enhancement, not a blocker**: unsigned packs remain valid.
  A signature receipt, when present, is fail-closed verified.
* **Receipt is structural only**: ``validate_receipt`` checks the schema; the
  cryptographic force requires an external ``cosign verify-blob`` pass plus an
  acquisition-registry trust-anchor cross-check. The receipt never proves
  conformity, release, or CAB conclusion on its own.
* **cosign is acquired separately** (acquisition receipt + runtime registry,
  same trust-anchor pattern as Syft). This module only builds the command and
  validates the receipt; it never downloads or executes cosign itself.

The CLI integration (``sign-selftest-pack`` / ``verify-signature``) lands with
the cosign acquisition step; this module is the framework those commands build
on.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import EvidenceError

SIGNING_SCHEMA_VERSION = "sbom-workbench.signature-receipt/v1"
SUPPORTED_SIGNATURE_SCHEME = "cosign-key-based-offline"
_SHA256_HEX_LEN = 64
# cosign flags that force online interaction (Fulcio cert / Rekor upload / OIDC).
# --tlog-upload is handled specially: =false is REQUIRED (force offline); bare
# or =true is forbidden (checked in _assert_offline).
_FORBIDDEN_ONLINE_FLAGS = (
    "--upload",
    "--rekor-url",
    "--fulcio-url",
    "--oidc",
    "--identity-token",
    "--certificate",
    "--cert-email",
    "--bundle",
)
_ALLOWED_COSIGN_VERBS = ("sign-blob", "verify-blob")


class SigningError(EvidenceError):
    """Raised when a signature receipt cannot be built or verified fail-closed."""


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LEN:
        raise SigningError(f"{label} must be a {_SHA256_HEX_LEN}-char sha256 hex string")
    return value


def _require_non_empty_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SigningError(f"{label} must be a non-empty string")
    return value


def build_cosign_sign_command(
    cosign_bin: Path | str,
    key_path: Path | str,
    artefact_path: Path | str,
    output_signature_path: Path | str,
) -> list[str]:
    """Build an offline key-based ``cosign sign-blob`` command.

    cosign 2.x defaults to Rekor transparency-log upload (online); the builder
    MUST emit ``--tlog-upload=false`` to stay offline. The ``--`` separator
    prevents a ``--``-prefixed artefact path being parsed as a flag. The caller
    runs this under a network-deny sandbox and owns timeout enforcement.
    """
    argv = [
        str(cosign_bin),
        "sign-blob",
        "--key",
        str(key_path),
        "--tlog-upload=false",
        "--use-signing-config=false",
        "--new-bundle-format=false",
        "--output-signature",
        str(output_signature_path),
        "--",
        str(artefact_path),
    ]
    _assert_offline(argv)
    return argv


def build_cosign_verify_command(
    cosign_bin: Path | str,
    key_path: Path | str,
    artefact_path: Path | str,
    signature_path: Path | str,
) -> list[str]:
    """Build an offline key-based ``cosign verify-blob`` command."""
    argv = [
        str(cosign_bin),
        "verify-blob",
        "--key",
        str(key_path),
        "--signature",
        str(signature_path),
        "--insecure-ignore-tlog=true",
        "--",
        str(artefact_path),
    ]
    _assert_offline(argv)
    return argv


def _assert_offline(argv: list[str]) -> None:
    """Allowlist + denylist guard for offline key-based cosign commands."""
    if len(argv) < 3 or argv[1] not in _ALLOWED_COSIGN_VERBS:
        raise SigningError(
            "cosign verb must be sign-blob or verify-blob (keyless verbs forbidden)"
        )
    if "--key" not in argv:
        raise SigningError("cosign command must be key-based (--key required)")
    if argv[1] == "sign-blob":
        if "--tlog-upload=false" not in argv:
            raise SigningError("cosign sign-blob must force --tlog-upload=false (offline)")
        if "--use-signing-config=false" not in argv:
            raise SigningError(
                "cosign sign-blob must force --use-signing-config=false "
                "(cosign 3.x defaults to a remote signing config)"
            )
        if "--new-bundle-format=false" not in argv:
            raise SigningError(
                "cosign sign-blob must force --new-bundle-format=false "
                "(cosign 3.x defaults to bundle; detached signature required)"
            )
        if "--output-signature" not in argv:
            raise SigningError("cosign sign-blob must emit --output-signature")
    else:  # verify-blob
        if "--signature" not in argv:
            raise SigningError("cosign verify-blob must carry --signature")
        if "--insecure-ignore-tlog=true" not in argv:
            raise SigningError(
                "cosign verify-blob must force --insecure-ignore-tlog=true "
                "(offline key signatures carry no Rekor entry; this skips the "
                "online tlog query, it does not weaken the key-based signature check)"
            )
    for argument in argv:
        if "--tlog-upload" in argument and "false" not in argument:
            raise SigningError("cosign --tlog-upload must be =false (offline)")
        if any(forbidden in argument for forbidden in _FORBIDDEN_ONLINE_FLAGS):
            raise SigningError(
                "cosign command must stay offline; forbidden online flag present"
            )


def build_receipt(
    *,
    subject_name: str,
    subject_sha256: str,
    signature_path: str,
    signature_sha256: str,
    key_id: str,
    signed_at_utc: str,
    tool_identity: dict[str, Any],
) -> dict[str, Any]:
    """Build a signature receipt binding one artefact to one key."""
    _require_non_empty_str(subject_name, "subject_name")
    _require_sha256(subject_sha256, "subject_sha256")
    _require_non_empty_str(signature_path, "signature_path")
    _require_sha256(signature_sha256, "signature_sha256")
    _require_non_empty_str(key_id, "key_id")
    _require_non_empty_str(signed_at_utc, "signed_at_utc")
    if not isinstance(tool_identity, dict):
        raise SigningError("tool_identity must be a dict")
    for required in ("name", "version", "binary_sha256"):
        if required not in tool_identity:
            raise SigningError(f"tool_identity missing required field: {required}")
    _require_sha256(tool_identity["binary_sha256"], "tool_identity.binary_sha256")
    return {
        "schema_version": SIGNING_SCHEMA_VERSION,
        "scheme": SUPPORTED_SIGNATURE_SCHEME,
        "subject": {"name": subject_name, "digest": {"sha256": subject_sha256}},
        "signature": {
            "path": signature_path,
            "sha256": signature_sha256,
        },
        "key_id": key_id,
        "signed_at_utc": signed_at_utc,
        "tool_identity": tool_identity,
        "boundary": (
            "Signature receipt is structural only; cryptographic force requires an "
            "external cosign verify-blob pass plus acquisition-registry trust-anchor "
            "cross-check. Non-repudiation enhancement only; not release authority, "
            "CRA/prEN-7 conformity, manufacturer authorization, or CAB conclusion."
        ),
    }


def validate_receipt(receipt: object) -> dict[str, Any]:
    """Fail-closed structural verification of a signature receipt."""
    if not isinstance(receipt, dict):
        raise SigningError("receipt must be a dict")
    expected_keys = {
        "schema_version",
        "scheme",
        "subject",
        "signature",
        "key_id",
        "signed_at_utc",
        "tool_identity",
        "boundary",
    }
    if set(receipt) != expected_keys:
        raise SigningError("receipt fields do not match the fixed schema")
    if receipt["schema_version"] != SIGNING_SCHEMA_VERSION:
        raise SigningError("receipt schema_version is not supported")
    if receipt["scheme"] != SUPPORTED_SIGNATURE_SCHEME:
        raise SigningError("receipt scheme must be cosign offline key-based")
    subject = receipt["subject"]
    if not isinstance(subject, dict):
        raise SigningError("subject must be a dict")
    _require_non_empty_str(subject.get("name"), "subject.name")
    digest = subject.get("digest")
    if not isinstance(digest, dict):
        raise SigningError("subject.digest must be a dict")
    _require_sha256(digest.get("sha256"), "subject.digest.sha256")
    signature = receipt["signature"]
    if not isinstance(signature, dict):
        raise SigningError("signature must be a dict")
    _require_non_empty_str(signature.get("path"), "signature.path")
    _require_sha256(signature.get("sha256"), "signature.sha256")
    _require_non_empty_str(receipt.get("key_id"), "key_id")
    _require_non_empty_str(receipt.get("signed_at_utc"), "signed_at_utc")
    tool_identity = receipt.get("tool_identity")
    if not isinstance(tool_identity, dict):
        raise SigningError("tool_identity must be a dict")
    for required in ("name", "version", "binary_sha256"):
        if required not in tool_identity:
            raise SigningError(f"tool_identity missing required field: {required}")
    _require_sha256(tool_identity.get("binary_sha256"), "tool_identity.binary_sha256")
    return receipt
