"""Freeze the exact public schema bytes used by the offline engineering validator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path


SOURCES = (
    {
        "artifact_id": "cyclonedx-json-schema-1.7",
        "url": "https://raw.githubusercontent.com/CycloneDX/specification/4b3f59453366e27c8073fd24e98bf21ef8892c8e/schema/bom-1.7.schema.json",
        "relative_path": "cyclonedx-1.7/bom-1.7.schema.json",
        "cache_name": "cyclonedx-bom-1.7.schema.json",
        "sha256": "df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221",
        "license_expression_candidate": "Apache-2.0",
    },
    {
        "artifact_id": "spdx-json-schema-3.0.1",
        "url": "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        "relative_path": "spdx-3.0.1/spdx-json-schema.json",
        "cache_name": "spdx-json-schema-3.0.1.json",
        "sha256": "582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1",
        "license_expression_candidate": "LICENSE_REVIEW_REQUIRED",
    },
    {
        "artifact_id": "spdx-jsonld-context-3.0.1",
        "url": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "relative_path": "spdx-3.0.1/spdx-context.jsonld",
        "cache_name": "spdx-context-3.0.1.jsonld",
        "sha256": "c72b0928f094c83e5c127784edb1ebca2af74a104fcacc007c332b23cbc788bd",
        "license_expression_candidate": "LICENSE_REVIEW_REQUIRED",
    },
    {
        "artifact_id": "spdx-ontology-shacl-3.0.1",
        "url": "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        "relative_path": "spdx-3.0.1/spdx-model.ttl",
        "cache_name": "spdx-model-3.0.1.ttl",
        "sha256": "30ebb4af2d70a9809044ef46f44cc3dc5125226d70f818a50ed2e1d5f404c593",
        "license_expression_candidate": "LICENSE_REVIEW_REQUIRED",
    },
)

ALLOWED_HOSTS = {"raw.githubusercontent.com", "spdx.org"}
MAX_BYTES = 2_000_000


class FreezeError(RuntimeError):
    """Raised when a frozen public artifact does not match its declared identity."""


def _verify_payload(source: dict[str, str], payload: bytes) -> bytes:
    if len(payload) > MAX_BYTES:
        raise FreezeError(f"artifact exceeds byte limit: {source['artifact_id']}")
    observed = hashlib.sha256(payload).hexdigest()
    if observed != source["sha256"]:
        raise FreezeError(
            f"SHA-256 mismatch for {source['artifact_id']}: expected {source['sha256']}, got {observed}"
        )
    return payload


def _download(source: dict[str, str]) -> bytes:
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": "offline-sbom-evidence-workbench/0.1 schema-freezer"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        final_url = response.geturl()
        host = (urllib.parse.urlsplit(final_url).hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise FreezeError(f"redirected to an unapproved host: {host}")
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None and int(declared_length) > MAX_BYTES:
            raise FreezeError(f"artifact exceeds byte limit: {source['artifact_id']}")
        payload = response.read(MAX_BYTES + 1)
    return _verify_payload(source, payload)


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def freeze(destination: Path, cache_directory: Path | None = None) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for source in SOURCES:
        if cache_directory is None:
            payload = _download(source)
            import_method = "HTTPS_WITH_HASH_VERIFICATION"
        else:
            cache_file = cache_directory / source["cache_name"]
            if not cache_file.is_file() or cache_file.is_symlink():
                raise FreezeError(f"verified cache artifact is missing or unsafe: {cache_file}")
            payload = _verify_payload(source, cache_file.read_bytes())
            import_method = "LOCAL_CACHE_WITH_HASH_VERIFICATION"
        target = destination / source["relative_path"]
        _write_atomic(target, payload)
        records.append(
            {
                **source,
                "byte_count": len(payload),
                "rights_status": "AWAITING_NAMED_REVIEW",
                "distribution_status": "NOT_APPROVED",
                "use_scope": "OFFLINE_MECHANICAL_VALIDATION_ENGINEERING",
                "import_method": import_method,
            }
        )
    manifest = {
        "schema_version": "1.0",
        "classification": "ENGINEERING_EVALUATION_ONLY",
        "frozen_at": "2026-08-02",
        "network_required_at_runtime": False,
        "artifacts": records,
    }
    _write_atomic(
        destination / "SOURCE_MANIFEST.json",
        (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "vendor" / "specs",
    )
    parser.add_argument(
        "--cache-directory",
        type=Path,
        help="directory containing previously downloaded bytes with the declared cache names",
    )
    arguments = parser.parse_args()
    manifest = freeze(arguments.destination, arguments.cache_directory)
    print(json.dumps({"status": "FROZEN", "artifacts": len(manifest["artifacts"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
