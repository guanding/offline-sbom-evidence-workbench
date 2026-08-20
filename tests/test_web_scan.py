from __future__ import annotations

import hashlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from sbom_workbench.web_scan import (
    OUTPUTS,
    SCAN_RECEIPT_FORMAT,
    BackendResult,
    DownloadArtifact,
    ScanJobStore,
    WebScanError,
    _replace_sensitive_home_roots,
    _sensitive_path_count,
    canonical_intake_fingerprint,
    discover_scanner_runtime,
)


def intake(
    *,
    files: list[dict[str, object]] | None = None,
    source_kind: str = "directory",
) -> dict[str, object]:
    return {
        "source_kind": source_kind,
        "product_name": "Synthetic Browser Project",
        "declared_version": "1.2.3-test",
        "output_format": "cyclonedx-json",
        "files": files or [{"relative_path": "project/requirements.txt", "size": 12}],
    }


class FakeScanner:
    def status(self) -> dict[str, object]:
        return {
            "enabled": True,
            "status": "FAKE_TEST_SCANNER",
            "formats": list(OUTPUTS),
        }

    def scan(
        self,
        *,
        job_root: Path,
        source_root: Path,
        output_root: Path,
        product_name: str,
        declared_version: str,
    ) -> BackendResult:
        self.source_bytes = (source_root / "project" / "requirements.txt").read_bytes()
        download_root = job_root / "downloads"
        download_root.mkdir()
        artifacts: dict[str, DownloadArtifact] = {}
        downloads: dict[str, dict[str, object]] = {}
        for format_id, (_, label, suffix) in OUTPUTS.items():
            path = download_root / f"synthetic.{suffix}.json"
            payload = json.dumps(
                {
                    "format": format_id,
                    "product": product_name,
                    "version": declared_version,
                },
                sort_keys=True,
            ).encode()
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            artifact = DownloadArtifact(
                format_id=format_id,
                label=label,
                path=path,
                filename=path.name,
                sha256=digest,
                size=len(payload),
            )
            artifacts[format_id] = artifact
            downloads[format_id] = {
                "format": format_id,
                "label": label,
                "filename": path.name,
                "sha256": digest,
                "size": len(payload),
                "url": f"/api/intakes/{{job_id}}/downloads/{format_id}",
            }
        receipt_payload = json.dumps(
            {
                "classification": "SYNTHETIC_NOT_EVIDENCE",
                "status": "FAKE_TEST_RECEIPT",
            },
            sort_keys=True,
        ).encode()
        receipt_path = download_root / "synthetic.scan-receipt.json"
        receipt_path.write_bytes(receipt_payload)
        receipt_digest = hashlib.sha256(receipt_payload).hexdigest()
        artifacts[SCAN_RECEIPT_FORMAT] = DownloadArtifact(
            format_id=SCAN_RECEIPT_FORMAT,
            label="Scan evidence receipt JSON",
            path=receipt_path,
            filename=receipt_path.name,
            sha256=receipt_digest,
            size=len(receipt_payload),
        )
        # The store must ignore backend-provided routes and reconstruct local URLs.
        downloads[SCAN_RECEIPT_FORMAT] = {
            "format": SCAN_RECEIPT_FORMAT,
            "label": "Untrusted backend label",
            "filename": "untrusted.json",
            "sha256": "0" * 64,
            "size": 1,
            "url": "https://attacker.invalid/receipt",
        }
        return BackendResult(
            public={
                "component_count": 1,
                "coverage_gate": "OPEN_REVIEW",
                "component_population_gate": "OPEN_REVIEW_SINGLE_SOURCE_DECLARATION_SCOPE",
                "downloads": downloads,
            },
            artifacts=artifacts,
        )


class WebScanContractTests(unittest.TestCase):
    def test_privacy_projection_replaces_scanner_home_defaults(self) -> None:
        projected, count = _replace_sensitive_home_roots(
            {
                "go_cache": "/" + "Users/customer/go/pkg/mod",
                "maven_cache": "/home/operator/.m2/repository",
                "windows_cache": "C:" + r"\Users\engineer\.cache",
            }
        )
        self.assertEqual(count, 3)
        self.assertEqual(_sensitive_path_count(projected), 0)
        self.assertEqual(projected["go_cache"], "${USER_HOME}/go/pkg/mod")

    def test_intake_fingerprint_is_deterministic(self) -> None:
        first = canonical_intake_fingerprint(intake())
        second = canonical_intake_fingerprint(intake())
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_intake_rejects_case_and_file_directory_collisions(self) -> None:
        with self.assertRaisesRegex(WebScanError, "case-insensitive collision"):
            canonical_intake_fingerprint(
                intake(
                    files=[
                        {"relative_path": "project/Readme.md", "size": 1},
                        {"relative_path": "project/README.md", "size": 1},
                    ]
                )
            )
        with self.assertRaisesRegex(WebScanError, "parent directory"):
            canonical_intake_fingerprint(
                intake(
                    files=[
                        {"relative_path": "project/vendor", "size": 1},
                        {"relative_path": "project/vendor/module.py", "size": 1},
                    ]
                )
            )
        with self.assertRaisesRegex(WebScanError, "directory spellings collide"):
            canonical_intake_fingerprint(
                intake(
                    files=[
                        {"relative_path": "Project/a.txt", "size": 1},
                        {"relative_path": "project/b.txt", "size": 1},
                    ]
                )
            )

    def test_individual_file_selection_cannot_invent_directories(self) -> None:
        with self.assertRaisesRegex(WebScanError, "cannot declare directory"):
            canonical_intake_fingerprint(intake(source_kind="files"))

    def test_partial_explicit_runtime_tuple_is_blocked(self) -> None:
        with self.assertRaisesRegex(WebScanError, "provided together"):
            discover_scanner_runtime(syft_bin=Path("/tmp/not-used"))

    def test_disabled_store_refuses_intake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            store = ScanJobStore(root, None)
            try:
                with self.assertRaisesRegex(WebScanError, "尚未配置"):
                    store.create(intake())
            finally:
                store.shutdown()
            self.assertFalse(root.exists())

    def test_upload_scan_download_and_discard_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            scanner = FakeScanner()
            store = ScanJobStore(root, scanner)
            try:
                created = store.create(intake())
                job_id = created["job_id"]
                self.assertEqual(created["status"], "UPLOADING")
                uploaded = store.upload(job_id, 0, io.BytesIO(b"requests==2\n"), 12)
                self.assertEqual(uploaded["status"], "READY")
                self.assertEqual(uploaded["source"]["uploaded_bytes"], 12)
                queued = store.start(job_id)
                self.assertIn(queued["status"], {"QUEUED", "SCANNING", "COMPLETE"})
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    current = store.public(job_id)
                    if current["status"] not in {"QUEUED", "SCANNING"}:
                        break
                    time.sleep(0.01)
                self.assertEqual(current["status"], "COMPLETE")
                self.assertEqual(scanner.source_bytes, b"requests==2\n")
                artifact = store.artifact(job_id, "cyclonedx-json")
                self.assertEqual(hashlib.sha256(artifact.path.read_bytes()).hexdigest(), artifact.sha256)
                self.assertIn(job_id, current["result"]["downloads"]["cyclonedx-json"]["url"])
                receipt = current["result"]["downloads"][SCAN_RECEIPT_FORMAT]
                self.assertEqual(receipt["label"], "Scan evidence receipt JSON")
                self.assertEqual(
                    receipt["url"],
                    f"/api/intakes/{job_id}/downloads/{SCAN_RECEIPT_FORMAT}",
                )
                discarded = store.discard(job_id)
                self.assertEqual(discarded["status"], "DISCARDED")
                with self.assertRaisesRegex(WebScanError, "not registered"):
                    store.public(job_id)
            finally:
                store.shutdown()

    def test_truncated_upload_is_removed_and_can_be_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            store = ScanJobStore(root, FakeScanner())
            try:
                request = intake(files=[{"relative_path": "project/requirements.txt", "size": 2}])
                job_id = store.create(request)["job_id"]
                with self.assertRaisesRegex(WebScanError, "ended before"):
                    store.upload(job_id, 0, io.BytesIO(b"x"), 2)
                job_root = root / job_id / "source" / "project"
                self.assertFalse((job_root / "requirements.txt").exists())
                self.assertFalse((job_root / ".requirements.txt.uploading").exists())
                uploaded = store.upload(job_id, 0, io.BytesIO(b"xy"), 2)
                self.assertEqual(uploaded["status"], "READY")
            finally:
                store.shutdown()

    def test_discard_refuses_an_in_progress_upload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ScanJobStore(Path(temporary) / "jobs", FakeScanner())
            try:
                job_id = store.create(intake())["job_id"]
                job = store._job(job_id)
                with job.lock:
                    job.uploading_indexes.add(0)
                with self.assertRaisesRegex(WebScanError, "正在上传或扫描"):
                    store.discard(job_id)
                with job.lock:
                    job.uploading_indexes.clear()
                self.assertEqual(store.discard(job_id)["status"], "DISCARDED")
            finally:
                store.shutdown()

    def test_download_hash_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ScanJobStore(Path(temporary) / "jobs", FakeScanner())
            try:
                job_id = store.create(intake())["job_id"]
                store.upload(job_id, 0, io.BytesIO(b"requests==2\n"), 12)
                store.start(job_id)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    current = store.public(job_id)
                    if current["status"] == "COMPLETE":
                        break
                    time.sleep(0.01)
                artifact = store.artifact(job_id, "cyclonedx-json")
                artifact.path.write_bytes(b"{}")
                with self.assertRaisesRegex(WebScanError, "metadata changed"):
                    store.artifact(job_id, "cyclonedx-json")
            finally:
                store.shutdown()


if __name__ == "__main__":
    unittest.main()
