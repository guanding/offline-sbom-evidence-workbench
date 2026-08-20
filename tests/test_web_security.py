from __future__ import annotations

import hashlib
import http.client
import json
import errno
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sbom_workbench.webapp import RegisteredRunStore, WebAppError, create_server
from tests.test_web_scan import FakeScanner, intake


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def dashboard(*, release_status: str = "SOURCE_DERIVED_CANDIDATE") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "run_id": "run-1",
        "classification": "SYNTHETIC_NOT_EVIDENCE",
        "release": {
            "release_id": "release-1",
            "product": "Synthetic Yocto Fixture",
            "product_version": "1.0",
            "build_id": "build-1",
            "release_status": release_status,
        },
        "components": [
            {
                "component_id": "component-a",
                "name": "alpha",
                "version": "1.0.0",
                "producer": "Synthetic Producer",
                "identifiers": ["pkg:generic/alpha@1.0.0"],
                "status": "CONFLICT",
            }
        ],
        "reconciliation": {
            "status": "RECONCILIATION_OPEN",
            "conflicts": [
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
                }
            ],
        },
        "validation": {
            "status": "MECHANICALLY_VALID",
            "boundary": "format validation only",
        },
    }


def write_data_root(root: Path, value: dict[str, object] | None = None) -> None:
    payload = canonical_bytes(value or dashboard())
    run = root / "runs" / "run-1"
    run.mkdir(parents=True)
    (run / "dashboard.json").write_bytes(payload)
    registry = {
        "schema_version": "1.0",
        "runs": [
            {
                "run_id": "run-1",
                "relative_path": "runs/run-1",
                "dashboard_sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }
    (root / "runs.json").write_bytes(canonical_bytes(registry))


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        write_data_root(self.root)
        try:
            self.server = create_server(self.root, port=0)
        except OSError as exc:
            self.temporary.cleanup()
            if exc.errno not in {errno.EACCES, errno.EPERM} or os.environ.get(
                "SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS"
            ) == "1":
                raise
            self.skipTest(
                "sandbox forbids loopback bind; release gate must rerun with "
                "SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1 on a loopback-capable host"
            )
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, payload

    def auth(self, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.server.session_token}", **extra}

    def test_api_requires_session_token_but_local_shell_contains_no_data(self) -> None:
        status, _, payload = self.request("GET", "/api/runs")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(payload)["error"], "SESSION_REQUIRED")

        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertIn("default-src 'none'", headers["content-security-policy"])

    def test_generation_only_store_requires_no_evidence_directory(self) -> None:
        store = RegisteredRunStore(None)
        self.assertEqual(store.list_runs(), [])
        with self.assertRaisesRegex(WebAppError, "not registered"):
            store.get_run("run-1")

    def test_port_collision_preserves_original_bind_error(self) -> None:
        with self.assertRaises(OSError) as raised:
            create_server(None, port=self.port)
        self.assertIn(raised.exception.errno, {errno.EADDRINUSE, errno.EACCES})

    def test_launch_url_uses_fragment_and_does_not_set_cross_port_cookie(self) -> None:
        self.assertEqual(
            self.server.launch_url,
            f"http://127.0.0.1:{self.port}/#token={self.server.session_token}",
        )
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", headers)

        status, _, payload = self.request("GET", f"/?token={self.server.session_token}")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"], "QUERY_BLOCKED")

    def test_bad_host_and_origin_are_blocked(self) -> None:
        status, _, payload = self.request(
            "GET",
            "/api/runs",
            headers=self.auth(Host="attacker.example"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "HOST_BLOCKED")

        status, _, payload = self.request(
            "GET",
            "/api/runs",
            headers=self.auth(Origin="http://attacker.example"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "ORIGIN_BLOCKED")

    def test_write_requires_allowed_origin_and_csrf(self) -> None:
        body = json.dumps({"conflict_id": "conflict-1"}).encode()
        base = self.auth(**{"Content-Type": "application/json"})

        status, _, payload = self.request("POST", "/api/runs/run-1/model-advice", headers=base, body=body)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "ORIGIN_REQUIRED")

        status, _, payload = self.request(
            "POST",
            "/api/runs/run-1/model-advice",
            headers={**base, "Origin": self.origin},
            body=body,
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "CSRF_BLOCKED")

        status, _, payload = self.request(
            "POST",
            "/api/runs/run-1/model-advice",
            headers={
                **base,
                "Origin": self.origin,
                "X-CSRF-Token": "wrong-token",
            },
            body=body,
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "CSRF_BLOCKED")

    def test_path_traversal_and_unregistered_run_are_blocked(self) -> None:
        status, _, payload = self.request("GET", "/api/runs/..%2frun-1", headers=self.auth())
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"], "INVALID_REQUEST_PATH")

        status, _, payload = self.request("GET", "/api/runs/not-registered", headers=self.auth())
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(payload)["error"], "RUN_NOT_REGISTERED")

    def test_registry_cannot_register_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "runs.json").write_bytes(
                canonical_bytes(
                    {
                        "schema_version": "1.0",
                        "runs": [
                            {
                                "run_id": "run-1",
                                "relative_path": "../outside",
                                "dashboard_sha256": "0" * 64,
                            }
                        ],
                    }
                )
            )
            with self.assertRaises(WebAppError):
                RegisteredRunStore(root)

    def test_model_disabled_does_not_break_read_only_main_flow(self) -> None:
        status, headers, payload = self.request("GET", "/api/runs", headers=self.auth())
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(json.loads(payload)["runs"][0]["run_id"], "run-1")

        status, _, payload = self.request("GET", "/api/runs/run-1", headers=self.auth())
        detail = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(detail["classification"], "SYNTHETIC_NOT_EVIDENCE")
        self.assertFalse(detail["authority_boundary"]["manufacturer_authorization"])
        self.assertFalse(detail["authority_boundary"]["cab_conclusion"])

        body = json.dumps({"conflict_id": "conflict-1"}).encode()
        status, _, payload = self.request(
            "POST",
            "/api/runs/run-1/model-advice",
            headers=self.auth(
                Origin=self.origin,
                **{
                    "Content-Type": "application/json",
                    "X-CSRF-Token": self.server.csrf_token,
                },
            ),
            body=body,
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["error"], "MODEL_DISABLED")

    def test_scan_intake_fails_closed_when_scanner_is_not_configured(self) -> None:
        body = json.dumps(intake()).encode()
        status, _, payload = self.request(
            "POST",
            "/api/intakes",
            headers=self.auth(
                Origin=self.origin,
                **{
                    "Content-Type": "application/json",
                    "X-CSRF-Token": self.server.csrf_token,
                },
            ),
            body=body,
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["error"], "SCANNER_DISABLED")

    def test_hash_drift_and_synthetic_release_upgrade_fail_closed(self) -> None:
        dashboard_path = self.root / "runs" / "run-1" / "dashboard.json"
        dashboard_path.write_bytes(canonical_bytes({**dashboard(), "components": []}))
        status, _, payload = self.request("GET", "/api/runs/run-1", headers=self.auth())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["error"], "REGISTERED_RUN_HASH_MISMATCH")

        # Restore a hash-bound but impermissibly upgraded synthetic dashboard.
        upgraded = dashboard(release_status="SBOM_ARTIFACT_RELEASED")
        upgraded_payload = canonical_bytes(upgraded)
        dashboard_path.write_bytes(upgraded_payload)
        registry = json.loads((self.root / "runs.json").read_text(encoding="utf-8"))
        registry["runs"][0]["dashboard_sha256"] = hashlib.sha256(upgraded_payload).hexdigest()
        (self.root / "runs.json").write_bytes(canonical_bytes(registry))

        # A new server freezes the updated registry and still rejects authority escalation.
        store = RegisteredRunStore(self.root)
        with self.assertRaisesRegex(WebAppError, "synthetic data cannot carry"):
            store.get_run("run-1")

    def test_public_reference_cannot_acquire_manufacturer_or_conformity_status(self) -> None:
        value = dashboard()
        value["classification"] = "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE"
        value["release"] = {
            **value["release"],
            "manufacturer_role": "Manufacturer",
            "product_conformity_status": "NO_PRODUCT_CONFORMITY_STATUS",
        }
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            write_data_root(root, value)
            store = RegisteredRunStore(root)
            with self.assertRaisesRegex(WebAppError, "cannot carry a manufacturer role"):
                store.get_run("run-1")

        value["release"] = {
            **value["release"],
            "manufacturer_role": None,
            "product_conformity_status": "CRA_COMPLIANT",
        }
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            write_data_root(root, value)
            store = RegisteredRunStore(root)
            with self.assertRaisesRegex(WebAppError, "cannot carry product conformity status"):
                store.get_run("run-1")


class WebScanHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        write_data_root(self.root)
        try:
            self.server = create_server(self.root, port=0, scanner_backend=FakeScanner())
        except OSError as exc:
            self.temporary.cleanup()
            if exc.errno not in {errno.EACCES, errno.EPERM} or os.environ.get(
                "SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS"
            ) == "1":
                raise
            self.skipTest(
                "sandbox forbids loopback bind; release gate must rerun with "
                "SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1 on a loopback-capable host"
            )
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, payload

    def auth(self, *, write: bool = False, **extra: str) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.server.session_token}", **extra}
        if write:
            headers.update(
                {
                    "Origin": self.origin,
                    "X-CSRF-Token": self.server.csrf_token,
                }
            )
        return headers

    def create_job(self) -> str:
        status, _, payload = self.request(
            "POST",
            "/api/intakes",
            headers=self.auth(write=True, **{"Content-Type": "application/json"}),
            body=json.dumps(intake()).encode(),
        )
        self.assertEqual(status, 201)
        return json.loads(payload)["job_id"]

    def test_session_exposes_bounded_scanner_capability(self) -> None:
        status, _, payload = self.request("GET", "/api/session", headers=self.auth())
        value = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertTrue(value["scanner"]["enabled"])
        self.assertEqual(value["scanner"]["limits"]["max_files"], 10_000)
        self.assertNotIn("syft_bin", json.dumps(value))

    def test_intake_requires_origin_and_csrf(self) -> None:
        body = json.dumps(intake()).encode()
        status, _, payload = self.request(
            "POST",
            "/api/intakes",
            headers=self.auth(**{"Content-Type": "application/json"}),
            body=body,
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "ORIGIN_REQUIRED")

    def test_full_upload_scan_download_and_cleanup_flow(self) -> None:
        job_id = self.create_job()
        status, _, payload = self.request(
            "PUT",
            f"/api/intakes/{job_id}/files/0",
            headers=self.auth(write=True, **{"Content-Type": "application/octet-stream"}),
            body=b"requests==2\n",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(payload)["status"], "READY")

        status, _, _ = self.request(
            "POST",
            f"/api/intakes/{job_id}/complete",
            headers=self.auth(write=True, **{"Content-Type": "application/json"}),
            body=b"{}",
        )
        self.assertEqual(status, 202)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status, _, payload = self.request(
                "GET", f"/api/intakes/{job_id}", headers=self.auth()
            )
            value = json.loads(payload)
            if value["status"] == "COMPLETE":
                break
            time.sleep(0.01)
        self.assertEqual(value["status"], "COMPLETE")
        metadata = value["result"]["downloads"]["cyclonedx-json"]
        receipt_metadata = value["result"]["downloads"]["scan-receipt"]
        self.assertEqual(
            receipt_metadata["url"],
            f"/api/intakes/{job_id}/downloads/scan-receipt",
        )

        status, _, payload = self.request(
            "GET", metadata["url"], headers={"Authorization": "Bearer wrong"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(payload)["error"], "SESSION_REQUIRED")

        status, headers, payload = self.request("GET", metadata["url"], headers=self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), metadata["sha256"])
        self.assertEqual(headers["x-content-sha256"], metadata["sha256"])
        self.assertTrue(headers["content-disposition"].startswith("attachment;"))
        self.assertNotIn("access-control-allow-origin", headers)

        status, headers, payload = self.request(
            "GET", receipt_metadata["url"], headers=self.auth()
        )
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), receipt_metadata["sha256"])
        self.assertEqual(headers["x-content-sha256"], receipt_metadata["sha256"])
        self.assertEqual(json.loads(payload)["status"], "FAKE_TEST_RECEIPT")

        status, _, payload = self.request(
            "DELETE", f"/api/intakes/{job_id}", headers=self.auth(write=True)
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["status"], "DISCARDED")

    def test_upload_route_rejects_encoded_path_and_wrong_media_type(self) -> None:
        job_id = self.create_job()
        status, _, payload = self.request(
            "PUT",
            f"/api/intakes/{job_id}/files/%30",
            headers=self.auth(write=True, **{"Content-Type": "application/octet-stream"}),
            body=b"requests==2\n",
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"], "INVALID_REQUEST_PATH")

        status, _, payload = self.request(
            "PUT",
            f"/api/intakes/{job_id}/files/0",
            headers=self.auth(write=True, **{"Content-Type": "text/plain"}),
            body=b"requests==2\n",
        )
        self.assertEqual(status, 415)
        self.assertEqual(json.loads(payload)["error"], "BINARY_REQUIRED")


if __name__ == "__main__":
    unittest.main()
