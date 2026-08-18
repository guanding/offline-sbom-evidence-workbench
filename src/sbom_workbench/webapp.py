"""Small, localhost-only review UI using only the Python standard library."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from .model import (
    ModelAdapterError,
    ModelDisabledError,
    OmlxModelAdapter,
    build_minimal_conflict_card,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
REGISTRY_FILENAME = "runs.json"
DASHBOARD_FILENAME = "dashboard.json"
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_DASHBOARD_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 4096
MAX_COMPONENTS = 100_000

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255}")
_RUN_ROUTE = re.compile(r"/api/runs/([A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255})")
_MODEL_ROUTE = re.compile(
    r"/api/runs/([A-Za-z0-9][A-Za-z0-9._:@+_-]{0,255})/model-advice"
)
_REGISTRY_KEYS = {"schema_version", "runs"}
_RUN_ENTRY_KEYS = {"run_id", "relative_path", "dashboard_sha256"}
_DASHBOARD_KEYS = {
    "schema_version",
    "run_id",
    "classification",
    "release",
    "components",
    "reconciliation",
    "validation",
}
_SYNTHETIC_FORBIDDEN_STATUSES = {
    "SBOM_RELEASE_AUTHORIZED_BY_MANUFACTURER",
    "SBOM_ARTIFACT_RELEASED",
    "CRA_COMPLIANT",
    "CONFORMITY_CONFIRMED",
    "CAB_APPROVED",
    "CERTIFIED",
}
_PUBLIC_REFERENCE_CLASSIFICATION = "PUBLIC_BUILD_REFERENCE_NOT_CUSTOMER_EVIDENCE"
_SELF_TEST_CLASSIFICATION = "SELF_TEST_NOT_CUSTOMER_EVIDENCE"


class WebAppError(ValueError):
    """A bounded request or registered-data failure safe to map to an API error."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebAppError(400, "INVALID_JSON", f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _decode_json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except WebAppError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WebAppError(400, "INVALID_JSON", f"{label} is not strict UTF-8 JSON") from exc


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise WebAppError(400, "INVALID_IDENTIFIER", f"{label} is not a safe identifier")
    return value


def _safe_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise WebAppError(500, "INVALID_RUN_REGISTRY", f"{label} is not a relative path")
    if "\\" in value or "\x00" in value:
        raise WebAppError(500, "INVALID_RUN_REGISTRY", f"{label} is not a safe POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise WebAppError(500, "INVALID_RUN_REGISTRY", f"{label} is not normalized")
    return value


def _read_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WebAppError(500, "REGISTERED_DATA_UNAVAILABLE", f"cannot access {label}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise WebAppError(500, "UNSAFE_REGISTERED_DATA", f"{label} must be one regular file")
        if info.st_size > maximum:
            raise WebAppError(500, "REGISTERED_DATA_TOO_LARGE", f"{label} exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    except WebAppError:
        raise
    except OSError as exc:
        raise WebAppError(500, "REGISTERED_DATA_UNAVAILABLE", f"cannot read {label}") from exc
    finally:
        os.close(descriptor)
    if len(payload) > maximum:
        raise WebAppError(500, "REGISTERED_DATA_TOO_LARGE", f"{label} exceeds its byte limit")
    return payload


class RegisteredRunStore:
    """Read only a startup-frozen list of hash-bound run dashboards."""

    def __init__(self, data_root: Path) -> None:
        candidate = Path(data_root)
        if candidate.is_symlink():
            raise WebAppError(500, "UNSAFE_DATA_ROOT", "data_root must not be a symlink")
        try:
            self.root = candidate.resolve(strict=True)
        except OSError as exc:
            raise WebAppError(500, "DATA_ROOT_UNAVAILABLE", "data_root cannot be resolved") from exc
        if not self.root.is_dir():
            raise WebAppError(500, "DATA_ROOT_UNAVAILABLE", "data_root must be a directory")
        self._entries = self._load_registry()

    def _load_registry(self) -> dict[str, dict[str, str]]:
        registry_path = self.root / REGISTRY_FILENAME
        payload = _read_regular_file(
            registry_path,
            maximum=MAX_REGISTRY_BYTES,
            label="run registry",
        )
        value = _decode_json(payload, "run registry")
        if not isinstance(value, dict) or set(value) != _REGISTRY_KEYS:
            raise WebAppError(500, "INVALID_RUN_REGISTRY", "run registry fields do not match")
        if value.get("schema_version") != "1.0":
            raise WebAppError(500, "INVALID_RUN_REGISTRY", "run registry version is unsupported")
        runs = value.get("runs")
        if not isinstance(runs, list) or len(runs) > 10_000:
            raise WebAppError(500, "INVALID_RUN_REGISTRY", "run registry entries are invalid")

        entries: dict[str, dict[str, str]] = {}
        for index, raw_entry in enumerate(runs):
            label = f"runs[{index}]"
            if not isinstance(raw_entry, dict) or set(raw_entry) != _RUN_ENTRY_KEYS:
                raise WebAppError(500, "INVALID_RUN_REGISTRY", f"{label} fields do not match")
            run_id = _safe_id(raw_entry.get("run_id"), f"{label}.run_id")
            if run_id in entries:
                raise WebAppError(500, "INVALID_RUN_REGISTRY", "run IDs must be unique")
            relative_path = _safe_relative_path(raw_entry.get("relative_path"), f"{label}.relative_path")
            if relative_path != f"runs/{run_id}":
                raise WebAppError(
                    500,
                    "INVALID_RUN_REGISTRY",
                    f"{label}.relative_path must be runs/<run_id>",
                )
            digest = raw_entry.get("dashboard_sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise WebAppError(500, "INVALID_RUN_REGISTRY", f"{label} hash is invalid")
            entries[run_id] = {
                "run_id": run_id,
                "relative_path": relative_path,
                "dashboard_sha256": digest,
            }
        return entries

    def _registered_run_directory(self, entry: dict[str, str]) -> Path:
        current = self.root
        for part in PurePosixPath(entry["relative_path"]).parts:
            current = current / part
            try:
                info = current.lstat()
            except OSError as exc:
                raise WebAppError(
                    500,
                    "REGISTERED_DATA_UNAVAILABLE",
                    "registered run cannot be accessed",
                ) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise WebAppError(
                    500,
                    "UNSAFE_REGISTERED_DATA",
                    "registered run path must contain only directories",
                )
        try:
            resolved = current.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise WebAppError(
                500,
                "PATH_ESCAPE_BLOCKED",
                "registered run escaped data_root",
            ) from exc
        return resolved

    def _synthetic_status_guard(self, dashboard: dict[str, Any]) -> None:
        classification = dashboard["classification"]
        reference_like = classification in {
            _PUBLIC_REFERENCE_CLASSIFICATION,
            _SELF_TEST_CLASSIFICATION,
        }
        if not (
            classification.startswith("SYNTHETIC")
            or reference_like
        ):
            return
        release = dashboard["release"]
        if reference_like:
            if release.get("manufacturer_role") is not None:
                raise WebAppError(
                    500,
                    "REFERENCE_AUTHORITY_ESCALATION_BLOCKED",
                    "non-customer reference data cannot carry a manufacturer role",
                )
            if release.get("product_conformity_status") != "NO_PRODUCT_CONFORMITY_STATUS":
                raise WebAppError(
                    500,
                    "REFERENCE_AUTHORITY_ESCALATION_BLOCKED",
                    "non-customer reference data cannot carry product conformity status",
                )
        for key, value in release.items():
            if (
                isinstance(key, str)
                and (key == "status" or key.endswith("_status"))
                and isinstance(value, str)
                and value.upper() in _SYNTHETIC_FORBIDDEN_STATUSES
            ):
                raise WebAppError(
                    500,
                    "REFERENCE_AUTHORITY_ESCALATION_BLOCKED"
                    if reference_like
                    else "SYNTHETIC_AUTHORITY_ESCALATION_BLOCKED",
                    "non-customer reference data cannot carry manufacturer, CAB, conformity, or release authority"
                    if reference_like
                    else "synthetic data cannot carry manufacturer, CAB, conformity, or release authority",
                )

    def get_run(self, run_id: object) -> dict[str, Any]:
        normalized_id = _safe_id(run_id, "run_id")
        entry = self._entries.get(normalized_id)
        if entry is None:
            raise WebAppError(404, "RUN_NOT_REGISTERED", "run is not registered")
        run_directory = self._registered_run_directory(entry)
        payload = _read_regular_file(
            run_directory / DASHBOARD_FILENAME,
            maximum=MAX_DASHBOARD_BYTES,
            label="registered run dashboard",
        )
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(actual_sha256, entry["dashboard_sha256"]):
            raise WebAppError(
                409,
                "REGISTERED_RUN_HASH_MISMATCH",
                "registered dashboard no longer matches its trust anchor",
            )
        dashboard = _decode_json(payload, "registered run dashboard")
        if not isinstance(dashboard, dict) or set(dashboard) != _DASHBOARD_KEYS:
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard fields do not match")
        if dashboard.get("schema_version") != "1.0" or dashboard.get("run_id") != normalized_id:
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard identity does not match")
        classification = dashboard.get("classification")
        if not isinstance(classification, str) or not classification or len(classification) > 128:
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard classification is invalid")
        if not isinstance(dashboard.get("release"), dict):
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard release is invalid")
        components = dashboard.get("components")
        if not isinstance(components, list) or len(components) > MAX_COMPONENTS:
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard components are invalid")
        if not isinstance(dashboard.get("reconciliation"), dict):
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard reconciliation is invalid")
        if not isinstance(dashboard.get("validation"), dict):
            raise WebAppError(500, "INVALID_RUN_DASHBOARD", "dashboard validation is invalid")
        self._synthetic_status_guard(dashboard)
        return {
            **dashboard,
            "authority_boundary": {
                "manufacturer_authorization": False,
                "cab_conclusion": False,
                "cra_conformity": False,
                "certification": False,
                "message": (
                    "工作台展示和机械校验不构成制造商授权、CAB结论、CRA符合或认证。"
                ),
            },
        }

    def list_runs(self) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for run_id in sorted(self._entries, key=lambda value: value.encode("utf-8")):
            dashboard = self.get_run(run_id)
            release = dashboard["release"]
            reconciliation = dashboard["reconciliation"]
            validation = dashboard["validation"]
            summaries.append(
                {
                    "run_id": run_id,
                    "classification": dashboard["classification"],
                    "release_id": release.get("release_id", "UNKNOWN"),
                    "product": release.get("product", "UNKNOWN"),
                    "build_id": release.get("build_id", "UNKNOWN"),
                    "component_count": len(dashboard["components"]),
                    "reconciliation_status": reconciliation.get("status", "UNKNOWN"),
                    "validation_status": validation.get("status", "NOT_ASSESSED"),
                }
            )
        return summaries

    def get_conflict(self, run_id: object, conflict_id: object) -> dict[str, Any]:
        normalized_conflict_id = _safe_id(conflict_id, "conflict_id")
        dashboard = self.get_run(run_id)
        conflicts = dashboard["reconciliation"].get("conflicts")
        if not isinstance(conflicts, list) or len(conflicts) > MAX_COMPONENTS:
            raise WebAppError(404, "CONFLICT_NOT_REGISTERED", "run has no registered conflicts")
        matches = [
            conflict
            for conflict in conflicts
            if isinstance(conflict, dict) and conflict.get("conflict_id") == normalized_conflict_id
        ]
        if len(matches) != 1:
            raise WebAppError(404, "CONFLICT_NOT_REGISTERED", "conflict is not uniquely registered")
        return matches[0]


class WorkbenchHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        store: RegisteredRunStore,
        model_adapter: OmlxModelAdapter,
    ) -> None:
        host, _ = server_address
        if host != DEFAULT_HOST:
            raise WebAppError(500, "NON_LOOPBACK_BIND_BLOCKED", "web UI may bind only 127.0.0.1")
        self.store = store
        self.model_adapter = model_adapter
        self.session_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.static_root = Path(__file__).resolve().parent / "static"
        super().__init__(server_address, WorkbenchRequestHandler)
        port = self.server_address[1]
        self.allowed_hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
        self.allowed_origins = frozenset(
            {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        )
        # URL fragments are never sent in the HTTP request target or Referer.
        self.launch_url = f"http://127.0.0.1:{port}/#token={quote(self.session_token)}"


class WorkbenchRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SBOM-Workbench"
    sys_version = ""

    @property
    def app(self) -> WorkbenchHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: object) -> None:
        # Keep run IDs, conflict IDs, and request metadata out of default logs.
        return

    def version_string(self) -> str:
        return self.server_version

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")

    def _send_bytes(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        extra_headers: tuple[tuple[str, str], ...] = (),
        head_only: bool = False,
    ) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        for key, value in extra_headers:
            self.send_header(key, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)
        self.close_connection = True

    def _json(
        self,
        status: int,
        value: object,
        *,
        head_only: bool = False,
    ) -> None:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send_bytes(status, payload, "application/json; charset=utf-8", head_only=head_only)

    def _error(self, error: WebAppError, *, head_only: bool = False) -> None:
        self._json(
            error.status,
            {"status": "BLOCKED", "error": error.code, "message": error.message},
            head_only=head_only,
        )

    def _single_header(self, name: str) -> str | None:
        values = self.headers.get_all(name, [])
        if len(values) > 1:
            raise WebAppError(400, "DUPLICATE_HEADER", f"duplicate {name} header is forbidden")
        return values[0] if values else None

    def _check_host_and_origin(self, *, unsafe: bool) -> None:
        host = self._single_header("Host")
        if host is None or host.lower() not in self.app.allowed_hosts:
            raise WebAppError(403, "HOST_BLOCKED", "Host is not in the loopback allowlist")
        origin = self._single_header("Origin")
        if unsafe and origin is None:
            raise WebAppError(403, "ORIGIN_REQUIRED", "write requests require an allowed Origin")
        if origin is not None and origin not in self.app.allowed_origins:
            raise WebAppError(403, "ORIGIN_BLOCKED", "Origin is not in the loopback allowlist")

    def _authenticated(self) -> bool:
        authorization = self._single_header("Authorization")
        bearer = None
        if authorization is not None and authorization.startswith("Bearer "):
            bearer = authorization.removeprefix("Bearer ")
        return bearer is not None and hmac.compare_digest(bearer, self.app.session_token)

    def _require_session(self) -> None:
        if not self._authenticated():
            raise WebAppError(401, "SESSION_REQUIRED", "a valid local session token is required")

    def _require_csrf(self) -> None:
        token = self._single_header("X-CSRF-Token")
        if token is None or not hmac.compare_digest(token, self.app.csrf_token):
            raise WebAppError(403, "CSRF_BLOCKED", "write request CSRF token is missing or invalid")

    def _request_path(self) -> tuple[str, str]:
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise WebAppError(400, "INVALID_REQUEST_TARGET", "request target must be origin-form")
        raw_path = parsed.path
        if "%" in raw_path or "\\" in raw_path or "\x00" in raw_path or "//" in raw_path:
            raise WebAppError(400, "INVALID_REQUEST_PATH", "encoded or noncanonical path is forbidden")
        try:
            path = unquote(raw_path, errors="strict")
        except UnicodeError as exc:
            raise WebAppError(400, "INVALID_REQUEST_PATH", "request path is invalid") from exc
        if any(part in {".", ".."} for part in PurePosixPath(path).parts):
            raise WebAppError(400, "INVALID_REQUEST_PATH", "dot path segments are forbidden")
        return path, parsed.query

    def _static(self, filename: str, content_type: str, *, head_only: bool) -> None:
        path = self.app.static_root / filename
        payload = _read_regular_file(path, maximum=2 * 1024 * 1024, label="local UI asset")
        self._send_bytes(200, payload, content_type, head_only=head_only)

    def _handle_get(self, *, head_only: bool = False) -> None:
        try:
            self._check_host_and_origin(unsafe=False)
            path, query = self._request_path()
            if query:
                raise WebAppError(400, "QUERY_BLOCKED", "query parameters are not accepted")
            if path == "/":
                self._static("index.html", "text/html; charset=utf-8", head_only=head_only)
                return
            if path == "/static/app.js":
                self._static("app.js", "text/javascript; charset=utf-8", head_only=head_only)
                return
            if path == "/static/style.css":
                self._static("style.css", "text/css; charset=utf-8", head_only=head_only)
                return
            self._require_session()
            if path == "/api/session":
                self._json(
                    200,
                    {
                        "status": "LOCAL_SESSION_ACTIVE",
                        "csrf_token": self.app.csrf_token,
                        "model": self.app.model_adapter.status(),
                        "authority_boundary": (
                            "No UI or model action grants manufacturer, CAB, conformity, or release authority."
                        ),
                    },
                    head_only=head_only,
                )
                return
            if path == "/api/runs":
                self._json(
                    200,
                    {"status": "REGISTERED_RUNS", "runs": self.app.store.list_runs()},
                    head_only=head_only,
                )
                return
            match = _RUN_ROUTE.fullmatch(path)
            if match:
                self._json(200, self.app.store.get_run(match.group(1)), head_only=head_only)
                return
            raise WebAppError(404, "NOT_FOUND", "resource was not found")
        except WebAppError as error:
            self._error(error, head_only=head_only)

    def _read_request_json(self) -> dict[str, Any]:
        if self._single_header("Transfer-Encoding") is not None:
            raise WebAppError(400, "TRANSFER_ENCODING_BLOCKED", "chunked request bodies are forbidden")
        raw_length = self._single_header("Content-Length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdigit():
            raise WebAppError(411, "CONTENT_LENGTH_REQUIRED", "bounded Content-Length is required")
        length = int(raw_length)
        if length < 1 or length > MAX_REQUEST_BYTES:
            raise WebAppError(413, "REQUEST_TOO_LARGE", "request body exceeds its byte limit")
        content_type = self._single_header("Content-Type")
        if content_type is None or content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise WebAppError(415, "JSON_REQUIRED", "Content-Type must be application/json")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise WebAppError(400, "TRUNCATED_REQUEST", "request body is truncated")
        value = _decode_json(payload, "request body")
        if not isinstance(value, dict):
            raise WebAppError(400, "INVALID_JSON", "request body must be an object")
        return value

    def do_GET(self) -> None:
        self._handle_get()

    def do_HEAD(self) -> None:
        self._handle_get(head_only=True)

    def do_POST(self) -> None:
        try:
            self._check_host_and_origin(unsafe=True)
            self._require_session()
            self._require_csrf()
            path, query = self._request_path()
            if query:
                raise WebAppError(400, "QUERY_BLOCKED", "query parameters are not accepted")
            match = _MODEL_ROUTE.fullmatch(path)
            if match is None:
                raise WebAppError(404, "NOT_FOUND", "write endpoint was not found")
            body = self._read_request_json()
            if set(body) != {"conflict_id"}:
                raise WebAppError(400, "INVALID_REQUEST", "request must contain only conflict_id")
            conflict = self.app.store.get_conflict(match.group(1), body.get("conflict_id"))
            card = build_minimal_conflict_card(match.group(1), conflict)
            result = self.app.model_adapter.advise(card)
            self._json(200, result)
        except ModelDisabledError as exc:
            self._error(WebAppError(409, "MODEL_DISABLED", str(exc)))
        except ModelAdapterError as exc:
            self._error(WebAppError(422, "MODEL_OUTPUT_REJECTED", str(exc)))
        except WebAppError as error:
            self._error(error)

    def _unsupported_write(self) -> None:
        try:
            self._check_host_and_origin(unsafe=True)
            self._require_session()
            self._require_csrf()
            raise WebAppError(405, "METHOD_NOT_ALLOWED", "method is not supported")
        except WebAppError as error:
            self._error(error)

    do_PUT = _unsupported_write
    do_PATCH = _unsupported_write
    do_DELETE = _unsupported_write

    def do_OPTIONS(self) -> None:
        try:
            self._check_host_and_origin(unsafe=False)
            raise WebAppError(405, "CORS_DISABLED", "cross-origin preflight is not supported")
        except WebAppError as error:
            self._error(error)

    def do_TRACE(self) -> None:
        self._error(WebAppError(405, "METHOD_NOT_ALLOWED", "TRACE is not supported"))

    def do_CONNECT(self) -> None:
        self._error(WebAppError(405, "METHOD_NOT_ALLOWED", "CONNECT is not supported"))


def create_server(
    data_root: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    model_adapter: OmlxModelAdapter | None = None,
) -> WorkbenchHTTPServer:
    """Create, but do not start, a loopback server with fresh session secrets."""

    store = RegisteredRunStore(Path(data_root))
    return WorkbenchHTTPServer((host, port), store, model_adapter or OmlxModelAdapter())


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sbom_workbench.webapp")
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parsed = parser.parse_args(arguments)
    try:
        server = create_server(parsed.data_root, port=parsed.port)
    except (OSError, WebAppError, ModelAdapterError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(f"Local UI: {server.launch_url}", file=sys.stderr)
    print("Model adapter: DISABLED", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
