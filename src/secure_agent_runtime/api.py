"""Dependency-free JSON HTTP API for the secure runtime."""

from __future__ import annotations

import hmac
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlparse

from . import __version__
from .models import JsonValue, Message, RuntimeRequest
from .runtime import SecureAgentRuntime

MAX_BODY_BYTES = 1_048_576


class RuntimeHTTPServer(ThreadingHTTPServer):
    runtime: SecureAgentRuntime
    api_token: str | None


class RuntimeRequestHandler(BaseHTTPRequestHandler):
    server_version = "SecureAgentRuntime/1.0"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "version": __version__,
                    "policy_version": self._server.runtime.policy.config.policy_version,
                },
            )
            return
        if not self._authorized():
            return
        if path == "/v1/audit/verify":
            self._send_json(
                HTTPStatus.OK,
                self._server.runtime.audit.verify().to_dict(),
            )
            return
        self._send_error(HTTPStatus.NOT_FOUND, "route not found")

    def do_POST(self) -> None:
        if not self._authorized():
            return
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
            if path == "/v1/evaluate":
                text = payload.get("text")
                if not isinstance(text, str):
                    raise ValueError("text must be a string")
                result = self._server.runtime.policy.evaluate_input(
                    (Message(role="user", content=text),)
                )
                self._send_json(HTTPStatus.OK, result.to_dict())
                return
            if path == "/v1/run":
                request = RuntimeRequest.from_dict(payload)
                response = self._server.runtime.run(request)
                self._send_json(HTTPStatus.OK, response.to_dict())
                return
            self._send_error(HTTPStatus.NOT_FOUND, "route not found")
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "request body must be valid JSON")
        except Exception:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "request failed safely")

    @property
    def _server(self) -> RuntimeHTTPServer:
        return cast(RuntimeHTTPServer, self.server)

    def _authorized(self) -> bool:
        expected = self._server.api_token
        if not expected:
            return True
        supplied = self.headers.get("Authorization", "")
        if supplied.startswith("Bearer "):
            supplied = supplied[7:]
        else:
            supplied = ""
        if hmac.compare_digest(supplied.encode(), expected.encode()):
            return True
        self._send_error(HTTPStatus.UNAUTHORIZED, "authentication required")
        return False

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type.lower():
            raise ValueError("Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError(f"request body must not exceed {MAX_BODY_BYTES} bytes")
        body = self.rfile.read(length)
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, {"error": message, "status": int(status)})

    def _send_json(self, status: HTTPStatus, payload: JsonValue) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid accidental prompt or credential exposure in default HTTP access logs.
        del format, args


def create_server(
    runtime: SecureAgentRuntime,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    api_token: str | None = None,
) -> RuntimeHTTPServer:
    server = RuntimeHTTPServer((host, port), RuntimeRequestHandler)
    server.runtime = runtime
    server.api_token = api_token
    return server
