"""Dependency-free HTTP application for the CR01 Evidence Console."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .evidence import EvidenceStore, json_bytes, run_live_validation, validate_demo_seed
from .native_demo import NativeDemoUnavailable, UNAVAILABLE


LOGGER = logging.getLogger("cr01.showcase")
from ._paths import default_project_root

STATIC_ROOT = Path(__file__).with_name("web")
MAX_REQUEST_BYTES = 4_096

STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/assets/cr01-logo.png": ("cr01-logo.png", "image/png"),
    "/favicon.ico": ("favicon.svg", "image/svg+xml"),
}


@dataclass(frozen=True)
class ShowcaseConfig:
    repo_root: Path
    access_token: str | None = None


class ShowcaseHTTPServer(ThreadingHTTPServer):
    """Threaded server carrying immutable app configuration and action gate."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        config: ShowcaseConfig,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.config = config
        self.evidence_store = EvidenceStore(config.repo_root)
        self.action_token = secrets.token_urlsafe(32)
        self.validation_gate = threading.BoundedSemaphore(value=1)
        self.started_monotonic = time.monotonic()


class ShowcaseRequestHandler(BaseHTTPRequestHandler):
    """Serve static UI assets and a small versioned JSON API."""

    server: ShowcaseHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "CR01-Showcase/0.2"
    sys_version = ""

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler's default emits HTML, including on API errors.
        self._send_api_error(HTTPStatus(code), "Request rejected", "http_error")

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def _check_host(self) -> bool:
        if is_loopback_host(str(self.server.server_address[0])):
            try:
                host = urlsplit("//" + self.headers.get("Host", "")).hostname
            except ValueError:
                host = None
            if host is None or not is_loopback_host(host):
                self._send_api_error(HTTPStatus.BAD_REQUEST, "Invalid loopback Host", "host_rejected")
                return False
        return True

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if not self._check_host():
            return
        path = urlsplit(self.path).path
        if path in STATIC_ROUTES:
            self._serve_static(path)
            return
        if path == "/api/v1/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "cr01-evidence-console",
                    "schema": "CR01-HEALTH-v1",
                    "uptime_seconds": round(time.monotonic() - self.server.started_monotonic, 3),
                },
            )
            return
        if path == "/api/v1/session":
            if not self._authorize_api():
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "schema": "CR01-SHOWCASE-SESSION-v1",
                    "action_token": self.server.action_token,
                    "bearer_required": self.server.config.access_token is not None,
                },
            )
            return
        if path in {"/api/v1/status", "/api/v1/evidence/export"}:
            if not self._authorize_api():
                return
            snapshot = self.server.evidence_store.build_snapshot()
            disposition = None
            if path.endswith("/export"):
                disposition = 'attachment; filename="cr01-evidence-snapshot.json"'
            self._send_json(HTTPStatus.OK, snapshot, content_disposition=disposition)
            return
        if path.startswith("/api/"):
            self._send_api_error(HTTPStatus.NOT_FOUND, "API route not found", "route_not_found")
            return
        self._send_api_error(HTTPStatus.NOT_FOUND, "Resource not found", "resource_not_found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if not self._check_host():
            return
        path = urlsplit(self.path).path
        if path != "/api/v1/validate":
            self._send_api_error(HTTPStatus.NOT_FOUND, "API route not found", "route_not_found")
            return
        if not self._authorize_api() or not self._authorize_action():
            return
        try:
            body = self._read_json_body()
            seed = validate_demo_seed(body.get("seed", 9700))
        except RequestError as exc:
            self._send_api_error(exc.status, exc.public_message, exc.code)
            return
        except ValueError as exc:
            self._send_api_error(HTTPStatus.BAD_REQUEST, str(exc), "invalid_seed")
            return

        if not self.server.validation_gate.acquire(blocking=False):
            self._send_api_error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "A live validation is already running",
                "validation_busy",
                retry_after="2",
            )
            return
        try:
            result = run_live_validation(seed=seed, repo_root=self.server.config.repo_root)
        except NativeDemoUnavailable:
            LOGGER.warning("Native live validation unavailable")
            self._send_api_error(HTTPStatus.SERVICE_UNAVAILABLE, UNAVAILABLE, "native_engine_unavailable")
        except Exception:
            LOGGER.exception("Bounded live validation failed")
            self._send_api_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Live validation failed; inspect the local server log",
                "validation_failed",
            )
        else:
            self._send_json(HTTPStatus.OK, result)
        finally:
            self.server.validation_gate.release()

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        self._send_api_error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "Cross-origin API negotiation is not enabled",
            "cors_disabled",
        )

    def _serve_static(self, path: str) -> None:
        filename, content_type = STATIC_ROUTES[path]
        file_path = (STATIC_ROOT / filename).resolve()
        try:
            file_path.relative_to(STATIC_ROOT.resolve())
            payload = file_path.read_bytes()
        except (ValueError, OSError):
            self._send_api_error(HTTPStatus.NOT_FOUND, "Resource not found", "resource_not_found")
            return
        self._send_bytes(
            HTTPStatus.OK,
            payload,
            content_type,
            cache_control="no-cache" if filename == "index.html" else "public, max-age=300",
        )

    def _authorize_api(self) -> bool:
        configured = self.server.config.access_token
        if configured is None:
            return True
        header = self.headers.get("Authorization", "")
        scheme, separator, supplied = header.partition(" ")
        if separator and scheme.lower() == "bearer" and supplied.isascii() and hmac.compare_digest(supplied, configured):
            return True
        self._send_api_error(
            HTTPStatus.UNAUTHORIZED,
            "Bearer access token required",
            "access_token_required",
            authenticate='Bearer realm="CR01 Evidence Console"',
        )
        return False

    def _authorize_action(self) -> bool:
        supplied = self.headers.get("X-CR01-Action-Token", "")
        if not supplied.isascii() or not hmac.compare_digest(supplied, self.server.action_token):
            self._send_api_error(
                HTTPStatus.FORBIDDEN,
                "Action session is missing or expired",
                "action_token_required",
            )
            return False
        origin = self.headers.get("Origin")
        if origin:
            origin_host = urlsplit(origin).netloc.lower()
            request_host = self.headers.get("Host", "").lower()
            if not origin_host or not hmac.compare_digest(origin_host, request_host):
                self._send_api_error(
                    HTTPStatus.FORBIDDEN,
                    "Cross-origin actions are not allowed",
                    "origin_rejected",
                )
                return False
        return True

    def _read_json_body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Ambiguous request framing", "invalid_framing")
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise RequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "Request body must be application/json",
                "unsupported_media_type",
            )
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise RequestError(
                HTTPStatus.LENGTH_REQUIRED,
                "Content-Length is required",
                "length_required",
            )
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "Invalid Content-Length",
                "invalid_content_length",
            ) from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise RequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Request body exceeds {MAX_REQUEST_BYTES} bytes",
                "request_too_large",
            )
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "Request body is not valid JSON",
                "invalid_json",
            ) from exc
        if not isinstance(value, dict):
            raise RequestError(
                HTTPStatus.BAD_REQUEST,
                "Request JSON must be an object",
                "invalid_json_shape",
            )
        return value

    def _send_api_error(
        self,
        status: HTTPStatus,
        message: str,
        code: str,
        *,
        authenticate: str | None = None,
        retry_after: str | None = None,
    ) -> None:
        self.close_connection = True  # Never parse an unread error body as a second request.
        headers: dict[str, str] = {"Connection": "close"}
        if authenticate:
            headers["WWW-Authenticate"] = authenticate
        if retry_after:
            headers["Retry-After"] = retry_after
        self._send_json(
            status,
            {
                "error": {
                    "code": code,
                    "message": message,
                    "status": int(status),
                }
            },
            extra_headers=headers,
        )

    def _send_json(
        self,
        status: HTTPStatus,
        value: object,
        *,
        content_disposition: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        headers = dict(extra_headers or {})
        if content_disposition:
            headers["Content-Disposition"] = content_disposition
        self._send_bytes(
            status,
            json_bytes(value),
            "application/json; charset=utf-8",
            cache_control="no-store",
            extra_headers=headers,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        content_type: str,
        *,
        cache_control: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        request_id = secrets.token_hex(8)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; "
            "object-src 'none'; script-src 'self'; style-src 'self'",
        )
        self.send_header("X-Request-Id", request_id)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format_string: str, *args: object) -> None:
        LOGGER.info("%s - %s", self.address_string(), format_string % args)


class RequestError(Exception):
    def __init__(self, status: HTTPStatus, public_message: str, code: str) -> None:
        super().__init__(public_message)
        self.status = status
        self.public_message = public_message
        self.code = code


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    repo_root: Path | str | None = None,
    access_token: str | None = None,
) -> ShowcaseHTTPServer:
    if access_token is not None and (not isinstance(access_token, str) or not access_token.isascii() or not access_token):
        raise ValueError("bearer token must be a nonempty ASCII string")
    if not is_loopback_host(host) and (not isinstance(access_token, str) or len(access_token) < 24):
        raise ValueError("non-loopback server creation requires a bearer token of at least 24 characters")
    config = ShowcaseConfig(
        repo_root=Path(repo_root).resolve() if repo_root is not None else default_project_root(),
        access_token=access_token,
    )
    return ShowcaseHTTPServer((host, port), ShowcaseRequestHandler, config)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CR01 Evidence Console.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host; loopback by default.")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765).")
    parser.add_argument("--repo-root", type=Path, default=default_project_root())
    parser.add_argument("--open", action="store_true", help="Open the console in the default browser.")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow a non-loopback bind. Requires a bearer token environment variable.",
    )
    parser.add_argument(
        "--access-token-env",
        default="CR01_SHOWCASE_ACCESS_TOKEN",
        help="Environment variable containing the optional bearer token.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not 0 <= args.port <= 65_535:
        raise SystemExit("--port must be between 0 and 65535")

    access_token = os.environ.get(args.access_token_env) or None
    remote = not is_loopback_host(args.host)
    if remote and not args.allow_remote:
        raise SystemExit("Non-loopback binding requires --allow-remote")
    if remote and (access_token is None or len(access_token) < 24):
        raise SystemExit(
            f"Remote binding requires {args.access_token_env} with at least 24 characters"
        )

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = create_server(
        args.host,
        args.port,
        repo_root=args.repo_root,
        access_token=access_token,
    )
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else actual_host
    url = f"http://{browser_host}:{actual_port}/"
    print(f"CR01 Evidence Console: {url}")
    print("Mode: controlled remote evaluation" if remote else "Mode: local loopback demo")
    if remote:
        print("Terminate TLS and enterprise identity policy at a trusted reverse proxy.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping CR01 Evidence Console.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
