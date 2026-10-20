"""Local dashboard server (standard library only).

Threat model: the dashboard shows data from logs an attacker may have influenced, and a
browser on the same machine may have other (hostile) pages open. So:

  * It listens on loopback only and refuses to start otherwise.
  * Every API call needs a random per-run token in the `X-TW-Token` header. The token is
    embedded in the page you open from the printed URL; other web pages cannot read it,
    and a cross-site request cannot add a custom header without a CORS preflight, which
    this server never approves (it sends no CORS headers).
  * The Host header must be this server's own loopback address (DNS-rebinding defence) and
    any Origin on a POST must be the same origin.
  * The page is served with a strict Content-Security-Policy: scripts and styles only from
    this server, no inline code, no framing, no outside connections.
  * Log and feed text is returned as JSON and rendered with textContent only.
  * Nothing here blocks, sends or publishes anything outside the local `out/` folder.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import shutil
import socket
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import api
from .api import ApiError, Context

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
JSON_BODY_SLACK = 1024 * 1024  # JSON bodies may be this much larger than the paste limit
CHUNK = 1024 * 1024
TOKEN_BYTES = 12  # 16 URL-safe characters
DRAIN_AUTH_FAILURE = 1024 * 1024  # after a 403 we only swallow a little of what an unauthenticated client sends
DRAIN_IDLE_SECONDS = 5

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

_ID = re.compile(r"^/api/(case|indicator|advisory)/([A-Za-z0-9-]{1,40})$")
_ADV_ACTION = re.compile(r"^/api/advisory/(\d{1,9})/(edit|submit|approve|reject|publish)$")

POST_ROUTES = {
    "/api/plan": api.plan_save,
    "/api/feedback": api.feedback_add,
    "/api/ingest": api.ingest,
    "/api/sources/remove": api.remove_source,
    "/api/feeds/fetch": api.fetch_feed,
    "/api/advisory/draft": api.advisory_draft,
    "/api/advisory/check": api.advisory_check,
}
ADV_ACTIONS = {
    "edit": api.advisory_edit, "submit": api.advisory_submit, "approve": api.advisory_approve,
    "reject": api.advisory_reject, "publish": api.advisory_publish,
}


class DashboardServer(ThreadingHTTPServer):
    """On Windows, SO_REUSEADDR lets a second process bind a port that is already being listened on, and
    the operating system then hands connections to either one. A stale dashboard could answer your browser
    with a different access token than the one printed by the new dashboard. Binding exclusively makes a
    second dashboard pick the next free port instead. (On other systems SO_REUSEADDR only allows a quick
    restart, so it stays on.)"""

    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_handler(ctx: Context, token: str, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "ThreatWeaver"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 120  # a stalled client cannot hold a thread (or a half-written upload) forever

        # -- plumbing ----------------------------------------------------
        def log_message(self, fmt: str, *args: Any) -> None:  # never log the query string (it holds the token)
            sys.stderr.write(f"[ui] {self.command} {urlsplit(self.path).path} -> {args[1] if len(args) > 1 else ''}\n")

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        _unread = 0  # bytes of the current request body not yet read

        def _error(self, status: int, message: str) -> None:
            self.close_connection = True  # an unread request body must not be mistaken for the next request
            self._json(status, {"error": message})
            self._drain(DRAIN_AUTH_FAILURE if status in (HTTPStatus.FORBIDDEN, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                        else api.MAX_UPLOAD_BYTES + JSON_BODY_SLACK)

        def _drain(self, limit: int) -> None:
            """Read and discard what the client is still sending after we replied early.

            Closing with unread data makes the operating system reset the connection, and the
            browser may then show a network error instead of our message. This is skipped when
            the body was already read.
            """
            remaining = min(self._unread, limit)
            self._unread = 0
            if remaining <= 0:
                return
            try:
                self.connection.settimeout(DRAIN_IDLE_SECONDS)
                while remaining > 0:
                    block = self.rfile.read(min(CHUNK, remaining))
                    if not block:
                        break
                    remaining -= len(block)
            except OSError:
                pass

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _api_ok(self) -> bool:
            if not self._host_ok():
                self._error(HTTPStatus.FORBIDDEN, "bad host")
                return False
            sent = self.headers.get("X-TW-Token", "")
            if not hmac.compare_digest(sent.encode(), token.encode()):
                self._error(HTTPStatus.FORBIDDEN, "missing or wrong token; open the dashboard from the URL printed in the terminal")
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                self._error(HTTPStatus.FORBIDDEN, "bad origin")
                return False
            return True

        # -- GET ---------------------------------------------------------
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path, query = parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}

            if path in ("/", "/index.html"):
                if not self._host_ok():
                    return self._error(HTTPStatus.FORBIDDEN, "bad host")
                if not hmac.compare_digest(query.get("token", "").encode(), token.encode()):
                    return self._send(HTTPStatus.FORBIDDEN, b"Open the dashboard from the URL printed in the terminal (it contains the access token).",
                                      "text/plain; charset=utf-8")
                html = (STATIC_DIR / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", token)
                return self._send(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": CSP})

            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if not self._host_ok() or name not in STATIC_FILES:
                    return self._error(HTTPStatus.NOT_FOUND, "not found")
                return self._send(HTTPStatus.OK, (STATIC_DIR / name).read_bytes(), STATIC_FILES[name])

            if not path.startswith("/api/"):
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            if not self._api_ok():
                return
            try:
                if path in ("/api/report.md", "/api/report.json"):
                    body, content_type, filename = api.report_download(ctx, path.rsplit(".", 1)[1])
                    return self._send(HTTPStatus.OK, body, content_type, {"Content-Disposition": f'attachment; filename="{filename}"'})
                self._json(HTTPStatus.OK, self._route_get(path, query))
            except ApiError as exc:
                self._error(exc.status, exc.message)
            except Exception as exc:  # never leak internals to the browser
                sys.stderr.write(f"[ui] internal error on {path}: {type(exc).__name__}: {exc}\n")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error; see the terminal")

        def _route_get(self, path: str, query: dict[str, str]) -> Any:
            if path == "/api/status":
                return api.status(ctx)
            if path == "/api/feedback":
                return api.feedback_overview(ctx)
            if path == "/api/overview":
                return api.overview(ctx)
            if path == "/api/cases":
                return api.cases(ctx, query)
            if path == "/api/indicators":
                return api.indicators(ctx, query)
            if path == "/api/graph":
                return api.graph(ctx, query)
            if path == "/api/sources":
                return api.sources(ctx)
            if path == "/api/report":
                return api.report(ctx)
            if path == "/api/advisories":
                return api.advisories(ctx)
            if path == "/api/jobs":
                return api.jobs_status(ctx)
            m = _ID.match(path)
            if m:
                kind, ident = m.groups()
                if kind == "case":
                    return api.case_detail(ctx, ident)
                if not ident.isdigit():
                    raise ApiError(404, "not found")
                return api.indicator_detail(ctx, int(ident)) if kind == "indicator" else api.advisory_detail(ctx, int(ident))
            raise ApiError(404, "not found")

        # -- POST --------------------------------------------------------
        def do_POST(self) -> None:
            try:
                self._unread = max(0, int(self.headers.get("Content-Length", "0")))
            except ValueError:
                self._unread = 0
            path = urlsplit(self.path).path
            if not path.startswith("/api/"):
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            if not self._api_ok():
                return
            if path == "/api/upload":
                return self._upload(urlsplit(self.path))
            if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON only")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "bad length")
            if length < 0 or length > api.MAX_PASTE_BYTES + JSON_BODY_SLACK:
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request too large")
            try:
                raw = self.rfile.read(length)
                self._unread = 0
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "invalid JSON")
            try:
                m = _ADV_ACTION.match(path)
                if m:
                    result = ADV_ACTIONS[m.group(2)](ctx, int(m.group(1)), body)
                elif path in POST_ROUTES:
                    result = POST_ROUTES[path](ctx, body)
                else:
                    raise ApiError(404, "not found")
                self._json(HTTPStatus.OK, result)
            except ApiError as exc:
                self._error(exc.status, exc.message)
            except Exception as exc:
                sys.stderr.write(f"[ui] internal error on {path}: {type(exc).__name__}: {exc}\n")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error; see the terminal")

        def _upload(self, parts: Any) -> None:
            """Stream the request body to a temporary file, then hand it to the background worker."""
            if not self.headers.get("Content-Type", "").lower().startswith("application/octet-stream"):
                return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send the file as application/octet-stream")
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                return self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
            try:
                length = int(raw_length)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "bad length")
            name = api.clean_name(parse_qs(parts.query).get("name", [""])[0])
            if not name:
                return self._error(HTTPStatus.BAD_REQUEST, "a file name is required")
            if length <= 0:
                return self._error(HTTPStatus.BAD_REQUEST, "the file is empty")
            if length > api.MAX_UPLOAD_BYTES:
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                   f"file is larger than {api.MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
            jobs = ctx.jobs()
            if not jobs.has_room():
                return self._error(HTTPStatus.TOO_MANY_REQUESTS, "too many files are waiting; try again shortly")
            # Ingest needs the temporary copy plus roughly 2x the size again for the database.
            need = length * 3 + 100 * 1024 * 1024
            free = shutil.disk_usage(jobs.work_dir).free
            if free < need:
                return self._error(HTTPStatus.INSUFFICIENT_STORAGE,
                                   f"not enough free disk space: about {need // 2 ** 20} MB needed, {free // 2 ** 20} MB free")
            tmp = jobs.new_upload_path()
            received = 0
            try:
                with open(tmp, "wb") as out:
                    while received < length:
                        block = self.rfile.read(min(CHUNK, length - received))
                        if not block:
                            raise ConnectionError("the upload was cut short")
                        out.write(block)
                        received += len(block)
                        self._unread = length - received
            except (OSError, ConnectionError, TimeoutError) as exc:
                tmp.unlink(missing_ok=True)
                sys.stderr.write(f"[ui] upload of {name!r} failed after {received} bytes: {type(exc).__name__}\n")
                try:
                    self._error(HTTPStatus.BAD_REQUEST, "the upload did not complete")
                except OSError:
                    pass  # the browser is already gone
                return
            try:
                self._json(HTTPStatus.ACCEPTED, api.start_upload(ctx, name, tmp, length))
            except Exception:
                tmp.unlink(missing_ok=True)
                raise

        def do_PUT(self) -> None:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

        do_DELETE = do_PATCH = do_PUT

    return Handler


def create_server(ctx: Context, host: str = "127.0.0.1", port: int = 8765, token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    if host not in LOOPBACK:
        raise ValueError("the dashboard only listens on loopback (127.0.0.1); it will not expose your data to the network")
    # 96 bits is ample for a per-run, loopback-only secret, and keeps the whole link under 50 characters so it
    # does not wrap in a narrow terminal (a wrapped link breaks when copied).
    token = token or secrets.token_urlsafe(TOKEN_BYTES)
    server = None
    for candidate in ([port] if port == 0 else range(port, port + 20)):  # first free port from the one requested
        try:
            server = DashboardServer((host, candidate), lambda *a, **k: None)  # real handler is set below
            break
        except OSError:
            continue
    if server is None:
        raise OSError(f"no free port in {port}-{port + 19}; pass --port")
    server.RequestHandlerClass = make_handler(ctx, token, server.server_address[1])
    server.daemon_threads = True
    return server, token


def serve(ctx: Context, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    server, token = create_server(ctx, host, port)
    chosen = server.server_address[1]
    url = f"http://127.0.0.1:{chosen}/?token={token}"
    if port and chosen != port:
        print(f"Port {port} is already in use (is another dashboard still running?), so this one uses port {chosen}.")
    print(f"ThreatWeaver dashboard for {ctx.db_path}")
    print("Your browser should open by itself. If not, copy this whole link (it holds the access token):")
    print(url)
    print("Listening on loopback only. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
        ctx.close()
