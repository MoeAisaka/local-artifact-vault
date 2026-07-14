from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .vault import Vault, VaultError


def handler_for(vault: Vault):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LocalArtifactVault/0.1"

        def do_GET(self):  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path == "/healthz":
                return self._text(HTTPStatus.OK, "ok")
            prefix = "/download/"
            if not parsed.path.startswith(prefix):
                return self._text(HTTPStatus.NOT_FOUND, "not found")
            artifact_id = unquote(parsed.path[len(prefix):])
            query = parse_qs(parsed.query)
            try:
                expires = int(query.get("e", [""])[0])
                signature = query.get("s", [""])[0]
                path, record = vault.resolve(artifact_id, expires, signature)
            except (ValueError, VaultError):
                return self._text(HTTPStatus.FORBIDDEN, "invalid or expired link")
            data = path.read_bytes()
            encoded_name = quote(str(record["name"]), safe="")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename=artifact; filename*=UTF-8''{encoded_name}")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format, *_args):
            return

        def _text(self, status: HTTPStatus, value: str):
            data = value.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(root: Path, host: str, port: int, *, allow_remote: bool = False) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"} and not allow_remote:
        raise VaultError("remote binding requires --allow-remote and an authenticated TLS reverse proxy")
    vault = Vault(root)
    vault.initialize()
    ThreadingHTTPServer((host, port), handler_for(vault)).serve_forever()
