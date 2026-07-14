from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlencode


class VaultError(RuntimeError):
    pass


ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
FORBIDDEN_SUFFIXES = {".env", ".key", ".pem", ".p12", ".pfx", ".sqlite", ".db", ".log"}
FORBIDDEN_NAME_PARTS = {"credential", "secret", "token", "openclaw.json", "sessions.json"}
CONTENT_PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "openai-style-key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "github-token": re.compile(rb"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Vault:
    def __init__(self, root: Path | str, *, max_bytes: int = 100 * 1024 * 1024, scan_bytes: int = 2 * 1024 * 1024):
        self.root = Path(root).expanduser().resolve()
        self.objects = self.root / "objects"
        self.records = self.root / "records"
        self.secret_file = self.root / "signing-secret"
        self.max_bytes = max_bytes
        self.scan_bytes = scan_bytes

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.objects.mkdir(exist_ok=True, mode=0o700)
        self.records.mkdir(exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        if not self.secret_file.exists():
            fd = os.open(self.secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(secrets.token_urlsafe(48) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        if stat.S_IMODE(self.secret_file.stat().st_mode) != 0o600:
            os.chmod(self.secret_file, 0o600)

    def _secret(self) -> bytes:
        self.initialize()
        return self.secret_file.read_text(encoding="ascii").strip().encode("ascii")

    def _record_path(self, artifact_id: str) -> Path:
        if not ID_RE.fullmatch(artifact_id):
            raise VaultError("invalid artifact id")
        return self.records / f"{artifact_id}.json"

    def _scan(self, source: Path) -> None:
        if source.is_symlink() or not source.is_file():
            raise VaultError("source must be a regular, non-symlink file")
        size = source.stat().st_size
        if size <= 0 or size > self.max_bytes:
            raise VaultError("file size is outside the configured limit")
        lowered = source.name.lower()
        if source.suffix.lower() in FORBIDDEN_SUFFIXES or any(value in lowered for value in FORBIDDEN_NAME_PARTS):
            raise VaultError("filename or extension is blocked")
        with source.open("rb") as handle:
            sample = handle.read(self.scan_bytes)
        for label, pattern in CONTENT_PATTERNS.items():
            if pattern.search(sample):
                raise VaultError(f"content scan rejected the file ({label})")

    def signature(self, artifact_id: str, file_hash: str, expires: int) -> str:
        message = f"{artifact_id}|{file_hash}|{expires}".encode("utf-8")
        return hmac.new(self._secret(), message, hashlib.sha256).hexdigest()

    def publish(self, source: Path | str, *, ttl_seconds: int = 86400, base_url: str | None = None) -> dict:
        if not 60 <= ttl_seconds <= 30 * 24 * 60 * 60:
            raise VaultError("ttl_seconds must be between 60 seconds and 30 days")
        unresolved = Path(source).expanduser()
        if unresolved.is_symlink():
            raise VaultError("source must be a regular, non-symlink file")
        source_path = unresolved.resolve(strict=True)
        self._scan(source_path)
        self.initialize()
        artifact_id = secrets.token_urlsafe(18).replace("-", "_")
        file_hash = _sha256(source_path)
        destination = self.objects / artifact_id
        shutil.copyfile(source_path, destination, follow_symlinks=False)
        os.chmod(destination, 0o600)
        expires = int(time.time()) + ttl_seconds
        record = {
            "schemaVersion": 1,
            "artifactId": artifact_id,
            "name": source_path.name,
            "sha256": file_hash,
            "size": destination.stat().st_size,
            "createdAt": int(time.time()),
            "expiresAt": expires,
            "object": artifact_id,
        }
        _atomic_json(self._record_path(artifact_id), record)
        signature = self.signature(artifact_id, file_hash, expires)
        url = None
        if base_url:
            url = f"{base_url.rstrip('/')}/download/{quote(artifact_id, safe='')}?{urlencode({'e': expires, 's': signature})}"
        return {**record, "signature": signature, "url": url}

    def resolve(self, artifact_id: str, expires: int, signature: str, *, now: int | None = None) -> tuple[Path, dict]:
        current = int(time.time()) if now is None else now
        record_path = self._record_path(artifact_id)
        if not record_path.is_file():
            raise VaultError("artifact not found")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if expires != int(record["expiresAt"]) or current > expires:
            raise VaultError("link expired")
        expected = self.signature(artifact_id, str(record["sha256"]), expires)
        if not hmac.compare_digest(expected, signature):
            raise VaultError("invalid signature")
        object_path = (self.objects / str(record["object"])).resolve()
        if object_path.parent != self.objects.resolve() or not object_path.is_file() or object_path.is_symlink():
            raise VaultError("invalid object path")
        if _sha256(object_path) != record["sha256"]:
            raise VaultError("artifact integrity check failed")
        return object_path, record

    def cleanup(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else now
        removed = 0
        self.initialize()
        for record_path in self.records.glob("*.json"):
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
                if int(record["expiresAt"]) >= current:
                    continue
                object_path = self.objects / str(record["object"])
                if object_path.is_file() and not object_path.is_symlink():
                    object_path.unlink()
                record_path.unlink()
                removed += 1
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return removed
