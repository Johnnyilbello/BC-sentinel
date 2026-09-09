from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .service_update import version_key
from .path_security import has_reparse_component, is_reparse_point

RELEASE_ENVELOPE_SCHEMA = "bcsentinel.release-envelope.v1"
PINNED_RELEASE_ED25519_PUBLIC_KEY_B64 = "v1jDXpvPXQ9+4/b8FqTF6WbuGfA8YB4KXLR/JQlzaFs="
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_RELEASE_FILES = 5000


class ReleaseEnvelopeError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class VerifiedReleaseEnvelope:
    product: str
    version: str
    sequence: int
    issued_at: float
    expires_at: float
    payload_sha256: str
    key_fingerprint: str
    files: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "payload_sha256": self.payload_sha256,
            "key_fingerprint": self.key_fingerprint,
            "files": {k: dict(v) for k, v in self.files.items()},
        }


def canonical_release_bytes(envelope: dict[str, Any]) -> bytes:
    try:
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ReleaseEnvelopeError(f"release envelope is not canonical JSON: {exc}") from exc


def _parse_time(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise ReleaseEnvelopeError(f"{field} is invalid")
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str):
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
        except ValueError as exc:
            raise ReleaseEnvelopeError(f"{field} is invalid") from exc
    else:
        raise ReleaseEnvelopeError(f"{field} is invalid")
    if ts <= 0:
        raise ReleaseEnvelopeError(f"{field} must be positive")
    return ts


def _validate_relative_path(raw: str) -> str:
    value = str(raw or "").replace("\\", "/").strip()
    if not value or value.startswith("/") or "\x00" in value:
        raise ReleaseEnvelopeError("release file path is invalid")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseEnvelopeError("release file path cannot traverse directories")
    if ":" in path.parts[0]:
        raise ReleaseEnvelopeError("release file path cannot contain a drive prefix")
    return path.as_posix()


class SignedReleaseEnvelopeVerifier:
    def __init__(self, public_key_b64: str = PINNED_RELEASE_ED25519_PUBLIC_KEY_B64):
        try:
            raw = base64.b64decode(str(public_key_b64), validate=True)
            if len(raw) != 32:
                raise ValueError("wrong key size")
            self.public_key_bytes = raw
            self.public_key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise ReleaseEnvelopeError(f"invalid release public key: {exc}") from exc
        self.key_fingerprint = hashlib.sha256(self.public_key_bytes).hexdigest()[:24]

    def verify(self, envelope: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedReleaseEnvelope:
        if not isinstance(envelope, dict):
            raise ReleaseEnvelopeError("release envelope must be an object")
        allowed = {"schema", "product", "version", "sequence", "issued_at", "expires_at", "files"}
        unknown = set(envelope) - allowed
        if unknown:
            raise ReleaseEnvelopeError(f"unsupported release field(s): {', '.join(sorted(unknown))}")
        if str(envelope.get("schema") or "") != RELEASE_ENVELOPE_SCHEMA:
            raise ReleaseEnvelopeError(f"unsupported release schema; expected {RELEASE_ENVELOPE_SCHEMA}")
        product = str(envelope.get("product") or "").strip()
        if product != "BC Sentinel":
            raise ReleaseEnvelopeError("release product identity mismatch")
        version = str(envelope.get("version") or "").strip()
        try:
            version_key(version)
        except Exception as exc:
            raise ReleaseEnvelopeError(f"release version is invalid: {exc}") from exc
        sequence = envelope.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ReleaseEnvelopeError("release sequence must be a positive integer")
        issued = _parse_time(envelope.get("issued_at"), "issued_at")
        expires = _parse_time(envelope.get("expires_at"), "expires_at")
        current = time.time() if now is None else float(now)
        if expires <= issued or expires <= current:
            raise ReleaseEnvelopeError("release envelope is expired or has an invalid validity window")
        if issued > current + 300:
            raise ReleaseEnvelopeError("release envelope issued_at is too far in the future")
        files = envelope.get("files")
        if not isinstance(files, dict) or not files or len(files) > MAX_RELEASE_FILES:
            raise ReleaseEnvelopeError(f"release files must contain 1..{MAX_RELEASE_FILES} entries")
        normalized: dict[str, dict[str, Any]] = {}
        for raw_path, meta in files.items():
            rel = _validate_relative_path(str(raw_path))
            if rel in normalized:
                raise ReleaseEnvelopeError("duplicate release file path")
            if not isinstance(meta, dict) or set(meta) - {"sha256", "size"}:
                raise ReleaseEnvelopeError("release file metadata accepts only sha256/size")
            digest = str(meta.get("sha256") or "").strip().casefold()
            size = meta.get("size")
            if not SHA256_RE.fullmatch(digest):
                raise ReleaseEnvelopeError("release file sha256 is invalid")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ReleaseEnvelopeError("release file size is invalid")
            normalized[rel] = {"sha256": digest, "size": int(size)}
        canonical = canonical_release_bytes(envelope)
        try:
            sig = base64.b64decode(str(signature_b64 or ""), validate=True)
            if len(sig) != 64:
                raise ValueError("wrong signature size")
        except Exception as exc:
            raise ReleaseEnvelopeError(f"release signature encoding is invalid: {exc}") from exc
        try:
            self.public_key.verify(sig, canonical)
        except InvalidSignature as exc:
            raise ReleaseEnvelopeError("release envelope signature verification failed") from exc
        return VerifiedReleaseEnvelope(
            product=product, version=version, sequence=int(sequence), issued_at=issued, expires_at=expires,
            payload_sha256=hashlib.sha256(canonical).hexdigest(), key_fingerprint=self.key_fingerprint,
            files=normalized,
        )

    def verify_tree(
        self,
        root: str | Path,
        envelope: dict[str, Any],
        signature_b64: str,
        *,
        now: float | None = None,
        require_exact_file_set: bool = True,
    ) -> dict[str, Any]:
        verified = self.verify(envelope, signature_b64, now=now)
        root = Path(root).resolve()
        if not root.is_dir() or has_reparse_component(root, include_leaf=True) or is_reparse_point(root):
            raise ReleaseEnvelopeError("release root is missing or unsafe")
        checked = 0
        expected = set(verified.files)
        observed: set[str] = set()
        for rel, meta in verified.files.items():
            path = root / Path(rel)
            if has_reparse_component(path, include_leaf=True) or is_reparse_point(path):
                raise ReleaseEnvelopeError(f"release file path uses reparse/symlink: {rel}")
            if not path.is_file():
                raise ReleaseEnvelopeError(f"release file is missing: {rel}")
            st = path.stat()
            if int(st.st_size) != int(meta["size"]):
                raise ReleaseEnvelopeError(f"release file size mismatch: {rel}")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != str(meta["sha256"]):
                raise ReleaseEnvelopeError(f"release file hash mismatch: {rel}")
            checked += 1
            observed.add(rel)
        if require_exact_file_set:
            actual = {
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            if actual != expected:
                extra = sorted(actual - expected)[:8]
                missing = sorted(expected - actual)[:8]
                raise ReleaseEnvelopeError(f"release file set mismatch; extra={extra} missing={missing}")
        return {
            "verified": True,
            "version": verified.version,
            "sequence": verified.sequence,
            "payload_sha256": verified.payload_sha256,
            "key_fingerprint": verified.key_fingerprint,
            "files_checked": checked,
            "exact_file_set": bool(require_exact_file_set),
        }
