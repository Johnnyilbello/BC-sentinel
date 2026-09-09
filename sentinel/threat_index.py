from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import APP_VERSION
from .path_security import has_reparse_component, is_reparse_point, secure_write_parent
from .service_hardening import ensure_integrity_key
from .service_update import version_key
from .threat_retrieval import MAX_RETRIEVAL_BYTES
from .threat_trust import ThreatTrustStore

THREAT_INDEX_SCHEMA = "bcsentinel.threat-index.v1"
PINNED_THREAT_INDEX_ED25519_PUBLIC_KEY_B64 = "zz6lTDx/0DINkQOs2z1U06NHq6ijVJ2mBdJBmCSIRKI="
INDEX_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_INDEX_PACKAGES = 128
MAX_INDEX_BYTES = 128 * 1024
INDEX_STATE_SCHEMA = 1
MAX_CACHE_ENTRIES = 32
MAX_CACHE_BYTES = 4 * 1024 * 1024


class ThreatIndexError(ValueError):
    pass


def canonical_index_bytes(index: dict[str, Any]) -> bytes:
    try:
        return json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ThreatIndexError(f"threat index is not canonical JSON: {exc}") from exc


def _parse_time(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise ThreatIndexError(f"{field} is invalid")
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
            raise ThreatIndexError(f"{field} must be ISO-8601 or epoch seconds") from exc
    else:
        raise ThreatIndexError(f"{field} is invalid")
    if ts <= 0:
        raise ThreatIndexError(f"{field} must be positive")
    return ts


def _validate_https_url(value: object) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        raise ThreatIndexError(f"package URL is invalid: {exc}") from exc
    if parsed.scheme.casefold() != "https":
        raise ThreatIndexError("package URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ThreatIndexError("package URL cannot contain credentials")
    if not parsed.hostname or parsed.fragment:
        raise ThreatIndexError("package URL host/fragment is invalid")
    if int(parsed.port or 443) != 443:
        raise ThreatIndexError("package URL only permits TCP/443")
    return raw


@dataclass(slots=True, frozen=True)
class VerifiedThreatIndex:
    index_id: str
    sequence: int
    generated_at: float
    expires_at: float
    payload_sha256: str
    key_fingerprint: str
    packages: tuple[dict[str, Any], ...]
    raw_index: dict[str, Any]
    signature_b64: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_id": self.index_id,
            "sequence": self.sequence,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "payload_sha256": self.payload_sha256,
            "key_fingerprint": self.key_fingerprint,
            "package_count": len(self.packages),
            "packages": [dict(item) for item in self.packages],
        }


class SignedThreatIndexVerifier:
    def __init__(
        self,
        public_key_b64: str = PINNED_THREAT_INDEX_ED25519_PUBLIC_KEY_B64,
        *,
        product_version: str = APP_VERSION,
    ):
        try:
            raw = base64.b64decode(str(public_key_b64), validate=True)
            if len(raw) != 32:
                raise ValueError("wrong key size")
            self.public_key_bytes = raw
            self.public_key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise ThreatIndexError(f"invalid Ed25519 threat-index public key: {exc}") from exc
        self.key_fingerprint = hashlib.sha256(self.public_key_bytes).hexdigest()[:24]
        self.product_version = str(product_version)

    def verify(self, index: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedThreatIndex:
        if not isinstance(index, dict):
            raise ThreatIndexError("threat index must be an object")
        allowed = {"schema", "index_id", "sequence", "generated_at", "expires_at", "packages"}
        unknown = set(index) - allowed
        if unknown:
            raise ThreatIndexError(f"unsupported threat index field(s): {', '.join(sorted(unknown))}")
        if str(index.get("schema") or "") != THREAT_INDEX_SCHEMA:
            raise ThreatIndexError(f"unsupported threat index schema; expected {THREAT_INDEX_SCHEMA}")
        index_id = str(index.get("index_id") or "").strip()
        if not INDEX_ID_RE.fullmatch(index_id):
            raise ThreatIndexError("index_id is invalid")
        sequence = index.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ThreatIndexError("threat index sequence must be a positive integer")
        generated_at = _parse_time(index.get("generated_at"), field="generated_at")
        expires_at = _parse_time(index.get("expires_at"), field="expires_at")
        if expires_at <= generated_at:
            raise ThreatIndexError("threat index expires_at must be after generated_at")
        current = time.time() if now is None else float(now)
        if generated_at > current + 300:
            raise ThreatIndexError("threat index generated_at is too far in the future")
        if expires_at <= current:
            raise ThreatIndexError("threat index is expired")

        packages = index.get("packages")
        if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_INDEX_PACKAGES:
            raise ThreatIndexError(f"packages must contain 1..{MAX_INDEX_PACKAGES} entries")
        normalized: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_sequences: set[int] = set()
        allowed_components = {"ioc", "yara", "behavior", "reputation"}
        for item in packages:
            if not isinstance(item, dict):
                raise ThreatIndexError("package index entries must be objects")
            item_allowed = {
                "package_id", "sequence", "version", "sha256", "size", "url",
                "signing_key_id", "components", "min_product_version",
            }
            extra = set(item) - item_allowed
            if extra:
                raise ThreatIndexError(f"unsupported package metadata field(s): {', '.join(sorted(extra))}")
            package_id = str(item.get("package_id") or "").strip()
            if not PACKAGE_ID_RE.fullmatch(package_id) or package_id.casefold() in seen_ids:
                raise ThreatIndexError("package_id is invalid or duplicated")
            seen_ids.add(package_id.casefold())
            pkg_sequence = item.get("sequence")
            if isinstance(pkg_sequence, bool) or not isinstance(pkg_sequence, int) or pkg_sequence <= 0:
                raise ThreatIndexError("package sequence must be a positive integer")
            if pkg_sequence in seen_sequences:
                raise ThreatIndexError("package sequence is duplicated in threat index")
            seen_sequences.add(pkg_sequence)
            version = str(item.get("version") or "").strip()
            if not version or len(version) > 64:
                raise ThreatIndexError("package version metadata is invalid")
            digest = str(item.get("sha256") or "").strip().casefold()
            if not HEX64_RE.fullmatch(digest):
                raise ThreatIndexError("package sha256 metadata is invalid")
            size = item.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_RETRIEVAL_BYTES:
                raise ThreatIndexError(f"package size must be between 1 and {MAX_RETRIEVAL_BYTES} bytes")
            url = _validate_https_url(item.get("url"))
            signing_key_id = str(item.get("signing_key_id") or "").strip()
            if not KEY_ID_RE.fullmatch(signing_key_id):
                raise ThreatIndexError("package signing_key_id is invalid")
            components = item.get("components")
            if not isinstance(components, list) or not components:
                raise ThreatIndexError("package components metadata must be a non-empty list")
            component_set = {str(value).strip().casefold() for value in components}
            if not component_set or component_set - allowed_components:
                raise ThreatIndexError("package components metadata contains unsupported values")
            min_product = str(item.get("min_product_version") or "").strip()
            try:
                version_key(min_product)
            except Exception as exc:
                raise ThreatIndexError(f"package min_product_version is invalid: {exc}") from exc
            normalized.append({
                "package_id": package_id,
                "sequence": int(pkg_sequence),
                "version": version,
                "sha256": digest,
                "size": int(size),
                "url": url,
                "signing_key_id": signing_key_id,
                "components": sorted(component_set),
                "min_product_version": min_product,
            })

        canonical = canonical_index_bytes(index)
        if len(canonical) > MAX_INDEX_BYTES:
            raise ThreatIndexError(f"threat index exceeds {MAX_INDEX_BYTES} bytes")
        try:
            signature = base64.b64decode(str(signature_b64 or ""), validate=True)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
            self.public_key.verify(signature, canonical)
        except (InvalidSignature, ValueError) as exc:
            raise ThreatIndexError("threat index signature verification failed") from exc
        except Exception as exc:
            raise ThreatIndexError(f"threat index signature verification failed: {exc}") from exc

        return VerifiedThreatIndex(
            index_id=index_id,
            sequence=int(sequence),
            generated_at=generated_at,
            expires_at=expires_at,
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            key_fingerprint=self.key_fingerprint,
            packages=tuple(normalized),
            raw_index=dict(index),
            signature_b64=str(signature_b64),
        )


class ThreatIndexStore:
    """HMAC-authenticated accepted-index state with sequence high-water anti-rollback."""

    def __init__(
        self,
        base_dir: str | Path,
        *,
        verifier: SignedThreatIndexVerifier | None = None,
        integrity_key: bytes | None = None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.verifier = verifier or SignedThreatIndexVerifier()
        self.integrity_key = bytes(integrity_key) if integrity_key is not None else ensure_integrity_key()
        self.index_path = self.base_dir / "current-index.json"
        self.signature_path = self.base_dir / "current-index.sig"
        self.state_path = self.base_dir / "state.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if has_reparse_component(self.base_dir, include_leaf=False) or is_reparse_point(self.base_dir):
            raise ThreatIndexError("remote threat index path cannot traverse a reparse point")

    @staticmethod
    def _canonical_state(body: dict[str, Any]) -> bytes:
        return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _write_state(self, body: dict[str, Any]) -> None:
        payload = dict(body)
        payload.pop("hmac", None)
        payload["hmac"] = hmac.new(self.integrity_key, self._canonical_state(payload), hashlib.sha256).hexdigest()
        secure_write_parent(self.state_path)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema": INDEX_STATE_SCHEMA,
                "high_water_sequence": 0,
                "high_water_payload_sha256": "",
                "accepted": None,
                "updated_at": 0.0,
            }
        try:
            obj = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ThreatIndexError(f"cannot read threat-index state: {exc}") from exc
        supplied = str(obj.pop("hmac", ""))
        expected = hmac.new(self.integrity_key, self._canonical_state(obj), hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ThreatIndexError("threat-index state HMAC verification failed")
        if int(obj.get("schema") or 0) != INDEX_STATE_SCHEMA:
            raise ThreatIndexError("threat-index state schema is invalid")
        return obj

    def accept(self, index: dict[str, Any], signature_b64: str, *, now: float | None = None) -> dict[str, Any]:
        verified = self.verifier.verify(index, signature_b64, now=now)
        state = self._read_state()
        high = int(state.get("high_water_sequence") or 0)
        high_digest = str(state.get("high_water_payload_sha256") or "")
        if verified.sequence < high:
            raise ThreatIndexError("threat index anti-rollback: sequence is below accepted high-water mark")
        if verified.sequence == high and high and high_digest and verified.payload_sha256 != high_digest:
            raise ThreatIndexError("threat index anti-rollback: sequence reuse with a different payload is forbidden")
        idempotent = bool(
            verified.sequence == high and high and high_digest == verified.payload_sha256
            and self.index_path.exists() and self.signature_path.exists()
        )
        if not idempotent:
            secure_write_parent(self.index_path)
            index_tmp = self.index_path.with_suffix(".json.tmp")
            sig_tmp = self.signature_path.with_suffix(".sig.tmp")
            index_tmp.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
            sig_tmp.write_text(str(signature_b64).strip() + "\n", encoding="ascii")
            os.replace(index_tmp, self.index_path)
            os.replace(sig_tmp, self.signature_path)
        state["accepted"] = {
            "index_id": verified.index_id,
            "sequence": verified.sequence,
            "payload_sha256": verified.payload_sha256,
            "expires_at": verified.expires_at,
            "key_fingerprint": verified.key_fingerprint,
            "package_count": len(verified.packages),
        }
        if verified.sequence > high:
            state["high_water_sequence"] = verified.sequence
            state["high_water_payload_sha256"] = verified.payload_sha256
        state["updated_at"] = time.time()
        self._write_state(state)
        return {"accepted": not idempotent, "idempotent": idempotent, "index": verified.to_dict()}

    def current(self, *, now: float | None = None) -> VerifiedThreatIndex | None:
        if not self.index_path.exists() or not self.signature_path.exists():
            return None
        try:
            index = json.loads(self.index_path.read_text(encoding="utf-8"))
            signature = self.signature_path.read_text(encoding="ascii").strip()
        except Exception as exc:
            raise ThreatIndexError(f"cannot read accepted threat index: {exc}") from exc
        return self.verifier.verify(index, signature, now=now)

    def select_candidate(
        self,
        *,
        active_sequence: int = 0,
        product_version: str = APP_VERSION,
        trust_store: ThreatTrustStore | None = None,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        current = self.current(now=now)
        if current is None:
            return None
        active_sequence = max(0, int(active_sequence))
        candidates = sorted(current.packages, key=lambda item: int(item["sequence"]), reverse=True)
        for item in candidates:
            if int(item["sequence"]) <= active_sequence:
                continue
            try:
                if version_key(product_version) < version_key(str(item["min_product_version"])):
                    continue
            except Exception:
                continue
            if trust_store is not None:
                try:
                    if trust_store.is_revoked(str(item["signing_key_id"])):
                        continue
                    trust_store.resolve_key(str(item["signing_key_id"]), now=now)
                except Exception:
                    continue
            return dict(item)
        return None

    def status(self, *, now: float | None = None) -> dict[str, Any]:
        state = self._read_state()
        valid = True
        error = ""
        current = None
        try:
            verified = self.current(now=now)
            if verified is not None:
                current = verified.to_dict()
        except Exception as exc:
            valid = False
            error = str(exc)
        return {
            "schema": INDEX_STATE_SCHEMA,
            "signature": "Ed25519",
            "key_fingerprint": self.verifier.key_fingerprint,
            "installed": current is not None or self.index_path.exists(),
            "valid": valid,
            "error": error,
            "current": current,
            "high_water_sequence": int(state.get("high_water_sequence") or 0),
            "anti_rollback": True,
            "auto_stage": False,
            "auto_activate": False,
        }


class ThreatContentCache:
    """Content-addressed bounded cache. Cache content is data only and never executed."""

    def __init__(
        self,
        base_dir: str | Path,
        *,
        max_entries: int = MAX_CACHE_ENTRIES,
        max_bytes: int = MAX_CACHE_BYTES,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.max_entries = max(1, min(int(max_entries), MAX_CACHE_ENTRIES))
        self.max_bytes = max(MAX_RETRIEVAL_BYTES, min(int(max_bytes), MAX_CACHE_BYTES))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if has_reparse_component(self.base_dir, include_leaf=False) or is_reparse_point(self.base_dir):
            raise ThreatIndexError("threat cache path cannot traverse a reparse point")

    def _path(self, digest: str) -> Path:
        normalized = str(digest or "").strip().casefold()
        if not HEX64_RE.fullmatch(normalized):
            raise ThreatIndexError("cache digest is invalid")
        path = self.base_dir / f"{normalized}.json"
        if has_reparse_component(path, include_leaf=path.exists()) or (path.exists() and is_reparse_point(path)):
            raise ThreatIndexError("threat cache entry is unsafe")
        return path

    def store(self, body: bytes, *, expected_sha256: str) -> dict[str, Any]:
        payload = bytes(body)
        if not payload or len(payload) > MAX_RETRIEVAL_BYTES:
            raise ThreatIndexError("cached threat content size is invalid")
        digest = hashlib.sha256(payload).hexdigest()
        expected = str(expected_sha256 or "").strip().casefold()
        if digest != expected:
            raise ThreatIndexError("cached threat content hash mismatch")
        path = self._path(digest)
        if path.exists():
            existing = path.read_bytes()
            if hashlib.sha256(existing).hexdigest() != digest:
                raise ThreatIndexError("existing threat cache entry failed content-address verification")
            os.utime(path, None)
        else:
            secure_write_parent(path)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_bytes(payload)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, path)
        self.prune()
        return {"sha256": digest, "size": len(payload), "cache_name": path.name}

    def read(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.is_file():
            raise ThreatIndexError("threat cache entry is missing")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != str(digest).casefold():
            raise ThreatIndexError("threat cache entry hash verification failed")
        return payload

    def prune(self) -> dict[str, int]:
        entries: list[tuple[Path, int, float]] = []
        for path in self.base_dir.glob("*.json"):
            if not path.is_file() or is_reparse_point(path):
                continue
            try:
                stat = path.stat()
                entries.append((path, int(stat.st_size), float(stat.st_mtime)))
            except OSError:
                continue
        entries.sort(key=lambda item: item[2], reverse=True)
        total = sum(size for _, size, _ in entries)
        kept = 0
        removed = 0
        kept_bytes = 0
        for path, size, _ in entries:
            if kept < self.max_entries and kept_bytes + size <= self.max_bytes:
                kept += 1
                kept_bytes += size
                continue
            try:
                path.unlink()
                removed += 1
                total -= size
            except OSError:
                pass
        return {"entries": kept, "bytes": kept_bytes, "removed": removed}

    def status(self) -> dict[str, Any]:
        entries = []
        for path in self.base_dir.glob("*.json"):
            try:
                if path.is_file() and not is_reparse_point(path):
                    entries.append(path.stat().st_size)
            except OSError:
                pass
        return {
            "content_addressed": True,
            "hash": "SHA-256",
            "entries": len(entries),
            "bytes": int(sum(entries)),
            "max_entries": self.max_entries,
            "max_bytes": self.max_bytes,
            "executable_content": False,
        }
