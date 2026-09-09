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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_security import has_reparse_component, is_reparse_point, secure_write_parent
from .service_hardening import ensure_integrity_key

THREAT_KEYSET_SCHEMA = "bcsentinel.threat-keyset.v1"
PINNED_THREAT_ROOT_ED25519_PUBLIC_KEY_B64 = "JlLUG6t44kj1Z0cOEoRLw33z00lPCEnE5YLBJibb2HY="
LEGACY_THREAT_KEY_ID = "legacy-beta1"
LEGACY_THREAT_ED25519_PUBLIC_KEY_B64 = "dbficwacIUN7Hs43olocLDvr1WisoXRpBaCOX0/Ch88="
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
KEYSET_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_CONTENT_KEYS = 16
MAX_REVOKED_KEYS = 64
TRUST_STATE_SCHEMA = 1


class ThreatTrustError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class ContentKey:
    key_id: str
    public_key_b64: str
    public_key_bytes: bytes
    not_before: float
    not_after: float

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key_b64": self.public_key_b64,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "fingerprint": self.fingerprint,
        }


@dataclass(slots=True, frozen=True)
class VerifiedThreatKeyset:
    keyset_id: str
    sequence: int
    issued_at: float
    expires_at: float
    payload_sha256: str
    root_key_fingerprint: str
    keys: tuple[ContentKey, ...]
    revoked_key_ids: tuple[str, ...]
    raw_keyset: dict[str, Any]
    signature_b64: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "keyset_id": self.keyset_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "payload_sha256": self.payload_sha256,
            "root_key_fingerprint": self.root_key_fingerprint,
            "keys": [key.to_dict() for key in self.keys],
            "revoked_key_ids": list(self.revoked_key_ids),
        }


def canonical_keyset_bytes(keyset: dict[str, Any]) -> bytes:
    try:
        return json.dumps(keyset, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ThreatTrustError(f"threat keyset is not canonical JSON: {exc}") from exc


def _parse_time(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise ThreatTrustError(f"{field} is invalid")
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
            raise ThreatTrustError(f"{field} must be ISO-8601 or epoch seconds") from exc
    else:
        raise ThreatTrustError(f"{field} is invalid")
    if ts <= 0:
        raise ThreatTrustError(f"{field} must be positive")
    return ts


class ThreatKeysetVerifier:
    def __init__(self, root_public_key_b64: str = PINNED_THREAT_ROOT_ED25519_PUBLIC_KEY_B64):
        try:
            raw = base64.b64decode(str(root_public_key_b64), validate=True)
            if len(raw) != 32:
                raise ValueError("wrong key size")
            self.root_public_key_bytes = raw
            self.root_public_key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise ThreatTrustError(f"invalid threat root public key: {exc}") from exc
        self.root_key_fingerprint = hashlib.sha256(self.root_public_key_bytes).hexdigest()[:24]

    def verify(self, keyset: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedThreatKeyset:
        if not isinstance(keyset, dict):
            raise ThreatTrustError("threat keyset must be an object")
        allowed = {"schema", "keyset_id", "sequence", "issued_at", "expires_at", "keys", "revoked_key_ids"}
        unknown = set(keyset) - allowed
        if unknown:
            raise ThreatTrustError(f"unsupported threat keyset field(s): {', '.join(sorted(unknown))}")
        if str(keyset.get("schema") or "") != THREAT_KEYSET_SCHEMA:
            raise ThreatTrustError(f"unsupported threat keyset schema; expected {THREAT_KEYSET_SCHEMA}")
        keyset_id = str(keyset.get("keyset_id") or "").strip()
        if not KEYSET_ID_RE.fullmatch(keyset_id):
            raise ThreatTrustError("keyset_id is invalid")
        sequence = keyset.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ThreatTrustError("keyset sequence must be a positive integer")
        issued_at = _parse_time(keyset.get("issued_at"), field="issued_at")
        expires_at = _parse_time(keyset.get("expires_at"), field="expires_at")
        current = time.time() if now is None else float(now)
        if expires_at <= issued_at or expires_at <= current:
            raise ThreatTrustError("threat keyset is expired or has an invalid validity window")
        if issued_at > current + 300:
            raise ThreatTrustError("threat keyset issued_at is too far in the future")

        raw_keys = keyset.get("keys")
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= MAX_CONTENT_KEYS:
            raise ThreatTrustError(f"threat keyset keys must contain 1..{MAX_CONTENT_KEYS} entries")
        keys: list[ContentKey] = []
        seen: set[str] = set()
        for item in raw_keys:
            if not isinstance(item, dict) or set(item) - {"key_id", "public_key_b64", "not_before", "not_after"}:
                raise ThreatTrustError("content key accepts only key_id/public_key_b64/not_before/not_after")
            key_id = str(item.get("key_id") or "").strip()
            if not KEY_ID_RE.fullmatch(key_id) or key_id in seen or key_id == LEGACY_THREAT_KEY_ID:
                raise ThreatTrustError("content key id is invalid, duplicated, or reserved")
            seen.add(key_id)
            try:
                public_raw = base64.b64decode(str(item.get("public_key_b64") or ""), validate=True)
                if len(public_raw) != 32:
                    raise ValueError("wrong key size")
                Ed25519PublicKey.from_public_bytes(public_raw)
            except Exception as exc:
                raise ThreatTrustError(f"invalid content public key for {key_id}: {exc}") from exc
            not_before = _parse_time(item.get("not_before"), field=f"{key_id}.not_before")
            not_after = _parse_time(item.get("not_after"), field=f"{key_id}.not_after")
            if not_after <= not_before:
                raise ThreatTrustError("content key validity window is invalid")
            if not_before < issued_at - 86400 or not_after > expires_at + 86400:
                raise ThreatTrustError("content key validity window escapes the signed keyset lifetime")
            keys.append(ContentKey(key_id, str(item["public_key_b64"]), public_raw, not_before, not_after))

        revoked_raw = keyset.get("revoked_key_ids", [])
        if not isinstance(revoked_raw, list) or len(revoked_raw) > MAX_REVOKED_KEYS:
            raise ThreatTrustError(f"revoked_key_ids must contain at most {MAX_REVOKED_KEYS} entries")
        revoked: list[str] = []
        revoked_seen: set[str] = set()
        for raw in revoked_raw:
            key_id = str(raw or "").strip()
            if not KEY_ID_RE.fullmatch(key_id) or key_id in revoked_seen:
                raise ThreatTrustError("revoked key id is invalid or duplicated")
            revoked_seen.add(key_id)
            revoked.append(key_id)
        if seen.intersection(revoked_seen):
            raise ThreatTrustError("a content key cannot be active and revoked in the same keyset")

        canonical = canonical_keyset_bytes(keyset)
        try:
            signature = base64.b64decode(str(signature_b64 or ""), validate=True)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
        except Exception as exc:
            raise ThreatTrustError(f"invalid threat keyset signature encoding: {exc}") from exc
        try:
            self.root_public_key.verify(signature, canonical)
        except InvalidSignature as exc:
            raise ThreatTrustError("threat keyset root signature verification failed") from exc

        return VerifiedThreatKeyset(
            keyset_id=keyset_id,
            sequence=int(sequence),
            issued_at=issued_at,
            expires_at=expires_at,
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            root_key_fingerprint=self.root_key_fingerprint,
            keys=tuple(keys),
            revoked_key_ids=tuple(revoked),
            raw_keyset=json.loads(json.dumps(keyset)),
            signature_b64=str(signature_b64),
        )


class ThreatTrustStore:
    """Root-pinned content-key lifecycle with authenticated local high-water state."""

    def __init__(
        self,
        base_dir: str | Path,
        *,
        integrity_key: bytes | None = None,
        verifier: ThreatKeysetVerifier | None = None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.integrity_key = bytes(integrity_key) if integrity_key is not None else ensure_integrity_key()
        self.verifier = verifier or ThreatKeysetVerifier()
        self.state_path = self.base_dir / "trust-state.json"
        self.keyset_path = self.base_dir / "active-keyset.json"
        self.audit_path = self.base_dir / "trust-transparency.jsonl"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if has_reparse_component(self.base_dir, include_leaf=False) or is_reparse_point(self.base_dir):
            raise ThreatTrustError("threat trust path cannot traverse a reparse point")

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _write_state(self, state: dict[str, Any]) -> None:
        payload = dict(state)
        payload.pop("hmac", None)
        payload["hmac"] = hmac.new(self.integrity_key, self._canonical(payload), hashlib.sha256).hexdigest()
        secure_write_parent(self.state_path)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema": TRUST_STATE_SCHEMA,
                "high_water_sequence": 0,
                "high_water_payload_sha256": "",
                "active_sequence": 0,
                "active_payload_sha256": "",
                "updated_at": 0.0,
            }
        try:
            obj = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ThreatTrustError(f"cannot read threat trust state: {exc}") from exc
        supplied = str(obj.pop("hmac", ""))
        expected = hmac.new(self.integrity_key, self._canonical(obj), hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ThreatTrustError("threat trust state HMAC verification failed")
        if int(obj.get("schema") or 0) != TRUST_STATE_SCHEMA:
            raise ThreatTrustError("threat trust state schema is invalid")
        return obj

    def _audit(self, event: str, *, keyset: VerifiedThreatKeyset | None = None, detail: str = "") -> None:
        record = {
            "ts": time.time(),
            "event": str(event),
            "keyset_id": keyset.keyset_id if keyset else "",
            "sequence": keyset.sequence if keyset else 0,
            "payload_sha256": keyset.payload_sha256 if keyset else "",
            "root_key_fingerprint": self.verifier.root_key_fingerprint,
            "detail": str(detail or "")[:512],
        }
        record["hmac"] = hmac.new(self.integrity_key, self._canonical(record), hashlib.sha256).hexdigest()
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    def validate_keyset(self, keyset: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedThreatKeyset:
        return self.verifier.verify(keyset, signature_b64, now=now)

    def install_keyset(self, keyset: dict[str, Any], signature_b64: str, *, now: float | None = None) -> dict[str, Any]:
        verified = self.validate_keyset(keyset, signature_b64, now=now)
        state = self._read_state()
        high = int(state.get("high_water_sequence") or 0)
        high_digest = str(state.get("high_water_payload_sha256") or "")
        if verified.sequence < high:
            raise ThreatTrustError("threat keyset anti-rollback: sequence is below the accepted high-water mark")
        if verified.sequence == high and high and high_digest and verified.payload_sha256 != high_digest:
            raise ThreatTrustError("threat keyset anti-rollback: sequence reuse with a different payload is forbidden")
        if verified.sequence == int(state.get("active_sequence") or 0) and verified.payload_sha256 == str(state.get("active_payload_sha256") or ""):
            return {"installed": False, "idempotent": True, "keyset": verified.to_dict()}

        payload = {"keyset": verified.raw_keyset, "signature": verified.signature_b64, "verified": verified.to_dict()}
        tmp = self.keyset_path.with_suffix(".json.tmp")
        secure_write_parent(self.keyset_path)
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.keyset_path)
        state["active_sequence"] = verified.sequence
        state["active_payload_sha256"] = verified.payload_sha256
        if verified.sequence > high:
            state["high_water_sequence"] = verified.sequence
            state["high_water_payload_sha256"] = verified.payload_sha256
        state["updated_at"] = time.time()
        self._write_state(state)
        self._audit("keyset_installed", keyset=verified, detail=f"active_keys={len(verified.keys)} revoked={len(verified.revoked_key_ids)}")
        return {"installed": True, "idempotent": False, "keyset": verified.to_dict()}

    def _active_keyset(self, *, now: float | None = None) -> VerifiedThreatKeyset | None:
        if not self.keyset_path.exists():
            return None
        try:
            obj = json.loads(self.keyset_path.read_text(encoding="utf-8"))
            verified = self.verifier.verify(obj.get("keyset"), str(obj.get("signature") or ""), now=now)
        except ThreatTrustError:
            raise
        except Exception as exc:
            raise ThreatTrustError(f"cannot load active threat keyset: {exc}") from exc
        state = self._read_state()
        if verified.sequence != int(state.get("active_sequence") or 0) or verified.payload_sha256 != str(state.get("active_payload_sha256") or ""):
            raise ThreatTrustError("active threat keyset does not match authenticated trust state")
        return verified

    def is_revoked(self, key_id: str, *, now: float | None = None) -> bool:
        key_id = str(key_id or "").strip()
        keyset = self._active_keyset(now=now)
        return bool(keyset and key_id in set(keyset.revoked_key_ids))

    def resolve_key(self, key_id: str, *, now: float | None = None) -> tuple[bytes, str]:
        key_id = str(key_id or "").strip()
        current = time.time() if now is None else float(now)
        if not key_id or key_id == LEGACY_THREAT_KEY_ID:
            if self.is_revoked(LEGACY_THREAT_KEY_ID, now=current):
                raise ThreatTrustError("legacy threat content key is revoked")
            raw = base64.b64decode(LEGACY_THREAT_ED25519_PUBLIC_KEY_B64, validate=True)
            return raw, LEGACY_THREAT_KEY_ID
        if not KEY_ID_RE.fullmatch(key_id):
            raise ThreatTrustError("threat content signing key id is invalid")
        keyset = self._active_keyset(now=current)
        if keyset is None:
            raise ThreatTrustError("no root-signed threat keyset is installed")
        if key_id in set(keyset.revoked_key_ids):
            raise ThreatTrustError(f"threat content signing key is revoked: {key_id}")
        for key in keyset.keys:
            if key.key_id == key_id:
                if current < key.not_before or current >= key.not_after:
                    raise ThreatTrustError(f"threat content signing key is outside its validity window: {key_id}")
                return key.public_key_bytes, key.key_id
        raise ThreatTrustError(f"threat content signing key is not trusted: {key_id}")

    def status(self, *, now: float | None = None) -> dict[str, Any]:
        state = self._read_state()
        keyset = None
        keyset_error = ""
        keyset_present = self.keyset_path.exists()
        try:
            keyset = self._active_keyset(now=now)
        except ThreatTrustError as exc:
            # Status remains readable even when a keyset has expired or become
            # invalid. Validation/resolution still fail closed.
            keyset_error = str(exc)
        active_keys = [] if keyset is None else [key.to_dict() for key in keyset.keys]
        revoked = [] if keyset is None else list(keyset.revoked_key_ids)
        return {
            "root_signature": "Ed25519",
            "root_key_fingerprint": self.verifier.root_key_fingerprint,
            "keyset_installed": bool(keyset_present),
            "keyset_valid": keyset is not None if keyset_present else True,
            "keyset_error": keyset_error,
            "keyset_id": keyset.keyset_id if keyset else "",
            "keyset_sequence": keyset.sequence if keyset else int(state.get("active_sequence") or 0),
            "high_water_sequence": int(state.get("high_water_sequence") or 0),
            "active_keys": active_keys,
            "revoked_key_ids": revoked,
            "legacy_key_id": LEGACY_THREAT_KEY_ID,
            "key_rotation": True,
            "key_revocation": True,
            "keyset_rollback_allowed": False,
        }
