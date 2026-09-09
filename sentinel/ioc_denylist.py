from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import base64
import hashlib
import ipaddress
import json
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Production trust anchor for BC Sentinel signed IOC bundles. The corresponding
# private key is NOT shipped with the product.
PINNED_IOC_ED25519_PUBLIC_KEY_B64 = "raQ5aV3CzQOhgiZtkf0rfcFPOUUw4SzalaNJ9eVAGas="
IOC_SCHEMA = "bcsentinel.ioc.v1"
MAX_IOC_ENTRIES = 1000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


class IOCBundleError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class IOCEntry:
    kind: str
    value: str
    severity: str
    label: str = ""
    expires_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class VerifiedIOCBundle:
    bundle_id: str
    sequence: int
    issued_at: float
    expires_at: float
    payload_sha256: str
    signature_b64: str
    entries: tuple[IOCEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "payload_sha256": self.payload_sha256,
            "signature_b64": self.signature_b64,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def canonical_bundle_bytes(bundle: dict[str, Any]) -> bytes:
    try:
        return json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise IOCBundleError(f"IOC bundle is not canonical JSON: {exc}") from exc


def _parse_time(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise IOCBundleError(f"{field} is invalid")
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise IOCBundleError(f"{field} is required")
        try:
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
        except ValueError as exc:
            raise IOCBundleError(f"{field} must be ISO-8601 or epoch seconds") from exc
    else:
        raise IOCBundleError(f"{field} is invalid")
    if ts <= 0:
        raise IOCBundleError(f"{field} must be positive")
    return ts


def _normalize_entry(raw: object, *, bundle_expires_at: float) -> IOCEntry:
    if not isinstance(raw, dict):
        raise IOCBundleError("IOC entries must be objects")
    allowed = {"kind", "value", "severity", "label", "expires_at"}
    unknown = set(raw) - allowed
    if unknown:
        raise IOCBundleError(f"Unsupported IOC entry field(s): {', '.join(sorted(unknown))}")
    kind = str(raw.get("kind") or "").strip().casefold()
    value = str(raw.get("value") or "").strip()
    severity = str(raw.get("severity") or "high").strip().casefold()
    label = " ".join(str(raw.get("label") or "").split())
    if severity not in {"medium", "high", "critical"}:
        raise IOCBundleError("IOC severity must be medium, high or critical")
    if len(label) > 180:
        raise IOCBundleError("IOC label is too long")
    if kind == "sha256":
        value = value.casefold()
        if not SHA256_RE.fullmatch(value):
            raise IOCBundleError("sha256 IOC must be a 64-character hex digest")
    elif kind == "network":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise IOCBundleError("network IOC must be an IPv4/IPv6 address or CIDR") from exc
        # Signed feeds may carry networks, but containment never accepts overly
        # broad scopes: keep the same safety floor as the managed firewall.
        min_prefix = 8 if network.version == 4 else 16
        if network.prefixlen < min_prefix or network.is_unspecified or network.is_multicast or network.is_loopback:
            raise IOCBundleError(f"network IOC is outside the safe scope floor /{min_prefix}")
        value = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    elif kind == "domain":
        value = value.rstrip(".").casefold()
        if not DOMAIN_RE.fullmatch(value):
            raise IOCBundleError("domain IOC is invalid")
    else:
        raise IOCBundleError("IOC kind must be sha256, network or domain")
    expires_at = bundle_expires_at
    if raw.get("expires_at") not in (None, ""):
        expires_at = min(bundle_expires_at, _parse_time(raw.get("expires_at"), field="entry.expires_at"))
    return IOCEntry(kind=kind, value=value, severity=severity, label=label, expires_at=expires_at)


class SignedIOCVerifier:
    def __init__(self, public_key_b64: str = PINNED_IOC_ED25519_PUBLIC_KEY_B64):
        try:
            key_bytes = base64.b64decode(str(public_key_b64), validate=True)
            if len(key_bytes) != 32:
                raise ValueError("wrong key size")
            self.public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception as exc:
            raise IOCBundleError(f"invalid Ed25519 public key: {exc}") from exc

    def verify(self, bundle: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedIOCBundle:
        if not isinstance(bundle, dict):
            raise IOCBundleError("IOC bundle must be an object")
        allowed = {"schema", "bundle_id", "sequence", "issued_at", "expires_at", "entries"}
        unknown = set(bundle) - allowed
        if unknown:
            raise IOCBundleError(f"Unsupported IOC bundle field(s): {', '.join(sorted(unknown))}")
        if str(bundle.get("schema") or "") != IOC_SCHEMA:
            raise IOCBundleError(f"unsupported IOC schema; expected {IOC_SCHEMA}")
        bundle_id = str(bundle.get("bundle_id") or "").strip()
        if not bundle_id or len(bundle_id) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", bundle_id):
            raise IOCBundleError("bundle_id is invalid")
        sequence = bundle.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise IOCBundleError("sequence must be a positive integer")
        issued_at = _parse_time(bundle.get("issued_at"), field="issued_at")
        expires_at = _parse_time(bundle.get("expires_at"), field="expires_at")
        if expires_at <= issued_at:
            raise IOCBundleError("IOC bundle expires_at must be after issued_at")
        current = time.time() if now is None else float(now)
        if issued_at > current + 300:
            raise IOCBundleError("IOC bundle issued_at is too far in the future")
        if expires_at <= current:
            raise IOCBundleError("IOC bundle is expired")
        entries_raw = bundle.get("entries")
        if not isinstance(entries_raw, list) or len(entries_raw) > MAX_IOC_ENTRIES:
            raise IOCBundleError(f"entries must be a list with at most {MAX_IOC_ENTRIES} items")
        canonical = canonical_bundle_bytes(bundle)
        try:
            signature = base64.b64decode(str(signature_b64 or ""), validate=True)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
        except Exception as exc:
            raise IOCBundleError(f"invalid Ed25519 signature encoding: {exc}") from exc
        try:
            self.public_key.verify(signature, canonical)
        except InvalidSignature as exc:
            raise IOCBundleError("IOC bundle signature verification failed") from exc
        entries = tuple(_normalize_entry(item, bundle_expires_at=expires_at) for item in entries_raw)
        # Duplicate identities inside one signed bundle are rejected so feed
        # precedence remains deterministic and auditable.
        identities = [(entry.kind, entry.value) for entry in entries]
        if len(set(identities)) != len(identities):
            raise IOCBundleError("IOC bundle contains duplicate indicators")
        return VerifiedIOCBundle(
            bundle_id=bundle_id,
            sequence=int(sequence),
            issued_at=issued_at,
            expires_at=expires_at,
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            signature_b64=str(signature_b64),
            entries=entries,
        )
