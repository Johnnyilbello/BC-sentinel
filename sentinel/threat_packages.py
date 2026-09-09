from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import ipaddress
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import APP_VERSION
from .ioc_denylist import IOCEntry, _normalize_entry
from .path_security import has_reparse_component, is_reparse_point, secure_write_parent
from .service_hardening import ensure_integrity_key
from .service_update import version_key
from .threat_trust import (
    LEGACY_THREAT_ED25519_PUBLIC_KEY_B64, LEGACY_THREAT_KEY_ID, ThreatTrustError, ThreatTrustStore,
)

THREAT_PACKAGE_SCHEMA = "bcsentinel.threat-package.v1"
PINNED_THREAT_ED25519_PUBLIC_KEY_B64 = LEGACY_THREAT_ED25519_PUBLIC_KEY_B64
MAX_PACKAGE_BYTES = 192 * 1024
MAX_YARA_BYTES = 128 * 1024
MAX_YARA_RULES = 128
MAX_BEHAVIOR_RULES = 256
MAX_IOC_ENTRIES = 5000
MAX_REPUTATION_ENTRIES = 10000
STATE_SCHEMA = 1
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ThreatPackageError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class VerifiedThreatPackage:
    package_id: str
    sequence: int
    issued_at: float
    expires_at: float
    min_product_version: str
    payload_sha256: str
    signature_b64: str
    key_fingerprint: str
    signing_key_id: str
    component_hashes: dict[str, str]
    ioc_entries: tuple[IOCEntry, ...]
    yara_rules: tuple[dict[str, str], ...]
    behavior_rules: tuple[dict[str, Any], ...]
    reputation_entries: tuple[dict[str, Any], ...]
    raw_package: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "min_product_version": self.min_product_version,
            "payload_sha256": self.payload_sha256,
            "signature_b64": self.signature_b64,
            "key_fingerprint": self.key_fingerprint,
            "signing_key_id": self.signing_key_id,
            "component_hashes": dict(self.component_hashes),
            "ioc_entries": [entry.to_dict() for entry in self.ioc_entries],
            "yara_rules": [dict(rule) for rule in self.yara_rules],
            "behavior_rules": [dict(rule) for rule in self.behavior_rules],
            "reputation_entries": [dict(item) for item in self.reputation_entries],
        }


def canonical_package_bytes(package: dict[str, Any]) -> bytes:
    try:
        return json.dumps(package, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ThreatPackageError(f"threat package is not canonical JSON: {exc}") from exc


def _canonical_component(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise ThreatPackageError(f"threat component is not canonical JSON: {exc}") from exc


def _parse_time(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise ThreatPackageError(f"{field} is invalid")
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ThreatPackageError(f"{field} is required")
        try:
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
        except ValueError as exc:
            raise ThreatPackageError(f"{field} must be ISO-8601 or epoch seconds") from exc
    else:
        raise ThreatPackageError(f"{field} is invalid")
    if ts <= 0:
        raise ThreatPackageError(f"{field} must be positive")
    return ts


def _validate_yara_component(raw: object) -> tuple[dict[str, str], ...]:
    if raw in (None, {}):
        return ()
    if not isinstance(raw, dict) or set(raw) - {"rules"}:
        raise ThreatPackageError("YARA component accepts only a rules list")
    rules = raw.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_YARA_RULES:
        raise ThreatPackageError(f"YARA rules must be a list with at most {MAX_YARA_RULES} items")
    normalized: list[dict[str, str]] = []
    total = 0
    seen: set[str] = set()
    for item in rules:
        if not isinstance(item, dict) or set(item) - {"name", "source"}:
            raise ThreatPackageError("YARA rule accepts only name/source")
        name = str(item.get("name") or "").strip()
        source = str(item.get("source") or "")
        if not RULE_NAME_RE.fullmatch(name):
            raise ThreatPackageError("YARA rule name is invalid")
        if name.casefold() in seen:
            raise ThreatPackageError("duplicate YARA rule name")
        seen.add(name.casefold())
        raw_bytes = source.encode("utf-8")
        if not source.strip() or b"\x00" in raw_bytes:
            raise ThreatPackageError("YARA rule source is invalid")
        total += len(raw_bytes)
        if total > MAX_YARA_BYTES:
            raise ThreatPackageError(f"YARA component exceeds {MAX_YARA_BYTES} bytes")
        normalized.append({"name": name, "source": source})
    return tuple(normalized)


def validate_yara_compile(rules: tuple[dict[str, str], ...]) -> None:
    if not rules:
        return
    try:
        import yara
    except Exception as exc:
        raise ThreatPackageError(f"YARA compiler is unavailable: {exc}") from exc
    try:
        for rule in rules:
            yara.compile(source=rule["source"])
    except Exception as exc:
        raise ThreatPackageError(f"YARA package compile validation failed: {exc}") from exc


def _validate_behavior_component(raw: object) -> tuple[dict[str, Any], ...]:
    if raw in (None, {}):
        return ()
    if not isinstance(raw, dict) or set(raw) - {"rules"}:
        raise ThreatPackageError("behavior component accepts only a rules list")
    rules = raw.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_BEHAVIOR_RULES:
        raise ThreatPackageError(f"behavior rules must be a list with at most {MAX_BEHAVIOR_RULES} items")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed_categories = {"process", "file", "network", "persistence", "download", "registry"}
    for item in rules:
        if not isinstance(item, dict):
            raise ThreatPackageError("behavior rules must be objects")
        allowed = {"id", "category", "weight", "description", "enabled"}
        unknown = set(item) - allowed
        if unknown:
            raise ThreatPackageError(f"unsupported behavior rule field(s): {', '.join(sorted(unknown))}")
        rule_id = str(item.get("id") or "").strip()
        category = str(item.get("category") or "").strip().casefold()
        description = " ".join(str(item.get("description") or "").split())
        weight = item.get("weight")
        enabled = item.get("enabled", True)
        if not PACKAGE_ID_RE.fullmatch(rule_id) or rule_id.casefold() in seen:
            raise ThreatPackageError("behavior rule id is invalid or duplicated")
        seen.add(rule_id.casefold())
        if category not in allowed_categories:
            raise ThreatPackageError("behavior category is invalid")
        if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= 25:
            raise ThreatPackageError("behavior weight must be an integer between 0 and 25")
        if not isinstance(enabled, bool):
            raise ThreatPackageError("behavior enabled must be boolean")
        if len(description) > 220:
            raise ThreatPackageError("behavior description is too long")
        # v0.8 beta.1 behavior content is advisory data only. Actions, commands,
        # paths, scripts and mutation directives are deliberately not part of
        # the schema so a signed content package cannot become arbitrary code.
        out.append({
            "id": rule_id,
            "category": category,
            "weight": int(weight),
            "description": description,
            "enabled": enabled,
        })
    return tuple(out)


def _normalize_reputation_domain(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or " " in raw or "\x00" in raw:
        raise ThreatPackageError("reputation domain is invalid")
    try:
        normalized = raw.encode("idna").decode("ascii").casefold()
    except Exception as exc:
        raise ThreatPackageError(f"reputation domain is invalid: {exc}") from exc
    labels = normalized.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ThreatPackageError("reputation domain is invalid")
    return normalized


def _validate_reputation_component(raw: object, *, package_expires_at: float) -> tuple[dict[str, Any], ...]:
    if raw in (None, {}):
        return ()
    if not isinstance(raw, dict) or set(raw) - {"entries"}:
        raise ThreatPackageError("reputation component accepts only an entries list")
    entries = raw.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_REPUTATION_ENTRIES:
        raise ThreatPackageError(f"reputation entries must be a list with at most {MAX_REPUTATION_ENTRIES} items")
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ThreatPackageError("reputation entries must be objects")
        allowed = {"kind", "value", "status", "confidence", "label", "expires_at"}
        unknown = set(item) - allowed
        if unknown:
            raise ThreatPackageError(f"unsupported reputation field(s): {', '.join(sorted(unknown))}")
        kind = str(item.get("kind") or "").strip().casefold()
        if kind not in {"domain", "network"}:
            raise ThreatPackageError("reputation kind must be domain or network")
        if kind == "domain":
            value = _normalize_reputation_domain(str(item.get("value") or ""))
        else:
            try:
                network = ipaddress.ip_network(str(item.get("value") or "").strip(), strict=False)
            except ValueError as exc:
                raise ThreatPackageError(f"reputation network is invalid: {exc}") from exc
            if network.is_loopback or network.is_multicast or network.is_unspecified:
                raise ThreatPackageError("reputation network cannot target loopback/multicast/unspecified space")
            value = str(network)
        identity = (kind, value)
        if identity in seen:
            raise ThreatPackageError("reputation component contains duplicate indicators")
        seen.add(identity)
        status = str(item.get("status") or "").strip().casefold()
        if status not in {"malicious", "suspicious"}:
            raise ThreatPackageError("signed reputation status must be malicious or suspicious")
        confidence = item.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, int) or not 1 <= confidence <= 100:
            raise ThreatPackageError("signed reputation confidence must be an integer between 1 and 100")
        label = " ".join(str(item.get("label") or "").split())
        if len(label) > 220:
            raise ThreatPackageError("signed reputation label is too long")
        expires_at = package_expires_at
        if item.get("expires_at") is not None:
            expires_at = _parse_time(item.get("expires_at"), field="reputation.expires_at")
            if expires_at > package_expires_at:
                raise ThreatPackageError("reputation entry cannot outlive its signed package")
        out.append({
            "kind": kind, "value": value, "status": status, "confidence": int(confidence),
            "label": label, "expires_at": float(expires_at),
        })
    return tuple(out)


class SignedThreatPackageVerifier:
    def __init__(
        self, public_key_b64: str = PINNED_THREAT_ED25519_PUBLIC_KEY_B64, *,
        product_version: str = APP_VERSION, trust_store: ThreatTrustStore | None = None,
    ):
        try:
            key_bytes = base64.b64decode(str(public_key_b64), validate=True)
            if len(key_bytes) != 32:
                raise ValueError("wrong key size")
            self.public_key_bytes = key_bytes
            self.public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception as exc:
            raise ThreatPackageError(f"invalid Ed25519 public key: {exc}") from exc
        self.product_version = str(product_version)
        self.key_fingerprint = hashlib.sha256(self.public_key_bytes).hexdigest()[:24]
        self.trust_store = trust_store

    def verify(self, package: dict[str, Any], signature_b64: str, *, now: float | None = None) -> VerifiedThreatPackage:
        if not isinstance(package, dict):
            raise ThreatPackageError("threat package must be an object")
        allowed = {"schema", "package_id", "sequence", "issued_at", "expires_at", "min_product_version", "signing_key_id", "components"}
        unknown = set(package) - allowed
        if unknown:
            raise ThreatPackageError(f"unsupported threat package field(s): {', '.join(sorted(unknown))}")
        if str(package.get("schema") or "") != THREAT_PACKAGE_SCHEMA:
            raise ThreatPackageError(f"unsupported threat package schema; expected {THREAT_PACKAGE_SCHEMA}")
        package_id = str(package.get("package_id") or "").strip()
        if not PACKAGE_ID_RE.fullmatch(package_id):
            raise ThreatPackageError("package_id is invalid")
        sequence = package.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ThreatPackageError("sequence must be a positive integer")
        issued_at = _parse_time(package.get("issued_at"), field="issued_at")
        expires_at = _parse_time(package.get("expires_at"), field="expires_at")
        if expires_at <= issued_at:
            raise ThreatPackageError("expires_at must be after issued_at")
        current = time.time() if now is None else float(now)
        if issued_at > current + 300:
            raise ThreatPackageError("threat package issued_at is too far in the future")
        if expires_at <= current:
            raise ThreatPackageError("threat package is expired")
        min_product = str(package.get("min_product_version") or "").strip()
        try:
            if version_key(self.product_version) < version_key(min_product):
                raise ThreatPackageError(
                    f"package requires BC Sentinel {min_product} or newer; current={self.product_version}"
                )
        except ThreatPackageError:
            raise
        except Exception as exc:
            raise ThreatPackageError(f"invalid min_product_version: {exc}") from exc
        components = package.get("components")
        if not isinstance(components, dict) or not components:
            raise ThreatPackageError("components must be a non-empty object")
        allowed_components = {"ioc", "yara", "behavior", "reputation"}
        unknown_components = set(components) - allowed_components
        if unknown_components:
            raise ThreatPackageError(f"unsupported threat component(s): {', '.join(sorted(unknown_components))}")
        if len(canonical_package_bytes(package)) > MAX_PACKAGE_BYTES:
            raise ThreatPackageError(f"threat package exceeds {MAX_PACKAGE_BYTES} bytes")
        canonical = canonical_package_bytes(package)
        try:
            signature = base64.b64decode(str(signature_b64 or ""), validate=True)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
        except Exception as exc:
            raise ThreatPackageError(f"invalid Ed25519 signature encoding: {exc}") from exc
        signing_key_id = str(package.get("signing_key_id") or "").strip() or LEGACY_THREAT_KEY_ID
        verify_key = self.public_key
        key_fingerprint = self.key_fingerprint
        if self.trust_store is not None:
            try:
                raw_key, resolved_key_id = self.trust_store.resolve_key(signing_key_id, now=current)
                verify_key = Ed25519PublicKey.from_public_bytes(raw_key)
                signing_key_id = resolved_key_id
                key_fingerprint = hashlib.sha256(raw_key).hexdigest()[:24]
            except ThreatTrustError as exc:
                raise ThreatPackageError(str(exc)) from exc
        elif signing_key_id != LEGACY_THREAT_KEY_ID:
            raise ThreatPackageError("rotated threat content key requires an installed root-signed keyset")
        try:
            verify_key.verify(signature, canonical)
        except InvalidSignature as exc:
            raise ThreatPackageError("threat package signature verification failed") from exc

        ioc_entries: tuple[IOCEntry, ...] = ()
        if "ioc" in components:
            ioc_raw = components.get("ioc")
            if not isinstance(ioc_raw, dict) or set(ioc_raw) - {"entries"}:
                raise ThreatPackageError("IOC component accepts only an entries list")
            entries_raw = ioc_raw.get("entries")
            if not isinstance(entries_raw, list) or len(entries_raw) > MAX_IOC_ENTRIES:
                raise ThreatPackageError(f"IOC entries must be a list with at most {MAX_IOC_ENTRIES} items")
            ioc_entries = tuple(_normalize_entry(item, bundle_expires_at=expires_at) for item in entries_raw)
            identities = [(entry.kind, entry.value) for entry in ioc_entries]
            if len(identities) != len(set(identities)):
                raise ThreatPackageError("IOC component contains duplicate indicators")

        yara_rules = _validate_yara_component(components.get("yara"))
        behavior_rules = _validate_behavior_component(components.get("behavior"))
        reputation_entries = _validate_reputation_component(components.get("reputation"), package_expires_at=expires_at)
        component_hashes = {
            name: hashlib.sha256(_canonical_component(value)).hexdigest()
            for name, value in sorted(components.items())
        }
        return VerifiedThreatPackage(
            package_id=package_id,
            sequence=int(sequence),
            issued_at=issued_at,
            expires_at=expires_at,
            min_product_version=min_product,
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            signature_b64=str(signature_b64),
            key_fingerprint=key_fingerprint,
            signing_key_id=signing_key_id,
            component_hashes=component_hashes,
            ioc_entries=ioc_entries,
            yara_rules=yara_rules,
            behavior_rules=behavior_rules,
            reputation_entries=reputation_entries,
            raw_package=json.loads(json.dumps(package)),
        )


class ThreatPackageManager:
    """Machine-owned signed security-content staging/activation manager.

    The package format is declarative only. v0.8 beta.1 activates IOC data and
    hot-reloadable YARA rules. Behavior rules are signature-validated and
    published for transparency/future consumption, but remain advisory data in
    this beta. Last-known-good rollback is the only permitted lower-sequence
    activation path.
    """

    def __init__(
        self,
        base_dir: str | Path,
        *,
        db=None,
        verifier: SignedThreatPackageVerifier | None = None,
        integrity_key: bytes | None = None,
        require_yara_compile: bool = True,
        fault_injector=None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.db = db
        self.verifier = verifier or SignedThreatPackageVerifier()
        self.integrity_key = bytes(integrity_key) if integrity_key is not None else ensure_integrity_key()
        self.require_yara_compile = bool(require_yara_compile)
        self.fault_injector = fault_injector
        self.staging_dir = self.base_dir / "staging"
        self.packages_dir = self.base_dir / "packages"
        self.active_yara_dir = self.base_dir / "active-yara"
        self.active_behavior_path = self.base_dir / "active-behavior.json"
        self.state_path = self.base_dir / "state.json"
        self.audit_path = self.base_dir / "transparency.jsonl"
        self.activation_journal_path = self.base_dir / "activation-journal.json"
        self.last_recovery: dict[str, Any] | None = None
        self._ensure_dirs()
        self._recover_incomplete_activation()

    def _ensure_dirs(self) -> None:
        if has_reparse_component(self.base_dir, include_leaf=False) or is_reparse_point(self.base_dir):
            raise ThreatPackageError("threat intelligence path cannot traverse a reparse point")
        for path in (self.base_dir, self.staging_dir, self.packages_dir):
            path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass

    def _assert_managed_path_safe(self, path: Path, *, include_leaf: bool = True) -> None:
        path = Path(path)
        if has_reparse_component(path, include_leaf=include_leaf) or (include_leaf and is_reparse_point(path)):
            raise ThreatPackageError(f"managed threat-intelligence path is a reparse/symlink: {path}")
        try:
            path.resolve().relative_to(self.base_dir)
        except Exception as exc:
            raise ThreatPackageError("managed threat-intelligence path escaped its protected root") from exc

    def _canonical_state(self, body: dict[str, Any]) -> bytes:
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

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
                "schema": STATE_SCHEMA,
                "active": None,
                "last_known_good": None,
                "high_water_sequence": 0,
                "high_water_payload_sha256": "",
                "updated_at": 0.0,
            }
        try:
            obj = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ThreatPackageError(f"cannot read threat-intelligence state: {exc}") from exc
        supplied = str(obj.pop("hmac", ""))
        expected = hmac.new(self.integrity_key, self._canonical_state(obj), hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ThreatPackageError("threat-intelligence state HMAC verification failed")
        if int(obj.get("schema") or 0) != STATE_SCHEMA:
            raise ThreatPackageError("threat-intelligence state schema is invalid")
        return obj

    def _audit(self, event: str, *, package: VerifiedThreatPackage | None = None, detail: str = "") -> None:
        record = {
            "ts": time.time(),
            "event": str(event),
            "package_id": package.package_id if package else "",
            "sequence": package.sequence if package else 0,
            "payload_sha256": package.payload_sha256 if package else "",
            "key_fingerprint": package.key_fingerprint if package else self.verifier.key_fingerprint,
            "detail": str(detail or "")[:512],
        }
        mac = hmac.new(self.integrity_key, self._canonical_state(record), hashlib.sha256).hexdigest()
        record["hmac"] = mac
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    @staticmethod
    def _ref(package: VerifiedThreatPackage) -> dict[str, Any]:
        return {
            "package_id": package.package_id,
            "sequence": package.sequence,
            "payload_sha256": package.payload_sha256,
            "expires_at": package.expires_at,
            "key_fingerprint": package.key_fingerprint,
            "signing_key_id": package.signing_key_id,
            "component_hashes": dict(package.component_hashes),
        }

    def _package_dir_name(self, package: VerifiedThreatPackage) -> str:
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", package.package_id)
        return f"{package.sequence:010d}-{safe_id}-{package.payload_sha256[:12]}"

    @staticmethod
    def _remove_tree_with_retry(path: Path, *, required: bool, attempts: int = 6) -> bool:
        """Remove a managed package tree without making transient Windows locks fatal.

        AV/indexer processes can briefly retain directory handles after files are read.
        Cleanup of the staging copy is therefore best-effort; cleanup of a stale final
        destination is required before it can be reused.
        """
        last_error: OSError | None = None
        for attempt in range(max(1, int(attempts))):
            if not path.exists():
                return True
            try:
                shutil.rmtree(path)
                return not path.exists()
            except OSError as exc:
                last_error = exc
                time.sleep(min(0.05 * (2 ** attempt), 0.8))
        if required and path.exists():
            detail = f": {last_error}" if last_error is not None else ""
            raise ThreatPackageError(f"cannot remove stale managed package tree{detail}")
        return not path.exists()

    def _assert_tree_has_no_reparse_entries(self, root: Path) -> None:
        for entry in root.rglob("*"):
            if entry.is_symlink() or is_reparse_point(entry):
                raise ThreatPackageError("staged threat package contains an unsafe reparse/symlink entry")

    def _promote_staged_tree(
        self, source: Path, destination: Path, expected: VerifiedThreatPackage
    ) -> VerifiedThreatPackage:
        """Promote staging using copy -> cryptographic re-verify -> cleanup.

        Renaming a non-empty directory with os.replace() is vulnerable to transient
        WinError 5/32 failures when Defender, an indexer, or another reader briefly
        holds a directory handle.  Package trees are small and immutable, so copying
        to the unreferenced final tree and re-verifying it is safer and portable.

        A crash during the copy cannot change the active package because state/journal
        publication happens only after this method returns.  A partial destination is
        detected and rebuilt on the next activation attempt.
        """
        self._assert_managed_path_safe(source, include_leaf=True)
        self._assert_tree_has_no_reparse_entries(source)

        if destination.exists():
            try:
                existing = self._load_tree(destination)
            except Exception:
                existing = None
            if (
                existing is not None
                and existing.sequence == expected.sequence
                and existing.payload_sha256 == expected.payload_sha256
                and existing.package_id == expected.package_id
            ):
                self._remove_tree_with_retry(source, required=False)
                return existing
            self._remove_tree_with_retry(destination, required=True)

        try:
            shutil.copytree(source, destination, symlinks=False, copy_function=shutil.copy2)
            copied = self._load_tree(destination)
            if (
                copied.sequence != expected.sequence
                or copied.payload_sha256 != expected.payload_sha256
                or copied.package_id != expected.package_id
            ):
                raise ThreatPackageError("promoted threat package identity mismatch")
        except Exception:
            self._remove_tree_with_retry(destination, required=False)
            raise

        # Staging is no longer authoritative once the final tree was verified.  A
        # transient Windows lock may leave this duplicate behind; that is harmless and
        # must not roll back an otherwise verified activation.
        self._remove_tree_with_retry(source, required=False)
        return copied

    def _write_package_tree(self, root: Path, package: VerifiedThreatPackage) -> None:
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=False)
        (root / "package.json").write_text(json.dumps(package.raw_package, ensure_ascii=False, indent=2), encoding="utf-8")
        (root / "signature.txt").write_text(package.signature_b64 + "\n", encoding="ascii")
        meta = package.to_dict()
        (root / "verified.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        if package.ioc_entries:
            (root / "ioc.json").write_text(
                json.dumps([entry.to_dict() for entry in package.ioc_entries], ensure_ascii=False, indent=2), encoding="utf-8"
            )
        if package.yara_rules:
            yara_dir = root / "yara"
            yara_dir.mkdir()
            for rule in package.yara_rules:
                (yara_dir / f"{rule['name']}.yar").write_text(rule["source"], encoding="utf-8")
        if package.behavior_rules:
            (root / "behavior.json").write_text(json.dumps(list(package.behavior_rules), ensure_ascii=False, indent=2), encoding="utf-8")
        if package.reputation_entries:
            (root / "reputation.json").write_text(json.dumps(list(package.reputation_entries), ensure_ascii=False, indent=2), encoding="utf-8")

    def stage(self, package: dict[str, Any], signature_b64: str, *, now: float | None = None) -> dict[str, Any]:
        verified = self.verifier.verify(package, signature_b64, now=now)
        if self.require_yara_compile:
            validate_yara_compile(verified.yara_rules)
        state = self._read_state()
        high = int(state.get("high_water_sequence") or 0)
        high_digest = str(state.get("high_water_payload_sha256") or "")
        if verified.sequence < high:
            raise ThreatPackageError("threat package anti-rollback: sequence is below the accepted high-water mark")
        if verified.sequence == high and high and high_digest and verified.payload_sha256 != high_digest:
            raise ThreatPackageError("threat package anti-rollback: sequence reuse with a different payload is forbidden")
        stage_id = self._package_dir_name(verified)
        target = self.staging_dir / stage_id
        self._assert_managed_path_safe(target, include_leaf=target.exists())
        if target.exists():
            existing = json.loads((target / "verified.json").read_text(encoding="utf-8"))
            if str(existing.get("payload_sha256") or "") == verified.payload_sha256:
                return {"staged": False, "idempotent": True, "stage_id": stage_id, "package": self._ref(verified)}
            raise ThreatPackageError("staging collision with a different package")
        self._write_package_tree(target, verified)
        self._audit("staged", package=verified)
        return {"staged": True, "idempotent": False, "stage_id": stage_id, "package": self._ref(verified)}

    def _load_tree(self, root: Path) -> VerifiedThreatPackage:
        if not root.is_dir() or has_reparse_component(root, include_leaf=True):
            raise ThreatPackageError("package tree is missing or unsafe")
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        signature = (root / "signature.txt").read_text(encoding="ascii").strip()
        return self.verifier.verify(package, signature)

    def _publish_yara(self, package: VerifiedThreatPackage, source_root: Path) -> None:
        tmp = self.base_dir / "active-yara.tmp"
        self._assert_managed_path_safe(tmp, include_leaf=tmp.exists())
        self._assert_managed_path_safe(self.active_yara_dir, include_leaf=self.active_yara_dir.exists())
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True, exist_ok=False)
        src = source_root / "yara"
        if src.is_dir():
            for path in sorted(src.glob("*.yar")):
                shutil.copy2(path, tmp / path.name)
        marker = {
            "package_id": package.package_id,
            "sequence": package.sequence,
            "payload_sha256": package.payload_sha256,
            "activated_at": time.time(),
        }
        (tmp / "active-package.json").write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8")
        if self.active_yara_dir.exists():
            shutil.rmtree(self.active_yara_dir)
        os.replace(tmp, self.active_yara_dir)

    def _publish_behavior(self, package: VerifiedThreatPackage) -> None:
        payload = {
            "schema": 1,
            "package_id": package.package_id,
            "sequence": package.sequence,
            "advisory_only": True,
            "rules": list(package.behavior_rules),
        }
        self._assert_managed_path_safe(self.active_behavior_path, include_leaf=self.active_behavior_path.exists())
        tmp = self.active_behavior_path.with_suffix(".json.tmp")
        self._assert_managed_path_safe(tmp, include_leaf=tmp.exists())
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.active_behavior_path)

    def _apply_iocs(self, package: VerifiedThreatPackage | None) -> None:
        if self.db is None or not hasattr(self.db, "activate_threat_package_iocs"):
            return
        if package is None:
            self.db.activate_threat_package_iocs(None, [])
            return
        self.db.activate_threat_package_iocs(package, [entry.to_dict() for entry in package.ioc_entries])

    def _apply_reputation(self, package: VerifiedThreatPackage | None) -> None:
        if self.db is None or not hasattr(self.db, "activate_threat_package_reputation"):
            return
        if package is None:
            self.db.activate_threat_package_reputation(None, [])
            return
        self.db.activate_threat_package_reputation(package, [dict(item) for item in package.reputation_entries])

    def _journal_write(self, body: dict[str, Any]) -> None:
        payload = dict(body)
        payload.pop("hmac", None)
        payload["hmac"] = hmac.new(self.integrity_key, self._canonical_state(payload), hashlib.sha256).hexdigest()
        tmp = self.activation_journal_path.with_suffix(".json.tmp")
        secure_write_parent(self.activation_journal_path)
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.activation_journal_path)

    def _journal_read(self) -> dict[str, Any] | None:
        if not self.activation_journal_path.exists():
            return None
        try:
            obj = json.loads(self.activation_journal_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ThreatPackageError(f"cannot read activation recovery journal: {exc}") from exc
        supplied = str(obj.pop("hmac", ""))
        expected = hmac.new(self.integrity_key, self._canonical_state(obj), hashlib.sha256).hexdigest()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ThreatPackageError("activation recovery journal HMAC verification failed")
        return obj

    def _journal_clear(self) -> None:
        if self.activation_journal_path.exists():
            self.activation_journal_path.unlink()

    def _publish_ref_content(self, ref: dict[str, Any] | None) -> None:
        package, root = self._load_ref(ref)
        if package is None:
            self._apply_iocs(None)
            self._apply_reputation(None)
            if self.active_yara_dir.exists():
                shutil.rmtree(self.active_yara_dir)
            self.active_yara_dir.mkdir(parents=True, exist_ok=True)
            (self.active_yara_dir / "active-package.json").write_text(json.dumps({"package_id":"","sequence":0,"payload_sha256":"","activated_at":time.time()}, indent=2), encoding="utf-8")
            tmp = self.active_behavior_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps({"schema":1,"package_id":"","sequence":0,"advisory_only":True,"rules":[]}, indent=2), encoding="utf-8")
            os.replace(tmp, self.active_behavior_path)
            return
        self._apply_iocs(package)
        self._apply_reputation(package)
        self._publish_yara(package, root)
        self._publish_behavior(package)

    def _recover_incomplete_activation(self) -> None:
        journal = self._journal_read()
        if not journal:
            return
        state = self._read_state()
        target = journal.get("target") if isinstance(journal.get("target"), dict) else None
        current = state.get("active") if isinstance(state.get("active"), dict) else None
        target_digest = str((target or {}).get("payload_sha256") or "")
        current_digest = str((current or {}).get("payload_sha256") or "")
        if target_digest and current_digest == target_digest:
            self.last_recovery = {"action":"commit_confirmed","target_payload_sha256":target_digest,"ts":time.time()}
            self._journal_clear()
            self._audit("activation_recovery_commit_confirmed", detail=target_digest[:16])
            return
        previous = journal.get("previous_active") if isinstance(journal.get("previous_active"), dict) else None
        self._publish_ref_content(previous)
        self.last_recovery = {"action":"rolled_back_partial_activation","target_payload_sha256":target_digest,"ts":time.time()}
        self._journal_clear()
        self._audit("activation_recovered", detail=f"rolled back partial target={target_digest[:16]}")

    def _fault(self, phase: str) -> None:
        if callable(self.fault_injector):
            self.fault_injector(str(phase))

    def activate(self, stage_id: str) -> dict[str, Any]:
        stage_id = str(stage_id or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,220}", stage_id):
            raise ThreatPackageError("stage_id is invalid")
        source = self.staging_dir / stage_id
        self._assert_managed_path_safe(source, include_leaf=True)
        package = self._load_tree(source)
        state = self._read_state()
        high = int(state.get("high_water_sequence") or 0)
        high_digest = str(state.get("high_water_payload_sha256") or "")
        active = state.get("active")
        if active and int(active.get("sequence") or 0) == package.sequence and str(active.get("payload_sha256") or "") == package.payload_sha256:
            return {"activated": False, "idempotent": True, "active": dict(active)}
        if package.sequence < high:
            raise ThreatPackageError("threat package anti-rollback: activation sequence is below the high-water mark")
        if package.sequence == high and high and high_digest and package.payload_sha256 != high_digest:
            raise ThreatPackageError("threat package anti-rollback: sequence reuse with a different payload is forbidden")
        destination = self.packages_dir / self._package_dir_name(package)
        self._assert_managed_path_safe(destination, include_leaf=destination.exists())
        package = self._promote_staged_tree(source, destination, package)
        self._fault("after_package_promote")
        previous = dict(active) if isinstance(active, dict) else None
        target_ref = self._ref(package)
        target_ref["tree"] = destination.name
        self._journal_write({
            "schema": 1, "action": "activate", "phase": "prepared", "created_at": time.time(),
            "previous_active": previous, "previous_lkg": state.get("last_known_good"), "target": target_ref,
        })
        self._fault("after_journal_prepare")
        self._apply_iocs(package)
        self._fault("after_ioc_publish")
        self._apply_reputation(package)
        self._fault("after_reputation_publish")
        self._publish_yara(package, destination)
        self._fault("after_yara_publish")
        self._publish_behavior(package)
        self._fault("after_behavior_publish")
        journal = self._journal_read() or {}
        journal["phase"] = "content_published"
        self._journal_write(journal)
        self._fault("after_content_journal_commit")
        self._fault("after_content_publish")
        state["last_known_good"] = previous
        state["active"] = self._ref(package)
        state["active"]["tree"] = destination.name
        state["active"]["activated_at"] = time.time()
        if package.sequence > high:
            state["high_water_sequence"] = package.sequence
            state["high_water_payload_sha256"] = package.payload_sha256
        state["updated_at"] = time.time()
        self._write_state(state)
        self._fault("after_state_commit")
        self._fault("before_journal_clear")
        self._journal_clear()
        self._fault("after_journal_clear")
        self._audit("activated", package=package)
        return {"activated": True, "idempotent": False, "active": dict(state["active"]), "last_known_good": state.get("last_known_good")}

    def _load_ref(self, ref: dict[str, Any] | None) -> tuple[VerifiedThreatPackage | None, Path | None]:
        if not ref:
            return None, None
        tree = str(ref.get("tree") or "")
        if not tree:
            # Older state references can be reconstructed from immutable package trees.
            seq = int(ref.get("sequence") or 0)
            digest = str(ref.get("payload_sha256") or "")
            matches = [p for p in self.packages_dir.glob(f"{seq:010d}-*-{digest[:12]}") if p.is_dir()]
            if len(matches) != 1:
                raise ThreatPackageError("last-known-good package tree is unavailable")
            root = matches[0]
        else:
            root = self.packages_dir / tree
        package = self._load_tree(root)
        if package.payload_sha256 != str(ref.get("payload_sha256") or ""):
            raise ThreatPackageError("package tree does not match signed state reference")
        return package, root

    def rollback_last_known_good(self) -> dict[str, Any]:
        state = self._read_state()
        current_ref = state.get("active") if isinstance(state.get("active"), dict) else None
        lkg_ref = state.get("last_known_good") if isinstance(state.get("last_known_good"), dict) else None
        package, root = self._load_ref(lkg_ref)
        if package is None:
            self._apply_iocs(None)
            self._apply_reputation(None)
            if self.active_yara_dir.exists():
                shutil.rmtree(self.active_yara_dir)
            self.active_yara_dir.mkdir(parents=True, exist_ok=True)
            marker = {"package_id": "", "sequence": 0, "payload_sha256": "", "activated_at": time.time()}
            (self.active_yara_dir / "active-package.json").write_text(json.dumps(marker, indent=2), encoding="utf-8")
            tmp = self.active_behavior_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps({"schema": 1, "package_id": "", "sequence": 0, "advisory_only": True, "rules": []}, indent=2), encoding="utf-8")
            os.replace(tmp, self.active_behavior_path)
            state["active"] = None
        else:
            self._apply_iocs(package)
            self._apply_reputation(package)
            self._publish_yara(package, root)
            self._publish_behavior(package)
            restored = dict(lkg_ref)
            restored["tree"] = root.name
            restored["activated_at"] = time.time()
            state["active"] = restored
        # One-step reversible rollback: the package we just rolled back from
        # becomes the next LKG, allowing a controlled operator undo/redo while
        # the high-water anti-downgrade marker remains unchanged.
        state["last_known_good"] = current_ref
        state["updated_at"] = time.time()
        self._write_state(state)
        self._audit("rolled_back", package=package, detail="last-known-good restoration")
        return {"rolled_back": True, "active": state.get("active"), "last_known_good": state.get("last_known_good")}

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        active = state.get("active") if isinstance(state.get("active"), dict) else None
        lkg = state.get("last_known_good") if isinstance(state.get("last_known_good"), dict) else None
        staged = 0
        try:
            staged = sum(1 for p in self.staging_dir.iterdir() if p.is_dir())
        except OSError:
            pass
        active_signer_revoked = False
        if active and self.verifier.trust_store is not None:
            try:
                active_signer_revoked = self.verifier.trust_store.is_revoked(str(active.get("signing_key_id") or LEGACY_THREAT_KEY_ID))
            except Exception:
                active_signer_revoked = True
        reputation_entries = 0
        if self.db is not None and hasattr(self.db, "threat_package_reputation_count"):
            try:
                reputation_entries = int(self.db.threat_package_reputation_count())
            except Exception:
                reputation_entries = 0
        if not active:
            revocation_state = "no_active_package"
        elif active_signer_revoked:
            revocation_state = "critical_replacement_required"
        else:
            revocation_state = "ok"
        revocation_policy = {
            "state": revocation_state,
            "active_content_retained": True,
            "replacement_required": bool(active_signer_revoked),
            "new_packages_from_revoked_key_rejected": True,
            "automatic_destructive_action": False,
            "fail_open": False,
        }
        return {
            "schema": STATE_SCHEMA,
            "channel": "signed_local_content",
            "signature": "Ed25519",
            "key_fingerprint": self.verifier.key_fingerprint,
            "active": active,
            "last_known_good": lkg,
            "active_signer_revoked": active_signer_revoked,
            "revocation_policy": revocation_policy,
            "signed_reputation_entries": reputation_entries,
            "high_water_sequence": int(state.get("high_water_sequence") or 0),
            "staged_packages": staged,
            "staged_activation": True,
            "last_known_good_rollback": True,
            "arbitrary_code_execution": False,
            "supported_components": ["ioc", "yara", "behavior_advisory", "signed_reputation_advisory"],
            "signed_reputation_enforcement": False,
            "activation_recovery": True,
            "recovery_journal_pending": self.activation_journal_path.exists(),
            "last_recovery": dict(self.last_recovery) if isinstance(self.last_recovery, dict) else None,
            "behavior_enforcement": False,
            "yara_compile_required": bool(self.require_yara_compile),
        }

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(int(limit), 200)):]:
            try:
                obj = json.loads(line)
                supplied = str(obj.pop("hmac", ""))
                expected = hmac.new(self.integrity_key, self._canonical_state(obj), hashlib.sha256).hexdigest()
                obj["authenticated"] = bool(supplied and hmac.compare_digest(supplied, expected))
                obj["hmac"] = supplied
                rows.append(obj)
            except Exception:
                continue
        return rows
