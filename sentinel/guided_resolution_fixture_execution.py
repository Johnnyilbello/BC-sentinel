from __future__ import annotations

"""B6-5.5 harmless fixture-only execution provider and rollback acceptance.

This milestone proves that BC Sentinel can cross an execution boundary without
silently turning confirmation into broad remediation authority.  The provider is
intentionally restricted to a freshly prepared directory under the operating
system temporary directory whose name starts with ``BCSentinel-B655-`` and that
contains the exact B6-5.5 fixture marker.

Only a reversible QUARANTINE operation is available.  It requires an
integrity-bound B6-5.2 plan, a valid B6-5.3 explicit-confirmation receipt, fresh
post-confirmation SHA-256 revalidation, a one-shot short-lived permit, an
append-only hash-chained journal and a verified rollback snapshot.  The normal
Home does not load this execution provider and no real user/system file is in
scope for this checkpoint.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Final

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_execution_gate as execution_gate
from sentinel import guided_resolution_provider_loader as source_provider_boundary

PROFILE: Final[str] = "v0.11.0-beta.6-b65.5-fixture-execution"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-execution-v1"
PROVIDER_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-provider-v1"
PERMIT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-permit-v1"
RESULT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-result-v1"
ROLLBACK_RESULT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-rollback-v1"
JOURNAL_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-fixture-journal-v1"

PROVIDER_NAME: Final[str] = "BC Sentinel B6-5.5 harmless fixture execution provider"
PROVIDER_PROFILE: Final[str] = PROFILE
PROVIDER_PROVENANCE: Final[str] = "builtin:b655_fixture_quarantine_execution_v1"

FIXTURE_PREFIX: Final[str] = "BCSentinel-B655-"
FIXTURE_MARKER_NAME: Final[str] = ".bc-sentinel-b655-fixture-only"
FIXTURE_MARKER_CONTENT: Final[str] = "BC_SENTINEL_B655_HARMLESS_FIXTURE_ONLY\n"
SUPPORTED_ACTION: Final[str] = "QUARANTINE"
AUTHORITY_SCOPE: Final[str] = "HARMLESS_FIXTURE_ONLY"
PERMIT_PREFIX: Final[str] = "B655-PERMIT-"
RESULT_PREFIX: Final[str] = "B655-RESULT-"
ROLLBACK_PREFIX: Final[str] = "B655-ROLLBACK-"
MAX_PERMIT_TTL_SECONDS: Final[int] = 60
MAX_POST_CONFIRM_REVALIDATION_AGE_SECONDS: Final[int] = 30
ZERO_HASH: Final[str] = "0" * 64


# ---------------------------------------------------------------------------
# Canonical hashing and path safety
# ---------------------------------------------------------------------------

def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _normalized_path(path: str | Path) -> str:
    return os.path.normcase(str(_resolved(path)))


def _system_temp_root() -> Path:
    return _resolved(tempfile.gettempdir())


def _validate_fixture_root_path(root: Path) -> None:
    temp_root = _system_temp_root()
    if not _is_within(root, temp_root):
        raise ValueError("b655_fixture_root_must_be_under_system_temp")
    if not root.name.startswith(FIXTURE_PREFIX):
        raise ValueError("b655_fixture_root_prefix_required")


def _require_fixture_marker(root: Path) -> None:
    marker = root / FIXTURE_MARKER_NAME
    if not marker.is_file():
        raise ValueError("b655_fixture_marker_missing")
    try:
        content = marker.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("b655_fixture_marker_unreadable") from exc
    if content != FIXTURE_MARKER_CONTENT:
        raise ValueError("b655_fixture_marker_invalid")


def _require_regular_file(path: Path, *, error_prefix: str) -> None:
    if path.is_symlink():
        raise ValueError(f"{error_prefix}_symlink_refused")
    if not path.is_file():
        raise ValueError(f"{error_prefix}_regular_file_required")


# ---------------------------------------------------------------------------
# Explicit harmless fixture environment
# ---------------------------------------------------------------------------

def prepare_fixture_environment(root: str | Path) -> dict[str, str]:
    """Create only the dedicated B6-5.5 temporary fixture structure.

    The caller must supply a unique path under the OS temp directory whose name
    starts with ``BCSentinel-B655-``.  This helper is never called by Home.
    """

    fixture_root = _resolved(root)
    _validate_fixture_root_path(fixture_root)
    fixture_root.mkdir(parents=True, exist_ok=False)
    (fixture_root / FIXTURE_MARKER_NAME).write_text(FIXTURE_MARKER_CONTENT, encoding="utf-8")

    input_root = fixture_root / "input"
    quarantine_root = fixture_root / "quarantine"
    rollback_root = fixture_root / "rollback"
    journal_root = fixture_root / "journal"
    for directory in (input_root, quarantine_root, rollback_root, journal_root):
        directory.mkdir(parents=False, exist_ok=False)

    return {
        "fixture_root": str(fixture_root),
        "input_root": str(input_root),
        "quarantine_root": str(quarantine_root),
        "rollback_root": str(rollback_root),
        "journal_path": str(journal_root / "events.jsonl"),
    }


# ---------------------------------------------------------------------------
# Dedicated execution provider
# ---------------------------------------------------------------------------

class FixtureQuarantineProvider:
    name = PROVIDER_NAME
    profile = PROVIDER_PROFILE
    provenance = PROVIDER_PROVENANCE

    def __init__(self, fixture_root: str | Path) -> None:
        root = _resolved(fixture_root)
        _validate_fixture_root_path(root)
        _require_fixture_marker(root)
        self.fixture_root = root
        self.input_root = root / "input"
        self.quarantine_root = root / "quarantine"
        self.rollback_root = root / "rollback"
        self.journal_path = root / "journal" / "events.jsonl"
        for directory in (self.input_root, self.quarantine_root, self.rollback_root, self.journal_path.parent):
            if not directory.is_dir():
                raise ValueError("b655_fixture_structure_incomplete")

    def capabilities(self) -> dict:
        return {
            "schema": PROVIDER_SCHEMA,
            "accepted": True,
            "available": True,
            "execution_available": True,
            "authority_scope": AUTHORITY_SCOPE,
            "fixture_only": True,
            "automatic_action": False,
            "destructive_authority": False,
            "one_shot_permit_required": True,
            "fresh_target_sha256_required": True,
            "journal_required": True,
            "rollback_snapshot_required": True,
            "fixture_root": str(self.fixture_root),
            "input_root": str(self.input_root),
            "quarantine_root": str(self.quarantine_root),
            "rollback_root": str(self.rollback_root),
            "journal_path": str(self.journal_path),
            "actions": [
                {
                    "action_id": SUPPORTED_ACTION,
                    "available": True,
                    "mutates_system": True,
                    "reversible": True,
                    "fixture_only": True,
                }
            ],
        }

    def snapshot_sha256(self) -> str:
        return _sha256_payload(self.capabilities())

    def _validate_target(self, target: str | Path, expected_sha256: str) -> Path:
        if not _is_sha256(expected_sha256):
            raise ValueError("b655_target_sha256_required")
        path = _resolved(target)
        if not _is_within(path, self.input_root):
            raise ValueError("b655_target_outside_fixture_input")
        _require_regular_file(path, error_prefix="b655_target")
        actual = _sha256_file(path)
        if actual != expected_sha256.casefold():
            raise ValueError("b655_target_sha256_drift")
        return path

    def _read_journal(self) -> list[dict]:
        if not self.journal_path.exists():
            return []
        entries: list[dict] = []
        try:
            with self.journal_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    text = line.strip()
                    if text:
                        item = json.loads(text)
                        if not isinstance(item, dict):
                            raise ValueError("b655_journal_entry_not_mapping")
                        entries.append(item)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("b655_journal_unreadable") from exc
        return entries

    def _append_journal(self, permit: "FixtureExecutionPermit", event: str, *, now: float, payload: dict) -> dict:
        entries = self._read_journal()
        previous = str(entries[-1].get("entry_sha256") or ZERO_HASH) if entries else ZERO_HASH
        sequence = len(entries) + 1
        body = {
            "schema": JOURNAL_SCHEMA,
            "profile": PROFILE,
            "sequence": sequence,
            "permit_id": permit.permit_id,
            "permit_sha256": permit.permit_sha256,
            "event": str(event),
            "timestamp": float(now),
            "target_locator": permit.target_locator,
            "target_sha256": permit.target_sha256,
            "previous_entry_sha256": previous,
            "payload": dict(payload),
        }
        digest = _sha256_payload(body)
        entry = {**body, "entry_sha256": digest}
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry

    def _permit_already_consumed(self, permit_id: str) -> bool:
        return any(
            item.get("permit_id") == permit_id and item.get("event") == "PERMIT_CONSUMED"
            for item in self._read_journal()
        )

    def execute_quarantine(self, permit: "FixtureExecutionPermit", *, now: float) -> "FixtureExecutionResult":
        """Execute the single reversible fixture action after validating the permit."""

        permit.validate()
        _validate_permit_for_provider(permit, self, now=float(now))
        if self._permit_already_consumed(permit.permit_id):
            raise ValueError("b655_permit_replay_refused")

        target = self._validate_target(permit.target_locator, permit.target_sha256)
        snapshot_path = self.rollback_root / f"{permit.permit_id}.snapshot"
        quarantine_path = self.quarantine_root / f"{permit.permit_id}-{target.name}"
        if snapshot_path.exists() or quarantine_path.exists():
            raise ValueError("b655_execution_artifact_collision")

        shutil.copy2(target, snapshot_path)
        _require_regular_file(snapshot_path, error_prefix="b655_snapshot")
        if _sha256_file(snapshot_path) != permit.target_sha256:
            raise ValueError("b655_snapshot_verification_failed")

        self._append_journal(
            permit,
            "PRE_STATE_RECORDED",
            now=float(now),
            payload={"snapshot_path": str(snapshot_path), "snapshot_sha256": permit.target_sha256},
        )
        self._append_journal(
            permit,
            "PERMIT_CONSUMED",
            now=float(now),
            payload={"one_shot": True, "authority_scope": AUTHORITY_SCOPE},
        )

        started = float(now)
        try:
            os.replace(target, quarantine_path)
            if target.exists():
                raise ValueError("b655_target_still_present_after_quarantine")
            _require_regular_file(quarantine_path, error_prefix="b655_quarantine")
            if _sha256_file(quarantine_path) != permit.target_sha256:
                raise ValueError("b655_quarantine_verification_failed")
        except Exception as exc:
            # Fixture-only emergency restoration.  Never overwrite an unrelated
            # existing path and never leave a known moved fixture stranded.
            restored = False
            if not target.exists():
                if quarantine_path.is_file() and not quarantine_path.is_symlink():
                    os.replace(quarantine_path, target)
                    restored = _sha256_file(target) == permit.target_sha256
                elif snapshot_path.is_file() and not snapshot_path.is_symlink():
                    shutil.copy2(snapshot_path, target)
                    restored = _sha256_file(target) == permit.target_sha256
            self._append_journal(
                permit,
                "ACTION_FAILED",
                now=float(now),
                payload={"error": type(exc).__name__, "emergency_restore_verified": restored},
            )
            raise

        action_entry = self._append_journal(
            permit,
            "ACTION_RESULT",
            now=float(now),
            payload={
                "state": "QUARANTINED_VERIFIED",
                "quarantine_path": str(quarantine_path),
                "snapshot_path": str(snapshot_path),
                "sha256": permit.target_sha256,
            },
        )

        draft = FixtureExecutionResult(
            result_id="",
            result_sha256="",
            permit_id=permit.permit_id,
            permit_sha256=permit.permit_sha256,
            state="QUARANTINED_VERIFIED",
            target_locator=str(target),
            target_sha256=permit.target_sha256,
            quarantine_path=str(quarantine_path),
            snapshot_path=str(snapshot_path),
            started_at=started,
            finished_at=float(now),
            journal_tail_sha256=str(action_entry["entry_sha256"]),
            pre_state_verified=True,
            post_state_verified=True,
        )
        digest = _sha256_payload(draft.canonical_without_hash())
        result = FixtureExecutionResult(
            **{
                **draft.__dict__,
                "result_id": RESULT_PREFIX + digest[:16].upper(),
                "result_sha256": digest,
            }
        )
        result.validate()
        return result

    def rollback_quarantine(
        self,
        permit: "FixtureExecutionPermit",
        result: "FixtureExecutionResult",
        *,
        now: float,
    ) -> "FixtureRollbackResult":
        """Restore the exact fixture target and verify its SHA-256."""

        permit.validate()
        result.validate()
        _validate_permit_for_provider(permit, self, now=float(now), allow_expired_after_execution=True)
        if result.permit_id != permit.permit_id or result.permit_sha256 != permit.permit_sha256:
            raise ValueError("b655_rollback_result_permit_mismatch")
        if any(
            item.get("permit_id") == permit.permit_id and item.get("event") == "ROLLBACK_RESULT"
            for item in self._read_journal()
        ):
            raise ValueError("b655_rollback_replay_refused")

        target = _resolved(result.target_locator)
        quarantine_path = _resolved(result.quarantine_path)
        snapshot_path = _resolved(result.snapshot_path)
        if not _is_within(target, self.input_root):
            raise ValueError("b655_rollback_target_outside_fixture_input")
        if not _is_within(quarantine_path, self.quarantine_root):
            raise ValueError("b655_rollback_quarantine_path_invalid")
        if not _is_within(snapshot_path, self.rollback_root):
            raise ValueError("b655_rollback_snapshot_path_invalid")
        if target.exists():
            raise ValueError("b655_rollback_refuses_existing_target")

        _require_regular_file(quarantine_path, error_prefix="b655_rollback_quarantine")
        _require_regular_file(snapshot_path, error_prefix="b655_rollback_snapshot")
        if _sha256_file(quarantine_path) != permit.target_sha256:
            raise ValueError("b655_rollback_quarantine_hash_mismatch")
        if _sha256_file(snapshot_path) != permit.target_sha256:
            raise ValueError("b655_rollback_snapshot_hash_mismatch")

        self._append_journal(
            permit,
            "ROLLBACK_STARTED",
            now=float(now),
            payload={"quarantine_path": str(quarantine_path), "snapshot_path": str(snapshot_path)},
        )

        os.replace(quarantine_path, target)
        _require_regular_file(target, error_prefix="b655_restored_target")
        restored_hash = _sha256_file(target)
        if restored_hash != permit.target_sha256:
            raise ValueError("b655_rollback_verification_failed")
        if quarantine_path.exists():
            raise ValueError("b655_quarantine_artifact_still_present_after_rollback")

        rollback_entry = self._append_journal(
            permit,
            "ROLLBACK_RESULT",
            now=float(now),
            payload={"state": "RESTORED_VERIFIED", "restored_sha256": restored_hash},
        )
        final_entry = self._append_journal(
            permit,
            "FINAL_OUTCOME",
            now=float(now),
            payload={"state": "RECOVERED", "target_restored": True},
        )

        draft = FixtureRollbackResult(
            rollback_id="",
            rollback_sha256="",
            permit_id=permit.permit_id,
            result_id=result.result_id,
            state="RESTORED_VERIFIED",
            target_locator=str(target),
            target_sha256=restored_hash,
            quarantine_absent=True,
            snapshot_verified=True,
            journal_rollback_sha256=str(rollback_entry["entry_sha256"]),
            journal_final_sha256=str(final_entry["entry_sha256"]),
            finished_at=float(now),
        )
        digest = _sha256_payload(draft.canonical_without_hash())
        rollback = FixtureRollbackResult(
            **{
                **draft.__dict__,
                "rollback_id": ROLLBACK_PREFIX + digest[:16].upper(),
                "rollback_sha256": digest,
            }
        )
        rollback.validate()
        return rollback


# ---------------------------------------------------------------------------
# Permit and result records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FixtureExecutionPermit:
    permit_id: str
    permit_sha256: str
    plan_id: str
    plan_sha256: str
    receipt_id: str
    receipt_sha256: str
    requested_action: str
    finding_id: str
    target_locator: str
    target_sha256: str
    target_fingerprint: str
    source_provider_snapshot_sha256: str
    execution_provider_snapshot_sha256: str
    post_confirmation_revalidation_sha256: str
    fixture_root: str
    journal_path: str
    rollback_root: str
    issued_at: float
    expires_at: float
    nonce: str
    authority_scope: str = AUTHORITY_SCOPE
    execution_authorized: bool = True
    live_home_execution_authorized: bool = False
    journal_write_authority: bool = True
    rollback_execution_authority: bool = True
    automatic_action: bool = False
    destructive_authority: bool = False
    schema: str = PERMIT_SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "requested_action": self.requested_action,
            "finding_id": self.finding_id,
            "target_locator": self.target_locator,
            "target_sha256": self.target_sha256,
            "target_fingerprint": self.target_fingerprint,
            "source_provider_snapshot_sha256": self.source_provider_snapshot_sha256,
            "execution_provider_snapshot_sha256": self.execution_provider_snapshot_sha256,
            "post_confirmation_revalidation_sha256": self.post_confirmation_revalidation_sha256,
            "fixture_root": self.fixture_root,
            "journal_path": self.journal_path,
            "rollback_root": self.rollback_root,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "authority_scope": self.authority_scope,
            "execution_authorized": True,
            "live_home_execution_authorized": False,
            "journal_write_authority": True,
            "rollback_execution_authority": True,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != PERMIT_SCHEMA:
            raise ValueError("b655_permit_schema_mismatch")
        if self.authority_scope != AUTHORITY_SCOPE:
            raise ValueError("b655_permit_scope_invalid")
        if self.requested_action != SUPPORTED_ACTION:
            raise ValueError("b655_permit_action_invalid")
        if not self.plan_id.startswith(planning.PLAN_PREFIX) or not _is_sha256(self.plan_sha256):
            raise ValueError("b655_permit_plan_binding_invalid")
        if not self.receipt_id.startswith(confirmation.RECEIPT_PREFIX) or not _is_sha256(self.receipt_sha256):
            raise ValueError("b655_permit_receipt_binding_invalid")
        for value in (
            self.target_sha256,
            self.target_fingerprint,
            self.source_provider_snapshot_sha256,
            self.execution_provider_snapshot_sha256,
            self.post_confirmation_revalidation_sha256,
        ):
            if not _is_sha256(value):
                raise ValueError("b655_permit_hash_binding_invalid")
        if not self.finding_id.strip() or not self.target_locator.strip():
            raise ValueError("b655_permit_subject_required")
        root = _resolved(self.fixture_root)
        _validate_fixture_root_path(root)
        if not _is_within(_resolved(self.target_locator), root / "input"):
            raise ValueError("b655_permit_target_outside_fixture")
        if not _is_within(_resolved(self.journal_path), root / "journal"):
            raise ValueError("b655_permit_journal_binding_invalid")
        if _resolved(self.rollback_root) != root / "rollback":
            raise ValueError("b655_permit_rollback_binding_invalid")
        if self.issued_at <= 0 or self.expires_at <= self.issued_at:
            raise ValueError("b655_permit_time_invalid")
        if self.expires_at - self.issued_at > MAX_PERMIT_TTL_SECONDS:
            raise ValueError("b655_permit_ttl_too_long")
        if len(self.nonce) < 16:
            raise ValueError("b655_permit_nonce_too_short")
        if not self.execution_authorized or not self.journal_write_authority or not self.rollback_execution_authority:
            raise ValueError("b655_fixture_authority_missing")
        if self.live_home_execution_authorized or self.automatic_action or self.destructive_authority:
            raise ValueError("b655_broad_or_automatic_authority_forbidden")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.permit_sha256:
            raise ValueError("b655_permit_integrity_mismatch")
        if self.permit_id != PERMIT_PREFIX + self.permit_sha256[:16].upper():
            raise ValueError("b655_permit_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["permit_id"] = self.permit_id
        payload["permit_sha256"] = self.permit_sha256
        return payload


@dataclass(frozen=True)
class FixtureExecutionResult:
    result_id: str
    result_sha256: str
    permit_id: str
    permit_sha256: str
    state: str
    target_locator: str
    target_sha256: str
    quarantine_path: str
    snapshot_path: str
    started_at: float
    finished_at: float
    journal_tail_sha256: str
    pre_state_verified: bool
    post_state_verified: bool
    automatic_action: bool = False
    destructive_authority: bool = False
    schema: str = RESULT_SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "permit_id": self.permit_id,
            "permit_sha256": self.permit_sha256,
            "state": self.state,
            "target_locator": self.target_locator,
            "target_sha256": self.target_sha256,
            "quarantine_path": self.quarantine_path,
            "snapshot_path": self.snapshot_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "journal_tail_sha256": self.journal_tail_sha256,
            "pre_state_verified": self.pre_state_verified,
            "post_state_verified": self.post_state_verified,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != RESULT_SCHEMA or self.state != "QUARANTINED_VERIFIED":
            raise ValueError("b655_result_state_invalid")
        if not self.permit_id.startswith(PERMIT_PREFIX) or not _is_sha256(self.permit_sha256):
            raise ValueError("b655_result_permit_binding_invalid")
        if not _is_sha256(self.target_sha256) or not _is_sha256(self.journal_tail_sha256):
            raise ValueError("b655_result_hash_invalid")
        if not self.pre_state_verified or not self.post_state_verified:
            raise ValueError("b655_result_verification_missing")
        if self.automatic_action or self.destructive_authority:
            raise ValueError("b655_result_forbidden_authority")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.result_sha256:
            raise ValueError("b655_result_integrity_mismatch")
        if self.result_id != RESULT_PREFIX + self.result_sha256[:16].upper():
            raise ValueError("b655_result_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["result_id"] = self.result_id
        payload["result_sha256"] = self.result_sha256
        return payload


@dataclass(frozen=True)
class FixtureRollbackResult:
    rollback_id: str
    rollback_sha256: str
    permit_id: str
    result_id: str
    state: str
    target_locator: str
    target_sha256: str
    quarantine_absent: bool
    snapshot_verified: bool
    journal_rollback_sha256: str
    journal_final_sha256: str
    finished_at: float
    schema: str = ROLLBACK_RESULT_SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "permit_id": self.permit_id,
            "result_id": self.result_id,
            "state": self.state,
            "target_locator": self.target_locator,
            "target_sha256": self.target_sha256,
            "quarantine_absent": self.quarantine_absent,
            "snapshot_verified": self.snapshot_verified,
            "journal_rollback_sha256": self.journal_rollback_sha256,
            "journal_final_sha256": self.journal_final_sha256,
            "finished_at": self.finished_at,
        }

    def validate(self) -> None:
        if self.schema != ROLLBACK_RESULT_SCHEMA or self.state != "RESTORED_VERIFIED":
            raise ValueError("b655_rollback_state_invalid")
        if not self.permit_id.startswith(PERMIT_PREFIX) or not self.result_id.startswith(RESULT_PREFIX):
            raise ValueError("b655_rollback_binding_invalid")
        for value in (self.target_sha256, self.journal_rollback_sha256, self.journal_final_sha256):
            if not _is_sha256(value):
                raise ValueError("b655_rollback_hash_invalid")
        if not self.quarantine_absent or not self.snapshot_verified:
            raise ValueError("b655_rollback_verification_missing")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.rollback_sha256:
            raise ValueError("b655_rollback_integrity_mismatch")
        if self.rollback_id != ROLLBACK_PREFIX + self.rollback_sha256[:16].upper():
            raise ValueError("b655_rollback_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["rollback_id"] = self.rollback_id
        payload["rollback_sha256"] = self.rollback_sha256
        return payload


# ---------------------------------------------------------------------------
# Permit issuance and journal validation
# ---------------------------------------------------------------------------

def _validate_source_provider_binding(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    source_provider_load: source_provider_boundary.ProviderLoadResult,
) -> str:
    if source_provider_load.loaded is not True or source_provider_load.accepted is not True:
        raise ValueError("b655_source_provider_not_accepted")
    digest = _sha256_payload(source_provider_load.to_dict())
    if digest != plan.provider_snapshot_sha256:
        raise ValueError("b655_source_provider_drift_from_plan")
    if digest != receipt.provider_snapshot_sha256:
        raise ValueError("b655_source_provider_drift_from_confirmation")
    return digest


def _validate_post_confirmation_revalidation(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    evidence: confirmation.TargetRevalidation,
    *,
    now: float,
) -> str:
    evidence.validate()
    if _normalized_path(evidence.locator) != _normalized_path(plan.target.locator):
        raise ValueError("b655_target_locator_drift")
    if evidence.observed_sha256.casefold() != str(plan.target.sha256 or "").casefold():
        raise ValueError("b655_target_sha256_drift")
    if evidence.observed_at < receipt.decided_at:
        raise ValueError("b655_revalidation_precedes_confirmation")
    if evidence.observed_at > now + 1.0:
        raise ValueError("b655_revalidation_from_future")
    if now - evidence.observed_at > MAX_POST_CONFIRM_REVALIDATION_AGE_SECONDS:
        raise ValueError("b655_revalidation_too_old")
    return _sha256_payload(evidence.to_dict())


def issue_fixture_execution_permit(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    source_provider_load: source_provider_boundary.ProviderLoadResult,
    fixture_provider: FixtureQuarantineProvider,
    post_confirmation_revalidation: confirmation.TargetRevalidation,
    *,
    now: float,
    ttl_seconds: int = 30,
    nonce: str,
) -> FixtureExecutionPermit:
    """Issue a short-lived permit scoped only to one harmless temp fixture."""

    predecessor = execution_gate.validate_b654_execution_gate_contract()
    if predecessor.get("passed") is not True:
        raise ValueError("b655_b654_predecessor_contract_not_green")

    plan.validate()
    receipt.validate()
    if receipt.plan_id != plan.plan_id or receipt.plan_sha256 != plan.plan_sha256:
        raise ValueError("b655_receipt_plan_binding_mismatch")
    if receipt.requested_action != plan.requested_action or receipt.finding_id != plan.finding_id:
        raise ValueError("b655_receipt_subject_mismatch")
    if not (
        receipt.decision == confirmation.DECISION_CONFIRM
        and receipt.state == confirmation.STATE_CONFIRMED_NOT_EXECUTABLE
        and receipt.confirmed is True
        and receipt.explicit_human_decision is True
    ):
        raise ValueError("b655_explicit_confirmation_required")
    if plan.requested_action != SUPPORTED_ACTION:
        raise ValueError("b655_only_quarantine_fixture_action_supported")

    ttl = int(ttl_seconds)
    if ttl <= 0 or ttl > MAX_PERMIT_TTL_SECONDS:
        raise ValueError("b655_permit_ttl_invalid")
    permit_nonce = str(nonce or "").strip()
    if len(permit_nonce) < 16:
        raise ValueError("b655_permit_nonce_too_short")

    source_provider_hash = _validate_source_provider_binding(plan, receipt, source_provider_load)
    revalidation_hash = _validate_post_confirmation_revalidation(
        plan,
        receipt,
        post_confirmation_revalidation,
        now=float(now),
    )

    capabilities = fixture_provider.capabilities()
    if capabilities.get("accepted") is not True or capabilities.get("available") is not True:
        raise ValueError("b655_execution_provider_not_accepted")
    if capabilities.get("execution_available") is not True or capabilities.get("fixture_only") is not True:
        raise ValueError("b655_execution_provider_scope_invalid")
    if capabilities.get("authority_scope") != AUTHORITY_SCOPE:
        raise ValueError("b655_execution_provider_authority_scope_invalid")
    if capabilities.get("automatic_action") is not False or capabilities.get("destructive_authority") is not False:
        raise ValueError("b655_execution_provider_broad_authority_forbidden")
    actions = capabilities.get("actions")
    matches = [item for item in actions or [] if isinstance(item, dict) and item.get("action_id") == SUPPORTED_ACTION]
    if len(matches) != 1 or matches[0].get("available") is not True or matches[0].get("reversible") is not True:
        raise ValueError("b655_quarantine_action_not_available_and_reversible")

    target = fixture_provider._validate_target(plan.target.locator, str(plan.target.sha256 or ""))
    if _normalized_path(target) != _normalized_path(post_confirmation_revalidation.locator):
        raise ValueError("b655_revalidated_target_path_mismatch")

    provider_hash = fixture_provider.snapshot_sha256()
    issued = float(now)
    draft = FixtureExecutionPermit(
        permit_id="",
        permit_sha256="",
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        receipt_id=receipt.receipt_id,
        receipt_sha256=receipt.receipt_sha256,
        requested_action=plan.requested_action,
        finding_id=plan.finding_id,
        target_locator=str(target),
        target_sha256=str(plan.target.sha256).casefold(),
        target_fingerprint=plan.target.fingerprint.casefold(),
        source_provider_snapshot_sha256=source_provider_hash,
        execution_provider_snapshot_sha256=provider_hash,
        post_confirmation_revalidation_sha256=revalidation_hash,
        fixture_root=str(fixture_provider.fixture_root),
        journal_path=str(fixture_provider.journal_path),
        rollback_root=str(fixture_provider.rollback_root),
        issued_at=issued,
        expires_at=issued + ttl,
        nonce=permit_nonce,
    )
    digest = _sha256_payload(draft.canonical_without_hash())
    permit = FixtureExecutionPermit(
        **{
            **draft.__dict__,
            "permit_id": PERMIT_PREFIX + digest[:16].upper(),
            "permit_sha256": digest,
        }
    )
    permit.validate()
    return permit


def _validate_permit_for_provider(
    permit: FixtureExecutionPermit,
    provider: FixtureQuarantineProvider,
    *,
    now: float,
    allow_expired_after_execution: bool = False,
) -> None:
    permit.validate()
    if permit.execution_provider_snapshot_sha256 != provider.snapshot_sha256():
        raise ValueError("b655_execution_provider_snapshot_drift")
    if _resolved(permit.fixture_root) != provider.fixture_root:
        raise ValueError("b655_fixture_root_binding_drift")
    if _resolved(permit.journal_path) != provider.journal_path:
        raise ValueError("b655_journal_binding_drift")
    if _resolved(permit.rollback_root) != provider.rollback_root:
        raise ValueError("b655_rollback_binding_drift")
    if float(now) < permit.issued_at - 1.0:
        raise ValueError("b655_permit_used_before_issue")
    if not allow_expired_after_execution and float(now) > permit.expires_at:
        raise ValueError("b655_permit_expired")


def validate_fixture_journal(provider: FixtureQuarantineProvider) -> dict:
    entries = provider._read_journal()
    failures: list[str] = []
    previous = ZERO_HASH
    expected_sequence = 1
    for entry in entries:
        if entry.get("schema") != JOURNAL_SCHEMA:
            failures.append(f"schema:{expected_sequence}")
        if entry.get("sequence") != expected_sequence:
            failures.append(f"sequence:{expected_sequence}")
        if entry.get("previous_entry_sha256") != previous:
            failures.append(f"previous_hash:{expected_sequence}")
        claimed = str(entry.get("entry_sha256") or "")
        body = dict(entry)
        body.pop("entry_sha256", None)
        actual = _sha256_payload(body)
        if claimed != actual:
            failures.append(f"entry_hash:{expected_sequence}")
        previous = claimed if _is_sha256(claimed) else previous
        expected_sequence += 1

    return {
        "schema": JOURNAL_SCHEMA,
        "passed": not failures,
        "failures": failures,
        "entry_count": len(entries),
        "tail_sha256": previous if entries else ZERO_HASH,
        "events": [str(item.get("event") or "") for item in entries],
        "entries": entries,
    }


def validate_b655_fixture_execution_contract() -> dict:
    predecessor = execution_gate.validate_b654_execution_gate_contract()
    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": predecessor.get("passed") is True,
        "b654_predecessor_required": True,
        "b654_predecessor_green": predecessor.get("passed") is True,
        "execution_provider_loaded_by_home": False,
        "live_home_execution_authorized": False,
        "authority_scope": AUTHORITY_SCOPE,
        "fixture_root_must_be_under_system_temp": True,
        "fixture_marker_required": True,
        "supported_mutating_actions": [SUPPORTED_ACTION],
        "quarantine_is_reversible": True,
        "explicit_confirmation_required": True,
        "fresh_post_confirmation_sha256_required": True,
        "one_shot_short_lived_permit_required": True,
        "hash_chained_journal_required": True,
        "verified_rollback_snapshot_required": True,
        "fixture_journal_write_authority": True,
        "fixture_rollback_execution_authority": True,
        "automatic_action": False,
        "destructive_authority": False,
        "real_user_or_system_file_scope": False,
        "next_execution_owner": "B6-5.6+",
    }
