from __future__ import annotations

"""B6-5.6 explicit real-file quarantine boundary.

This milestone extends the reversible B6-5.5 mechanics to exactly one existing,
non-privileged user file.  It remains deliberately narrow: Desktop, Documents
or Downloads under the current user profile only; explicit SHA-256 binding;
explicit B6-5.3 confirmation; fresh post-confirmation revalidation; one-shot
permit; append-only hash-chained journal; verified rollback snapshot; and no
Home auto-execution.

System/privileged paths, AppData, ProgramData, Windows, Program Files, BC
Sentinel source/runtime paths, symlinks/reparse escapes and oversized files are
refused fail-closed.  Only QUARANTINE is supported.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Final, Iterable

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_execution_gate as execution_gate
from sentinel import guided_resolution_provider_loader as source_provider_boundary

PROFILE: Final[str] = "v0.11.0-beta.6-b65.6-real-file-quarantine"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-execution-v1"
PROVIDER_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-provider-v1"
PERMIT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-permit-v1"
RESULT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-result-v1"
ROLLBACK_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-rollback-v1"
JOURNAL_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-real-file-journal-v1"

PROVIDER_NAME: Final[str] = "BC Sentinel B6-5.6 real-file quarantine provider"
PROVIDER_PROVENANCE: Final[str] = "builtin:b656_real_file_quarantine_v1"
SUPPORTED_ACTION: Final[str] = "QUARANTINE"
AUTHORITY_SCOPE: Final[str] = "EXPLICIT_NON_PRIVILEGED_USER_FILE_ONLY"
MAX_TARGET_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PERMIT_TTL_SECONDS: Final[int] = 60
MAX_REVALIDATION_AGE_SECONDS: Final[int] = 30
ZERO_HASH: Final[str] = "0" * 64
PERMIT_PREFIX: Final[str] = "B656-PERMIT-"
RESULT_PREFIX: Final[str] = "B656-RESULT-"
ROLLBACK_PREFIX: Final[str] = "B656-ROLLBACK-"


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _norm(path: str | Path) -> str:
    return os.path.normcase(str(_resolved(path)))


def _profile_root(user_profile: str | Path | None = None) -> Path:
    return _resolved(user_profile or os.environ.get("USERPROFILE") or Path.home())


def allowed_user_roots(user_profile: str | Path | None = None) -> tuple[Path, ...]:
    profile = _profile_root(user_profile)
    return tuple(_resolved(profile / name) for name in ("Desktop", "Documents", "Downloads"))


def _environment_protected_roots() -> tuple[Path, ...]:
    values: list[str | Path] = []
    for key in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(key)
        if value:
            values.append(value)
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        values.append(local_app)
    # Current repository/source is always self-managed and not a target.
    values.append(Path(__file__).resolve().parents[1])
    runtime_root = os.environ.get("BC_SENTINEL_FULL_RUNTIME_ROOT")
    if runtime_root:
        values.append(runtime_root)
    return tuple(_resolved(v) for v in values)


def _path_has_symlink_component(path: Path, stop_root: Path) -> bool:
    current = path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        if current == stop_root or current.parent == current:
            return False
        current = current.parent


def assess_target_eligibility(
    target: str | Path,
    *,
    user_profile: str | Path | None = None,
    extra_protected_roots: Iterable[str | Path] = (),
) -> dict:
    """Return a fail-closed eligibility decision without modifying the target."""

    profile = _profile_root(user_profile)
    raw = Path(target).expanduser()
    reasons: list[str] = []
    try:
        resolved = raw.resolve(strict=True)
    except OSError:
        resolved = raw.resolve(strict=False)
        reasons.append("target_missing_or_unresolvable")

    roots = allowed_user_roots(profile)
    if not any(_is_within(resolved, root) for root in roots):
        reasons.append("outside_allowed_user_roots")
    if _is_within(resolved, profile / "AppData"):
        reasons.append("appdata_forbidden")

    protected = list(_environment_protected_roots()) + [_resolved(p) for p in extra_protected_roots]
    if any(_is_within(resolved, root) for root in protected):
        reasons.append("protected_or_self_managed_path")

    try:
        if raw.is_symlink() or resolved.is_symlink():
            reasons.append("symlink_refused")
        if _path_has_symlink_component(raw.absolute(), profile):
            reasons.append("symlink_component_refused")
        if not resolved.is_file():
            reasons.append("regular_file_required")
        elif resolved.stat().st_size > MAX_TARGET_BYTES:
            reasons.append("target_too_large")
    except OSError:
        reasons.append("target_metadata_unavailable")

    return {
        "eligible": not reasons,
        "target": str(resolved),
        "allowed_roots": [str(r) for r in roots],
        "max_target_bytes": MAX_TARGET_BYTES,
        "reasons": sorted(set(reasons)),
    }


def _local_appdata_root() -> Path:
    value = os.environ.get("LOCALAPPDATA")
    if value:
        return _resolved(value)
    return _resolved(_profile_root() / "AppData" / "Local")


def default_storage_root() -> Path:
    return _local_appdata_root() / "BCSentinel" / "B656"


def _validate_storage_root(root: Path) -> None:
    expected = default_storage_root()
    if root != expected:
        raise ValueError("b656_storage_root_must_equal_dedicated_localappdata_root")


@dataclass(frozen=True)
class RealFileExecutionPermit:
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
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "authority_scope": AUTHORITY_SCOPE,
            "execution_authorized": True,
            "live_home_execution_authorized": False,
            "journal_write_authority": True,
            "rollback_execution_authority": True,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != PERMIT_SCHEMA or self.authority_scope != AUTHORITY_SCOPE:
            raise ValueError("b656_permit_contract_invalid")
        if self.requested_action != SUPPORTED_ACTION:
            raise ValueError("b656_only_quarantine_supported")
        if not self.plan_id.startswith(planning.PLAN_PREFIX) or not _is_sha256(self.plan_sha256):
            raise ValueError("b656_plan_binding_invalid")
        if not self.receipt_id.startswith(confirmation.RECEIPT_PREFIX) or not _is_sha256(self.receipt_sha256):
            raise ValueError("b656_receipt_binding_invalid")
        for value in (self.target_sha256, self.target_fingerprint, self.source_provider_snapshot_sha256, self.execution_provider_snapshot_sha256, self.post_confirmation_revalidation_sha256):
            if not _is_sha256(value):
                raise ValueError("b656_hash_binding_invalid")
        if self.issued_at <= 0 or self.expires_at <= self.issued_at or self.expires_at - self.issued_at > MAX_PERMIT_TTL_SECONDS:
            raise ValueError("b656_permit_time_invalid")
        if len(self.nonce) < 16:
            raise ValueError("b656_nonce_too_short")
        if not self.execution_authorized or not self.journal_write_authority or not self.rollback_execution_authority:
            raise ValueError("b656_required_authority_missing")
        if self.live_home_execution_authorized or self.automatic_action or self.destructive_authority:
            raise ValueError("b656_broad_authority_forbidden")
        expected = _sha256_payload(self.canonical_without_hash())
        if expected != self.permit_sha256 or self.permit_id != PERMIT_PREFIX + expected[:16].upper():
            raise ValueError("b656_permit_integrity_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        return {**self.canonical_without_hash(), "permit_id": self.permit_id, "permit_sha256": self.permit_sha256}


@dataclass(frozen=True)
class RealFileExecutionResult:
    result_id: str
    result_sha256: str
    permit_id: str
    state: str
    target_locator: str
    target_sha256: str
    quarantine_path: str
    snapshot_path: str
    journal_tail_sha256: str
    pre_state_verified: bool
    post_state_verified: bool
    finished_at: float

    def canonical_without_hash(self) -> dict:
        return {"schema": RESULT_SCHEMA, "profile": PROFILE, "permit_id": self.permit_id, "state": self.state, "target_locator": self.target_locator, "target_sha256": self.target_sha256, "quarantine_path": self.quarantine_path, "snapshot_path": self.snapshot_path, "journal_tail_sha256": self.journal_tail_sha256, "pre_state_verified": self.pre_state_verified, "post_state_verified": self.post_state_verified, "finished_at": self.finished_at}

    def validate(self) -> None:
        if self.state != "QUARANTINED_VERIFIED" or not self.pre_state_verified or not self.post_state_verified:
            raise ValueError("b656_result_verification_invalid")
        expected = _sha256_payload(self.canonical_without_hash())
        if expected != self.result_sha256 or self.result_id != RESULT_PREFIX + expected[:16].upper():
            raise ValueError("b656_result_integrity_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        return {**self.canonical_without_hash(), "result_id": self.result_id, "result_sha256": self.result_sha256}


@dataclass(frozen=True)
class RealFileRollbackResult:
    rollback_id: str
    rollback_sha256: str
    permit_id: str
    result_id: str
    state: str
    target_locator: str
    target_sha256: str
    quarantine_absent: bool
    snapshot_verified: bool
    journal_final_sha256: str
    finished_at: float

    def canonical_without_hash(self) -> dict:
        return {"schema": ROLLBACK_SCHEMA, "profile": PROFILE, "permit_id": self.permit_id, "result_id": self.result_id, "state": self.state, "target_locator": self.target_locator, "target_sha256": self.target_sha256, "quarantine_absent": self.quarantine_absent, "snapshot_verified": self.snapshot_verified, "journal_final_sha256": self.journal_final_sha256, "finished_at": self.finished_at}

    def validate(self) -> None:
        if self.state != "RESTORED_VERIFIED" or not self.quarantine_absent or not self.snapshot_verified:
            raise ValueError("b656_rollback_verification_invalid")
        expected = _sha256_payload(self.canonical_without_hash())
        if expected != self.rollback_sha256 or self.rollback_id != ROLLBACK_PREFIX + expected[:16].upper():
            raise ValueError("b656_rollback_integrity_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        return {**self.canonical_without_hash(), "rollback_id": self.rollback_id, "rollback_sha256": self.rollback_sha256}


class RealFileQuarantineProvider:
    name = PROVIDER_NAME
    profile = PROFILE
    provenance = PROVIDER_PROVENANCE

    def __init__(self, *, user_profile: str | Path | None = None, storage_root: str | Path | None = None, extra_protected_roots: Iterable[str | Path] = ()) -> None:
        self.user_profile = _profile_root(user_profile)
        self.storage_root = _resolved(storage_root or default_storage_root())
        _validate_storage_root(self.storage_root)
        self.extra_protected_roots = tuple(_resolved(p) for p in extra_protected_roots)
        self.quarantine_root = self.storage_root / "quarantine"
        self.rollback_root = self.storage_root / "rollback"
        self.journal_path = self.storage_root / "journal" / "events.jsonl"
        for d in (self.quarantine_root, self.rollback_root, self.journal_path.parent):
            d.mkdir(parents=True, exist_ok=True)

    def capabilities(self) -> dict:
        return {"schema": PROVIDER_SCHEMA, "accepted": True, "available": True, "execution_available": True, "authority_scope": AUTHORITY_SCOPE, "automatic_action": False, "destructive_authority": False, "live_home_execution_authorized": False, "allowed_roots": [str(r) for r in allowed_user_roots(self.user_profile)], "max_target_bytes": MAX_TARGET_BYTES, "actions": [{"action_id": SUPPORTED_ACTION, "available": True, "mutates_system": True, "reversible": True}]}

    def snapshot_sha256(self) -> str:
        return _sha256_payload(self.capabilities())

    def _read_journal(self) -> list[dict]:
        if not self.journal_path.exists():
            return []
        items = []
        with self.journal_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError("b656_journal_entry_invalid")
                    items.append(item)
        return items

    def _append_journal(self, permit: RealFileExecutionPermit, event: str, *, now: float, payload: dict) -> dict:
        entries = self._read_journal()
        previous = str(entries[-1].get("entry_sha256") or ZERO_HASH) if entries else ZERO_HASH
        body = {"schema": JOURNAL_SCHEMA, "profile": PROFILE, "sequence": len(entries) + 1, "permit_id": permit.permit_id, "permit_sha256": permit.permit_sha256, "event": event, "timestamp": float(now), "target_locator": permit.target_locator, "target_sha256": permit.target_sha256, "previous_entry_sha256": previous, "payload": dict(payload)}
        digest = _sha256_payload(body)
        entry = {**body, "entry_sha256": digest}
        with self.journal_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            handle.flush(); os.fsync(handle.fileno())
        return entry

    def _validate_target(self, path: str | Path, expected_sha256: str) -> Path:
        decision = assess_target_eligibility(path, user_profile=self.user_profile, extra_protected_roots=self.extra_protected_roots)
        if decision["eligible"] is not True:
            raise ValueError("b656_target_ineligible:" + ",".join(decision["reasons"]))
        target = _resolved(decision["target"])
        if not _is_sha256(expected_sha256) or _sha256_file(target) != expected_sha256.casefold():
            raise ValueError("b656_target_sha256_drift")
        return target

    def execute_quarantine(self, permit: RealFileExecutionPermit, *, now: float) -> RealFileExecutionResult:
        permit.validate()
        if now > permit.expires_at:
            raise ValueError("b656_permit_expired")
        if permit.execution_provider_snapshot_sha256 != self.snapshot_sha256():
            raise ValueError("b656_execution_provider_drift")
        if any(e.get("permit_id") == permit.permit_id and e.get("event") == "PERMIT_CONSUMED" for e in self._read_journal()):
            raise ValueError("b656_permit_replay_refused")
        target = self._validate_target(permit.target_locator, permit.target_sha256)
        token = permit.permit_id.casefold()
        snapshot = self.rollback_root / f"{token}.snapshot"
        quarantined = self.quarantine_root / f"{token}-{target.name}"
        if snapshot.exists() or quarantined.exists():
            raise ValueError("b656_execution_artifact_collision")
        shutil.copy2(target, snapshot)
        if _sha256_file(snapshot) != permit.target_sha256:
            raise ValueError("b656_snapshot_verification_failed")
        self._append_journal(permit, "PRE_STATE_RECORDED", now=now, payload={"snapshot_path": str(snapshot)})
        self._append_journal(permit, "PERMIT_CONSUMED", now=now, payload={"one_shot": True})
        os.replace(target, quarantined)
        if target.exists() or not quarantined.is_file() or _sha256_file(quarantined) != permit.target_sha256:
            raise ValueError("b656_quarantine_verification_failed")
        entry = self._append_journal(permit, "ACTION_RESULT", now=now, payload={"state": "QUARANTINED_VERIFIED", "quarantine_path": str(quarantined)})
        draft = RealFileExecutionResult("", "", permit.permit_id, "QUARANTINED_VERIFIED", str(target), permit.target_sha256, str(quarantined), str(snapshot), str(entry["entry_sha256"]), True, True, float(now))
        digest = _sha256_payload(draft.canonical_without_hash())
        result = RealFileExecutionResult(RESULT_PREFIX + digest[:16].upper(), digest, permit.permit_id, draft.state, draft.target_locator, draft.target_sha256, draft.quarantine_path, draft.snapshot_path, draft.journal_tail_sha256, True, True, draft.finished_at)
        result.validate(); return result

    def rollback_quarantine(self, permit: RealFileExecutionPermit, result: RealFileExecutionResult, *, now: float) -> RealFileRollbackResult:
        permit.validate(); result.validate()
        target = _resolved(result.target_locator); quarantined = _resolved(result.quarantine_path); snapshot = _resolved(result.snapshot_path)
        if target.exists():
            raise ValueError("b656_rollback_refuses_existing_target")
        if not _is_within(quarantined, self.quarantine_root) or not _is_within(snapshot, self.rollback_root):
            raise ValueError("b656_rollback_artifact_path_invalid")
        if _sha256_file(quarantined) != permit.target_sha256 or _sha256_file(snapshot) != permit.target_sha256:
            raise ValueError("b656_rollback_artifact_hash_mismatch")
        self._append_journal(permit, "ROLLBACK_STARTED", now=now, payload={})
        os.replace(quarantined, target)
        if _sha256_file(target) != permit.target_sha256:
            raise ValueError("b656_rollback_verification_failed")
        self._append_journal(permit, "ROLLBACK_RESULT", now=now, payload={"state": "RESTORED_VERIFIED"})
        final = self._append_journal(permit, "FINAL_OUTCOME", now=now, payload={"state": "RECOVERED"})
        draft = RealFileRollbackResult("", "", permit.permit_id, result.result_id, "RESTORED_VERIFIED", str(target), permit.target_sha256, not quarantined.exists(), _sha256_file(snapshot) == permit.target_sha256, str(final["entry_sha256"]), float(now))
        digest = _sha256_payload(draft.canonical_without_hash())
        rollback = RealFileRollbackResult(ROLLBACK_PREFIX + digest[:16].upper(), digest, draft.permit_id, draft.result_id, draft.state, draft.target_locator, draft.target_sha256, draft.quarantine_absent, draft.snapshot_verified, draft.journal_final_sha256, draft.finished_at)
        rollback.validate(); return rollback


def issue_real_file_execution_permit(plan: planning.ResolutionActionPlan, receipt: confirmation.ConfirmationReceipt, source_provider_load: source_provider_boundary.ProviderLoadResult, execution_provider: RealFileQuarantineProvider, post_confirmation_revalidation: confirmation.TargetRevalidation, *, now: float, ttl_seconds: int = 30, nonce: str) -> RealFileExecutionPermit:
    if execution_gate.validate_b654_execution_gate_contract().get("passed") is not True:
        raise ValueError("b656_b654_predecessor_not_green")
    plan.validate(); receipt.validate(); post_confirmation_revalidation.validate()
    if receipt.plan_id != plan.plan_id or receipt.plan_sha256 != plan.plan_sha256 or receipt.decision != confirmation.DECISION_CONFIRM or receipt.confirmed is not True:
        raise ValueError("b656_explicit_confirmation_required")
    if plan.requested_action != SUPPORTED_ACTION or receipt.requested_action != SUPPORTED_ACTION:
        raise ValueError("b656_action_binding_invalid")
    source_hash = _sha256_payload(source_provider_load.to_dict())
    if not source_provider_load.loaded or not source_provider_load.accepted or source_hash != plan.provider_snapshot_sha256 or source_hash != receipt.provider_snapshot_sha256:
        raise ValueError("b656_source_provider_drift")
    target = execution_provider._validate_target(plan.target.locator, str(plan.target.sha256 or ""))
    if _norm(post_confirmation_revalidation.locator) != _norm(target) or post_confirmation_revalidation.observed_sha256.casefold() != str(plan.target.sha256 or "").casefold():
        raise ValueError("b656_post_confirmation_target_drift")
    if post_confirmation_revalidation.observed_at < receipt.decided_at or now - post_confirmation_revalidation.observed_at > MAX_REVALIDATION_AGE_SECONDS:
        raise ValueError("b656_post_confirmation_revalidation_stale")
    ttl = int(ttl_seconds)
    if ttl <= 0 or ttl > MAX_PERMIT_TTL_SECONDS or len(str(nonce or "")) < 16:
        raise ValueError("b656_permit_parameters_invalid")
    execution_hash = execution_provider.snapshot_sha256()
    revalidation_hash = _sha256_payload(post_confirmation_revalidation.to_dict())
    draft = RealFileExecutionPermit("", "", plan.plan_id, plan.plan_sha256, receipt.receipt_id, receipt.receipt_sha256, SUPPORTED_ACTION, plan.finding_id, str(target), str(plan.target.sha256), plan.target.fingerprint, source_hash, execution_hash, revalidation_hash, float(now), float(now + ttl), str(nonce))
    digest = _sha256_payload(draft.canonical_without_hash())
    permit = RealFileExecutionPermit(PERMIT_PREFIX + digest[:16].upper(), digest, draft.plan_id, draft.plan_sha256, draft.receipt_id, draft.receipt_sha256, draft.requested_action, draft.finding_id, draft.target_locator, draft.target_sha256, draft.target_fingerprint, draft.source_provider_snapshot_sha256, draft.execution_provider_snapshot_sha256, draft.post_confirmation_revalidation_sha256, draft.issued_at, draft.expires_at, draft.nonce)
    permit.validate(); return permit


def validate_journal(provider: RealFileQuarantineProvider) -> dict:
    entries = provider._read_journal(); failures: list[str] = []; previous = ZERO_HASH
    for index, entry in enumerate(entries, start=1):
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        if entry.get("sequence") != index: failures.append("sequence_mismatch")
        if entry.get("previous_entry_sha256") != previous: failures.append("chain_mismatch")
        digest = _sha256_payload(body)
        if digest != entry.get("entry_sha256"): failures.append("entry_hash_mismatch")
        previous = str(entry.get("entry_sha256") or "")
    return {"passed": not failures and bool(entries), "failures": sorted(set(failures)), "events": [e.get("event") for e in entries], "entry_count": len(entries), "tail_sha256": previous}


def validate_b656_contract() -> dict:
    predecessor = execution_gate.validate_b654_execution_gate_contract()
    return {"schema": SCHEMA, "profile": PROFILE, "passed": predecessor.get("passed") is True, "b654_predecessor_green": predecessor.get("passed") is True, "supported_mutating_actions": [SUPPORTED_ACTION], "authority_scope": AUTHORITY_SCOPE, "explicit_confirmation_required": True, "fresh_post_confirmation_sha256_required": True, "one_shot_short_lived_permit_required": True, "hash_chained_journal_required": True, "verified_rollback_snapshot_required": True, "allowed_user_roots_only": True, "system_and_privileged_paths_forbidden": True, "self_managed_paths_forbidden": True, "symlink_escape_refused": True, "max_target_bytes": MAX_TARGET_BYTES, "live_home_execution_authorized": False, "automatic_action": False, "destructive_authority": False, "delete_authorized": False, "repair_authorized": False, "terminate_process_authorized": False, "trust_allowlist_mutation_authorized": False, "next_execution_owner": "B6-5.7+"}
