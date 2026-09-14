from __future__ import annotations

"""B6-5.8 restart-safe Home quarantine integration.

B6-5.8 keeps the B6-5.7 Home quarantine boundary deliberately narrow while
adding restart-safe restore metadata. A confirmed quarantine is now preceded by
an atomic recovery record containing the exact B6-5.6 execution permit. After
the quarantine succeeds, the record is finalized with the verified execution
result. On a later application start the controller can reconstruct a verified
restore command from disk without retaining Python objects from the original
session.

Startup discovery is read-only. The mutating B6-5.6 provider is still created
only after an explicit quarantine confirmation or an explicit restore click.
DELETE, REPAIR, process control, trust mutation and automatic remediation remain
unavailable.
"""

from dataclasses import dataclass, fields
from datetime import datetime
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Final

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_provider_loader as boundary
from sentinel import guided_resolution_real_file_execution as real_file
from sentinel import home_guided_resolution as guided
from sentinel import home_threat_cards as threat

B657_PROFILE: Final[str] = "v0.11.0-beta.6-b65.7-home-quarantine"
B657_SCHEMA: Final[str] = "bc-sentinel-beta6-home-quarantine-v1"
PROFILE: Final[str] = "v0.11.0-beta.6-b65.8-persistent-restore"
SCHEMA: Final[str] = "bc-sentinel-beta6-home-quarantine-v2"
RECOVERY_SCHEMA: Final[str] = "bc-sentinel-beta6-home-quarantine-recovery-v1"
RECOVERY_DIRNAME: Final[str] = "home-restore"
RECOVERY_PREPARED: Final[str] = "PREPARED"
RECOVERY_ACTIVE: Final[str] = "QUARANTINED_VERIFIED"
RECOVERY_RESTORED: Final[str] = "RESTORED_VERIFIED"
ELIGIBLE_SEVERITIES: Final[frozenset[str]] = frozenset({"HIGH", "CRITICAL"})


@dataclass(frozen=True)
class HomeQuarantineAvailability:
    ready: bool
    state: str
    reason: str
    target_locator: str = ""
    target_sha256: str = ""


@dataclass(frozen=True)
class HomeQuarantineSession:
    card: threat.ThreatCardModel
    resolution: guided.GuidedResolutionModel
    plan: planning.ResolutionActionPlan
    request: confirmation.ConfirmationRequest
    initial_revalidation: confirmation.TargetRevalidation


@dataclass
class _ActiveQuarantine:
    provider: real_file.RealFileQuarantineProvider
    permit: real_file.RealFileExecutionPermit
    result: real_file.RealFileExecutionResult


@dataclass(frozen=True)
class _PersistentQuarantine:
    finding_id: str
    permit: real_file.RealFileExecutionPermit
    result: real_file.RealFileExecutionResult
    severity: str
    reason: str
    title: str
    record_path: Path


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _plain_reason(code: str) -> str:
    mapping = {
        "severity_not_eligible": "Per questa fase la quarantena Home è disponibile solo per rilevamenti HIGH o CRITICAL.",
        "target_identity_not_verified": "Il rilevamento non contiene un unico SHA-256 verificabile.",
        "outside_allowed_user_roots": "Il file non si trova in Desktop, Documenti o Download.",
        "appdata_forbidden": "I file in AppData non sono autorizzati in questa fase.",
        "protected_or_self_managed_path": "Il percorso è protetto o appartiene a BC Sentinel.",
        "symlink_refused": "Il file è un collegamento simbolico e viene rifiutato.",
        "symlink_component_refused": "Il percorso contiene un collegamento simbolico e viene rifiutato.",
        "target_too_large": "Il file supera il limite di 64 MiB previsto da B6-5.8.",
        "target_missing_or_unresolvable": "Il file non è più disponibile o non è risolvibile.",
        "regular_file_required": "Il target non è un file regolare.",
        "target_metadata_unavailable": "I metadati del file non sono leggibili.",
        "target_sha256_drift": "Il file è cambiato rispetto all'hash rilevato dalla scansione.",
    }
    return mapping.get(code, "Il file non soddisfa i requisiti di sicurezza per la quarantena Home.")


def _recovery_root() -> Path:
    return real_file.default_storage_root() / RECOVERY_DIRNAME


def _record_name(finding_id: str) -> str:
    digest = hashlib.sha256(str(finding_id).encode("utf-8")).hexdigest()
    return f"{digest}.json"


def _record_path(finding_id: str) -> Path:
    return _recovery_root() / _record_name(finding_id)


def _permit_from_dict(payload: dict) -> real_file.RealFileExecutionPermit:
    if not isinstance(payload, dict):
        raise ValueError("b658_recovery_permit_invalid")
    names = {item.name for item in fields(real_file.RealFileExecutionPermit)}
    values = {name: payload[name] for name in names if name in payload}
    permit = real_file.RealFileExecutionPermit(**values)
    permit.validate()
    return permit


def _result_from_dict(payload: dict) -> real_file.RealFileExecutionResult:
    if not isinstance(payload, dict):
        raise ValueError("b658_recovery_result_invalid")
    names = {item.name for item in fields(real_file.RealFileExecutionResult)}
    values = {name: payload[name] for name in names if name in payload}
    result = real_file.RealFileExecutionResult(**values)
    result.validate()
    return result


def _recovery_body(
    *,
    finding_id: str,
    permit: real_file.RealFileExecutionPermit,
    result: real_file.RealFileExecutionResult | None,
    state: str,
    severity: str,
    reason: str,
    title: str,
    updated_at: float,
    rollback: real_file.RealFileRollbackResult | None = None,
) -> dict:
    permit.validate()
    if result is not None:
        result.validate()
    if rollback is not None:
        rollback.validate()
    return {
        "schema": RECOVERY_SCHEMA,
        "profile": PROFILE,
        "finding_id": str(finding_id),
        "state": str(state),
        "permit": permit.to_dict(),
        "result": result.to_dict() if result is not None else None,
        "display": {
            "severity": str(severity),
            "reason": str(reason),
            "title": str(title),
        },
        "rollback": rollback.to_dict() if rollback is not None else None,
        "updated_at": float(updated_at),
    }


def _write_recovery_record(body: dict) -> Path:
    finding_id = str(body.get("finding_id") or "")
    if not finding_id:
        raise ValueError("b658_recovery_finding_id_missing")
    root = _recovery_root()
    root.mkdir(parents=True, exist_ok=True)
    path = _record_path(finding_id)
    payload = dict(body)
    payload["record_sha256"] = _sha256_payload(body)
    tmp = root / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    return path


def _read_record(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("b658_recovery_record_unreadable") from exc
    if not isinstance(payload, dict):
        raise ValueError("b658_recovery_record_invalid")
    expected = str(payload.get("record_sha256") or "")
    body = {key: value for key, value in payload.items() if key != "record_sha256"}
    if payload.get("schema") != RECOVERY_SCHEMA or _sha256_payload(body) != expected:
        raise ValueError("b658_recovery_record_integrity_mismatch")
    finding_id = str(payload.get("finding_id") or "")
    if not finding_id or path.name != _record_name(finding_id):
        raise ValueError("b658_recovery_record_identity_mismatch")
    return payload


def _read_journal_readonly() -> list[dict]:
    path = real_file.default_storage_root() / "journal" / "events.jsonl"
    if not path.is_file():
        return []
    entries: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("b658_journal_entry_invalid")
                entries.append(item)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("b658_journal_unreadable") from exc
    previous = real_file.ZERO_HASH
    for index, entry in enumerate(entries, start=1):
        body = {key: value for key, value in entry.items() if key != "entry_sha256"}
        digest = _sha256_payload(body)
        if (
            entry.get("sequence") != index
            or entry.get("previous_entry_sha256") != previous
            or entry.get("entry_sha256") != digest
        ):
            raise ValueError("b658_journal_integrity_mismatch")
        previous = str(entry.get("entry_sha256") or "")
    return entries


def _journal_result_for_permit(
    permit: real_file.RealFileExecutionPermit,
    entries: list[dict],
) -> real_file.RealFileExecutionResult | None:
    snapshot_path = ""
    action_entry: dict | None = None
    terminal_after_action = False
    for entry in entries:
        if str(entry.get("permit_id") or "") != permit.permit_id:
            continue
        if str(entry.get("permit_sha256") or "") != permit.permit_sha256:
            raise ValueError("b658_journal_permit_binding_mismatch")
        event = str(entry.get("event") or "")
        payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
        if event == "PRE_STATE_RECORDED":
            snapshot_path = str(payload.get("snapshot_path") or "")
        elif event == "ACTION_RESULT" and payload.get("state") == RECOVERY_ACTIVE:
            action_entry = entry
            terminal_after_action = False
        elif action_entry is not None and event in {"ROLLBACK_RESULT", "FINAL_OUTCOME"}:
            terminal_after_action = True

    if action_entry is None or terminal_after_action or not snapshot_path:
        return None
    payload = action_entry.get("payload") if isinstance(action_entry.get("payload"), dict) else {}
    quarantine_path = str(payload.get("quarantine_path") or "")
    if not quarantine_path:
        return None

    draft = real_file.RealFileExecutionResult(
        "",
        "",
        permit.permit_id,
        RECOVERY_ACTIVE,
        permit.target_locator,
        permit.target_sha256,
        quarantine_path,
        snapshot_path,
        str(action_entry.get("entry_sha256") or ""),
        True,
        True,
        float(action_entry.get("timestamp") or 0.0),
    )
    digest = _sha256_payload(draft.canonical_without_hash())
    result = real_file.RealFileExecutionResult(
        real_file.RESULT_PREFIX + digest[:16].upper(),
        digest,
        draft.permit_id,
        draft.state,
        draft.target_locator,
        draft.target_sha256,
        draft.quarantine_path,
        draft.snapshot_path,
        draft.journal_tail_sha256,
        True,
        True,
        draft.finished_at,
    )
    result.validate()
    return result


def _validate_active_artifacts(
    permit: real_file.RealFileExecutionPermit,
    result: real_file.RealFileExecutionResult,
    entries: list[dict],
) -> None:
    permit.validate()
    result.validate()
    if (
        result.permit_id != permit.permit_id
        or result.target_locator != permit.target_locator
        or result.target_sha256.casefold() != permit.target_sha256.casefold()
    ):
        raise ValueError("b658_recovery_result_binding_mismatch")

    anchor = next(
        (
            entry
            for entry in entries
            if entry.get("entry_sha256") == result.journal_tail_sha256
        ),
        None,
    )
    if anchor is None:
        raise ValueError("b658_recovery_journal_anchor_missing")
    payload = anchor.get("payload") if isinstance(anchor.get("payload"), dict) else {}
    if (
        anchor.get("event") != "ACTION_RESULT"
        or str(anchor.get("permit_id") or "") != permit.permit_id
        or str(anchor.get("permit_sha256") or "") != permit.permit_sha256
        or str(anchor.get("target_locator") or "") != permit.target_locator
        or str(anchor.get("target_sha256") or "").casefold() != permit.target_sha256.casefold()
        or payload.get("state") != RECOVERY_ACTIVE
        or str(payload.get("quarantine_path") or "") != result.quarantine_path
    ):
        raise ValueError("b658_recovery_journal_anchor_invalid")

    storage = real_file.default_storage_root().resolve(strict=False)
    quarantine_root = (storage / "quarantine").resolve(strict=False)
    rollback_root = (storage / "rollback").resolve(strict=False)
    target = Path(result.target_locator).resolve(strict=False)
    quarantined = Path(result.quarantine_path).resolve(strict=False)
    snapshot = Path(result.snapshot_path).resolve(strict=False)
    if target.exists():
        raise ValueError("b658_recovery_target_collision")
    if not _is_within(quarantined, quarantine_root) or not _is_within(snapshot, rollback_root):
        raise ValueError("b658_recovery_artifact_path_invalid")
    if not quarantined.is_file() or not snapshot.is_file():
        raise ValueError("b658_recovery_artifact_missing")
    if (
        _sha256_file(quarantined).casefold() != permit.target_sha256.casefold()
        or _sha256_file(snapshot).casefold() != permit.target_sha256.casefold()
    ):
        raise ValueError("b658_recovery_artifact_hash_mismatch")


def _persistent_from_path(path: Path) -> _PersistentQuarantine | None:
    payload = _read_record(path)
    if str(payload.get("state") or "") == RECOVERY_RESTORED:
        return None

    permit = _permit_from_dict(payload.get("permit"))
    finding_id = str(payload.get("finding_id") or "")
    if permit.finding_id != finding_id:
        raise ValueError("b658_recovery_finding_binding_mismatch")

    entries = _read_journal_readonly()
    result_payload = payload.get("result")
    result = _result_from_dict(result_payload) if isinstance(result_payload, dict) else None
    journal_result = _journal_result_for_permit(permit, entries)
    if journal_result is None:
        return None
    if result is None:
        result = journal_result
    elif result.result_sha256 != journal_result.result_sha256:
        raise ValueError("b658_recovery_result_journal_mismatch")

    _validate_active_artifacts(permit, result, entries)
    display = payload.get("display") if isinstance(payload.get("display"), dict) else {}
    return _PersistentQuarantine(
        finding_id=finding_id,
        permit=permit,
        result=result,
        severity=str(display.get("severity") or "HIGH/CRITICAL"),
        reason=str(display.get("reason") or "Risoluzione guidata verificata"),
        title=str(display.get("title") or Path(result.target_locator).name),
        record_path=path,
    )


def _load_persistent(finding_id: str) -> _PersistentQuarantine | None:
    path = _record_path(str(finding_id))
    if not path.is_file():
        return None
    try:
        return _persistent_from_path(path)
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _list_persistent() -> list[_PersistentQuarantine]:
    root = _recovery_root()
    if not root.is_dir():
        return []
    records: list[_PersistentQuarantine] = []
    try:
        paths = sorted(root.glob("*.json"))
    except OSError:
        return []
    for path in paths:
        try:
            record = _persistent_from_path(path)
        except (OSError, ValueError, TypeError, KeyError):
            continue
        if record is not None:
            records.append(record)
    return records


class HomeQuarantineController:
    """User-mediated B6-5.8 controller with read-only restart discovery."""

    def __init__(
        self,
        source_provider_load: boundary.ProviderLoadResult,
        *,
        user_profile: str | Path | None = None,
    ) -> None:
        self.source_provider_load = source_provider_load
        self.user_profile = Path(user_profile).expanduser().resolve(strict=False) if user_profile else None
        self._active: dict[str, _ActiveQuarantine] = {}

    def _build_plan(
        self,
        card: threat.ThreatCardModel,
        resolution: guided.GuidedResolutionModel,
    ) -> planning.ResolutionActionPlan:
        return planning.build_action_plan(
            card,
            resolution,
            self.source_provider_load,
            requested_action=real_file.SUPPORTED_ACTION,
        )

    def assess(
        self,
        card: threat.ThreatCardModel,
        resolution: guided.GuidedResolutionModel,
    ) -> HomeQuarantineAvailability:
        if self.has_active_quarantine(card.finding_id):
            return HomeQuarantineAvailability(
                False,
                "QUARANTINED",
                "Il file è già in quarantena ed è disponibile per il ripristino.",
            )
        if card.severity not in ELIGIBLE_SEVERITIES:
            return HomeQuarantineAvailability(False, "BLOCKED", _plain_reason("severity_not_eligible"))
        try:
            plan = self._build_plan(card, resolution)
        except Exception:
            return HomeQuarantineAvailability(False, "BLOCKED", _plain_reason("target_identity_not_verified"))
        if plan.target.identity_state != planning.TARGET_IDENTITY_VERIFIED or not plan.target.sha256:
            return HomeQuarantineAvailability(False, "BLOCKED", _plain_reason("target_identity_not_verified"))

        decision = real_file.assess_target_eligibility(
            plan.target.locator,
            user_profile=self.user_profile,
        )
        if decision.get("eligible") is not True:
            reason_code = str((decision.get("reasons") or ["blocked"])[0])
            return HomeQuarantineAvailability(
                False,
                "BLOCKED",
                _plain_reason(reason_code),
                str(plan.target.locator),
                str(plan.target.sha256),
            )

        try:
            current_hash = _sha256_file(plan.target.locator)
        except OSError:
            return HomeQuarantineAvailability(False, "BLOCKED", _plain_reason("target_metadata_unavailable"))
        if current_hash.casefold() != str(plan.target.sha256).casefold():
            return HomeQuarantineAvailability(
                False,
                "BLOCKED",
                _plain_reason("target_sha256_drift"),
                str(plan.target.locator),
                str(plan.target.sha256),
            )
        return HomeQuarantineAvailability(
            True,
            "READY",
            "Quarantena reversibile disponibile. È richiesta una conferma esplicita.",
            str(plan.target.locator),
            str(plan.target.sha256),
        )

    def prepare_confirmation(
        self,
        card: threat.ThreatCardModel,
        resolution: guided.GuidedResolutionModel,
    ) -> HomeQuarantineSession:
        availability = self.assess(card, resolution)
        if not availability.ready:
            raise ValueError("b658_home_quarantine_not_ready")
        plan = self._build_plan(card, resolution)
        now = time.time()
        initial = confirmation.TargetRevalidation(
            locator=plan.target.locator,
            observed_sha256=_sha256_file(plan.target.locator),
            observed_at=now,
            provenance="home_b658_pre_confirmation_sha256",
        )
        request = confirmation.build_confirmation_request(
            plan,
            self.source_provider_load,
            initial,
            now=now,
            nonce=secrets.token_hex(16),
        )
        return HomeQuarantineSession(card, resolution, plan, request, initial)

    def confirm_and_execute(self, session: HomeQuarantineSession) -> real_file.RealFileExecutionResult:
        now = time.time()
        confirm_revalidation = confirmation.TargetRevalidation(
            locator=session.plan.target.locator,
            observed_sha256=_sha256_file(session.plan.target.locator),
            observed_at=now,
            provenance="home_b658_confirmation_sha256",
        )
        receipt = confirmation.record_explicit_decision(
            session.request,
            session.plan,
            self.source_provider_load,
            confirm_revalidation,
            decision=confirmation.DECISION_CONFIRM,
            now=now,
        )
        if not receipt.confirmed:
            raise ValueError("b658_confirmation_not_accepted")

        # The mutating provider is intentionally created only after the user has
        # explicitly confirmed the exact target/action pair.
        provider = real_file.RealFileQuarantineProvider(user_profile=self.user_profile)
        post_time = max(time.time(), receipt.decided_at)
        post_confirmation = confirmation.TargetRevalidation(
            locator=session.plan.target.locator,
            observed_sha256=_sha256_file(session.plan.target.locator),
            observed_at=post_time,
            provenance="home_b658_post_confirmation_sha256",
        )
        permit = real_file.issue_real_file_execution_permit(
            session.plan,
            receipt,
            self.source_provider_load,
            provider,
            post_confirmation,
            now=post_time,
            ttl_seconds=30,
            nonce=secrets.token_hex(16),
        )

        # Recovery metadata is made durable before the file is moved. If this
        # atomic write fails, quarantine is not attempted.
        prepared = _recovery_body(
            finding_id=session.card.finding_id,
            permit=permit,
            result=None,
            state=RECOVERY_PREPARED,
            severity=session.card.severity,
            reason=session.card.reason,
            title=session.card.title,
            updated_at=post_time,
        )
        _write_recovery_record(prepared)

        result = provider.execute_quarantine(permit, now=max(time.time(), post_time))
        self._active[session.card.finding_id] = _ActiveQuarantine(provider, permit, result)

        # Finalization is best-effort because PREPARED + the verified journal can
        # reconstruct the same result after a crash/restart.
        try:
            finalized = _recovery_body(
                finding_id=session.card.finding_id,
                permit=permit,
                result=result,
                state=RECOVERY_ACTIVE,
                severity=session.card.severity,
                reason=session.card.reason,
                title=session.card.title,
                updated_at=result.finished_at,
            )
            _write_recovery_record(finalized)
        except OSError:
            pass
        return result

    def has_active_quarantine(self, finding_id: str) -> bool:
        key = str(finding_id)
        if key in self._active:
            return True
        return _load_persistent(key) is not None

    def rollback(self, finding_id: str) -> real_file.RealFileRollbackResult:
        key = str(finding_id)
        active = self._active.get(key)
        persistent: _PersistentQuarantine | None = None
        if active is None:
            persistent = _load_persistent(key)
            if persistent is None:
                raise ValueError("b658_no_verified_persistent_quarantine")
            # Provider construction remains lazy and happens only after the
            # explicit restore action.
            provider = real_file.RealFileQuarantineProvider(user_profile=self.user_profile)
            active = _ActiveQuarantine(provider, persistent.permit, persistent.result)

        rollback = active.provider.rollback_quarantine(
            active.permit,
            active.result,
            now=time.time(),
        )
        self._active.pop(key, None)

        if persistent is None:
            persistent = _load_persistent(key)
        severity = persistent.severity if persistent is not None else "HIGH/CRITICAL"
        reason = persistent.reason if persistent is not None else "Risoluzione guidata verificata"
        title = persistent.title if persistent is not None else Path(active.result.target_locator).name
        try:
            restored = _recovery_body(
                finding_id=key,
                permit=active.permit,
                result=active.result,
                state=RECOVERY_RESTORED,
                severity=severity,
                reason=reason,
                title=title,
                updated_at=rollback.finished_at,
                rollback=rollback,
            )
            _write_recovery_record(restored)
        except OSError:
            # Journal FINAL_OUTCOME is authoritative for filtering the record;
            # a failed metadata finalization must not invalidate a verified
            # rollback that already restored the original SHA-256.
            pass
        return rollback

    def quarantine_rows(self) -> list[dict]:
        """Return restart-safe active rows without mutating persistent storage."""

        rows: list[dict] = []
        for record in _list_persistent():
            ts = float(record.result.finished_at or 0.0)
            try:
                date = datetime.fromtimestamp(ts).astimezone().strftime("%d/%m/%Y %H:%M") if ts else ""
            except (OverflowError, OSError, ValueError):
                date = ""
            rows.append(
                {
                    "file": Path(record.result.target_locator).name,
                    "path": record.result.target_locator,
                    "date": date,
                    "risk": record.severity,
                    "reason": record.reason,
                    "status": "In quarantena",
                    "action": "Ripristina file",
                    "restore_key": record.finding_id,
                    "permit_id": record.permit.permit_id,
                }
            )
        return rows


def validate_b657_contract() -> dict:
    predecessor = real_file.validate_b656_contract()
    return {
        "schema": B657_SCHEMA,
        "profile": B657_PROFILE,
        "passed": predecessor.get("passed") is True,
        "b656_predecessor_green": predecessor.get("passed") is True,
        "home_quarantine_action_available": True,
        "eligible_severities": sorted(ELIGIBLE_SEVERITIES),
        "explicit_user_click_required": True,
        "second_confirmation_required": True,
        "fresh_sha256_before_confirmation": True,
        "fresh_sha256_at_confirmation": True,
        "fresh_sha256_after_confirmation": True,
        "lazy_execution_provider": True,
        "quarantine_page_uses_persistent_read_only_journal": True,
        "session_bound_verified_rollback_available": True,
        "persistent_restore_after_restart": False,
        "general_home_execution_authorized": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
        "next_execution_owner": "B6-5.8",
    }


def validate_b658_contract() -> dict:
    predecessor = validate_b657_contract()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": predecessor.get("passed") is True,
        "b657_predecessor_green": predecessor.get("passed") is True,
        "home_quarantine_action_available": True,
        "eligible_severities": sorted(ELIGIBLE_SEVERITIES),
        "explicit_user_click_required": True,
        "second_confirmation_required": True,
        "lazy_execution_provider": True,
        "recovery_metadata_written_before_move": True,
        "atomic_recovery_record": True,
        "restart_discovery_read_only": True,
        "journal_anchor_required": True,
        "quarantine_artifact_sha256_required": True,
        "rollback_snapshot_sha256_required": True,
        "persistent_restore_after_restart": True,
        "quarantine_page_restore_action_available": True,
        "general_home_execution_authorized": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
        "next_execution_owner": "B6-5.9+",
    }
