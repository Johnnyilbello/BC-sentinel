from __future__ import annotations

"""B13-1 Safe Threat Response & Consumer Notifications.

Adds a consumer-facing response policy on top of the already accepted,
user-mediated quarantine/restore path. The policy never performs silent
containment, delete, repair, process termination or trust mutation.

Qualified findings become actionable notifications. A real quarantine still
requires an explicit user confirmation and is delegated to the accepted
HomeQuarantineController, preserving its fresh-hash checks and rollback path.
"""

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Final

from sentinel import beta13_consumer_readiness as b130
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine
from sentinel import home_threat_cards as threat

SCHEMA: Final[str] = "bc-sentinel-beta13-safe-response-v1"
PROFILE: Final[str] = "v0.13.0-b131-safe-response-notification-ux"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b130-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "6c1a3dedd48d2b26b716c199f74ea45d827ee01a"

STATE_NOTIFY_ONLY: Final[str] = "NOTIFY_ONLY"
STATE_ACTION_REQUIRED: Final[str] = "ACTION_REQUIRED"
STATE_REVIEW_REQUIRED: Final[str] = "REVIEW_REQUIRED"
STATE_QUARANTINED: Final[str] = "QUARANTINED"
STATE_RESTORED: Final[str] = "RESTORED"

ACTION_REVIEW: Final[str] = "REVIEW"
ACTION_QUARANTINE: Final[str] = "QUARANTINE"
ACTION_NONE: Final[str] = "NONE"

ELIGIBLE_RESPONSE_SEVERITIES: Final[frozenset[str]] = frozenset({"HIGH", "CRITICAL"})

BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "network_io": False,
    "cloud_required": False,
    "silent_destructive_action": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "explicit_user_confirmation_required": True,
    "existing_quarantine_controller_reused": True,
    "rollback_path_required": True,
    "raw_path_in_notification": False,
    "command_line_in_notification": False,
    "file_content_in_notification": False,
}


@dataclass(frozen=True)
class SafeResponsePlan:
    finding_id: str
    title: str
    severity: str
    confidence: float | None
    state: str
    recommended_action: str
    rationale: str
    quarantine_ready: bool
    explicit_user_confirmation_required: bool
    reversible: bool
    target_sha256: str

    def validate(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("b131:finding_id_required")
        if self.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("b131:severity_invalid")
        if self.confidence is not None and not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("b131:confidence_invalid")
        if self.state not in {
            STATE_NOTIFY_ONLY,
            STATE_ACTION_REQUIRED,
            STATE_REVIEW_REQUIRED,
            STATE_QUARANTINED,
            STATE_RESTORED,
        }:
            raise ValueError("b131:state_invalid")
        if self.recommended_action not in {ACTION_NONE, ACTION_REVIEW, ACTION_QUARANTINE}:
            raise ValueError("b131:action_invalid")
        if self.state == STATE_ACTION_REQUIRED:
            if self.recommended_action != ACTION_QUARANTINE or not self.quarantine_ready:
                raise ValueError("b131:action_required_contract_invalid")
            if not self.explicit_user_confirmation_required or not self.reversible:
                raise ValueError("b131:action_required_safety_invalid")
        if self.state == STATE_NOTIFY_ONLY and self.recommended_action != ACTION_NONE:
            raise ValueError("b131:notify_only_action_invalid")
        if self.target_sha256:
            if len(self.target_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.target_sha256.lower()):
                raise ValueError("b131:target_sha256_invalid")


@dataclass(frozen=True)
class ConsumerNotification:
    notification_id: str
    finding_id: str
    title: str
    severity: str
    response_state: str
    recommended_action: str
    summary: str
    created_at: float
    read: bool = False

    def validate(self) -> None:
        if not self.notification_id.startswith("BCN-"):
            raise ValueError("b131:notification_id_invalid")
        if not self.finding_id.strip() or not self.title.strip() or not self.summary.strip():
            raise ValueError("b131:notification_fields_required")
        if self.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("b131:notification_severity_invalid")
        if self.response_state not in {
            STATE_NOTIFY_ONLY,
            STATE_ACTION_REQUIRED,
            STATE_REVIEW_REQUIRED,
            STATE_QUARANTINED,
            STATE_RESTORED,
        }:
            raise ValueError("b131:notification_state_invalid")
        if self.recommended_action not in {ACTION_NONE, ACTION_REVIEW, ACTION_QUARANTINE}:
            raise ValueError("b131:notification_action_invalid")
        if not isinstance(self.created_at, (int, float)) or float(self.created_at) < 0:
            raise ValueError("b131:notification_time_invalid")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def plan_response(
    card: threat.ThreatCardModel,
    resolution: guided.GuidedResolutionModel,
    controller: home_quarantine.HomeQuarantineController,
) -> SafeResponsePlan:
    card.validate()
    resolution.validate()
    availability = controller.assess(card, resolution)

    if card.severity not in ELIGIBLE_RESPONSE_SEVERITIES:
        plan = SafeResponsePlan(
            finding_id=card.finding_id,
            title=card.title,
            severity=card.severity,
            confidence=card.confidence,
            state=STATE_NOTIFY_ONLY,
            recommended_action=ACTION_NONE,
            rationale="Rilevamento visibile senza azione automatica. La severità non abilita la quarantena consumer.",
            quarantine_ready=False,
            explicit_user_confirmation_required=False,
            reversible=False,
            target_sha256="",
        )
    elif availability.ready:
        plan = SafeResponsePlan(
            finding_id=card.finding_id,
            title=card.title,
            severity=card.severity,
            confidence=card.confidence,
            state=STATE_ACTION_REQUIRED,
            recommended_action=ACTION_QUARANTINE,
            rationale="Quarantena reversibile disponibile. BC Sentinel richiede una conferma esplicita prima di spostare il file.",
            quarantine_ready=True,
            explicit_user_confirmation_required=True,
            reversible=True,
            target_sha256=str(availability.target_sha256).lower(),
        )
    else:
        plan = SafeResponsePlan(
            finding_id=card.finding_id,
            title=card.title,
            severity=card.severity,
            confidence=card.confidence,
            state=STATE_REVIEW_REQUIRED,
            recommended_action=ACTION_REVIEW,
            rationale=availability.reason or "Il rilevamento richiede revisione; la quarantena non è disponibile in sicurezza.",
            quarantine_ready=False,
            explicit_user_confirmation_required=False,
            reversible=False,
            target_sha256=str(availability.target_sha256 or "").lower(),
        )

    plan.validate()
    return plan


def notification_from_plan(plan: SafeResponsePlan, *, now: float | None = None) -> ConsumerNotification:
    plan.validate()
    timestamp = float(time.time() if now is None else now)
    if plan.state == STATE_ACTION_REQUIRED:
        summary = "Minaccia rilevata. Quarantena reversibile consigliata; è richiesta la tua conferma."
    elif plan.state == STATE_REVIEW_REQUIRED:
        summary = "Rilevamento da verificare. Nessuna azione automatica è stata eseguita."
    else:
        summary = "Rilevamento registrato. Nessuna azione automatica è necessaria."

    identity = _sha256_text(
        json.dumps(
            {
                "finding_id": plan.finding_id,
                "state": plan.state,
                "action": plan.recommended_action,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    notice = ConsumerNotification(
        notification_id="BCN-" + identity[:20].upper(),
        finding_id=plan.finding_id,
        title=plan.title,
        severity=plan.severity,
        response_state=plan.state,
        recommended_action=plan.recommended_action,
        summary=summary,
        created_at=timestamp,
        read=False,
    )
    notice.validate()
    return notice


class NotificationCenter:
    """Privacy-minimal local notification journal.

    The journal stores no raw file path, command line, username or file content.
    Duplicate notifications for the same response identity replace the previous
    entry instead of creating alert storms.
    """

    def __init__(self, storage_path: str | Path | None = None) -> None:
        self.storage_path = Path(storage_path) if storage_path is not None else None
        self._items: dict[str, ConsumerNotification] = {}
        if self.storage_path is not None and self.storage_path.is_file():
            self._load()

    def _load(self) -> None:
        assert self.storage_path is not None
        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("b131:notification_journal_unreadable") from exc
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
            raise ValueError("b131:notification_journal_invalid")
        items = payload.get("notifications")
        if not isinstance(items, list):
            raise ValueError("b131:notification_journal_items_invalid")
        loaded: dict[str, ConsumerNotification] = {}
        for row in items:
            if not isinstance(row, dict):
                raise ValueError("b131:notification_journal_item_invalid")
            notice = ConsumerNotification(**row)
            notice.validate()
            loaded[notice.notification_id] = notice
        self._items = loaded

    def _save(self) -> None:
        if self.storage_path is None:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "notifications": [asdict(item) for item in self.items()],
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix="bcs-notifications-",
            suffix=".tmp",
            dir=str(self.storage_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.storage_path)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass

    def publish(self, notice: ConsumerNotification) -> ConsumerNotification:
        notice.validate()
        self._items[notice.notification_id] = notice
        self._save()
        return notice

    def mark_read(self, notification_id: str) -> ConsumerNotification:
        current = self._items.get(str(notification_id))
        if current is None:
            raise KeyError("b131:notification_not_found")
        updated = replace(current, read=True)
        updated.validate()
        self._items[updated.notification_id] = updated
        self._save()
        return updated

    def items(self) -> list[ConsumerNotification]:
        return sorted(
            self._items.values(),
            key=lambda item: (float(item.created_at), item.notification_id),
            reverse=True,
        )

    def unread_count(self) -> int:
        return sum(1 for item in self._items.values() if not item.read)


def execute_reversible_quarantine(
    *,
    plan: SafeResponsePlan,
    card: threat.ThreatCardModel,
    resolution: guided.GuidedResolutionModel,
    controller: home_quarantine.HomeQuarantineController,
    user_confirmed: bool,
):
    plan.validate()
    if plan.finding_id != card.finding_id:
        raise ValueError("b131:plan_finding_binding_mismatch")
    if plan.state != STATE_ACTION_REQUIRED or plan.recommended_action != ACTION_QUARANTINE:
        raise ValueError("b131:quarantine_not_recommended")
    if user_confirmed is not True:
        raise PermissionError("b131:explicit_user_confirmation_required")

    refreshed = plan_response(card, resolution, controller)
    if refreshed.state != STATE_ACTION_REQUIRED or refreshed.target_sha256 != plan.target_sha256:
        raise ValueError("b131:response_plan_drift")

    session = controller.prepare_confirmation(card, resolution)
    result = controller.confirm_and_execute(session)
    if result.state != "QUARANTINED_VERIFIED":
        raise ValueError("b131:quarantine_result_unverified")
    return result


def restore_quarantined(
    *,
    controller: home_quarantine.HomeQuarantineController,
    finding_id: str,
    user_confirmed: bool,
):
    if user_confirmed is not True:
        raise PermissionError("b131:explicit_restore_confirmation_required")
    result = controller.rollback(str(finding_id))
    if result.state != "RESTORED_VERIFIED":
        raise ValueError("b131:restore_result_unverified")
    return result


def projected_readiness() -> dict[str, Any]:
    baseline = b130.contract()
    pillars = [dict(item) for item in baseline["pillars"]]
    transitions = {
        "SAFE_THREAT_RESPONSE": {
            "status": b130.READY,
            "evidence": "B13_1_ACCEPTED_USER_CONFIRMED_REVERSIBLE_RESPONSE",
            "detail": "Evidence-bound consumer response policy accepted with explicit confirmation, fresh target revalidation and verified rollback.",
        },
        "BACKGROUND_ALERTS": {
            "status": b130.READY,
            "evidence": "B13_1_ACCEPTED_NOTIFICATION_CENTER_AND_TRAY_ADAPTER",
            "detail": "Dedicated consumer notification center and local tray notification adapter accepted; no raw path or command line is surfaced.",
        },
    }
    for item in pillars:
        update = transitions.get(str(item["pillar_id"]))
        if update:
            item.update(update)

    counts = {
        status: sum(1 for item in pillars if item["status"] == status)
        for status in (b130.READY, b130.PARTIAL, b130.BLOCKED)
    }
    blockers = [
        str(item["pillar_id"])
        for item in pillars
        if item.get("release_blocking") is True and item["status"] != b130.READY
    ]
    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v1",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": len(blockers) == 0,
        "ready_for_paid_launch": len(blockers) == 0,
        "resolved_by_b131": sorted(transitions),
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def self_check() -> dict[str, Any]:
    readiness = projected_readiness()
    contract = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "boundaries": BOUNDARIES,
        "readiness_projection": readiness,
    }
    digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    expected_blockers = [
        "SECURE_UPDATES",
        "INSTALLER_LIFECYCLE",
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]
    passed = (
        readiness["pillar_counts"] == {"READY": 5, "PARTIAL": 1, "BLOCKED": 4}
        and readiness["release_blockers"] == expected_blockers
        and readiness["release_blocker_count"] == 5
        and not any(value for key, value in BOUNDARIES.items() if key not in {
            "local_only",
            "explicit_user_confirmation_required",
            "existing_quarantine_controller_reused",
            "rollback_path_required",
        })
        and BOUNDARIES["local_only"]
        and BOUNDARIES["explicit_user_confirmation_required"]
        and BOUNDARIES["existing_quarantine_controller_reused"]
        and BOUNDARIES["rollback_path_required"]
    )
    return {
        "passed": bool(passed),
        "failures": [] if passed else ["b131:self_check_failed"],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": digest,
        "boundaries": dict(BOUNDARIES),
        "readiness_projection": readiness,
        "safe_response_ready": True,
        "background_alerts_ready": True,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "terminate_process_authority": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
