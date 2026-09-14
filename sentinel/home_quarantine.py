from __future__ import annotations

"""B6-5.7 explicit Home quarantine integration.

This layer exposes the already-accepted B6-5.6 reversible QUARANTINE action to
Home, but only after an explicit user click and a second confirmation dialog.
The execution provider is created lazily after confirmation, never at startup.
Only HIGH/CRITICAL findings with one explicit SHA-256 and an eligible
Desktop/Documents/Downloads file can proceed. DELETE, REPAIR, process control,
trust mutation and automatic remediation remain unavailable.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
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

PROFILE: Final[str] = "v0.11.0-beta.6-b65.7-home-quarantine"
SCHEMA: Final[str] = "bc-sentinel-beta6-home-quarantine-v1"
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


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plain_reason(code: str) -> str:
    mapping = {
        "severity_not_eligible": "Per questa fase la quarantena Home è disponibile solo per rilevamenti HIGH o CRITICAL.",
        "target_identity_not_verified": "Il rilevamento non contiene un unico SHA-256 verificabile.",
        "outside_allowed_user_roots": "Il file non si trova in Desktop, Documenti o Download.",
        "appdata_forbidden": "I file in AppData non sono autorizzati in questa fase.",
        "protected_or_self_managed_path": "Il percorso è protetto o appartiene a BC Sentinel.",
        "symlink_refused": "Il file è un collegamento simbolico e viene rifiutato.",
        "symlink_component_refused": "Il percorso contiene un collegamento simbolico e viene rifiutato.",
        "target_too_large": "Il file supera il limite di 64 MiB previsto da B6-5.7.",
        "target_missing_or_unresolvable": "Il file non è più disponibile o non è risolvibile.",
        "regular_file_required": "Il target non è un file regolare.",
        "target_metadata_unavailable": "I metadati del file non sono leggibili.",
        "target_sha256_drift": "Il file è cambiato rispetto all'hash rilevato dalla scansione.",
    }
    return mapping.get(code, "Il file non soddisfa i requisiti di sicurezza per la quarantena Home.")


class HomeQuarantineController:
    """User-mediated B6-5.7 controller with no startup execution side effects."""

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
            raise ValueError("b657_home_quarantine_not_ready")
        plan = self._build_plan(card, resolution)
        now = time.time()
        initial = confirmation.TargetRevalidation(
            locator=plan.target.locator,
            observed_sha256=_sha256_file(plan.target.locator),
            observed_at=now,
            provenance="home_b657_pre_confirmation_sha256",
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
            provenance="home_b657_confirmation_sha256",
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
            raise ValueError("b657_confirmation_not_accepted")

        # The mutating provider is intentionally created only after the user has
        # explicitly confirmed the exact target/action pair.
        provider = real_file.RealFileQuarantineProvider(user_profile=self.user_profile)
        post_time = max(time.time(), receipt.decided_at)
        post_confirmation = confirmation.TargetRevalidation(
            locator=session.plan.target.locator,
            observed_sha256=_sha256_file(session.plan.target.locator),
            observed_at=post_time,
            provenance="home_b657_post_confirmation_sha256",
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
        result = provider.execute_quarantine(permit, now=max(time.time(), post_time))
        self._active[session.card.finding_id] = _ActiveQuarantine(provider, permit, result)
        return result

    def has_active_quarantine(self, finding_id: str) -> bool:
        return str(finding_id) in self._active

    def rollback(self, finding_id: str) -> real_file.RealFileRollbackResult:
        key = str(finding_id)
        active = self._active.get(key)
        if active is None:
            raise ValueError("b657_no_session_bound_quarantine")
        rollback = active.provider.rollback_quarantine(
            active.permit,
            active.result,
            now=time.time(),
        )
        self._active.pop(key, None)
        return rollback

    def quarantine_rows(self) -> list[dict]:
        """Read the persistent B6-5.6 journal without creating storage at startup."""

        journal_path = real_file.default_storage_root() / "journal" / "events.jsonl"
        if not journal_path.is_file():
            return []
        try:
            entries: list[dict] = []
            with journal_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        item = json.loads(line)
                        if isinstance(item, dict):
                            entries.append(item)
        except (OSError, json.JSONDecodeError):
            return []

        active: dict[str, dict] = {}
        for entry in entries:
            permit_id = str(entry.get("permit_id") or "")
            event = str(entry.get("event") or "")
            payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
            if event == "ACTION_RESULT" and payload.get("state") == "QUARANTINED_VERIFIED":
                active[permit_id] = entry
            elif event in {"ROLLBACK_RESULT", "FINAL_OUTCOME"}:
                active.pop(permit_id, None)

        rows: list[dict] = []
        for entry in active.values():
            target = str(entry.get("target_locator") or "")
            ts = float(entry.get("timestamp") or 0.0)
            try:
                date = datetime.fromtimestamp(ts).astimezone().strftime("%d/%m/%Y %H:%M") if ts else ""
            except (OverflowError, OSError, ValueError):
                date = ""
            rows.append(
                {
                    "file": Path(target).name,
                    "path": target,
                    "date": date,
                    "risk": "HIGH/CRITICAL",
                    "reason": "Risoluzione guidata verificata",
                    "status": "In quarantena",
                    "action": "Ripristina dalla scheda rilevamento",
                }
            )
        return rows


def validate_b657_contract() -> dict:
    predecessor = real_file.validate_b656_contract()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
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
        "next_execution_owner": "B6-5.8+",
    }
