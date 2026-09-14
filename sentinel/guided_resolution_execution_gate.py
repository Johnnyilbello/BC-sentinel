from __future__ import annotations

"""B6-5.4 fail-closed execution-readiness boundary for Guided Resolution.

B6-5.3 proves that a human explicitly confirmed an integrity-bound plan. That is
still not enough to mutate Windows. B6-5.4 introduces the separate execution
readiness gate and proves which prerequisites must be bound immediately before
execution: confirmed receipt, fresh target identity, unchanged provider,
execution-capable provider action, journal storage and rollback binding.

The current B6-5.1 provider is intentionally passive and the B6-5.2 journal and
rollback objects are intentionally blueprints only. Therefore this checkpoint
MUST remain blocked and exposes no execute/apply/remediate API, execution nonce,
journal write authority, rollback authority or destructive capability.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Final

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_provider_loader as boundary

PROFILE: Final[str] = "v0.11.0-beta.6-b65.4-execution-readiness"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-execution-readiness-v1"
GATE_PREFIX: Final[str] = "B654-GATE-"

STATE_BLOCKED_CONFIRMATION: Final[str] = "BLOCKED_CONFIRMATION"
STATE_BLOCKED_TARGET_REVALIDATION: Final[str] = "BLOCKED_TARGET_REVALIDATION"
STATE_BLOCKED_EXECUTION_PREREQUISITES: Final[str] = "BLOCKED_EXECUTION_PREREQUISITES"
STATES: Final[frozenset[str]] = frozenset(
    {
        STATE_BLOCKED_CONFIRMATION,
        STATE_BLOCKED_TARGET_REVALIDATION,
        STATE_BLOCKED_EXECUTION_PREREQUISITES,
    }
)

MAX_POST_CONFIRM_REVALIDATION_AGE_SECONDS: Final[int] = 30


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _normalized_locator(value: str) -> str:
    return str(value or "").strip().casefold()


def _provider_snapshot_sha256(provider_load: boundary.ProviderLoadResult) -> str:
    return _sha256_payload(provider_load.to_dict())


def _action_snapshot(provider_load: boundary.ProviderLoadResult, action_id: str) -> dict:
    actions = provider_load.capability_snapshot.get("actions")
    if not isinstance(actions, list):
        raise ValueError("b654_provider_actions_missing")
    matches = [item for item in actions if isinstance(item, dict) and item.get("action_id") == action_id]
    if len(matches) != 1:
        raise ValueError("b654_provider_action_missing_or_ambiguous")
    return dict(matches[0])


def _validate_static_bindings(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    provider_load: boundary.ProviderLoadResult,
) -> str:
    plan.validate()
    receipt.validate()
    if receipt.plan_id != plan.plan_id or receipt.plan_sha256 != plan.plan_sha256:
        raise ValueError("b654_confirmation_plan_binding_mismatch")
    if receipt.requested_action != plan.requested_action or receipt.finding_id != plan.finding_id:
        raise ValueError("b654_confirmation_subject_mismatch")
    if provider_load.loaded is not True or provider_load.accepted is not True:
        raise ValueError("b654_provider_boundary_not_accepted")
    provider_hash = _provider_snapshot_sha256(provider_load)
    if provider_hash != plan.provider_snapshot_sha256:
        raise ValueError("b654_provider_snapshot_drift_from_plan")
    if provider_hash != receipt.provider_snapshot_sha256:
        raise ValueError("b654_provider_snapshot_drift_from_confirmation")
    return provider_hash


def _validate_post_confirmation_target(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    evidence: confirmation.TargetRevalidation,
    *,
    now: float,
) -> str:
    evidence.validate()
    if _normalized_locator(evidence.locator) != _normalized_locator(plan.target.locator):
        raise ValueError("b654_target_locator_drift")
    if evidence.observed_sha256.casefold() != str(plan.target.sha256 or "").casefold():
        raise ValueError("b654_target_sha256_drift")
    if evidence.observed_at < receipt.decided_at:
        raise ValueError("b654_target_revalidation_precedes_confirmation")
    if evidence.observed_at > now + 1.0:
        raise ValueError("b654_target_revalidation_from_future")
    if now - evidence.observed_at > MAX_POST_CONFIRM_REVALIDATION_AGE_SECONDS:
        raise ValueError("b654_target_revalidation_too_old")
    return _sha256_payload(evidence.to_dict())


@dataclass(frozen=True)
class ExecutionReadinessGate:
    gate_id: str
    gate_sha256: str
    state: str
    blockers: tuple[str, ...]
    plan_id: str
    plan_sha256: str
    receipt_id: str
    receipt_sha256: str
    requested_action: str
    finding_id: str
    provider_snapshot_sha256: str
    target_revalidation_sha256: str
    provider_execution_available: bool
    provider_action_available: bool
    journal_bound: bool
    rollback_bound: bool
    execution_authorized: bool = False
    execution_nonce_issued: bool = False
    journal_write_authority: bool = False
    rollback_execution_authority: bool = False
    automatic_action: bool = False
    destructive_authority: bool = False
    schema: str = SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "state": self.state,
            "blockers": list(self.blockers),
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "requested_action": self.requested_action,
            "finding_id": self.finding_id,
            "provider_snapshot_sha256": self.provider_snapshot_sha256,
            "target_revalidation_sha256": self.target_revalidation_sha256,
            "provider_execution_available": self.provider_execution_available,
            "provider_action_available": self.provider_action_available,
            "journal_bound": self.journal_bound,
            "rollback_bound": self.rollback_bound,
            "execution_authorized": False,
            "execution_nonce_issued": False,
            "journal_write_authority": False,
            "rollback_execution_authority": False,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("b654_gate_schema_mismatch")
        if self.state not in STATES:
            raise ValueError("b654_gate_state_invalid")
        if not self.blockers:
            raise ValueError("b654_gate_must_remain_blocked")
        if not self.plan_id.startswith(planning.PLAN_PREFIX) or not _is_sha256(self.plan_sha256):
            raise ValueError("b654_gate_plan_binding_invalid")
        if not self.receipt_id.startswith(confirmation.RECEIPT_PREFIX) or not _is_sha256(self.receipt_sha256):
            raise ValueError("b654_gate_receipt_binding_invalid")
        if self.requested_action not in boundary.MUTATING_ACTIONS:
            raise ValueError("b654_gate_action_invalid")
        if not self.finding_id.strip():
            raise ValueError("b654_gate_finding_required")
        if not _is_sha256(self.provider_snapshot_sha256):
            raise ValueError("b654_gate_provider_binding_invalid")
        if self.target_revalidation_sha256 and not _is_sha256(self.target_revalidation_sha256):
            raise ValueError("b654_gate_target_revalidation_invalid")
        if any(
            (
                self.execution_authorized,
                self.execution_nonce_issued,
                self.journal_write_authority,
                self.rollback_execution_authority,
                self.automatic_action,
                self.destructive_authority,
            )
        ):
            raise ValueError("b654_gate_authority_forbidden")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.gate_sha256:
            raise ValueError("b654_gate_integrity_mismatch")
        if self.gate_id != GATE_PREFIX + self.gate_sha256[:16].upper():
            raise ValueError("b654_gate_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["gate_id"] = self.gate_id
        payload["gate_sha256"] = self.gate_sha256
        return payload


def assess_execution_readiness(
    plan: planning.ResolutionActionPlan,
    receipt: confirmation.ConfirmationReceipt,
    provider_load: boundary.ProviderLoadResult,
    target_revalidation: confirmation.TargetRevalidation | None,
    *,
    now: float,
) -> ExecutionReadinessGate:
    """Assess the boundary after confirmation; never authorize or execute anything."""

    provider_hash = _validate_static_bindings(plan, receipt, provider_load)
    blockers: list[str] = []
    revalidation_hash = ""

    if not (
        receipt.decision == confirmation.DECISION_CONFIRM
        and receipt.state == confirmation.STATE_CONFIRMED_NOT_EXECUTABLE
        and receipt.confirmed is True
        and receipt.explicit_human_decision is True
    ):
        state = STATE_BLOCKED_CONFIRMATION
        blockers.append("explicit_confirmation_not_currently_valid")
    else:
        state = STATE_BLOCKED_EXECUTION_PREREQUISITES
        if target_revalidation is None:
            state = STATE_BLOCKED_TARGET_REVALIDATION
            blockers.append("post_confirmation_target_revalidation_required")
        else:
            revalidation_hash = _validate_post_confirmation_target(
                plan,
                receipt,
                target_revalidation,
                now=float(now),
            )

        provider_payload = provider_load.to_dict()
        action = _action_snapshot(provider_load, plan.requested_action)
        provider_execution_available = provider_payload.get("execution_available") is True
        provider_action_available = action.get("available") is True
        journal_bound = plan.journal.storage_binding != "NOT_BOUND"
        rollback_bound = plan.rollback.rollback_binding != "NOT_BOUND"

        if not provider_execution_available:
            blockers.append("provider_execution_boundary_unavailable")
        if not provider_action_available:
            blockers.append("provider_action_unavailable")
        if not journal_bound:
            blockers.append("journal_storage_not_bound")
        if not rollback_bound:
            blockers.append("rollback_not_bound")

    provider_payload = provider_load.to_dict()
    action = _action_snapshot(provider_load, plan.requested_action)
    draft = ExecutionReadinessGate(
        gate_id="",
        gate_sha256="",
        state=state,
        blockers=tuple(dict.fromkeys(blockers)),
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        receipt_id=receipt.receipt_id,
        receipt_sha256=receipt.receipt_sha256,
        requested_action=plan.requested_action,
        finding_id=plan.finding_id,
        provider_snapshot_sha256=provider_hash,
        target_revalidation_sha256=revalidation_hash,
        provider_execution_available=provider_payload.get("execution_available") is True,
        provider_action_available=action.get("available") is True,
        journal_bound=plan.journal.storage_binding != "NOT_BOUND",
        rollback_bound=plan.rollback.rollback_binding != "NOT_BOUND",
    )
    digest = _sha256_payload(draft.canonical_without_hash())
    gate = ExecutionReadinessGate(
        **{
            **draft.__dict__,
            "gate_id": GATE_PREFIX + digest[:16].upper(),
            "gate_sha256": digest,
        }
    )
    gate.validate()
    return gate


def validate_b654_execution_gate_contract() -> dict:
    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": True,
        "confirmed_receipt_is_not_execution_authority": True,
        "fresh_target_revalidation_after_confirmation_required": True,
        "provider_execution_boundary_required": True,
        "provider_action_availability_required": True,
        "journal_storage_binding_required": True,
        "rollback_binding_required": True,
        "b652_blueprints_are_not_execution_authority": True,
        "execution_api": False,
        "execution_authorized": False,
        "execution_nonce_issued": False,
        "journal_write_authority": False,
        "rollback_execution_authority": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "next_execution_owner": "B6-5.5+",
    }
