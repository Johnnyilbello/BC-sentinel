from __future__ import annotations

"""B6-5.3 explicit-confirmation gate for Guided Resolution.

A confirmation is an integrity-bound record of an explicit human decision.  It
is deliberately *not* execution authorization.  This module performs no target
mutation, quarantine, repair, delete, process termination, trust change,
journal write or rollback operation.  B6-5.4+ must separately bind and accept
execution authority.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import secrets
import time
from typing import Final

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_provider_loader as boundary

PROFILE: Final[str] = "v0.11.0-beta.6-b65.3-explicit-confirmation"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-confirmation-v1"
REQUEST_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-confirmation-request-v1"
RECEIPT_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-confirmation-receipt-v1"
REVALIDATION_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-target-revalidation-v1"

REQUEST_PREFIX: Final[str] = "B653-REQ-"
RECEIPT_PREFIX: Final[str] = "B653-RCP-"
DEFAULT_TTL_SECONDS: Final[int] = 180
MAX_TTL_SECONDS: Final[int] = 600
MAX_REVALIDATION_AGE_SECONDS: Final[int] = 30

DECISION_CONFIRM: Final[str] = "CONFIRM"
DECISION_REFUSE: Final[str] = "REFUSE"
DECISIONS: Final[frozenset[str]] = frozenset({DECISION_CONFIRM, DECISION_REFUSE})

STATE_AWAITING_EXPLICIT_CONFIRMATION: Final[str] = "AWAITING_EXPLICIT_CONFIRMATION"
STATE_CONFIRMED_NOT_EXECUTABLE: Final[str] = "CONFIRMED_NOT_EXECUTABLE"
STATE_REFUSED: Final[str] = "REFUSED"
STATE_EXPIRED: Final[str] = "EXPIRED"


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _normalized_locator(value: str) -> str:
    return str(value or "").strip().casefold()


def _expected_target_fingerprint(plan: planning.ResolutionActionPlan) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "kind": plan.target.kind,
                "locator": _normalized_locator(plan.target.locator),
                "sha256": str(plan.target.sha256 or "").casefold(),
            }
        )
    ).hexdigest()


def _provider_snapshot_sha256(provider_load: boundary.ProviderLoadResult) -> str:
    return _sha256_payload(provider_load.to_dict())


@dataclass(frozen=True)
class TargetRevalidation:
    locator: str
    observed_sha256: str
    observed_at: float
    provenance: str
    schema: str = REVALIDATION_SCHEMA
    read_only: bool = True

    def validate(self) -> None:
        if self.schema != REVALIDATION_SCHEMA:
            raise ValueError("b653_revalidation_schema_mismatch")
        if not self.locator.strip():
            raise ValueError("b653_revalidation_locator_required")
        if not _is_sha256(self.observed_sha256):
            raise ValueError("b653_revalidation_sha256_required")
        if self.observed_at <= 0:
            raise ValueError("b653_revalidation_time_invalid")
        if not self.provenance.strip():
            raise ValueError("b653_revalidation_provenance_required")
        if self.read_only is not True:
            raise ValueError("b653_revalidation_must_be_read_only")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class ConfirmationRequest:
    request_id: str
    request_sha256: str
    plan_id: str
    plan_sha256: str
    requested_action: str
    finding_id: str
    target_locator: str
    target_sha256: str
    target_fingerprint: str
    provider_snapshot_sha256: str
    initial_revalidation_sha256: str
    issued_at: float
    expires_at: float
    nonce: str
    status: str = STATE_AWAITING_EXPLICIT_CONFIRMATION
    explicit_decision_required: bool = True
    execution_authorized: bool = False
    execution_nonce_issued: bool = False
    journal_write_authority: bool = False
    rollback_execution_authority: bool = False
    automatic_action: bool = False
    destructive_authority: bool = False
    schema: str = REQUEST_SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "requested_action": self.requested_action,
            "finding_id": self.finding_id,
            "target_locator": self.target_locator,
            "target_sha256": self.target_sha256,
            "target_fingerprint": self.target_fingerprint,
            "provider_snapshot_sha256": self.provider_snapshot_sha256,
            "initial_revalidation_sha256": self.initial_revalidation_sha256,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "status": self.status,
            "explicit_decision_required": True,
            "execution_authorized": False,
            "execution_nonce_issued": False,
            "journal_write_authority": False,
            "rollback_execution_authority": False,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != REQUEST_SCHEMA:
            raise ValueError("b653_request_schema_mismatch")
        if self.status != STATE_AWAITING_EXPLICIT_CONFIRMATION:
            raise ValueError("b653_request_status_invalid")
        if not self.plan_id.startswith(planning.PLAN_PREFIX) or not _is_sha256(self.plan_sha256):
            raise ValueError("b653_request_plan_binding_invalid")
        if self.requested_action not in boundary.MUTATING_ACTIONS:
            raise ValueError("b653_request_action_invalid")
        if not self.finding_id.strip():
            raise ValueError("b653_request_finding_required")
        if not self.target_locator.strip() or not _is_sha256(self.target_sha256):
            raise ValueError("b653_request_target_invalid")
        if not _is_sha256(self.target_fingerprint):
            raise ValueError("b653_request_target_fingerprint_invalid")
        if not _is_sha256(self.provider_snapshot_sha256):
            raise ValueError("b653_request_provider_snapshot_invalid")
        if not _is_sha256(self.initial_revalidation_sha256):
            raise ValueError("b653_request_revalidation_binding_invalid")
        if self.issued_at <= 0 or self.expires_at <= self.issued_at:
            raise ValueError("b653_request_expiry_invalid")
        if self.expires_at - self.issued_at > MAX_TTL_SECONDS:
            raise ValueError("b653_request_ttl_too_long")
        if len(self.nonce) < 16:
            raise ValueError("b653_request_nonce_too_short")
        if not self.explicit_decision_required:
            raise ValueError("b653_explicit_decision_requirement_missing")
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
            raise ValueError("b653_request_authority_forbidden")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.request_sha256:
            raise ValueError("b653_request_integrity_mismatch")
        if self.request_id != REQUEST_PREFIX + self.request_sha256[:16].upper():
            raise ValueError("b653_request_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["request_id"] = self.request_id
        payload["request_sha256"] = self.request_sha256
        return payload


@dataclass(frozen=True)
class ConfirmationReceipt:
    receipt_id: str
    receipt_sha256: str
    request_id: str
    request_sha256: str
    plan_id: str
    plan_sha256: str
    requested_action: str
    finding_id: str
    decision: str
    state: str
    decided_at: float
    confirmation_revalidation_sha256: str
    provider_snapshot_sha256: str
    explicit_human_decision: bool
    confirmed: bool
    execution_authorized: bool = False
    execution_nonce_issued: bool = False
    journal_write_authority: bool = False
    rollback_execution_authority: bool = False
    automatic_action: bool = False
    destructive_authority: bool = False
    schema: str = RECEIPT_SCHEMA

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "profile": PROFILE,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "requested_action": self.requested_action,
            "finding_id": self.finding_id,
            "decision": self.decision,
            "state": self.state,
            "decided_at": self.decided_at,
            "confirmation_revalidation_sha256": self.confirmation_revalidation_sha256,
            "provider_snapshot_sha256": self.provider_snapshot_sha256,
            "explicit_human_decision": self.explicit_human_decision,
            "confirmed": self.confirmed,
            "execution_authorized": False,
            "execution_nonce_issued": False,
            "journal_write_authority": False,
            "rollback_execution_authority": False,
            "automatic_action": False,
            "destructive_authority": False,
        }

    def validate(self) -> None:
        if self.schema != RECEIPT_SCHEMA:
            raise ValueError("b653_receipt_schema_mismatch")
        if self.decision not in DECISIONS:
            raise ValueError("b653_receipt_decision_invalid")
        allowed_states = {STATE_CONFIRMED_NOT_EXECUTABLE, STATE_REFUSED, STATE_EXPIRED}
        if self.state not in allowed_states:
            raise ValueError("b653_receipt_state_invalid")
        if self.decided_at <= 0:
            raise ValueError("b653_receipt_time_invalid")
        if not _is_sha256(self.request_sha256) or not _is_sha256(self.plan_sha256):
            raise ValueError("b653_receipt_binding_invalid")
        if not _is_sha256(self.confirmation_revalidation_sha256):
            raise ValueError("b653_receipt_revalidation_invalid")
        if not _is_sha256(self.provider_snapshot_sha256):
            raise ValueError("b653_receipt_provider_snapshot_invalid")
        if self.explicit_human_decision is not True:
            raise ValueError("b653_receipt_explicit_decision_required")
        expected_confirmed = self.decision == DECISION_CONFIRM and self.state == STATE_CONFIRMED_NOT_EXECUTABLE
        if self.confirmed is not expected_confirmed:
            raise ValueError("b653_receipt_confirmation_state_mismatch")
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
            raise ValueError("b653_receipt_authority_forbidden")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.receipt_sha256:
            raise ValueError("b653_receipt_integrity_mismatch")
        if self.receipt_id != RECEIPT_PREFIX + self.receipt_sha256[:16].upper():
            raise ValueError("b653_receipt_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["receipt_id"] = self.receipt_id
        payload["receipt_sha256"] = self.receipt_sha256
        return payload


def _validate_plan_for_confirmation(plan: planning.ResolutionActionPlan) -> None:
    plan.validate()
    if plan.plan_status != planning.PLAN_STATUS_PLANNED_NOT_AUTHORIZED:
        raise ValueError("b653_plan_not_confirmation_ready")
    if plan.target.identity_state != planning.TARGET_IDENTITY_VERIFIED:
        raise ValueError("b653_target_identity_not_verified")
    if not _is_sha256(plan.target.sha256):
        raise ValueError("b653_target_sha256_missing")
    expected_fingerprint = _expected_target_fingerprint(plan)
    if plan.target.fingerprint.casefold() != expected_fingerprint:
        raise ValueError("b653_target_fingerprint_semantics_mismatch")
    if plan.execution_authorized or plan.confirmation_issued or plan.destructive_authority:
        raise ValueError("b653_source_plan_authority_invalid")


def _validate_provider_binding(
    plan: planning.ResolutionActionPlan,
    provider_load: boundary.ProviderLoadResult,
) -> str:
    if provider_load.loaded is not True or provider_load.accepted is not True:
        raise ValueError("b653_provider_boundary_not_accepted")
    payload = provider_load.to_dict()
    if payload.get("execution_available") is not False:
        raise ValueError("b653_provider_execution_authority_exposed")
    if payload.get("automatic_action") is not False or payload.get("destructive_authority") is not False:
        raise ValueError("b653_provider_mutation_authority_exposed")
    current_hash = _provider_snapshot_sha256(provider_load)
    if current_hash != plan.provider_snapshot_sha256:
        raise ValueError("b653_provider_snapshot_drift")
    return current_hash


def _validate_target_revalidation(
    plan: planning.ResolutionActionPlan,
    evidence: TargetRevalidation,
    *,
    now: float,
    require_after: float | None = None,
) -> str:
    evidence.validate()
    if _normalized_locator(evidence.locator) != _normalized_locator(plan.target.locator):
        raise ValueError("b653_target_locator_drift")
    if evidence.observed_sha256.casefold() != str(plan.target.sha256).casefold():
        raise ValueError("b653_target_sha256_drift")
    if evidence.observed_at > now + 1.0:
        raise ValueError("b653_revalidation_from_future")
    if now - evidence.observed_at > MAX_REVALIDATION_AGE_SECONDS:
        raise ValueError("b653_revalidation_too_old")
    if require_after is not None and evidence.observed_at < require_after:
        raise ValueError("b653_confirmation_revalidation_precedes_request")
    return _sha256_payload(evidence.to_dict())


def build_confirmation_request(
    plan: planning.ResolutionActionPlan,
    provider_load: boundary.ProviderLoadResult,
    initial_revalidation: TargetRevalidation,
    *,
    now: float | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    nonce: str | None = None,
) -> ConfirmationRequest:
    """Create a short-lived confirmation request without granting execution authority."""

    current_time = float(time.time() if now is None else now)
    ttl = int(ttl_seconds)
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        raise ValueError("b653_confirmation_ttl_invalid")
    _validate_plan_for_confirmation(plan)
    provider_hash = _validate_provider_binding(plan, provider_load)
    revalidation_hash = _validate_target_revalidation(plan, initial_revalidation, now=current_time)
    request_nonce = str(nonce or secrets.token_hex(16)).strip()
    if len(request_nonce) < 16:
        raise ValueError("b653_confirmation_nonce_too_short")

    draft = ConfirmationRequest(
        request_id="",
        request_sha256="",
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        requested_action=plan.requested_action,
        finding_id=plan.finding_id,
        target_locator=plan.target.locator,
        target_sha256=str(plan.target.sha256).casefold(),
        target_fingerprint=plan.target.fingerprint.casefold(),
        provider_snapshot_sha256=provider_hash,
        initial_revalidation_sha256=revalidation_hash,
        issued_at=current_time,
        expires_at=current_time + ttl,
        nonce=request_nonce,
    )
    request_hash = _sha256_payload(draft.canonical_without_hash())
    request = ConfirmationRequest(
        **{
            **draft.__dict__,
            "request_id": REQUEST_PREFIX + request_hash[:16].upper(),
            "request_sha256": request_hash,
        }
    )
    request.validate()
    return request


def record_explicit_decision(
    request: ConfirmationRequest,
    plan: planning.ResolutionActionPlan,
    provider_load: boundary.ProviderLoadResult,
    confirmation_revalidation: TargetRevalidation,
    *,
    decision: str,
    now: float | None = None,
) -> ConfirmationReceipt:
    """Record CONFIRM/REFUSE explicitly; never turn that decision into execution authority."""

    request.validate()
    _validate_plan_for_confirmation(plan)
    current_time = float(time.time() if now is None else now)
    normalized_decision = str(decision or "").strip().upper()
    if normalized_decision not in DECISIONS:
        raise ValueError("b653_explicit_confirm_or_refuse_required")
    if request.plan_id != plan.plan_id or request.plan_sha256 != plan.plan_sha256:
        raise ValueError("b653_request_plan_drift")
    if request.requested_action != plan.requested_action or request.finding_id != plan.finding_id:
        raise ValueError("b653_request_context_drift")
    if _normalized_locator(request.target_locator) != _normalized_locator(plan.target.locator):
        raise ValueError("b653_request_target_locator_drift")
    if request.target_sha256.casefold() != str(plan.target.sha256).casefold():
        raise ValueError("b653_request_target_sha256_drift")
    if request.target_fingerprint.casefold() != plan.target.fingerprint.casefold():
        raise ValueError("b653_request_target_fingerprint_drift")

    provider_hash = _validate_provider_binding(plan, provider_load)
    if provider_hash != request.provider_snapshot_sha256:
        raise ValueError("b653_request_provider_snapshot_drift")
    revalidation_hash = _validate_target_revalidation(
        plan,
        confirmation_revalidation,
        now=current_time,
        require_after=request.issued_at,
    )

    if normalized_decision == DECISION_REFUSE:
        state = STATE_REFUSED
        confirmed = False
    elif current_time > request.expires_at:
        state = STATE_EXPIRED
        confirmed = False
    else:
        state = STATE_CONFIRMED_NOT_EXECUTABLE
        confirmed = True

    draft = ConfirmationReceipt(
        receipt_id="",
        receipt_sha256="",
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        requested_action=plan.requested_action,
        finding_id=plan.finding_id,
        decision=normalized_decision,
        state=state,
        decided_at=current_time,
        confirmation_revalidation_sha256=revalidation_hash,
        provider_snapshot_sha256=provider_hash,
        explicit_human_decision=True,
        confirmed=confirmed,
    )
    receipt_hash = _sha256_payload(draft.canonical_without_hash())
    receipt = ConfirmationReceipt(
        **{
            **draft.__dict__,
            "receipt_id": RECEIPT_PREFIX + receipt_hash[:16].upper(),
            "receipt_sha256": receipt_hash,
        }
    )
    receipt.validate()
    return receipt


def validate_b653_confirmation_contract() -> dict:
    """Static release-gate contract. Confirmation remains strictly non-executing."""

    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": True,
        "confirmation_requires_explicit_intent": True,
        "implicit_confirmation": False,
        "confirmation_ttl_seconds": DEFAULT_TTL_SECONDS,
        "maximum_confirmation_ttl_seconds": MAX_TTL_SECONDS,
        "target_revalidation_required_at_request": True,
        "target_revalidation_required_at_confirmation": True,
        "provider_snapshot_revalidation_required": True,
        "plan_integrity_binding_required": True,
        "target_sha256_binding_required": True,
        "target_fingerprint_semantics_revalidated": True,
        "confirmed_state": STATE_CONFIRMED_NOT_EXECUTABLE,
        "confirmation_is_execution_authority": False,
        "execution_api": False,
        "execution_authorized": False,
        "execution_nonce_issued": False,
        "journal_write_authority": False,
        "rollback_execution_authority": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "execution_owned_by": "B6-5.4+",
    }
