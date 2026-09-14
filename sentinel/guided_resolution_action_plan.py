from __future__ import annotations

"""B6-5.2 planning-only reversible action-plan and journal contract.

This checkpoint can bind a future mutating action proposal to one accepted B6-4
Threat Card and to the passive B6-5.1 provider capability snapshot.  It cannot
execute, confirm, quarantine, repair, delete, terminate a process, mutate trust,
or write a journal.  Those authorities belong to later separately accepted
checkpoints.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Final

from sentinel import guided_resolution_provider_loader as boundary
from sentinel import home_guided_resolution as guided
from sentinel import home_threat_cards as threat

PROFILE: Final[str] = "v0.11.0-beta.6-b65.2-action-plan"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-action-plan-v1"
JOURNAL_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-journal-blueprint-v1"
ROLLBACK_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-rollback-blueprint-v1"

PLAN_PREFIX: Final[str] = "B652-"
PLAN_STATUS_PLANNED_NOT_AUTHORIZED: Final[str] = "PLANNED_NOT_AUTHORIZED"
PLAN_STATUS_BLOCKED_TARGET_IDENTITY: Final[str] = "BLOCKED_TARGET_IDENTITY"
PLAN_STATUSES: Final[frozenset[str]] = frozenset(
    {PLAN_STATUS_PLANNED_NOT_AUTHORIZED, PLAN_STATUS_BLOCKED_TARGET_IDENTITY}
)

TARGET_KIND_FILE: Final[str] = "FILE"
TARGET_KIND_UNSUPPORTED: Final[str] = "UNSUPPORTED"
TARGET_IDENTITY_VERIFIED: Final[str] = "VERIFIED_SHA256"
TARGET_IDENTITY_UNVERIFIED: Final[str] = "UNVERIFIED"
TARGET_IDENTITY_AMBIGUOUS: Final[str] = "AMBIGUOUS"

JOURNAL_STAGES: Final[tuple[str, ...]] = (
    "PLAN_CREATED",
    "PRE_STATE_REQUIRED",
    "CONFIRMATION_REQUIRED",
    "ACTION_STARTED",
    "ACTION_RESULT",
    "POST_STATE_REQUIRED",
    "VERIFY_RESULT",
    "ROLLBACK_STARTED_ON_FAILURE",
    "ROLLBACK_RESULT",
    "FINAL_OUTCOME",
)


@dataclass(frozen=True)
class TargetBinding:
    kind: str
    locator: str
    identity_state: str
    sha256: str | None
    fingerprint: str
    evidence_source: str

    def validate(self) -> None:
        if self.kind not in {TARGET_KIND_FILE, TARGET_KIND_UNSUPPORTED}:
            raise ValueError("b652_target_kind_invalid")
        if not self.locator.strip():
            raise ValueError("b652_target_locator_required")
        if self.identity_state not in {
            TARGET_IDENTITY_VERIFIED,
            TARGET_IDENTITY_UNVERIFIED,
            TARGET_IDENTITY_AMBIGUOUS,
        }:
            raise ValueError("b652_target_identity_state_invalid")
        if self.identity_state == TARGET_IDENTITY_VERIFIED:
            if not _is_sha256(self.sha256):
                raise ValueError("b652_verified_target_sha256_required")
            if not _is_sha256(self.fingerprint):
                raise ValueError("b652_target_fingerprint_invalid")
        else:
            if self.sha256 is not None:
                raise ValueError("b652_unverified_target_must_not_choose_sha256")
            if self.fingerprint:
                raise ValueError("b652_unverified_target_must_not_have_fingerprint")


@dataclass(frozen=True)
class JournalBlueprint:
    schema: str = JOURNAL_SCHEMA
    status: str = "BLUEPRINT_ONLY"
    append_only_required: bool = True
    pre_state_required: bool = True
    post_state_required: bool = True
    verification_record_required: bool = True
    rollback_records_required: bool = True
    storage_binding: str = "NOT_BOUND"
    required_stages: tuple[str, ...] = JOURNAL_STAGES

    def validate(self) -> None:
        if self.schema != JOURNAL_SCHEMA or self.status != "BLUEPRINT_ONLY":
            raise ValueError("b652_journal_blueprint_invalid")
        if not all(
            (
                self.append_only_required,
                self.pre_state_required,
                self.post_state_required,
                self.verification_record_required,
                self.rollback_records_required,
            )
        ):
            raise ValueError("b652_journal_safety_requirement_missing")
        if self.storage_binding != "NOT_BOUND":
            raise ValueError("b652_journal_storage_must_remain_unbound")
        if self.required_stages != JOURNAL_STAGES:
            raise ValueError("b652_journal_stages_mismatch")


@dataclass(frozen=True)
class RollbackBlueprint:
    schema: str = ROLLBACK_SCHEMA
    status: str = "REQUIRED_NOT_BOUND"
    snapshot_required: bool = True
    protected_or_external_store_required: bool = True
    restore_verification_required: bool = True
    rollback_on_failure_required: bool = True
    rollback_binding: str = "NOT_BOUND"

    def validate(self) -> None:
        if self.schema != ROLLBACK_SCHEMA or self.status != "REQUIRED_NOT_BOUND":
            raise ValueError("b652_rollback_blueprint_invalid")
        if not all(
            (
                self.snapshot_required,
                self.protected_or_external_store_required,
                self.restore_verification_required,
                self.rollback_on_failure_required,
            )
        ):
            raise ValueError("b652_rollback_requirement_missing")
        if self.rollback_binding != "NOT_BOUND":
            raise ValueError("b652_rollback_store_must_remain_unbound")


@dataclass(frozen=True)
class ResolutionActionPlan:
    plan_id: str
    plan_sha256: str
    requested_action: str
    plan_status: str
    finding_id: str
    canonical_severity: str
    canonical_confidence: float | None
    source_card_sha256: str
    source_resolution_sha256: str
    provider_snapshot_sha256: str
    provider_name: str
    provider_profile: str
    provider_provenance: str
    provider_action_available: bool
    target: TargetBinding
    journal: JournalBlueprint
    rollback: RollbackBlueprint
    readiness_reasons: tuple[str, ...]
    authority_state: str = "PLANNING_ONLY"
    execution_authorized: bool = False
    confirmation_issued: bool = False
    automatic_action: bool = False
    destructive_authority: bool = False
    raw_binding: dict = field(default_factory=dict)

    def canonical_without_hash(self) -> dict:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "requested_action": self.requested_action,
            "plan_status": self.plan_status,
            "finding_id": self.finding_id,
            "canonical_severity": self.canonical_severity,
            "canonical_confidence": self.canonical_confidence,
            "source_card_sha256": self.source_card_sha256,
            "source_resolution_sha256": self.source_resolution_sha256,
            "provider_snapshot_sha256": self.provider_snapshot_sha256,
            "provider_name": self.provider_name,
            "provider_profile": self.provider_profile,
            "provider_provenance": self.provider_provenance,
            "provider_action_available": self.provider_action_available,
            "target": asdict(self.target),
            "journal": asdict(self.journal),
            "rollback": asdict(self.rollback),
            "readiness_reasons": list(self.readiness_reasons),
            "authority_state": self.authority_state,
            "execution_authorized": False,
            "confirmation_issued": False,
            "automatic_action": False,
            "destructive_authority": False,
            "raw_binding": dict(self.raw_binding),
        }

    def validate(self) -> None:
        if self.requested_action not in boundary.MUTATING_ACTIONS:
            raise ValueError("b652_plan_requires_known_mutating_action")
        if self.plan_status not in PLAN_STATUSES:
            raise ValueError("b652_plan_status_invalid")
        if not self.finding_id.strip():
            raise ValueError("b652_finding_id_required")
        if not _is_sha256(self.source_card_sha256):
            raise ValueError("b652_source_card_hash_invalid")
        if not _is_sha256(self.source_resolution_sha256):
            raise ValueError("b652_source_resolution_hash_invalid")
        if not _is_sha256(self.provider_snapshot_sha256):
            raise ValueError("b652_provider_snapshot_hash_invalid")
        if not all((self.provider_name, self.provider_profile, self.provider_provenance)):
            raise ValueError("b652_provider_identity_required")
        if self.provider_action_available:
            raise ValueError("b652_provider_mutating_action_must_remain_unavailable")
        if self.authority_state != "PLANNING_ONLY":
            raise ValueError("b652_authority_must_remain_planning_only")
        if self.execution_authorized or self.confirmation_issued or self.automatic_action or self.destructive_authority:
            raise ValueError("b652_execution_or_destructive_authority_forbidden")
        self.target.validate()
        self.journal.validate()
        self.rollback.validate()
        if not self.readiness_reasons:
            raise ValueError("b652_readiness_reasons_required")
        if self.target.identity_state == TARGET_IDENTITY_VERIFIED:
            if self.plan_status != PLAN_STATUS_PLANNED_NOT_AUTHORIZED:
                raise ValueError("b652_verified_target_plan_status_mismatch")
        elif self.plan_status != PLAN_STATUS_BLOCKED_TARGET_IDENTITY:
            raise ValueError("b652_unverified_target_must_be_blocked")
        expected_hash = _sha256_payload(self.canonical_without_hash())
        if expected_hash != self.plan_sha256:
            raise ValueError("b652_plan_integrity_mismatch")
        if self.plan_id != PLAN_PREFIX + self.plan_sha256[:16].upper():
            raise ValueError("b652_plan_id_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = self.canonical_without_hash()
        payload["plan_id"] = self.plan_id
        payload["plan_sha256"] = self.plan_sha256
        return payload


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _collect_sha256_evidence(value: object, *, key_hint: str = "") -> set[str]:
    """Collect only explicitly SHA-256-labelled evidence from one finding payload."""

    found: set[str] = set()
    normalized_hint = "".join(ch for ch in key_hint.casefold() if ch.isalnum())
    if isinstance(value, dict):
        for key, child in value.items():
            found.update(_collect_sha256_evidence(child, key_hint=str(key)))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.update(_collect_sha256_evidence(child, key_hint=key_hint))
    elif "sha256" in normalized_hint and _is_sha256(value):
        found.add(str(value).casefold())
    return found


def _bind_target(card: threat.ThreatCardModel) -> TargetBinding:
    finding_payload = card.advanced_details.get("finding")
    if not isinstance(finding_payload, dict):
        raise ValueError("b652_source_finding_required")
    path = str(finding_payload.get("path") or "").strip()
    if not path:
        locator = str(card.location or "").strip() or "Posizione non disponibile"
        return TargetBinding(
            kind=TARGET_KIND_UNSUPPORTED,
            locator=locator,
            identity_state=TARGET_IDENTITY_UNVERIFIED,
            sha256=None,
            fingerprint="",
            evidence_source="finding.path unavailable",
        )

    evidence = finding_payload.get("evidence")
    hashes = _collect_sha256_evidence(evidence if isinstance(evidence, dict) else {})
    if len(hashes) == 1:
        digest = next(iter(hashes))
        fingerprint = hashlib.sha256(
            _canonical_json({"kind": TARGET_KIND_FILE, "locator": path.casefold(), "sha256": digest})
        ).hexdigest()
        return TargetBinding(
            kind=TARGET_KIND_FILE,
            locator=path,
            identity_state=TARGET_IDENTITY_VERIFIED,
            sha256=digest,
            fingerprint=fingerprint,
            evidence_source="finding.evidence explicit sha256",
        )
    if len(hashes) > 1:
        return TargetBinding(
            kind=TARGET_KIND_FILE,
            locator=path,
            identity_state=TARGET_IDENTITY_AMBIGUOUS,
            sha256=None,
            fingerprint="",
            evidence_source="finding.evidence contains multiple sha256 values",
        )
    return TargetBinding(
        kind=TARGET_KIND_FILE,
        locator=path,
        identity_state=TARGET_IDENTITY_UNVERIFIED,
        sha256=None,
        fingerprint="",
        evidence_source="finding.evidence has no explicit sha256",
    )


def _provider_action(provider_load: boundary.ProviderLoadResult, action_id: str) -> dict:
    actions = provider_load.capability_snapshot.get("actions")
    if not isinstance(actions, list):
        raise ValueError("b652_provider_actions_missing")
    matches = [item for item in actions if isinstance(item, dict) and item.get("action_id") == action_id]
    if len(matches) != 1:
        raise ValueError("b652_provider_action_declaration_missing_or_ambiguous")
    action = dict(matches[0])
    if action.get("mutates_system") is not True:
        raise ValueError("b652_requested_action_not_declared_mutating")
    return action


def build_action_plan(
    card: threat.ThreatCardModel,
    resolution: guided.GuidedResolutionModel,
    provider_load: boundary.ProviderLoadResult,
    *,
    requested_action: str,
) -> ResolutionActionPlan:
    """Build an integrity-bound planning artifact; never authorize or execute it."""

    card.validate()
    resolution.validate()
    action_id = str(requested_action or "").strip().upper()
    if action_id not in boundary.MUTATING_ACTIONS:
        raise ValueError("b652_unknown_or_non_mutating_action")
    if provider_load.loaded is not True or provider_load.accepted is not True:
        raise ValueError("b652_capability_provider_boundary_not_accepted")
    if resolution.finding_id != card.finding_id:
        raise ValueError("b652_card_resolution_finding_mismatch")
    if resolution.canonical_severity != card.severity:
        raise ValueError("b652_card_resolution_severity_mismatch")
    if resolution.canonical_confidence != card.confidence:
        raise ValueError("b652_card_resolution_confidence_mismatch")
    if resolution.execution_available or resolution.authority_state != guided.AUTHORITY_REPORT_ONLY:
        raise ValueError("b652_source_resolution_authority_invalid")

    provider_action = _provider_action(provider_load, action_id)
    if provider_action.get("available") is not False:
        raise ValueError("b652_mutating_provider_action_must_still_be_unavailable")

    target = _bind_target(card)
    reasons = [
        "provider_mutating_action_currently_unavailable",
        "execution_authority_not_granted",
        "confirmation_not_issued",
        "rollback_not_bound",
        "journal_storage_not_bound",
    ]
    if target.identity_state == TARGET_IDENTITY_VERIFIED:
        plan_status = PLAN_STATUS_PLANNED_NOT_AUTHORIZED
        reasons.append("target_identity_bound_to_explicit_sha256")
    else:
        plan_status = PLAN_STATUS_BLOCKED_TARGET_IDENTITY
        reasons.append(f"target_identity_{target.identity_state.casefold()}")

    card_payload = card.to_dict()
    resolution_payload = resolution.to_dict()
    provider_payload = provider_load.to_dict()
    journal = JournalBlueprint()
    rollback = RollbackBlueprint()

    source_card_sha256 = _sha256_payload(card_payload)
    source_resolution_sha256 = _sha256_payload(resolution_payload)
    provider_snapshot_sha256 = _sha256_payload(provider_payload)

    raw_binding = {
        "source_card_schema": card_payload.get("schema"),
        "source_resolution_schema": resolution_payload.get("schema"),
        "provider_boundary_schema": provider_payload.get("schema"),
        "provider_action": provider_action,
        "capability_provider_boundary_verified": True,
        "remediation_provider_boundary_verified": False,
        "confirmation_owned_by": "B6-5.3",
        "execution_owned_by": "B6-5.4+",
    }

    draft = ResolutionActionPlan(
        plan_id="",
        plan_sha256="",
        requested_action=action_id,
        plan_status=plan_status,
        finding_id=card.finding_id,
        canonical_severity=card.severity,
        canonical_confidence=card.confidence,
        source_card_sha256=source_card_sha256,
        source_resolution_sha256=source_resolution_sha256,
        provider_snapshot_sha256=provider_snapshot_sha256,
        provider_name=provider_load.provider_name,
        provider_profile=provider_load.provider_profile,
        provider_provenance=provider_load.provider_provenance,
        provider_action_available=False,
        target=target,
        journal=journal,
        rollback=rollback,
        readiness_reasons=tuple(reasons),
        raw_binding=raw_binding,
    )
    plan_hash = _sha256_payload(draft.canonical_without_hash())
    plan = ResolutionActionPlan(
        **{
            **draft.__dict__,
            "plan_id": PLAN_PREFIX + plan_hash[:16].upper(),
            "plan_sha256": plan_hash,
        }
    )
    plan.validate()
    return plan


def validate_b652_planning_contract() -> dict:
    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": True,
        "authority": "PLANNING_ONLY",
        "execution_api": False,
        "execution_authorized": False,
        "confirmation_issued": False,
        "journal_write_authority": False,
        "rollback_execution_authority": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "target_sha256_required_for_bound_plan": True,
        "source_card_integrity_binding": True,
        "source_resolution_integrity_binding": True,
        "provider_snapshot_integrity_binding": True,
        "journal_blueprint_only": True,
        "rollback_blueprint_only": True,
    }
