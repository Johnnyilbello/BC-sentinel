from __future__ import annotations

"""B6-5.0 passive Guided Resolution decision model.

This checkpoint explains the safest next step for an accepted B6-4 Threat Card.
It deliberately has no remediation provider and no mutation authority.  The
purpose is to make the future action gate explicit before any execution path is
introduced.
"""

from dataclasses import asdict, dataclass, field
from typing import Final

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat

PROFILE: Final[str] = "v0.11.0-beta.6-b65.0-guided-resolution"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-v1"

REVIEW_REQUIRED: Final[str] = "REVIEW_REQUIRED"
EVIDENCE_INCOMPLETE: Final[str] = "EVIDENCE_INCOMPLETE"
REVIEW_STATES: Final[frozenset[str]] = frozenset({REVIEW_REQUIRED, EVIDENCE_INCOMPLETE})

AUTHORITY_REPORT_ONLY: Final[str] = "REPORT_ONLY"
ACTION_REVIEW_DETAILS: Final[str] = "REVIEW_DETAILS"

EVIDENCE_PRESENT: Final[str] = "PRESENT"
EVIDENCE_PARTIAL: Final[str] = "PARTIAL"
CONFIDENCE_PRESENT: Final[str] = "PRESENT"
CONFIDENCE_UNAVAILABLE: Final[str] = "UNAVAILABLE"
REVERSIBILITY_UNVERIFIED: Final[str] = "UNVERIFIED"
POTENTIAL_DAMAGE_UNDEFINED: Final[str] = "UNDEFINED_UNTIL_ACTION_DEFINED"


@dataclass(frozen=True)
class ResolutionCapability:
    capability_id: str
    label: str
    available: bool
    mutates_system: bool
    reason: str

    def validate(self) -> None:
        if not self.capability_id.strip() or not self.label.strip():
            raise ValueError("b65_capability_identity_required")
        if self.available and self.mutates_system:
            raise ValueError("b65_mutating_capability_must_not_be_available_in_b650")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class GuidedResolutionModel:
    finding_id: str
    title: str
    canonical_severity: str
    canonical_confidence: float | None
    review_state: str
    authority_state: str
    recommended_action: str
    headline: str
    next_step: str
    reasons: tuple[str, ...]
    evidence_strength: str
    confidence_state: str
    reversibility: str
    potential_damage: str
    execution_available: bool
    confirmation_required_for_mutation: bool
    rollback_required_for_mutation: bool
    provider_boundary_verified: bool
    capabilities: tuple[ResolutionCapability, ...]
    advanced_details: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("b65_finding_id_required")
        if self.canonical_severity not in smart.SEVERITIES:
            raise ValueError(f"b65_unknown_severity:{self.canonical_severity}")
        if self.canonical_confidence is not None and not (0.0 <= float(self.canonical_confidence) <= 1.0):
            raise ValueError("b65_confidence_out_of_range")
        if self.review_state not in REVIEW_STATES:
            raise ValueError(f"b65_unknown_review_state:{self.review_state}")
        if self.authority_state != AUTHORITY_REPORT_ONLY:
            raise ValueError("b65_authority_must_remain_report_only")
        if self.recommended_action != ACTION_REVIEW_DETAILS:
            raise ValueError("b65_only_review_action_is_allowed")
        if self.execution_available:
            raise ValueError("b65_execution_must_be_unavailable")
        if self.provider_boundary_verified:
            raise ValueError("b65_remediation_provider_boundary_not_yet_verified")
        if not self.confirmation_required_for_mutation or not self.rollback_required_for_mutation:
            raise ValueError("b65_future_mutation_requires_confirmation_and_rollback")
        if self.reversibility != REVERSIBILITY_UNVERIFIED:
            raise ValueError("b65_reversibility_must_remain_unverified")
        if self.potential_damage != POTENTIAL_DAMAGE_UNDEFINED:
            raise ValueError("b65_potential_damage_must_remain_undefined_without_action")
        for capability in self.capabilities:
            capability.validate()
        if any(item.available and item.mutates_system for item in self.capabilities):
            raise ValueError("b65_mutating_capability_exposed")

        source_card = self.advanced_details.get("threat_card")
        if not isinstance(source_card, dict):
            raise ValueError("b65_source_threat_card_required")
        if str(source_card.get("finding_id") or "") != self.finding_id:
            raise ValueError("b65_source_finding_mismatch")
        if str(source_card.get("severity") or "") != self.canonical_severity:
            raise ValueError("b65_source_severity_mismatch")
        if source_card.get("confidence") != self.canonical_confidence:
            raise ValueError("b65_source_confidence_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = asdict(self)
        payload["schema"] = SCHEMA
        payload["profile"] = PROFILE
        return payload


def _capabilities() -> tuple[ResolutionCapability, ...]:
    return (
        ResolutionCapability(
            ACTION_REVIEW_DETAILS,
            "Esamina i dettagli",
            True,
            False,
            "Disponibile: mostra soltanto evidenza e guida, senza modificare il sistema.",
        ),
        ResolutionCapability(
            "QUARANTINE",
            "Metti in quarantena",
            False,
            True,
            "Non disponibile in B6-5.0: provider, reversibilità e rollback non sono ancora verificati.",
        ),
        ResolutionCapability(
            "REPAIR",
            "Ripara",
            False,
            True,
            "Non disponibile in B6-5.0: nessun piano di riparazione live è autorizzato.",
        ),
        ResolutionCapability(
            "DELETE",
            "Elimina",
            False,
            True,
            "Non disponibile in B6-5.0: azione distruttiva non autorizzata.",
        ),
        ResolutionCapability(
            "TERMINATE_PROCESS",
            "Termina processo",
            False,
            True,
            "Non disponibile in B6-5.0: nessuna autorità di terminazione è esposta.",
        ),
        ResolutionCapability(
            "TRUST_OR_ALLOWLIST",
            "Considera attendibile",
            False,
            True,
            "Non disponibile in B6-5.0: nessuna mutazione di trust/allowlist è esposta.",
        ),
    )


def build_guided_resolution(card: threat.ThreatCardModel) -> GuidedResolutionModel:
    """Create a fail-closed, report-only resolution recommendation."""

    card.validate()
    advanced = dict(card.advanced_details)
    coverage = str(advanced.get("coverage") or "")
    scan_state = str(advanced.get("scan_state") or "")
    source_result = advanced.get("source_check_result")

    reasons: list[str] = []
    evidence_strength = EVIDENCE_PRESENT
    review_state = REVIEW_REQUIRED

    if coverage != smart.COVERAGE_COMPLETE:
        review_state = EVIDENCE_INCOMPLETE
        evidence_strength = EVIDENCE_PARTIAL
        reasons.append("scan_coverage_not_complete")
    if scan_state in {smart.STATE_CANCELLED, smart.STATE_INCOMPLETE, smart.STATE_FAILED}:
        review_state = EVIDENCE_INCOMPLETE
        evidence_strength = EVIDENCE_PARTIAL
        reasons.append(f"scan_state_{scan_state.casefold()}")
    if not isinstance(source_result, dict):
        review_state = EVIDENCE_INCOMPLETE
        evidence_strength = EVIDENCE_PARTIAL
        reasons.append("source_check_result_unavailable")

    if card.confidence is None:
        confidence_state = CONFIDENCE_UNAVAILABLE
        reasons.append("canonical_confidence_unavailable")
    else:
        confidence_state = CONFIDENCE_PRESENT
        reasons.append("canonical_confidence_preserved")

    reasons.append("live_remediation_provider_not_verified")
    reasons.append("system_mutation_not_authorized")

    if review_state == EVIDENCE_INCOMPLETE:
        headline = "Prima di intervenire serve completare o verificare le prove"
        next_step = (
            "Apri Dettagli avanzati e verifica il rilevamento. Non eseguire modifiche automatiche: "
            "la copertura o l'evidenza disponibile non consente una decisione di intervento affidabile."
        )
    else:
        headline = "Rilevamento da verificare prima di qualsiasi intervento"
        next_step = (
            "Esamina le prove tecniche e il contesto del rilevamento. B6-5.0 non autorizza ancora "
            "quarantena, riparazione, eliminazione o terminazione di processi."
        )

    capabilities = _capabilities()
    gate = {
        "confidence": card.confidence,
        "confidence_state": confidence_state,
        "severity": card.severity,
        "evidence_strength": evidence_strength,
        "reversibility": REVERSIBILITY_UNVERIFIED,
        "potential_damage": POTENTIAL_DAMAGE_UNDEFINED,
        "provider_boundary_verified": False,
        "execution_authorized": False,
        "decision": AUTHORITY_REPORT_ONLY,
        "reasons": list(reasons),
    }

    model = GuidedResolutionModel(
        finding_id=card.finding_id,
        title=card.title,
        canonical_severity=card.severity,
        canonical_confidence=card.confidence,
        review_state=review_state,
        authority_state=AUTHORITY_REPORT_ONLY,
        recommended_action=ACTION_REVIEW_DETAILS,
        headline=headline,
        next_step=next_step,
        reasons=tuple(reasons),
        evidence_strength=evidence_strength,
        confidence_state=confidence_state,
        reversibility=REVERSIBILITY_UNVERIFIED,
        potential_damage=POTENTIAL_DAMAGE_UNDEFINED,
        execution_available=False,
        confirmation_required_for_mutation=True,
        rollback_required_for_mutation=True,
        provider_boundary_verified=False,
        capabilities=capabilities,
        advanced_details={
            "schema": SCHEMA,
            "profile": PROFILE,
            "threat_card": card.to_dict(),
            "confidence_gate": gate,
            "capabilities": [item.to_dict() for item in capabilities],
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
            "execution_performed": False,
        },
    )
    model.validate()
    return model


def validate_b650_guided_resolution_contract() -> dict:
    """Static authority contract for the passive first B6-5 checkpoint."""

    capabilities = _capabilities()
    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": True,
        "authority": AUTHORITY_REPORT_ONLY,
        "remediation_provider_boundary_verified": False,
        "execution_available": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "delete_authorized": False,
        "process_termination_authorized": False,
        "trust_mutation_authorized": False,
        "confirmation_required_for_future_mutation": True,
        "rollback_required_for_future_mutation": True,
        "available_capabilities": [item.capability_id for item in capabilities if item.available],
    }
