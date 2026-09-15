from __future__ import annotations

"""B6-4 truthful threat-card presentation model.

This layer is intentionally presentation-only. It never changes scanner severity,
confidence, evidence, scan coverage, or remediation authority.
"""

from dataclasses import asdict, dataclass, field
from typing import Final

from sentinel import home_smart_scan as smart

PROFILE: Final[str] = "v0.11.0-beta.6-b64"
SCHEMA: Final[str] = "bc-sentinel-beta6-threat-card-v1"

SEVERITY_LABELS: Final[dict[str, str]] = {
    smart.SEVERITY_INFO: "Informazione",
    smart.SEVERITY_LOW: "Bassa",
    smart.SEVERITY_MEDIUM: "Media",
    smart.SEVERITY_HIGH: "Alta",
    smart.SEVERITY_CRITICAL: "Critica",
}

SEVERITY_ROLES: Final[dict[str, str]] = {
    smart.SEVERITY_INFO: "neutral",
    smart.SEVERITY_LOW: "attention",
    smart.SEVERITY_MEDIUM: "attention",
    smart.SEVERITY_HIGH: "danger",
    smart.SEVERITY_CRITICAL: "danger",
}


@dataclass(frozen=True)
class ThreatCardModel:
    finding_id: str
    title: str
    severity: str
    severity_label: str
    severity_role: str
    category: str
    reason: str
    source_check_id: str
    location: str
    confidence: float | None
    confidence_label: str
    recommendation: str
    advanced_details: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("threat_card_finding_id_required")
        if self.severity not in smart.SEVERITIES:
            raise ValueError(f"threat_card_unknown_severity:{self.severity}")
        if self.severity_label != SEVERITY_LABELS[self.severity]:
            raise ValueError("threat_card_severity_label_mismatch")
        if self.severity_role != SEVERITY_ROLES[self.severity]:
            raise ValueError("threat_card_severity_role_mismatch")
        if not self.source_check_id.strip():
            raise ValueError("threat_card_source_check_required")
        if self.confidence is not None and not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("threat_card_confidence_out_of_range")
        finding_payload = self.advanced_details.get("finding")
        if not isinstance(finding_payload, dict):
            raise ValueError("threat_card_advanced_finding_required")
        if str(finding_payload.get("finding_id") or "") != self.finding_id:
            raise ValueError("threat_card_advanced_finding_mismatch")
        if str(finding_payload.get("severity") or "") != self.severity:
            raise ValueError("threat_card_advanced_severity_mismatch")
        original_confidence = finding_payload.get("confidence")
        if original_confidence != self.confidence:
            raise ValueError("threat_card_advanced_confidence_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        payload = asdict(self)
        payload["schema"] = SCHEMA
        payload["profile"] = PROFILE
        return payload


def _confidence_label(value: float | None) -> str:
    if value is None:
        return "Non disponibile"
    return f"{float(value) * 100:.0f}%"


def _location(finding: smart.SmartScanFinding) -> str:
    for value in (finding.path, finding.process, finding.indicator):
        text = str(value or "").strip()
        if text:
            return text
    return "Posizione non disponibile"


def _title(finding: smart.SmartScanFinding) -> str:
    text = str(finding.title or "").strip()
    return text if text else "Elemento rilevato"


def _category(finding: smart.SmartScanFinding) -> str:
    text = str(finding.category or "").strip()
    return text if text else "Categoria non disponibile"


def _reason(finding: smart.SmartScanFinding) -> str:
    text = str(finding.reason or "").strip()
    return text if text else "Il provider non ha fornito una motivazione sintetica."


def build_threat_card(
    result: smart.SmartScanResult,
    finding: smart.SmartScanFinding,
) -> ThreatCardModel:
    """Build one truthful review card without altering finding semantics."""

    result.validate()
    finding.validate()

    source_result = next(
        (item for item in result.check_results if item.check_id == finding.source_check_id),
        None,
    )

    advanced_details = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "session_id": result.session_id,
        "correlation_id": result.correlation_id,
        "scan_state": result.state,
        "coverage": result.coverage,
        "provider_name": result.provider_name,
        "provider_profile": result.provider_profile,
        "provider_provenance": result.provider_provenance,
        "finding": finding.to_dict(),
        "source_check_result": source_result.to_dict() if source_result is not None else None,
        "scan_raw_evidence": dict(result.raw_evidence),
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
    }

    card = ThreatCardModel(
        finding_id=finding.finding_id,
        title=_title(finding),
        severity=finding.severity,
        severity_label=SEVERITY_LABELS[finding.severity],
        severity_role=SEVERITY_ROLES[finding.severity],
        category=_category(finding),
        reason=_reason(finding),
        source_check_id=finding.source_check_id,
        location=_location(finding),
        confidence=finding.confidence,
        confidence_label=_confidence_label(finding.confidence),
        recommendation=(
            str(result.recommendation or "").strip()
            or "Esamina i dettagli prima di qualsiasi azione."
        ),
        advanced_details=advanced_details,
    )
    card.validate()
    return card


def build_threat_cards(result: smart.SmartScanResult) -> tuple[ThreatCardModel, ...]:
    """Preserve provider/result finding order; introduce no ranking engine."""

    result.validate()
    return tuple(build_threat_card(result, finding) for finding in result.findings)


def validate_b64_presentation_contract() -> dict:
    """Static authority/truth contract for B6-4 presentation work."""

    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": True,
        "severity_mutation": False,
        "confidence_inference": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "guided_resolution_enabled": False,
        "per_card_advanced_details": True,
        "scan_level_advanced_details_preserved": True,
    }
