from __future__ import annotations

from dataclasses import asdict, dataclass, field
import importlib.util
from typing import Callable, Final, Mapping

from sentinel import rescue_home_ui_model as b61

PROFILE: Final[str] = "v0.11.0-beta.6-b62"
SCHEMA: Final[str] = "bc-sentinel-beta6-home-security-overview-v1"

STATUS_ACTIVE: Final[str] = "ACTIVE"
STATUS_READY: Final[str] = "READY"
STATUS_ENGINE_AVAILABLE: Final[str] = "ENGINE_AVAILABLE"
STATUS_UNAVAILABLE: Final[str] = "STATUS_UNAVAILABLE"
STATUS_ATTENTION: Final[str] = "ATTENTION"
STATUS_OFF: Final[str] = "OFF"

STATUSES: Final[tuple[str, ...]] = (
    STATUS_ACTIVE,
    STATUS_READY,
    STATUS_ENGINE_AVAILABLE,
    STATUS_UNAVAILABLE,
    STATUS_ATTENTION,
    STATUS_OFF,
)

POSTURE_PROTECTED: Final[str] = "PROTECTED"
POSTURE_ATTENTION: Final[str] = "ATTENTION"
POSTURE_UNVERIFIED: Final[str] = "UNVERIFIED"

LAYER_MALWARE: Final[str] = "malware"
LAYER_BEHAVIOR: Final[str] = "behavior_edr"
LAYER_WEB: Final[str] = "web"
LAYER_RECOVERY: Final[str] = "recovery"

REQUIRED_RUNTIME_LAYERS: Final[tuple[str, ...]] = (
    LAYER_MALWARE,
    LAYER_BEHAVIOR,
    LAYER_WEB,
)

SOURCE_MODULES: Final[Mapping[str, tuple[str, ...]]] = {
    LAYER_MALWARE: ("sentinel.advanced_antimalware",),
    LAYER_BEHAVIOR: ("sentinel.edr", "sentinel.edr_service_bridge"),
    LAYER_WEB: ("sentinel.web_deception", "sentinel.web_clone_scam", "sentinel.web_response"),
    LAYER_RECOVERY: ("sentinel.rescue_home_ui", "sentinel.rescue_home_ui_model"),
}

LAYER_COPY: Final[Mapping[str, tuple[str, str]]] = {
    LAYER_MALWARE: (
        "Malware protection",
        "File and antimalware engines available to BC Sentinel.",
    ),
    LAYER_BEHAVIOR: (
        "Behavior & EDR",
        "Behavioral and endpoint telemetry components.",
    ),
    LAYER_WEB: (
        "Web protection",
        "Web reputation, deception and anti-scam components.",
    ),
    LAYER_RECOVERY: (
        "System & Recovery",
        "Windows system discovery and offline Rescue entry point.",
    ),
}

STATUS_LABELS: Final[Mapping[str, str]] = {
    STATUS_ACTIVE: "Active",
    STATUS_READY: "Ready",
    STATUS_ENGINE_AVAILABLE: "Engine available",
    STATUS_UNAVAILABLE: "Status unavailable",
    STATUS_ATTENTION: "Needs attention",
    STATUS_OFF: "Off",
}


@dataclass(frozen=True)
class LayerEvidence:
    layer_id: str
    status: str
    runtime_verified: bool
    summary: str
    raw: dict = field(default_factory=dict)
    provenance: str = ""

    def validate(self) -> None:
        if self.layer_id not in SOURCE_MODULES:
            raise ValueError(f"unknown_layer:{self.layer_id}")
        if self.status not in STATUSES:
            raise ValueError(f"unknown_status:{self.status}")
        if self.status == STATUS_ACTIVE and not self.runtime_verified:
            raise ValueError("active_requires_runtime_verification")
        if self.status == STATUS_OFF and not self.runtime_verified:
            raise ValueError("off_requires_runtime_verification")


@dataclass(frozen=True)
class HomeProtectionCard:
    card_id: str
    label: str
    description: str
    status: str
    status_label: str
    summary: str
    runtime_verified: bool
    action_enabled: bool
    action_label: str
    advanced_details: dict
    provenance: str

    def validate(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown_card_status:{self.status}")
        if self.status == STATUS_ACTIVE and not self.runtime_verified:
            raise ValueError("card_active_requires_runtime_verification")
        if self.status == STATUS_ENGINE_AVAILABLE and self.runtime_verified:
            raise ValueError("engine_available_is_not_runtime_verified")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class HomeSecuritySnapshot:
    posture: str
    posture_label: str
    headline: str
    summary: str
    cards: tuple[HomeProtectionCard, ...]
    smart_scan_enabled: bool = False
    smart_scan_label: str = "Smart Scan — coming in B6-3"
    recent_activity_state: str = STATUS_UNAVAILABLE
    recent_activity_summary: str = "Activity history is not connected to the B6-2 Home yet."
    raw_evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "posture": self.posture,
            "posture_label": self.posture_label,
            "headline": self.headline,
            "summary": self.summary,
            "cards": [card.to_dict() for card in self.cards],
            "smart_scan_enabled": self.smart_scan_enabled,
            "smart_scan_label": self.smart_scan_label,
            "recent_activity_state": self.recent_activity_state,
            "recent_activity_summary": self.recent_activity_summary,
            "raw_evidence": dict(self.raw_evidence),
        }


def _module_availability(layer_id: str) -> dict:
    modules = SOURCE_MODULES[layer_id]
    availability = {name: importlib.util.find_spec(name) is not None for name in modules}
    return {
        "modules": list(modules),
        "available": availability,
        "all_available": all(availability.values()),
    }


def default_evidence_provider() -> dict[str, LayerEvidence]:
    """Return passive capability evidence only; never infer live protection from source presence."""
    evidence: dict[str, LayerEvidence] = {}
    for layer_id in (LAYER_MALWARE, LAYER_BEHAVIOR, LAYER_WEB):
        capability = _module_availability(layer_id)
        if capability["all_available"]:
            status = STATUS_ENGINE_AVAILABLE
            summary = "The engine is present, but this Home does not yet have accepted runtime proof that protection is active."
        else:
            status = STATUS_UNAVAILABLE
            summary = "BC Sentinel cannot verify the complete engine inventory for this protection layer."
        evidence[layer_id] = LayerEvidence(
            layer_id=layer_id,
            status=status,
            runtime_verified=False,
            summary=summary,
            raw=capability,
            provenance="passive_module_inventory",
        )

    recovery_capability = _module_availability(LAYER_RECOVERY)
    recovery_contract = b61.validate_engine_contract()
    recovery_ready = bool(recovery_capability["all_available"] and recovery_contract.get("passed"))
    evidence[LAYER_RECOVERY] = LayerEvidence(
        layer_id=LAYER_RECOVERY,
        status=STATUS_READY if recovery_ready else STATUS_UNAVAILABLE,
        runtime_verified=recovery_ready,
        summary=(
            "System & Recovery is available. Opening it does not start discovery or Rescue automatically."
            if recovery_ready
            else "System & Recovery is not currently available through the accepted B6-1 contract."
        ),
        raw={
            "module_inventory": recovery_capability,
            "b61_contract_passed": bool(recovery_contract.get("passed")),
            "startup_dispatch": recovery_contract.get("startup_dispatch"),
            "automatic_discovery": recovery_contract.get("automatic_discovery"),
            "automatic_rescue_dispatch": recovery_contract.get("automatic_rescue_dispatch"),
        },
        provenance="b61_passive_contract",
    )
    return evidence


def _normalize_provider_payload(payload: Mapping[str, LayerEvidence | Mapping]) -> dict[str, LayerEvidence]:
    normalized: dict[str, LayerEvidence] = {}
    for layer_id in SOURCE_MODULES:
        raw = payload.get(layer_id)
        if raw is None:
            normalized[layer_id] = LayerEvidence(
                layer_id=layer_id,
                status=STATUS_UNAVAILABLE,
                runtime_verified=False,
                summary="No accepted status evidence was supplied for this layer.",
                raw={},
                provenance="missing_provider_evidence",
            )
        elif isinstance(raw, LayerEvidence):
            normalized[layer_id] = raw
        else:
            normalized[layer_id] = LayerEvidence(
                layer_id=layer_id,
                status=str(raw.get("status") or STATUS_UNAVAILABLE),
                runtime_verified=bool(raw.get("runtime_verified", False)),
                summary=str(raw.get("summary") or "Status evidence supplied by provider."),
                raw=dict(raw.get("raw") or {}),
                provenance=str(raw.get("provenance") or "injected_provider"),
            )
        normalized[layer_id].validate()
    return normalized


def _overall_posture(evidence: Mapping[str, LayerEvidence]) -> tuple[str, str, str, str]:
    required = [evidence[layer_id] for layer_id in REQUIRED_RUNTIME_LAYERS]
    if any(item.status in {STATUS_ATTENTION, STATUS_OFF} and item.runtime_verified for item in required):
        return (
            POSTURE_ATTENTION,
            "Attention needed",
            "BC Sentinel found a protection state that needs attention.",
            "Review the affected protection layer before relying on the current protection posture.",
        )
    if required and all(item.status == STATUS_ACTIVE and item.runtime_verified for item in required):
        return (
            POSTURE_PROTECTED,
            "Protection verified",
            "Core protection is verified active.",
            "BC Sentinel has current runtime evidence for the core protection layers shown below.",
        )
    return (
        POSTURE_UNVERIFIED,
        "Status not fully verified",
        "BC Sentinel is ready, but live protection status is not fully verified yet.",
        "Available engines are shown separately from live runtime proof. This Home will never mark the PC protected without current evidence.",
    )


def build_snapshot(
    provider: Callable[[], Mapping[str, LayerEvidence | Mapping]] | None = None,
) -> HomeSecuritySnapshot:
    raw_payload = provider() if provider is not None else default_evidence_provider()
    evidence = _normalize_provider_payload(raw_payload)
    posture, posture_label, headline, summary = _overall_posture(evidence)

    cards: list[HomeProtectionCard] = []
    for layer_id in (LAYER_MALWARE, LAYER_BEHAVIOR, LAYER_WEB, LAYER_RECOVERY):
        item = evidence[layer_id]
        label, description = LAYER_COPY[layer_id]
        action_enabled = layer_id == LAYER_RECOVERY and item.status == STATUS_READY
        action_label = "Open System & Recovery" if layer_id == LAYER_RECOVERY else "Runtime controls not enabled in B6-2"
        card = HomeProtectionCard(
            card_id=layer_id,
            label=label,
            description=description,
            status=item.status,
            status_label=STATUS_LABELS[item.status],
            summary=item.summary,
            runtime_verified=item.runtime_verified,
            action_enabled=action_enabled,
            action_label=action_label,
            advanced_details={
                "layer_id": layer_id,
                "status": item.status,
                "runtime_verified": item.runtime_verified,
                "raw_evidence": dict(item.raw),
                "provenance": item.provenance,
            },
            provenance=item.provenance,
        )
        card.validate()
        cards.append(card)

    snapshot = HomeSecuritySnapshot(
        posture=posture,
        posture_label=posture_label,
        headline=headline,
        summary=summary,
        cards=tuple(cards),
        smart_scan_enabled=False,
        raw_evidence={layer_id: asdict(item) for layer_id, item in evidence.items()},
    )
    return snapshot


def validate_b62_safety_contract() -> dict:
    parent = b61.validate_engine_contract()
    failures: list[str] = []
    if parent.get("passed") is not True:
        failures.append("b61_contract_not_green")
    for key in ("startup_dispatch", "automatic_discovery", "automatic_selection", "automatic_rescue_dispatch"):
        if parent.get(key) is not False:
            failures.append(f"b61_safety_changed:{key}")
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "parent_b61": parent,
        "startup_scan_dispatch": False,
        "startup_rescue_dispatch": False,
        "automatic_repair": False,
        "automatic_quarantine": False,
        "destructive_authority_added": False,
        "smart_scan_enabled": False,
    }
