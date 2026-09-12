from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable, Final

from sentinel import rescue_target_discovery as discovery_engine
from sentinel import rescue_technician_ui_model as b60

PROFILE: Final[str] = "v0.11.0-beta.6-b61"
SCHEMA: Final[str] = "bc-sentinel-beta6-home-target-model-v1"

STATUS_RECOMMENDED: Final[str] = "RECOMMENDED"
STATUS_AVAILABLE: Final[str] = "AVAILABLE"
STATUS_NEEDS_ATTENTION: Final[str] = "NEEDS_ATTENTION"
STATUS_AMBIGUOUS: Final[str] = "AMBIGUOUS"
STATUS_UNSUPPORTED: Final[str] = "UNSUPPORTED"

TARGET_STATUSES: Final[tuple[str, ...]] = (
    STATUS_RECOMMENDED,
    STATUS_AVAILABLE,
    STATUS_NEEDS_ATTENTION,
    STATUS_AMBIGUOUS,
    STATUS_UNSUPPORTED,
)

HOME_STATES: Final[tuple[str, ...]] = (
    "IDLE",
    "DISCOVERING",
    "NO_TARGETS",
    "TARGETS_FOUND",
    "TARGET_SELECTED",
    "TARGET_NEEDS_ATTENTION",
    "TARGET_AMBIGUOUS",
    "TARGET_UNSUPPORTED",
    "DISCOVERY_ERROR",
)

SAFETY_FALSE_KEYS: Final[tuple[str, ...]] = (
    "write_attempted",
    "unlock_attempted",
    "mount_mutation",
    "format_disk",
    "partition_write",
    "bcd_write",
    "filesystem_repair",
    "target_execution",
    "service_install",
    "driver_install",
    "network_required",
    "cloud_required",
)


class DiscoverySafetyError(RuntimeError):
    pass


class TargetSelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class HomeTargetCard:
    target_id: str
    friendly_label: str
    location_label: str
    status: str
    explanation: str
    selectable: bool
    target_fingerprint: str
    normalized_root: str
    discovery_state: str
    reason: str
    advanced_details: dict

    def validate(self) -> None:
        if self.status not in TARGET_STATUSES:
            raise ValueError(f"unknown_target_status:{self.status}")
        if self.selectable and self.status not in {STATUS_RECOMMENDED, STATUS_AVAILABLE}:
            raise ValueError("non_selectable_status_marked_selectable")
        if self.selectable and not self.target_fingerprint:
            raise ValueError("selectable_target_requires_fingerprint")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class HomeDiscoveryView:
    session_id: str
    correlation_id: str
    created_utc: str
    targets: tuple[HomeTargetCard, ...]
    recommended_target_id: str = ""
    explicit_selection_required: bool = False
    raw_safety: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "created_utc": self.created_utc,
            "targets": [target.to_dict() for target in self.targets],
            "recommended_target_id": self.recommended_target_id,
            "explicit_selection_required": self.explicit_selection_required,
            "raw_safety": dict(self.raw_safety),
        }


@dataclass
class HomeUiState:
    state: str = "IDLE"
    selected_target_id: str = ""
    selected_target_root: str = ""
    selected_target_fingerprint: str = ""
    selection_revalidated: bool = False
    last_reason: str = ""

    def validate(self) -> None:
        if self.state not in HOME_STATES:
            raise ValueError(f"unknown_home_state:{self.state}")
        if self.state == "TARGET_SELECTED":
            if not self.selected_target_id or not self.selected_target_fingerprint:
                raise ValueError("selected_state_requires_target_identity")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


def validate_engine_contract() -> dict:
    """B6-1 must preserve the accepted B6-0/Beta5 safety contract."""
    contract = b60.validate_engine_contract()
    failures = list(contract.get("failures", ()))
    safety = dict(contract.get("safety", {}))
    if contract.get("passed") is not True:
        failures.append("b60_contract_not_green")
    if any(bool(value) for value in safety.values()):
        failures.append("b60_safety_boundary_changed")
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "parent_contract": contract,
        "startup_dispatch": False,
        "automatic_discovery": False,
        "automatic_selection": False,
        "automatic_rescue_dispatch": False,
    }


def validate_discovery_safety(payload: dict) -> None:
    safety = dict(payload.get("safety") or {})
    if safety.get("read_only_discovery") is not True:
        raise DiscoverySafetyError("read_only_discovery_not_true")
    for key in SAFETY_FALSE_KEYS:
        if safety.get(key) is not False:
            raise DiscoverySafetyError(f"unsafe_discovery_flag:{key}")


def _target_id(record: dict) -> str:
    fingerprint = str(record.get("target_fingerprint") or "").strip()
    root = str(record.get("normalized_root") or record.get("root") or "").strip().casefold()
    if fingerprint:
        return f"fp:{fingerprint}|root:{root}"
    return f"root:{root}"


def _location_label(record: dict) -> str:
    return str(record.get("root") or record.get("normalized_root") or "Unknown location")


def _friendly_label(record: dict) -> str:
    root = _location_label(record)
    if len(root) >= 2 and root[1:2] == ":":
        return f"Windows installation ({root[:2].upper()})"
    return "Windows installation"


def _plain_explanation(state: str, reason: str) -> str:
    if state == discovery_engine.STATE_READY:
        return "Windows was validated and can be selected for read-only analysis."
    if state == discovery_engine.STATE_LOCKED:
        return "This Windows volume is locked or encrypted. BC Sentinel will not attempt to unlock it automatically."
    if state == discovery_engine.STATE_ACCESS_DENIED:
        return "BC Sentinel cannot safely read enough information from this volume."
    if state == discovery_engine.STATE_INCOMPLETE:
        return "Windows appears to be present, but some required system evidence is missing or damaged."
    if state == discovery_engine.STATE_UNSUPPORTED:
        if reason == "live_system_volume_refused":
            return "This is the currently running Windows volume and is not an offline Rescue target."
        if reason == "no_windows_markers":
            return "No supported offline Windows installation was found on this volume."
        return "This target is not supported by the current Rescue workflow."
    return "BC Sentinel could not validate this target safely."


def _confidence(state: str) -> str:
    if state == discovery_engine.STATE_READY:
        return "HIGH"
    if state == discovery_engine.STATE_INCOMPLETE:
        return "MEDIUM"
    return "LOW"


def _base_status(state: str) -> str:
    if state == discovery_engine.STATE_READY:
        return STATUS_AVAILABLE
    if state in {
        discovery_engine.STATE_LOCKED,
        discovery_engine.STATE_ACCESS_DENIED,
        discovery_engine.STATE_INCOMPLETE,
        discovery_engine.STATE_ERROR,
    }:
        return STATUS_NEEDS_ATTENTION
    return STATUS_UNSUPPORTED


def _advanced_details(record: dict) -> dict:
    bitlocker = dict(record.get("bitlocker") or {})
    return {
        "physical_disk_identifier": record.get("physical_disk_identifier"),
        "partition_identifier": record.get("partition_identifier"),
        "partition_table_or_type": record.get("partition_table_or_type"),
        "volume_identifier": record.get("volume_identifier"),
        "filesystem": record.get("filesystem"),
        "mount_state": record.get("mount_state"),
        "read_only_state": True,
        "windows_root_candidate": record.get("normalized_root") or record.get("root"),
        "windows_version_build_evidence": record.get("windows_version_build_evidence"),
        "encryption_bitlocker_state": bitlocker,
        "unlock_state": "LOCKED" if bitlocker.get("locked") is True else "NOT_UNLOCKED_BY_BC_SENTINEL",
        "discovery_confidence": _confidence(str(record.get("state") or "")),
        "discovery_source": record.get("discovery_source"),
        "discovery_evidence": {
            "markers_present": list(record.get("markers_present") or ()),
            "markers_missing": list(record.get("markers_missing") or ()),
            "elapsed_ms": record.get("elapsed_ms"),
            "write_attempted": record.get("write_attempted"),
        },
        "fingerprint_target_identity": record.get("target_fingerprint"),
        "supported_or_unsupported_reason": record.get("reason"),
        "ambiguity_reason": "",
        "raw_record": dict(record),
    }


def build_discovery_view(payload: dict) -> HomeDiscoveryView:
    validate_discovery_safety(payload)
    records = [dict(row) for row in payload.get("candidates") or ()]

    ready_fingerprints: dict[str, list[int]] = {}
    for index, record in enumerate(records):
        if str(record.get("state")) != discovery_engine.STATE_READY:
            continue
        fingerprint = str(record.get("target_fingerprint") or "").strip()
        if fingerprint:
            ready_fingerprints.setdefault(fingerprint, []).append(index)

    duplicate_ready_indexes = {
        index
        for indexes in ready_fingerprints.values()
        if len(indexes) > 1
        for index in indexes
    }
    unique_ready_indexes = [
        index
        for index, record in enumerate(records)
        if str(record.get("state")) == discovery_engine.STATE_READY
        and index not in duplicate_ready_indexes
    ]
    recommended_index = unique_ready_indexes[0] if len(unique_ready_indexes) == 1 else None

    cards: list[HomeTargetCard] = []
    for index, record in enumerate(records):
        state = str(record.get("state") or "")
        reason = str(record.get("reason") or "")
        status = _base_status(state)
        details = _advanced_details(record)
        explanation = _plain_explanation(state, reason)

        if index in duplicate_ready_indexes:
            status = STATUS_AMBIGUOUS
            details["ambiguity_reason"] = "duplicate_target_fingerprint"
            explanation = "The same Windows identity was discovered through more than one target path. Selection is blocked until the ambiguity is resolved."
        elif recommended_index == index:
            status = STATUS_RECOMMENDED

        fingerprint = str(record.get("target_fingerprint") or "").strip()
        selectable = status in {STATUS_RECOMMENDED, STATUS_AVAILABLE} and bool(fingerprint)
        card = HomeTargetCard(
            target_id=_target_id(record),
            friendly_label=_friendly_label(record),
            location_label=_location_label(record),
            status=status,
            explanation=explanation,
            selectable=selectable,
            target_fingerprint=fingerprint,
            normalized_root=str(record.get("normalized_root") or record.get("root") or ""),
            discovery_state=state,
            reason=reason,
            advanced_details=details,
        )
        card.validate()
        cards.append(card)

    recommended_id = cards[recommended_index].target_id if recommended_index is not None else ""
    selectable_count = sum(1 for card in cards if card.selectable)
    return HomeDiscoveryView(
        session_id=str(payload.get("session_id") or ""),
        correlation_id=str(payload.get("correlation_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
        targets=tuple(cards),
        recommended_target_id=recommended_id,
        explicit_selection_required=selectable_count > 1,
        raw_safety=dict(payload.get("safety") or {}),
    )


def initial_state() -> HomeUiState:
    state = HomeUiState()
    state.validate()
    return state


def discovery_state_for(view: HomeDiscoveryView) -> str:
    if not view.targets:
        return "NO_TARGETS"
    if any(target.status in {STATUS_RECOMMENDED, STATUS_AVAILABLE} for target in view.targets):
        return "TARGETS_FOUND"
    if any(target.status == STATUS_AMBIGUOUS for target in view.targets):
        return "TARGET_AMBIGUOUS"
    if any(target.status == STATUS_NEEDS_ATTENTION for target in view.targets):
        return "TARGET_NEEDS_ATTENTION"
    return "TARGET_UNSUPPORTED"


def select_target(state: HomeUiState, view: HomeDiscoveryView, target_id: str) -> HomeUiState:
    target = next((row for row in view.targets if row.target_id == target_id), None)
    if target is None:
        raise TargetSelectionError("target_not_found")
    if not target.selectable:
        raise TargetSelectionError(f"target_not_selectable:{target.status}")
    state.state = "TARGET_SELECTED"
    state.selected_target_id = target.target_id
    state.selected_target_root = target.normalized_root
    state.selected_target_fingerprint = target.target_fingerprint
    state.selection_revalidated = False
    state.last_reason = "explicit_user_selection"
    state.validate()
    return state


def revalidate_selection(state: HomeUiState, fresh_payload: dict) -> HomeUiState:
    if state.state != "TARGET_SELECTED" or not state.selected_target_fingerprint:
        raise TargetSelectionError("no_selected_target")
    fresh_view = build_discovery_view(fresh_payload)
    candidates = [
        row for row in fresh_view.targets
        if row.normalized_root.casefold() == state.selected_target_root.casefold()
    ]
    if len(candidates) != 1:
        raise TargetSelectionError("selected_target_missing_or_ambiguous")
    fresh = candidates[0]
    if not fresh.selectable:
        raise TargetSelectionError(f"selected_target_no_longer_selectable:{fresh.status}")
    if fresh.target_fingerprint != state.selected_target_fingerprint:
        raise TargetSelectionError("selected_target_identity_changed")
    state.selection_revalidated = True
    state.last_reason = "target_identity_revalidated"
    state.validate()
    return state


def run_operator_discovery(provider: Callable[[], dict] | None = None) -> HomeDiscoveryView:
    payload = provider() if provider is not None else discovery_engine.discover_targets()
    return build_discovery_view(payload)
