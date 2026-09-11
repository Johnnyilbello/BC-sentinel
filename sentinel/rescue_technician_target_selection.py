from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, Iterable

from sentinel import rescue_target_discovery as b50
from sentinel import rescue_technician_ui_model as b60

PROFILE: Final[str] = "v0.11.0-beta.6-b61"
SCHEMA: Final[str] = "bc-sentinel-beta6-target-selection-ui-v1"

TARGET_STATES: Final[tuple[str, ...]] = (
    b50.STATE_READY,
    b50.STATE_LOCKED,
    b50.STATE_ACCESS_DENIED,
    b50.STATE_INCOMPLETE,
    b50.STATE_UNSUPPORTED,
    b50.STATE_ERROR,
)

_GUIDANCE: Final[dict[str, str]] = {
    b50.STATE_READY: "Validated offline Windows target. Explicit selection is allowed.",
    b50.STATE_LOCKED: "Volume appears locked. Unlock is not offered by BC Sentinel.",
    b50.STATE_ACCESS_DENIED: "Access is restricted. Review permissions outside the rescue workflow.",
    b50.STATE_INCOMPLETE: "Windows markers are incomplete. Do not treat this target as repair-ready.",
    b50.STATE_UNSUPPORTED: "This location is not a supported offline Windows rescue target.",
    b50.STATE_ERROR: "Discovery could not classify this target safely. Review diagnostics before continuing.",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TargetChoice:
    root: str
    normalized_root: str
    discovery_source: str
    state: str
    reason: str
    target_fingerprint: str
    bitlocker_locked: bool | None
    selectable: bool
    guidance: str
    write_attempted: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DiscoveryUiSnapshot:
    profile: str
    schema: str
    engine_profile: str
    session_id: str
    correlation_id: str
    counts: dict[str, int]
    targets: tuple[TargetChoice, ...]
    read_only: bool
    unlock_offered: bool
    mount_write_offered: bool

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["targets"] = [item.to_dict() for item in self.targets]
        return payload


def _bool_or_none(value: object) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _validate_safety(result: dict) -> list[str]:
    safety = dict(result.get("safety") or {})
    failures: list[str] = []
    expected_true = ("read_only_discovery",)
    expected_false = (
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
    for key in expected_true:
        if safety.get(key) is not True:
            failures.append(f"safety_not_true:{key}")
    for key in expected_false:
        if safety.get(key) is not False:
            failures.append(f"safety_not_false:{key}")
    return failures


def validate_discovery_result(result: dict) -> dict:
    failures: list[str] = []
    if str(result.get("schema")) != b50.RESULT_SCHEMA:
        failures.append("discovery_schema_mismatch")
    if str(result.get("profile")) != b50.PROFILE:
        failures.append("discovery_profile_mismatch")
    failures.extend(_validate_safety(result))

    candidates = result.get("candidates")
    if not isinstance(candidates, list):
        failures.append("candidates_not_list")
        candidates = []

    seen_roots: set[str] = set()
    choices: list[TargetChoice] = []
    for index, raw in enumerate(candidates):
        if not isinstance(raw, dict):
            failures.append(f"candidate_{index}_not_object")
            continue
        state = str(raw.get("state") or "")
        normalized = str(raw.get("normalized_root") or "")
        root = str(raw.get("root") or "")
        reason = str(raw.get("reason") or "")
        fingerprint = str(raw.get("target_fingerprint") or "").lower()
        write_attempted = bool(raw.get("write_attempted"))
        if state not in TARGET_STATES:
            failures.append(f"candidate_{index}_unknown_state:{state}")
        key = normalized.casefold()
        if not normalized:
            failures.append(f"candidate_{index}_normalized_root_empty")
        elif key in seen_roots:
            failures.append(f"candidate_{index}_duplicate_root")
        else:
            seen_roots.add(key)
        if write_attempted:
            failures.append(f"candidate_{index}_write_attempted")
        if state == b50.STATE_READY and not _SHA256_RE.fullmatch(fingerprint):
            failures.append(f"candidate_{index}_ready_fingerprint_invalid")
        if state != b50.STATE_READY and fingerprint:
            failures.append(f"candidate_{index}_nonready_fingerprint_present")
        if reason == "live_system_volume_refused" and state != b50.STATE_UNSUPPORTED:
            failures.append(f"candidate_{index}_live_system_not_unsupported")

        bitlocker = raw.get("bitlocker") if isinstance(raw.get("bitlocker"), dict) else {}
        selectable = state == b50.STATE_READY and bool(_SHA256_RE.fullmatch(fingerprint)) and not write_attempted
        choices.append(
            TargetChoice(
                root=root,
                normalized_root=normalized,
                discovery_source=str(raw.get("discovery_source") or ""),
                state=state,
                reason=reason,
                target_fingerprint=fingerprint,
                bitlocker_locked=_bool_or_none(bitlocker.get("locked")),
                selectable=selectable,
                guidance=_GUIDANCE.get(state, _GUIDANCE[b50.STATE_ERROR]),
                write_attempted=write_attempted,
            )
        )

    counts_raw = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    counts = {state: int(counts_raw.get(state, 0) or 0) for state in TARGET_STATES}
    actual_counts = {state: sum(1 for item in choices if item.state == state) for state in TARGET_STATES}
    if counts != actual_counts:
        failures.append("discovery_counts_mismatch")

    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "engine_profile": b50.PROFILE,
        "passed": not failures,
        "failures": failures,
        "choices": choices,
        "counts": counts,
        "session_id": str(result.get("session_id") or ""),
        "correlation_id": str(result.get("correlation_id") or ""),
    }


def snapshot_from_result(result: dict) -> DiscoveryUiSnapshot:
    validated = validate_discovery_result(result)
    if not validated["passed"]:
        raise ValueError("B6-1 discovery result refused:" + ";".join(validated["failures"]))
    return DiscoveryUiSnapshot(
        profile=PROFILE,
        schema=SCHEMA,
        engine_profile=b50.PROFILE,
        session_id=validated["session_id"],
        correlation_id=validated["correlation_id"],
        counts=dict(validated["counts"]),
        targets=tuple(validated["choices"]),
        read_only=True,
        unlock_offered=False,
        mount_write_offered=False,
    )


def run_discovery(
    explicit_roots: Iterable[Path] = (),
    *,
    include_windows_volumes: bool = True,
    limits: b50.DiscoveryLimits | None = None,
    bitlocker_probe=None,
) -> DiscoveryUiSnapshot:
    result = b50.discover_targets(
        explicit_roots,
        include_windows_volumes=include_windows_volumes,
        limits=limits,
        bitlocker_probe=bitlocker_probe,
    )
    return snapshot_from_result(result)


def select_target(
    snapshot: DiscoveryUiSnapshot,
    index: int,
    *,
    ui_state: b60.TechnicianUiState | None = None,
) -> b60.TechnicianUiState:
    if not (0 <= int(index) < len(snapshot.targets)):
        raise ValueError("target_index_out_of_range")
    choice = snapshot.targets[int(index)]
    if not choice.selectable or choice.state != b50.STATE_READY:
        raise ValueError(f"target_not_selectable:{choice.state}:{choice.reason}")
    if not _SHA256_RE.fullmatch(choice.target_fingerprint):
        raise ValueError("target_fingerprint_invalid")

    state = ui_state or b60.initial_state()
    state.selected_target = choice.normalized_root
    state.target_fingerprint = choice.target_fingerprint
    state.session_id = snapshot.session_id
    state.correlation_id = snapshot.correlation_id
    state.last_command = "discover"
    state.last_engine_state = choice.state
    state.last_reason = "operator_selected_ready_target"
    state.state = "READY"
    state.busy = False
    state.validate()
    return state


def safety_contract() -> dict:
    return {
        "profile": PROFILE,
        "read_only_discovery": True,
        "explicit_operator_selection_required": True,
        "ready_only_selection": True,
        "unlock_offered": False,
        "mount_write_offered": False,
        "automatic_target_selection": False,
        "automatic_repair": False,
        "automatic_destructive_action": False,
        "target_execution": False,
    }
