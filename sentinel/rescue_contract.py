from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Final


PROFILE: Final[str] = "v0.11.0-beta.3-rr0"
MAX_WORKERS_HARD_LIMIT: Final[int] = 8
MAX_INFLIGHT_HARD_LIMIT: Final[int] = 256


class RescueExecutionContext(str, Enum):
    COMPROMISED_WINDOWS = "compromised_windows"
    TRUSTED_EXTERNAL_MEDIA = "trusted_external_media"
    OFFLINE_IMAGE = "offline_image"


class RescueCapability(str, Enum):
    ACQUIRE_EVIDENCE = "acquire_evidence"
    INSPECT_FILESYSTEM = "inspect_filesystem"
    INSPECT_REGISTRY = "inspect_registry"
    EXPORT_EVIDENCE = "export_evidence"
    PLAN_QUARANTINE = "plan_quarantine"
    PLAN_REPAIR = "plan_repair"


class RescueStage(str, Enum):
    SESSION_START = "session_start"
    TRUST_ASSESSMENT = "trust_assessment"
    TARGET_DISCOVERY = "target_discovery"
    EVIDENCE_ACQUISITION = "evidence_acquisition"
    FILESYSTEM_INSPECTION = "filesystem_inspection"
    REGISTRY_INSPECTION = "registry_inspection"
    PLAN_GENERATION = "plan_generation"
    INTEGRITY_ASSESSMENT = "integrity_assessment"
    SESSION_CLOSE = "session_close"


@dataclass(frozen=True)
class RescueSafetyPolicy:
    profile: str = PROFILE
    read_only_default: bool = True
    allow_destructive_actions: bool = False
    allow_file_delete: bool = False
    allow_process_kill: bool = False
    allow_host_isolation: bool = False
    allow_registry_write: bool = False
    allow_boot_write: bool = False
    allow_filesystem_write: bool = False
    allow_recovery_certification: bool = False
    require_operator_confirmation_for_future_mutation: bool = True
    require_rollback_plan_for_future_mutation: bool = True
    require_provenance_for_future_mutation: bool = True
    evidence_hash_algorithm: str = "sha256"
    max_workers: int = 4
    max_inflight_items: int = 128

    def validate(self) -> None:
        unsafe = {
            "read_only_default": not self.read_only_default,
            "allow_destructive_actions": self.allow_destructive_actions,
            "allow_file_delete": self.allow_file_delete,
            "allow_process_kill": self.allow_process_kill,
            "allow_host_isolation": self.allow_host_isolation,
            "allow_registry_write": self.allow_registry_write,
            "allow_boot_write": self.allow_boot_write,
            "allow_filesystem_write": self.allow_filesystem_write,
            "allow_recovery_certification": self.allow_recovery_certification,
            "require_operator_confirmation_for_future_mutation": not self.require_operator_confirmation_for_future_mutation,
            "require_rollback_plan_for_future_mutation": not self.require_rollback_plan_for_future_mutation,
            "require_provenance_for_future_mutation": not self.require_provenance_for_future_mutation,
        }
        enabled_unsafe = sorted(name for name, is_unsafe in unsafe.items() if is_unsafe)
        if enabled_unsafe:
            raise ValueError("RR0 unsafe policy: " + ", ".join(enabled_unsafe))
        if self.evidence_hash_algorithm.casefold() != "sha256":
            raise ValueError("RR0 evidence hash algorithm must remain sha256")
        if not (1 <= int(self.max_workers) <= MAX_WORKERS_HARD_LIMIT):
            raise ValueError("RR0 max_workers outside bounded limit")
        if not (1 <= int(self.max_inflight_items) <= MAX_INFLIGHT_HARD_LIMIT):
            raise ValueError("RR0 max_inflight_items outside bounded limit")


@dataclass(frozen=True)
class RescueSessionManifest:
    session_id: str
    correlation_id: str
    execution_context: RescueExecutionContext
    target_fingerprint: str
    created_utc: str
    policy_profile: str = PROFILE
    evidence_hash_algorithm: str = "sha256"
    write_authorized: bool = False
    recovery_certification_available: bool = False

    def __post_init__(self) -> None:
        for name in ("session_id", "correlation_id", "target_fingerprint", "created_utc"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"RR0 manifest field required: {name}")
        if self.policy_profile != PROFILE:
            raise ValueError("RR0 manifest profile mismatch")
        if self.evidence_hash_algorithm.casefold() != "sha256":
            raise ValueError("RR0 manifest evidence hash must be sha256")
        if self.write_authorized:
            raise ValueError("RR0 sessions may not authorize writes")
        if self.recovery_certification_available:
            raise ValueError("RR0 may not certify recovery")

    def to_record(self) -> dict:
        record = asdict(self)
        record["execution_context"] = self.execution_context.value
        return record


@dataclass(frozen=True)
class RescueAuditRecord:
    session_id: str
    correlation_id: str
    stage: RescueStage
    component: str
    status: str
    reason: str
    target: str = ""
    duration_ms: float = 0.0

    def __post_init__(self) -> None:
        for name in ("session_id", "correlation_id", "component", "status", "reason"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"RR0 audit field required: {name}")
        if float(self.duration_ms) < 0:
            raise ValueError("RR0 audit duration may not be negative")

    def to_record(self) -> dict:
        record = asdict(self)
        record["stage"] = self.stage.value
        return record


_CONTEXT_CAPABILITIES: Final[dict[RescueExecutionContext, frozenset[RescueCapability]]] = {
    RescueExecutionContext.COMPROMISED_WINDOWS: frozenset(
        {
            RescueCapability.ACQUIRE_EVIDENCE,
            RescueCapability.INSPECT_FILESYSTEM,
            RescueCapability.INSPECT_REGISTRY,
            RescueCapability.EXPORT_EVIDENCE,
        }
    ),
    RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA: frozenset(
        {
            RescueCapability.ACQUIRE_EVIDENCE,
            RescueCapability.INSPECT_FILESYSTEM,
            RescueCapability.INSPECT_REGISTRY,
            RescueCapability.EXPORT_EVIDENCE,
            RescueCapability.PLAN_QUARANTINE,
            RescueCapability.PLAN_REPAIR,
        }
    ),
    RescueExecutionContext.OFFLINE_IMAGE: frozenset(
        {
            RescueCapability.ACQUIRE_EVIDENCE,
            RescueCapability.INSPECT_FILESYSTEM,
            RescueCapability.INSPECT_REGISTRY,
            RescueCapability.EXPORT_EVIDENCE,
            RescueCapability.PLAN_QUARANTINE,
            RescueCapability.PLAN_REPAIR,
        }
    ),
}


def allowed_capabilities(context: RescueExecutionContext) -> frozenset[RescueCapability]:
    return _CONTEXT_CAPABILITIES[RescueExecutionContext(context)]


def can_certify_recovery(context: RescueExecutionContext) -> bool:
    RescueExecutionContext(context)
    return False


def rr0_contract_snapshot() -> dict:
    policy = RescueSafetyPolicy()
    policy.validate()
    return {
        "profile": PROFILE,
        "read_only_default": policy.read_only_default,
        "destructive_actions_enabled": policy.allow_destructive_actions,
        "recovery_certification_enabled": policy.allow_recovery_certification,
        "evidence_hash_algorithm": policy.evidence_hash_algorithm,
        "max_workers": policy.max_workers,
        "max_inflight_items": policy.max_inflight_items,
        "contexts": {
            context.value: sorted(capability.value for capability in allowed_capabilities(context))
            for context in RescueExecutionContext
        },
    }
