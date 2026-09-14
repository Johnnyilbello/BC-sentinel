from __future__ import annotations

"""B6-5.1 fail-closed capability boundary for Guided Resolution.

This module deliberately supports capability introspection only.  It does not
expose an execution API and it rejects providers that expose one.  Live Home
remediation remains unauthorized until later B6-5 checkpoints separately prove
planning, rollback, explicit confirmation and harmless live execution.
"""

from dataclasses import dataclass, field
import importlib
from typing import Callable, Final

from sentinel import home_guided_resolution as guided

PROFILE: Final[str] = "v0.11.0-beta.6-b65.1-provider-boundary"
SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-provider-v1"
CAPABILITY_SCHEMA: Final[str] = "bc-sentinel-beta6-guided-resolution-capabilities-v1"

LIVE_PROVIDER_MODULE: Final[str] = "sentinel.guided_resolution_live_provider"
LIVE_PROVIDER_FACTORY: Final[str] = "create_provider"

KNOWN_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        guided.ACTION_REVIEW_DETAILS,
        "QUARANTINE",
        "REPAIR",
        "DELETE",
        "TERMINATE_PROCESS",
        "TRUST_OR_ALLOWLIST",
    }
)
MUTATING_ACTIONS: Final[frozenset[str]] = frozenset(
    {"QUARANTINE", "REPAIR", "DELETE", "TERMINATE_PROCESS", "TRUST_OR_ALLOWLIST"}
)
EXECUTION_API_NAMES: Final[tuple[str, ...]] = (
    "execute",
    "apply",
    "remediate",
    "quarantine",
    "repair",
    "delete",
    "terminate_process",
)


@dataclass(frozen=True)
class ProviderLoadResult:
    provider: object | None
    loaded: bool
    accepted: bool
    reason: str
    module_name: str = LIVE_PROVIDER_MODULE
    factory_name: str = LIVE_PROVIDER_FACTORY
    provider_name: str = ""
    provider_profile: str = ""
    provider_provenance: str = ""
    capability_snapshot: dict = field(default_factory=dict)
    failures: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "loaded": self.loaded,
            "accepted": self.accepted,
            "reason": self.reason,
            "module_name": self.module_name,
            "factory_name": self.factory_name,
            "provider_name": self.provider_name,
            "provider_profile": self.provider_profile,
            "provider_provenance": self.provider_provenance,
            "capability_snapshot": dict(self.capability_snapshot),
            "failures": list(self.failures),
            "execution_available": False,
            "automatic_action": False,
            "destructive_authority": False,
        }


def _fallback(reason: str, *, failures: tuple[str, ...] = ()) -> ProviderLoadResult:
    return ProviderLoadResult(
        provider=None,
        loaded=False,
        accepted=False,
        reason=reason,
        failures=failures,
    )


def _text_attr(provider: object, name: str) -> str:
    value = getattr(provider, name, "")
    return str(value or "").strip()


def validate_capability_provider(provider: object) -> dict:
    """Validate a passive provider without executing any remediation operation."""

    failures: list[str] = []
    provider_name = _text_attr(provider, "name")
    provider_profile = _text_attr(provider, "profile")
    provider_provenance = _text_attr(provider, "provenance")

    if not provider_name:
        failures.append("provider_name_missing")
    if not provider_profile:
        failures.append("provider_profile_missing")
    if not provider_provenance:
        failures.append("provider_provenance_missing")

    for method_name in EXECUTION_API_NAMES:
        if callable(getattr(provider, method_name, None)):
            failures.append(f"execution_api_present:{method_name}")

    capability_probe = getattr(provider, "capabilities", None)
    if not callable(capability_probe):
        failures.append("capability_probe_missing")
        return {
            "passed": False,
            "failures": failures,
            "provider_name": provider_name,
            "provider_profile": provider_profile,
            "provider_provenance": provider_provenance,
            "snapshot": {},
        }

    try:
        snapshot = capability_probe()
    except Exception as exc:
        failures.append(f"capability_probe_failed:{type(exc).__name__}")
        return {
            "passed": False,
            "failures": failures,
            "provider_name": provider_name,
            "provider_profile": provider_profile,
            "provider_provenance": provider_provenance,
            "snapshot": {},
        }

    if not isinstance(snapshot, dict):
        failures.append("capability_snapshot_not_mapping")
        snapshot = {}

    if snapshot.get("schema") != CAPABILITY_SCHEMA:
        failures.append("capability_schema_mismatch")
    if snapshot.get("accepted") is not True:
        failures.append("provider_not_accepted")
    if snapshot.get("available") is not True:
        failures.append("provider_not_available")
    if snapshot.get("side_effect_free_probe") is not True:
        failures.append("probe_not_declared_side_effect_free")
    if snapshot.get("execution_available") is not False:
        failures.append("execution_must_remain_unavailable")
    if snapshot.get("automatic_action") is not False:
        failures.append("automatic_action_must_be_false")
    if snapshot.get("destructive_authority") is not False:
        failures.append("destructive_authority_must_be_false")

    future_safety = snapshot.get("future_mutation_safety")
    if not isinstance(future_safety, dict):
        failures.append("future_mutation_safety_missing")
    else:
        if future_safety.get("explicit_confirmation_required") is not True:
            failures.append("future_confirmation_requirement_missing")
        if future_safety.get("rollback_required") is not True:
            failures.append("future_rollback_requirement_missing")
        if future_safety.get("journal_required") is not True:
            failures.append("future_journal_requirement_missing")
        if future_safety.get("target_revalidation_required") is not True:
            failures.append("future_target_revalidation_requirement_missing")

    actions = snapshot.get("actions")
    normalized_actions: list[dict] = []
    if not isinstance(actions, (list, tuple)) or not actions:
        failures.append("actions_missing")
    else:
        seen: set[str] = set()
        for index, item in enumerate(actions):
            if not isinstance(item, dict):
                failures.append(f"action_not_mapping:{index}")
                continue
            action_id = str(item.get("action_id") or "").strip()
            available = item.get("available")
            mutates_system = item.get("mutates_system")
            if not action_id:
                failures.append(f"action_id_missing:{index}")
                continue
            if action_id in seen:
                failures.append(f"duplicate_action:{action_id}")
            seen.add(action_id)
            if action_id not in KNOWN_ACTIONS:
                failures.append(f"unknown_action:{action_id}")
            if not isinstance(available, bool):
                failures.append(f"action_available_not_bool:{action_id}")
            if not isinstance(mutates_system, bool):
                failures.append(f"action_mutation_not_bool:{action_id}")
            if action_id in MUTATING_ACTIONS and mutates_system is not True:
                failures.append(f"mutating_action_not_marked_mutating:{action_id}")
            if action_id in MUTATING_ACTIONS and available is not False:
                failures.append(f"mutating_action_exposed:{action_id}")
            if action_id == guided.ACTION_REVIEW_DETAILS:
                if available is not True:
                    failures.append("review_details_must_be_available")
                if mutates_system is not False:
                    failures.append("review_details_must_be_non_mutating")
            normalized_actions.append(
                {
                    "action_id": action_id,
                    "available": bool(available) if isinstance(available, bool) else False,
                    "mutates_system": bool(mutates_system) if isinstance(mutates_system, bool) else False,
                    "reason": str(item.get("reason") or ""),
                }
            )

        if guided.ACTION_REVIEW_DETAILS not in seen:
            failures.append("review_details_action_missing")
        for action_id in MUTATING_ACTIONS:
            if action_id not in seen:
                failures.append(f"declared_mutating_action_missing:{action_id}")

    normalized_snapshot = {
        "schema": snapshot.get("schema"),
        "accepted": snapshot.get("accepted") is True,
        "available": snapshot.get("available") is True,
        "side_effect_free_probe": snapshot.get("side_effect_free_probe") is True,
        "execution_available": False,
        "automatic_action": False,
        "destructive_authority": False,
        "actions": normalized_actions,
        "future_mutation_safety": dict(future_safety) if isinstance(future_safety, dict) else {},
        "raw": dict(snapshot),
    }
    return {
        "passed": not failures,
        "failures": failures,
        "provider_name": provider_name,
        "provider_profile": provider_profile,
        "provider_provenance": provider_provenance,
        "snapshot": normalized_snapshot,
    }


def load_default_provider(
    *,
    import_module: Callable[[str], object] = importlib.import_module,
) -> ProviderLoadResult:
    """Load only the fixed B6-5.1 provider and perform a passive capability probe."""

    try:
        module = import_module(LIVE_PROVIDER_MODULE)
    except ModuleNotFoundError as exc:
        if exc.name == LIVE_PROVIDER_MODULE:
            return _fallback("guided_resolution_provider_module_missing")
        return _fallback(f"guided_resolution_provider_dependency_missing:{exc.name or 'unknown'}")
    except Exception as exc:
        return _fallback(f"guided_resolution_provider_import_failed:{type(exc).__name__}")

    factory = getattr(module, LIVE_PROVIDER_FACTORY, None)
    if not callable(factory):
        return _fallback("guided_resolution_provider_factory_missing")

    try:
        provider = factory()
    except Exception as exc:
        return _fallback(f"guided_resolution_provider_factory_failed:{type(exc).__name__}")
    if provider is None:
        return _fallback("guided_resolution_provider_factory_returned_none")

    validation = validate_capability_provider(provider)
    failures = tuple(str(item) for item in validation.get("failures") or [])
    if validation.get("passed") is not True:
        reason = "guided_resolution_provider_contract_rejected"
        if failures:
            reason += ":" + ",".join(failures)
        return ProviderLoadResult(
            provider=None,
            loaded=True,
            accepted=False,
            reason=reason,
            provider_name=str(validation.get("provider_name") or ""),
            provider_profile=str(validation.get("provider_profile") or ""),
            provider_provenance=str(validation.get("provider_provenance") or ""),
            capability_snapshot=dict(validation.get("snapshot") or {}),
            failures=failures,
        )

    return ProviderLoadResult(
        provider=provider,
        loaded=True,
        accepted=True,
        reason="accepted_passive_capability_provider",
        provider_name=str(validation.get("provider_name") or ""),
        provider_profile=str(validation.get("provider_profile") or ""),
        provider_provenance=str(validation.get("provider_provenance") or ""),
        capability_snapshot=dict(validation.get("snapshot") or {}),
        failures=(),
    )
