from __future__ import annotations

"""Fail-closed loader for the optional B6-3 live Smart Scan provider.

The connected GitHub repository is a synchronized delta and does not contain the
complete historical Windows scanner runtime.  The Home therefore looks for one
fixed adapter module that may exist in the complete local Windows source tree:
``sentinel.smart_scan_live_provider``.

Loading this module never starts a scan.  A provider is exposed only when its
capability contract is accepted and explicitly non-destructive.
"""

from dataclasses import dataclass
import importlib
from typing import Callable, Final

from sentinel import home_smart_scan as smart

LIVE_PROVIDER_MODULE: Final[str] = "sentinel.smart_scan_live_provider"
LIVE_PROVIDER_FACTORY: Final[str] = "create_provider"


@dataclass(frozen=True)
class ProviderLoadResult:
    provider: smart.SmartScanProvider
    loaded: bool
    accepted: bool
    reason: str
    module_name: str = LIVE_PROVIDER_MODULE
    factory_name: str = LIVE_PROVIDER_FACTORY
    provider_name: str = ""
    provider_profile: str = ""
    provider_provenance: str = ""

    def to_dict(self) -> dict:
        return {
            "loaded": self.loaded,
            "accepted": self.accepted,
            "reason": self.reason,
            "module_name": self.module_name,
            "factory_name": self.factory_name,
            "provider_name": self.provider_name,
            "provider_profile": self.provider_profile,
            "provider_provenance": self.provider_provenance,
        }


def _fallback(reason: str) -> ProviderLoadResult:
    provider = smart.UnavailableSmartScanProvider(reason=reason)
    capability = smart.validate_provider_capabilities(provider)
    return ProviderLoadResult(
        provider=provider,
        loaded=False,
        accepted=False,
        reason=reason,
        provider_name=str(capability.get("provider_name") or ""),
        provider_profile=str(capability.get("provider_profile") or ""),
        provider_provenance=str(capability.get("provider_provenance") or ""),
    )


def load_default_provider(
    *,
    import_module: Callable[[str], object] = importlib.import_module,
) -> ProviderLoadResult:
    """Load the one approved adapter location without planning or running a scan."""

    try:
        module = import_module(LIVE_PROVIDER_MODULE)
    except ModuleNotFoundError as exc:
        if exc.name == LIVE_PROVIDER_MODULE:
            return _fallback("live_provider_module_not_synchronized")
        return _fallback(f"live_provider_dependency_missing:{exc.name or 'unknown'}")
    except Exception as exc:
        return _fallback(f"live_provider_import_failed:{type(exc).__name__}")

    factory = getattr(module, LIVE_PROVIDER_FACTORY, None)
    if not callable(factory):
        return _fallback("live_provider_factory_missing")

    try:
        provider = factory()
    except Exception as exc:
        return _fallback(f"live_provider_factory_failed:{type(exc).__name__}")

    if provider is None:
        return _fallback("live_provider_factory_returned_none")

    try:
        capability = smart.validate_provider_capabilities(provider)
    except Exception as exc:
        return _fallback(f"live_provider_capability_probe_failed:{type(exc).__name__}")

    if capability.get("passed") is not True:
        failures = capability.get("failures") or []
        reason = "live_provider_contract_rejected"
        if failures:
            reason += ":" + ",".join(str(item) for item in failures)
        return _fallback(reason)

    if capability.get("available") is not True or capability.get("accepted") is not True:
        reason = str(capability.get("reason") or "live_provider_not_available_or_not_accepted")
        return _fallback(reason)

    return ProviderLoadResult(
        provider=provider,
        loaded=True,
        accepted=True,
        reason="accepted_live_provider_loaded",
        provider_name=str(capability.get("provider_name") or ""),
        provider_profile=str(capability.get("provider_profile") or ""),
        provider_provenance=str(capability.get("provider_provenance") or ""),
    )
