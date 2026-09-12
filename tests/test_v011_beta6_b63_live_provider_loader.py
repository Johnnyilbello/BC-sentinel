from __future__ import annotations

from types import SimpleNamespace

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_provider_loader as loader


class AcceptedProvider:
    def __init__(self) -> None:
        self.plan_calls = 0
        self.run_calls = 0

    def capabilities(self):
        return {
            "available": True,
            "accepted": True,
            "provider_name": "accepted-live-fixture",
            "provider_profile": "fixture-v1",
            "provider_provenance": "loader_test",
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }

    def build_plan(self):
        self.plan_calls += 1
        raise AssertionError("loader must not plan")

    def run(self, plan, progress_callback, cancel_check):
        self.run_calls += 1
        raise AssertionError("loader must not run")


def test_missing_live_module_fails_closed() -> None:
    def missing(name: str):
        exc = ModuleNotFoundError(name)
        exc.name = name
        raise exc

    result = loader.load_default_provider(import_module=missing)
    assert result.loaded is False
    assert result.accepted is False
    assert result.reason == "live_provider_module_not_synchronized"
    assert isinstance(result.provider, smart.UnavailableSmartScanProvider)


def test_missing_dependency_inside_live_module_fails_closed() -> None:
    def missing_dependency(name: str):
        exc = ModuleNotFoundError("native_runtime")
        exc.name = "native_runtime"
        raise exc

    result = loader.load_default_provider(import_module=missing_dependency)
    assert result.loaded is False
    assert result.accepted is False
    assert result.reason == "live_provider_dependency_missing:native_runtime"


def test_factory_missing_or_failed_fails_closed() -> None:
    missing_factory = loader.load_default_provider(
        import_module=lambda name: SimpleNamespace()
    )
    assert missing_factory.reason == "live_provider_factory_missing"
    assert missing_factory.accepted is False

    def fail_factory():
        raise RuntimeError("fixture")

    failed_factory = loader.load_default_provider(
        import_module=lambda name: SimpleNamespace(create_provider=fail_factory)
    )
    assert failed_factory.reason == "live_provider_factory_failed:RuntimeError"
    assert failed_factory.accepted is False


def test_accepted_provider_loads_without_planning_or_running() -> None:
    provider = AcceptedProvider()
    result = loader.load_default_provider(
        import_module=lambda name: SimpleNamespace(create_provider=lambda: provider)
    )
    assert result.loaded is True
    assert result.accepted is True
    assert result.reason == "accepted_live_provider_loaded"
    assert result.provider is provider
    assert result.provider_name == "accepted-live-fixture"
    assert result.provider_profile == "fixture-v1"
    assert result.provider_provenance == "loader_test"
    assert provider.plan_calls == 0
    assert provider.run_calls == 0


def test_provider_requesting_destructive_authority_is_rejected() -> None:
    class UnsafeProvider(AcceptedProvider):
        def capabilities(self):
            payload = dict(super().capabilities())
            payload["automatic_repair"] = True
            return payload

    result = loader.load_default_provider(
        import_module=lambda name: SimpleNamespace(create_provider=UnsafeProvider)
    )
    assert result.loaded is False
    assert result.accepted is False
    assert result.reason.startswith("live_provider_contract_rejected:")
    assert "forbidden_provider_authority:automatic_repair" in result.reason
    assert isinstance(result.provider, smart.UnavailableSmartScanProvider)


def test_available_but_unaccepted_provider_is_rejected() -> None:
    class UnacceptedProvider(AcceptedProvider):
        def capabilities(self):
            payload = dict(super().capabilities())
            payload["accepted"] = False
            payload["reason"] = "runtime_not_verified"
            return payload

    result = loader.load_default_provider(
        import_module=lambda name: SimpleNamespace(create_provider=UnacceptedProvider)
    )
    assert result.loaded is False
    assert result.accepted is False
    # The core capability validator rejects available=True + accepted=False before
    # the loader can ever expose this provider to the Home.
    assert "available_provider_must_be_accepted" in result.reason
