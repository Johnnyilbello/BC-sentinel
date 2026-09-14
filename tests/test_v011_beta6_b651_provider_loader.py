from __future__ import annotations

from types import SimpleNamespace

from sentinel import guided_resolution_provider_loader as loader
from sentinel import home_guided_resolution as guided


def _snapshot() -> dict:
    return {
        "schema": loader.CAPABILITY_SCHEMA,
        "accepted": True,
        "available": True,
        "side_effect_free_probe": True,
        "execution_available": False,
        "automatic_action": False,
        "destructive_authority": False,
        "actions": [
            {
                "action_id": guided.ACTION_REVIEW_DETAILS,
                "available": True,
                "mutates_system": False,
                "reason": "review",
            },
            {"action_id": "QUARANTINE", "available": False, "mutates_system": True},
            {"action_id": "REPAIR", "available": False, "mutates_system": True},
            {"action_id": "DELETE", "available": False, "mutates_system": True},
            {"action_id": "TERMINATE_PROCESS", "available": False, "mutates_system": True},
            {"action_id": "TRUST_OR_ALLOWLIST", "available": False, "mutates_system": True},
        ],
        "future_mutation_safety": {
            "explicit_confirmation_required": True,
            "rollback_required": True,
            "journal_required": True,
            "target_revalidation_required": True,
        },
    }


class _PassiveProvider:
    name = "fixture passive provider"
    profile = "fixture-b65.1"
    provenance = "unit-test"

    def capabilities(self) -> dict:
        return _snapshot()


def _module_for(provider: object) -> object:
    return SimpleNamespace(create_provider=lambda: provider)


def test_real_fixed_provider_loads_and_is_introspection_only() -> None:
    result = loader.load_default_provider()
    assert result.loaded is True
    assert result.accepted is True
    assert result.reason == "accepted_passive_capability_provider"
    assert result.provider_profile == "v0.11.0-beta.6-b65.1-passive-provider"
    assert result.capability_snapshot["side_effect_free_probe"] is True
    assert result.capability_snapshot["execution_available"] is False
    assert result.capability_snapshot["destructive_authority"] is False
    assert result.failures == ()
    assert result.provider is not None
    for method_name in loader.EXECUTION_API_NAMES:
        assert not callable(getattr(result.provider, method_name, None))


def test_good_synthetic_passive_provider_is_accepted() -> None:
    result = loader.load_default_provider(import_module=lambda _: _module_for(_PassiveProvider()))
    assert result.loaded is True
    assert result.accepted is True
    assert result.failures == ()
    actions = result.capability_snapshot["actions"]
    assert [item["action_id"] for item in actions if item["available"]] == [guided.ACTION_REVIEW_DETAILS]
    assert all(not item["available"] for item in actions if item["mutates_system"])


def test_missing_fixed_module_fails_closed() -> None:
    def _missing(name: str) -> object:
        exc = ModuleNotFoundError(name)
        exc.name = name
        raise exc

    result = loader.load_default_provider(import_module=_missing)
    assert result.loaded is False
    assert result.accepted is False
    assert result.provider is None
    assert result.reason == "guided_resolution_provider_module_missing"


def test_factory_missing_or_none_fails_closed() -> None:
    missing = loader.load_default_provider(import_module=lambda _: SimpleNamespace())
    assert missing.accepted is False
    assert missing.reason == "guided_resolution_provider_factory_missing"

    none_result = loader.load_default_provider(
        import_module=lambda _: SimpleNamespace(create_provider=lambda: None)
    )
    assert none_result.accepted is False
    assert none_result.reason == "guided_resolution_provider_factory_returned_none"


def test_provider_with_execution_api_is_rejected_even_if_snapshot_claims_passive() -> None:
    class UnsafeProvider(_PassiveProvider):
        def execute(self) -> None:
            raise AssertionError("must never be called")

    result = loader.load_default_provider(import_module=lambda _: _module_for(UnsafeProvider()))
    assert result.loaded is True
    assert result.accepted is False
    assert result.provider is None
    assert "execution_api_present:execute" in result.failures
    assert "guided_resolution_provider_contract_rejected" in result.reason


def test_provider_exposing_mutating_action_is_rejected() -> None:
    class UnsafeProvider(_PassiveProvider):
        def capabilities(self) -> dict:
            snapshot = _snapshot()
            snapshot["actions"] = [dict(item) for item in snapshot["actions"]]
            for item in snapshot["actions"]:
                if item["action_id"] == "QUARANTINE":
                    item["available"] = True
            return snapshot

    result = loader.load_default_provider(import_module=lambda _: _module_for(UnsafeProvider()))
    assert result.accepted is False
    assert "mutating_action_exposed:QUARANTINE" in result.failures


def test_false_execution_or_safety_declaration_is_rejected() -> None:
    class UnsafeProvider(_PassiveProvider):
        def capabilities(self) -> dict:
            snapshot = _snapshot()
            snapshot["execution_available"] = True
            snapshot["future_mutation_safety"] = dict(snapshot["future_mutation_safety"])
            snapshot["future_mutation_safety"]["rollback_required"] = False
            return snapshot

    result = loader.load_default_provider(import_module=lambda _: _module_for(UnsafeProvider()))
    assert result.accepted is False
    assert "execution_must_remain_unavailable" in result.failures
    assert "future_rollback_requirement_missing" in result.failures


def test_capability_probe_failure_is_rejected_without_execution_fallback() -> None:
    class BrokenProvider(_PassiveProvider):
        def capabilities(self) -> dict:
            raise RuntimeError("fixture")

    result = loader.load_default_provider(import_module=lambda _: _module_for(BrokenProvider()))
    assert result.accepted is False
    assert "capability_probe_failed:RuntimeError" in result.failures
    assert result.provider is None
