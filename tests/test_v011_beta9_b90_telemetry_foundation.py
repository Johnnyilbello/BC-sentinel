from copy import deepcopy
import json

import pytest

from sentinel import beta9_telemetry_foundation as foundation


@pytest.fixture
def inventory():
    return {"schema": foundation.SCHEMA, "source": "WINDOWS_CHANNEL_CONFIGURATION",
            "channels": [{"channel": c, "state": "AVAILABLE", "enabled": True}
                         for c in foundation.CHANNELS], "boundaries": dict(foundation.BOUNDARIES)}


def test_deterministic_inventory_does_not_verify_detection(inventory):
    result = foundation.summarize(inventory)
    assert result == foundation.summarize(deepcopy(inventory))
    assert result["passed"]
    assert result["coverage_summary"]["VERIFIED"] == 0
    assert result["event_readability_tested"] is False
    assert result["detector_verification_performed"] is False


@pytest.mark.parametrize("state,enabled", [("DISABLED", False), ("ACCESS_DENIED", None), ("MISSING", None), ("ERROR", None)])
def test_unavailable_sources_remain_explicit(inventory, state, enabled):
    inventory["channels"][0].update(state=state, enabled=enabled)
    result = foundation.summarize(inventory)
    assert result["passed"]
    assert "System" not in result["available_channels"]
    assert result["unavailable_channels"][0] == {"channel": "System", "state": state}


@pytest.mark.parametrize("value", [None, [], "raw", 1, {}])
def test_malformed_inventory_fails_closed(value):
    assert not foundation.summarize(value)["passed"]


@pytest.mark.parametrize("field", list(foundation.BOUNDARIES))
def test_boundary_changes_rejected(inventory, field):
    inventory["boundaries"][field] = not inventory["boundaries"][field]
    assert not foundation.summarize(inventory)["passed"]


@pytest.mark.parametrize("field", ["message", "username", "command_line", "token"])
def test_unexpected_fields_rejected_without_disclosure(inventory, field):
    inventory["channels"][0][field] = "PRIVATE_SENTINEL_VALUE"
    result = foundation.summarize(inventory)
    assert not result["passed"]
    assert "PRIVATE_SENTINEL_VALUE" not in json.dumps(result)


def test_duplicate_or_missing_channel_rejected(inventory):
    inventory["channels"][1] = inventory["channels"][0]
    assert not foundation.summarize(inventory)["passed"]
    inventory["channels"].pop()
    assert not foundation.summarize(inventory)["passed"]


@pytest.mark.parametrize("state,enabled", [("AVAILABLE", 1), ("DISABLED", 0), ("MISSING", False), ([], None), ("UNKNOWN", None)])
def test_invalid_states_and_boolean_lookalikes_rejected(inventory, state, enabled):
    inventory["channels"][0].update(state=state, enabled=enabled)
    assert not foundation.summarize(inventory)["passed"]
