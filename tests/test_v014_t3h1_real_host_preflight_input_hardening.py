from __future__ import annotations

import pytest

from sentinel import beta14_real_host_preflight as b1410


@pytest.mark.parametrize(
    "bad",
    [[], {}, 1, True, None],
    ids=["list", "dict", "int", "bool", "none"],
)
def test_real_host_architecture_type_confusion_fails_closed(bad):
    observation = b1410.fixture()
    observation["architecture"] = bad
    failures = b1410.validate(observation)
    assert "b1410:architecture_invalid" in failures


@pytest.mark.parametrize(
    "bad",
    [None, [], "raw", 1, True, {"unexpected": "shape"}],
    ids=["none", "list", "string", "int", "bool", "wrong-object"],
)
def test_real_host_summary_never_crashes_on_malformed_top_level(bad):
    report = b1410.summarize(bad)
    assert report["passed"] is False
    assert report["real_host_preflight"] is False
    assert report["ready_for_revert_drill"] is False
    assert len(report["observation_digest"]) == 64
    assert report["sample_execution_performed"] is False
    assert report["network_configuration_modified"] is False
    assert report["hypervisor_state_modified"] is False


@pytest.mark.parametrize(
    ("field", "bad", "expected"),
    [
        ("kvm_device_present", 1, "b1410:kvm_device_present_required"),
        ("snapshot_present", "true", "b1410:snapshot_present_required"),
        ("interfaces_distinct", [], "b1410:interfaces_distinct_required"),
        (
            "analysis_interface_has_default_route",
            0,
            "b1410:analysis_default_route_forbidden",
        ),
        (
            "shared_filesystem_device_present",
            None,
            "b1410:shared_filesystem_forbidden",
        ),
        (
            "sample_execution_performed",
            "false",
            "b1410:sample_execution_performed_forbidden",
        ),
    ],
    ids=[
        "required-int",
        "required-string",
        "required-list",
        "forbidden-int",
        "forbidden-none",
        "forbidden-string",
    ],
)
def test_real_host_boolean_fields_require_literal_booleans(field, bad, expected):
    observation = b1410.fixture()
    observation[field] = bad
    assert expected in b1410.validate(observation)


def test_real_host_preflight_cannot_become_t3_authority_from_input_only():
    observation = b1410.fixture()
    report = b1410.summarize(observation)

    assert report["passed"] is True
    assert report["ready_for_revert_drill"] is True
    assert report["authoritative_physical_lab"] is False
    assert report["t2_real_campaign_ready"] is False
    assert report["t3_real_campaign_ready"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_malformed_input_digest_is_deterministic():
    malformed = ["not", "a", "host", "observation"]
    first = b1410.summarize(malformed)
    second = b1410.summarize(list(malformed))
    assert first["observation_digest"] == second["observation_digest"]
