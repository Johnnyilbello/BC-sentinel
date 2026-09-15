from __future__ import annotations

import copy
import json

import pytest

from sentinel import beta8_coverage_baseline as baseline


def _payload() -> dict:
    return baseline.load_baseline()


def test_default_beta8_baseline_is_valid_and_exact() -> None:
    payload = _payload()
    result = baseline.validate_baseline(payload)
    assert result.passed, result.failures
    assert tuple(item["scenario_id"] for item in payload["scenarios"]) == baseline.EXPECTED_ORDER
    assert payload["summary"] == {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}


def test_self_check_binds_exact_beta7_final_state_and_stays_read_only() -> None:
    result = baseline.self_check()
    assert result["passed"], result["failures"]
    assert result["source_checkpoint"] == "checkpoint/v011-beta7-b77-pass"
    assert result["source_checkpoint_commit"] == "4d57f749276c588782147d47078ef4c52d1adc51"
    assert result["source_final_core_digest"] == result["live_final_core_digest"]
    assert result["source_campaign_digest"] == result["live_campaign_digest"]
    assert result["summary"] == {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}
    assert result["verification_targets"] == [
        "B7-RANSOMWARE-001",
        "B7-DEFENSE-EVASION-001",
        "B7-CREDENTIAL-001",
    ]
    assert result["verification_target_count"] == 3
    assert result["read_only"] is True
    assert result["authority_granted"] is False
    assert result["execution_authority_added"] is False


def test_serialization_and_digest_are_stable() -> None:
    first = _payload()
    second = _payload()
    assert baseline.baseline_digest(first) == baseline.baseline_digest(second)
    encoded = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert json.loads(encoded) == first


def test_reordered_scenarios_fail_closed() -> None:
    payload = copy.deepcopy(_payload())
    payload["scenarios"][0], payload["scenarios"][1] = payload["scenarios"][1], payload["scenarios"][0]
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert "baseline:scenario_order_or_set_changed" in result.failures


def test_missing_or_unknown_scenario_fails_closed() -> None:
    missing = copy.deepcopy(_payload())
    missing["scenarios"].pop()
    assert not baseline.validate_baseline(missing).passed

    unknown = copy.deepcopy(_payload())
    unknown["scenarios"][-1]["scenario_id"] = "B8-UNKNOWN-999"
    result = baseline.validate_baseline(unknown)
    assert not result.passed
    assert "baseline:scenario_order_or_set_changed" in result.failures


def test_verified_promotion_is_rejected() -> None:
    payload = copy.deepcopy(_payload())
    payload["scenarios"][0]["status"] = "VERIFIED"
    payload["summary"] = {"PARTIAL": 2, "GAP": 3, "VERIFIED": 1}
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert any("unsupported_verified_promotion" in failure for failure in result.failures)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_checkpoint_commit", "0" * 40),
        ("source_final_core_digest", "0" * 64),
        ("source_campaign_digest", "f" * 64),
    ],
)
def test_source_binding_tampering_fails_closed(field: str, value: str) -> None:
    payload = copy.deepcopy(_payload())
    payload[field] = value
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert any(field in failure for failure in result.failures)


def test_next_acceptance_mapping_and_targets_are_fixed() -> None:
    payload = copy.deepcopy(_payload())
    payload["scenarios"][2]["next_acceptance_milestone"] = "B8-4"
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert any("next_milestone_mismatch" in failure for failure in result.failures)

    payload = copy.deepcopy(_payload())
    payload["scenarios"][2]["verification_target"] = False
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert any("verification_target_mismatch" in failure for failure in result.failures)


@pytest.mark.parametrize(
    "field",
    [
        "process_execution",
        "file_write",
        "network_io",
        "registry_mutation",
        "credential_access",
        "remediation_execution",
        "automatic_quarantine",
        "automatic_repair",
        "automatic_restore",
        "general_home_execution_authorized",
        "delete_authorized",
        "repair_authorized",
        "terminate_process_authorized",
        "trust_allowlist_mutation_authorized",
        "privileged_system_mutation_authorized",
        "authority_granted",
        "execution_authority_added",
    ],
)
def test_authority_or_mutation_tampering_fails_closed(field: str) -> None:
    payload = copy.deepcopy(_payload())
    payload[field] = True
    result = baseline.validate_baseline(payload)
    assert not result.passed
    assert f"baseline:{field}_must_be_false" in result.failures


def test_unsupported_claim_switches_fail_closed() -> None:
    for field in (
        "unsupported_positive_claims_allowed",
        "verified_without_detector_acceptance_allowed",
    ):
        payload = copy.deepcopy(_payload())
        payload[field] = True
        result = baseline.validate_baseline(payload)
        assert not result.passed
        assert f"baseline:{field}_must_be_false" in result.failures
