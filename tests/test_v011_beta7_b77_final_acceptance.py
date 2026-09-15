from __future__ import annotations

from copy import deepcopy

from sentinel import beta7_final_acceptance as final


def test_final_self_check_passes_and_preserves_safety() -> None:
    result = final.self_check()
    assert result["passed"] is True
    assert result["deterministic_core"] is True
    assert result["campaign_summary"] == {"GAP": 3, "PARTIAL": 3, "VERIFIED": 0}
    assert result["beta6_portable_contract_passed"] is True
    assert result["attack_chain_safe"] is True
    assert result["explainable_security_grounded"] is True
    assert result["authority_granted"] is False
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False


def test_final_core_is_reproducible() -> None:
    first = final._core_snapshot()
    second = final._core_snapshot()
    assert first == second
    assert final._stable_hash(first) == final._stable_hash(second)


def test_resource_cost_is_measured_and_bounded() -> None:
    report = final.run_final_acceptance()
    validation = final.validate_report(report)
    assert validation.passed is True
    assert report.elapsed_seconds >= 0
    assert report.elapsed_seconds <= final.MAX_SYNTHETIC_PIPELINE_SECONDS
    assert report.peak_memory_bytes >= 0
    assert report.peak_memory_bytes <= final.MAX_SYNTHETIC_PEAK_BYTES


def test_beta6_portable_contract_remains_inherited() -> None:
    core = final._core_snapshot()
    portable = core["beta6_portable_contract"]
    assert portable["passed"] is True
    assert portable["packaging_mode"] == "onedir"
    assert portable["portable"] is True
    assert portable["windowed"] is True
    assert portable["installer_required"] is False
    assert portable["service_install"] is False
    assert portable["driver_install"] is False
    assert portable["network_required"] is False
    assert portable["cloud_required"] is False
    assert portable["explicit_operator_action_required"] is True
    assert portable["general_home_execution_authorized"] is False


def test_campaign_keeps_explicit_gaps_and_zero_verified_claims() -> None:
    core = final._core_snapshot()
    campaign = core["coverage_campaign"]
    assert campaign["summary"] == {"GAP": 3, "PARTIAL": 3, "VERIFIED": 0}
    assert campaign["partial_count"] == 3
    assert campaign["explicit_gap_count"] == 3
    assert campaign["verified_count"] == 0
    assert campaign["unsupported_verified_claims_allowed"] is False


def test_validation_rejects_authority_expansion() -> None:
    payload = final.run_final_acceptance().to_dict()
    broken = deepcopy(payload)
    broken["core"]["safety"]["automatic_quarantine"] = True
    broken["core_digest"] = final._stable_hash(broken["core"])
    validation = final.validate_report(broken)
    assert validation.passed is False
    assert "final:safety_automatic_quarantine_must_be_false" in validation.failures


def test_validation_rejects_unsupported_verified_coverage() -> None:
    payload = final.run_final_acceptance().to_dict()
    broken = deepcopy(payload)
    broken["core"]["coverage_campaign"]["summary"] = {"GAP": 2, "PARTIAL": 3, "VERIFIED": 1}
    broken["core"]["coverage_campaign"]["verified_count"] = 1
    broken["core_digest"] = final._stable_hash(broken["core"])
    validation = final.validate_report(broken)
    assert validation.passed is False
    assert "final:coverage_campaign_summary_changed" in validation.failures
    assert "final:coverage_campaign_counts_changed" in validation.failures


def test_validation_rejects_resource_cost_missing() -> None:
    payload = final.run_final_acceptance().to_dict()
    broken = deepcopy(payload)
    broken.pop("resource_cost")
    validation = final.validate_report(broken)
    assert validation.passed is False
    assert "final:resource_cost_missing" in validation.failures


def test_source_checkpoint_is_exact_b76_acceptance() -> None:
    assert final.SOURCE_CHECKPOINT == "checkpoint/v011-beta7-b76-pass"
    assert final.SOURCE_CHECKPOINT_COMMIT == "1bd66f4f9e55313388e871e26c6a35d55a3dbb20"
