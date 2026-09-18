from __future__ import annotations

from sentinel import beta12_active_protection_foundation as b120


def test_b120_self_check_passes() -> None:
    report = b120.self_check()
    assert report["passed"] is True
    assert report["failures"] == []


def test_b120_freezes_exact_beta11_final_checkpoint() -> None:
    report = b120.contract()
    assert report["source_checkpoint"] == "checkpoint/v011-beta11-b119-pass"
    assert report["source_checkpoint_commit"] == "3c5204ca949d41d3a740b8745ab9af06913b8555"


def test_b120_preserves_exact_baseline_coverage() -> None:
    report = b120.contract()
    assert report["baseline_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert report["baseline_verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
    ]


def test_b120_defines_seven_active_protection_pillars() -> None:
    report = b120.contract()
    assert [p["pillar_id"] for p in report["protection_pillars"]] == [
        "CORRELATED_TELEMETRY",
        "SCRIPT_ABUSE_DETECTION",
        "PERSISTENCE_STARTUP_DETECTION",
        "PROCESS_TREE_INTELLIGENCE",
        "RANSOMWARE_RESILIENCE",
        "LOCAL_REPUTATION",
        "LOW_NOISE_PERFORMANCE",
    ]
    for pillar in report["protection_pillars"]:
        assert pillar["goal"]
        assert len(pillar["acceptance_signals"]) >= 3


def test_b120_has_complete_ten_milestone_beta12_plan() -> None:
    report = b120.contract()
    assert [m["id"] for m in report["milestones"]] == [f"B12-{i}" for i in range(10)]
    assert report["milestones"][-1]["name"] == "Windows Active Protection Acceptance & Freeze"


def test_b120_requires_at_least_two_new_verified_scenarios_before_final_freeze() -> None:
    targets = b120.contract()["final_freeze_targets"]
    assert targets["minimum_total_verified_scenarios"] == 4
    assert targets["minimum_new_verified_scenarios"] == 2
    assert targets["windows_evidence_required_for_new_verified"] is True
    assert targets["synthetic_only_verified_promotion_forbidden"] is True


def test_b120_foundation_does_not_promote_coverage_or_claim_protection() -> None:
    report = b120.contract()
    check = b120.self_check()
    assert report["foundation_promotes_coverage"] is False
    assert report["foundation_adds_protection_claim"] is False
    assert check["coverage_promoted"] is False
    assert check["protection_claim_expanded"] is False


def test_b120_does_not_expand_remediation_authority() -> None:
    report = b120.contract()
    assert report["foundation_adds_remediation_authority"] is False
    assert all(value is False for value in report["authority_boundary"].values())
    assert b120.self_check()["authority_expanded"] is False


def test_b120_keeps_core_acceptance_local_first() -> None:
    report = b120.contract()
    assert report["network_required"] is False
    assert report["cloud_required"] is False


def test_b120_explicitly_defers_installer_work() -> None:
    policy = b120.contract()["installer_policy"]
    assert policy == {
        "installer_work_deferred_until_after_beta12": True,
        "b120_changes_installer_behavior": False,
        "b120_signs_artifacts": False,
        "b120_publishes_release": False,
    }


def test_b120_rejects_authority_expansion() -> None:
    report = b120.contract()
    report["authority_boundary"]["automatic_quarantine"] = True
    assert "b120:contract_changed" in b120.validate_contract(report)
    assert "b120:authority_boundary_invalid" in b120.validate_contract(report)


def test_b120_rejects_false_verified_baseline() -> None:
    report = b120.contract()
    report["baseline_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b120:baseline_coverage_invalid" in b120.validate_contract(report)


def test_b120_contract_is_deterministic() -> None:
    assert b120.contract() == b120.contract()
    assert b120.self_check()["deterministic_contract"] is True
