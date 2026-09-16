from __future__ import annotations

from sentinel import beta10_value_foundation as b100


def test_b100_self_check_passes() -> None:
    result = b100.self_check()
    assert result["passed"] is True
    assert result["failures"] == []


def test_b100_freezes_exact_beta9_baseline() -> None:
    report = b100.contract()
    assert report["source_checkpoint"] == "checkpoint/v011-beta9-b94-pass"
    assert report["source_checkpoint_commit"] == "cc32c2c31ebb9b863624632a38175ec5825430e4"
    assert report["baseline_coverage"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    assert report["verified_scenario_id"] == "B7-RANSOMWARE-001"


def test_b100_has_six_customer_value_pillars() -> None:
    report = b100.contract()
    assert [p["pillar_id"] for p in report["value_pillars"]] == [
        "PROTECTION_PROOF",
        "ATTACK_STORY",
        "SAFE_RESPONSE",
        "RESCUE_CONTINUITY",
        "LOW_NOISE_OPERATION",
        "LOCAL_FIRST_PRIVACY",
    ]
    for pillar in report["value_pillars"]:
        assert pillar["customer_value"]
        assert len(pillar["success_metrics"]) >= 3
        assert pillar["market_role"]


def test_b100_milestone_order_is_complete_and_deterministic() -> None:
    report = b100.contract()
    assert [m["id"] for m in report["milestones"]] == [f"B10-{i}" for i in range(10)]
    assert report == b100.contract()
    assert b100.self_check()["deterministic_contract"] is True


def test_b100_foundation_does_not_expand_protection_claims() -> None:
    report = b100.contract()
    assert report["beta10_adds_protection_claim_at_foundation"] is False
    assert b100.self_check()["protection_claim_expanded"] is False


def test_b100_foundation_does_not_expand_authority() -> None:
    report = b100.contract()
    assert report["beta10_adds_remediation_authority_at_foundation"] is False
    assert all(value is False for value in report["authority_boundary"].values())
    assert b100.self_check()["authority_expanded"] is False


def test_b100_rejects_authority_flip() -> None:
    report = b100.contract()
    report["authority_boundary"]["automatic_quarantine"] = True
    assert "b100:authority_boundary_invalid" in b100.validate_contract(report)


def test_b100_rejects_false_verified_baseline() -> None:
    report = b100.contract()
    report["baseline_coverage"] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert "b100:baseline_invalid" in b100.validate_contract(report)


def test_b100_rejects_missing_success_metrics() -> None:
    report = b100.contract()
    report["value_pillars"][0]["success_metrics"] = []
    assert "b100:pillar_metrics_invalid" in b100.validate_contract(report)


def test_b100_rejects_milestone_reordering() -> None:
    report = b100.contract()
    report["milestones"][0], report["milestones"][1] = report["milestones"][1], report["milestones"][0]
    assert "b100:milestone_order_invalid" in b100.validate_contract(report)
