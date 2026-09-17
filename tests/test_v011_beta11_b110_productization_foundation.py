from copy import deepcopy

from sentinel import beta11_productization_foundation as b110


def test_b110_contract_self_check_passes():
    result = b110.self_check()
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["deterministic_contract"] is True


def test_b110_binds_exact_beta10_final_checkpoint():
    contract = b110.contract()
    assert contract["source_checkpoint"] == "checkpoint/v011-beta10-b109-pass"
    assert contract["source_checkpoint_commit"] == "89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9"


def test_b110_preserves_beta10_coverage_and_verified_set():
    contract = b110.contract()
    assert contract["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert contract["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert contract["adds_protection_claim_in_b110"] is False


def test_b110_defines_six_productization_pillars():
    contract = b110.contract()
    assert [p["pillar_id"] for p in contract["productization_pillars"]] == [
        "CANONICAL_DESKTOP_ENTRY",
        "REPRODUCIBLE_ARTIFACT",
        "INSTALL_LIFECYCLE",
        "FIRST_RUN_HEALTH",
        "RELEASE_PROVENANCE",
        "SAFE_UPGRADE_RECOVERY",
    ]
    assert all(len(p["acceptance_metrics"]) >= 3 for p in contract["productization_pillars"])


def test_b110_defines_ordered_ten_milestone_beta11_line():
    contract = b110.contract()
    assert [m["id"] for m in contract["milestones"]] == [f"B11-{i}" for i in range(10)]
    assert contract["milestones"][0]["name"] == "Windows Productization Foundation"
    assert contract["milestones"][-1]["name"] == "Windows Release Candidate Acceptance & Freeze"


def test_b110_does_not_pretend_distribution_features_exist():
    state = b110.contract()["current_distribution_state"]
    assert state == b110.CURRENT_DISTRIBUTION_STATE
    assert not any(state.values())
    assert state["installer_available"] is False
    assert state["artifact_signed"] is False
    assert state["windows_service_installed"] is False
    assert state["kernel_driver_installed"] is False
    assert state["automatic_update_enabled"] is False
    assert state["network_required_for_core_startup"] is False
    assert state["cloud_required_for_core_startup"] is False


def test_b110_preserves_general_authority_boundary():
    boundary = b110.contract()["inherited_authority_boundary"]
    assert boundary == b110.INHERITED_AUTHORITY_BOUNDARY
    assert not any(boundary.values())
    assert boundary["general_home_execution"] is False
    assert boundary["automatic_quarantine"] is False
    assert boundary["automatic_repair"] is False
    assert boundary["privileged_system_mutation"] is False
    assert boundary["broad_protection_claimed"] is False


def test_b110_requires_exact_release_evidence_before_rc_freeze():
    guardrails = b110.contract()["foundation_guardrails"]
    assert guardrails["source_checkpoint_must_be_immutable"] is True
    assert guardrails["accepted_beta10_sources_may_be_modified"] is False
    assert guardrails["installer_may_be_claimed_before_acceptance"] is False
    assert guardrails["signature_may_be_claimed_before_verification"] is False
    assert guardrails["release_requires_exact_ci_and_local_acceptance"] is True
    assert guardrails["clean_pc_acceptance_required_before_rc_freeze"] is True


def test_b110_validation_rejects_early_installer_claim():
    candidate = deepcopy(b110.contract())
    candidate["current_distribution_state"]["installer_available"] = True
    failures = b110.validate_contract(candidate)
    assert "b110:distribution_state_invalid" in failures or "b110:distribution_capability_claimed_too_early" in failures


def test_b110_validation_rejects_authority_expansion():
    candidate = deepcopy(b110.contract())
    candidate["inherited_authority_boundary"]["general_home_execution"] = True
    failures = b110.validate_contract(candidate)
    assert "b110:authority_boundary_invalid" in failures or "b110:authority_expansion_forbidden" in failures


def test_b110_validation_rejects_coverage_promotion():
    candidate = deepcopy(b110.contract())
    candidate["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    failures = b110.validate_contract(candidate)
    assert "b110:coverage_changed" in failures


def test_b110_validation_rejects_milestone_reordering():
    candidate = deepcopy(b110.contract())
    candidate["milestones"][0], candidate["milestones"][1] = candidate["milestones"][1], candidate["milestones"][0]
    failures = b110.validate_contract(candidate)
    assert "b110:milestone_order_invalid" in failures
