from __future__ import annotations

from sentinel import beta14_test_readiness as b140


def test_b140_binds_exact_beta13_final_checkpoint() -> None:
    report = b140.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b137-pass"
    assert report["source_checkpoint_commit"] == "01df0a9c58b856cfe841909fb5c39f7ef71decb8"


def test_b140_preserves_canonical_coverage() -> None:
    report = b140.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["verified_scenario_count"] == 7
    assert report["coverage_promoted"] is False


def test_b140_gate_inventory_is_fail_closed() -> None:
    report = b140.self_check()
    assert report["evidence_gate_counts"] == {
        b140.READY: 2,
        b140.PARTIAL: 3,
        b140.BLOCKED: 5,
    }
    assert report["independent_test_ready"] is False
    assert report["independent_certification_claimed"] is False


def test_b140_real_world_and_reference_corpus_are_blocked() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["REAL_WORLD_PROTECTION_CORPUS"]["status"] == b140.BLOCKED
    assert gates["PREVALENT_MALWARE_REFERENCE_SET"]["status"] == b140.BLOCKED


def test_b140_existing_low_noise_evidence_is_not_overclaimed() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["FALSE_POSITIVE_BREADTH"]["status"] == b140.PARTIAL
    assert gates["SYSTEM_PERFORMANCE_IMPACT"]["status"] == b140.PARTIAL


def test_b140_behavioral_evidence_remains_scenario_specific() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["BEHAVIORAL_DETECTION_BREADTH"]["status"] == b140.PARTIAL
    assert b140.SOURCE_COVERAGE["VERIFIED"] == 7


def test_b140_offline_online_matrix_not_invented() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["OFFLINE_ONLINE_PROTECTION_MATRIX"]["status"] == b140.BLOCKED
    report = b140.self_check()
    assert report["network_required"] is False
    assert report["cloud_required"] is False


def test_b140_independent_lab_readiness_not_claimed() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["INDEPENDENT_LAB_SUBMISSION_READINESS"]["status"] == b140.BLOCKED
    assert b140.self_check()["independent_test_ready"] is False


def test_b140_public_trust_code_signing_remains_separate_blocker() -> None:
    gates = {item["gate_id"]: item for item in b140.contract()["evidence_gates"]}
    assert gates["PUBLIC_TRUST_CODE_SIGNING"]["status"] == b140.BLOCKED
    report = b140.self_check()
    assert report["release_blockers"] == ["CODE_SIGNING"]
    assert report["public_release_ready"] is False
    assert report["paid_release_ready"] is False


def test_b140_ordinary_ci_local_acceptance_is_harmless_fixture_only() -> None:
    policy = b140.contract()["safe_lab_policy"]
    assert policy["ordinary_ci_local_authentic_malware_execution_allowed"] is False
    assert policy["ordinary_ci_local_harmless_fixtures_only"] is True
    assert policy["synthetic_only_evidence_may_promote_verified"] is False


def test_b140_future_authentic_sample_work_requires_separate_lab_contract() -> None:
    policy = b140.contract()["safe_lab_policy"]
    assert policy["future_authentic_sample_work_requires_separate_authorized_isolated_lab"] is True
    assert policy["future_authentic_sample_work_requires_explicit_scope_and_cleanup"] is True


def test_b140_does_not_expand_response_authority() -> None:
    boundaries = b140.contract()["boundaries"]
    assert all(value is False for value in boundaries.values())
    report = b140.self_check()
    assert report["authority_expanded"] is False


def test_b140_contract_is_deterministic() -> None:
    first = b140.self_check()
    second = b140.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]
