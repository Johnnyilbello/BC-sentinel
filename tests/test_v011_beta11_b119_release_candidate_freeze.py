from __future__ import annotations

from sentinel import beta11_release_candidate_freeze as b119


def test_contract_is_deterministic() -> None:
    assert b119.contract() == b119.contract()
    assert b119.self_check()["deterministic_contract"] is True


def test_source_checkpoint_is_exact_b118_acceptance() -> None:
    report = b119.self_check()
    assert report["source_checkpoint"] == "checkpoint/v011-beta11-b118-pass"
    assert report["source_checkpoint_commit"] == "46d18b77aa382573e1e4e2a2eb381bcb71e03a69"


def test_all_nine_accepted_beta11_predecessor_checkpoints_are_bound() -> None:
    contract = b119.contract()
    assert len(contract["accepted_beta11_checkpoints"]) == 9
    assert contract["accepted_beta11_checkpoints"][-1] == {
        "checkpoint": "checkpoint/v011-beta11-b118-pass",
        "commit": "46d18b77aa382573e1e4e2a2eb381bcb71e03a69",
    }


def test_b118_digests_are_frozen() -> None:
    report = b119.self_check()
    assert report["source_b118_contract_digest"] == "8fb9060e3e41146a400a9cebdeec8978b96909c6aa6b2e29327ad9c60fb36269"
    assert report["source_b118_transcript_digest"] == "1d010b2ff4a4e52f8fed405180ff404331c4ada08684cf1bc1e126600b62bf22"


def test_coverage_is_not_promoted() -> None:
    report = b119.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert report["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert report["coverage_promoted"] is False


def test_unsigned_candidate_can_be_rc_but_not_signed_release_ready() -> None:
    result = b119.evaluate_candidate_evidence(
        build_commit="a" * 40,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status="READY",
        lifecycle_contract_digest=b119.SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=b119.SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="UNSIGNED",
    )
    assert result["candidate_ready"] is True
    assert result["signed_release_ready"] is False


def test_verified_signed_candidate_is_signed_release_ready() -> None:
    result = b119.evaluate_candidate_evidence(
        build_commit="b" * 40,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status="READY",
        lifecycle_contract_digest=b119.SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=b119.SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="SIGNED_VERIFIED",
    )
    assert result["candidate_ready"] is True
    assert result["signed_release_ready"] is True


def test_unverified_signature_fails_closed() -> None:
    result = b119.evaluate_candidate_evidence(
        build_commit="c" * 40,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status="READY",
        lifecycle_contract_digest=b119.SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=b119.SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="SIGNED_UNVERIFIED",
    )
    assert result["candidate_ready"] is False
    assert "authenticode_state_not_acceptable" in result["reasons"]


def test_non_ready_health_blocks_candidate() -> None:
    result = b119.evaluate_candidate_evidence(
        build_commit="d" * 40,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status="DEGRADED",
        lifecycle_contract_digest=b119.SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=b119.SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="UNSIGNED",
    )
    assert result["candidate_ready"] is False


def test_lifecycle_digest_mismatch_blocks_candidate() -> None:
    result = b119.evaluate_candidate_evidence(
        build_commit="e" * 40,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status="READY",
        lifecycle_contract_digest="0" * 64,
        lifecycle_transcript_digest=b119.SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="UNSIGNED",
    )
    assert result["candidate_ready"] is False


def test_final_freeze_does_not_publish_or_sign() -> None:
    report = b119.self_check()
    assert report["release_publication_execution_available"] is False
    assert report["artifact_signing_execution_available"] is False
    assert report["authority_expanded"] is False


def test_self_check_passes() -> None:
    report = b119.self_check()
    assert report["passed"] is True
    assert report["failures"] == []
