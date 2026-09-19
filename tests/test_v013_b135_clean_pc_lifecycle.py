from __future__ import annotations

from copy import deepcopy

from sentinel import beta13_clean_pc_lifecycle as b135


def _evidence(environment: str) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema": b135.EVIDENCE_SCHEMA,
        "profile": b135.PROFILE,
        "source_checkpoint": b135.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": b135.SOURCE_CHECKPOINT_COMMIT,
        "build_commit": "a" * 40,
        "environment": environment,
        "authoritative_clean_pc_evidence": environment == b135.CI_ENVIRONMENT,
        "predecessor_installer_format": b135.LIFECYCLE_POLICY["predecessor_installer_format"],
        "target_installer_format": b135.LIFECYCLE_POLICY["target_installer_format"],
        "predecessor_install_passed": True,
        "predecessor_unsigned_observed": True,
        "predecessor_self_check_passed": True,
        "predecessor_ui_smoke_passed": True,
        "upgrade_passed": True,
        "target_signed_observed": True,
        "signer_consistent": True,
        "timestamp_present": True,
        "target_hash_changed": True,
        "upgraded_self_check_passed": True,
        "upgraded_ui_smoke_passed": True,
        "unknown_child_preserved_across_upgrade": True,
        "persistent_data_preserved_across_upgrade": True,
        "uninstall_passed": True,
        "unknown_child_preserved_after_uninstall": True,
        "persistent_data_preserved_after_uninstall": True,
        "registry_cleaned": True,
        "start_menu_cleaned": True,
        "service_registration_observed": False,
        "driver_registration_observed": False,
        "autostart_registration_observed": False,
        "administrator_required": False,
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "predecessor_app_sha256": "1" * 64,
        "upgraded_app_sha256": "2" * 64,
        "target_signer_thumbprint": "3" * 40,
    }
    return b135.finalize_lifecycle_evidence(raw)


def test_contract_binds_exact_b134_checkpoint() -> None:
    data = b135.contract()
    assert data["source_checkpoint"] == "checkpoint/v013-b134-pass"
    assert data["source_checkpoint_commit"] == "c2dc1b0df4becc18afa56915bb47b29b533a9a55"


def test_contract_preserves_accepted_coverage_and_readiness() -> None:
    data = b135.contract()
    assert data["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert data["source_readiness"] == {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}
    assert data["source_release_blockers"] == [
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]
    assert data["implementation_state"]["coverage_promoted"] is False
    assert data["implementation_state"]["authority_expanded"] is False


def test_contract_requires_real_per_user_lifecycle_and_preservation() -> None:
    policy = b135.contract()["lifecycle_policy"]
    assert policy["real_per_user_install_required"] is True
    assert policy["real_per_user_upgrade_required"] is True
    assert policy["real_per_user_uninstall_required"] is True
    assert policy["unknown_install_child_preserved_across_upgrade"] is True
    assert policy["unknown_install_child_preserved_after_uninstall"] is True
    assert policy["external_persistent_data_preserved_across_upgrade"] is True
    assert policy["external_persistent_data_preserved_after_uninstall"] is True


def test_contract_keeps_privilege_and_registration_boundaries_closed() -> None:
    policy = b135.contract()["lifecycle_policy"]
    assert policy["administrator_required"] is False
    assert policy["service_registration_allowed"] is False
    assert policy["driver_registration_allowed"] is False
    assert policy["autostart_registration_allowed"] is False
    state = b135.contract()["implementation_state"]
    assert state["service_registration_available"] is False
    assert state["driver_registration_available"] is False
    assert state["autostart_registration_available"] is False


def test_environment_classification_only_grants_clean_pc_to_windows_ci() -> None:
    assert (
        b135.classify_environment({"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows"})
        == b135.CI_ENVIRONMENT
    )
    assert (
        b135.classify_environment({"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"})
        == b135.LOCAL_ENVIRONMENT
    )
    assert b135.classify_environment({}) == b135.LOCAL_ENVIRONMENT


def test_contract_validation_is_deterministic() -> None:
    data = b135.contract()
    assert b135.validate_contract(data) == ()
    assert b135.contract() == b135.contract()
    assert b135.self_check()["passed"] is True
    assert len(b135.self_check()["contract_digest"]) == 64


def test_ci_evidence_accepts_authoritative_clean_pc_classification() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    assert evidence["authoritative_clean_pc_evidence"] is True
    assert b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40) == ()


def test_local_evidence_is_valid_but_not_authoritative_clean_pc() -> None:
    evidence = _evidence(b135.LOCAL_ENVIRONMENT)
    assert evidence["authoritative_clean_pc_evidence"] is False
    assert b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40) == ()


def test_evidence_rejects_fake_clean_pc_claim_from_local_environment() -> None:
    evidence = _evidence(b135.LOCAL_ENVIRONMENT)
    evidence["authoritative_clean_pc_evidence"] = True
    evidence = b135.finalize_lifecycle_evidence(evidence)
    failures = b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40)
    assert "b135:clean_pc_authority_invalid" in failures


def test_evidence_rejects_missing_preservation_or_upgrade_proof() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    evidence["unknown_child_preserved_across_upgrade"] = False
    evidence["target_hash_changed"] = False
    evidence = b135.finalize_lifecycle_evidence(evidence)
    failures = b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40)
    assert "b135:required_pass_missing:unknown_child_preserved_across_upgrade" in failures
    assert "b135:required_pass_missing:target_hash_changed" in failures


def test_evidence_rejects_public_trust_or_forbidden_registration_claims() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    evidence["public_trust_signature_verified"] = True
    evidence["service_registration_observed"] = True
    evidence = b135.finalize_lifecycle_evidence(evidence)
    failures = b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40)
    assert "b135:forbidden_state_observed:public_trust_signature_verified" in failures
    assert "b135:forbidden_state_observed:service_registration_observed" in failures


def test_evidence_rejects_same_predecessor_and_upgraded_hash() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    evidence["upgraded_app_sha256"] = evidence["predecessor_app_sha256"]
    evidence = b135.finalize_lifecycle_evidence(evidence)
    failures = b135.validate_lifecycle_evidence(evidence, expected_build_commit="a" * 40)
    assert "b135:upgrade_did_not_change_application_hash" in failures


def test_evidence_digest_detects_tamper() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    tampered = deepcopy(evidence)
    tampered["upgrade_passed"] = False
    failures = b135.validate_lifecycle_evidence(tampered, expected_build_commit="a" * 40)
    assert "b135:required_pass_missing:upgrade_passed" in failures
    assert "b135:evidence_digest_invalid" in failures


def test_build_commit_binding_is_exact() -> None:
    evidence = _evidence(b135.CI_ENVIRONMENT)
    failures = b135.validate_lifecycle_evidence(evidence, expected_build_commit="b" * 40)
    assert "b135:evidence_build_commit_invalid" in failures
