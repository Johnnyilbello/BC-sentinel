from __future__ import annotations

import copy

from sentinel import beta11_artifact_manifest as artifact_manifest
from sentinel import beta11_release_provenance as provenance
from sentinel import beta11_upgrade_migration_contract as migration


def _unsigned() -> dict:
    return provenance.derive_signing_evidence(signature_present=False)


def _verified() -> dict:
    return provenance.derive_signing_evidence(
        signature_present=True,
        signature_verified=True,
        signer_subject="CN=BC Sentinel Test",
        certificate_thumbprint_sha256="a" * 64,
        verification_method=provenance.AUTHENTICODE_VERIFICATION_METHOD,
        timestamp_present=True,
    )


def _record(signing: dict | None = None, **overrides: object) -> dict:
    values: dict[str, object] = {
        "artifact_name": provenance.ARTIFACT_NAME,
        "artifact_sha256": "1" * 64,
        "artifact_tree_digest": "2" * 64,
        "artifact_manifest_digest": "3" * 64,
        "build_commit": provenance.SOURCE_CHECKPOINT_COMMIT,
        "ci_run_id": 35255724334,
        "ci_commit": provenance.SOURCE_CHECKPOINT_COMMIT,
        "ci_passed": True,
        "local_commit": provenance.SOURCE_CHECKPOINT_COMMIT,
        "local_passed": True,
        "signing_evidence": signing or _unsigned(),
    }
    values.update(overrides)
    return provenance.build_release_record(**values)


def test_b117_contract_is_deterministic_valid_and_self_checks() -> None:
    first = provenance.contract()
    second = provenance.contract()
    assert first == second
    assert provenance.validate_contract(first) == ()
    report = provenance.self_check()
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["deterministic_contract"] is True
    assert len(report["contract_digest"]) == 64


def test_b117_binds_exact_b116_checkpoint_and_contract_digest() -> None:
    contract = provenance.contract()
    assert contract["source_checkpoint"] == "checkpoint/v011-beta11-b116-pass"
    assert contract["source_checkpoint_commit"] == "25fc9b50b17d9deb65d61a8e8994334259bb5042"
    assert contract["source_b116_contract_digest"] == "d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9"
    assert contract["source_b116_contract_digest"] == migration.self_check()["contract_digest"]


def test_b117_reuses_accepted_artifact_identity_without_rewriting_b112() -> None:
    contract = provenance.contract()
    assert contract["artifact_name"] == artifact_manifest.ARTIFACT_NAME
    assert contract["artifact_manifest_schema"] == artifact_manifest.SCHEMA
    assert contract["artifact_name"] == "BC-Sentinel-Beta11.exe"


def test_b117_preserves_coverage_and_verified_scenarios() -> None:
    contract = provenance.contract()
    assert contract["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert contract["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert provenance.IMPLEMENTATION_STATE["coverage_promoted"] is False
    assert provenance.IMPLEMENTATION_STATE["authority_expanded"] is False


def test_b117_signature_absence_is_factually_unsigned() -> None:
    evidence = _unsigned()
    assert evidence["accepted"] is True
    assert evidence["state"] == "UNSIGNED"
    assert evidence["signature_present"] is False
    assert evidence["signature_verified"] is False
    assert evidence["signing_executed_by_b117"] is False
    assert evidence["verification_executed_by_b117"] is False
    assert provenance.validate_signing_evidence(evidence) == ()


def test_b117_signature_presence_without_verification_is_not_promoted() -> None:
    evidence = provenance.derive_signing_evidence(signature_present=True)
    assert evidence["accepted"] is True
    assert evidence["state"] == "SIGNED_UNVERIFIED"
    assert evidence["signature_verified"] is False
    assert provenance.validate_signing_evidence(evidence) == ()


def test_b117_verified_signature_requires_explicit_authenticode_evidence() -> None:
    evidence = _verified()
    assert evidence["accepted"] is True
    assert evidence["state"] == "SIGNED_VERIFIED"
    assert evidence["signature_present"] is True
    assert evidence["signature_verified"] is True
    assert evidence["signer_subject"] == "CN=BC Sentinel Test"
    assert evidence["certificate_thumbprint_sha256"] == "a" * 64
    assert evidence["verification_method"] == provenance.AUTHENTICODE_VERIFICATION_METHOD
    assert provenance.validate_signing_evidence(evidence) == ()


def test_b117_verified_signature_fails_closed_without_subject_thumbprint_or_method() -> None:
    evidence = provenance.derive_signing_evidence(
        signature_present=True,
        signature_verified=True,
    )
    assert evidence["accepted"] is False
    assert evidence["state"] == "SIGNED_VERIFIED"
    assert evidence["reasons"] == [
        "verified_certificate_thumbprint_invalid",
        "verified_signature_method_invalid",
        "verified_signer_subject_missing",
    ]


def test_b117_contradictory_unsigned_evidence_fails_closed_and_stays_unsigned() -> None:
    evidence = provenance.derive_signing_evidence(
        signature_present=False,
        signature_verified=True,
        signer_subject="CN=Forged",
        certificate_thumbprint_sha256="f" * 64,
        verification_method=provenance.AUTHENTICODE_VERIFICATION_METHOD,
        timestamp_present=True,
    )
    assert evidence["accepted"] is False
    assert evidence["state"] == "UNSIGNED"
    assert "verified_signature_without_signature" in evidence["reasons"]
    assert "signer_subject_without_signature" in evidence["reasons"]
    assert "certificate_thumbprint_without_signature" in evidence["reasons"]


def test_b117_unsigned_release_record_is_provenance_ready_but_not_signed_ready() -> None:
    first = _record()
    second = _record()
    assert first == second
    assert provenance.validate_release_record(first) == ()
    assert first["provenance_ready"] is True
    assert first["signing_state"] == "UNSIGNED"
    assert first["signed_release_ready"] is False
    assert len(first["record_digest"]) == 64


def test_b117_verified_signed_record_requires_same_build_commit_for_ci_and_local() -> None:
    record = _record(_verified())
    assert provenance.validate_release_record(record) == ()
    assert record["provenance_ready"] is True
    assert record["signing_state"] == "SIGNED_VERIFIED"
    assert record["signed_release_ready"] is True
    assert record["ci_evidence"]["commit"] == record["build_commit"]
    assert record["local_evidence"]["commit"] == record["build_commit"]


def test_b117_record_fails_closed_on_artifact_hash_or_manifest_hash_errors() -> None:
    record = _record(
        artifact_sha256="bad",
        artifact_tree_digest="also-bad",
        artifact_manifest_digest="still-bad",
    )
    assert record["provenance_ready"] is False
    assert record["signed_release_ready"] is False
    assert record["reasons"] == [
        "artifact_manifest_digest_invalid",
        "artifact_sha256_invalid",
        "artifact_tree_digest_invalid",
    ]


def test_b117_record_fails_closed_on_ci_or_local_commit_mismatch() -> None:
    record = _record(
        ci_commit="0" * 40,
        local_commit="1" * 40,
    )
    assert record["provenance_ready"] is False
    assert record["reasons"] == ["ci_commit_mismatch", "local_commit_mismatch"]
    assert record["signed_release_ready"] is False


def test_b117_record_requires_successful_ci_and_local_acceptance() -> None:
    record = _record(ci_passed=False, local_passed=False)
    assert record["provenance_ready"] is False
    assert record["reasons"] == ["ci_acceptance_not_passed", "local_acceptance_not_passed"]


def test_b117_record_rejects_invalid_ci_run_identity() -> None:
    record = _record(ci_run_id=0)
    assert record["provenance_ready"] is False
    assert record["reasons"] == ["ci_run_id_invalid"]


def test_b117_record_never_treats_hashes_as_signature_evidence() -> None:
    record = _record()
    assert record["artifact_sha256"] == "1" * 64
    assert record["artifact_tree_digest"] == "2" * 64
    assert record["artifact_manifest_digest"] == "3" * 64
    assert record["signing_state"] == "UNSIGNED"
    assert record["signed_release_ready"] is False


def test_b117_validator_detects_tampering_with_record_digest_or_signing_state() -> None:
    record = _record()
    tampered = copy.deepcopy(record)
    tampered["artifact_sha256"] = "4" * 64
    assert "b117:release_record_digest_invalid" in provenance.validate_release_record(tampered)

    tampered = copy.deepcopy(record)
    tampered["signing_state"] = "SIGNED_VERIFIED"
    failures = provenance.validate_release_record(tampered)
    assert "b117:release_record_digest_invalid" in failures
    assert "b117:release_record_signing_state_inconsistent" in failures


def test_b117_contract_validator_rejects_checkpoint_coverage_or_execution_promotion() -> None:
    broken = copy.deepcopy(provenance.contract())
    broken["source_checkpoint_commit"] = "0" * 40
    assert "b117:source_checkpoint_invalid" in provenance.validate_contract(broken)

    broken = copy.deepcopy(provenance.contract())
    broken["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b117:coverage_changed" in provenance.validate_contract(broken)

    broken = copy.deepcopy(provenance.contract())
    broken["implementation_state"]["artifact_signing_execution_available"] = True
    assert "b117:implementation_state_changed" in provenance.validate_contract(broken)


def test_b117_has_no_signing_keys_publication_network_or_host_mutation_authority() -> None:
    state = provenance.contract()["implementation_state"]
    assert state
    assert not any(state.values())
    report = provenance.self_check()
    assert report["artifact_signing_execution_available"] is False
    assert report["signature_verification_execution_available"] is False
    assert report["private_key_access_available"] is False
    assert report["certificate_enrollment_available"] is False
    assert report["timestamp_service_execution_available"] is False
    assert report["release_publication_execution_available"] is False
    assert report["artifact_mutation_available"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False


def test_b117_self_check_is_explicitly_sample_only_and_does_not_claim_real_signature() -> None:
    report = provenance.self_check()
    assert report["sample_release_record_only"] is True
    assert report["release_artifact_observed"] is False
    assert report["sample_signing_state"] == "UNSIGNED"
    assert report["sample_provenance_ready"] is True
    assert report["sample_signed_release_ready"] is False
    assert report["verified_signing_state_supported"] is True
