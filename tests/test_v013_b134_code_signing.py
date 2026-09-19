from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import beta13_code_signing as b134


def _artifact(
    role: str,
    *,
    status: str = "UnknownError",
    verify: bool = False,
    subject: str = "CN=BC TECH Studio Engineering Test",
    thumbprint: str = "a" * 40,
) -> dict:
    return {
        "name": "BC-Sentinel.exe" if role == "APPLICATION_EXE" else "BC-Sentinel-Setup-v0.13.0-b134.exe",
        "path_role": role,
        "pre_sign_sha256": "1" * 64 if role == "APPLICATION_EXE" else "2" * 64,
        "post_sign_sha256": "3" * 64 if role == "APPLICATION_EXE" else "4" * 64,
        "authenticode_present": True,
        "windows_signature_status": status,
        "signer_subject": subject,
        "signer_thumbprint": thumbprint,
        "timestamp_present": True,
        "timestamp_subject": "CN=Microsoft Public RSA Time Stamping Authority",
        "signtool_verify_passed": verify,
        "modified_after_signing": False,
    }


def test_self_check_binds_exact_b133_checkpoint_and_keeps_public_trust_separate():
    report = b134.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b133-pass"
    assert report["source_checkpoint_commit"] == "b6014ef74ffc77814f489532c8f2d09fb92fe17f"
    assert report["self_signed_counts_as_public_trust"] is False
    assert report["public_trust_signature_required_to_resolve_blocker"] is True
    assert report["smartscreen_reputation_guaranteed"] is False


def test_engineering_projection_does_not_resolve_code_signing():
    projection = b134.projected_readiness(public_trust_signature_verified=False)
    assert projection["pillar_counts"] == {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}
    assert projection["release_blocker_count"] == 3
    assert projection["release_blockers"] == [
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]
    assert projection["resolved_by_b134"] == []


def test_public_trust_projection_resolves_only_code_signing():
    projection = b134.projected_readiness(public_trust_signature_verified=True)
    assert projection["pillar_counts"] == {"READY": 8, "PARTIAL": 1, "BLOCKED": 1}
    assert projection["release_blocker_count"] == 2
    assert projection["release_blockers"] == [
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]
    assert projection["resolved_by_b134"] == ["CODE_SIGNING"]


def test_engineering_signing_evidence_can_be_valid_without_public_trust():
    artifacts = [
        _artifact("APPLICATION_EXE"),
        _artifact("INSTALLER_EXE"),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="b" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is True
    assert evidence["public_trust_signature_verified"] is False
    assert evidence["code_signing_release_blocker_resolved"] is False
    assert evidence["smartscreen_reputation_guaranteed"] is False
    assert b134.validate_signing_evidence(evidence, expected_build_commit="b" * 40) == ()


def test_public_trust_requires_windows_valid_and_signtool_verification():
    artifacts = [
        _artifact("APPLICATION_EXE", status="Valid", verify=True, subject="CN=BC TECH Studio"),
        _artifact("INSTALLER_EXE", status="Valid", verify=True, subject="CN=BC TECH Studio"),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="c" * 40,
        provider=b134.PROVIDER_ARTIFACT_SIGNING,
        trust_level=b134.TRUST_PUBLIC,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is True
    assert evidence["public_trust_signature_verified"] is True
    assert evidence["code_signing_release_blocker_resolved"] is True
    assert b134.validate_signing_evidence(evidence, expected_build_commit="c" * 40) == ()


def test_public_trust_rejects_untrusted_signature_status():
    artifacts = [
        _artifact("APPLICATION_EXE", status="UnknownError", verify=False, subject="CN=BC TECH Studio"),
        _artifact("INSTALLER_EXE", status="UnknownError", verify=False, subject="CN=BC TECH Studio"),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="c" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_PUBLIC,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is False
    assert evidence["public_trust_signature_verified"] is False
    assert "b134:release_signature_not_valid" in evidence["failures"]
    assert "b134:release_signtool_verify_failed" in evidence["failures"]


def test_publisher_drift_is_rejected():
    artifacts = [
        _artifact("APPLICATION_EXE", subject="CN=BC TECH Studio"),
        _artifact("INSTALLER_EXE", subject="CN=Someone Else"),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="d" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is False
    assert "b134:publisher_identity_drift" in evidence["failures"]


def test_signer_thumbprint_drift_is_rejected():
    artifacts = [
        _artifact("APPLICATION_EXE", thumbprint="a" * 40),
        _artifact("INSTALLER_EXE", thumbprint="b" * 40),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="d" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is False
    assert "b134:signer_thumbprint_drift" in evidence["failures"]


def test_timestamp_is_required_even_for_engineering_pipeline_evidence():
    artifacts = [
        _artifact("APPLICATION_EXE"),
        _artifact("INSTALLER_EXE"),
    ]
    artifacts[0]["timestamp_present"] = False
    artifacts[0]["timestamp_subject"] = ""
    evidence = b134.build_signing_evidence(
        build_commit="e" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is False
    assert "b134:rfc3161_timestamp_missing" in evidence["failures"]


def test_post_sign_hash_must_change_and_artifact_cannot_be_modified_after_signing():
    artifacts = [
        _artifact("APPLICATION_EXE"),
        _artifact("INSTALLER_EXE"),
    ]
    artifacts[0]["post_sign_sha256"] = artifacts[0]["pre_sign_sha256"]
    artifacts[1]["modified_after_signing"] = True
    evidence = b134.build_signing_evidence(
        build_commit="f" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    assert evidence["pipeline_evidence_valid"] is False
    assert "b134:signature_did_not_change_artifact_hash" in evidence["failures"]
    assert "b134:artifact_modified_after_signing" in evidence["failures"]


def test_evidence_digest_tampering_fails_validation():
    artifacts = [
        _artifact("APPLICATION_EXE"),
        _artifact("INSTALLER_EXE"),
    ]
    evidence = b134.build_signing_evidence(
        build_commit="a" * 40,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )
    tampered = deepcopy(evidence)
    tampered["smartscreen_reputation_guaranteed"] = True
    failures = b134.validate_signing_evidence(tampered, expected_build_commit="a" * 40)
    assert "b134:evidence_digest_invalid" in failures
    assert "b134:evidence_smartscreen_reputation_guaranteed_invalid" in failures


@pytest.mark.parametrize("provider", ["", "UNKNOWN"])
def test_invalid_provider_fails_closed(provider):
    artifacts = [_artifact("APPLICATION_EXE"), _artifact("INSTALLER_EXE")]
    with pytest.raises(ValueError, match="provider_invalid"):
        b134.build_signing_evidence(
            build_commit="a" * 40,
            provider=provider,
            trust_level=b134.TRUST_ENGINEERING,
            expected_publisher="BC TECH Studio",
            artifacts=artifacts,
            timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
        )
