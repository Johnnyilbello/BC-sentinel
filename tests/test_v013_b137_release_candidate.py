from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import beta13_code_signing as b134
from sentinel import beta13_release_candidate as b137


def _sha(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _signing_evidence(installer: Path, *, build_commit: str = "a" * 40) -> dict:
    installer_sha = b137.sha256_file(installer)
    artifacts = []
    for role, name in (
        ("APPLICATION_EXE", "BC-Sentinel.exe"),
        ("INSTALLER_EXE", "BC-Sentinel-Setup-v0.13.0-b134.exe"),
        ("UNINSTALLER_EXE", "Uninstall.exe"),
    ):
        post_hash = installer_sha if role == "INSTALLER_EXE" else _sha(role + ":post")
        artifacts.append(
            {
                "name": name,
                "path_role": role,
                "pre_sign_sha256": _sha(role + ":pre"),
                "post_sign_sha256": post_hash,
                "authenticode_present": True,
                "windows_signature_status": "UnknownError",
                "signer_subject": "CN=BC TECH Studio Engineering Test",
                "signer_thumbprint": "1" * 40,
                "timestamp_present": True,
                "timestamp_subject": "CN=Microsoft Public RSA Time Stamping Authority",
                "signtool_verify_passed": False,
                "modified_after_signing": False,
            }
        )
    return b134.build_signing_evidence(
        build_commit=build_commit,
        provider=b134.PROVIDER_CERTIFICATE_STORE,
        trust_level=b134.TRUST_ENGINEERING,
        expected_publisher="BC TECH Studio",
        artifacts=artifacts,
        timestamp_url=b134.DEFAULT_TIMESTAMP_URL,
    )


def _bundle(tmp_path: Path, *, build_commit: str = "a" * 40) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    installer = root / b137.INSTALLER_FILENAME
    installer.write_bytes(b"controlled-engineering-installer")
    evidence = _signing_evidence(installer, build_commit=build_commit)
    signing_path = tmp_path / "source-signing-evidence.json"
    signing_path.write_text(json.dumps(evidence), encoding="utf-8")
    b137.write_distribution_metadata(
        root=root,
        build_commit=build_commit,
        signing_evidence_path=signing_path,
    )
    return root


def test_self_check_binds_exact_b136_checkpoint_and_preserves_code_signing_blocker() -> None:
    report = b137.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b136-pass"
    assert report["source_checkpoint_commit"] == "b981afa453e6540e18e5ec1fac7da74ce9344829"
    assert report["accepted_checkpoint_count"] == 7
    projection = report["readiness_projection"]
    assert projection["pillar_counts"] == {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}
    assert projection["release_blockers"] == ["CODE_SIGNING"]
    assert projection["engineering_release_candidate_ready"] is True
    assert projection["ready_for_public_launch"] is False
    assert projection["ready_for_paid_launch"] is False


def test_contract_is_deterministic_and_keeps_scenario_specific_coverage() -> None:
    first = b137.contract()
    second = b137.contract()
    assert first == second
    assert first["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert first["boundaries"]["coverage_promoted"] is False
    assert first["boundaries"]["authority_expanded"] is False


def test_manifest_binds_installer_to_engineering_signing_evidence(tmp_path: Path) -> None:
    installer = tmp_path / b137.INSTALLER_FILENAME
    installer.write_bytes(b"installer")
    evidence = _signing_evidence(installer)
    manifest = b137.build_distribution_manifest(
        build_commit="a" * 40,
        installer_path=installer,
        signing_evidence=evidence,
    )
    assert manifest["installer_sha256"] == b137.sha256_file(installer)
    assert manifest["trust_level"] == b134.TRUST_ENGINEERING
    assert manifest["public_trust_signature_verified"] is False
    assert manifest["public_release_ready"] is False
    assert b137.validate_distribution_manifest(
        manifest,
        installer_path=installer,
        expected_build_commit="a" * 40,
    ) == ()


def test_manifest_rejects_tampered_installer(tmp_path: Path) -> None:
    installer = tmp_path / b137.INSTALLER_FILENAME
    installer.write_bytes(b"installer")
    evidence = _signing_evidence(installer)
    manifest = b137.build_distribution_manifest(
        build_commit="a" * 40,
        installer_path=installer,
        signing_evidence=evidence,
    )
    installer.write_bytes(b"tampered")
    failures = b137.validate_distribution_manifest(
        manifest,
        installer_path=installer,
        expected_build_commit="a" * 40,
    )
    assert "b137:manifest_installer_hash_mismatch" in failures


def test_manifest_refuses_public_trust_claim_in_engineering_rc(tmp_path: Path) -> None:
    installer = tmp_path / b137.INSTALLER_FILENAME
    installer.write_bytes(b"installer")
    evidence = _signing_evidence(installer)
    evidence["public_trust_signature_verified"] = True
    body = dict(evidence)
    body.pop("evidence_digest")
    evidence["evidence_digest"] = b134._digest(body)
    with pytest.raises(ValueError, match="signing_evidence_invalid|public_trust"):
        b137.build_distribution_manifest(
            build_commit="a" * 40,
            installer_path=installer,
            signing_evidence=evidence,
        )


def test_provenance_contains_all_accepted_beta13_checkpoints(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    provenance = json.loads((root / b137.PROVENANCE_FILENAME).read_text(encoding="utf-8"))
    assert provenance["accepted_checkpoints"] == b137.ACCEPTED_CHECKPOINTS
    assert provenance["accepted_checkpoint_count"] == 7
    assert provenance["b135_clean_pc_ci_run"] == 35446297278
    assert provenance["b136_commercial_ci_run"] == 35447930415
    assert provenance["remaining_release_blockers"] == ["CODE_SIGNING"]
    assert provenance["public_release_ready"] is False


def test_distribution_root_has_exact_inventory_and_hashes(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    assert b137.validate_distribution_root(root, expected_build_commit="a" * 40) == ()
    assert {item.name for item in root.iterdir()} == {
        b137.INSTALLER_FILENAME,
        b137.SIGNING_EVIDENCE_FILENAME,
        b137.MANIFEST_FILENAME,
        b137.PROVENANCE_FILENAME,
        b137.HASHES_FILENAME,
        b137.NOTICE_FILENAME,
    }


def test_distribution_root_detects_modified_metadata(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    notice = root / b137.NOTICE_FILENAME
    notice.write_text(notice.read_text(encoding="utf-8") + "tamper", encoding="utf-8")
    failures = b137.validate_distribution_root(root, expected_build_commit="a" * 40)
    assert any(item.startswith("b137:hash_mismatch:") for item in failures)


def test_notice_makes_public_trust_boundary_explicit() -> None:
    notice = b137.rc_notice()
    assert "ENGINEERING RELEASE CANDIDATE" in notice
    assert "does NOT establish Public Trust" in notice
    assert "CODE_SIGNING" in notice
    assert "PARTIAL=4 / GAP=0 / VERIFIED=7" in notice


@pytest.mark.parametrize(
    ("environment", "authoritative"),
    [
        ("DISPOSABLE_WINDOWS_CI_RUNNER", True),
        ("LOCAL_GUARDED_REHEARSAL", False),
    ],
)
def test_freeze_evidence_distinguishes_clean_pc_authority(
    environment: str,
    authoritative: bool,
) -> None:
    evidence = b137.build_freeze_evidence(
        build_commit="a" * 40,
        environment_classification=environment,
        authoritative_clean_pc_evidence=authoritative,
        archive_sha256="1" * 64,
        installer_sha256="2" * 64,
        manifest_digest="3" * 64,
        provenance_digest="4" * 64,
        install_passed=True,
        self_check_passed=True,
        ui_smoke_passed=True,
        diagnostics_passed=True,
        uninstall_passed=True,
    )
    assert b137.validate_freeze_evidence(
        evidence,
        expected_build_commit="a" * 40,
    ) == ()
    assert evidence["public_release_ready"] is False
    assert evidence["remaining_release_blockers"] == ["CODE_SIGNING"]


def test_local_cannot_claim_authoritative_clean_pc() -> None:
    with pytest.raises(ValueError, match="clean_pc_authority_invalid"):
        b137.build_freeze_evidence(
            build_commit="a" * 40,
            environment_classification="LOCAL_GUARDED_REHEARSAL",
            authoritative_clean_pc_evidence=True,
            archive_sha256="1" * 64,
            installer_sha256="2" * 64,
            manifest_digest="3" * 64,
            provenance_digest="4" * 64,
            install_passed=True,
            self_check_passed=True,
            ui_smoke_passed=True,
            diagnostics_passed=True,
            uninstall_passed=True,
        )


def test_freeze_evidence_rejects_failed_packaged_probe() -> None:
    evidence = b137.build_freeze_evidence(
        build_commit="a" * 40,
        environment_classification="LOCAL_GUARDED_REHEARSAL",
        authoritative_clean_pc_evidence=False,
        archive_sha256="1" * 64,
        installer_sha256="2" * 64,
        manifest_digest="3" * 64,
        provenance_digest="4" * 64,
        install_passed=True,
        self_check_passed=True,
        ui_smoke_passed=False,
        diagnostics_passed=True,
        uninstall_passed=True,
    )
    failures = b137.validate_freeze_evidence(evidence, expected_build_commit="a" * 40)
    assert "b137:evidence_ui_smoke_passed_false" in failures


def test_freeze_evidence_digest_detects_tamper() -> None:
    evidence = b137.build_freeze_evidence(
        build_commit="a" * 40,
        environment_classification="LOCAL_GUARDED_REHEARSAL",
        authoritative_clean_pc_evidence=False,
        archive_sha256="1" * 64,
        installer_sha256="2" * 64,
        manifest_digest="3" * 64,
        provenance_digest="4" * 64,
        install_passed=True,
        self_check_passed=True,
        ui_smoke_passed=True,
        diagnostics_passed=True,
        uninstall_passed=True,
    )
    evidence["archive_sha256"] = "5" * 64
    failures = b137.validate_freeze_evidence(evidence, expected_build_commit="a" * 40)
    assert "b137:evidence_digest_invalid" in failures


def test_b137_does_not_expand_authority_network_or_cloud() -> None:
    report = b137.self_check()
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["public_release_ready"] is False
    assert report["paid_release_ready"] is False
    assert report["public_trust_signature_verified"] is False
    assert report["smartscreen_reputation_guaranteed"] is False
