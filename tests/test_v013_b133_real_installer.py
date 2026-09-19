from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import beta13_installer as b133


def _payload(tmp_path: Path) -> Path:
    root = tmp_path / "BC-Sentinel"
    (root / "_internal" / "nested").mkdir(parents=True)
    (root / b133.PRODUCT_EXE).write_bytes(b"controlled exe")
    (root / "_internal" / "a.dll").write_bytes(b"dll")
    (root / "_internal" / "nested" / "data.bin").write_bytes(b"data")
    return root


def _manifest(tmp_path: Path) -> tuple[Path, dict]:
    root = _payload(tmp_path)
    manifest = b133.build_payload_manifest(
        root,
        build_commit="a" * 40,
        python_version="3.12.10",
        pyinstaller_version="7.0.0",
    )
    return root, manifest


def test_self_check_binds_exact_b132_checkpoint_and_reduces_blockers():
    report = b133.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b132-pass"
    assert report["source_checkpoint_commit"] == "3e64155858d9b8c7efebc28aecc9689795159ae9"
    assert report["per_user_install"] is True
    assert report["administrator_required"] is False
    projection = report["readiness_projection"]
    assert projection["pillar_counts"] == {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}
    assert projection["release_blocker_count"] == 3
    assert projection["release_blockers"] == [
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]


def test_payload_manifest_is_deterministic_and_bound_to_exact_tree(tmp_path: Path):
    root = _payload(tmp_path)
    first = b133.build_payload_manifest(
        root,
        build_commit="a" * 40,
        python_version="3.12.10",
        pyinstaller_version="7.0.0",
    )
    second = b133.build_payload_manifest(
        root,
        build_commit="a" * 40,
        python_version="3.12.10",
        pyinstaller_version="7.0.0",
    )
    assert first == second
    assert b133.validate_payload_manifest(first, root=root, expected_build_commit="a" * 40) == ()
    assert first["file_count"] == 3
    assert len(first["tree_digest"]) == 64
    assert len(first["exe_sha256"]) == 64


def test_payload_manifest_detects_file_tampering(tmp_path: Path):
    root, manifest = _manifest(tmp_path)
    (root / "_internal" / "a.dll").write_bytes(b"tampered")

    failures = b133.validate_payload_manifest(manifest, root=root, expected_build_commit="a" * 40)

    assert "b133:payload_tree_changed" in failures


def test_uninstall_include_deletes_only_manifested_payload(tmp_path: Path):
    _, manifest = _manifest(tmp_path)

    text = b133.uninstall_include(manifest)

    assert 'Delete "$INSTDIR\\BC-Sentinel.exe"' in text
    assert 'Delete "$INSTDIR\\_internal\\a.dll"' in text
    assert 'Delete "$INSTDIR\\_internal\\nested\\data.bin"' in text
    assert 'Delete "$INSTDIR\\install-payload-manifest.json"' in text
    assert "RMDir /r" not in text
    assert "user-owned.keep" not in text


def test_installer_evidence_is_hash_bound_and_unsigned(tmp_path: Path):
    root, manifest = _manifest(tmp_path)
    installer = tmp_path / b133.INSTALLER_FILENAME
    installer.write_bytes(b"controlled NSIS installer fixture")

    evidence = b133.build_installer_evidence(
        installer,
        payload_manifest=manifest,
        build_commit="a" * 40,
        nsis_version=b133.NSIS_VERSION,
    )

    assert b133.validate_installer_evidence(
        evidence,
        installer_path=installer,
        expected_build_commit="a" * 40,
    ) == ()
    assert evidence["installer_available"] is True
    assert evidence["uninstaller_available"] is True
    assert evidence["artifact_signed"] is False
    assert evidence["signing_deferred_to_b134"] is True
    assert evidence["persistent_data_preserved_by_default"] is True
    assert evidence["unknown_install_children_preserved"] is True


def test_installer_evidence_detects_installer_tampering(tmp_path: Path):
    _, manifest = _manifest(tmp_path)
    installer = tmp_path / b133.INSTALLER_FILENAME
    installer.write_bytes(b"original")
    evidence = b133.build_installer_evidence(
        installer,
        payload_manifest=manifest,
        build_commit="a" * 40,
        nsis_version=b133.NSIS_VERSION,
    )
    installer.write_bytes(b"tampered-longer")

    failures = b133.validate_installer_evidence(
        evidence,
        installer_path=installer,
        expected_build_commit="a" * 40,
    )

    assert "b133:evidence_installer_hash_mismatch" in failures
    assert "b133:evidence_installer_size_mismatch" in failures


def test_invalid_build_commit_fails_closed(tmp_path: Path):
    root = _payload(tmp_path)
    with pytest.raises(ValueError, match="build_commit_invalid"):
        b133.build_payload_manifest(
            root,
            build_commit="not-a-commit",
            python_version="3.12",
            pyinstaller_version="7",
        )


def test_nsis_source_is_per_user_and_has_no_privileged_security_mutations():
    nsi = Path("packaging/beta13_installer.nsi").read_text(encoding="utf-8")

    assert "RequestExecutionLevel user" in nsi
    assert 'InstallDir "$LOCALAPPDATA\\Programs\\BC Sentinel"' in nsi
    assert "SetShellVarContext current" in nsi
    assert "WriteRegStr HKCU" in nsi
    assert "WriteRegStr HKLM" not in nsi
    assert "RequestExecutionLevel admin" not in nsi
    assert "nsExec" not in nsi
    assert "sc.exe" not in nsi
    assert "schtasks" not in nsi
    assert "netsh" not in nsi
    assert "Windows Defender" not in nsi
    assert "RMDir /r" not in nsi


def test_persistent_data_namespace_is_outside_install_root():
    assert b133.DEFAULT_INSTALL_TOKEN != b133.PERSISTENT_DATA_TOKEN
    assert "\\Programs\\BC Sentinel" in b133.DEFAULT_INSTALL_TOKEN
    assert b133.PERSISTENT_DATA_TOKEN.endswith("\\BCSentinel")
    assert b133.self_check()["persistent_data_preserved_by_default"] is True


def test_nsis_toolchain_is_pinned():
    assert b133.NSIS_VERSION == "3.12"
    assert b133.NSIS_ZIP_SHA256 == "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"


def test_b133_does_not_claim_signing_service_driver_or_autostart():
    report = b133.self_check()
    assert report["artifact_signed"] is False
    assert report["signing_deferred_to_b134"] is True
    assert report["service_registration"] is False
    assert report["driver_registration"] is False
    assert report["autostart_registration"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
