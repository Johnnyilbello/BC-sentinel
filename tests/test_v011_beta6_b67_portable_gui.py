from __future__ import annotations

import json
from pathlib import Path

from sentinel import portable_gui_release as b67


ROOT = Path(__file__).resolve().parents[1]


def _manifest_for(exe: Path) -> dict:
    release = b67.release_contract()
    return {
        "schema": b67.MANIFEST_SCHEMA,
        "profile": b67.PROFILE,
        "artifact": b67.ARTIFACT_EXE,
        "sha256": b67.sha256_file(exe),
        "build_mode": b67.PACKAGING_MODE,
        "windowed": True,
        "portable": True,
        "build_commit": "test-build",
        "source_checkpoint": b67.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": b67.SOURCE_CHECKPOINT_SHA256,
        "installer_required": release["installer_required"],
        "service_install": release["service_install"],
        "driver_install": release["driver_install"],
        "network_required": release["network_required"],
        "cloud_required": release["cloud_required"],
        "explicit_operator_action_required": True,
        "general_home_execution_authorized": release["general_home_execution_authorized"],
        "automatic_cleanup": release["automatic_cleanup"],
        "automatic_quarantine": release["automatic_quarantine"],
        "automatic_restore": release["automatic_restore"],
        "automatic_repair": release["automatic_repair"],
        "delete_authorized": release["delete_authorized"],
        "repair_authorized": release["repair_authorized"],
        "terminate_process_authorized": release["terminate_process_authorized"],
        "trust_allowlist_mutation_authorized": release["trust_allowlist_mutation_authorized"],
        "privileged_system_file_mutation_authorized": release[
            "privileged_system_file_mutation_authorized"
        ],
    }


def test_b67_contract_is_portable_windowed_and_fail_closed() -> None:
    payload = b67.validate_b67_contract()
    assert payload["passed"] is True
    release = payload["release"]
    assert release["packaging_mode"] == "onedir"
    assert release["windowed"] is True
    assert release["portable"] is True
    assert release["installer_required"] is False
    assert release["service_install"] is False
    assert release["driver_install"] is False
    assert release["network_required"] is False
    assert release["cloud_required"] is False
    assert release["startup_command_dispatch"] is False
    assert release["explicit_operator_action_required"] is True
    assert release["general_home_execution_authorized"] is False
    assert release["automatic_quarantine"] is False
    assert release["automatic_restore"] is False
    assert release["automatic_repair"] is False
    assert release["delete_authorized"] is False
    assert release["repair_authorized"] is False


def test_b67_is_frozen_from_exact_b659_checkpoint() -> None:
    assert b67.SOURCE_CHECKPOINT == "checkpoint/v011-beta6-b659-pass"
    assert b67.SOURCE_CHECKPOINT_SHA256 == "72c18bbdf1c50c633343750ead0f2467d8705e12"


def test_b67_entrypoint_targets_current_beta6_gui() -> None:
    text = (ROOT / "packaging" / "beta6_portable_gui_entry.py").read_text(encoding="utf-8")
    assert "home_guided_resolution_window" in text
    assert "portable_gui_release" in text
    assert "--b67-contract-out" in text
    assert "_ensure_windowed_streams" in text


def test_b67_build_uses_onedir_windowed_and_explicit_hidden_providers() -> None:
    text = (ROOT / "BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1").read_text(encoding="utf-8")
    assert "--onedir" in text
    assert "--windowed" in text
    assert "--onefile" not in text
    assert "sentinel.smart_scan_live_provider" in text
    assert "sentinel.guided_resolution_live_provider" in text
    assert "BC-Sentinel-Beta6-Portable" in text
    assert "portable-gui-integrity.json" in text


def test_b67_build_does_not_request_install_or_elevation() -> None:
    text = (ROOT / "BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1").read_text(encoding="utf-8").lower()
    assert "--uac-admin" not in text
    assert "new-service" not in text
    assert "sc.exe create" not in text
    assert "pnputil" not in text
    assert "driver_install = $false" in text
    assert "service_install = $false" in text
    assert "installer_required = $false" in text


def test_artifact_integrity_manifest_accepts_exact_exe(tmp_path: Path) -> None:
    artifact = tmp_path / b67.ARTIFACT_NAME
    artifact.mkdir()
    exe = artifact / b67.ARTIFACT_EXE
    exe.write_bytes(b"MZ B6-7 deterministic fake executable")
    manifest = _manifest_for(exe)
    (artifact / b67.MANIFEST_NAME).write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )

    result = b67.verify_artifact(artifact)
    assert result.passed is True
    assert result.failures == ()
    assert result.exe_sha256 == manifest["sha256"]


def test_artifact_integrity_manifest_rejects_tampered_exe(tmp_path: Path) -> None:
    artifact = tmp_path / b67.ARTIFACT_NAME
    artifact.mkdir()
    exe = artifact / b67.ARTIFACT_EXE
    exe.write_bytes(b"MZ B6-7 original")
    manifest = _manifest_for(exe)
    (artifact / b67.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    exe.write_bytes(b"MZ B6-7 tampered")

    result = b67.verify_artifact(artifact)
    assert result.passed is False
    assert "artifact_sha256_mismatch" in result.failures


def test_artifact_manifest_rejects_authority_expansion(tmp_path: Path) -> None:
    artifact = tmp_path / b67.ARTIFACT_NAME
    artifact.mkdir()
    exe = artifact / b67.ARTIFACT_EXE
    exe.write_bytes(b"MZ B6-7 authority fixture")
    manifest = _manifest_for(exe)
    manifest["delete_authorized"] = True
    manifest["automatic_repair"] = True
    (artifact / b67.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    result = b67.verify_artifact(artifact)
    assert result.passed is False
    assert "manifest_safety_mismatch:delete_authorized" in result.failures
    assert "manifest_safety_mismatch:automatic_repair" in result.failures


def test_artifact_manifest_requires_explicit_operator_action(tmp_path: Path) -> None:
    artifact = tmp_path / b67.ARTIFACT_NAME
    artifact.mkdir()
    exe = artifact / b67.ARTIFACT_EXE
    exe.write_bytes(b"MZ B6-7 operator action fixture")
    manifest = _manifest_for(exe)
    manifest["explicit_operator_action_required"] = False
    (artifact / b67.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    result = b67.verify_artifact(artifact)
    assert result.passed is False
    assert "manifest_explicit_operator_action_missing" in result.failures
