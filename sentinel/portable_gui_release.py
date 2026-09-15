from __future__ import annotations

"""B6-7 Portable Technician GUI release contract.

This module describes and verifies the final Beta6 built-artifact boundary.  It
adds packaging/acceptance metadata only; it does not grant new remediation
capabilities.  The accepted B6-5.9 quarantine/restore path remains the complete
mutation authority exposed by the current GUI.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Final

PROFILE: Final[str] = "v0.11.0-beta.6-b67-portable-gui"
SCHEMA: Final[str] = "bc-sentinel-beta6-portable-gui-v1"
MANIFEST_SCHEMA: Final[str] = "bc-sentinel-beta6-portable-gui-manifest-v1"
ARTIFACT_NAME: Final[str] = "BC-Sentinel-Beta6-Portable"
ARTIFACT_EXE: Final[str] = ARTIFACT_NAME + ".exe"
MANIFEST_NAME: Final[str] = "portable-gui-integrity.json"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta6-b659-pass"
SOURCE_CHECKPOINT_SHA256: Final[str] = "72c18bbdf1c50c633343750ead0f2467d8705e12"
PACKAGING_MODE: Final[str] = "onedir"


@dataclass(frozen=True)
class ArtifactVerification:
    passed: bool
    failures: tuple[str, ...]
    manifest: dict
    exe_sha256: str

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failures": list(self.failures),
            "manifest": dict(self.manifest),
            "exe_sha256": self.exe_sha256,
        }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_contract() -> dict:
    """Return the immutable B6-7 packaging/safety contract."""

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "artifact_name": ARTIFACT_NAME,
        "artifact_exe": ARTIFACT_EXE,
        "packaging_mode": PACKAGING_MODE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_SHA256,
        "gui": True,
        "windowed": True,
        "portable": True,
        "installer_required": False,
        "service_install": False,
        "driver_install": False,
        "network_required": False,
        "cloud_required": False,
        "startup_command_dispatch": False,
        "general_home_execution_authorized": False,
        "explicit_operator_action_required": True,
        "home_quarantine_action_available": True,
        "persistent_restore_after_restart": True,
        "automatic_cleanup": False,
        "automatic_quarantine": False,
        "automatic_restore": False,
        "automatic_repair": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
        "privileged_system_file_mutation_authorized": False,
    }


def runtime_contract() -> dict:
    """Probe the packaged GUI code without dispatching a scan or remediation."""

    from sentinel import home_guided_resolution_window as window

    ui = window.self_check()
    release = release_contract()
    checks = {
        "release_profile": release.get("profile") == PROFILE,
        "beta6_ui_self_check": ui.get("passed") is True,
        "no_startup_scan": ui.get("startup_scan_dispatch") is False,
        "no_general_execution": ui.get("live_home_execution_authorized") is False,
        "explicit_quarantine_only": ui.get("home_quarantine_action_available") is True,
        "persistent_restore": ui.get("persistent_restore_after_restart") is True,
        "no_automatic_quarantine": ui.get("automatic_quarantine") is False,
        "no_automatic_repair": ui.get("automatic_repair") is False,
        "portable_no_installer": release.get("installer_required") is False,
        "portable_no_service": release.get("service_install") is False,
        "portable_no_driver": release.get("driver_install") is False,
        "portable_no_network": release.get("network_required") is False,
        "portable_no_cloud": release.get("cloud_required") is False,
    }
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": all(checks.values()),
        "checks": checks,
        "release": release,
        "ui_profile": ui.get("profile"),
        "ui_schema": ui.get("schema"),
        "ui_failures": list(ui.get("failures") or []),
    }


def verify_artifact(
    artifact_dir: str | Path,
    manifest_path: str | Path | None = None,
) -> ArtifactVerification:
    root = Path(artifact_dir)
    manifest_file = Path(manifest_path) if manifest_path is not None else root / MANIFEST_NAME
    failures: list[str] = []
    manifest: dict = {}

    if not root.is_dir():
        failures.append("artifact_directory_missing")
    if not manifest_file.is_file():
        failures.append("manifest_missing")
    else:
        try:
            loaded = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = loaded
            else:
                failures.append("manifest_not_mapping")
        except Exception:
            failures.append("manifest_unreadable")

    exe = root / ARTIFACT_EXE
    actual_hash = ""
    if not exe.is_file():
        failures.append("artifact_executable_missing")
    else:
        try:
            actual_hash = sha256_file(exe)
        except OSError:
            failures.append("artifact_executable_unreadable")

    expected = release_contract()
    if manifest:
        if manifest.get("schema") != MANIFEST_SCHEMA:
            failures.append("manifest_schema_mismatch")
        if manifest.get("profile") != PROFILE:
            failures.append("manifest_profile_mismatch")
        if manifest.get("artifact") != ARTIFACT_EXE:
            failures.append("manifest_artifact_name_mismatch")
        if manifest.get("build_mode") != PACKAGING_MODE:
            failures.append("manifest_build_mode_mismatch")
        if manifest.get("source_checkpoint") != SOURCE_CHECKPOINT:
            failures.append("manifest_source_checkpoint_mismatch")
        if manifest.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_SHA256:
            failures.append("manifest_source_checkpoint_commit_mismatch")
        if str(manifest.get("sha256") or "").lower() != actual_hash.lower():
            failures.append("artifact_sha256_mismatch")
        for key in (
            "installer_required",
            "service_install",
            "driver_install",
            "network_required",
            "cloud_required",
            "general_home_execution_authorized",
            "automatic_cleanup",
            "automatic_quarantine",
            "automatic_restore",
            "automatic_repair",
            "delete_authorized",
            "repair_authorized",
            "terminate_process_authorized",
            "trust_allowlist_mutation_authorized",
            "privileged_system_file_mutation_authorized",
        ):
            if manifest.get(key) is not expected.get(key):
                failures.append(f"manifest_safety_mismatch:{key}")
        if manifest.get("explicit_operator_action_required") is not True:
            failures.append("manifest_explicit_operator_action_missing")
        if manifest.get("windowed") is not True:
            failures.append("manifest_windowed_missing")
        if manifest.get("portable") is not True:
            failures.append("manifest_portable_missing")

    return ArtifactVerification(
        passed=not failures,
        failures=tuple(failures),
        manifest=manifest,
        exe_sha256=actual_hash,
    )


def validate_b67_contract() -> dict:
    payload = release_contract()
    checks = {
        "profile": payload["profile"] == PROFILE,
        "onedir": payload["packaging_mode"] == "onedir",
        "windowed": payload["windowed"] is True,
        "portable": payload["portable"] is True,
        "no_installer": payload["installer_required"] is False,
        "no_service": payload["service_install"] is False,
        "no_driver": payload["driver_install"] is False,
        "no_network": payload["network_required"] is False,
        "no_cloud": payload["cloud_required"] is False,
        "no_startup_dispatch": payload["startup_command_dispatch"] is False,
        "explicit_operator_action": payload["explicit_operator_action_required"] is True,
        "no_general_execution": payload["general_home_execution_authorized"] is False,
        "no_automatic_quarantine": payload["automatic_quarantine"] is False,
        "no_automatic_restore": payload["automatic_restore"] is False,
        "no_automatic_repair": payload["automatic_repair"] is False,
        "no_delete": payload["delete_authorized"] is False,
        "no_repair": payload["repair_authorized"] is False,
        "no_process_termination": payload["terminate_process_authorized"] is False,
        "no_trust_mutation": payload["trust_allowlist_mutation_authorized"] is False,
    }
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": all(checks.values()),
        "checks": checks,
        "release": payload,
    }
