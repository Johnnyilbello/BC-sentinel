from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_qt_runtime_hook_prefers_frozen_bundle_without_system_mutation():
    text = (ROOT / "packaging" / "windows_qt_runtime_hook.py").read_text(encoding="utf-8")

    assert 'getattr(sys, "frozen", False)' in text
    assert 'getattr(sys, "_MEIPASS", None)' in text
    assert 'getattr(os, "add_dll_directory", None)' in text
    assert '"QT_PLUGIN_PATH"' in text
    assert '"QT_QPA_PLATFORM_PLUGIN_PATH"' in text
    assert '"QML2_IMPORT_PATH"' in text
    assert "subprocess" not in text
    assert "winreg" not in text


def test_windows_installer_build_uses_isolated_environment_and_qt_smoke():
    text = (ROOT / "BUILD-V013-B133-INSTALLER.ps1").read_text(encoding="utf-8")

    assert "isolated-clean-venv" in text
    assert "-m venv" in text
    assert "-m pip check" in text
    assert "PySide6-Essentials" in text
    assert "PySide6-Addons" in text
    assert "shiboken6" in text
    assert "--noupx" in text
    assert "'PySide6.QtCore'" in text
    assert "'PySide6.QtGui'" in text
    assert "'PySide6.QtWidgets'" in text
    assert "Assert-BundledQtRuntime" in text
    assert "Invoke-CleanPackagedCheck" in text
    assert "'QT-SMOKE'" in text


def test_sandbox_wrapper_is_t1_only_and_refuses_real_attack_capabilities():
    text = (
        ROOT / "tools" / "testing" / "RUN-WINDOWS-SANDBOX-T1-SIMULATION.ps1"
    ).read_text(encoding="utf-8")

    assert "-Tier T1" in text
    assert "-ConfirmAuthorizedT1" in text
    assert "WDAGUtilityAccount" in text
    assert "real_malware_executed" in text
    assert "credential_access" in text
    assert "real_persistence_mutation" in text
    assert "security_control_impairment" in text
    assert "user_file_access" in text
    assert "T2" not in text
    assert "T3" not in text
