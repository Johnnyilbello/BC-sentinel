from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.service_update import version_key
from tools.release_candidate_acceptance import run

ROOT = Path(__file__).resolve().parents[1]


def test_rc1_version_order_and_files():
    assert version_key(APP_VERSION) >= version_key("0.8.0-rc.1")
    assert version_key("0.8.0-beta.3") < version_key("0.8.0-rc.1") < version_key("0.8.0")
    assert (ROOT / "RELEASE-NOTES-v0.9.0-beta.3.md").is_file()
    assert (ROOT / "BC_SENTINEL_V080_RC1_CONSOLIDATION_REPORT.md").is_file()


def test_rc1_acceptance_local():
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["local_foundation_passed"] is True
    assert result["consolidation"]["private_key_markers_absent"] is True
    assert all(result["regression_gates"].values())
    assert result["release_policy"]["remote_auto_activate"] is False
    assert result["release_policy"]["cloud_required"] is False


def test_rc1_windows_gate_and_version_neutral_build_banner():
    windows = (ROOT / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    build = (ROOT / "BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
    assert "release-v080-rc1-foundation" in windows
    assert "release-v080-rc1-live" in windows
    assert "BUILD PROTECTION SERVICE + UAC BROKER + FIREWALL OK" in build
    assert "FIREWALL v0.7 OK" not in build
