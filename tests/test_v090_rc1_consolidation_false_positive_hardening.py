from pathlib import Path

from sentinel.config import APP_VERSION
from sentinel.service_update import version_key
from tools.v090_release_candidate_acceptance import run

ROOT = Path(__file__).resolve().parents[1]


def test_v090_rc1_version_order_and_artifacts():
    assert APP_VERSION == "0.9.0-rc.1"
    assert version_key("0.9.0-beta.3") < version_key(APP_VERSION) < version_key("0.9.0")
    assert (ROOT / "RELEASE-NOTES-v0.9.0-beta.3.md").is_file()
    assert (ROOT / "RELEASE-NOTES-v0.9.0-rc.1.md").is_file()
    assert (ROOT / "BC_SENTINEL_V090_RC1_CONSOLIDATION_REPORT.md").is_file()
    assert (ROOT / "BC_Sentinel_Roadmap_v0_9_0_RC1_Updated.md").is_file()


def test_v090_rc1_local_release_candidate_gate():
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["local_foundation_passed"] is True
    assert all(result["regression_gates"].values())
    fp = result["false_positive_hardening"]
    assert fp["all_benign_cases_below_high"] is True
    assert fp["routine_admin_cases_safe"] is True
    assert fp["strong_detection_retained"] is True


def test_v090_rc1_safety_freeze_remains_non_destructive():
    result = run(service_live=False)
    policy = result["release_policy"]
    assert policy["single_dual_use_tool_is_malware"] is False
    assert policy["single_evidence_high_allowed"] is False
    assert policy["automatic_process_termination"] is False
    assert policy["automatic_file_delete"] is False
    assert policy["automatic_quarantine"] is False
    assert policy["automatic_persistence_remediation"] is False
    assert policy["native_windows_acceptance_required_before_freeze"] is True
    assert policy["service_live_acceptance_required_before_freeze"] is True


def test_v090_rc1_windows_acceptance_contains_foundation_and_live_gates():
    windows = (ROOT / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "release-v090-rc1-foundation" in windows
    assert "release-v090-rc1-live" in windows
