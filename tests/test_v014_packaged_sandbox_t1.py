from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import sandbox_t1_runtime as t1


def _summary() -> dict:
    return {
        "passed": True,
        "control_results": {
            "positive": {"outcome": "DETECTED"},
            "administrative": {"outcome": "REVIEW_REQUIRED"},
            "benign": {"outcome": "NO_MATCH"},
        },
    }


def test_packaged_t1_requires_explicit_confirmation(tmp_path: Path):
    with pytest.raises(PermissionError):
        t1.run_authorized_t1(
            confirmed=False,
            report_path=tmp_path / "result.json",
        )


def test_packaged_t1_refuses_unapproved_environment(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(t1, "_authorized_environment", lambda **kwargs: None)
    with pytest.raises(PermissionError):
        t1.run_authorized_t1(
            confirmed=True,
            report_path=tmp_path / "result.json",
        )


def test_triplet_extracts_only_expected_detector_outcomes():
    assert t1._triplet(_summary()) == {
        "positive": "DETECTED",
        "administrative": "REVIEW_REQUIRED",
        "benign": "NO_MATCH",
    }


def test_packaged_t1_report_contract_without_live_side_effects(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        t1,
        "_authorized_environment",
        lambda **kwargs: "TEST_DISPOSABLE",
    )
    monkeypatch.setattr(
        t1,
        "_run_powershell_control",
        lambda **kwargs: {"fixture": True},
    )
    for _test_id, _scenario_id, _script, _switch, module in t1.CONTROL_SCRIPTS:
        monkeypatch.setattr(module, "summarize", lambda evidence: _summary())
    monkeypatch.setattr(t1, "_ransomware_evidence", lambda: {"fixture": True})
    monkeypatch.setattr(t1.beta9_ransomware_controls, "summarize", lambda evidence: _summary())

    report_path = tmp_path / "result.json"
    result = t1.run_authorized_t1(
        confirmed=True,
        report_path=report_path,
    )

    assert result["passed"] is True
    assert result["test_count"] == 4
    assert result["python_or_git_required"] is False
    assert result["winget_required"] is False
    assert result["network_required"] is False
    assert result["coverage_promoted"] is False
    assert result["remediation_authority_expanded"] is False
    assert all(value is False for key, value in result["safety"].items() if key not in {
        "authorized_t1_only",
        "disposable_temp_workspaces_only",
    })
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["passed"] is True
    assert saved["test_count"] == 4


def test_packaged_t1_source_has_no_real_attack_or_network_capability():
    source = Path(t1.__file__).read_text(encoding="utf-8")
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
    assert "winreg" not in source
    assert "schtasks" not in source.casefold()
    assert "credential" in source
    assert "real_malware_executed" in source
    assert "real_persistence_mutation" in source
    assert "security_control_impairment" in source
    assert "user_file_access" in source
