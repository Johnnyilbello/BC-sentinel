from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import rescue_session_resume as b53


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ KERNEL")
    return root


def make_session(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = make_windows(tmp_path / "offline")
    workspace = tmp_path / "workspace"
    created = b53.create_session(target, workspace)
    return target, workspace, Path(created["journal_path"])


def test_init_creates_hashed_journal_outside_target(tmp_path: Path) -> None:
    target, workspace, journal = make_session(tmp_path)
    payload = json.loads(journal.read_text(encoding="utf-8"))
    assert payload["profile"] == b53.PROFILE
    assert payload["schema"] == b53.JOURNAL_SCHEMA
    assert len(payload["journal_sha256"]) == 64
    assert payload["safety"]["automatic_mutation_resume"] is False
    assert journal.parent == workspace.resolve()
    assert not str(journal).startswith(str(target.resolve()))


def test_workspace_inside_target_refused(tmp_path: Path) -> None:
    target = make_windows(tmp_path / "offline")
    with pytest.raises(ValueError, match="outside target"):
        b53.create_session(target, target / "evidence")


def test_read_only_started_stage_can_resume(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="scan_begin")
    decision = b53.build_resume_decision(journal, target)
    action = next(a for a in decision["actions"] if a["stage"] == "offline_scan")
    assert decision["trusted"] is True
    assert action["decision"] == "RESUME_READ_ONLY_ALLOWED"
    assert action["automatic_resume_allowed"] is True


def test_read_only_interrupted_stage_can_resume(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="stress_probe", state=b53.STATE_INTERRUPTED, reason="power_loss")
    decision = b53.build_resume_decision(journal, target)
    action = next(a for a in decision["actions"] if a["stage"] == "stress_probe")
    assert action["decision"] == "RESUME_READ_ONLY_ALLOWED"


def test_repair_interruption_requires_reconfirmation(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="repair_execute", state=b53.STATE_INTERRUPTED, reason="crash")
    decision = b53.build_resume_decision(journal, target)
    action = next(a for a in decision["actions"] if a["stage"] == "repair_execute")
    assert action["decision"] == "RECONFIRM_REQUIRED"
    assert action["automatic_resume_allowed"] is False
    assert decision["safety"]["repair_auto_resume"] is False


def test_data_rescue_interruption_requires_reconfirmation(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="data_rescue", state=b53.STATE_STARTED, reason="copy_started")
    decision = b53.build_resume_decision(journal, target)
    action = next(a for a in decision["actions"] if a["stage"] == "data_rescue")
    assert action["decision"] == "RECONFIRM_REQUIRED"
    assert decision["safety"]["data_rescue_auto_resume"] is False


def test_completed_stage_is_terminal_skip(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="target_validation", state=b53.STATE_COMPLETED, reason="validated")
    decision = b53.build_resume_decision(journal, target)
    action = next(a for a in decision["actions"] if a["stage"] == "target_validation")
    assert action["decision"] == "SKIP_TERMINAL"
    assert action["automatic_resume_allowed"] is False


def test_duplicate_event_replay_refused(tmp_path: Path) -> None:
    _, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="same")
    with pytest.raises(ValueError, match="idempotent replay refused"):
        b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="same")


def test_event_hash_chain_is_linked(tmp_path: Path) -> None:
    _, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="target_validation", state=b53.STATE_COMPLETED, reason="one")
    result = b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="two")
    first, second = result["events"]
    assert second["previous_event_sha256"] == first["event_sha256"]
    assert len(second["event_sha256"]) == 64


def test_tampered_journal_is_refused(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="scan")
    payload = json.loads(journal.read_text(encoding="utf-8"))
    payload["events"][0]["reason"] = "tampered"
    journal.write_text(json.dumps(payload), encoding="utf-8")
    decision = b53.build_resume_decision(journal, target)
    assert decision["trusted"] is False
    assert decision["state"] == "REFUSED"
    assert any("hash_mismatch" in r or "journal_sha256_mismatch" in r for r in decision["reasons"])
    assert all(a["automatic_resume_allowed"] is False for a in decision["actions"])


def test_changed_target_fingerprint_refuses_resume(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="scan")
    (target / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"SYSTEM CHANGED")
    decision = b53.build_resume_decision(journal, target)
    assert decision["trusted"] is False
    assert "target_fingerprint_mismatch" in decision["reasons"]


def test_evidence_hash_is_verified_on_resume(tmp_path: Path) -> None:
    target, workspace, journal = make_session(tmp_path)
    evidence = workspace / "scan.json"
    evidence.write_text('{"scan":"ok"}', encoding="utf-8")
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_COMPLETED, reason="scan_done", evidence_path=evidence)
    decision = b53.build_resume_decision(journal, target)
    assert decision["trusted"] is True
    assert decision["evidence_verified"] == 1
    assert decision["evidence_failed"] == 0


def test_tampered_evidence_refuses_resume(tmp_path: Path) -> None:
    target, workspace, journal = make_session(tmp_path)
    evidence = workspace / "scan.json"
    evidence.write_text('{"scan":"ok"}', encoding="utf-8")
    b53.append_event(journal, stage="offline_scan", state=b53.STATE_COMPLETED, reason="scan_done", evidence_path=evidence)
    evidence.write_text('{"scan":"tampered"}', encoding="utf-8")
    decision = b53.build_resume_decision(journal, target)
    assert decision["trusted"] is False
    assert decision["evidence_failed"] == 1
    assert any("evidence_untrusted" in r for r in decision["reasons"])


def test_evidence_inside_target_refused(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    evidence = target / "inside.json"
    evidence.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="outside target"):
        b53.append_event(journal, stage="offline_scan", state=b53.STATE_COMPLETED, evidence_path=evidence)


def test_root_symlink_refused_before_resolution_when_supported(tmp_path: Path) -> None:
    target = make_windows(tmp_path / "offline")
    link = tmp_path / "target-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="symlink/reparse refused before resolution"):
        b53.create_session(link, tmp_path / "workspace")


def test_decision_hash_and_no_mutation_authority(tmp_path: Path) -> None:
    target, _, journal = make_session(tmp_path)
    b53.append_event(journal, stage="health_assessment", state=b53.STATE_INTERRUPTED, reason="restart")
    decision = b53.build_resume_decision(journal, target)
    assert len(decision["decision_sha256"]) == 64
    int(decision["decision_sha256"], 16)
    assert decision["safety"]["automatic_mutation_resume"] is False
    assert decision["safety"]["target_write_authority_added"] is False
    assert decision["safety"]["repair_execution_authority_added"] is False
