from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel import rescue_console_integrated_certification as b44
from sentinel import rescue_hostile_scenarios as b51
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_recovery_decision as b54
from sentinel import rescue_session_resume as b53
from sentinel import rescue_stress_hardening as b52


FP = "a" * 64


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_b42(path: Path) -> Path:
    return write_json(path, {
        "profile": b54.B42_PROFILE,
        "target_fingerprint": FP,
        "operator_confirmation_required": True,
        "execution_performed": False,
        "automatic_execution": False,
        "automatic_repair": False,
    })


def make_b43(path: Path, *, executed: bool = True) -> Path:
    return write_json(path, {
        "profile": b54.B43_PROFILE,
        "target_fingerprint": FP,
        "execution_requested": executed,
        "safety": {"source_read_only": True, "repair_execution": False, "recovery_certification": False},
    })


def make_cert(path: Path, outcome: str, *, b42_path: Path | None = None, b43_path: Path | None = None) -> Path:
    recovered = outcome == rr6.OUTCOME_RECOVERED
    core = {
        "schema": b44.SUMMARY_SCHEMA,
        "profile": b44.PROFILE,
        "created_utc": "2026-09-11T00:00:00Z",
        "session_id": "B44-TEST",
        "correlation_id": "test",
        "target_fingerprint": FP,
        "outcome": outcome,
        "certified_recovered": recovered,
        "rr6_invoked": outcome != rr6.OUTCOME_REFUSED,
        "rr6_report_path": "",
        "rr6_report_sha256": "",
        "session_refusal_reasons": ["fixture_refusal"] if outcome == rr6.OUTCOME_REFUSED else [],
        "rr6_refusal_reasons": ["fixture_refusal"] if outcome == rr6.OUTCOME_REFUSED else [],
        "rr6_not_recovered_reasons": ["fixture_unresolved"] if outcome == rr6.OUTCOME_NOT_RECOVERED else [],
        "evidence": {
            "b40_plan_sha256": "1" * 64,
            "rr3_scan_sha256": "2" * 64,
            "critical_baseline_sha256": "3" * 64,
            "provenance_sha256": "4" * 64,
            "b42_handoff_sha256": file_sha(b42_path) if b42_path else "",
            "repair_transaction_sha256": "",
            "b43_summary_sha256": file_sha(b43_path) if b43_path else "",
            "b43_manifest_sha256": "",
        },
        "safety": {
            "target_read_only": True,
            "repair_execution": False,
            "automatic_destructive_action": False,
            "format_or_reimage_suppressed": False,
        },
        "duration_ms": 1.0,
    }
    payload = {**core, "summary_sha256": hashlib.sha256(canonical(core)).hexdigest()}
    return write_json(path, payload)


def make_health(path: Path, state: str) -> Path:
    core = {
        "schema": b51.SCHEMA,
        "profile": b51.PROFILE,
        "target_root": "X:/offline",
        "target_fingerprint": FP,
        "target_contract_valid": state != b51.STATE_DAMAGED,
        "target_contract_error": "" if state != b51.STATE_DAMAGED else "fixture",
        "state": state,
        "reason": "fixture",
        "critical_present": [],
        "critical_missing": [],
        "limits": {},
        "counters": {},
        "total_sampled_bytes": 0,
        "truncated_by_files": False,
        "truncated_by_bytes": False,
        "truncated_by_time": False,
        "records": [],
        "safety": {"target_read_only": True, "write_attempted": False},
    }
    payload = {
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "elapsed_ms": 1.0,
        "assessment_sha256": hashlib.sha256(canonical(core)).hexdigest(),
    }
    return write_json(path, payload)


def make_stress(path: Path, state: str = b52.STATE_COMPLETE, *, fingerprint: str = FP) -> Path:
    core = {
        "schema": b52.SCHEMA,
        "profile": b52.PROFILE,
        "target_root": "X:/offline",
        "target_fingerprint": fingerprint,
        "state": state,
        "reason": "fixture",
        "limits": {},
        "counters": {"probed": 1, "slow_reads": 0},
        "enumeration": {},
        "sampled_bytes": 1,
        "records": [],
        "safety": {"target_read_only": True, "write_attempted": False},
    }
    stable = dict(core)
    stable["counters"] = {"probed": 1}
    payload = {
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "probe_sha256": hashlib.sha256(canonical(stable)).hexdigest(),
        "performance": {"elapsed_ms": 1.0},
    }
    return write_json(path, payload)


def make_resume(path: Path, *, trusted: bool = True, reconfirm: bool = False) -> Path:
    core = {
        "schema": b53.RESUME_SCHEMA,
        "profile": b53.PROFILE,
        "session_id": "B53-TEST",
        "correlation_id": "test",
        "journal_path": "journal.json",
        "journal_sha256": "5" * 64,
        "expected_target_root": "X:/offline",
        "current_target_root": "X:/offline",
        "expected_target_fingerprint": FP,
        "current_target_fingerprint": FP,
        "trusted": trusted,
        "state": "READY" if trusted else "REFUSED",
        "reasons": [] if trusted else ["fixture_refusal"],
        "actions": [{
            "stage": "repair_execute" if reconfirm else "offline_scan",
            "latest_state": "STARTED",
            "decision": "RECONFIRM_REQUIRED" if reconfirm else "RESUME_READ_ONLY_ALLOWED",
            "reason": "fixture",
            "automatic_resume_allowed": not reconfirm,
        }],
        "evidence_verified": 0,
        "evidence_failed": 0,
        "safety": {
            "automatic_mutation_resume": False,
            "repair_auto_resume": False,
            "data_rescue_auto_resume": False,
            "operator_reconfirmation_preserved": True,
            "target_write_authority_added": False,
            "repair_execution_authority_added": False,
            "quarantine_execution_authority_added": False,
        },
    }
    payload = {**core, "decision_sha256": hashlib.sha256(canonical(core)).hexdigest(), "elapsed_ms": 1.0}
    return write_json(path, payload)


def decide(tmp_path: Path, cert: Path, **kwargs: Path) -> dict:
    return b54.build_decision(b54.DecisionRequest(
        certification_summary=cert,
        output_path=tmp_path / "decision.json",
        health_assessment=kwargs.get("health"),
        stress_probe=kwargs.get("stress"),
        resume_decision=kwargs.get("resume"),
        repair_handoff=kwargs.get("repair"),
        data_rescue_summary=kwargs.get("rescue"),
    ))


def test_rr6_refused_is_indeterminate_even_with_repair(tmp_path: Path) -> None:
    repair = make_b42(tmp_path / "b42.json")
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_REFUSED, b42_path=repair)
    result = decide(tmp_path, cert, repair=repair)
    assert result["state"] == b54.STATE_INDETERMINATE
    assert "rr6_outcome_indeterminate_refused_preserved" in result["reasons"]


def test_not_recovered_without_route_recommends_reimage(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED)
    result = decide(tmp_path, cert)
    assert result["state"] == b54.STATE_REIMAGE_RECOMMENDED


def test_not_recovered_with_bound_repair_is_repairable(tmp_path: Path) -> None:
    repair = make_b42(tmp_path / "b42.json")
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED, b42_path=repair)
    result = decide(tmp_path, cert, repair=repair)
    assert result["state"] == b54.STATE_REPAIRABLE
    assert result["signals"]["repair_handoff_available"] is True


def test_not_recovered_with_data_rescue_only(tmp_path: Path) -> None:
    rescue = make_b43(tmp_path / "b43.json", executed=True)
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED, b43_path=rescue)
    result = decide(tmp_path, cert, rescue=rescue)
    assert result["state"] == b54.STATE_DATA_RESCUE_ONLY


def test_reconfirm_required_precedes_repairable(tmp_path: Path) -> None:
    repair = make_b42(tmp_path / "b42.json")
    resume = make_resume(tmp_path / "resume.json", reconfirm=True)
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED, b42_path=repair)
    result = decide(tmp_path, cert, repair=repair, resume=resume)
    assert result["state"] == b54.STATE_MANUAL_REVIEW
    assert result["signals"]["resume_reconfirm_required"] is True


def test_recovered_clean_is_manual_signoff_not_repair(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    health = make_health(tmp_path / "health.json", b51.STATE_HEALTHY)
    stress = make_stress(tmp_path / "stress.json")
    result = decide(tmp_path, cert, health=health, stress=stress)
    assert result["state"] == b54.STATE_MANUAL_REVIEW
    assert result["rr6_certified_recovered"] is True


def test_recovered_review_required_stays_manual(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    health = make_health(tmp_path / "health.json", b51.STATE_REVIEW)
    result = decide(tmp_path, cert, health=health)
    assert result["state"] == b54.STATE_MANUAL_REVIEW
    assert "persistence_items_still_require_operator_review" in result["reasons"]


def test_recovered_conflicting_damage_becomes_indeterminate(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    health = make_health(tmp_path / "health.json", b51.STATE_DAMAGED)
    result = decide(tmp_path, cert, health=health)
    assert result["state"] == b54.STATE_INDETERMINATE


def test_recovered_incomplete_stress_requires_manual_review(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    stress = make_stress(tmp_path / "stress.json", b52.STATE_PARTIAL_FILE_LIMIT)
    result = decide(tmp_path, cert, stress=stress)
    assert result["state"] == b54.STATE_MANUAL_REVIEW
    assert any("stress_probe_incomplete" in reason for reason in result["reasons"])


def test_tampered_b44_fails_closed(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED)
    payload = json.loads(cert.read_text(encoding="utf-8"))
    payload["outcome"] = rr6.OUTCOME_RECOVERED
    write_json(cert, payload)
    result = decide(tmp_path, cert)
    assert result["state"] == b54.STATE_INDETERMINATE
    assert any("certification_untrusted" in reason for reason in result["reasons"])


def test_tampered_health_fails_closed(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    health = make_health(tmp_path / "health.json", b51.STATE_HEALTHY)
    payload = json.loads(health.read_text(encoding="utf-8"))
    payload["state"] = b51.STATE_REVIEW
    write_json(health, payload)
    result = decide(tmp_path, cert, health=health)
    assert result["state"] == b54.STATE_INDETERMINATE


def test_stress_fingerprint_mismatch_fails_closed(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_RECOVERED)
    stress = make_stress(tmp_path / "stress.json", fingerprint="b" * 64)
    result = decide(tmp_path, cert, stress=stress)
    assert result["state"] == b54.STATE_INDETERMINATE


def test_untrusted_resume_fails_closed(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED)
    resume = make_resume(tmp_path / "resume.json", trusted=False)
    result = decide(tmp_path, cert, resume=resume)
    assert result["state"] == b54.STATE_INDETERMINATE
    assert "b53_session_not_trusted" in result["reasons"]


def test_repair_file_binding_mismatch_fails_closed(tmp_path: Path) -> None:
    repair = make_b42(tmp_path / "b42.json")
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED, b42_path=repair)
    payload = json.loads(repair.read_text(encoding="utf-8"))
    payload["extra"] = "tamper"
    write_json(repair, payload)
    result = decide(tmp_path, cert, repair=repair)
    assert result["state"] == b54.STATE_INDETERMINATE


def test_output_hash_and_safety_contract(tmp_path: Path) -> None:
    cert = make_cert(tmp_path / "cert.json", rr6.OUTCOME_NOT_RECOVERED)
    result = decide(tmp_path, cert)
    assert len(result["decision_sha256"]) == 64
    int(result["decision_sha256"], 16)
    assert result["safety"]["advisory_only"] is True
    assert result["safety"]["rr6_outcome_override"] is False
    assert result["safety"]["automatic_destructive_action"] is False
    assert (tmp_path / "decision.json").is_file()
