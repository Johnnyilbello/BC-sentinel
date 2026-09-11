from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console_integrated_certification as b44
from sentinel import rescue_hostile_scenarios as b51
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_recovery_decision as b54
from sentinel import rescue_session_resume as b53
from sentinel import rescue_stress_hardening as b52

PROFILE = b54.PROFILE
CHECKPOINT = "B5-4-advanced-recovery-decision-engine"
FP = "c" * 64


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


def make_b43(path: Path) -> Path:
    return write_json(path, {
        "profile": b54.B43_PROFILE,
        "target_fingerprint": FP,
        "execution_requested": True,
        "safety": {"source_read_only": True, "repair_execution": False, "recovery_certification": False},
    })


def make_cert(path: Path, outcome: str, *, b42_path: Path | None = None, b43_path: Path | None = None) -> Path:
    core = {
        "schema": b44.SUMMARY_SCHEMA,
        "profile": b44.PROFILE,
        "created_utc": "2026-09-11T00:00:00Z",
        "session_id": "B44-B54-ACCEPTANCE",
        "correlation_id": "b54-acceptance",
        "target_fingerprint": FP,
        "outcome": outcome,
        "certified_recovered": outcome == rr6.OUTCOME_RECOVERED,
        "rr6_invoked": outcome != rr6.OUTCOME_REFUSED,
        "rr6_report_path": "",
        "rr6_report_sha256": "",
        "session_refusal_reasons": ["fixture_refused"] if outcome == rr6.OUTCOME_REFUSED else [],
        "rr6_refusal_reasons": ["fixture_refused"] if outcome == rr6.OUTCOME_REFUSED else [],
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
    return write_json(path, {**core, "summary_sha256": hashlib.sha256(canonical(core)).hexdigest()})


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
    return write_json(path, {
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "elapsed_ms": 1.0,
        "assessment_sha256": hashlib.sha256(canonical(core)).hexdigest(),
    })


def make_stress(path: Path, state: str = b52.STATE_COMPLETE) -> Path:
    core = {
        "schema": b52.SCHEMA,
        "profile": b52.PROFILE,
        "target_root": "X:/offline",
        "target_fingerprint": FP,
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
    return write_json(path, {
        **core,
        "created_utc": "2026-09-11T00:00:00Z",
        "probe_sha256": hashlib.sha256(canonical(stable)).hexdigest(),
        "performance": {"elapsed_ms": 1.0},
    })


def make_resume(path: Path, *, reconfirm: bool = False) -> Path:
    core = {
        "schema": b53.RESUME_SCHEMA,
        "profile": b53.PROFILE,
        "session_id": "B53-B54-ACCEPTANCE",
        "correlation_id": "b54-acceptance",
        "journal_path": "journal.json",
        "journal_sha256": "5" * 64,
        "expected_target_root": "X:/offline",
        "current_target_root": "X:/offline",
        "expected_target_fingerprint": FP,
        "current_target_fingerprint": FP,
        "trusted": True,
        "state": "READY",
        "reasons": [],
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
    return write_json(path, {**core, "decision_sha256": hashlib.sha256(canonical(core)).hexdigest(), "elapsed_ms": 1.0})


def run_case(base: Path, name: str, outcome: str, *, repair: bool = False, rescue: bool = False, reconfirm: bool = False, health_state: str | None = None, stress_state: str | None = None) -> dict:
    case = base / name
    case.mkdir(parents=True, exist_ok=True)
    b42_path = make_b42(case / "b42.json") if repair else None
    b43_path = make_b43(case / "b43.json") if rescue else None
    cert = make_cert(case / "cert.json", outcome, b42_path=b42_path, b43_path=b43_path)
    health = make_health(case / "health.json", health_state) if health_state else None
    stress = make_stress(case / "stress.json", stress_state or b52.STATE_COMPLETE) if stress_state else None
    resume = make_resume(case / "resume.json", reconfirm=reconfirm) if reconfirm else None
    return b54.build_decision(b54.DecisionRequest(
        certification_summary=cert,
        output_path=case / "decision.json",
        health_assessment=health,
        stress_probe=stress,
        resume_decision=resume,
        repair_handoff=b42_path,
        data_rescue_summary=b43_path,
    ))


def build_live_fixture(base: Path) -> dict[str, str]:
    base.mkdir(parents=True, exist_ok=True)
    cert = make_cert(base / "cert.json", rr6.OUTCOME_RECOVERED)
    health = make_health(base / "health.json", b51.STATE_HEALTHY)
    stress = make_stress(base / "stress.json", b52.STATE_COMPLETE)
    return {"cert": str(cert), "health": str(health), "stress": str(stress), "output": str(base / "live-decision.json")}


def run_acceptance(output: Path, fixture_dir: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b54-") as td:
        base = Path(td)
        refused = run_case(base, "refused", rr6.OUTCOME_REFUSED, repair=True)
        repairable = run_case(base, "repairable", rr6.OUTCOME_NOT_RECOVERED, repair=True)
        rescue_only = run_case(base, "rescue", rr6.OUTCOME_NOT_RECOVERED, rescue=True)
        reimage = run_case(base, "reimage", rr6.OUTCOME_NOT_RECOVERED)
        recovered = run_case(base, "recovered", rr6.OUTCOME_RECOVERED, health_state=b51.STATE_HEALTHY, stress_state=b52.STATE_COMPLETE)
        reconfirm = run_case(base, "reconfirm", rr6.OUTCOME_NOT_RECOVERED, repair=True, reconfirm=True)
        conflict = run_case(base, "conflict", rr6.OUTCOME_RECOVERED, health_state=b51.STATE_DAMAGED)

        tamper_dir = base / "tamper"
        cert = make_cert(tamper_dir / "cert.json", rr6.OUTCOME_NOT_RECOVERED)
        payload = json.loads(cert.read_text(encoding="utf-8"))
        payload["outcome"] = rr6.OUTCOME_RECOVERED
        write_json(cert, payload)
        tampered = b54.build_decision(b54.DecisionRequest(cert, tamper_dir / "decision.json"))

        checks = {
            "profile": refused.get("profile") == PROFILE,
            "refused_preserved_indeterminate": refused.get("state") == b54.STATE_INDETERMINATE,
            "repairable_state": repairable.get("state") == b54.STATE_REPAIRABLE,
            "data_rescue_only_state": rescue_only.get("state") == b54.STATE_DATA_RESCUE_ONLY,
            "reimage_recommended_state": reimage.get("state") == b54.STATE_REIMAGE_RECOMMENDED,
            "recovered_requires_manual_signoff": recovered.get("state") == b54.STATE_MANUAL_REVIEW,
            "reconfirm_precedes_repairable": reconfirm.get("state") == b54.STATE_MANUAL_REVIEW,
            "recovered_damage_conflict_indeterminate": conflict.get("state") == b54.STATE_INDETERMINATE,
            "tampered_certification_indeterminate": tampered.get("state") == b54.STATE_INDETERMINATE,
            "decision_hash_present": all(len(str(x.get("decision_sha256", ""))) == 64 for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
            "advisory_only": all(x["safety"]["advisory_only"] is True for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
            "rr6_never_overridden": all(x["safety"]["rr6_outcome_override"] is False for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
            "no_automatic_destructive_action": all(x["safety"]["automatic_destructive_action"] is False for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
            "no_repair_execution_authority": all(x["safety"]["repair_execution_authority_added"] is False for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
            "no_quarantine_execution_authority": all(x["safety"]["quarantine_execution_authority_added"] is False for x in [refused, repairable, rescue_only, reimage, recovered, reconfirm, conflict, tampered]),
        }
        live_fixture = build_live_fixture(fixture_dir) if fixture_dir is not None else {}
        payload = {
            "profile": PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "refused_state": refused["state"],
                "repairable_state": repairable["state"],
                "data_rescue_only_state": rescue_only["state"],
                "reimage_state": reimage["state"],
                "recovered_state": recovered["state"],
                "reconfirm_state": reconfirm["state"],
                "conflict_state": conflict["state"],
                "tampered_state": tampered["state"],
                "repairable_decision_sha256": repairable["decision_sha256"],
                "live_fixture": live_fixture,
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
            "rr6_outcome_override_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture-dir")
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output), Path(args.fixture_dir) if args.fixture_dir else None)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
