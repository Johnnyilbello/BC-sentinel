from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_session_resume as b53

PROFILE = b53.PROFILE
CHECKPOINT = "B5-3-session-resume-crash-recovery"


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B53 SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B53 SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B53 KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def action(decision: dict, stage: str) -> dict:
    return next(row for row in decision["actions"] if row["stage"] == stage)


def run_acceptance(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b53-") as td:
        base = Path(td)
        target = make_windows(base / "offline")
        workspace = base / "workspace"
        before = tree_hashes(target)

        created = b53.create_session(target, workspace)
        journal = Path(created["journal_path"])
        evidence = workspace / "offline-scan.json"
        evidence.write_text('{"result":"trusted"}', encoding="utf-8")

        b53.append_event(journal, stage="target_validation", state=b53.STATE_COMPLETED, reason="validated")
        b53.append_event(journal, stage="offline_scan", state=b53.STATE_STARTED, reason="scan_started", evidence_path=evidence)
        b53.append_event(journal, stage="offline_scan", state=b53.STATE_INTERRUPTED, reason="simulated_power_loss", evidence_path=evidence)
        b53.append_event(journal, stage="repair_execute", state=b53.STATE_INTERRUPTED, reason="simulated_crash")
        b53.append_event(journal, stage="data_rescue", state=b53.STATE_STARTED, reason="copy_started")

        trusted = b53.build_resume_decision(journal, target)

        replay_refused = False
        try:
            b53.append_event(journal, stage="repair_execute", state=b53.STATE_INTERRUPTED, reason="simulated_crash")
        except ValueError as exc:
            replay_refused = "idempotent replay refused" in str(exc)

        evidence.write_text('{"result":"tampered"}', encoding="utf-8")
        evidence_refused = b53.build_resume_decision(journal, target)
        evidence.write_text('{"result":"trusted"}', encoding="utf-8")

        (target / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"B53 SYSTEM CHANGED")
        target_refused = b53.build_resume_decision(journal, target)
        (target / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"B53 SYSTEM")

        original_journal_text = journal.read_text(encoding="utf-8")
        tampered = json.loads(original_journal_text)
        tampered["events"][0]["reason"] = "tampered"
        journal.write_text(json.dumps(tampered), encoding="utf-8")
        journal_refused = b53.build_resume_decision(journal, target)
        journal.write_text(original_journal_text, encoding="utf-8")

        after = tree_hashes(target)
        checks = {
            "profile": trusted.get("profile") == PROFILE,
            "journal_outside_target": not str(journal.resolve()).casefold().startswith(str(target.resolve()).casefold()),
            "journal_hash_present": len(str(created.get("journal_sha256", ""))) == 64,
            "trusted_resume_ready": trusted.get("trusted") is True and trusted.get("state") == "READY",
            "read_only_resume_allowed": action(trusted, "offline_scan").get("decision") == "RESUME_READ_ONLY_ALLOWED",
            "completed_stage_skipped": action(trusted, "target_validation").get("decision") == "SKIP_TERMINAL",
            "repair_reconfirmation_required": action(trusted, "repair_execute").get("decision") == "RECONFIRM_REQUIRED",
            "data_rescue_reconfirmation_required": action(trusted, "data_rescue").get("decision") == "RECONFIRM_REQUIRED",
            "no_repair_auto_resume": trusted["safety"]["repair_auto_resume"] is False,
            "no_data_rescue_auto_resume": trusted["safety"]["data_rescue_auto_resume"] is False,
            "replay_refused": replay_refused,
            "tampered_evidence_refused": evidence_refused.get("trusted") is False and int(evidence_refused.get("evidence_failed", 0)) >= 1,
            "changed_target_refused": target_refused.get("trusted") is False and "target_fingerprint_mismatch" in target_refused.get("reasons", []),
            "tampered_journal_refused": journal_refused.get("trusted") is False and any("hash_mismatch" in r or "journal_sha256_mismatch" in r for r in journal_refused.get("reasons", [])),
            "decision_hash_present": len(str(trusted.get("decision_sha256", ""))) == 64,
            "target_byte_identical_after_restoration": before == after,
            "no_target_write_authority": trusted["safety"]["target_write_authority_added"] is False,
            "no_repair_execution_authority": trusted["safety"]["repair_execution_authority_added"] is False,
            "no_quarantine_execution_authority": trusted["safety"]["quarantine_execution_authority_added"] is False,
        }
        passed = all(checks.values())
        payload = {
            "profile": PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": passed,
            "checks": checks,
            "detail": {
                "session_id": trusted.get("session_id"),
                "correlation_id": trusted.get("correlation_id"),
                "journal_sha256": trusted.get("journal_sha256"),
                "decision_sha256": trusted.get("decision_sha256"),
                "trusted_action_count": len(trusted.get("actions", [])),
                "evidence_refusal_reasons": evidence_refused.get("reasons", []),
                "target_refusal_reasons": target_refused.get("reasons", []),
                "journal_refusal_reasons": journal_refused.get("reasons", []),
            },
            "new_mutation_authority_added": False,
            "automatic_mutation_resume_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
