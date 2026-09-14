from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import uuid

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import guided_resolution_real_file_execution as real_execution
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_result(target: Path, digest: str) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b656-real-file-acceptance",
        title="B6-5.6 controlled real-file acceptance",
        severity=smart.SEVERITY_HIGH,
        category="acceptance",
        reason="Controlled user-profile file for reversible B6-5.6 acceptance",
        source_check_id="files",
        path=str(target),
        confidence=1.0,
        evidence={"sha256": digest, "signals": ["b656_controlled_real_file_acceptance"]},
    )
    plan = smart.SmartScanPlan(
        provider_name="b656-acceptance-source",
        provider_profile="b656-acceptance-source-v1",
        provider_provenance="b656_live_acceptance",
        checks=(smart.SmartScanCheck("files", "Files", "Controlled user file", True, "b656_live_acceptance"),),
    )
    check = smart.SmartScanCheckResult("files", smart.CHECK_COMPLETED, "Controlled file prepared", findings=(finding,), evidence={"controlled_acceptance": True})
    return smart.SmartScanResult(
        session_id="b656-live-session",
        correlation_id="b656-live-correlation",
        state=smart.STATE_COMPLETED_FINDINGS,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=smart.COVERAGE_COMPLETE,
        completed_checks=1,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_HIGH,
        summary="Controlled B6-5.6 real-file boundary acceptance",
        recommendation="Use only for B6-5.6 acceptance.",
        provider_name="b656-acceptance-source",
        provider_profile="b656-acceptance-source-v1",
        provider_provenance="b656_live_acceptance",
        plan=plan,
        check_results=(check,),
        raw_evidence={"controlled_acceptance": True},
    )


def run_acceptance(*, confirmed_by_launcher: bool) -> dict:
    if confirmed_by_launcher is not True:
        raise ValueError("b656_acceptance_requires_explicit_launcher_confirmation")

    profile = Path(os.environ.get("USERPROFILE") or Path.home()).resolve()
    documents = profile / "Documents"
    documents.mkdir(parents=True, exist_ok=True)
    acceptance_root = documents / f"BCSentinel-B656-Acceptance-{uuid.uuid4().hex}"
    acceptance_root.mkdir(parents=False, exist_ok=False)
    target = acceptance_root / "controlled-real-file.txt"
    data = b"BC Sentinel B6-5.6 controlled real-file quarantine acceptance\n"
    target.write_bytes(data)
    digest = _sha256(data)

    eligibility = real_execution.assess_target_eligibility(target, user_profile=profile)
    if eligibility.get("eligible") is not True:
        raise RuntimeError("b656_acceptance_target_not_eligible:" + ",".join(eligibility.get("reasons") or []))

    source_provider = provider_loader.load_default_provider()
    if source_provider.accepted is not True:
        raise RuntimeError("b656_source_provider_not_accepted")

    card = threat.build_threat_cards(_build_result(target, digest))[0]
    resolution = guided.build_guided_resolution(card)
    plan = planning.build_action_plan(card, resolution, source_provider, requested_action="QUARANTINE")

    request_time = time.time()
    request = confirmation.build_confirmation_request(
        plan,
        source_provider,
        confirmation.TargetRevalidation(locator=str(target), observed_sha256=digest, observed_at=request_time, provenance="b656_initial_probe"),
        now=request_time,
        ttl_seconds=180,
        nonce=uuid.uuid4().hex + uuid.uuid4().hex,
    )
    decision_time = time.time()
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        source_provider,
        confirmation.TargetRevalidation(locator=str(target), observed_sha256=digest, observed_at=decision_time, provenance="b656_confirmation_probe"),
        decision="CONFIRM",
        now=decision_time,
    )

    provider = real_execution.RealFileQuarantineProvider(user_profile=profile)
    permit_time = time.time()
    permit = real_execution.issue_real_file_execution_permit(
        plan,
        receipt,
        source_provider,
        provider,
        confirmation.TargetRevalidation(locator=str(target), observed_sha256=digest, observed_at=permit_time, provenance="b656_post_confirmation_probe"),
        now=permit_time,
        ttl_seconds=30,
        nonce=uuid.uuid4().hex + uuid.uuid4().hex,
    )

    result = provider.execute_quarantine(permit, now=time.time())
    quarantined_ok = (
        not target.exists()
        and Path(result.quarantine_path).is_file()
        and hashlib.sha256(Path(result.quarantine_path).read_bytes()).hexdigest() == digest
        and Path(result.snapshot_path).is_file()
        and hashlib.sha256(Path(result.snapshot_path).read_bytes()).hexdigest() == digest
    )

    rollback = provider.rollback_quarantine(permit, result, now=time.time())
    restored_ok = target.is_file() and target.read_bytes() == data and _sha256(target.read_bytes()) == digest and not Path(result.quarantine_path).exists()
    journal = real_execution.validate_journal(provider)
    expected_tail = ["PRE_STATE_RECORDED", "PERMIT_CONSUMED", "ACTION_RESULT", "ROLLBACK_STARTED", "ROLLBACK_RESULT", "FINAL_OUTCOME"]
    own_events = [e.get("event") for e in provider._read_journal() if e.get("permit_id") == permit.permit_id]
    contract = real_execution.validate_b656_contract()

    evidence = {
        "checkpoint": "B6-5.6-real-file-quarantine-boundary",
        "profile": real_execution.PROFILE,
        "passed": bool(contract.get("passed") is True and receipt.confirmed is True and permit.execution_authorized is True and permit.live_home_execution_authorized is False and quarantined_ok and restored_ok and rollback.state == "RESTORED_VERIFIED" and journal.get("passed") is True and own_events == expected_tail),
        "controlled_acceptance_file": True,
        "real_user_profile_scope": True,
        "arbitrary_user_file_automatic_scope": False,
        "live_home_execution_authorized": False,
        "automatic_action": False,
        "destructive_authority": False,
        "eligibility": eligibility,
        "target_path": str(target),
        "target_sha256": digest,
        "execution_permit": permit.to_dict(),
        "execution_result": result.to_dict(),
        "rollback_result": rollback.to_dict(),
        "quarantined_state_verified": quarantined_ok,
        "restored_state_verified": restored_ok,
        "journal_validation": journal,
        "permit_events": own_events,
        "contract": contract,
        "cleanup_verified": False,
    }

    # Cleanup only artifacts created by this acceptance. The append-only journal
    # intentionally remains as durable evidence; never delete unrelated history.
    snapshot = Path(result.snapshot_path)
    if snapshot.is_file():
        snapshot.unlink()
    shutil.rmtree(acceptance_root)
    evidence["cleanup_verified"] = not acceptance_root.exists() and not snapshot.exists()
    evidence["passed"] = bool(evidence["passed"] and evidence["cleanup_verified"])
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-5.6 real-file quarantine acceptance")
    parser.add_argument("--confirm-real-file-acceptance", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    try:
        evidence = run_acceptance(confirmed_by_launcher=args.confirm_real_file_acceptance)
    except Exception as exc:
        evidence = {"checkpoint": "B6-5.6-real-file-quarantine-boundary", "profile": real_execution.PROFILE, "passed": False, "error": f"{type(exc).__name__}:{exc}", "live_home_execution_authorized": False, "automatic_action": False, "destructive_authority": False}
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"checkpoint": evidence.get("checkpoint"), "passed": evidence.get("passed"), "real_user_profile_scope": evidence.get("real_user_profile_scope"), "restored_state_verified": evidence.get("restored_state_verified"), "journal_passed": (evidence.get("journal_validation") or {}).get("passed"), "cleanup_verified": evidence.get("cleanup_verified"), "live_home_execution_authorized": evidence.get("live_home_execution_authorized"), "output": str(output), "error": evidence.get("error")}, indent=2, sort_keys=True))
    return 0 if evidence.get("passed") is True else 4


if __name__ == "__main__":
    raise SystemExit(main())
