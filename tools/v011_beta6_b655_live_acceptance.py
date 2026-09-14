from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
import uuid

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_fixture_execution as fixture_execution
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_result(target: Path, digest: str) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b655-live-harmless-fixture",
        title="B6-5.5 harmless live fixture",
        severity=smart.SEVERITY_HIGH,
        category="fixture",
        reason="Controlled reversible B6-5.5 execution acceptance fixture",
        source_check_id="files",
        path=str(target),
        confidence=1.0,
        evidence={"sha256": digest, "signals": ["controlled_fixture_only"]},
    )
    scan_plan = smart.SmartScanPlan(
        provider_name="b655-live-fixture-source",
        provider_profile="b655-live-fixture-source-v1",
        provider_provenance="b655_live_acceptance",
        checks=(smart.SmartScanCheck("files", "Files", "Harmless fixture", True, "b655_live_acceptance"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Harmless fixture prepared",
        findings=(finding,),
        evidence={"fixture_only": True},
    )
    return smart.SmartScanResult(
        session_id="b655-live-session",
        correlation_id="b655-live-correlation",
        state=smart.STATE_COMPLETED_FINDINGS,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=smart.COVERAGE_COMPLETE,
        completed_checks=1,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_HIGH,
        summary="Controlled harmless fixture",
        recommendation="Use only for B6-5.5 acceptance.",
        provider_name="b655-live-fixture-source",
        provider_profile="b655-live-fixture-source-v1",
        provider_provenance="b655_live_acceptance",
        plan=scan_plan,
        check_results=(check,),
        raw_evidence={"fixture_only": True},
    )


def run_acceptance(*, confirmed_by_launcher: bool) -> dict:
    if confirmed_by_launcher is not True:
        raise ValueError("b655_live_acceptance_requires_explicit_launcher_confirmation")

    root = Path(tempfile.gettempdir()) / f"{fixture_execution.FIXTURE_PREFIX}{uuid.uuid4().hex}"
    environment = fixture_execution.prepare_fixture_environment(root)
    target = Path(environment["input_root"]) / "harmless-b655-fixture.txt"
    data = b"BC Sentinel B6-5.5 harmless fixture execution acceptance\n"
    target.write_bytes(data)
    digest = _sha256_bytes(data)

    source_provider = provider_loader.load_default_provider()
    if source_provider.accepted is not True:
        raise RuntimeError("b655_source_provider_not_accepted")

    card = threat.build_threat_cards(_build_result(target, digest))[0]
    resolution = guided.build_guided_resolution(card)
    plan = planning.build_action_plan(
        card,
        resolution,
        source_provider,
        requested_action="QUARANTINE",
    )

    request_time = time.time()
    request = confirmation.build_confirmation_request(
        plan,
        source_provider,
        confirmation.TargetRevalidation(
            locator=str(target),
            observed_sha256=digest,
            observed_at=request_time,
            provenance="b655_live_initial_read_only_probe",
        ),
        now=request_time,
        ttl_seconds=180,
        nonce=uuid.uuid4().hex + uuid.uuid4().hex,
    )

    decision_time = time.time()
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        source_provider,
        confirmation.TargetRevalidation(
            locator=str(target),
            observed_sha256=digest,
            observed_at=decision_time,
            provenance="b655_live_confirmation_read_only_probe",
        ),
        decision="CONFIRM",
        now=decision_time,
    )

    provider = fixture_execution.FixtureQuarantineProvider(root)
    permit_time = time.time()
    permit = fixture_execution.issue_fixture_execution_permit(
        plan,
        receipt,
        source_provider,
        provider,
        confirmation.TargetRevalidation(
            locator=str(target),
            observed_sha256=digest,
            observed_at=permit_time,
            provenance="b655_live_post_confirmation_read_only_probe",
        ),
        now=permit_time,
        ttl_seconds=30,
        nonce=uuid.uuid4().hex + uuid.uuid4().hex,
    )

    execution_time = time.time()
    result = provider.execute_quarantine(permit, now=execution_time)
    quarantined_state_ok = (
        not target.exists()
        and Path(result.quarantine_path).is_file()
        and hashlib.sha256(Path(result.quarantine_path).read_bytes()).hexdigest() == digest
        and Path(result.snapshot_path).is_file()
        and hashlib.sha256(Path(result.snapshot_path).read_bytes()).hexdigest() == digest
    )

    rollback_time = time.time()
    rollback = provider.rollback_quarantine(permit, result, now=rollback_time)
    restored_state_ok = (
        target.is_file()
        and target.read_bytes() == data
        and hashlib.sha256(target.read_bytes()).hexdigest() == digest
        and not Path(result.quarantine_path).exists()
    )

    journal = fixture_execution.validate_fixture_journal(provider)
    expected_events = [
        "PRE_STATE_RECORDED",
        "PERMIT_CONSUMED",
        "ACTION_RESULT",
        "ROLLBACK_STARTED",
        "ROLLBACK_RESULT",
        "FINAL_OUTCOME",
    ]
    contract = fixture_execution.validate_b655_fixture_execution_contract()

    evidence = {
        "checkpoint": "B6-5.5-harmless-fixture-execution",
        "profile": fixture_execution.PROFILE,
        "passed": (
            contract.get("passed") is True
            and receipt.confirmed is True
            and permit.execution_authorized is True
            and permit.live_home_execution_authorized is False
            and permit.automatic_action is False
            and permit.destructive_authority is False
            and quarantined_state_ok
            and restored_state_ok
            and rollback.state == "RESTORED_VERIFIED"
            and journal.get("passed") is True
            and journal.get("events") == expected_events
        ),
        "explicit_launcher_confirmation": True,
        "fixture_only": True,
        "real_user_or_system_file_scope": False,
        "live_home_execution_authorized": False,
        "automatic_action": False,
        "destructive_authority": False,
        "fixture_root": str(root),
        "target_path": str(target),
        "target_sha256": digest,
        "source_plan": plan.to_dict(),
        "confirmation_receipt": receipt.to_dict(),
        "execution_permit": permit.to_dict(),
        "execution_result": result.to_dict(),
        "rollback_result": rollback.to_dict(),
        "quarantined_state_verified": quarantined_state_ok,
        "restored_state_verified": restored_state_ok,
        "journal_validation": journal,
        "contract": contract,
        "cleanup_performed": False,
        "cleanup_verified": False,
    }

    shutil.rmtree(root)
    evidence["cleanup_performed"] = True
    evidence["cleanup_verified"] = not root.exists()
    evidence["passed"] = bool(evidence["passed"] and evidence["cleanup_verified"])
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-5.5 harmless fixture execution acceptance")
    parser.add_argument("--confirm-fixture-execution", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    output = Path(args.output)
    try:
        evidence = run_acceptance(confirmed_by_launcher=args.confirm_fixture_execution)
    except Exception as exc:
        evidence = {
            "checkpoint": "B6-5.5-harmless-fixture-execution",
            "profile": fixture_execution.PROFILE,
            "passed": False,
            "error": f"{type(exc).__name__}:{exc}",
            "fixture_only": True,
            "live_home_execution_authorized": False,
            "automatic_action": False,
            "destructive_authority": False,
        }

    output.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "checkpoint": evidence.get("checkpoint"),
        "passed": evidence.get("passed"),
        "fixture_only": evidence.get("fixture_only"),
        "restored_state_verified": evidence.get("restored_state_verified"),
        "journal_passed": (evidence.get("journal_validation") or {}).get("passed"),
        "cleanup_verified": evidence.get("cleanup_verified"),
        "output": str(output),
        "error": evidence.get("error"),
    }, indent=2, sort_keys=True))
    return 0 if evidence.get("passed") is True else 4


if __name__ == "__main__":
    raise SystemExit(main())
