from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from sentinel import beta10_attack_story as story
from sentinel import beta10_reversible_response_pilot as pilot
from sentinel import beta10_safe_response_plan as response


def _source_plan() -> dict:
    stages = []
    for order, stage_id in enumerate(story.STAGE_IDS, start=1):
        observed = stage_id in {"FILE_ACTIVITY", "DETECTION"}
        stages.append(
            story.StoryStage(
                stage_id=stage_id,
                label=story.STAGE_LABELS[stage_id],
                order=order,
                status="OBSERVED" if observed else "UNKNOWN",
                started_at_utc="2026-09-17T10:00:00Z" if observed else None,
                ended_at_utc="2026-09-17T10:00:01Z" if observed else None,
                evidence_ids=("b106-harmless-live-fixture",) if observed else (),
                node_ids=(f"b106-node-{stage_id.lower()}",) if observed else (),
                edge_ids=(),
                confidence=1.0 if observed else None,
                explanation="B10-6 harmless reversible-response acceptance fixture."
                if observed
                else "No accepted evidence for this stage.",
            )
        )
    claims = (
        story.StoryClaim(
            claim_id="b106-file",
            stage_id="FILE_ACTIVITY",
            certainty="DIRECT_EVIDENCE",
            text="Harmless local acceptance file activity observed.",
            evidence_ids=("b106-harmless-live-fixture",),
            node_ids=("b106-node-file_activity",),
            confidence=1.0,
        ),
        story.StoryClaim(
            claim_id="b106-detection",
            stage_id="DETECTION",
            certainty="CORRELATED_EVIDENCE",
            text="Harmless local acceptance detection context observed.",
            evidence_ids=("b106-harmless-live-fixture",),
            node_ids=("b106-node-detection",),
            confidence=1.0,
        ),
    )
    source = story.AttackStory(
        story_id="attack-story:b106-acceptance",
        incident_id="incident:b106-acceptance",
        source_graph_digest="3" * 64,
        source_correlation_digest="4" * 64,
        stages=tuple(stages),
        claims=claims,
        relationships=(),
        plain_language_summary="B10-6 harmless acceptance fixture.",
        technical_summary="b106_acceptance=true; harmless_fixture=true.",
        source_live_control=True,
    ).to_dict()
    return response.build_response_plan(source)


def run(workspace: Path) -> dict:
    content = b"BC Sentinel B10-6 harmless reversible response pilot acceptance fixture\n"
    pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    fixture_dir = workspace / "payloads"
    fixture_dir.mkdir()
    target = fixture_dir / "harmless-fixture.bin"
    target.write_bytes(content)

    ticket = pilot.build_authorization_ticket(
        _source_plan(),
        workspace,
        "payloads/harmless-fixture.bin",
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    if target.exists():
        raise AssertionError("B10-6 fixture still present after quarantine")

    quarantined_state = pilot.inspect_transaction(workspace, executed["transaction_id"])
    if not quarantined_state.get("passed") or quarantined_state.get("state") != "QUARANTINED":
        raise AssertionError(f"B10-6 quarantine state invalid: {quarantined_state}")

    rolled_back = pilot.rollback_reversible_quarantine(
        ticket,
        workspace,
        executed["transaction_id"],
        authorization_phrase=pilot.AUTHORIZE_ROLLBACK,
    )
    if target.read_bytes() != content:
        raise AssertionError("B10-6 rollback did not restore exact fixture bytes")

    final_state = pilot.inspect_transaction(workspace, executed["transaction_id"])
    if not final_state.get("passed") or final_state.get("state") != "ROLLED_BACK":
        raise AssertionError(f"B10-6 rollback state invalid: {final_state}")

    contract = pilot.validate_b106_contract()
    if not contract.get("passed"):
        raise AssertionError(f"B10-6 contract invalid: {contract}")

    return {
        "passed": True,
        "profile": pilot.PROFILE,
        "transaction_id": executed["transaction_id"],
        "ticket_digest": ticket["ticket_digest"],
        "target_binding_id": ticket["target_binding_id"],
        "quarantine_state": quarantined_state["state"],
        "final_state": final_state["state"],
        "journal_record_count": final_state["journal_record_count"],
        "restored_sha256": rolled_back["restored_sha256"],
        "automatic_action": contract["automatic_action"],
        "broad_home_execution": contract["broad_home_execution"],
        "delete_authority": contract["delete_authority"],
        "repair_authority": contract["repair_authority"],
        "terminate_process_authority": contract["terminate_process_authority"],
        "privileged_system_mutation": contract["privileged_system_mutation"],
        "pilot_quarantine_authority": contract["pilot_quarantine_authority"],
        "pilot_rollback_authority": contract["pilot_rollback_authority"],
        "authority_expanded": contract["authority_expanded"],
        "broad_remediation_claimed": contract["broad_remediation_claimed"],
        "coverage_summary": contract["coverage_summary"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run BC Sentinel B10-6 harmless reversible-response pilot.")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--confirm-reversible-response-pilot", action="store_true")
    args = parser.parse_args()
    if not args.confirm_reversible_response_pilot:
        raise SystemExit("Explicit B10-6 reversible-response pilot confirmation required.")
    workspace = args.workspace
    try:
        result = run(workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    finally:
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
