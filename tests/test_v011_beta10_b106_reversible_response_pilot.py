from __future__ import annotations

import copy
import json
import uuid

import pytest

from sentinel import beta10_attack_story as story
from sentinel import beta10_reversible_response_pilot as pilot
from sentinel import beta10_safe_response_plan as response


def _partial_story() -> dict:
    stages = []
    for order, stage_id in enumerate(story.STAGE_IDS, start=1):
        observed = stage_id in {"FILE_ACTIVITY", "DETECTION"}
        evidence = ["e-live-file"] if observed else []
        nodes = [f"node-{stage_id.lower()}"] if observed else []
        stages.append(
            story.StoryStage(
                stage_id=stage_id,
                label=story.STAGE_LABELS[stage_id],
                order=order,
                status="OBSERVED" if observed else "UNKNOWN",
                started_at_utc="2026-09-17T10:00:00Z" if observed else None,
                ended_at_utc="2026-09-17T10:00:01Z" if observed else None,
                evidence_ids=tuple(evidence),
                node_ids=tuple(nodes),
                edge_ids=(),
                confidence=1.0 if observed else None,
                explanation="fixture observed" if observed else "fixture unknown",
            )
        )
    claims = (
        story.StoryClaim(
            claim_id="claim-file",
            stage_id="FILE_ACTIVITY",
            certainty="DIRECT_EVIDENCE",
            text="Fase osservata: Attività file.",
            evidence_ids=("e-live-file",),
            node_ids=("node-file_activity",),
            confidence=1.0,
        ),
        story.StoryClaim(
            claim_id="claim-detection",
            stage_id="DETECTION",
            certainty="CORRELATED_EVIDENCE",
            text="Fase osservata: Rilevamento.",
            evidence_ids=("e-live-file",),
            node_ids=("node-detection",),
            confidence=1.0,
        ),
    )
    return story.AttackStory(
        story_id="attack-story:b106-fixture",
        incident_id="incident:b106-fixture",
        source_graph_digest="1" * 64,
        source_correlation_digest="2" * 64,
        stages=tuple(stages),
        claims=claims,
        relationships=(),
        plain_language_summary="Fixture B10-6.",
        technical_summary="fixture=true; read_only=true.",
        source_live_control=True,
    ).to_dict()


def _source_plan() -> dict:
    return response.build_response_plan(_partial_story())


def _workspace(tmp_path):
    return tmp_path / f"{pilot.WORKSPACE_PREFIX}{uuid.uuid4().hex}"


def _prepared_fixture(tmp_path, content: bytes = b"harmless-b106-fixture"):
    workspace = _workspace(tmp_path)
    marker = pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    payload_dir = workspace / "payloads"
    payload_dir.mkdir()
    target = payload_dir / "fixture.bin"
    target.write_bytes(content)
    plan = _source_plan()
    ticket = pilot.build_authorization_ticket(
        plan,
        workspace,
        "payloads/fixture.bin",
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    return workspace, marker, target, plan, ticket


def test_b106_contract_is_narrow_explicit_and_reversible() -> None:
    contract = pilot.validate_b106_contract()
    assert contract["passed"]
    assert contract["scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
    assert contract["explicit_operator_confirmation_required"] is True
    assert contract["target_identity_binding_required"] is True
    assert contract["journal_required"] is True
    assert contract["rollback_required"] is True
    assert contract["automatic_action"] is False
    assert contract["broad_home_execution"] is False
    assert contract["delete_authority"] is False
    assert contract["repair_authority"] is False
    assert contract["terminate_process_authority"] is False
    assert contract["privileged_system_mutation"] is False
    assert contract["rescue_write_authority"] is False
    assert contract["outside_disposable_workspace_execution"] is False
    assert contract["pilot_quarantine_authority"] is True
    assert contract["pilot_rollback_authority"] is True
    assert contract["authority_expanded"] is True
    assert contract["broad_remediation_claimed"] is False
    assert contract["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}


def test_workspace_requires_explicit_confirmation_and_prefix(tmp_path) -> None:
    good = _workspace(tmp_path)
    with pytest.raises(PermissionError, match="confirmation_required"):
        pilot.initialize_pilot_workspace(good, operator_confirmed=False)
    bad = tmp_path / "not-a-pilot"
    with pytest.raises(ValueError, match="workspace_prefix_required"):
        pilot.initialize_pilot_workspace(bad, operator_confirmed=True)


def test_workspace_marker_is_integrity_bound(tmp_path) -> None:
    workspace = _workspace(tmp_path)
    marker = pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    assert marker["workspace_id"].startswith("b106-workspace:")
    assert pilot.validate_workspace(workspace)["passed"]

    marker_path = workspace / pilot.MARKER_NAME
    tampered = json.loads(marker_path.read_text(encoding="utf-8"))
    tampered["scope"] = "GENERAL_HOME"
    marker_path.write_text(json.dumps(tampered), encoding="utf-8")
    validation = pilot.validate_workspace(workspace)
    assert not validation["passed"]
    assert "workspace_marker_scope_invalid" in validation["failures"][0]


def test_ticket_binds_exact_file_hash_size_workspace_and_plan(tmp_path) -> None:
    workspace, marker, target, plan, ticket = _prepared_fixture(tmp_path)
    assert pilot.validate_authorization_ticket(ticket)["passed"]
    assert ticket["workspace_id"] == marker["workspace_id"]
    assert ticket["source_plan_id"] == plan["plan_id"]
    assert ticket["source_plan_digest"] == plan["plan_digest"]
    assert ticket["target_relative_path"] == "payloads/fixture.bin"
    assert ticket["target_size"] == target.stat().st_size
    assert ticket["target_sha256"] == pilot._sha256_file(target)
    assert ticket["target_binding_id"].startswith("b106-target:")
    assert ticket["automatic"] is False
    assert ticket["rollback_required"] is True


def test_ticket_requires_exact_authorization_phrase(tmp_path) -> None:
    workspace = _workspace(tmp_path)
    pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    (workspace / "fixture.bin").write_bytes(b"fixture")
    with pytest.raises(PermissionError, match="authorization_phrase_invalid"):
        pilot.build_authorization_ticket(
            _source_plan(),
            workspace,
            "fixture.bin",
            authorization_phrase="YES",
        )


def test_ticket_rejects_tampered_source_plan(tmp_path) -> None:
    workspace = _workspace(tmp_path)
    pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    (workspace / "fixture.bin").write_bytes(b"fixture")
    plan = _source_plan()
    plan["plan_state"] = "EXECUTABLE"
    with pytest.raises(ValueError, match="source_plan_invalid"):
        pilot.build_authorization_ticket(
            plan,
            workspace,
            "fixture.bin",
            authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
        )


@pytest.mark.parametrize(
    "relative_path",
    [
        "../outside.bin",
        ".quarantine/inside.bin",
        ".journal/inside.bin",
        ".bc-sentinel-b106-pilot.json",
    ],
)
def test_ticket_rejects_escape_and_reserved_targets(tmp_path, relative_path) -> None:
    workspace = _workspace(tmp_path)
    pilot.initialize_pilot_workspace(workspace, operator_confirmed=True)
    with pytest.raises((ValueError, FileNotFoundError)):
        pilot.build_authorization_ticket(
            _source_plan(),
            workspace,
            relative_path,
            authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
        )


def test_target_binding_change_fails_closed_before_quarantine(tmp_path) -> None:
    workspace, _, target, _, ticket = _prepared_fixture(tmp_path, b"original")
    target.write_bytes(b"changed")
    with pytest.raises(ValueError, match="target_binding_changed"):
        pilot.execute_reversible_quarantine(
            ticket,
            workspace,
            authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
        )
    assert target.read_bytes() == b"changed"


def test_quarantine_and_rollback_round_trip_preserves_exact_bytes(tmp_path) -> None:
    original = b"harmless reversible response pilot fixture\x00\x01"
    workspace, _, target, _, ticket = _prepared_fixture(tmp_path, original)

    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    assert executed["passed"]
    assert executed["quarantined"] is True
    assert executed["rollback_available"] is True
    assert executed["automatic"] is False
    assert executed["pilot_response_action_observed"] is True
    assert executed["source_response_stage_claimed_observed"] is False
    assert executed["broad_remediation_claimed"] is False
    assert executed["scope"] == pilot.PILOT_SCOPE
    assert not target.exists()

    state = pilot.inspect_transaction(workspace, executed["transaction_id"])
    assert state["passed"]
    assert state["state"] == "QUARANTINED"
    assert state["events"] == ["QUARANTINE_PREPARED", "QUARANTINE_COMMITTED"]

    rolled_back = pilot.rollback_reversible_quarantine(
        ticket,
        workspace,
        executed["transaction_id"],
        authorization_phrase=pilot.AUTHORIZE_ROLLBACK,
    )
    assert rolled_back["passed"]
    assert rolled_back["rolled_back"] is True
    assert rolled_back["quarantined"] is False
    assert target.read_bytes() == original
    assert rolled_back["restored_sha256"] == ticket["target_sha256"]

    final_state = pilot.inspect_transaction(workspace, executed["transaction_id"])
    assert final_state["passed"]
    assert final_state["state"] == "ROLLED_BACK"
    assert final_state["events"] == [
        "QUARANTINE_PREPARED",
        "QUARANTINE_COMMITTED",
        "ROLLBACK_PREPARED",
        "ROLLED_BACK",
    ]


def test_execute_and_rollback_each_require_their_exact_phrase(tmp_path) -> None:
    workspace, _, _, _, ticket = _prepared_fixture(tmp_path)
    with pytest.raises(PermissionError, match="quarantine_authorization_phrase_invalid"):
        pilot.execute_reversible_quarantine(ticket, workspace, authorization_phrase="NO")
    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    with pytest.raises(PermissionError, match="rollback_authorization_phrase_invalid"):
        pilot.rollback_reversible_quarantine(
            ticket,
            workspace,
            executed["transaction_id"],
            authorization_phrase="NO",
        )


def test_rollback_fails_if_original_destination_is_occupied(tmp_path) -> None:
    workspace, _, target, _, ticket = _prepared_fixture(tmp_path)
    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    target.write_bytes(b"replacement")
    with pytest.raises(ValueError, match="rollback_destination_occupied"):
        pilot.rollback_reversible_quarantine(
            ticket,
            workspace,
            executed["transaction_id"],
            authorization_phrase=pilot.AUTHORIZE_ROLLBACK,
        )
    assert target.read_bytes() == b"replacement"


def test_second_rollback_is_rejected(tmp_path) -> None:
    workspace, _, _, _, ticket = _prepared_fixture(tmp_path)
    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    pilot.rollback_reversible_quarantine(
        ticket,
        workspace,
        executed["transaction_id"],
        authorization_phrase=pilot.AUTHORIZE_ROLLBACK,
    )
    with pytest.raises(ValueError, match="transaction_not_rollback_ready"):
        pilot.rollback_reversible_quarantine(
            ticket,
            workspace,
            executed["transaction_id"],
            authorization_phrase=pilot.AUTHORIZE_ROLLBACK,
        )


def test_journal_is_digest_chained_and_tampering_fails_closed(tmp_path) -> None:
    workspace, _, _, _, ticket = _prepared_fixture(tmp_path)
    executed = pilot.execute_reversible_quarantine(
        ticket,
        workspace,
        authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
    )
    journal_path = workspace / pilot.JOURNAL_DIR / pilot.JOURNAL_NAME
    lines = journal_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["previous_digest"] == ""
    assert second["previous_digest"] == first["record_digest"]

    first["target_size"] = int(first["target_size"]) + 1
    lines[0] = json.dumps(first, sort_keys=True)
    journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    state = pilot.inspect_transaction(workspace, executed["transaction_id"])
    assert not state["passed"]
    assert "journal_digest_invalid:1" in state["failures"][0]


def test_ticket_tampering_fails_closed_at_execution(tmp_path) -> None:
    workspace, _, target, _, ticket = _prepared_fixture(tmp_path)
    tampered = copy.deepcopy(ticket)
    tampered["target_size"] += 1
    validation = pilot.validate_authorization_ticket(tampered)
    assert not validation["passed"]
    assert "b106:ticket_digest_invalid" in validation["failures"]
    with pytest.raises(ValueError, match="ticket_invalid"):
        pilot.execute_reversible_quarantine(
            tampered,
            workspace,
            authorization_phrase=pilot.AUTHORIZE_QUARANTINE,
        )
    assert target.exists()
