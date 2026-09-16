from __future__ import annotations

import copy

import pytest

from sentinel import beta10_attack_story as story
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
                started_at_utc="2026-09-16T12:00:00Z" if observed else None,
                ended_at_utc="2026-09-16T12:00:01Z" if observed else None,
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
        story_id="attack-story:b104-fixture",
        incident_id="incident:b104-fixture",
        source_graph_digest="1" * 64,
        source_correlation_digest="2" * 64,
        stages=tuple(stages),
        claims=claims,
        relationships=(),
        plain_language_summary="Fixture B10-4.",
        technical_summary="fixture=true; read_only=true.",
        source_live_control=True,
    ).to_dict()


def test_plan_is_deterministic_and_integrity_bound() -> None:
    source = _partial_story()
    first = response.build_response_plan(source)
    second = response.build_response_plan(source)
    assert first == second
    assert response.validate_response_plan(first)["passed"]
    assert first["source_story_digest"] == source["story_digest"]
    assert first["plan_digest"] == response._digest(response._plan_core(first))
    assert first["plan_id"].startswith("safe-response:")


def test_current_ransomware_story_yields_four_ordered_actions() -> None:
    plan = response.build_response_plan(_partial_story())
    assert [row["action_id"] for row in plan["actions"]] == [
        "PRESERVE_INCIDENT_EVIDENCE",
        "PREPARE_CONTAINMENT",
        "VERIFY_UNKNOWN_STAGES",
        "PREPARE_RESCUE_HANDOFF",
    ]
    assert [row["priority"] for row in plan["actions"]] == [1, 2, 3, 4]


def test_containment_is_declared_but_blocked_not_executable() -> None:
    plan = response.build_response_plan(_partial_story())
    action = next(row for row in plan["actions"] if row["action_id"] == "PREPARE_CONTAINMENT")
    assert action["state"] == response.ACTION_BLOCKED_AUTHORITY
    assert action["would_mutate_system_if_executed"] is True
    assert action["execution_available"] is False
    assert action["execution_authorized"] is False
    assert action["mutates_system"] is False
    assert action["automatic"] is False
    assert action["rollback_required"] is True
    assert action["user_confirmation_required"] is True
    assert {
        "execution_authority_not_granted",
        "quarantine_authority_not_granted",
        "target_identity_binding_required",
        "journal_storage_not_bound",
        "rollback_not_bound",
    }.issubset(set(action["blockers"]))


def test_planning_does_not_turn_response_into_observed_evidence() -> None:
    source = _partial_story()
    assert next(row for row in source["stages"] if row["stage_id"] == "RESPONSE")["status"] == "UNKNOWN"
    plan = response.build_response_plan(source)
    assert plan["source_response_stage_status"] == "UNKNOWN"
    assert plan["response_stage_claimed_observed"] is False
    assert "RESPONSE" in plan["unknown_stage_ids"]


def test_unknown_stages_are_preserved_for_investigation() -> None:
    plan = response.build_response_plan(_partial_story())
    assert plan["observed_stage_ids"] == ["FILE_ACTIVITY", "DETECTION"]
    assert plan["unknown_stage_ids"] == [
        "ENTRY_POINT",
        "EXECUTION",
        "PERSISTENCE",
        "NETWORK_ACTIVITY",
        "RESPONSE",
    ]
    investigate = next(row for row in plan["actions"] if row["action_id"] == "VERIFY_UNKNOWN_STAGES")
    assert investigate["state"] == response.ACTION_GUIDANCE_ONLY
    assert investigate["mutates_system"] is False


def test_tampered_source_story_digest_fails_closed() -> None:
    source = _partial_story()
    source["story_digest"] = "0" * 64
    validation = response.validate_source_story(source)
    assert not validation["passed"]
    assert "safe_response:story_digest_invalid" in validation["failures"]
    with pytest.raises(ValueError, match="source_invalid"):
        response.build_response_plan(source)


def test_source_story_with_authority_fails_closed() -> None:
    source = _partial_story()
    source["authority_boundary"]["automatic_quarantine"] = True
    source["story_digest"] = response._digest(response._story_core(source))
    validation = response.validate_source_story(source)
    assert not validation["passed"]
    assert "safe_response:story_authority_boundary_invalid" in validation["failures"]


def test_plan_validator_rejects_any_execution_or_mutation_flag_even_with_valid_digest() -> None:
    original = response.build_response_plan(_partial_story())
    for field in ("execution_available", "execution_authorized", "automatic", "mutates_system"):
        plan = copy.deepcopy(original)
        plan["actions"][0][field] = True
        plan["plan_digest"] = response._digest(response._plan_core(plan))
        validation = response.validate_response_plan(plan)
        assert not validation["passed"], field
        assert "safe_response:action_execution_or_mutation_forbidden" in validation["failures"]


def test_live_wrapper_metadata_does_not_break_canonical_plan_digest() -> None:
    plan = response.build_response_plan(_partial_story())
    digest = plan["plan_digest"]
    plan.update(
        {
            "passed": True,
            "source_detector_outcome": "DETECTED",
            "source_detector_score": 10,
            "detector_to_security_graph_bound": True,
            "security_graph_to_incident_bound": True,
            "synthetic_fallback_used": False,
        }
    )
    validation = response.validate_response_plan(plan)
    assert validation["passed"]
    assert plan["plan_digest"] == digest
    assert response._digest(response._plan_core(plan)) == digest

    tampered = copy.deepcopy(plan)
    tampered["plan_state"] = "EXECUTABLE"
    validation = response.validate_response_plan(tampered)
    assert not validation["passed"]
    assert "safe_response:plan_state_invalid" in validation["failures"]
    assert "safe_response:plan_digest_invalid" in validation["failures"]


def test_coverage_and_privacy_boundaries_match_accepted_b10_3() -> None:
    plan = response.build_response_plan(_partial_story())
    assert plan["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert plan["coverage_changed"] is False
    assert plan["broad_protection_claimed"] is False
    assert plan["authority_expanded"] is False
    assert not any(plan["authority_boundary"].values())
    assert plan["privacy"] == response.PRIVACY_BOUNDARY


def test_b6_execution_safety_boundary_is_preserved() -> None:
    contract = response.validate_b104_contract()
    assert contract["passed"]
    assert contract["planning_only"] is True
    assert contract["execution_api"] is False
    assert contract["execution_authorized"] is False
    assert contract["response_planning_is_not_observed_response"] is True
    assert contract["legacy_guided_resolution_boundary_preserved"] is True
    assert contract["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
