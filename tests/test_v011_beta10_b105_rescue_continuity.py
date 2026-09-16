from __future__ import annotations

import copy
import json

import pytest

from sentinel import beta10_attack_story as story
from sentinel import beta10_rescue_continuity as continuity
from sentinel import beta10_safe_response_plan as response
from sentinel import rescue_contract


def _source_story() -> dict:
    stages = []
    for order, stage_id in enumerate(story.STAGE_IDS, start=1):
        observed = stage_id in {"FILE_ACTIVITY", "DETECTION"}
        stages.append(
            story.StoryStage(
                stage_id=stage_id,
                label=story.STAGE_LABELS[stage_id],
                order=order,
                status="OBSERVED" if observed else "UNKNOWN",
                started_at_utc="2026-09-16T12:00:00Z" if observed else None,
                ended_at_utc="2026-09-16T12:00:01Z" if observed else None,
                evidence_ids=("b93-live-file:b105-fixture",) if observed else (),
                node_ids=(f"node-{stage_id.lower()}",) if observed else (),
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
            evidence_ids=("b93-live-file:b105-fixture",),
            node_ids=("node-file_activity",),
            confidence=1.0,
        ),
        story.StoryClaim(
            claim_id="claim-detection",
            stage_id="DETECTION",
            certainty="CORRELATED_EVIDENCE",
            text="Fase osservata: Rilevamento.",
            evidence_ids=("b93-live-file:b105-fixture",),
            node_ids=("node-detection",),
            confidence=1.0,
        ),
    )
    return story.AttackStory(
        story_id="attack-story:b105-fixture",
        incident_id="incident:b105-fixture",
        source_graph_digest="1" * 64,
        source_correlation_digest="2" * 64,
        stages=tuple(stages),
        claims=claims,
        relationships=(),
        plain_language_summary="Fixture B10-5.",
        technical_summary="fixture=true; read_only=true.",
        source_live_control=True,
    ).to_dict()


def _plan() -> dict:
    return response.build_response_plan(_source_story())


def _rebind_plan_integrity(plan: dict) -> None:
    plan["plan_id"] = "safe-response:" + response._digest(
        {
            "incident_id": plan.get("incident_id"),
            "story_id": plan.get("source_story_id"),
            "story_digest": plan.get("source_story_digest"),
            "actions": plan.get("actions"),
            "observed": plan.get("observed_stage_ids"),
            "unknown": plan.get("unknown_stage_ids"),
        }
    )[:24]
    plan["plan_digest"] = response._digest(response._plan_core(plan))


def test_continuity_envelope_is_deterministic_and_integrity_bound() -> None:
    plan = _plan()
    first = continuity.build_continuity_envelope(plan)
    second = continuity.build_continuity_envelope(plan)
    assert first == second
    assert continuity.validate_continuity_envelope(first)["passed"]
    assert first["source_plan_id"] == plan["plan_id"]
    assert first["source_plan_digest"] == plan["plan_digest"]
    assert first["continuity_id"].startswith("rescue-continuity:")


def test_continuity_preserves_incident_provenance_without_paths() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    assert envelope["incident_id"] == "incident:b105-fixture"
    assert envelope["evidence_provenance"] == [
        {
            "reference": "b93-live-file:b105-fixture",
            "reference_sha256": continuity.hashlib.sha256(b"b93-live-file:b105-fixture").hexdigest(),
        }
    ]
    assert envelope["target_binding_state"] == "REQUIRED"
    assert envelope["privacy"]["absolute_paths_exported"] is False
    serialized = json.dumps(envelope, sort_keys=True)
    assert "target_root" not in serialized
    assert "output_dir" not in serialized
    assert "journal_path" not in serialized


def test_recommended_steps_are_ordered_and_non_executing() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    steps = envelope["recommended_rescue_steps"]
    assert [row["step_id"] for row in steps] == [
        "VERIFY_CONTINUITY_INTEGRITY",
        "BIND_RESCUE_TARGET",
        "ACQUIRE_READ_ONLY_EVIDENCE",
        "INSPECT_OFFLINE_TARGET",
        "REVIEW_UNKNOWN_ATTACK_STAGES",
        "REVIEW_PLANNED_RECOVERY",
    ]
    assert [row["priority"] for row in steps] == [1, 2, 3, 4, 5, 6]
    assert all(row["execution_available"] is False for row in steps)
    assert steps[-1]["state"] == "PLANNING_ONLY"


def test_source_plan_without_rescue_handoff_fails_closed() -> None:
    plan = _plan()
    plan["actions"] = [row for row in plan["actions"] if row["action_id"] != "PREPARE_RESCUE_HANDOFF"]
    _rebind_plan_integrity(plan)
    assert response.validate_response_plan(plan)["passed"]
    validation = continuity.validate_source_plan(plan)
    assert not validation["passed"]
    assert "rescue_continuity:exactly_one_rescue_handoff_required" in validation["failures"]
    with pytest.raises(ValueError, match="source_plan_invalid"):
        continuity.build_continuity_envelope(plan)


def test_tampered_source_plan_digest_fails_before_continuity() -> None:
    plan = _plan()
    plan["plan_digest"] = "0" * 64
    validation = continuity.validate_source_plan(plan)
    assert not validation["passed"]
    with pytest.raises(ValueError, match="source_plan_invalid"):
        continuity.build_continuity_envelope(plan)


def test_tampered_continuity_core_fails_closed() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    envelope["incident_id"] = "incident:tampered"
    validation = continuity.validate_continuity_envelope(envelope)
    assert not validation["passed"]
    assert "rescue_continuity:continuity_digest_invalid" in validation["failures"]


def test_path_leakage_is_refused_even_as_extra_wrapper_metadata() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    envelope["target_root"] = r"C:\Users\example\Documents"
    validation = continuity.validate_continuity_envelope(envelope)
    assert not validation["passed"]
    assert "rescue_continuity:path_or_content_field_forbidden" in validation["failures"]
    assert "rescue_continuity:absolute_path_value_forbidden" in validation["failures"]


def test_trusted_external_media_projection_is_read_only_and_unbound() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    projection = continuity.project_for_rescue(
        envelope, rescue_contract.RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA.value
    )
    assert continuity.validate_rescue_projection(projection)["passed"]
    assert projection["target_bound"] is False
    assert projection["write_authorized"] is False
    assert projection["execution_available"] is False
    assert projection["execution_authorized"] is False
    assert projection["automatic_resume_allowed"] is False
    assert projection["operator_confirmation_required"] is True
    assert projection["planning_only_capabilities"] == ["plan_quarantine", "plan_repair"]


def test_offline_image_projection_preserves_same_authority_boundary() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    projection = continuity.project_for_rescue(
        envelope, rescue_contract.RescueExecutionContext.OFFLINE_IMAGE.value
    )
    assert continuity.validate_rescue_projection(projection)["passed"]
    assert projection["target_binding_state"] == "REQUIRED"
    assert projection["system_mutation_performed"] is False
    assert projection["authority_expanded"] is False


def test_compromised_windows_context_is_not_accepted_as_rescue_handoff_target() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    with pytest.raises(ValueError, match="execution_context_not_accepted"):
        continuity.project_for_rescue(
            envelope, rescue_contract.RescueExecutionContext.COMPROMISED_WINDOWS.value
        )


def test_projection_with_write_authority_is_rejected() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    projection = continuity.project_for_rescue(
        envelope, rescue_contract.RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA.value
    )
    projection["write_authorized"] = True
    projection["projection_digest"] = continuity._digest(continuity._import_core(projection))
    validation = continuity.validate_rescue_projection(projection)
    assert not validation["passed"]
    assert "rescue_continuity:projection_forbidden_authority:write_authorized" in validation["failures"]


def test_json_round_trip_preserves_continuity_and_projection_digests() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    transported = json.loads(json.dumps(envelope, sort_keys=True))
    assert transported == envelope
    assert continuity.validate_continuity_envelope(transported)["passed"]
    projection = continuity.project_for_rescue(
        transported, rescue_contract.RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA.value
    )
    projection_round_trip = json.loads(json.dumps(projection, sort_keys=True))
    assert continuity.validate_rescue_projection(projection_round_trip)["passed"]


def test_coverage_privacy_and_response_boundaries_remain_unchanged() -> None:
    envelope = continuity.build_continuity_envelope(_plan())
    assert envelope["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert envelope["coverage_changed"] is False
    assert envelope["broad_protection_claimed"] is False
    assert envelope["response_stage_claimed_observed"] is False
    assert envelope["source_response_stage_status"] == "UNKNOWN"
    assert envelope["authority_expanded"] is False
    assert not any(envelope["authority_boundary"].values())
    assert envelope["privacy"] == continuity.PRIVACY_BOUNDARY


def test_legacy_rescue_and_resume_safety_contracts_are_preserved() -> None:
    contract = continuity.validate_b105_contract()
    assert contract["passed"]
    assert contract["continuity_only"] is True
    assert contract["path_free_handoff"] is True
    assert contract["target_binding_required"] is True
    assert contract["rescue_start_authorized"] is False
    assert contract["execution_available"] is False
    assert contract["execution_authorized"] is False
    assert contract["automatic_mutation_resume"] is False
    assert contract["authority_expanded"] is False
    assert contract["legacy_rescue_read_only_default"] is True
    assert contract["legacy_destructive_actions_enabled"] is False
    assert contract["legacy_resume_boundary_preserved"] is True
    assert contract["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}


def test_continuity_envelope_does_not_mutate_input_plan() -> None:
    plan = _plan()
    before = copy.deepcopy(plan)
    continuity.build_continuity_envelope(plan)
    assert plan == before
