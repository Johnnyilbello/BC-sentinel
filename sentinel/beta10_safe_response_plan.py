from __future__ import annotations

"""B10-4 Safe Response Plan Engine.

Build a deterministic response plan from accepted Attack Story evidence without
executing or authorizing any response. Planner output is evidence-bound,
planning-only, and must never make the Attack Story RESPONSE stage observed.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import beta10_attack_story as attack_story
from sentinel import guided_resolution_execution_gate

SCHEMA: Final[str] = "bc-sentinel-beta10-safe-response-plan-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b104-safe-response-plan-engine"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b103-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b3de7f34cb7ddc381499f34cf68ebd4dd02c0fb8"
CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
PLAN_STATE: Final[str] = "PLANNED_NOT_EXECUTABLE"

ACTION_GUIDANCE_ONLY: Final[str] = "GUIDANCE_ONLY"
ACTION_BLOCKED_AUTHORITY: Final[str] = "BLOCKED_AUTHORITY"
ACTION_HANDOFF_ONLY: Final[str] = "HANDOFF_ONLY"
ACTION_STATES: Final[frozenset[str]] = frozenset(
    {ACTION_GUIDANCE_ONLY, ACTION_BLOCKED_AUTHORITY, ACTION_HANDOFF_ONLY}
)
REVERSIBILITY_STATES: Final[frozenset[str]] = frozenset(
    {"NOT_APPLICABLE", "CONDITIONALLY_REVERSIBLE"}
)

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "execution_authority": False,
    "rollback_execution_authority": False,
    "journal_write_authority": False,
}
PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "remote_access": False,
}

_STORY_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "source_checkpoint",
    "source_checkpoint_commit",
    "story_id",
    "incident_id",
    "source_graph_digest",
    "source_correlation_digest",
    "stages",
    "claims",
    "relationships",
    "plain_language_summary",
    "technical_summary",
    "source_live_control",
    "coverage_summary",
    "coverage_changed",
    "broad_protection_claimed",
    "read_only",
    "authority_boundary",
    "privacy",
)

_PLAN_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "source_checkpoint",
    "source_checkpoint_commit",
    "plan_id",
    "incident_id",
    "source_story_id",
    "source_story_digest",
    "source_live_control",
    "plan_state",
    "actions",
    "observed_stage_ids",
    "unknown_stage_ids",
    "source_response_stage_status",
    "response_stage_claimed_observed",
    "plain_language_summary",
    "technical_summary",
    "coverage_summary",
    "coverage_changed",
    "broad_protection_claimed",
    "authority_expanded",
    "execution_api",
    "execution_available",
    "execution_authorized",
    "automatic_action",
    "remediation_performed",
    "system_mutation_performed",
    "legacy_guided_resolution_boundary_preserved",
    "authority_boundary",
    "privacy",
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _story_core(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in _STORY_CORE_KEYS}


def _plan_core(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical signed plan body, excluding live-wrapper metadata."""
    return {key: payload.get(key) for key in _PLAN_CORE_KEYS}


def _stage_map(source_story: dict[str, Any]) -> dict[str, dict[str, Any]]:
    stages = source_story.get("stages")
    if not isinstance(stages, list):
        raise ValueError("safe_response:story_stages_required")
    mapped: dict[str, dict[str, Any]] = {}
    for row in stages:
        if not isinstance(row, dict):
            raise ValueError("safe_response:story_stage_invalid")
        stage_id = str(row.get("stage_id") or "")
        if stage_id in mapped:
            raise ValueError("safe_response:duplicate_story_stage")
        mapped[stage_id] = row
    if tuple(mapped) != attack_story.STAGE_IDS:
        raise ValueError("safe_response:story_stage_order_invalid")
    return mapped


def validate_source_story(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["safe_response:story_not_object"]}
    if payload.get("schema") != attack_story.SCHEMA or payload.get("profile") != attack_story.PROFILE:
        failures.append("safe_response:story_schema_or_profile_invalid")
    if payload.get("read_only") is not True or payload.get("broad_protection_claimed") is not False:
        failures.append("safe_response:story_read_only_boundary_invalid")
    source_authority = payload.get("authority_boundary")
    if source_authority != attack_story.AUTHORITY_BOUNDARY or any(
        bool(value) for value in dict(source_authority or {}).values()
    ):
        failures.append("safe_response:story_authority_boundary_invalid")
    if payload.get("privacy") != attack_story.PRIVACY_BOUNDARY:
        failures.append("safe_response:story_privacy_boundary_invalid")
    if str(payload.get("story_digest") or "") != _digest(_story_core(payload)):
        failures.append("safe_response:story_digest_invalid")

    try:
        stages = _stage_map(payload)
    except ValueError as exc:
        failures.append(str(exc))
        stages = {}

    observed_stages: set[str] = set()
    observed_evidence: set[str] = set()
    for stage_id, row in stages.items():
        status = row.get("status")
        evidence_ids = row.get("evidence_ids")
        node_ids = row.get("node_ids")
        if status not in {"OBSERVED", "UNKNOWN"}:
            failures.append(f"safe_response:stage_status_invalid:{stage_id}")
            continue
        if not isinstance(evidence_ids, list) or not isinstance(node_ids, list):
            failures.append(f"safe_response:stage_evidence_invalid:{stage_id}")
            continue
        if status == "UNKNOWN" and (evidence_ids or node_ids):
            failures.append(f"safe_response:unknown_stage_contains_evidence:{stage_id}")
        if status == "OBSERVED":
            observed_stages.add(stage_id)
            observed_evidence.update(str(item) for item in evidence_ids if str(item))

    claims = payload.get("claims")
    if not isinstance(claims, list):
        failures.append("safe_response:story_claims_required")
    else:
        for claim in claims:
            if not isinstance(claim, dict):
                failures.append("safe_response:story_claim_invalid")
                continue
            if claim.get("stage_id") not in observed_stages:
                failures.append("safe_response:claim_without_observed_stage")
            claim_evidence = claim.get("evidence_ids")
            if not isinstance(claim_evidence, list) or not claim_evidence:
                failures.append("safe_response:claim_evidence_required")
            elif not set(str(item) for item in claim_evidence).issubset(observed_evidence):
                failures.append("safe_response:claim_evidence_outside_story")
    if not observed_stages or not observed_evidence:
        failures.append("safe_response:accepted_observed_evidence_required")
    return {
        "passed": not failures,
        "failures": failures,
        "observed_stages": sorted(observed_stages),
        "observed_evidence_ids": sorted(observed_evidence),
    }


def _action(
    *,
    action_id: str,
    title: str,
    category: str,
    priority: int,
    state: str,
    reason: str,
    evidence_stage_ids: list[str],
    evidence_ids: list[str],
    expected_impact: str,
    required_authorities: list[str],
    blockers: list[str],
    reversibility: str,
    rollback_required: bool,
    user_confirmation_required: bool,
    would_mutate_system_if_executed: bool,
) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "title": title,
        "category": category,
        "priority": int(priority),
        "state": state,
        "reason": reason,
        "evidence_stage_ids": list(evidence_stage_ids),
        "evidence_ids": list(evidence_ids),
        "expected_impact": expected_impact,
        "required_authorities": list(required_authorities),
        "blockers": list(blockers),
        "reversibility": reversibility,
        "rollback_required": bool(rollback_required),
        "user_confirmation_required": bool(user_confirmation_required),
        "would_mutate_system_if_executed": bool(would_mutate_system_if_executed),
        "execution_available": False,
        "execution_authorized": False,
        "automatic": False,
        "mutates_system": False,
    }


def _evidence_for(stages: dict[str, dict[str, Any]], *stage_ids: str) -> list[str]:
    evidence: set[str] = set()
    for stage_id in stage_ids:
        row = stages.get(stage_id) or {}
        if row.get("status") == "OBSERVED":
            evidence.update(str(item) for item in row.get("evidence_ids", []) if str(item))
    return sorted(evidence)


def _validate_legacy_boundary() -> None:
    legacy = guided_resolution_execution_gate.validate_b654_execution_gate_contract()
    required = (
        "confirmed_receipt_is_not_execution_authority",
        "fresh_target_revalidation_after_confirmation_required",
        "provider_execution_boundary_required",
        "provider_action_availability_required",
        "journal_storage_binding_required",
        "rollback_binding_required",
    )
    if not legacy.get("passed") or not all(legacy.get(key) is True for key in required):
        raise RuntimeError("safe_response:legacy_execution_boundary_not_preserved")
    forbidden = (
        "execution_api",
        "execution_authorized",
        "execution_nonce_issued",
        "journal_write_authority",
        "rollback_execution_authority",
        "automatic_quarantine",
        "automatic_repair",
        "automatic_destructive_action",
    )
    if any(legacy.get(key) is True for key in forbidden):
        raise RuntimeError("safe_response:legacy_boundary_unexpected_authority")


def build_response_plan(source_story: dict[str, Any]) -> dict[str, Any]:
    source_validation = validate_source_story(source_story)
    if not source_validation["passed"]:
        raise ValueError("safe_response:source_invalid:" + ",".join(source_validation["failures"]))
    _validate_legacy_boundary()

    stages = _stage_map(source_story)
    observed = [sid for sid in attack_story.STAGE_IDS if stages[sid].get("status") == "OBSERVED"]
    unknown = [sid for sid in attack_story.STAGE_IDS if stages[sid].get("status") == "UNKNOWN"]
    all_evidence = sorted(
        {str(eid) for sid in observed for eid in stages[sid].get("evidence_ids", []) if str(eid)}
    )

    actions: list[dict[str, Any]] = [
        _action(
            action_id="PRESERVE_INCIDENT_EVIDENCE",
            title="Preserva le prove dell'incidente",
            category="EVIDENCE",
            priority=1,
            state=ACTION_GUIDANCE_ONLY,
            reason="Conservare gli ID di prova e la provenienza accettata prima di qualsiasi futura risposta.",
            evidence_stage_ids=observed,
            evidence_ids=all_evidence,
            expected_impact="Nessuna modifica al sistema; mantiene tracciabile la base probatoria del piano.",
            required_authorities=[],
            blockers=[],
            reversibility="NOT_APPLICABLE",
            rollback_required=False,
            user_confirmation_required=False,
            would_mutate_system_if_executed=False,
        )
    ]

    if stages["DETECTION"].get("status") == "OBSERVED":
        containment_stages = [
            sid for sid in ("FILE_ACTIVITY", "DETECTION") if stages[sid].get("status") == "OBSERVED"
        ]
        actions.append(
            _action(
                action_id="PREPARE_CONTAINMENT",
                title="Prepara il contenimento",
                category="CONTAINMENT",
                priority=2,
                state=ACTION_BLOCKED_AUTHORITY,
                reason="Il rilevamento è osservato, ma il contenimento reale richiede autorità, identità del target, journal e rollback non concessi a B10-4.",
                evidence_stage_ids=containment_stages,
                evidence_ids=_evidence_for(stages, *containment_stages),
                expected_impact="Se autorizzato in una milestone futura, potrebbe isolare il target; B10-4 non esegue alcuna modifica.",
                required_authorities=[
                    "EXPLICIT_USER_CONFIRMATION",
                    "TARGET_IDENTITY_BINDING",
                    "QUARANTINE_AUTHORITY",
                    "JOURNAL_BINDING",
                    "ROLLBACK_BINDING",
                ],
                blockers=[
                    "execution_authority_not_granted",
                    "quarantine_authority_not_granted",
                    "target_identity_binding_required",
                    "journal_storage_not_bound",
                    "rollback_not_bound",
                ],
                reversibility="CONDITIONALLY_REVERSIBLE",
                rollback_required=True,
                user_confirmation_required=True,
                would_mutate_system_if_executed=True,
            )
        )

    if unknown:
        actions.append(
            _action(
                action_id="VERIFY_UNKNOWN_STAGES",
                title="Verifica le fasi non dimostrate",
                category="INVESTIGATION",
                priority=3,
                state=ACTION_GUIDANCE_ONLY,
                reason="Attack Story mantiene alcune fasi UNKNOWN; il piano le elenca senza inventare causalità o telemetria.",
                evidence_stage_ids=observed,
                evidence_ids=all_evidence,
                expected_impact="Aumenta la chiarezza investigativa senza cambiare lo stato delle fasi o il sistema.",
                required_authorities=[],
                blockers=[],
                reversibility="NOT_APPLICABLE",
                rollback_required=False,
                user_confirmation_required=False,
                would_mutate_system_if_executed=False,
            )
        )

    actions.append(
        _action(
            action_id="PREPARE_RESCUE_HANDOFF",
            title="Prepara il passaggio a Rescue",
            category="RECOVERY",
            priority=4,
            state=ACTION_HANDOFF_ONLY,
            reason="Preserva incidente, prove e contesto di risposta per il futuro flusso Rescue Continuity.",
            evidence_stage_ids=observed,
            evidence_ids=all_evidence,
            expected_impact="Crea solo il contesto di handoff; nessuna azione Rescue viene eseguita da B10-4.",
            required_authorities=["EXPLICIT_USER_DECISION_FOR_FUTURE_RESCUE"],
            blockers=["rescue_execution_owned_by_later_milestone"],
            reversibility="NOT_APPLICABLE",
            rollback_required=False,
            user_confirmation_required=True,
            would_mutate_system_if_executed=False,
        )
    )

    plan_material = {
        "incident_id": source_story["incident_id"],
        "story_id": source_story["story_id"],
        "story_digest": source_story["story_digest"],
        "actions": actions,
        "observed": observed,
        "unknown": unknown,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "plan_id": "safe-response:" + _digest(plan_material)[:24],
        "incident_id": source_story["incident_id"],
        "source_story_id": source_story["story_id"],
        "source_story_digest": source_story["story_digest"],
        "source_live_control": bool(source_story.get("source_live_control")),
        "plan_state": PLAN_STATE,
        "actions": actions,
        "observed_stage_ids": observed,
        "unknown_stage_ids": unknown,
        "source_response_stage_status": str(stages["RESPONSE"].get("status")),
        "response_stage_claimed_observed": False,
        "plain_language_summary": "Piano di risposta preparato; nessuna azione è stata eseguita o autorizzata.",
        "technical_summary": (
            f"incident={source_story['incident_id']}; story={source_story['story_digest']}; "
            f"actions={len(actions)}; execution=false; authority_expanded=false."
        ),
        "coverage_summary": dict(CURRENT_COVERAGE),
        "coverage_changed": False,
        "broad_protection_claimed": False,
        "authority_expanded": False,
        "execution_api": False,
        "execution_available": False,
        "execution_authorized": False,
        "automatic_action": False,
        "remediation_performed": False,
        "system_mutation_performed": False,
        "legacy_guided_resolution_boundary_preserved": True,
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "privacy": dict(PRIVACY_BOUNDARY),
    }
    payload["plan_digest"] = _digest(_plan_core(payload))
    validation = validate_response_plan(payload)
    if not validation["passed"]:
        raise RuntimeError("safe_response:generated_plan_invalid:" + ",".join(validation["failures"]))
    return payload


def validate_response_plan(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["safe_response:plan_not_object"]}
    if payload.get("schema") != SCHEMA or payload.get("profile") != PROFILE:
        failures.append("safe_response:plan_schema_or_profile_invalid")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT or payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("safe_response:plan_source_checkpoint_invalid")
    if payload.get("plan_state") != PLAN_STATE:
        failures.append("safe_response:plan_state_invalid")
    if payload.get("coverage_summary") != CURRENT_COVERAGE or payload.get("coverage_changed") is not False:
        failures.append("safe_response:coverage_boundary_invalid")
    if payload.get("broad_protection_claimed") is not False or payload.get("authority_expanded") is not False:
        failures.append("safe_response:claim_or_authority_boundary_invalid")
    if payload.get("response_stage_claimed_observed") is not False:
        failures.append("safe_response:planner_cannot_claim_response_observed")
    if payload.get("legacy_guided_resolution_boundary_preserved") is not True:
        failures.append("safe_response:legacy_boundary_missing")
    for key in (
        "execution_api",
        "execution_available",
        "execution_authorized",
        "automatic_action",
        "remediation_performed",
        "system_mutation_performed",
    ):
        if payload.get(key) is not False:
            failures.append(f"safe_response:forbidden_plan_authority:{key}")
    authority = payload.get("authority_boundary")
    if authority != AUTHORITY_BOUNDARY or any(bool(v) for v in dict(authority or {}).values()):
        failures.append("safe_response:authority_boundary_invalid")
    if payload.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("safe_response:privacy_boundary_invalid")

    actions = payload.get("actions")
    priorities: list[int] = []
    if not isinstance(actions, list) or not actions:
        failures.append("safe_response:actions_required")
        actions = []
    for action in actions:
        if not isinstance(action, dict):
            failures.append("safe_response:action_invalid")
            continue
        if action.get("state") not in ACTION_STATES:
            failures.append("safe_response:action_state_invalid")
        if action.get("reversibility") not in REVERSIBILITY_STATES:
            failures.append("safe_response:action_reversibility_invalid")
        if any(action.get(key) is not False for key in ("execution_available", "execution_authorized", "automatic", "mutates_system")):
            failures.append("safe_response:action_execution_or_mutation_forbidden")
        if not isinstance(action.get("evidence_stage_ids"), list) or not isinstance(action.get("evidence_ids"), list):
            failures.append("safe_response:action_evidence_binding_invalid")
        try:
            priorities.append(int(action.get("priority")))
        except (TypeError, ValueError):
            failures.append("safe_response:action_priority_invalid")
        if action.get("state") == ACTION_BLOCKED_AUTHORITY:
            if not action.get("blockers") or not action.get("required_authorities"):
                failures.append("safe_response:blocked_action_requires_blockers_and_authorities")
            if action.get("would_mutate_system_if_executed") is not True:
                failures.append("safe_response:blocked_mutating_intent_not_declared")
            if action.get("rollback_required") is not True or action.get("user_confirmation_required") is not True:
                failures.append("safe_response:blocked_action_safety_requirements_missing")
    if priorities and priorities != sorted(priorities):
        failures.append("safe_response:action_priority_order_invalid")

    if payload.get("plan_digest") != _digest(_plan_core(payload)):
        failures.append("safe_response:plan_digest_invalid")
    expected_plan_id = "safe-response:" + _digest(
        {
            "incident_id": payload.get("incident_id"),
            "story_id": payload.get("source_story_id"),
            "story_digest": payload.get("source_story_digest"),
            "actions": payload.get("actions"),
            "observed": payload.get("observed_stage_ids"),
            "unknown": payload.get("unknown_stage_ids"),
        }
    )[:24]
    if payload.get("plan_id") != expected_plan_id:
        failures.append("safe_response:plan_id_invalid")
    return {"passed": not failures, "failures": failures, "action_count": len(actions)}


def plan_from_b93_evidence(evidence: object) -> dict[str, Any]:
    source = attack_story.story_from_b93_evidence(evidence)
    if not source.get("passed"):
        return {"passed": False, "failures": ["safe_response:attack_story_source_not_accepted"]}
    try:
        plan = build_response_plan(source)
    except (ValueError, RuntimeError) as exc:
        return {"passed": False, "failures": [str(exc)]}
    plan.update(
        {
            "passed": True,
            "source_detector_outcome": source.get("source_detector_outcome"),
            "source_detector_score": source.get("source_detector_score"),
            "detector_to_security_graph_bound": source.get("detector_to_security_graph_bound"),
            "security_graph_to_incident_bound": source.get("security_graph_to_incident_bound"),
            "synthetic_fallback_used": source.get("synthetic_fallback_used"),
        }
    )
    wrapper_validation = validate_response_plan(plan)
    if not wrapper_validation["passed"]:
        return {"passed": False, "failures": wrapper_validation["failures"]}
    return plan


def validate_b104_contract() -> dict[str, Any]:
    legacy = guided_resolution_execution_gate.validate_b654_execution_gate_contract()
    return {
        "profile": PROFILE,
        "schema": SCHEMA,
        "passed": bool(legacy.get("passed")),
        "planning_only": True,
        "execution_api": False,
        "execution_authorized": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_restore": False,
        "privileged_system_mutation": False,
        "response_planning_is_not_observed_response": True,
        "legacy_guided_resolution_boundary_preserved": bool(legacy.get("passed")),
        "coverage_summary": dict(CURRENT_COVERAGE),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B10-4 Safe Response Plan Engine")
    parser.add_argument("--b93-evidence", type=Path)
    args = parser.parse_args(argv)
    if args.b93_evidence is None:
        print(json.dumps(validate_b104_contract(), indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    evidence = json.loads(args.b93_evidence.read_text(encoding="utf-8-sig"))
    result = plan_from_b93_evidence(evidence)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
