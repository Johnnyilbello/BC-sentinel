from __future__ import annotations

"""B10-5 Rescue Continuity.

Carry accepted B10-4 incident, evidence-provenance and response-plan context into
legacy Rescue planning without selecting a target or granting execution authority.
The continuity envelope is deterministic, path-free, local-first and read-only.
"""

import argparse
import hashlib
import json
import re
from typing import Any, Final

from sentinel import beta10_safe_response_plan as safe_response
from sentinel import rescue_contract
from sentinel import rescue_session_resume

SCHEMA: Final[str] = "bc-sentinel-beta10-rescue-continuity-v1"
IMPORT_SCHEMA: Final[str] = "bc-sentinel-beta10-rescue-import-context-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b105-rescue-continuity"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b104-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "a23550a0cf31aecdce54d5eca333b3930ca2edc7"
CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
CONTINUITY_STATE: Final[str] = "PORTABLE_CONTEXT_PREPARED_NOT_EXECUTABLE"
TARGET_BINDING_STATE: Final[str] = "REQUIRED"

RECOMMENDED_RESCUE_CONTEXTS: Final[tuple[str, ...]] = (
    rescue_contract.RescueExecutionContext.TRUSTED_EXTERNAL_MEDIA.value,
    rescue_contract.RescueExecutionContext.OFFLINE_IMAGE.value,
)

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "execution_authority": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "rescue_write_authority": False,
    "rescue_repair_execution": False,
    "rescue_quarantine_execution": False,
    "rescue_automatic_mutation_resume": False,
}

PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "remote_access": False,
    "network_required": False,
    "cloud_required": False,
}

_FORBIDDEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "target_root",
        "current_target_root",
        "expected_target_root",
        "output_dir",
        "journal_path",
        "evidence_path",
        "absolute_path",
        "file_path",
        "command_line",
        "script_content",
        "file_content",
    }
)
_WINDOWS_ABSOLUTE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:[\\/]")

_CONTINUITY_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "source_checkpoint",
    "source_checkpoint_commit",
    "continuity_id",
    "incident_id",
    "source_story_id",
    "source_story_digest",
    "source_plan_id",
    "source_plan_digest",
    "source_live_control",
    "continuity_state",
    "target_binding_state",
    "accepted_rescue_contexts",
    "evidence_provenance",
    "observed_stage_ids",
    "unknown_stage_ids",
    "recommended_rescue_steps",
    "source_response_stage_status",
    "response_stage_claimed_observed",
    "rescue_start_authorized",
    "execution_available",
    "execution_authorized",
    "automatic_action",
    "remediation_performed",
    "system_mutation_performed",
    "authority_expanded",
    "coverage_summary",
    "coverage_changed",
    "broad_protection_claimed",
    "legacy_rescue_contract_profile",
    "legacy_rescue_contract_digest",
    "legacy_rescue_resume_boundary_preserved",
    "authority_boundary",
    "privacy",
)

_IMPORT_CORE_KEYS: Final[tuple[str, ...]] = (
    "schema",
    "profile",
    "continuity_id",
    "continuity_digest",
    "incident_id",
    "source_plan_id",
    "source_plan_digest",
    "execution_context",
    "legacy_allowed_capabilities",
    "planning_only_capabilities",
    "recommended_rescue_steps",
    "target_binding_state",
    "target_bound",
    "write_authorized",
    "recovery_certification_available",
    "automatic_resume_allowed",
    "operator_confirmation_required",
    "execution_available",
    "execution_authorized",
    "system_mutation_performed",
    "authority_expanded",
    "privacy",
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _continuity_core(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in _CONTINUITY_CORE_KEYS}


def _import_core(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in _IMPORT_CORE_KEYS}


def _contains_forbidden_field(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in _FORBIDDEN_FIELDS or _contains_forbidden_field(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_field(item) for item in value)
    return False


def _contains_absolute_path_string(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_absolute_path_string(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_absolute_path_string(item) for item in value)
    if isinstance(value, str):
        text = value.strip()
        return bool(_WINDOWS_ABSOLUTE_RE.match(text) or text.startswith("\\\\") or text.startswith("/"))
    return False


def _opaque_reference_valid(value: object) -> bool:
    text = str(value or "").strip()
    return bool(
        text
        and len(text) <= 256
        and "\\" not in text
        and "/" not in text
        and "\n" not in text
        and "\r" not in text
        and text not in {".", ".."}
    )


def _legacy_contract_snapshot() -> dict[str, Any]:
    snapshot = rescue_contract.rr0_contract_snapshot()
    if snapshot.get("read_only_default") is not True:
        raise RuntimeError("rescue_continuity:legacy_rescue_not_read_only")
    if snapshot.get("destructive_actions_enabled") is not False:
        raise RuntimeError("rescue_continuity:legacy_destructive_actions_enabled")
    if snapshot.get("recovery_certification_enabled") is not False:
        raise RuntimeError("rescue_continuity:legacy_recovery_certification_enabled")
    return snapshot


def _resume_boundary_preserved() -> bool:
    expected_operator_gated = {"repair_handoff", "repair_execute", "repair_rollback", "data_rescue"}
    return (
        expected_operator_gated.issubset(set(rescue_session_resume.OPERATOR_GATED_STAGES))
        and rescue_session_resume.OPERATOR_GATED_STAGES.isdisjoint(
            rescue_session_resume.READ_ONLY_RESUMABLE_STAGES
        )
    )


def validate_source_plan(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    validation = safe_response.validate_response_plan(payload)
    if not validation.get("passed"):
        failures.extend(f"rescue_continuity:source:{item}" for item in validation.get("failures", []))
        return {"passed": False, "failures": failures}
    assert isinstance(payload, dict)

    if payload.get("authority_expanded") is not False:
        failures.append("rescue_continuity:source_authority_expanded")
    if payload.get("execution_available") is not False or payload.get("execution_authorized") is not False:
        failures.append("rescue_continuity:source_execution_boundary_invalid")
    if payload.get("remediation_performed") is not False or payload.get("system_mutation_performed") is not False:
        failures.append("rescue_continuity:source_mutation_boundary_invalid")
    if payload.get("privacy") != safe_response.PRIVACY_BOUNDARY:
        failures.append("rescue_continuity:source_privacy_boundary_invalid")

    actions = payload.get("actions") if isinstance(payload.get("actions"), list) else []
    handoffs = [row for row in actions if isinstance(row, dict) and row.get("action_id") == "PREPARE_RESCUE_HANDOFF"]
    if len(handoffs) != 1:
        failures.append("rescue_continuity:exactly_one_rescue_handoff_required")
    else:
        handoff = handoffs[0]
        if handoff.get("state") != safe_response.ACTION_HANDOFF_ONLY:
            failures.append("rescue_continuity:rescue_handoff_state_invalid")
        if handoff.get("user_confirmation_required") is not True:
            failures.append("rescue_continuity:rescue_handoff_confirmation_required")
        if any(handoff.get(key) is not False for key in ("execution_available", "execution_authorized", "automatic", "mutates_system")):
            failures.append("rescue_continuity:rescue_handoff_must_be_non_executing")

    return {"passed": not failures, "failures": failures}


def _collect_evidence_provenance(plan: dict[str, Any]) -> list[dict[str, str]]:
    refs: set[str] = set()
    for action in plan.get("actions", []):
        if not isinstance(action, dict):
            continue
        for value in action.get("evidence_ids", []):
            if not _opaque_reference_valid(value):
                raise ValueError("rescue_continuity:evidence_reference_not_portable")
            refs.add(str(value))
    if not refs:
        raise ValueError("rescue_continuity:evidence_provenance_required")
    return [
        {"reference": ref, "reference_sha256": hashlib.sha256(ref.encode("utf-8")).hexdigest()}
        for ref in sorted(refs)
    ]


def _recommended_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {
            "step_id": "VERIFY_CONTINUITY_INTEGRITY",
            "priority": 1,
            "state": "READ_ONLY_GUIDANCE",
            "legacy_capabilities": [],
            "reason": "Verificare digest e provenienza prima di usare il contesto nel flusso Rescue.",
            "target_binding_required": False,
            "operator_confirmation_required": False,
            "execution_available": False,
        },
        {
            "step_id": "BIND_RESCUE_TARGET",
            "priority": 2,
            "state": "TARGET_BINDING_REQUIRED",
            "legacy_capabilities": [],
            "reason": "Il target Rescue non viene ereditato dal sistema installato e deve essere rivalidato nel contesto Rescue.",
            "target_binding_required": True,
            "operator_confirmation_required": True,
            "execution_available": False,
        },
        {
            "step_id": "ACQUIRE_READ_ONLY_EVIDENCE",
            "priority": 3,
            "state": "READ_ONLY_GUIDANCE",
            "legacy_capabilities": [rescue_contract.RescueCapability.ACQUIRE_EVIDENCE.value],
            "reason": "Acquisire nuova evidenza Rescue in sola lettura mantenendo il collegamento con la provenienza dell'incidente.",
            "target_binding_required": True,
            "operator_confirmation_required": False,
            "execution_available": False,
        },
        {
            "step_id": "INSPECT_OFFLINE_TARGET",
            "priority": 4,
            "state": "READ_ONLY_GUIDANCE",
            "legacy_capabilities": [
                rescue_contract.RescueCapability.INSPECT_FILESYSTEM.value,
                rescue_contract.RescueCapability.INSPECT_REGISTRY.value,
            ],
            "reason": "Usare le capacità Rescue accettate per ispezionare il target senza scritture o remediation automatica.",
            "target_binding_required": True,
            "operator_confirmation_required": False,
            "execution_available": False,
        },
    ]
    if plan.get("unknown_stage_ids"):
        steps.append(
            {
                "step_id": "REVIEW_UNKNOWN_ATTACK_STAGES",
                "priority": 5,
                "state": "READ_ONLY_GUIDANCE",
                "legacy_capabilities": [],
                "reason": "Conservare come UNKNOWN le fasi non dimostrate e cercare solo nuova evidenza verificabile.",
                "target_binding_required": True,
                "operator_confirmation_required": False,
                "execution_available": False,
            }
        )
    steps.append(
        {
            "step_id": "REVIEW_PLANNED_RECOVERY",
            "priority": 6,
            "state": "PLANNING_ONLY",
            "legacy_capabilities": [
                rescue_contract.RescueCapability.PLAN_QUARANTINE.value,
                rescue_contract.RescueCapability.PLAN_REPAIR.value,
            ],
            "reason": "Preparare eventuali opzioni di recovery senza trasformare il piano in autorità di esecuzione.",
            "target_binding_required": True,
            "operator_confirmation_required": True,
            "execution_available": False,
        }
    )
    return steps


def build_continuity_envelope(source_plan: dict[str, Any]) -> dict[str, Any]:
    source_validation = validate_source_plan(source_plan)
    if not source_validation["passed"]:
        raise ValueError("rescue_continuity:source_plan_invalid:" + ",".join(source_validation["failures"]))

    legacy = _legacy_contract_snapshot()
    if not _resume_boundary_preserved():
        raise RuntimeError("rescue_continuity:legacy_resume_boundary_not_preserved")

    provenance = _collect_evidence_provenance(source_plan)
    steps = _recommended_steps(source_plan)
    material = {
        "incident_id": source_plan["incident_id"],
        "source_plan_id": source_plan["plan_id"],
        "source_plan_digest": source_plan["plan_digest"],
        "evidence_provenance": provenance,
        "recommended_rescue_steps": steps,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "continuity_id": "rescue-continuity:" + _digest(material)[:24],
        "incident_id": source_plan["incident_id"],
        "source_story_id": source_plan["source_story_id"],
        "source_story_digest": source_plan["source_story_digest"],
        "source_plan_id": source_plan["plan_id"],
        "source_plan_digest": source_plan["plan_digest"],
        "source_live_control": bool(source_plan.get("source_live_control")),
        "continuity_state": CONTINUITY_STATE,
        "target_binding_state": TARGET_BINDING_STATE,
        "accepted_rescue_contexts": list(RECOMMENDED_RESCUE_CONTEXTS),
        "evidence_provenance": provenance,
        "observed_stage_ids": list(source_plan["observed_stage_ids"]),
        "unknown_stage_ids": list(source_plan["unknown_stage_ids"]),
        "recommended_rescue_steps": steps,
        "source_response_stage_status": source_plan["source_response_stage_status"],
        "response_stage_claimed_observed": False,
        "rescue_start_authorized": False,
        "execution_available": False,
        "execution_authorized": False,
        "automatic_action": False,
        "remediation_performed": False,
        "system_mutation_performed": False,
        "authority_expanded": False,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "coverage_changed": False,
        "broad_protection_claimed": False,
        "legacy_rescue_contract_profile": str(legacy["profile"]),
        "legacy_rescue_contract_digest": _digest(legacy),
        "legacy_rescue_resume_boundary_preserved": True,
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "privacy": dict(PRIVACY_BOUNDARY),
    }
    payload["continuity_digest"] = _digest(_continuity_core(payload))
    validation = validate_continuity_envelope(payload)
    if not validation["passed"]:
        raise RuntimeError("rescue_continuity:generated_envelope_invalid:" + ",".join(validation["failures"]))
    return payload


def validate_continuity_envelope(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["rescue_continuity:envelope_not_object"]}
    if payload.get("schema") != SCHEMA or payload.get("profile") != PROFILE:
        failures.append("rescue_continuity:schema_or_profile_invalid")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT or payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("rescue_continuity:source_checkpoint_invalid")
    if payload.get("continuity_state") != CONTINUITY_STATE:
        failures.append("rescue_continuity:state_invalid")
    if payload.get("target_binding_state") != TARGET_BINDING_STATE:
        failures.append("rescue_continuity:target_binding_must_remain_required")
    if payload.get("accepted_rescue_contexts") != list(RECOMMENDED_RESCUE_CONTEXTS):
        failures.append("rescue_continuity:rescue_contexts_invalid")
    if payload.get("coverage_summary") != CURRENT_COVERAGE or payload.get("coverage_changed") is not False:
        failures.append("rescue_continuity:coverage_boundary_invalid")
    if payload.get("broad_protection_claimed") is not False or payload.get("authority_expanded") is not False:
        failures.append("rescue_continuity:claim_or_authority_boundary_invalid")
    if payload.get("response_stage_claimed_observed") is not False:
        failures.append("rescue_continuity:cannot_claim_response_observed")
    for key in (
        "rescue_start_authorized",
        "execution_available",
        "execution_authorized",
        "automatic_action",
        "remediation_performed",
        "system_mutation_performed",
    ):
        if payload.get(key) is not False:
            failures.append(f"rescue_continuity:forbidden_authority:{key}")
    if payload.get("authority_boundary") != AUTHORITY_BOUNDARY or any(
        bool(value) for value in dict(payload.get("authority_boundary") or {}).values()
    ):
        failures.append("rescue_continuity:authority_boundary_invalid")
    if payload.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("rescue_continuity:privacy_boundary_invalid")
    if payload.get("legacy_rescue_resume_boundary_preserved") is not True:
        failures.append("rescue_continuity:legacy_resume_boundary_missing")

    try:
        legacy = _legacy_contract_snapshot()
        if payload.get("legacy_rescue_contract_profile") != legacy.get("profile"):
            failures.append("rescue_continuity:legacy_contract_profile_invalid")
        if payload.get("legacy_rescue_contract_digest") != _digest(legacy):
            failures.append("rescue_continuity:legacy_contract_digest_invalid")
    except RuntimeError as exc:
        failures.append(str(exc))
    if not _resume_boundary_preserved():
        failures.append("rescue_continuity:legacy_resume_boundary_not_preserved")

    provenance = payload.get("evidence_provenance")
    if not isinstance(provenance, list) or not provenance:
        failures.append("rescue_continuity:evidence_provenance_required")
        provenance = []
    seen_refs: set[str] = set()
    for row in provenance:
        if not isinstance(row, dict):
            failures.append("rescue_continuity:evidence_provenance_invalid")
            continue
        ref = str(row.get("reference") or "")
        if not _opaque_reference_valid(ref):
            failures.append("rescue_continuity:evidence_reference_not_portable")
        if ref in seen_refs:
            failures.append("rescue_continuity:evidence_reference_duplicate")
        seen_refs.add(ref)
        expected = hashlib.sha256(ref.encode("utf-8")).hexdigest()
        if row.get("reference_sha256") != expected:
            failures.append("rescue_continuity:evidence_reference_digest_invalid")

    steps = payload.get("recommended_rescue_steps")
    priorities: list[int] = []
    if not isinstance(steps, list) or not steps:
        failures.append("rescue_continuity:recommended_steps_required")
        steps = []
    for step in steps:
        if not isinstance(step, dict):
            failures.append("rescue_continuity:recommended_step_invalid")
            continue
        if step.get("execution_available") is not False:
            failures.append("rescue_continuity:recommended_step_cannot_execute")
        try:
            priorities.append(int(step.get("priority")))
        except (TypeError, ValueError):
            failures.append("rescue_continuity:recommended_step_priority_invalid")
    if priorities and priorities != sorted(priorities):
        failures.append("rescue_continuity:recommended_step_order_invalid")

    if _contains_forbidden_field(payload):
        failures.append("rescue_continuity:path_or_content_field_forbidden")
    if _contains_absolute_path_string(payload):
        failures.append("rescue_continuity:absolute_path_value_forbidden")
    if payload.get("continuity_digest") != _digest(_continuity_core(payload)):
        failures.append("rescue_continuity:continuity_digest_invalid")

    material = {
        "incident_id": payload.get("incident_id"),
        "source_plan_id": payload.get("source_plan_id"),
        "source_plan_digest": payload.get("source_plan_digest"),
        "evidence_provenance": payload.get("evidence_provenance"),
        "recommended_rescue_steps": payload.get("recommended_rescue_steps"),
    }
    expected_id = "rescue-continuity:" + _digest(material)[:24]
    if payload.get("continuity_id") != expected_id:
        failures.append("rescue_continuity:continuity_id_invalid")
    return {
        "passed": not failures,
        "failures": failures,
        "evidence_reference_count": len(provenance),
        "recommended_step_count": len(steps),
    }


def project_for_rescue(payload: dict[str, Any], execution_context: str) -> dict[str, Any]:
    validation = validate_continuity_envelope(payload)
    if not validation["passed"]:
        raise ValueError("rescue_continuity:envelope_invalid:" + ",".join(validation["failures"]))
    if execution_context not in RECOMMENDED_RESCUE_CONTEXTS:
        raise ValueError("rescue_continuity:execution_context_not_accepted_for_handoff")

    context = rescue_contract.RescueExecutionContext(execution_context)
    capabilities = sorted(cap.value for cap in rescue_contract.allowed_capabilities(context))
    planning_only = sorted(
        cap
        for cap in capabilities
        if cap in {
            rescue_contract.RescueCapability.PLAN_QUARANTINE.value,
            rescue_contract.RescueCapability.PLAN_REPAIR.value,
        }
    )
    projection: dict[str, Any] = {
        "schema": IMPORT_SCHEMA,
        "profile": PROFILE,
        "continuity_id": payload["continuity_id"],
        "continuity_digest": payload["continuity_digest"],
        "incident_id": payload["incident_id"],
        "source_plan_id": payload["source_plan_id"],
        "source_plan_digest": payload["source_plan_digest"],
        "execution_context": context.value,
        "legacy_allowed_capabilities": capabilities,
        "planning_only_capabilities": planning_only,
        "recommended_rescue_steps": list(payload["recommended_rescue_steps"]),
        "target_binding_state": TARGET_BINDING_STATE,
        "target_bound": False,
        "write_authorized": False,
        "recovery_certification_available": False,
        "automatic_resume_allowed": False,
        "operator_confirmation_required": True,
        "execution_available": False,
        "execution_authorized": False,
        "system_mutation_performed": False,
        "authority_expanded": False,
        "privacy": dict(PRIVACY_BOUNDARY),
    }
    projection["projection_digest"] = _digest(_import_core(projection))
    projection_validation = validate_rescue_projection(projection)
    if not projection_validation["passed"]:
        raise RuntimeError("rescue_continuity:generated_projection_invalid:" + ",".join(projection_validation["failures"]))
    return projection


def validate_rescue_projection(payload: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["rescue_continuity:projection_not_object"]}
    if payload.get("schema") != IMPORT_SCHEMA or payload.get("profile") != PROFILE:
        failures.append("rescue_continuity:projection_schema_or_profile_invalid")
    if payload.get("execution_context") not in RECOMMENDED_RESCUE_CONTEXTS:
        failures.append("rescue_continuity:projection_context_invalid")
    if payload.get("target_binding_state") != TARGET_BINDING_STATE or payload.get("target_bound") is not False:
        failures.append("rescue_continuity:projection_target_must_remain_unbound")
    for key in (
        "write_authorized",
        "recovery_certification_available",
        "automatic_resume_allowed",
        "execution_available",
        "execution_authorized",
        "system_mutation_performed",
        "authority_expanded",
    ):
        if payload.get(key) is not False:
            failures.append(f"rescue_continuity:projection_forbidden_authority:{key}")
    if payload.get("operator_confirmation_required") is not True:
        failures.append("rescue_continuity:projection_operator_confirmation_required")
    if payload.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("rescue_continuity:projection_privacy_invalid")
    if _contains_forbidden_field(payload) or _contains_absolute_path_string(payload):
        failures.append("rescue_continuity:projection_path_or_content_forbidden")

    try:
        context = rescue_contract.RescueExecutionContext(str(payload.get("execution_context")))
        expected_capabilities = sorted(cap.value for cap in rescue_contract.allowed_capabilities(context))
        if payload.get("legacy_allowed_capabilities") != expected_capabilities:
            failures.append("rescue_continuity:projection_capabilities_invalid")
        expected_planning = sorted(
            cap
            for cap in expected_capabilities
            if cap in {
                rescue_contract.RescueCapability.PLAN_QUARANTINE.value,
                rescue_contract.RescueCapability.PLAN_REPAIR.value,
            }
        )
        if payload.get("planning_only_capabilities") != expected_planning:
            failures.append("rescue_continuity:projection_planning_capabilities_invalid")
    except ValueError:
        failures.append("rescue_continuity:projection_context_invalid")

    if payload.get("projection_digest") != _digest(_import_core(payload)):
        failures.append("rescue_continuity:projection_digest_invalid")
    return {"passed": not failures, "failures": failures}


def continuity_from_b93_evidence(evidence: object) -> dict[str, Any]:
    plan = safe_response.plan_from_b93_evidence(evidence)
    if not plan.get("passed"):
        return {"passed": False, "failures": ["rescue_continuity:source_safe_response_not_accepted"]}
    try:
        envelope = build_continuity_envelope(plan)
        projections = [project_for_rescue(envelope, context) for context in RECOMMENDED_RESCUE_CONTEXTS]
    except (ValueError, RuntimeError) as exc:
        return {"passed": False, "failures": [str(exc)]}
    return {
        "passed": True,
        "envelope": envelope,
        "projections": projections,
        "source_detector_outcome": plan.get("source_detector_outcome"),
        "source_detector_score": plan.get("source_detector_score"),
        "detector_to_security_graph_bound": plan.get("detector_to_security_graph_bound"),
        "security_graph_to_incident_bound": plan.get("security_graph_to_incident_bound"),
        "synthetic_fallback_used": plan.get("synthetic_fallback_used"),
    }


def validate_b105_contract() -> dict[str, Any]:
    legacy = _legacy_contract_snapshot()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": bool(_resume_boundary_preserved()),
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "continuity_only": True,
        "path_free_handoff": True,
        "target_binding_required": True,
        "rescue_start_authorized": False,
        "execution_available": False,
        "execution_authorized": False,
        "automatic_mutation_resume": False,
        "authority_expanded": False,
        "legacy_rescue_read_only_default": bool(legacy.get("read_only_default")),
        "legacy_destructive_actions_enabled": bool(legacy.get("destructive_actions_enabled")),
        "legacy_resume_boundary_preserved": bool(_resume_boundary_preserved()),
        "coverage_summary": dict(CURRENT_COVERAGE),
        "privacy": dict(PRIVACY_BOUNDARY),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B10-5 Rescue Continuity")
    parser.add_argument("--b93-evidence")
    args = parser.parse_args(argv)
    if not args.b93_evidence:
        print(json.dumps(validate_b105_contract(), indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    try:
        with open(args.b93_evidence, "r", encoding="utf-8-sig") as handle:
            evidence = json.load(handle)
        result = continuity_from_b93_evidence(evidence)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        result = {"passed": False, "failures": [f"rescue_continuity:input_error:{type(exc).__name__}"]}
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
