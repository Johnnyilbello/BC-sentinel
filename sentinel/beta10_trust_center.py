from __future__ import annotations

"""B10-8 Trust Center product integration.

Create one customer-facing, fail-closed snapshot of BC Sentinel's accepted
protection proof, coverage limitations, incident-story capability, response
boundaries, rescue continuity, privacy posture, and operational-impact status.

This module is presentation/data integration only. It does not execute scans,
quarantine files, restore files, mutate trust, access credentials, perform
network tests, or expand authority beyond the already accepted B10-6 disposable
workspace pilot.
"""

from copy import deepcopy
from typing import Any, Final

from sentinel import beta10_operational_impact as impact
from sentinel import beta10_reversible_response_pilot as reversible

SCHEMA: Final[str] = "bc-sentinel-beta10-trust-center-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b108-trust-center-product-integration"
SOURCE_PREDECESSOR_BRANCH: Final[str] = "feature/v011-beta10-b107-live-coverage-expansion-ii"
SOURCE_PREDECESSOR_COMMIT: Final[str] = "2428817e99b9e0969fc00e4c76e383a1004ba26c"
SOURCE_PREDECESSOR_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b107-pass"

CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

SCENARIOS: Final[tuple[dict[str, str], ...]] = (
    {
        "scenario_id": "B7-POWERSHELL-001",
        "label": "PowerShell",
        "status": "VERIFIED",
        "evidence_basis": "CONTROLLED_LIVE_POWERSHELL_METADATA_DETECTOR_PATH",
        "limitation": "Verifica limitata al detector metadata-only di burst del ciclo di vita PowerShell; non dimostra copertura generale degli abusi di script.",
    },
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "label": "Persistenza",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "limitation": "Non esiste ancora una sorgente live positiva innocua accettata per il detector di persistenza.",
    },
    {
        "scenario_id": "B7-RANSOMWARE-001",
        "label": "Comportamento ransomware-like",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B9_CONTROLLED_LIVE_LOCAL_DETECTOR_PATH",
        "limitation": "Verifica specifica dello scenario controllato locale; non equivale a copertura generale di tutte le famiglie ransomware.",
    },
    {
        "scenario_id": "B7-DEFENSE-EVASION-001",
        "label": "Defense evasion / tamper",
        "status": "PARTIAL",
        "evidence_basis": "BLOCKED_BY_CURRENT_AUTHORITY_BOUNDARY",
        "limitation": "Un controllo live positivo significativo richiederebbe mutazioni di controlli di sicurezza protetti non autorizzate in Beta10.",
    },
    {
        "scenario_id": "B7-C2-DNS-001",
        "label": "DNS / C2",
        "status": "PARTIAL",
        "evidence_basis": "BLOCKED_BY_NETWORK_TEST_AUTHORITY",
        "limitation": "La verifica live positiva richiederebbe autorità di test di rete che B10-7/B10-8 non concedono.",
    },
    {
        "scenario_id": "B7-CREDENTIAL-001",
        "label": "Accesso credenziali",
        "status": "PARTIAL",
        "evidence_basis": "BLOCKED_BY_PRIVACY_BOUNDARY",
        "limitation": "Un controllo positivo richiederebbe accesso sensibile alle credenziali, proibito dal confine privacy corrente.",
    },
)

PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "powershell_content_read": False,
    "event_message_read": False,
    "event_payload_read": False,
    "event_properties_read": False,
    "credential_access": False,
    "remote_access": False,
    "network_io": False,
    "cloud_required": False,
}

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "new_authority_expanded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "general_home_execution": False,
    "network_test_authority": False,
    "credential_access_authority": False,
    "protected_security_control_mutation": False,
    "broad_persistence_mutation": False,
}

CAPABILITIES: Final[tuple[dict[str, Any], ...]] = (
    {
        "capability_id": "PROTECTION_PROOF",
        "label": "Protection Proof",
        "status": "AVAILABLE",
        "summary": "Mostra quali scenari sono realmente verificati e quali restano parziali, con limiti espliciti.",
        "execution_authority": False,
    },
    {
        "capability_id": "ATTACK_STORY",
        "label": "Attack Story",
        "status": "AVAILABLE_WHEN_EVIDENCE_EXISTS",
        "summary": "Costruisce una storia dell'incidente solo da evidenza accettata; gli stadi mancanti restano UNKNOWN.",
        "execution_authority": False,
    },
    {
        "capability_id": "SAFE_RESPONSE_PLAN",
        "label": "Safe Response",
        "status": "PLANNING_AVAILABLE",
        "summary": "Può proporre azioni, impatto e rollback. L'esecuzione generale resta disabilitata.",
        "execution_authority": False,
    },
    {
        "capability_id": "REVERSIBLE_RESPONSE_PILOT",
        "label": "Reversible Response Pilot",
        "status": "NARROW_PILOT_AVAILABLE",
        "summary": "Quarantena reversibile solo in workspace temporaneo esplicitamente inizializzato, con conferma, binding del target, journal e rollback.",
        "execution_authority": True,
        "scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
    },
    {
        "capability_id": "RESCUE_CONTINUITY",
        "label": "Rescue Continuity",
        "status": "AVAILABLE",
        "summary": "Preserva continuità di incident ID, provenienza dell'evidenza e contesto di recupero verso i workflow rescue accettati.",
        "execution_authority": False,
    },
    {
        "capability_id": "OPERATIONAL_IMPACT",
        "label": "Operational Impact",
        "status": "AVAILABLE",
        "summary": "Misura latenza, CPU, RAM, falsi positivi e interruzioni utente senza modificare la copertura.",
        "execution_authority": False,
    },
)


def _accepted_foundation_ok() -> tuple[bool, list[str]]:
    failures: list[str] = []
    b106 = reversible.validate_b106_contract()
    b107 = impact.validate_b107_contract()
    if not b106.get("passed"):
        failures.append("foundation:b106_contract_failed")
    if not b107.get("passed"):
        failures.append("foundation:b107_contract_failed")
    if b107.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("foundation:b107_coverage_mismatch")
    if b107.get("source_predecessor_commit") != SOURCE_PREDECESSOR_COMMIT and b107.get("profile") != impact.PROFILE:
        failures.append("foundation:b107_identity_invalid")
    if b106.get("pilot_quarantine_authority") is not True or b106.get("pilot_rollback_authority") is not True:
        failures.append("foundation:b106_pilot_authority_missing")
    if b106.get("broad_home_execution") is not False:
        failures.append("foundation:b106_broad_home_execution_changed")
    return not failures, failures


def _impact_projection(report: object | None) -> tuple[dict[str, Any], list[str]]:
    if report is None:
        return (
            {
                "status": "NOT_LOADED",
                "measured": False,
                "metrics": None,
                "budgets": dict(impact.BUDGETS),
                "false_positive_controls_passed": None,
                "user_interruption_budget_passed": None,
                "performance_budget_passed": None,
            },
            [],
        )
    if not isinstance(report, dict):
        return ({"status": "INVALID", "measured": False, "metrics": None, "budgets": dict(impact.BUDGETS)}, ["impact:not_object"])

    failures: list[str] = []
    if report.get("schema") != impact.SCHEMA or report.get("profile") != impact.PROFILE:
        failures.append("impact:identity_invalid")
    if report.get("passed") is not True:
        failures.append("impact:not_passed")
    if report.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("impact:coverage_changed")
    if report.get("coverage_promoted") is not False:
        failures.append("impact:unexpected_coverage_promotion")
    if report.get("new_authority_expanded") is not False:
        failures.append("impact:authority_expanded")
    if report.get("false_positive_controls_passed") is not True:
        failures.append("impact:false_positive_controls_failed")
    if report.get("user_interruption_budget_passed") is not True:
        failures.append("impact:user_interruption_budget_failed")
    if report.get("performance_budget_passed") is not True:
        failures.append("impact:performance_budget_failed")
    metrics = report.get("operational_metrics")
    if not isinstance(metrics, dict):
        failures.append("impact:metrics_missing")
    if failures:
        return ({"status": "INVALID", "measured": False, "metrics": None, "budgets": dict(impact.BUDGETS)}, failures)
    return (
        {
            "status": "MEASURED",
            "measured": True,
            "metrics": deepcopy(metrics),
            "budgets": dict(impact.BUDGETS),
            "false_positive_controls_passed": True,
            "user_interruption_budget_passed": True,
            "performance_budget_passed": True,
        },
        [],
    )


def build_trust_center_snapshot(*, impact_report: object | None = None) -> dict[str, Any]:
    foundation_ok, foundation_failures = _accepted_foundation_ok()
    impact_view, impact_failures = _impact_projection(impact_report)
    failures = [*foundation_failures, *impact_failures]

    scenarios = [deepcopy(item) for item in SCENARIOS]
    coverage = {key: sum(1 for item in scenarios if item["status"] == key) for key in ("PARTIAL", "GAP", "VERIFIED")}
    if coverage != CURRENT_COVERAGE:
        failures.append("trust_center:coverage_projection_invalid")
    verified_ids = tuple(item["scenario_id"] for item in scenarios if item["status"] == "VERIFIED")
    if verified_ids != VERIFIED_SCENARIOS:
        failures.append("trust_center:verified_set_invalid")

    snapshot = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": foundation_ok and not failures,
        "failures": list(dict.fromkeys(failures)),
        "source_predecessor_branch": SOURCE_PREDECESSOR_BRANCH,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "source_predecessor_checkpoint": SOURCE_PREDECESSOR_CHECKPOINT,
        "headline": "Trust Center",
        "summary": "Stato verificabile di protezione, limiti, privacy e risposta di BC Sentinel.",
        "coverage_summary": coverage,
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "scenarios": scenarios,
        "capabilities": [deepcopy(item) for item in CAPABILITIES],
        "incident_story": {
            "status": "NO_INCIDENT_LOADED",
            "observed_stages_claimed": 0,
            "unknown_stages_preserved": True,
            "invented_entry_point": False,
        },
        "response": {
            "planning_available": True,
            "general_execution_available": False,
            "automatic_remediation": False,
            "reversible_pilot_available": True,
            "reversible_pilot_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
            "explicit_confirmation_required": True,
            "target_identity_binding_required": True,
            "journal_required": True,
            "rollback_required": True,
        },
        "rescue_continuity": {
            "available": True,
            "integrity_bound": True,
            "local_first": True,
            "execution_implied": False,
        },
        "operational_impact": impact_view,
        "privacy": dict(PRIVACY_BOUNDARY),
        "authority": dict(AUTHORITY_BOUNDARY),
        "broad_protection_claimed": False,
        "coverage_promoted_by_presentation": False,
        "remediation_performed": False,
        "system_mutation_performed": False,
    }
    return snapshot


def validate_snapshot(snapshot: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(snapshot, dict):
        return {"passed": False, "failures": ["snapshot:not_object"]}
    if snapshot.get("schema") != SCHEMA or snapshot.get("profile") != PROFILE:
        failures.append("snapshot:identity_invalid")
    if snapshot.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("snapshot:coverage_invalid")
    if tuple(snapshot.get("verified_scenarios") or []) != VERIFIED_SCENARIOS:
        failures.append("snapshot:verified_set_invalid")
    scenarios = snapshot.get("scenarios")
    if not isinstance(scenarios, list) or scenarios != [dict(item) for item in SCENARIOS]:
        failures.append("snapshot:scenario_facts_changed")
    capabilities = snapshot.get("capabilities")
    if not isinstance(capabilities, list) or capabilities != [dict(item) for item in CAPABILITIES]:
        failures.append("snapshot:capabilities_changed")
    if snapshot.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("snapshot:privacy_changed")
    if snapshot.get("authority") != AUTHORITY_BOUNDARY:
        failures.append("snapshot:authority_changed")
    if snapshot.get("broad_protection_claimed") is not False:
        failures.append("snapshot:broad_protection_claimed")
    if snapshot.get("coverage_promoted_by_presentation") is not False:
        failures.append("snapshot:presentation_promoted_coverage")
    if snapshot.get("remediation_performed") is not False or snapshot.get("system_mutation_performed") is not False:
        failures.append("snapshot:unexpected_execution")
    response = snapshot.get("response")
    if not isinstance(response, dict):
        failures.append("snapshot:response_missing")
    else:
        expected_response = {
            "planning_available": True,
            "general_execution_available": False,
            "automatic_remediation": False,
            "reversible_pilot_available": True,
            "reversible_pilot_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
            "explicit_confirmation_required": True,
            "target_identity_binding_required": True,
            "journal_required": True,
            "rollback_required": True,
        }
        if response != expected_response:
            failures.append("snapshot:response_boundary_changed")
    return {"passed": not failures, "failures": failures}


def validate_b108_contract() -> dict[str, Any]:
    snapshot = build_trust_center_snapshot()
    validation = validate_snapshot(snapshot)
    foundation_ok, foundation_failures = _accepted_foundation_ok()
    failures = [*foundation_failures, *validation["failures"]]
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": foundation_ok and validation["passed"] and not failures,
        "failures": list(dict.fromkeys(failures)),
        "source_predecessor_branch": SOURCE_PREDECESSOR_BRANCH,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "source_predecessor_checkpoint": SOURCE_PREDECESSOR_CHECKPOINT,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "scenario_count": len(SCENARIOS),
        "capability_count": len(CAPABILITIES),
        "trust_center_ui_read_only": True,
        "presentation_can_promote_coverage": False,
        "attack_story_requires_evidence": True,
        "general_response_execution_available": False,
        "reversible_response_pilot_available": True,
        "reversible_response_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
        "new_authority_expanded": False,
        "broad_protection_claimed": False,
        "privacy": dict(PRIVACY_BOUNDARY),
        "authority": dict(AUTHORITY_BOUNDARY),
    }
