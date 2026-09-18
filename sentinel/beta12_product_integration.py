from __future__ import annotations

"""B12-8 Verified Coverage Expansion & Product Integration.

Projects the accepted Beta12 evidence into one read-only product snapshot.
Coverage is reconciled from accepted milestones only; the presentation layer
cannot promote scenarios, mutate trust, execute remediation, or broaden claims.
"""

from copy import deepcopy
import hashlib
import json
from typing import Any, Final

from sentinel import beta12_low_noise_performance as b127

SCHEMA: Final[str] = "bc-sentinel-beta12-product-trust-center-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b128-verified-coverage-product-integration"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b127-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "8e5614c919611a7b072dd0a4f462c56751ba331d"

CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
    "B12-RANSOMWARE-PROCESS-001",
    "B12-LOCAL-REPUTATION-001",
)

SCENARIOS: Final[tuple[dict[str, str], ...]] = (
    {
        "scenario_id": "B7-POWERSHELL-001",
        "label": "PowerShell lifecycle metadata",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B10_METADATA_LIFECYCLE_BURST_CONTROL",
        "limitation": "Metadata-only lifecycle burst; non equivale a copertura generale di tutti gli abusi PowerShell.",
    },
    {
        "scenario_id": "B7-RANSOMWARE-001",
        "label": "Ransomware-like behavior",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B9_CONTROLLED_LOCAL_RANSOMWARE_LIKE_PATH",
        "limitation": "Scenario locale controllato; non dimostra copertura universale di tutte le famiglie ransomware.",
    },
    {
        "scenario_id": "B12-SCRIPT-ABUSE-001",
        "label": "Script abuse expansion",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_2_LIVE_WINDOWS_SCRIPT_MUTATION_PATH",
        "limitation": "Burst innocuo in workspace temporaneo; nessuna ispezione del contenuto script o command line.",
    },
    {
        "scenario_id": "B12-AUTOSTART-LINK-001",
        "label": "Autostart shortcut pattern",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_3_LIVE_WINDOWS_SHORTCUT_PATTERN",
        "limitation": "Pattern shortcut in workspace temporaneo; nessuna reale Startup folder o Run key viene modificata.",
    },
    {
        "scenario_id": "B12-PROCESS-TREE-001",
        "label": "Suspicious process tree",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_4_LIVE_WINDOWS_PROCESS_TREE",
        "limitation": "Catena parent-child-grandchild limitata e controllata; non è una copertura generale di tutti i process tree.",
    },
    {
        "scenario_id": "B12-RANSOMWARE-PROCESS-001",
        "label": "Ransomware process attribution",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_5_PROCESS_ATTRIBUTION",
        "limitation": "Attribuzione del processo sul controllo live B9 già accettato; nessun nuovo simulatore ransomware.",
    },
    {
        "scenario_id": "B12-LOCAL-REPUTATION-001",
        "label": "Local reputation",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_6_LOCAL_HASH_SIGNER_ALLOWLIST",
        "limitation": "Classificazione locale hash+signer+allowlist; nessun verdetto cloud o giudizio di malware su file sconosciuti.",
    },
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "label": "Persistence",
        "status": "PARTIAL",
        "evidence_basis": "NO_REAL_PERSISTENCE_SURFACE_MUTATION",
        "limitation": "L'esecuzione reale di persistenza resta non verificata.",
    },
    {
        "scenario_id": "B7-DEFENSE-EVASION-001",
        "label": "Defense evasion / tamper",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_SAFE_LIVE_POSITIVE_CONTROL",
        "limitation": "Non vengono alterati controlli di sicurezza protetti per creare un test positivo.",
    },
    {
        "scenario_id": "B7-C2-DNS-001",
        "label": "DNS / C2",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_NETWORK_CONTROL",
        "limitation": "L'acceptance core resta network-free e non esercita un C2 live.",
    },
    {
        "scenario_id": "B7-CREDENTIAL-001",
        "label": "Credential access",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_SENSITIVE_ACCESS_CONTROL",
        "limitation": "L'accesso a credenziali reali resta proibito dal confine privacy.",
    },
)

CAPABILITIES: Final[tuple[dict[str, Any], ...]] = (
    {
        "capability_id": "ACTIVE_PROTECTION_EVIDENCE",
        "label": "Active Protection Evidence",
        "status": "AVAILABLE",
        "summary": "Riconcilia i percorsi Windows verificati Beta12 senza promuovere scenari dalla UI.",
        "execution_authority": False,
    },
    {
        "capability_id": "PROCESS_FILE_CORRELATION",
        "label": "Process / File Correlation",
        "status": "AVAILABLE",
        "summary": "Collega processi, file ed evidenza con ancestry opzionale e provenienza verificabile.",
        "execution_authority": False,
    },
    {
        "capability_id": "PROCESS_TREE_INTELLIGENCE",
        "label": "Process Tree Intelligence",
        "status": "AVAILABLE",
        "summary": "Distingue la catena sospetta controllata da attività amministrativa e benigna.",
        "execution_authority": False,
    },
    {
        "capability_id": "RANSOMWARE_PROCESS_ATTRIBUTION",
        "label": "Ransomware Attribution",
        "status": "AVAILABLE",
        "summary": "Lega il comportamento ransomware-like accettato al processo osservato e all'incident graph.",
        "execution_authority": False,
    },
    {
        "capability_id": "LOCAL_REPUTATION",
        "label": "Local Reputation",
        "status": "AVAILABLE",
        "summary": "Usa SHA-256, firma Authenticode e allowlist locale esplicita senza lookup cloud obbligatori.",
        "execution_authority": False,
    },
    {
        "capability_id": "LOW_NOISE_GATE",
        "label": "Low-Noise Gate",
        "status": "MEASURED",
        "summary": "Verifica stabilità outcome, falsi positivi, latenza, CPU, RAM e interruzioni utente.",
        "execution_authority": False,
    },
    {
        "capability_id": "SAFE_RESPONSE_BOUNDARY",
        "label": "Safe Response Boundary",
        "status": "PLANNING_ONLY",
        "summary": "Nessuna remediation automatica generale; resta valido solo il precedente pilot reversibile confinato.",
        "execution_authority": False,
    },
)

PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_exported": False,
    "raw_paths_exported": False,
    "command_lines_exported": False,
    "credential_access": False,
    "network_io": False,
    "cloud_required": False,
}

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "new_authority_expanded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "general_home_execution": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _foundation_status() -> tuple[bool, list[str]]:
    report = b127.self_check()
    failures: list[str] = []
    if report.get("passed") is not True:
        failures.append("foundation:b127_self_check_failed")
    if report.get("source_checkpoint_commit") != "b1f55ea32564d72cae6056308f90f8b41137dc94":
        failures.append("foundation:b127_source_identity_invalid")
    if report.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("foundation:b127_coverage_mismatch")
    if report.get("coverage_promoted_by_self_check") is not False:
        failures.append("foundation:b127_unexpected_promotion")
    return not failures, failures


def _impact_projection(report: object | None) -> tuple[dict[str, Any], list[str]]:
    if report is None:
        return (
            {
                "status": "NOT_LOADED",
                "measured": False,
                "metrics": None,
                "budgets": dict(b127.BUDGETS),
                "false_positive_gate_passed": None,
                "outcome_stability_gate_passed": None,
                "performance_gate_passed": None,
                "user_interruption_gate_passed": None,
            },
            [],
        )
    if not isinstance(report, dict):
        return (
            {"status": "INVALID", "measured": False, "metrics": None, "budgets": dict(b127.BUDGETS)},
            ["impact:not_object"],
        )

    failures: list[str] = []
    if report.get("schema") != b127.SCHEMA or report.get("profile") != b127.PROFILE:
        failures.append("impact:identity_invalid")
    if report.get("passed") is not True:
        failures.append("impact:not_passed")
    if report.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("impact:coverage_changed")
    if report.get("coverage_promoted") is not False:
        failures.append("impact:coverage_promoted")
    for field in (
        "false_positive_gate_passed",
        "outcome_stability_gate_passed",
        "performance_gate_passed",
        "user_interruption_gate_passed",
    ):
        if report.get(field) is not True:
            failures.append(f"impact:{field}_failed")
    metrics = report.get("operational_metrics")
    if not isinstance(metrics, dict):
        failures.append("impact:metrics_missing")
    if failures:
        return (
            {"status": "INVALID", "measured": False, "metrics": None, "budgets": dict(b127.BUDGETS)},
            failures,
        )
    return (
        {
            "status": "MEASURED",
            "measured": True,
            "metrics": deepcopy(metrics),
            "budgets": dict(b127.BUDGETS),
            "false_positive_gate_passed": True,
            "outcome_stability_gate_passed": True,
            "performance_gate_passed": True,
            "user_interruption_gate_passed": True,
        },
        [],
    )


def build_product_snapshot(*, impact_report: object | None = None) -> dict[str, Any]:
    foundation_ok, foundation_failures = _foundation_status()
    impact_view, impact_failures = _impact_projection(impact_report)
    failures = [*foundation_failures, *impact_failures]

    scenarios = [deepcopy(item) for item in SCENARIOS]
    coverage = {
        key: sum(1 for item in scenarios if item["status"] == key)
        for key in ("PARTIAL", "GAP", "VERIFIED")
    }
    if coverage != CURRENT_COVERAGE:
        failures.append("snapshot:coverage_projection_invalid")
    verified = tuple(item["scenario_id"] for item in scenarios if item["status"] == "VERIFIED")
    if verified != VERIFIED_SCENARIOS:
        failures.append("snapshot:verified_set_invalid")

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": foundation_ok and not failures,
        "failures": list(dict.fromkeys(failures)),
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "headline": "Trust Center · Active Protection",
        "summary": "Stato verificabile della protezione Beta12, dei limiti e dell'impatto operativo.",
        "coverage_summary": coverage,
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "scenarios": scenarios,
        "capabilities": [deepcopy(item) for item in CAPABILITIES],
        "operational_impact": impact_view,
        "privacy": dict(PRIVACY_BOUNDARY),
        "authority": dict(AUTHORITY_BOUNDARY),
        "product_ui_read_only": True,
        "coverage_promoted_by_presentation": False,
        "broad_protection_claimed": False,
        "automatic_remediation_claimed": False,
        "maliciousness_verdict_for_unknown_files_claimed": False,
        "trust_allowlist_mutated": False,
        "remediation_performed": False,
        "system_mutation_performed": False,
    }


def validate_snapshot(snapshot: object) -> dict[str, Any]:
    failures: list[str] = []
    if not isinstance(snapshot, dict):
        return {"passed": False, "failures": ["snapshot:not_object"]}
    if snapshot.get("schema") != SCHEMA or snapshot.get("profile") != PROFILE:
        failures.append("snapshot:identity_invalid")
    if snapshot.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("snapshot:checkpoint_invalid")
    if snapshot.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("snapshot:checkpoint_commit_invalid")
    if snapshot.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("snapshot:coverage_invalid")
    if tuple(snapshot.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("snapshot:verified_set_invalid")
    if snapshot.get("scenarios") != [dict(item) for item in SCENARIOS]:
        failures.append("snapshot:scenario_facts_changed")
    if snapshot.get("capabilities") != [dict(item) for item in CAPABILITIES]:
        failures.append("snapshot:capabilities_changed")
    if snapshot.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("snapshot:privacy_changed")
    if snapshot.get("authority") != AUTHORITY_BOUNDARY:
        failures.append("snapshot:authority_changed")
    for field in (
        "coverage_promoted_by_presentation",
        "broad_protection_claimed",
        "automatic_remediation_claimed",
        "maliciousness_verdict_for_unknown_files_claimed",
        "trust_allowlist_mutated",
        "remediation_performed",
        "system_mutation_performed",
    ):
        if snapshot.get(field) is not False:
            failures.append(f"snapshot:{field}_invalid")
    if snapshot.get("product_ui_read_only") is not True:
        failures.append("snapshot:ui_not_read_only")
    impact = snapshot.get("operational_impact")
    if not isinstance(impact, dict) or impact.get("status") not in {"NOT_LOADED", "MEASURED"}:
        failures.append("snapshot:impact_invalid")
    return {"passed": not failures, "failures": list(dict.fromkeys(failures))}


def self_check() -> dict[str, Any]:
    snapshot = build_product_snapshot()
    validation = validate_snapshot(snapshot)
    contract = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "coverage": CURRENT_COVERAGE,
        "verified_scenarios": VERIFIED_SCENARIOS,
        "scenario_count": len(SCENARIOS),
        "capability_count": len(CAPABILITIES),
        "privacy": PRIVACY_BOUNDARY,
        "authority": AUTHORITY_BOUNDARY,
    }
    return {
        "passed": snapshot.get("passed") is True and validation["passed"],
        "failures": [*snapshot.get("failures", []), *validation["failures"]],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _sha(contract),
        "coverage_summary": dict(CURRENT_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "scenario_count": len(SCENARIOS),
        "capability_count": len(CAPABILITIES),
        "product_ui_read_only": True,
        "coverage_promoted_by_presentation": False,
        "new_verified_scenario_earned": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }
