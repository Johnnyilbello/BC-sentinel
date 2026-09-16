from __future__ import annotations

"""B10-1 Sentinel Proof Mode.

Expose exactly what BC Sentinel has proven, what remains partial, and why. The
module may attach a fresh harmless B9-3 ransomware proof, but presentation alone
can never promote coverage. No remediation or execution authority is added.
"""

import argparse
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from sentinel import beta9_ransomware_controls

SCHEMA: Final[str] = "bc-sentinel-beta10-proof-mode-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b101-sentinel-proof-mode"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b100-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "8f9b315eb3137f461dce1f679af32d8a9d680990"
BASELINE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
TARGET_SCENARIO: Final[str] = "B7-RANSOMWARE-001"

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "remote_access": False,
}

SCENARIOS: Final[tuple[dict[str, str], ...]] = (
    {
        "scenario_id": "B7-POWERSHELL-001",
        "label": "PowerShell",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "accepted_checkpoint": "checkpoint/v011-beta9-b94-pass",
        "proof_capability": "NOT_YET_AVAILABLE",
        "limitation": "No accepted live positive threat-detector path without reading script or command payload data.",
    },
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "label": "Persistence",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "accepted_checkpoint": "checkpoint/v011-beta9-b94-pass",
        "proof_capability": "NOT_YET_AVAILABLE",
        "limitation": "No accepted live persistence detector source is wired to a harmless positive control.",
    },
    {
        "scenario_id": TARGET_SCENARIO,
        "label": "Ransomware-like behavior",
        "status": "VERIFIED",
        "evidence_basis": "CONTROLLED_LIVE_LOCAL_DETECTOR_PATH",
        "accepted_checkpoint": "checkpoint/v011-beta9-b93-pass",
        "proof_capability": "SAFE_ON_DEMAND_LOCAL_CONTROL",
        "limitation": "Scenario-specific controlled local detector-path verification; not a claim of broad ransomware-family coverage.",
    },
    {
        "scenario_id": "B7-DEFENSE-EVASION-001",
        "label": "Defense evasion / tamper",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "accepted_checkpoint": "checkpoint/v011-beta9-b94-pass",
        "proof_capability": "NOT_YET_AVAILABLE",
        "limitation": "Positive live control would require security-control mutation outside the current authority boundary.",
    },
    {
        "scenario_id": "B7-C2-DNS-001",
        "label": "DNS / C2 indicators",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "accepted_checkpoint": "checkpoint/v011-beta9-b94-pass",
        "proof_capability": "NOT_YET_AVAILABLE",
        "limitation": "No accepted live DNS threat-detector path is available without enabling network test authority.",
    },
    {
        "scenario_id": "B7-CREDENTIAL-001",
        "label": "Credential-access indicators",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "accepted_checkpoint": "checkpoint/v011-beta9-b94-pass",
        "proof_capability": "NOT_YET_AVAILABLE",
        "limitation": "Positive live credential-access control would require sensitive access prohibited by the privacy boundary.",
    },
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def baseline_report() -> dict[str, Any]:
    scenarios = []
    for item in SCENARIOS:
        row: dict[str, Any] = dict(item)
        row.update(
            {
                "fresh_proof": False,
                "proof_outcome": None,
                "proof_evidence_id": None,
                "proof_details": None,
            }
        )
        scenarios.append(row)
    core = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "coverage_summary": dict(BASELINE_COVERAGE),
        "verified_scenario_id": TARGET_SCENARIO,
        "scenarios": scenarios,
        "current_machine_proof_performed": False,
        "broad_protection_claimed": False,
        "synthetic_fallback_used": False,
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "privacy": {
            "local_only": True,
            "user_file_access": False,
            "file_content_collected": False,
            "absolute_paths_exported": False,
            "personal_data_collected": False,
            "remote_access": False,
        },
    }
    core["report_digest"] = _digest(core)
    return core


def _validate_baseline_shape(report: object) -> tuple[str, ...]:
    if not isinstance(report, dict):
        return ("proof:not_object",)
    failures: list[str] = []
    if report.get("schema") != SCHEMA or report.get("profile") != PROFILE:
        failures.append("proof:schema_or_profile_invalid")
    if report.get("source_checkpoint") != SOURCE_CHECKPOINT or report.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("proof:source_checkpoint_invalid")
    if report.get("coverage_summary") != BASELINE_COVERAGE or report.get("verified_scenario_id") != TARGET_SCENARIO:
        failures.append("proof:coverage_baseline_invalid")
    if report.get("broad_protection_claimed") is not False or report.get("synthetic_fallback_used") is not False:
        failures.append("proof:claim_boundary_invalid")
    if report.get("authority_boundary") != AUTHORITY_BOUNDARY or any(AUTHORITY_BOUNDARY.values()):
        failures.append("proof:authority_boundary_invalid")
    privacy = report.get("privacy")
    if not isinstance(privacy, dict) or privacy != {
        "local_only": True,
        "user_file_access": False,
        "file_content_collected": False,
        "absolute_paths_exported": False,
        "personal_data_collected": False,
        "remote_access": False,
    }:
        failures.append("proof:privacy_boundary_invalid")
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 6:
        failures.append("proof:scenario_count_invalid")
        return tuple(failures)
    expected_ids = [item["scenario_id"] for item in SCENARIOS]
    if [row.get("scenario_id") for row in scenarios if isinstance(row, dict)] != expected_ids:
        failures.append("proof:scenario_order_invalid")
    for expected, row in zip(SCENARIOS, scenarios):
        if not isinstance(row, dict):
            failures.append("proof:scenario_not_object")
            continue
        for key in ("scenario_id", "label", "status", "evidence_basis", "accepted_checkpoint", "proof_capability", "limitation"):
            if row.get(key) != expected[key]:
                failures.append(f"proof:{expected['scenario_id']}:accepted_fact_changed")
        if not isinstance(row.get("limitation"), str) or not row["limitation"]:
            failures.append(f"proof:{expected['scenario_id']}:limitation_missing")
    verified = [row for row in scenarios if isinstance(row, dict) and row.get("status") == "VERIFIED"]
    if len(verified) != 1 or verified[0].get("scenario_id") != TARGET_SCENARIO:
        failures.append("proof:verified_set_invalid")
    return tuple(failures)


def attach_fresh_ransomware_proof(
    report: object,
    evidence: object,
    *,
    proof_started_after_utc: str,
) -> dict[str, Any]:
    failures = list(_validate_baseline_shape(report))
    threshold = _parse_utc(proof_started_after_utc)
    if threshold is None:
        failures.append("proof:freshness_threshold_invalid")
    evidence_failures = beta9_ransomware_controls.validate_evidence(evidence)
    failures.extend(f"b93:{failure}" for failure in evidence_failures)
    if failures:
        return {"passed": False, "failures": failures}
    assert isinstance(report, dict)
    assert isinstance(evidence, dict)
    assert threshold is not None

    controls = evidence.get("controls")
    assert isinstance(controls, list)
    for row in controls:
        if not isinstance(row, dict):
            return {"passed": False, "failures": ["proof:control_invalid"]}
        started = _parse_utc(row.get("started_at_utc"))
        if started is None or started < threshold:
            return {"passed": False, "failures": ["proof:stale_or_replayed_evidence"]}

    b93 = beta9_ransomware_controls.summarize(evidence)
    if not b93.get("passed"):
        return {"passed": False, "failures": ["proof:b93_live_control_not_accepted"]}
    if b93.get("coverage_summary") != BASELINE_COVERAGE:
        return {"passed": False, "failures": ["proof:coverage_changed_by_proof"]}
    if b93.get("target_scenario_id") != TARGET_SCENARIO:
        return {"passed": False, "failures": ["proof:target_scenario_mismatch"]}
    if b93.get("synthetic_fallback_used") is not False or b93.get("broad_ransomware_protection_claimed") is not False:
        return {"passed": False, "failures": ["proof:claim_boundary_changed"]}

    result = copy.deepcopy(report)
    result.pop("report_digest", None)
    scenarios = result["scenarios"]
    for row in scenarios:
        if row["scenario_id"] == TARGET_SCENARIO:
            row["fresh_proof"] = True
            row["proof_outcome"] = "DETECTED"
            row["proof_evidence_id"] = b93.get("positive_evidence_id")
            row["proof_details"] = {
                "control_outcomes": dict(b93.get("control_outcomes") or {}),
                "positive_score": b93.get("positive_score"),
                "matched_signals": list(b93.get("positive_matched_signals") or []),
                "detector_to_security_graph_bound": bool(b93.get("detector_to_security_graph_bound")),
                "security_graph_to_incident_bound": bool(b93.get("security_graph_to_incident_bound")),
                "graph_digest": b93.get("graph_digest"),
                "correlation_digest": b93.get("correlation_digest"),
            }
    result["current_machine_proof_performed"] = True
    result["report_digest"] = _digest(result)
    post_failures = _validate_baseline_shape(result)
    if post_failures:
        return {"passed": False, "failures": list(post_failures)}
    result["passed"] = True
    result["failures"] = []
    return result


def proof_summary(report: object) -> dict[str, Any]:
    failures = _validate_baseline_shape(report)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(report, dict)
    scenarios = report["scenarios"]
    return {
        "passed": True,
        "coverage_summary": dict(report["coverage_summary"]),
        "verified_scenario_id": report["verified_scenario_id"],
        "verified_count": sum(1 for row in scenarios if row["status"] == "VERIFIED"),
        "scenario_count": len(scenarios),
        "fresh_proof_count": sum(1 for row in scenarios if row.get("fresh_proof") is True),
        "current_machine_proof_performed": bool(report.get("current_machine_proof_performed")),
        "broad_protection_claimed": bool(report.get("broad_protection_claimed")),
        "authority_expanded": any(report["authority_boundary"].values()),
        "proof_capable_scenarios": [row["scenario_id"] for row in scenarios if row["proof_capability"] == "SAFE_ON_DEMAND_LOCAL_CONTROL"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--proof-started-after-utc")
    args = parser.parse_args()
    report = baseline_report()
    if args.evidence is not None:
        if not args.proof_started_after_utc:
            result: dict[str, Any] = {"passed": False, "failures": ["proof:freshness_threshold_required"]}
        else:
            try:
                evidence = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, ValueError):
                result = {"passed": False, "failures": ["proof:evidence_unreadable_or_invalid_json"]}
            else:
                result = attach_fresh_ransomware_proof(
                    report,
                    evidence,
                    proof_started_after_utc=args.proof_started_after_utc,
                )
    else:
        result = report
        result["passed"] = not _validate_baseline_shape(result)
        result["failures"] = list(_validate_baseline_shape(result))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
