from __future__ import annotations

"""B8-4 deterministic coverage recomputation from accepted detector evidence."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import (
    beta8_coverage_baseline,
    credential_access_detector,
    defense_evasion_detector,
    ransomware_detector,
)

SCHEMA: Final[str] = "bc-sentinel-beta8-coverage-verification-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b84-coverage-verification"
EXPECTED_ORDER: Final[tuple[str, ...]] = beta8_coverage_baseline.EXPECTED_ORDER
EXPECTED_SUMMARY: Final[dict[str, int]] = {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}

ACCEPTED_DETECTORS: Final[dict[str, dict[str, str]]] = {
    "B7-RANSOMWARE-001": {
        "checkpoint": "checkpoint/v011-beta8-b81-pass",
        "commit": "5d25da3fcb8cd67d9faefbf2440eda19a6086eba",
    },
    "B7-DEFENSE-EVASION-001": {
        "checkpoint": "checkpoint/v011-beta8-b82-pass",
        "commit": "a4f4b53bf2ea2dcd00744438c716a18ef5287262",
    },
    "B7-CREDENTIAL-001": {
        "checkpoint": "checkpoint/v011-beta8-b83-pass",
        "commit": "ccb182f4869ec9ee050e86269a8a9b7269f9dbbf",
    },
}

FALSE_AUTHORITY_FIELDS: Final[tuple[str, ...]] = (
    "process_execution",
    "file_write",
    "network_io",
    "registry_mutation",
    "credential_access",
    "remediation_execution",
    "automatic_quarantine",
    "automatic_repair",
    "automatic_restore",
    "general_home_execution_authorized",
    "delete_authorized",
    "repair_authorized",
    "terminate_process_authorized",
    "trust_allowlist_mutation_authorized",
    "privileged_system_mutation_authorized",
    "authority_granted",
    "execution_authority_added",
)


def default_report_path() -> Path:
    return Path(__file__).resolve().parent.parent / "coverage" / "beta8_coverage_verification.json"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def load_report(path: str | Path | None = None) -> dict[str, Any]:
    source = Path(path) if path is not None else default_report_path()
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("b84_report_not_object")
    return payload


def collect_detector_evidence() -> dict[str, dict[str, Any]]:
    return {
        "B7-RANSOMWARE-001": ransomware_detector.self_check(),
        "B7-DEFENSE-EVASION-001": defense_evasion_detector.self_check(),
        "B7-CREDENTIAL-001": credential_access_detector.self_check(),
    }


def recompute(
    baseline: dict[str, Any] | None = None,
    detector_evidence: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    baseline = baseline if baseline is not None else beta8_coverage_baseline.load_baseline()
    evidence = detector_evidence if detector_evidence is not None else collect_detector_evidence()
    failures: list[str] = []

    baseline_validation = beta8_coverage_baseline.validate_baseline(baseline)
    if not baseline_validation.passed:
        failures.extend(f"baseline:{item}" for item in baseline_validation.failures)

    accepted: dict[str, dict[str, str]] = {}
    for scenario_id, binding in ACCEPTED_DETECTORS.items():
        item = evidence.get(scenario_id)
        if not isinstance(item, dict):
            failures.append(f"{scenario_id}:evidence_missing")
            continue
        required = {
            "passed": True,
            "target_scenario_id": scenario_id,
            "coverage_status": "PARTIAL",
            "positive_outcome": "DETECTED",
            "synthetic_fixture_only": True,
            "deterministic_serialization": True,
            "stable_round_trip": True,
            "evidence_ids_preserved": True,
        }
        for field, expected in required.items():
            if item.get(field) != expected:
                failures.append(f"{scenario_id}:{field}_invalid")
        for field in FALSE_AUTHORITY_FIELDS:
            if item.get(field) is not False:
                failures.append(f"{scenario_id}:{field}_must_be_false")
        accepted[scenario_id] = {
            **binding,
            "detector_digest": str(item.get("detector_digest") or ""),
            "graph_digest": str(item.get("graph_digest") or ""),
            "correlation_digest": str(item.get("correlation_digest") or ""),
        }

    scenarios: list[dict[str, str]] = []
    for item in baseline.get("scenarios") or []:
        if not isinstance(item, dict):
            continue
        scenario_id = str(item.get("scenario_id") or "")
        if scenario_id in ACCEPTED_DETECTORS:
            status = "PARTIAL" if scenario_id in accepted else "GAP"
            basis = "ACCEPTED_SYNTHETIC_DETECTOR" if status == "PARTIAL" else "EVIDENCE_MISSING"
        else:
            status = str(item.get("status") or "GAP").upper()
            basis = "ACCEPTED_BETA7_PARTIAL" if status == "PARTIAL" else "BASELINE_GAP"
        scenarios.append({"scenario_id": scenario_id, "status": status, "evidence_basis": basis})

    summary = {"PARTIAL": 0, "GAP": 0, "VERIFIED": 0}
    for item in scenarios:
        status = item["status"]
        if status in summary:
            summary[status] += 1
        else:
            failures.append(f"{item['scenario_id']}:status_invalid")
    if any(item["status"] == "VERIFIED" for item in scenarios):
        failures.append("synthetic_evidence_promoted_to_verified")

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_baseline_checkpoint": "checkpoint/v011-beta8-b80-pass",
        "source_baseline_commit": "969781bd7633d0b2bc92840e8f12220f00de4279",
        "accepted_detector_checkpoints": accepted,
        "summary": summary,
        "scenarios": scenarios,
        "failures": failures,
    }


def validate_report(report: dict[str, Any], live: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in (
        "schema",
        "profile",
        "source_baseline_checkpoint",
        "source_baseline_commit",
        "accepted_detector_checkpoints",
        "summary",
        "scenarios",
    ):
        if report.get(field) != live.get(field):
            failures.append(f"report:{field}_mismatch")
    if report.get("summary") != EXPECTED_SUMMARY:
        failures.append("report:summary_invalid")
    order = tuple(
        item.get("scenario_id") for item in report.get("scenarios", [])
        if isinstance(item, dict)
    )
    if order != EXPECTED_ORDER:
        failures.append("report:scenario_order_invalid")
    if report.get("read_only") is not True:
        failures.append("report:read_only_required")
    if report.get("synthetic_evidence_cannot_verify") is not True:
        failures.append("report:synthetic_verification_guard_required")
    if report.get("unsupported_positive_claims_allowed") is not False:
        failures.append("report:unsupported_claims_must_be_false")
    for field in FALSE_AUTHORITY_FIELDS:
        if report.get(field) is not False:
            failures.append(f"report:{field}_must_be_false")
    return failures


def self_check(path: str | Path | None = None) -> dict[str, Any]:
    report = load_report(path)
    first = recompute()
    second = recompute()
    failures = list(first["failures"])
    failures.extend(validate_report(report, first))
    deterministic = _canonical_json(first) == _canonical_json(second)
    if not deterministic:
        failures.append("recomputation_not_deterministic")
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "summary": first["summary"],
        "scenario_count": len(first["scenarios"]),
        "accepted_detector_count": len(first["accepted_detector_checkpoints"]),
        "report_digest": _digest(report),
        "deterministic_recomputation": deterministic,
        "read_only": report.get("read_only"),
        "synthetic_evidence_cannot_verify": report.get("synthetic_evidence_cannot_verify"),
        "unsupported_positive_claims_allowed": report.get("unsupported_positive_claims_allowed"),
        **{field: report.get(field) for field in FALSE_AUTHORITY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta8 B8-4 coverage verification")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--path", default=None)
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check(args.path)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
