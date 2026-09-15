from __future__ import annotations

"""B7-0 machine-readable attack coverage ledger.

This module is intentionally read-only. It validates coverage evidence and
prevents unsupported positive claims from being represented as accepted
coverage. It does not execute detectors, remediation, network activity or any
privileged action.
"""

from dataclasses import dataclass
import argparse
import json
from pathlib import Path
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-attack-coverage-ledger-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b70-coverage-ledger"
ALLOWED_STATUS: Final[set[str]] = {"PLANNED", "PARTIAL", "VERIFIED", "GAP"}
ALLOWED_FP_STATUS: Final[set[str]] = {
    "NOT_EVALUATED",
    "PASS",
    "FAIL",
    "ACCEPTED_RISK",
}
ALLOWED_EVIDENCE_QUALITY: Final[set[str]] = {"NONE", "LOW", "MEDIUM", "HIGH"}
CLAIM_FIELDS: Final[tuple[str, ...]] = (
    "detected",
    "correlated",
    "blocked",
    "recovered",
    "verified",
)
REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "scenario_id",
    "technique",
    "subtechnique",
    "scenario",
    "verification_status",
    "detected",
    "correlated",
    "blocked",
    "recovered",
    "verified",
    "false_positive_status",
    "time_to_detection",
    "time_to_interruption",
    "evidence_quality",
    "evidence_refs",
    "last_verified_build",
    "platform_profile",
    "notes",
)


@dataclass(frozen=True)
class LedgerValidation:
    passed: bool
    failures: tuple[str, ...]
    scenario_count: int
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "scenario_count": self.scenario_count,
            "summary": dict(self.summary),
            "read_only": True,
            "execution_authority_added": False,
        }


def _is_bool_or_none(value: Any) -> bool:
    return value is None or isinstance(value, bool)


def _validate_scenario(item: Any, index: int) -> list[str]:
    failures: list[str] = []
    prefix = f"scenario[{index}]"
    if not isinstance(item, dict):
        return [f"{prefix}:not_object"]

    missing = [field for field in REQUIRED_FIELDS if field not in item]
    failures.extend(f"{prefix}:missing:{field}" for field in missing)
    if missing:
        return failures

    scenario_id = str(item.get("scenario_id") or "").strip()
    if not scenario_id:
        failures.append(f"{prefix}:scenario_id_empty")

    scenario = str(item.get("scenario") or "").strip()
    if not scenario:
        failures.append(f"{prefix}:scenario_empty")

    status = str(item.get("verification_status") or "").strip().upper()
    if status not in ALLOWED_STATUS:
        failures.append(f"{prefix}:verification_status_invalid")

    for field in CLAIM_FIELDS:
        if not _is_bool_or_none(item.get(field)):
            failures.append(f"{prefix}:{field}_must_be_bool_or_null")

    fp_status = str(item.get("false_positive_status") or "").strip().upper()
    if fp_status not in ALLOWED_FP_STATUS:
        failures.append(f"{prefix}:false_positive_status_invalid")

    evidence_quality = str(item.get("evidence_quality") or "").strip().upper()
    if evidence_quality not in ALLOWED_EVIDENCE_QUALITY:
        failures.append(f"{prefix}:evidence_quality_invalid")

    evidence_refs = item.get("evidence_refs")
    if not isinstance(evidence_refs, list) or any(
        not isinstance(ref, str) or not ref.strip() for ref in evidence_refs
    ):
        failures.append(f"{prefix}:evidence_refs_invalid")
        evidence_refs = []

    for timing_field in ("time_to_detection", "time_to_interruption"):
        timing = item.get(timing_field)
        if timing is not None and (
            isinstance(timing, bool) or not isinstance(timing, (int, float)) or timing < 0
        ):
            failures.append(f"{prefix}:{timing_field}_invalid")

    last_verified = item.get("last_verified_build")
    if last_verified is not None and (
        not isinstance(last_verified, str) or not last_verified.strip()
    ):
        failures.append(f"{prefix}:last_verified_build_invalid")

    positive_claim = any(item.get(field) is True for field in CLAIM_FIELDS)
    evaluated_claim = any(item.get(field) is not None for field in CLAIM_FIELDS)

    if positive_claim:
        if not isinstance(last_verified, str) or not last_verified.strip():
            failures.append(f"{prefix}:positive_claim_without_build_provenance")
        if not evidence_refs:
            failures.append(f"{prefix}:positive_claim_without_evidence")
        if evidence_quality in {"", "NONE"}:
            failures.append(f"{prefix}:positive_claim_without_evidence_quality")

    if status == "PLANNED":
        if evaluated_claim:
            failures.append(f"{prefix}:planned_scenario_must_be_unevaluated")
        if evidence_refs:
            failures.append(f"{prefix}:planned_scenario_must_not_claim_evidence")
        if last_verified is not None:
            failures.append(f"{prefix}:planned_scenario_must_not_have_verified_build")
        if evidence_quality != "NONE":
            failures.append(f"{prefix}:planned_scenario_evidence_quality_must_be_none")

    if status in {"PARTIAL", "VERIFIED", "GAP"}:
        if not isinstance(last_verified, str) or not last_verified.strip():
            failures.append(f"{prefix}:{status.lower()}_requires_build_provenance")
        if not evidence_refs:
            failures.append(f"{prefix}:{status.lower()}_requires_evidence")
        if not evaluated_claim:
            failures.append(f"{prefix}:{status.lower()}_requires_evaluated_claim")

    if status == "VERIFIED" and item.get("detected") is not True:
        failures.append(f"{prefix}:verified_requires_detected_true")

    return failures


def validate_ledger(payload: Any) -> LedgerValidation:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return LedgerValidation(False, ("ledger:not_object",), 0, {})

    if payload.get("schema") != SCHEMA:
        failures.append("ledger:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("ledger:profile_mismatch")

    source_checkpoint = str(payload.get("source_checkpoint") or "").strip()
    source_commit = str(payload.get("source_checkpoint_commit") or "").strip()
    if not source_checkpoint:
        failures.append("ledger:source_checkpoint_missing")
    if len(source_commit) != 40:
        failures.append("ledger:source_checkpoint_commit_invalid")

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        return LedgerValidation(
            False,
            tuple(failures + ["ledger:scenarios_not_array"]),
            0,
            {},
        )

    seen: set[str] = set()
    summary = {status: 0 for status in sorted(ALLOWED_STATUS)}
    for index, item in enumerate(scenarios):
        failures.extend(_validate_scenario(item, index))
        if isinstance(item, dict):
            scenario_id = str(item.get("scenario_id") or "").strip()
            if scenario_id:
                if scenario_id in seen:
                    failures.append(f"scenario[{index}]:duplicate_scenario_id:{scenario_id}")
                seen.add(scenario_id)
            status = str(item.get("verification_status") or "").strip().upper()
            if status in summary:
                summary[status] += 1

    return LedgerValidation(
        passed=not failures,
        failures=tuple(failures),
        scenario_count=len(scenarios),
        summary=summary,
    )


def load_ledger(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("coverage_ledger_root_must_be_object")
    return payload


def validate_file(path: str | Path) -> LedgerValidation:
    return validate_ledger(load_ledger(path))


def default_ledger_path() -> Path:
    return Path(__file__).resolve().parents[1] / "coverage" / "attack_coverage_ledger.json"


def self_check() -> dict[str, Any]:
    validation = validate_file(default_ledger_path())
    result = validation.to_dict()
    result.update(
        {
            "default_ledger": str(default_ledger_path()),
            "unsupported_positive_claims_allowed": False,
            "duplicate_ids_allowed": False,
            "untested_success_allowed": False,
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_restore": False,
            "general_home_execution_authorized": False,
        }
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B7-0 coverage ledger validator")
    parser.add_argument("--ledger", default=str(default_ledger_path()))
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)

    result = self_check() if args.self_check else validate_file(args.ledger).to_dict()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") is True else 4


if __name__ == "__main__":
    raise SystemExit(main())
