from __future__ import annotations

"""B8-0 deterministic Beta8 coverage-baseline foundation.

The baseline is a read-only evidence snapshot derived from the immutable Beta7
final checkpoint. It cannot promote coverage, execute a detector, touch system
state, access credentials, or grant remediation authority.
"""

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sentinel import beta7_final_acceptance, coverage_campaign

SCHEMA: Final[str] = "bc-sentinel-beta8-coverage-baseline-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b80-coverage-baseline"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b77-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "4d57f749276c588782147d47078ef4c52d1adc51"
SOURCE_FINAL_CORE_DIGEST: Final[str] = "dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e"
SOURCE_CAMPAIGN_DIGEST: Final[str] = "e85f96cdfd21f85390c18e1e75387508ce2453c10dfc1af782ede16faad9fc17"

EXPECTED_ORDER: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-PERSISTENCE-001",
    "B7-RANSOMWARE-001",
    "B7-DEFENSE-EVASION-001",
    "B7-C2-DNS-001",
    "B7-CREDENTIAL-001",
)
EXPECTED_STATUS: Final[dict[str, str]] = {
    "B7-POWERSHELL-001": "PARTIAL",
    "B7-PERSISTENCE-001": "PARTIAL",
    "B7-RANSOMWARE-001": "GAP",
    "B7-DEFENSE-EVASION-001": "GAP",
    "B7-C2-DNS-001": "PARTIAL",
    "B7-CREDENTIAL-001": "GAP",
}
EXPECTED_MILESTONE: Final[dict[str, str]] = {
    "B7-POWERSHELL-001": "B8-4",
    "B7-PERSISTENCE-001": "B8-4",
    "B7-RANSOMWARE-001": "B8-1",
    "B7-DEFENSE-EVASION-001": "B8-2",
    "B7-C2-DNS-001": "B8-4",
    "B7-CREDENTIAL-001": "B8-3",
}
VERIFICATION_TARGETS: Final[set[str]] = {
    "B7-RANSOMWARE-001",
    "B7-DEFENSE-EVASION-001",
    "B7-CREDENTIAL-001",
}
EXPECTED_SUMMARY: Final[dict[str, int]] = {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}

FALSE_SAFETY_FIELDS: Final[tuple[str, ...]] = (
    "unsupported_positive_claims_allowed",
    "verified_without_detector_acceptance_allowed",
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


def default_baseline_path() -> Path:
    return Path(__file__).resolve().parent.parent / "coverage" / "beta8_coverage_baseline.json"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value.lower()
    )


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def load_baseline(path: str | Path | None = None) -> dict[str, Any]:
    source = Path(path) if path is not None else default_baseline_path()
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("beta8_baseline_not_object")
    return payload


@dataclass(frozen=True)
class BaselineValidation:
    passed: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
        }


def validate_baseline(payload: dict[str, Any] | Any) -> BaselineValidation:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return BaselineValidation(False, ("baseline:not_object",))

    exact_fields = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_final_core_digest": SOURCE_FINAL_CORE_DIGEST,
        "source_campaign_digest": SOURCE_CAMPAIGN_DIGEST,
    }
    for field_name, expected in exact_fields.items():
        if payload.get(field_name) != expected:
            failures.append(f"baseline:{field_name}_mismatch")

    if not _valid_sha256(payload.get("source_final_core_digest")):
        failures.append("baseline:source_final_core_digest_invalid")
    if not _valid_sha256(payload.get("source_campaign_digest")):
        failures.append("baseline:source_campaign_digest_invalid")

    if payload.get("summary") != EXPECTED_SUMMARY:
        failures.append("baseline:summary_mismatch")

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(EXPECTED_ORDER):
        failures.append("baseline:scenario_count_invalid")
        scenarios = []

    actual_order = tuple(
        str(item.get("scenario_id") or "") if isinstance(item, dict) else ""
        for item in scenarios
    )
    if actual_order != EXPECTED_ORDER:
        failures.append("baseline:scenario_order_or_set_changed")

    seen: set[str] = set()
    computed = {"PARTIAL": 0, "GAP": 0, "VERIFIED": 0}
    for index, item in enumerate(scenarios):
        if not isinstance(item, dict):
            failures.append(f"baseline:scenario[{index}]:not_object")
            continue
        scenario_id = str(item.get("scenario_id") or "")
        if scenario_id in seen:
            failures.append(f"baseline:scenario[{index}]:duplicate")
        seen.add(scenario_id)
        expected_status = EXPECTED_STATUS.get(scenario_id)
        status = str(item.get("status") or "").upper()
        if expected_status is None or status != expected_status:
            failures.append(f"baseline:scenario[{index}]:status_mismatch")
        if status == "VERIFIED":
            failures.append(f"baseline:scenario[{index}]:unsupported_verified_promotion")
        if status in computed:
            computed[status] += 1
        else:
            failures.append(f"baseline:scenario[{index}]:status_invalid")

        expected_milestone = EXPECTED_MILESTONE.get(scenario_id)
        if item.get("next_acceptance_milestone") != expected_milestone:
            failures.append(f"baseline:scenario[{index}]:next_milestone_mismatch")
        if not _nonempty(item.get("next_acceptance_requirement")):
            failures.append(f"baseline:scenario[{index}]:acceptance_requirement_missing")

        expected_target = scenario_id in VERIFICATION_TARGETS
        if item.get("verification_target") is not expected_target:
            failures.append(f"baseline:scenario[{index}]:verification_target_mismatch")
        if not _nonempty(item.get("family")):
            failures.append(f"baseline:scenario[{index}]:family_missing")

    if computed != EXPECTED_SUMMARY:
        failures.append("baseline:computed_summary_mismatch")
    if seen != set(EXPECTED_ORDER):
        failures.append("baseline:scenario_set_incomplete")

    if payload.get("read_only") is not True:
        failures.append("baseline:read_only_required")
    if payload.get("evidence_snapshot_only") is not True:
        failures.append("baseline:evidence_snapshot_only_required")
    for field_name in FALSE_SAFETY_FIELDS:
        if payload.get(field_name) is not False:
            failures.append(f"baseline:{field_name}_must_be_false")

    return BaselineValidation(not failures, tuple(failures))


def baseline_digest(payload: dict[str, Any]) -> str:
    validation = validate_baseline(payload)
    if not validation.passed:
        raise ValueError("invalid_beta8_baseline:" + ",".join(validation.failures))
    return _stable_hash(payload)


def self_check(path: str | Path | None = None) -> dict[str, Any]:
    payload = load_baseline(path)
    validation = validate_baseline(payload)

    beta7 = beta7_final_acceptance.self_check()
    campaign = coverage_campaign.self_check()
    live_core_digest = str(beta7.get("core_digest") or "")
    live_campaign_digest = str(campaign.get("campaign_digest") or "")

    failures = list(validation.failures)
    if beta7.get("passed") is not True or beta7.get("deterministic_core") is not True:
        failures.append("baseline:beta7_final_predecessor_invalid")
    if live_core_digest != SOURCE_FINAL_CORE_DIGEST:
        failures.append("baseline:beta7_final_core_digest_changed")
    if campaign.get("passed") is not True:
        failures.append("baseline:beta7_campaign_predecessor_invalid")
    if live_campaign_digest != SOURCE_CAMPAIGN_DIGEST:
        failures.append("baseline:beta7_campaign_digest_changed")

    round_trip = json.loads(_canonical_json(payload)) == payload
    deterministic_serialization = _canonical_json(payload) == _canonical_json(load_baseline(path))
    if not round_trip:
        failures.append("baseline:round_trip_unstable")
    if not deterministic_serialization:
        failures.append("baseline:serialization_unstable")

    digest = _stable_hash(payload)
    summary = payload.get("summary") or {}
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "baseline_digest": digest,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_final_core_digest": payload.get("source_final_core_digest"),
        "live_final_core_digest": live_core_digest,
        "source_campaign_digest": payload.get("source_campaign_digest"),
        "live_campaign_digest": live_campaign_digest,
        "scenario_count": len(payload.get("scenarios") or []),
        "summary": summary,
        "verification_target_count": sum(
            1 for item in (payload.get("scenarios") or [])
            if isinstance(item, dict) and item.get("verification_target") is True
        ),
        "verification_targets": [
            item.get("scenario_id") for item in (payload.get("scenarios") or [])
            if isinstance(item, dict) and item.get("verification_target") is True
        ],
        "stable_round_trip": round_trip,
        "deterministic_serialization": deterministic_serialization,
        "read_only": payload.get("read_only") is True,
        "evidence_snapshot_only": payload.get("evidence_snapshot_only") is True,
        "unsupported_positive_claims_allowed": payload.get("unsupported_positive_claims_allowed"),
        "verified_without_detector_acceptance_allowed": payload.get("verified_without_detector_acceptance_allowed"),
        "process_execution": payload.get("process_execution"),
        "file_write": payload.get("file_write"),
        "network_io": payload.get("network_io"),
        "registry_mutation": payload.get("registry_mutation"),
        "credential_access": payload.get("credential_access"),
        "remediation_execution": payload.get("remediation_execution"),
        "automatic_quarantine": payload.get("automatic_quarantine"),
        "automatic_repair": payload.get("automatic_repair"),
        "automatic_restore": payload.get("automatic_restore"),
        "general_home_execution_authorized": payload.get("general_home_execution_authorized"),
        "delete_authorized": payload.get("delete_authorized"),
        "repair_authorized": payload.get("repair_authorized"),
        "terminate_process_authorized": payload.get("terminate_process_authorized"),
        "trust_allowlist_mutation_authorized": payload.get("trust_allowlist_mutation_authorized"),
        "privileged_system_mutation_authorized": payload.get("privileged_system_mutation_authorized"),
        "authority_granted": payload.get("authority_granted"),
        "execution_authority_added": payload.get("execution_authority_added"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta8 B8-0 coverage baseline")
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
