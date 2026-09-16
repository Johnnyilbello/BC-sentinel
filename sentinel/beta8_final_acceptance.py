from __future__ import annotations

"""B8-7 final Beta8 acceptance contract, read-only and deterministic."""

import argparse
import hashlib
import json
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Final

from sentinel import (
    attack_prediction,
    beta8_coverage_verification,
    credential_access_detector,
    defense_evasion_detector,
    predictive_attack_chain,
    ransomware_detector,
)

SCHEMA: Final[str] = "bc-sentinel-beta8-final-acceptance-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b87-final-acceptance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta8-b86-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "ee98c6fb908c4a8ff133e8fe94f0afd2c2bc08f6"
EXPECTED_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}
MAX_PIPELINE_SECONDS: Final[float] = 60.0
MAX_PEAK_BYTES: Final[int] = 512 * 1024 * 1024

FALSE_AUTHORITY_FIELDS: Final[tuple[str, ...]] = beta8_coverage_verification.FALSE_AUTHORITY_FIELDS


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _core_snapshot() -> dict[str, Any]:
    detectors = {
        "ransomware": ransomware_detector.self_check(),
        "defense_evasion": defense_evasion_detector.self_check(),
        "credential_access": credential_access_detector.self_check(),
    }
    coverage = beta8_coverage_verification.self_check()
    prediction = attack_prediction.self_check()
    chain = predictive_attack_chain.self_check()
    return {
        "detectors": {
            name: {
                "passed": item.get("passed"),
                "positive_outcome": item.get("positive_outcome"),
                "coverage_status": item.get("coverage_status"),
                "deterministic_serialization": item.get("deterministic_serialization"),
                "stable_round_trip": item.get("stable_round_trip"),
                "evidence_ids_preserved": item.get("evidence_ids_preserved"),
                "synthetic_fixture_only": item.get("synthetic_fixture_only"),
                "detector_digest": item.get("detector_digest"),
            }
            for name, item in detectors.items()
        },
        "coverage": {
            "passed": coverage.get("passed"),
            "summary": coverage.get("summary"),
            "scenario_count": coverage.get("scenario_count"),
            "accepted_detector_count": coverage.get("accepted_detector_count"),
            "deterministic_recomputation": coverage.get("deterministic_recomputation"),
            "synthetic_evidence_cannot_verify": coverage.get("synthetic_evidence_cannot_verify"),
            "report_digest": coverage.get("report_digest"),
        },
        "prediction": {
            "passed": prediction.get("passed"),
            "outcome": prediction.get("outcome"),
            "predicted_stage": prediction.get("predicted_stage"),
            "confidence": prediction.get("confidence"),
            "deterministic_serialization": prediction.get("deterministic_serialization"),
            "prediction_digest": prediction.get("prediction_digest"),
            "advisory_only": prediction.get("advisory_only"),
            "prediction_is_evidence": prediction.get("prediction_is_evidence"),
        },
        "predictive_chain": {
            "passed": chain.get("passed"),
            "chain_order": chain.get("chain_order"),
            "predicted_stages": chain.get("predicted_stages"),
            "confidences": chain.get("confidences"),
            "accuracy": chain.get("accuracy"),
            "brier_score": chain.get("brier_score"),
            "confidence_monotonic": chain.get("confidence_monotonic"),
            "deterministic_serialization": chain.get("deterministic_serialization"),
            "report_digest": chain.get("report_digest"),
            "advisory_only": chain.get("advisory_only"),
            "predictions_are_evidence": chain.get("predictions_are_evidence"),
        },
        "safety": {field: False for field in FALSE_AUTHORITY_FIELDS},
    }


@dataclass(frozen=True)
class FinalAcceptanceReport:
    core: dict[str, Any]
    core_digest: str
    elapsed_seconds: float
    peak_memory_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "core": self.core,
            "core_digest": self.core_digest,
            "resource_cost": {
                "elapsed_seconds": self.elapsed_seconds,
                "peak_memory_bytes": self.peak_memory_bytes,
                "max_seconds": MAX_PIPELINE_SECONDS,
                "max_peak_memory_bytes": MAX_PEAK_BYTES,
            },
            "read_only": True,
            "synthetic_evidence_cannot_verify": True,
            "predictions_are_evidence": False,
            **{field: False for field in FALSE_AUTHORITY_FIELDS},
        }


def run_final_acceptance() -> FinalAcceptanceReport:
    tracemalloc.start()
    started = time.perf_counter()
    try:
        core = _core_snapshot()
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return FinalAcceptanceReport(core, _digest(core), float(elapsed), int(peak))


def validate_report(report: FinalAcceptanceReport | dict[str, Any]) -> tuple[str, ...]:
    data = report.to_dict() if isinstance(report, FinalAcceptanceReport) else report
    failures: list[str] = []
    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("final:schema_or_profile_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("final:source_checkpoint_invalid")
    core = data.get("core")
    if not isinstance(core, dict):
        return tuple(failures + ["final:core_missing"])
    if data.get("core_digest") != _digest(core) or not _valid_digest(data.get("core_digest")):
        failures.append("final:core_digest_invalid")
    for name, detector in core.get("detectors", {}).items():
        if detector.get("passed") is not True or detector.get("positive_outcome") != "DETECTED":
            failures.append(f"final:{name}_detector_invalid")
        if detector.get("coverage_status") != "PARTIAL" or detector.get("synthetic_fixture_only") is not True:
            failures.append(f"final:{name}_coverage_claim_invalid")
        if detector.get("deterministic_serialization") is not True or detector.get("stable_round_trip") is not True or detector.get("evidence_ids_preserved") is not True:
            failures.append(f"final:{name}_reproducibility_invalid")
        if not _valid_digest(detector.get("detector_digest")):
            failures.append(f"final:{name}_digest_invalid")
    coverage = core.get("coverage", {})
    if coverage.get("passed") is not True or coverage.get("summary") != EXPECTED_COVERAGE:
        failures.append("final:coverage_invalid")
    if coverage.get("scenario_count") != 6 or coverage.get("accepted_detector_count") != 3:
        failures.append("final:coverage_counts_invalid")
    if coverage.get("deterministic_recomputation") is not True or coverage.get("synthetic_evidence_cannot_verify") is not True:
        failures.append("final:coverage_safety_invalid")
    prediction = core.get("prediction", {})
    if prediction.get("passed") is not True or prediction.get("outcome") != "PREDICTED" or prediction.get("predicted_stage") != "DNS":
        failures.append("final:prediction_invalid")
    if prediction.get("advisory_only") is not True or prediction.get("prediction_is_evidence") is not False:
        failures.append("final:prediction_boundary_invalid")
    chain = core.get("predictive_chain", {})
    if chain.get("passed") is not True or chain.get("accuracy") != 1.0 or chain.get("confidence_monotonic") is not True:
        failures.append("final:predictive_chain_invalid")
    if chain.get("predicted_stages") != ["PERSISTENCE", "DNS", "DETECTION"]:
        failures.append("final:predictive_stages_invalid")
    if chain.get("advisory_only") is not True or chain.get("predictions_are_evidence") is not False:
        failures.append("final:predictive_chain_boundary_invalid")
    resources = data.get("resource_cost", {})
    elapsed, peak = resources.get("elapsed_seconds"), resources.get("peak_memory_bytes")
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not 0 <= elapsed <= MAX_PIPELINE_SECONDS:
        failures.append("final:elapsed_invalid")
    if isinstance(peak, bool) or not isinstance(peak, int) or not 0 <= peak <= MAX_PEAK_BYTES:
        failures.append("final:peak_memory_invalid")
    if data.get("read_only") is not True or data.get("synthetic_evidence_cannot_verify") is not True or data.get("predictions_are_evidence") is not False:
        failures.append("final:read_only_boundary_invalid")
    for field in FALSE_AUTHORITY_FIELDS:
        if data.get(field) is not False or core.get("safety", {}).get(field) is not False:
            failures.append(f"final:{field}_must_be_false")
    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = run_final_acceptance()
    failures = list(validate_report(first))
    deterministic = first.core == _core_snapshot()
    if not deterministic:
        failures.append("final:core_not_deterministic")
    data = first.to_dict()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "core_digest": first.core_digest,
        "deterministic_core": deterministic,
        "coverage_summary": first.core["coverage"]["summary"],
        "detector_count": len(first.core["detectors"]),
        "prediction_accuracy": first.core["predictive_chain"]["accuracy"],
        "resource_cost": data["resource_cost"],
        "read_only": data["read_only"],
        "synthetic_evidence_cannot_verify": data["synthetic_evidence_cannot_verify"],
        "predictions_are_evidence": data["predictions_are_evidence"],
        **{field: data[field] for field in FALSE_AUTHORITY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B8-7 final Beta8 acceptance")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
