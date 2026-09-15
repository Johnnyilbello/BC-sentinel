from __future__ import annotations

"""B7-7 final Beta7 acceptance and freeze contract.

This module is read-only. It composes the accepted Beta7 self-checks, preserves
the frozen Beta6 portable GUI contract, measures the synthetic acceptance
pipeline resource cost, and fails closed on any authority or coverage-claim
expansion. It does not execute remediation or mutate security state.
"""

from dataclasses import dataclass
import argparse
import hashlib
import json
import time
import tracemalloc
from typing import Any, Final

from sentinel import (
    attack_chain_harness,
    confidence_gate,
    coverage_campaign,
    coverage_ledger,
    explainable_security,
    incident_correlation,
    portable_gui_release,
    security_graph,
)

SCHEMA: Final[str] = "bc-sentinel-beta7-final-acceptance-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b77-final-acceptance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b76-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "1bd66f4f9e55313388e871e26c6a35d55a3dbb20"

MAX_SYNTHETIC_PIPELINE_SECONDS: Final[float] = 60.0
MAX_SYNTHETIC_PEAK_BYTES: Final[int] = 512 * 1024 * 1024


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value.lower()
    )


def _core_snapshot() -> dict[str, Any]:
    ledger = coverage_ledger.self_check()
    graph = security_graph.self_check()
    correlation = incident_correlation.self_check()
    confidence = confidence_gate.self_check()
    attack = attack_chain_harness.self_check()
    explanation = explainable_security.self_check()
    campaign = coverage_campaign.self_check()
    portable = portable_gui_release.validate_b67_contract()

    return {
        "ledger": {
            "passed": ledger.get("passed") is True,
            "scenario_count": ledger.get("scenario_count"),
            "summary": ledger.get("summary"),
            "unsupported_positive_claims_allowed": ledger.get("unsupported_positive_claims_allowed"),
        },
        "security_graph": {
            "passed": graph.get("passed") is True,
            "digest": graph.get("graph_digest"),
            "deterministic_serialization": graph.get("deterministic_serialization"),
            "stable_round_trip": graph.get("stable_round_trip"),
        },
        "incident_correlation": {
            "passed": correlation.get("passed") is True,
            "digest": correlation.get("correlation_digest"),
            "deterministic_serialization": correlation.get("deterministic_serialization"),
            "stable_round_trip": correlation.get("stable_round_trip"),
            "temporal_proximity_alone_correlates": correlation.get("temporal_proximity_alone_correlates"),
        },
        "confidence_gate": {
            "passed": confidence.get("passed") is True,
            "recommend_digest": confidence.get("recommend_digest"),
            "recommend_outcome": confidence.get("recommend_outcome"),
            "review_outcome": confidence.get("review_outcome"),
            "blocked_outcome": confidence.get("blocked_outcome"),
            "authority_granted": confidence.get("authority_granted"),
        },
        "attack_chain": {
            "passed": attack.get("passed") is True,
            "report_digest": attack.get("report_digest"),
            "stage_order": attack.get("stage_order"),
            "synthetic_fixture_only": attack.get("synthetic_fixture_only"),
            "process_execution": attack.get("process_execution"),
            "file_write": attack.get("file_write"),
            "network_io": attack.get("network_io"),
            "registry_mutation": attack.get("registry_mutation"),
            "remediation_execution": attack.get("remediation_execution"),
            "authority_granted": attack.get("authority_granted"),
        },
        "explainable_security": {
            "passed": explanation.get("passed") is True,
            "explanation_digest": explanation.get("explanation_digest"),
            "all_positive_claims_evidence_bound": explanation.get("all_positive_claims_evidence_bound"),
            "unsupported_positive_claims_allowed": explanation.get("unsupported_positive_claims_allowed"),
            "confidence_amplified": explanation.get("confidence_amplified"),
            "authority_granted": explanation.get("authority_granted"),
        },
        "coverage_campaign": {
            "passed": campaign.get("passed") is True,
            "campaign_digest": campaign.get("campaign_digest"),
            "summary": campaign.get("summary"),
            "partial_count": campaign.get("partial_count"),
            "explicit_gap_count": campaign.get("explicit_gap_count"),
            "verified_count": campaign.get("verified_count"),
            "unsupported_verified_claims_allowed": campaign.get("unsupported_verified_claims_allowed"),
            "synthetic_fixture_only": campaign.get("synthetic_fixture_only"),
            "authority_granted": campaign.get("authority_granted"),
        },
        "beta6_portable_contract": {
            "passed": portable.get("passed") is True,
            "profile": portable.get("profile"),
            "packaging_mode": portable.get("release", {}).get("packaging_mode"),
            "portable": portable.get("release", {}).get("portable"),
            "windowed": portable.get("release", {}).get("windowed"),
            "installer_required": portable.get("release", {}).get("installer_required"),
            "service_install": portable.get("release", {}).get("service_install"),
            "driver_install": portable.get("release", {}).get("driver_install"),
            "network_required": portable.get("release", {}).get("network_required"),
            "cloud_required": portable.get("release", {}).get("cloud_required"),
            "explicit_operator_action_required": portable.get("release", {}).get("explicit_operator_action_required"),
            "general_home_execution_authorized": portable.get("release", {}).get("general_home_execution_authorized"),
        },
        "safety": {
            "execution_authority_added": False,
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_restore": False,
            "delete_authorized": False,
            "repair_authorized": False,
            "terminate_process_authorized": False,
            "trust_allowlist_mutation_authorized": False,
            "privileged_system_mutation_authorized": False,
        },
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
                "max_seconds": MAX_SYNTHETIC_PIPELINE_SECONDS,
                "max_peak_memory_bytes": MAX_SYNTHETIC_PEAK_BYTES,
            },
            "read_only": True,
            "execution_authority_added": False,
        }


@dataclass(frozen=True)
class FinalAcceptanceValidation:
    passed: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "read_only": True,
            "execution_authority_added": False,
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
    return FinalAcceptanceReport(
        core=core,
        core_digest=_stable_hash(core),
        elapsed_seconds=float(elapsed),
        peak_memory_bytes=int(peak),
    )


def validate_report(report: FinalAcceptanceReport | dict[str, Any]) -> FinalAcceptanceValidation:
    payload = report.to_dict() if isinstance(report, FinalAcceptanceReport) else report
    failures: list[str] = []
    if not isinstance(payload, dict):
        return FinalAcceptanceValidation(False, ("final:not_object",))

    if payload.get("schema") != SCHEMA:
        failures.append("final:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("final:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("final:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("final:source_checkpoint_commit_mismatch")
    if payload.get("read_only") is not True or payload.get("execution_authority_added") is not False:
        failures.append("final:read_only_authority_contract_invalid")

    core = payload.get("core")
    if not isinstance(core, dict):
        return FinalAcceptanceValidation(False, tuple(failures + ["final:core_missing"]))
    expected_digest = _stable_hash(core)
    if payload.get("core_digest") != expected_digest or not _valid_sha256(payload.get("core_digest")):
        failures.append("final:core_digest_mismatch")

    ledger = core.get("ledger", {})
    if ledger.get("passed") is not True or ledger.get("scenario_count") != 6:
        failures.append("final:ledger_invalid")
    if ledger.get("summary") != {"GAP": 0, "PARTIAL": 0, "PLANNED": 6, "VERIFIED": 0}:
        failures.append("final:base_ledger_summary_changed")
    if ledger.get("unsupported_positive_claims_allowed") is not False:
        failures.append("final:ledger_unsupported_claims_allowed")

    graph = core.get("security_graph", {})
    if graph.get("passed") is not True or not _valid_sha256(graph.get("digest")):
        failures.append("final:security_graph_invalid")
    if graph.get("deterministic_serialization") is not True or graph.get("stable_round_trip") is not True:
        failures.append("final:security_graph_not_reproducible")

    correlation = core.get("incident_correlation", {})
    if correlation.get("passed") is not True or not _valid_sha256(correlation.get("digest")):
        failures.append("final:correlation_invalid")
    if correlation.get("deterministic_serialization") is not True or correlation.get("stable_round_trip") is not True:
        failures.append("final:correlation_not_reproducible")
    if correlation.get("temporal_proximity_alone_correlates") is not False:
        failures.append("final:correlation_safety_regression")

    confidence = core.get("confidence_gate", {})
    if confidence.get("passed") is not True or not _valid_sha256(confidence.get("recommend_digest")):
        failures.append("final:confidence_gate_invalid")
    if confidence.get("recommend_outcome") != "RECOMMEND" or confidence.get("review_outcome") != "REVIEW_REQUIRED" or confidence.get("blocked_outcome") != "BLOCKED_INSUFFICIENT_EVIDENCE":
        failures.append("final:confidence_outcomes_changed")
    if confidence.get("authority_granted") is not False:
        failures.append("final:confidence_authority_granted")

    attack = core.get("attack_chain", {})
    if attack.get("passed") is not True or not _valid_sha256(attack.get("report_digest")):
        failures.append("final:attack_chain_invalid")
    if attack.get("stage_order") != ["PROCESS", "SCRIPT", "PERSISTENCE", "DNS", "DETECTION"]:
        failures.append("final:attack_chain_order_changed")
    for field_name in ("process_execution", "file_write", "network_io", "registry_mutation", "remediation_execution", "authority_granted"):
        if attack.get(field_name) is not False:
            failures.append(f"final:attack_chain_{field_name}_must_be_false")
    if attack.get("synthetic_fixture_only") is not True:
        failures.append("final:attack_chain_not_synthetic")

    explanation = core.get("explainable_security", {})
    if explanation.get("passed") is not True or not _valid_sha256(explanation.get("explanation_digest")):
        failures.append("final:explainable_security_invalid")
    if explanation.get("all_positive_claims_evidence_bound") is not True:
        failures.append("final:explanation_unbound_claim")
    if explanation.get("unsupported_positive_claims_allowed") is not False or explanation.get("confidence_amplified") is not False or explanation.get("authority_granted") is not False:
        failures.append("final:explanation_safety_regression")

    campaign = core.get("coverage_campaign", {})
    if campaign.get("passed") is not True or not _valid_sha256(campaign.get("campaign_digest")):
        failures.append("final:coverage_campaign_invalid")
    if campaign.get("summary") != {"GAP": 3, "PARTIAL": 3, "VERIFIED": 0}:
        failures.append("final:coverage_campaign_summary_changed")
    if campaign.get("partial_count") != 3 or campaign.get("explicit_gap_count") != 3 or campaign.get("verified_count") != 0:
        failures.append("final:coverage_campaign_counts_changed")
    if campaign.get("unsupported_verified_claims_allowed") is not False or campaign.get("authority_granted") is not False:
        failures.append("final:coverage_campaign_claim_safety_regression")

    portable = core.get("beta6_portable_contract", {})
    if portable.get("passed") is not True or portable.get("packaging_mode") != "onedir" or portable.get("portable") is not True or portable.get("windowed") is not True:
        failures.append("final:beta6_portable_contract_invalid")
    for field_name in ("installer_required", "service_install", "driver_install", "network_required", "cloud_required", "general_home_execution_authorized"):
        if portable.get(field_name) is not False:
            failures.append(f"final:portable_{field_name}_must_be_false")
    if portable.get("explicit_operator_action_required") is not True:
        failures.append("final:portable_explicit_operator_action_missing")

    safety = core.get("safety", {})
    for field_name in (
        "execution_authority_added",
        "automatic_quarantine",
        "automatic_repair",
        "automatic_restore",
        "delete_authorized",
        "repair_authorized",
        "terminate_process_authorized",
        "trust_allowlist_mutation_authorized",
        "privileged_system_mutation_authorized",
    ):
        if safety.get(field_name) is not False:
            failures.append(f"final:safety_{field_name}_must_be_false")

    resources = payload.get("resource_cost")
    if not isinstance(resources, dict):
        failures.append("final:resource_cost_missing")
    else:
        elapsed = resources.get("elapsed_seconds")
        peak = resources.get("peak_memory_bytes")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or elapsed < 0 or elapsed > MAX_SYNTHETIC_PIPELINE_SECONDS:
            failures.append("final:resource_elapsed_invalid")
        if isinstance(peak, bool) or not isinstance(peak, int) or peak < 0 or peak > MAX_SYNTHETIC_PEAK_BYTES:
            failures.append("final:resource_peak_memory_invalid")

    return FinalAcceptanceValidation(not failures, tuple(failures))


def self_check() -> dict[str, Any]:
    first = run_final_acceptance()
    second_core = _core_snapshot()
    validation = validate_report(first)
    return {
        **validation.to_dict(),
        "core_digest": first.core_digest,
        "deterministic_core": first.core == second_core,
        "resource_cost": first.to_dict()["resource_cost"],
        "campaign_summary": first.core["coverage_campaign"]["summary"],
        "base_ledger_summary": first.core["ledger"]["summary"],
        "beta6_portable_contract_passed": first.core["beta6_portable_contract"]["passed"],
        "attack_chain_safe": first.core["attack_chain"]["passed"],
        "explainable_security_grounded": first.core["explainable_security"]["all_positive_claims_evidence_bound"],
        "authority_granted": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_restore": False,
        "general_home_execution_authorized": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B7-7 final Beta7 acceptance")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("deterministic_core") is True
        and result.get("campaign_summary") == {"GAP": 3, "PARTIAL": 3, "VERIFIED": 0}
        and result.get("beta6_portable_contract_passed") is True
        and result.get("attack_chain_safe") is True
        and result.get("explainable_security_grounded") is True
        and result.get("authority_granted") is False
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())
