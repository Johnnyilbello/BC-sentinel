from __future__ import annotations

"""B14-2 Detector / Emulation Integration.

Binds the accepted B14-1 inert emulation families to real BC Sentinel detector
entrypoints where an accepted detector already exists. The binding is interface-
level and metadata-only: it does not execute attack actions and does not convert
emulated evidence into canonical VERIFIED coverage.

An uncovered family is reported as an explicit GAP instead of being faked.
"""

import hashlib
import importlib
import json
from typing import Any, Final

from sentinel import beta14_safe_adversary_matrix as b141

SCHEMA: Final[str] = "bc-sentinel-beta14-detector-emulation-integration-v1"
PROFILE: Final[str] = "v0.14.0-b142-detector-emulation-integration"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b141-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b2a00aac183905ec7f5988ef558dcf5612761ad5"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

BOUND: Final[str] = "BOUND"
UNBOUND: Final[str] = "UNBOUND"

BINDINGS: Final[tuple[dict[str, Any], ...]] = (
    {
        "family": "SCRIPT_FILE_CHAIN",
        "scenario_id": "B14-EMU-SCRIPT-CHAIN-001",
        "status": BOUND,
        "module": "sentinel.beta12_script_abuse_controls",
        "entrypoint": "detect_control",
        "accepted_detector_scenario": "B12-SCRIPT-ABUSE-001",
    },
    {
        "family": "PROCESS_ANCESTRY",
        "scenario_id": "B14-EMU-PROCESS-TREE-001",
        "status": BOUND,
        "module": "sentinel.beta12_process_tree_intelligence",
        "entrypoint": "detect_control",
        "accepted_detector_scenario": "B12-PROCESS-TREE-001",
    },
    {
        "family": "PERSISTENCE_METADATA",
        "scenario_id": "B14-EMU-PERSISTENCE-META-001",
        "status": BOUND,
        "module": "sentinel.beta12_autostart_detection",
        "entrypoint": "detect_control",
        "accepted_detector_scenario": "B12-AUTOSTART-LINK-001",
    },
    {
        "family": "RANSOMWARE_LIKE_WORKSPACE",
        "scenario_id": "B14-EMU-RANSOMWARE-CHAIN-001",
        "status": BOUND,
        "module": "sentinel.ransomware_detector",
        "entrypoint": "detect",
        "accepted_detector_scenario": "B7-RANSOMWARE-001",
    },
    {
        "family": "LOCAL_REPUTATION",
        "scenario_id": "B14-EMU-REPUTATION-EDGE-001",
        "status": BOUND,
        "module": "sentinel.beta12_local_reputation",
        "entrypoint": "classify",
        "accepted_detector_scenario": "B12-LOCAL-REPUTATION-001",
    },
    {
        "family": "ARCHIVE_METADATA",
        "scenario_id": "B14-EMU-ARCHIVE-CHAIN-001",
        "status": UNBOUND,
        "module": None,
        "entrypoint": None,
        "accepted_detector_scenario": None,
        "gap_reason": "NO_ACCEPTED_ARCHIVE_CHAIN_DETECTOR",
    },
)

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "metadata_only": True,
    "real_attack_execution": False,
    "real_malware_execution": False,
    "network_io": False,
    "credential_access": False,
    "real_persistence_mutation": False,
    "real_data_encryption": False,
    "detector_threshold_mutation": False,
    "coverage_promoted": False,
    "authority_expanded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "privileged_system_mutation": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def binding_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "bindings": [dict(item) for item in BINDINGS],
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def validate_runtime_bindings() -> tuple[str, ...]:
    failures: list[str] = []
    for item in BINDINGS:
        if item["status"] == UNBOUND:
            if item.get("gap_reason") != "NO_ACCEPTED_ARCHIVE_CHAIN_DETECTOR":
                failures.append(f"b142:{item['family']}:gap_reason_invalid")
            continue

        module_name = item.get("module")
        entrypoint = item.get("entrypoint")
        if not isinstance(module_name, str) or not isinstance(entrypoint, str):
            failures.append(f"b142:{item['family']}:binding_metadata_invalid")
            continue
        try:
            module = importlib.import_module(module_name)
        except Exception:
            failures.append(f"b142:{item['family']}:module_import_failed")
            continue
        candidate = getattr(module, entrypoint, None)
        if not callable(candidate):
            failures.append(f"b142:{item['family']}:entrypoint_not_callable")
    return tuple(dict.fromkeys(failures))


def _binding_by_scenario(scenario_id: str) -> dict[str, Any]:
    match = next((item for item in BINDINGS if item["scenario_id"] == scenario_id), None)
    if match is None:
        raise ValueError("b142:scenario_not_registered")
    return dict(match)


def integrate_trace(trace: object) -> dict[str, Any]:
    failures = b141.validate_trace(trace)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(trace, dict)

    b141_result = b141.evaluate_trace(trace)
    binding = _binding_by_scenario(str(trace["scenario_id"]))

    if binding["status"] == UNBOUND:
        integration_status = "EXPLICIT_GAP"
        detector_available = False
        detector_module = None
        detector_entrypoint = None
    else:
        runtime_failures = validate_runtime_bindings()
        family_failure = any(f":{binding['family']}:" in f for f in runtime_failures)
        detector_available = not family_failure
        integration_status = "DETECTOR_BOUND" if detector_available else "BINDING_INVALID"
        detector_module = binding["module"]
        detector_entrypoint = binding["entrypoint"]

    return {
        "passed": integration_status in {"DETECTOR_BOUND", "EXPLICIT_GAP"},
        "failures": [] if integration_status in {"DETECTOR_BOUND", "EXPLICIT_GAP"} else ["b142:binding_invalid"],
        "trace_id": trace["trace_id"],
        "scenario_id": trace["scenario_id"],
        "family": binding["family"],
        "emulation_outcome": b141_result["outcome"],
        "integration_status": integration_status,
        "detector_available": detector_available,
        "detector_module": detector_module,
        "detector_entrypoint": detector_entrypoint,
        "accepted_detector_scenario": binding.get("accepted_detector_scenario"),
        "gap_reason": binding.get("gap_reason"),
        "real_execution": False,
        "detector_invoked_with_attack_payload": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def integration_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for scenario in b141.SCENARIOS:
        trace = b141.make_trace(
            scenario_id=str(scenario["scenario_id"]),
            signals=list(scenario["required_signals"]) + list(scenario["supporting_signals"]),
        )
        rows.append(integrate_trace(trace))
    return {
        "schema": "bc-sentinel-beta14-detector-integration-matrix-v1",
        "profile": PROFILE,
        "rows": rows,
        "bound_count": sum(1 for row in rows if row["integration_status"] == "DETECTOR_BOUND"),
        "explicit_gap_count": sum(1 for row in rows if row["integration_status"] == "EXPLICIT_GAP"),
        "source_coverage": dict(SOURCE_COVERAGE),
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = list(validate_runtime_bindings())
    contract = binding_contract()
    matrix = integration_matrix()

    if contract["source_checkpoint"] != SOURCE_CHECKPOINT:
        failures.append("b142:source_checkpoint_invalid")
    if contract["source_checkpoint_commit"] != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b142:source_commit_invalid")
    if contract["source_coverage"] != SOURCE_COVERAGE:
        failures.append("b142:source_coverage_changed")
    if len(BINDINGS) != len(b141.SCENARIOS):
        failures.append("b142:binding_count_invalid")
    if matrix["bound_count"] != 5:
        failures.append("b142:bound_count_invalid")
    if matrix["explicit_gap_count"] != 1:
        failures.append("b142:gap_count_invalid")
    if any(row["passed"] is not True for row in matrix["rows"]):
        failures.append("b142:integration_row_failed")
    if any(row["coverage_promoted"] for row in matrix["rows"]):
        failures.append("b142:coverage_promoted")
    if any(row["authority_expanded"] for row in matrix["rows"]):
        failures.append("b142:authority_expanded")

    if SAFETY_BOUNDARIES["metadata_only"] is not True:
        failures.append("b142:metadata_only_required")
    for key, value in SAFETY_BOUNDARIES.items():
        if key == "metadata_only":
            continue
        if value is not False:
            failures.append(f"b142:{key}_unexpectedly_enabled")

    first_digest = _digest(contract)
    second_digest = _digest(binding_contract())
    deterministic = first_digest == second_digest
    if not deterministic:
        failures.append("b142:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "binding_count": len(BINDINGS),
        "bound_count": matrix["bound_count"],
        "explicit_gap_count": matrix["explicit_gap_count"],
        "explicit_gap_family": "ARCHIVE_METADATA",
        "real_attack_execution": False,
        "real_malware_executed": False,
        "network_io": False,
        "credential_access": False,
        "real_persistence_mutation": False,
        "real_data_encryption": False,
        "detector_threshold_mutation": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "contract_digest": first_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
