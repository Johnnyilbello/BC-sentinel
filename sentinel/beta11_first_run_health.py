from __future__ import annotations

"""B11-4 first-run health and bounded repair guidance.

The health path is intentionally read-only. It collects runtime facts, evaluates
those facts deterministically, and produces operator guidance. It never installs
packages, elevates privileges, registers services/drivers/autostart, changes
security settings, performs remediation, or uses the network.
"""

import argparse
import hashlib
import importlib.util
import json
import platform
import struct
import sys
from pathlib import Path
from typing import Any, Final

from sentinel import beta11_runtime_identity as runtime_identity

SCHEMA: Final[str] = "bc-sentinel-beta11-first-run-health-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b114-first-run-health-repair-guidance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b113-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "4ce33199bb72d87c09b0c204a40c2046efcb615a"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

READY: Final[str] = "READY"
DEGRADED: Final[str] = "DEGRADED"
BLOCKED: Final[str] = "BLOCKED"
PASS: Final[str] = "PASS"
WARN: Final[str] = "WARN"
FAIL: Final[str] = "FAIL"

SUPPORTED_PYTHON: Final[tuple[int, int]] = (3, 12)
REQUIRED_MODULES: Final[tuple[str, ...]] = (
    "PySide6",
    "sentinel.beta10_trust_center",
    "sentinel.beta10_trust_center_ui",
    "sentinel.beta11_runtime_identity",
)
FEATURE_MODULES: Final[tuple[str, ...]] = (
    "psutil",
    "watchdog",
    "yara",
    "pefile",
    "cryptography",
    "etw",
)

NON_EXECUTION_BOUNDARY: Final[dict[str, bool]] = {
    "health_mutates_system": False,
    "automatic_repair": False,
    "repair_execution_available": False,
    "package_installation_available": False,
    "privilege_elevation_available": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "scheduled_task_creation_available": False,
    "defender_exclusion_creation_available": False,
    "firewall_rule_creation_available": False,
    "automatic_update_execution_available": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}

GUIDANCE: Final[dict[str, str]] = {
    "WINDOWS_PLATFORM": (
        "Use the accepted BC Sentinel Windows build on a Windows host. "
        "B11-4 does not attempt to change the operating system or compatibility settings."
    ),
    "X64_RUNTIME": (
        "Use the 64-bit Windows runtime/build for this Beta11 line. "
        "B11-4 does not switch architecture automatically."
    ),
    "PYTHON_RUNTIME": (
        "For source execution, restore the accepted Python 3.12 environment. "
        "For a packaged build, replace the candidate with a manifest-verified artifact instead of modifying it in place."
    ),
    "EXECUTABLE_PATH": (
        "Restore or replace the accepted runtime/artifact so the executable path resolves to an existing file. "
        "No file is created automatically."
    ),
    "REQUIRED_MODULE": (
        "Restore the accepted runtime dependencies or replace the packaged artifact from an accepted build. "
        "BC Sentinel will not install missing modules automatically."
    ),
    "RUNTIME_IDENTITY": (
        "Do not rely on this candidate. Rebuild or restore it from the accepted checkpoint until runtime identity validation passes."
    ),
    "TRUST_CENTER_CORE": (
        "Do not rely on the product UI until the accepted Trust Center snapshot validates again. "
        "Rebuild or restore from the accepted checkpoint; no automatic repair is attempted."
    ),
    "FEATURE_MODULE": (
        "The affected feature may be unavailable or degraded. Restore the accepted dependency set or replace the artifact before relying on that feature."
    ),
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _trust_center_snapshot_valid() -> tuple[bool, str | None]:
    try:
        from sentinel import beta10_trust_center as trust

        snapshot = trust.build_trust_center_snapshot()
        result = trust.validate_snapshot(snapshot)
        passed = bool(result.get("passed"))
        if passed:
            return True, None
        failures = result.get("failures") or []
        return False, ";".join(str(item) for item in failures[:8]) or "snapshot_invalid"
    except Exception as exc:  # fail closed: diagnostic text only
        return False, f"{type(exc).__name__}:{exc}"


def collect_environment_facts() -> dict[str, Any]:
    """Collect read-only runtime facts. No repair or machine mutation occurs."""

    identity_result = runtime_identity.self_check()
    trust_valid, trust_error = _trust_center_snapshot_valid()
    executable = Path(sys.executable)
    return {
        "platform_system": platform.system(),
        "pointer_bits": struct.calcsize("P") * 8,
        "python_version": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        "frozen_runtime": bool(getattr(sys, "frozen", False)),
        "executable_exists": executable.is_file(),
        "required_modules": {name: _module_available(name) for name in REQUIRED_MODULES},
        "feature_modules": {name: _module_available(name) for name in FEATURE_MODULES},
        "runtime_identity_valid": bool(identity_result.get("passed")),
        "trust_center_snapshot_valid": trust_valid,
        "trust_center_error": trust_error,
    }


def healthy_fixture_facts() -> dict[str, Any]:
    return {
        "platform_system": "Windows",
        "pointer_bits": 64,
        "python_version": [SUPPORTED_PYTHON[0], SUPPORTED_PYTHON[1], 10],
        "frozen_runtime": False,
        "executable_exists": True,
        "required_modules": {name: True for name in REQUIRED_MODULES},
        "feature_modules": {name: True for name in FEATURE_MODULES},
        "runtime_identity_valid": True,
        "trust_center_snapshot_valid": True,
        "trust_center_error": None,
    }


def _check(check_id: str, critical: bool, passed: bool, summary: str, guidance_id: str) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "critical": critical,
        "status": PASS if passed else (FAIL if critical else WARN),
        "summary": summary,
        "guidance_id": None if passed else guidance_id,
    }


def _guidance_for(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in checks:
        guidance_id = item.get("guidance_id")
        if not isinstance(guidance_id, str) or guidance_id in seen:
            continue
        seen.add(guidance_id)
        output.append(
            {
                "guidance_id": guidance_id,
                "operator_action": GUIDANCE[guidance_id],
                "automatic_execution_available": False,
                "product_requests_elevation": False,
                "product_performs_network_action": False,
            }
        )
    return output


def evaluate_health(facts: object) -> dict[str, Any]:
    """Pure evaluation: identical facts produce an identical report."""

    if not isinstance(facts, dict):
        facts = {}

    platform_ok = facts.get("platform_system") == "Windows"
    x64_ok = facts.get("pointer_bits") == 64
    version = facts.get("python_version")
    python_ok = (
        isinstance(version, list)
        and len(version) >= 2
        and version[0] == SUPPORTED_PYTHON[0]
        and version[1] == SUPPORTED_PYTHON[1]
    )
    executable_ok = facts.get("executable_exists") is True

    required = facts.get("required_modules") if isinstance(facts.get("required_modules"), dict) else {}
    feature = facts.get("feature_modules") if isinstance(facts.get("feature_modules"), dict) else {}

    checks: list[dict[str, Any]] = [
        _check("WINDOWS_PLATFORM", True, platform_ok, "Windows runtime detected", "WINDOWS_PLATFORM"),
        _check("X64_RUNTIME", True, x64_ok, "64-bit runtime detected", "X64_RUNTIME"),
        _check("PYTHON_RUNTIME", True, python_ok, "Accepted Python 3.12 runtime detected", "PYTHON_RUNTIME"),
        _check("EXECUTABLE_PATH", True, executable_ok, "Runtime executable path resolves", "EXECUTABLE_PATH"),
    ]

    for name in REQUIRED_MODULES:
        checks.append(
            _check(
                f"REQUIRED_MODULE:{name}",
                True,
                required.get(name) is True,
                f"Required runtime module available: {name}",
                "REQUIRED_MODULE",
            )
        )

    checks.extend(
        [
            _check(
                "RUNTIME_IDENTITY",
                True,
                facts.get("runtime_identity_valid") is True,
                "Canonical Beta11 runtime identity validates",
                "RUNTIME_IDENTITY",
            ),
            _check(
                "TRUST_CENTER_CORE",
                True,
                facts.get("trust_center_snapshot_valid") is True,
                "Accepted Trust Center snapshot validates",
                "TRUST_CENTER_CORE",
            ),
        ]
    )

    for name in FEATURE_MODULES:
        checks.append(
            _check(
                f"FEATURE_MODULE:{name}",
                False,
                feature.get(name) is True,
                f"Feature dependency available: {name}",
                "FEATURE_MODULE",
            )
        )

    critical_failures = [item for item in checks if item["critical"] and item["status"] == FAIL]
    warnings = [item for item in checks if item["status"] == WARN]
    overall = BLOCKED if critical_failures else (DEGRADED if warnings else READY)
    guidance = _guidance_for(checks)

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "overall_status": overall,
        "ready_to_start": overall != BLOCKED,
        "critical_failure_count": len(critical_failures),
        "warning_count": len(warnings),
        "checks": checks,
        "repair_guidance": guidance,
        "facts": json.loads(_canonical(facts)),
        "non_execution_boundary": dict(NON_EXECUTION_BOUNDARY),
    }


def validate_health_report(report: object) -> tuple[str, ...]:
    if not isinstance(report, dict):
        return ("b114:not_object",)

    failures: list[str] = []
    if report.get("schema") != SCHEMA or report.get("profile") != PROFILE:
        failures.append("b114:identity_invalid")
    if report.get("source_checkpoint") != SOURCE_CHECKPOINT or report.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b114:source_checkpoint_invalid")
    if report.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b114:coverage_changed")
    if tuple(report.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b114:verified_scenarios_changed")

    boundary = report.get("non_execution_boundary")
    if boundary != NON_EXECUTION_BOUNDARY or not isinstance(boundary, dict):
        failures.append("b114:non_execution_boundary_invalid")
    elif any(boundary.values()):
        failures.append("b114:mutation_or_authority_enabled")

    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        failures.append("b114:checks_missing")
        return tuple(failures)

    critical_failures = sum(1 for item in checks if isinstance(item, dict) and item.get("critical") is True and item.get("status") == FAIL)
    warnings = sum(1 for item in checks if isinstance(item, dict) and item.get("status") == WARN)
    expected_status = BLOCKED if critical_failures else (DEGRADED if warnings else READY)
    if report.get("overall_status") != expected_status:
        failures.append("b114:overall_status_not_derived")
    if report.get("critical_failure_count") != critical_failures:
        failures.append("b114:critical_failure_count_invalid")
    if report.get("warning_count") != warnings:
        failures.append("b114:warning_count_invalid")
    if report.get("ready_to_start") is not (expected_status != BLOCKED):
        failures.append("b114:ready_state_invalid")

    guidance = report.get("repair_guidance")
    if not isinstance(guidance, list):
        failures.append("b114:repair_guidance_invalid")
    else:
        for item in guidance:
            if not isinstance(item, dict):
                failures.append("b114:repair_guidance_entry_invalid")
                continue
            if item.get("automatic_execution_available") is not False:
                failures.append("b114:automatic_repair_enabled")
            if item.get("product_requests_elevation") is not False:
                failures.append("b114:repair_guidance_requests_elevation")
            if item.get("product_performs_network_action") is not False:
                failures.append("b114:repair_guidance_uses_network")
            if item.get("guidance_id") not in GUIDANCE:
                failures.append("b114:unknown_guidance_id")

    return tuple(failures)


def live_health_report() -> dict[str, Any]:
    return evaluate_health(collect_environment_facts())


def self_check() -> dict[str, Any]:
    healthy_facts = healthy_fixture_facts()
    healthy_a = evaluate_health(healthy_facts)
    healthy_b = evaluate_health(healthy_facts)

    degraded_facts = json.loads(_canonical(healthy_facts))
    degraded_facts["feature_modules"][FEATURE_MODULES[0]] = False
    degraded = evaluate_health(degraded_facts)

    blocked_facts = json.loads(_canonical(healthy_facts))
    blocked_facts["required_modules"][REQUIRED_MODULES[0]] = False
    blocked = evaluate_health(blocked_facts)

    failures = list(validate_health_report(healthy_a))
    failures.extend(validate_health_report(degraded))
    failures.extend(validate_health_report(blocked))
    if healthy_a != healthy_b or _digest(healthy_a) != _digest(healthy_b):
        failures.append("b114:health_evaluation_not_deterministic")
    if healthy_a["overall_status"] != READY:
        failures.append("b114:healthy_fixture_not_ready")
    if degraded["overall_status"] != DEGRADED or not degraded["ready_to_start"]:
        failures.append("b114:optional_failure_not_degraded")
    if blocked["overall_status"] != BLOCKED or blocked["ready_to_start"]:
        failures.append("b114:critical_failure_not_blocked")

    digest_payload = {
        "healthy": healthy_a,
        "degraded": degraded,
        "blocked": blocked,
    }
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "health_contract_digest": _digest(digest_payload),
        "deterministic_evaluation": healthy_a == healthy_b,
        "healthy_fixture_status": healthy_a["overall_status"],
        "degraded_fixture_status": degraded["overall_status"],
        "blocked_fixture_status": blocked["overall_status"],
        "critical_check_count": sum(1 for item in healthy_a["checks"] if item["critical"]),
        "optional_check_count": sum(1 for item in healthy_a["checks"] if not item["critical"]),
        "health_mutates_system": False,
        "automatic_repair": False,
        "repair_execution_available": False,
        "privilege_elevation_available": False,
        "network_required": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--health-json", action="store_true")
    args = parser.parse_args(argv)

    if args.self_check:
        report = self_check()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    report = live_health_report()
    validation_failures = validate_health_report(report)
    if validation_failures:
        report = dict(report)
        report["validation_failures"] = list(validation_failures)
        report["overall_status"] = BLOCKED
        report["ready_to_start"] = False
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_status"] != BLOCKED else 2


if __name__ == "__main__":
    raise SystemExit(main())
