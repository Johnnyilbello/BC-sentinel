from __future__ import annotations

import copy
from pathlib import Path

from sentinel import beta11_first_run_health as health

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "packaging" / "beta11_desktop_entry.py"


def _healthy() -> dict:
    return copy.deepcopy(health.healthy_fixture_facts())


def test_b114_is_bound_to_exact_b113_checkpoint() -> None:
    assert health.SOURCE_CHECKPOINT == "checkpoint/v011-beta11-b113-pass"
    assert health.SOURCE_CHECKPOINT_COMMIT == "4ce33199bb72d87c09b0c204a40c2046efcb615a"
    assert health.SOURCE_COVERAGE == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert health.VERIFIED_SCENARIOS == ("B7-POWERSHELL-001", "B7-RANSOMWARE-001")


def test_b114_self_check_proves_ready_degraded_and_blocked_semantics() -> None:
    report = health.self_check()
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["healthy_fixture_status"] == health.READY
    assert report["degraded_fixture_status"] == health.DEGRADED
    assert report["blocked_fixture_status"] == health.BLOCKED
    assert report["deterministic_evaluation"] is True
    assert len(report["health_contract_digest"]) == 64


def test_b114_identical_facts_produce_identical_health_report() -> None:
    facts = _healthy()
    first = health.evaluate_health(facts)
    second = health.evaluate_health(copy.deepcopy(facts))
    assert first == second
    assert health.validate_health_report(first) == ()
    assert first["overall_status"] == health.READY
    assert first["ready_to_start"] is True


def test_b114_missing_critical_module_fails_closed_and_adds_nonexecuting_guidance() -> None:
    facts = _healthy()
    facts["required_modules"][health.REQUIRED_MODULES[0]] = False
    report = health.evaluate_health(facts)
    assert report["overall_status"] == health.BLOCKED
    assert report["ready_to_start"] is False
    assert report["critical_failure_count"] == 1
    assert any(item["guidance_id"] == "REQUIRED_MODULE" for item in report["repair_guidance"])
    for item in report["repair_guidance"]:
        assert item["automatic_execution_available"] is False
        assert item["product_requests_elevation"] is False
        assert item["product_performs_network_action"] is False
    assert health.validate_health_report(report) == ()


def test_b114_missing_optional_feature_is_degraded_not_blocked() -> None:
    facts = _healthy()
    facts["feature_modules"][health.FEATURE_MODULES[0]] = False
    report = health.evaluate_health(facts)
    assert report["overall_status"] == health.DEGRADED
    assert report["ready_to_start"] is True
    assert report["critical_failure_count"] == 0
    assert report["warning_count"] == 1
    assert any(item["guidance_id"] == "FEATURE_MODULE" for item in report["repair_guidance"])


def test_b114_wrong_platform_architecture_or_python_blocks_ready_claim() -> None:
    mutations = (
        ("platform_system", "Linux"),
        ("pointer_bits", 32),
        ("python_version", [3, 11, 9]),
        ("executable_exists", False),
    )
    for key, value in mutations:
        facts = _healthy()
        facts[key] = value
        report = health.evaluate_health(facts)
        assert report["overall_status"] == health.BLOCKED
        assert report["ready_to_start"] is False
        assert report["critical_failure_count"] >= 1


def test_b114_invalid_runtime_identity_or_trust_center_blocks_startup() -> None:
    for key in ("runtime_identity_valid", "trust_center_snapshot_valid"):
        facts = _healthy()
        facts[key] = False
        report = health.evaluate_health(facts)
        assert report["overall_status"] == health.BLOCKED
        assert report["ready_to_start"] is False


def test_b114_nonexecution_boundary_has_no_enabled_mutation_or_authority() -> None:
    report = health.evaluate_health(_healthy())
    assert report["non_execution_boundary"] == health.NON_EXECUTION_BOUNDARY
    assert not any(report["non_execution_boundary"].values())
    self_check = health.self_check()
    for key in (
        "health_mutates_system",
        "automatic_repair",
        "repair_execution_available",
        "privilege_elevation_available",
        "network_required",
        "coverage_promoted",
        "authority_expanded",
    ):
        assert self_check[key] is False


def test_b114_validator_rejects_coverage_or_authority_tamper() -> None:
    report = health.evaluate_health(_healthy())
    broken = copy.deepcopy(report)
    broken["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b114:coverage_changed" in health.validate_health_report(broken)

    broken = copy.deepcopy(report)
    broken["non_execution_boundary"]["automatic_repair"] = True
    failures = health.validate_health_report(broken)
    assert "b114:non_execution_boundary_invalid" in failures or "b114:mutation_or_authority_enabled" in failures


def test_b114_validator_rejects_status_promotion_over_critical_failure() -> None:
    facts = _healthy()
    facts["runtime_identity_valid"] = False
    report = health.evaluate_health(facts)
    report["overall_status"] = health.READY
    report["ready_to_start"] = True
    assert "b114:overall_status_not_derived" in health.validate_health_report(report)


def test_b114_desktop_entry_exposes_health_probe_and_keeps_canonical_ui_binding() -> None:
    source = ENTRY.read_text(encoding="utf-8")
    assert 'parser.add_argument("--health-json", action="store_true")' in source
    assert "beta11_first_run_health as first_run_health" in source
    assert "beta10_trust_center_ui as product_ui" in source
    assert "product_ui.TrustCenterWindow" in source
    assert "first_run_health.live_health_report()" in source
    assert "automatic_repair_available" in source


def test_b114_live_windows_health_is_read_only_and_not_blocked() -> None:
    facts = health.collect_environment_facts()
    assert facts["platform_system"] == "Windows"
    assert facts["pointer_bits"] == 64
    assert facts["python_version"][:2] == [3, 12]
    assert all(facts["required_modules"].values())
    assert facts["runtime_identity_valid"] is True
    assert facts["trust_center_snapshot_valid"] is True

    report = health.evaluate_health(facts)
    assert health.validate_health_report(report) == ()
    assert report["overall_status"] in {health.READY, health.DEGRADED}
    assert report["ready_to_start"] is True
    assert not any(report["non_execution_boundary"].values())
