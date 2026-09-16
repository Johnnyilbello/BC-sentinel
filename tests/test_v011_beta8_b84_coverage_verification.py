from __future__ import annotations

import copy
import json

from sentinel import beta8_coverage_baseline, beta8_coverage_verification


def test_b84_self_check_recomputes_six_partial_without_verified_claims() -> None:
    result = beta8_coverage_verification.self_check()
    assert result["passed"], result["failures"]
    assert result["summary"] == {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}
    assert result["scenario_count"] == 6
    assert result["accepted_detector_count"] == 3
    assert result["deterministic_recomputation"] is True
    assert result["synthetic_evidence_cannot_verify"] is True


def test_recomputation_preserves_order_and_binds_each_frozen_detector() -> None:
    result = beta8_coverage_verification.recompute()
    assert not result["failures"]
    assert tuple(item["scenario_id"] for item in result["scenarios"]) == (
        beta8_coverage_verification.EXPECTED_ORDER
    )
    assert result["accepted_detector_checkpoints"] == (
        beta8_coverage_verification.load_report()["accepted_detector_checkpoints"]
    )


def test_report_serialization_and_digest_are_stable() -> None:
    report = beta8_coverage_verification.load_report()
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert json.loads(encoded) == report
    assert beta8_coverage_verification.self_check()["report_digest"] == (
        beta8_coverage_verification.self_check()["report_digest"]
    )


def test_missing_detector_evidence_fails_closed_and_retains_gap() -> None:
    evidence = beta8_coverage_verification.collect_detector_evidence()
    evidence.pop("B7-CREDENTIAL-001")
    result = beta8_coverage_verification.recompute(detector_evidence=evidence)
    assert "B7-CREDENTIAL-001:evidence_missing" in result["failures"]
    credential = next(
        item for item in result["scenarios"]
        if item["scenario_id"] == "B7-CREDENTIAL-001"
    )
    assert credential["status"] == "GAP"


def test_nondeterministic_or_authorized_detector_evidence_is_rejected() -> None:
    evidence = beta8_coverage_verification.collect_detector_evidence()
    evidence["B7-RANSOMWARE-001"]["deterministic_serialization"] = False
    evidence["B7-RANSOMWARE-001"]["remediation_execution"] = True
    result = beta8_coverage_verification.recompute(detector_evidence=evidence)
    assert "B7-RANSOMWARE-001:deterministic_serialization_invalid" in result["failures"]
    assert "B7-RANSOMWARE-001:remediation_execution_must_be_false" in result["failures"]


def test_baseline_tampering_fails_closed() -> None:
    baseline = copy.deepcopy(beta8_coverage_baseline.load_baseline())
    baseline["scenarios"][0]["status"] = "VERIFIED"
    result = beta8_coverage_verification.recompute(baseline=baseline)
    assert any(item.startswith("baseline:") for item in result["failures"])


def test_report_cannot_claim_verified_or_authority() -> None:
    report = copy.deepcopy(beta8_coverage_verification.load_report())
    report["summary"] = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    report["remediation_execution"] = True
    failures = beta8_coverage_verification.validate_report(
        report, beta8_coverage_verification.recompute()
    )
    assert "report:summary_mismatch" in failures
    assert "report:summary_invalid" in failures
    assert "report:remediation_execution_must_be_false" in failures


def test_all_authority_flags_remain_false() -> None:
    result = beta8_coverage_verification.self_check()
    for field in beta8_coverage_verification.FALSE_AUTHORITY_FIELDS:
        assert result[field] is False
