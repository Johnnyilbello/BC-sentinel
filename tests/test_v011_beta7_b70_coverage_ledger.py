from __future__ import annotations

from copy import deepcopy

from sentinel import coverage_ledger as ledger


def _valid_verified() -> dict:
    return {
        "scenario_id": "TEST-001",
        "technique": "T1059",
        "subtechnique": "T1059.001",
        "scenario": "Controlled PowerShell fixture",
        "verification_status": "VERIFIED",
        "detected": True,
        "correlated": True,
        "blocked": False,
        "recovered": None,
        "verified": True,
        "false_positive_status": "PASS",
        "time_to_detection": 0.4,
        "time_to_interruption": None,
        "evidence_quality": "HIGH",
        "evidence_refs": ["acceptance/test-001.json"],
        "last_verified_build": "0123456789abcdef0123456789abcdef01234567",
        "platform_profile": "windows-x64-controlled-fixture",
        "notes": "Deterministic fixture.",
    }


def _payload(scenarios: list[dict]) -> dict:
    return {
        "schema": ledger.SCHEMA,
        "profile": ledger.PROFILE,
        "source_checkpoint": "checkpoint/v011-beta6-b67-pass",
        "source_checkpoint_commit": "eb08758a304eb838d08af890ef9c4786264afbc0",
        "scenarios": scenarios,
    }


def test_bundled_coverage_ledger_is_valid_and_claim_free() -> None:
    result = ledger.validate_file(ledger.default_ledger_path())
    assert result.passed is True
    assert result.scenario_count == 6
    assert result.summary["PLANNED"] == 6
    assert result.summary["VERIFIED"] == 0
    assert result.summary["PARTIAL"] == 0
    assert result.summary["GAP"] == 0


def test_positive_claim_requires_build_evidence_and_quality() -> None:
    scenario = _valid_verified()
    scenario["last_verified_build"] = None
    scenario["evidence_refs"] = []
    scenario["evidence_quality"] = "NONE"
    result = ledger.validate_ledger(_payload([scenario]))
    assert result.passed is False
    assert any("positive_claim_without_build_provenance" in failure for failure in result.failures)
    assert any("positive_claim_without_evidence" in failure for failure in result.failures)
    assert any("positive_claim_without_evidence_quality" in failure for failure in result.failures)


def test_planned_scenario_cannot_silently_claim_success() -> None:
    scenario = _valid_verified()
    scenario["verification_status"] = "PLANNED"
    result = ledger.validate_ledger(_payload([scenario]))
    assert result.passed is False
    assert any("planned_scenario_must_be_unevaluated" in failure for failure in result.failures)


def test_duplicate_scenario_id_is_rejected() -> None:
    first = _valid_verified()
    second = deepcopy(first)
    result = ledger.validate_ledger(_payload([first, second]))
    assert result.passed is False
    assert any("duplicate_scenario_id:TEST-001" in failure for failure in result.failures)


def test_verified_scenario_requires_detection_true() -> None:
    scenario = _valid_verified()
    scenario["detected"] = False
    result = ledger.validate_ledger(_payload([scenario]))
    assert result.passed is False
    assert any("verified_requires_detected_true" in failure for failure in result.failures)


def test_gap_requires_real_evidence_not_empty_claim() -> None:
    scenario = _valid_verified()
    scenario.update(
        {
            "verification_status": "GAP",
            "detected": False,
            "correlated": False,
            "blocked": False,
            "recovered": False,
            "verified": False,
            "evidence_refs": ["acceptance/gap.json"],
            "evidence_quality": "HIGH",
        }
    )
    result = ledger.validate_ledger(_payload([scenario]))
    assert result.passed is True
    assert result.summary["GAP"] == 1


def test_self_check_preserves_beta7_no_authority_expansion() -> None:
    result = ledger.self_check()
    assert result["passed"] is True
    assert result["read_only"] is True
    assert result["execution_authority_added"] is False
    assert result["unsupported_positive_claims_allowed"] is False
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False
    assert result["general_home_execution_authorized"] is False
