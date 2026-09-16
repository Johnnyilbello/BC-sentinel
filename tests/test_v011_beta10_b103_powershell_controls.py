from __future__ import annotations

from copy import deepcopy

from sentinel import beta10_powershell_controls as b103


def _row(control_id: str, *, sessions: int, admin: bool = False, bulk: bool = False) -> dict:
    return {
        "control_id": control_id,
        "live_observation": True,
        "channel": "Windows PowerShell",
        "provider": "PowerShell",
        "session_count": sessions,
        "start_event_count": sessions,
        "stop_event_count": sessions,
        "unique_process_count": sessions,
        "duration_seconds": 2.5 if sessions >= 6 else 0.5,
        "known_admin_automation": admin,
        "user_initiated_bulk_operation": bulk,
        "started_at_utc": "2026-09-16T15:00:00+00:00",
        "completed_at_utc": "2026-09-16T15:00:03+00:00",
        "cleanup_state": "EXITED",
    }


def _evidence() -> dict:
    return {
        "schema": b103.SCHEMA,
        "source": b103.SOURCE,
        "controls": [
            _row("positive-powershell-burst", sessions=8),
            _row("administrative-powershell-burst", sessions=8, admin=True, bulk=True),
            _row("benign-powershell-session", sessions=1),
        ],
        "boundaries": dict(b103.BOUNDARIES),
    }


def test_b103_promotes_only_powershell_and_preserves_ransomware_verified():
    report = b103.summarize(_evidence())
    assert report["passed"] is True
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    statuses = {row["scenario_id"]: row["status"] for row in report["coverage_decisions"]}
    assert statuses["B7-POWERSHELL-001"] == "VERIFIED"
    assert statuses["B7-RANSOMWARE-001"] == "VERIFIED"
    assert all(statuses[x] == "PARTIAL" for x in (
        "B7-PERSISTENCE-001", "B7-DEFENSE-EVASION-001", "B7-C2-DNS-001", "B7-CREDENTIAL-001"
    ))


def test_b103_control_outcomes_are_positive_review_benign():
    report = b103.summarize(_evidence())
    outcomes = {key: value["outcome"] for key, value in report["control_results"].items()}
    assert outcomes == {
        "positive-powershell-burst": "DETECTED",
        "administrative-powershell-burst": "REVIEW_REQUIRED",
        "benign-powershell-session": "NO_MATCH",
    }
    assert report["detector_to_security_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True


def test_b103_never_reads_powershell_content_or_expands_authority():
    report = b103.summarize(_evidence())
    assert report["powershell_content_read"] is False
    assert report["synthetic_fallback_used"] is False
    assert report["broad_powershell_protection_claimed"] is False
    assert report["broad_protection_claimed"] is False
    assert report["authority_expanded"] is False
    assert report["boundaries"]["event_message_read"] is False
    assert report["boundaries"]["event_payload_read"] is False
    assert report["boundaries"]["event_properties_read"] is False
    assert report["boundaries"]["powershell_command_read"] is False
    assert report["boundaries"]["powershell_script_read"] is False
    assert report["boundaries"]["remediation_authority"] is False
    assert report["boundaries"]["product_process_termination_authority"] is False


def test_b103_fails_closed_if_positive_burst_is_too_small():
    data = _evidence()
    data["controls"][0]["session_count"] = 2
    data["controls"][0]["start_event_count"] = 2
    data["controls"][0]["stop_event_count"] = 2
    data["controls"][0]["unique_process_count"] = 2
    report = b103.summarize(data)
    assert report["passed"] is False
    assert report["coverage_summary"]["VERIFIED"] == 1
    power = next(x for x in report["coverage_decisions"] if x["scenario_id"] == "B7-POWERSHELL-001")
    assert power["status"] == "PARTIAL"


def test_b103_admin_suppressors_prevent_detected_outcome():
    data = _evidence()
    result = b103.detect_control(data["controls"][1])
    assert result["score"] >= 6
    assert result["outcome"] == "REVIEW_REQUIRED"
    assert result["suppressor"] is True


def test_b103_rejects_payload_boundary_or_unexpected_fields():
    data = _evidence()
    data["boundaries"]["event_payload_read"] = True
    assert "evidence:boundary_invalid" in b103.validate_evidence(data)

    data = _evidence()
    data["controls"][0]["command"] = "should-never-exist"
    assert "control[0]:fields_invalid" in b103.validate_evidence(data)


def test_b103_persistence_remains_partial_with_explicit_blocker():
    report = b103.summarize(_evidence())
    persistence = next(x for x in report["coverage_decisions"] if x["scenario_id"] == "B7-PERSISTENCE-001")
    assert persistence["status"] == "PARTIAL"
    assert "persistence detector source" in persistence["limitation"]
