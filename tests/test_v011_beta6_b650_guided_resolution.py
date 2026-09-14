from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QPushButton

from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel.home_guided_resolution_ui import B65SmartScanPage, B65ThreatCardWidget


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _result(
    *,
    confidence: float | None = 0.82,
    state: str = smart.STATE_COMPLETED_FINDINGS,
    coverage: str = smart.COVERAGE_COMPLETE,
) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b650-fixture-finding",
        title="Guided resolution fixture",
        severity=smart.SEVERITY_HIGH,
        category="heuristic",
        reason="Harmless B6-5.0 fixture evidence",
        source_check_id="files",
        path=r"C:\Fixture\guided.test",
        confidence=confidence,
        evidence={"fixture": True, "signals": ["b650"]},
    )
    plan = smart.SmartScanPlan(
        provider_name="b650-fixture-provider",
        provider_profile="b650-fixture-v1",
        provider_provenance="b650_unit_test",
        checks=(
            smart.SmartScanCheck("files", "Files", "Fixture", True, "b650_unit_test"),
        ),
        raw={"scope": "fixture"},
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_CANCELLED if state == smart.STATE_CANCELLED else smart.CHECK_COMPLETED,
        "Fixture result",
        findings=(finding,),
        evidence={"source_evidence": "preserved"},
    )
    return smart.SmartScanResult(
        session_id="b650-session",
        correlation_id="b650-correlation",
        state=state,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=coverage,
        completed_checks=1 if coverage == smart.COVERAGE_COMPLETE else 0,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_HIGH,
        summary="Fixture summary",
        recommendation="Review the finding.",
        provider_name="b650-fixture-provider",
        provider_profile="b650-fixture-v1",
        provider_provenance="b650_unit_test",
        plan=plan,
        check_results=(check,),
        raw_evidence={"provider_raw": {"fixture": True}},
    )


def _guidance(**kwargs) -> guided.GuidedResolutionModel:
    card = threat.build_threat_cards(_result(**kwargs))[0]
    return guided.build_guided_resolution(card)


def test_b650_profile_and_report_only_authority_contract() -> None:
    assert guided.PROFILE == "v0.11.0-beta.6-b65.0-guided-resolution"
    assert guided.SCHEMA == "bc-sentinel-beta6-guided-resolution-v1"
    contract = guided.validate_b650_guided_resolution_contract()
    assert contract["passed"] is True
    assert contract["authority"] == guided.AUTHORITY_REPORT_ONLY
    assert contract["remediation_provider_boundary_verified"] is False
    assert contract["execution_available"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False
    assert contract["delete_authorized"] is False
    assert contract["process_termination_authorized"] is False
    assert contract["trust_mutation_authorized"] is False
    assert contract["available_capabilities"] == [guided.ACTION_REVIEW_DETAILS]


def test_guidance_preserves_canonical_severity_and_confidence_without_authorizing_action() -> None:
    model = _guidance(confidence=0.82)
    assert model.canonical_severity == smart.SEVERITY_HIGH
    assert model.canonical_confidence == 0.82
    assert model.review_state == guided.REVIEW_REQUIRED
    assert model.confidence_state == guided.CONFIDENCE_PRESENT
    assert model.authority_state == guided.AUTHORITY_REPORT_ONLY
    assert model.execution_available is False
    assert model.provider_boundary_verified is False
    assert model.confirmation_required_for_mutation is True
    assert model.rollback_required_for_mutation is True
    assert model.advanced_details["confidence_gate"]["execution_authorized"] is False


def test_missing_confidence_remains_unavailable_and_is_not_inferred() -> None:
    model = _guidance(confidence=None)
    assert model.canonical_confidence is None
    assert model.confidence_state == guided.CONFIDENCE_UNAVAILABLE
    assert "canonical_confidence_unavailable" in model.reasons
    assert model.advanced_details["threat_card"]["confidence"] is None
    assert model.advanced_details["confidence_gate"]["confidence"] is None


def test_incomplete_or_cancelled_scan_fails_closed_to_evidence_incomplete() -> None:
    model = _guidance(
        confidence=0.82,
        state=smart.STATE_CANCELLED,
        coverage=smart.COVERAGE_INCOMPLETE,
    )
    assert model.review_state == guided.EVIDENCE_INCOMPLETE
    assert model.evidence_strength == guided.EVIDENCE_PARTIAL
    assert "scan_coverage_not_complete" in model.reasons
    assert "scan_state_cancelled" in model.reasons
    assert model.execution_available is False


def test_only_non_mutating_review_capability_is_available() -> None:
    model = _guidance()
    available = [item for item in model.capabilities if item.available]
    assert len(available) == 1
    assert available[0].capability_id == guided.ACTION_REVIEW_DETAILS
    assert available[0].mutates_system is False
    assert all(not item.available for item in model.capabilities if item.mutates_system)


def test_advanced_details_preserve_exact_b64_card_and_gate_inputs() -> None:
    result = _result(confidence=0.82)
    card = threat.build_threat_cards(result)[0]
    model = guided.build_guided_resolution(card)
    assert model.advanced_details["threat_card"] == card.to_dict()
    gate = model.advanced_details["confidence_gate"]
    assert gate["severity"] == card.severity
    assert gate["confidence"] == card.confidence
    assert gate["reversibility"] == guided.REVERSIBILITY_UNVERIFIED
    assert gate["potential_damage"] == guided.POTENTIAL_DAMAGE_UNDEFINED
    assert gate["provider_boundary_verified"] is False
    assert gate["execution_authorized"] is False


def test_b650_scan_page_renders_passive_guidance_without_mutation_controls() -> None:
    app = _app()
    page = B65SmartScanPage(provider_available=True)
    page.set_result(_result())
    page.show()
    app.processEvents()

    assert page.threat_section.isVisible()
    assert len(page.threat_card_widgets) == 1
    widget = page.threat_card_widgets[0]
    assert isinstance(widget, B65ThreatCardWidget)
    assert widget.resolution_model.execution_available is False
    assert widget.resolution_panel.isVisible()
    assert "REPORT_ONLY" in widget.resolution_panel.state_label.text()
    assert "Nessuna quarantena" in widget.resolution_panel.safety_label.text()

    button_texts = [button.text() for button in widget.findChildren(QPushButton)]
    assert "Metti in quarantena" not in button_texts
    assert "Ripara" not in button_texts
    assert "Elimina" not in button_texts
    assert "Termina processo" not in button_texts

    widget.resolution_panel.details_button.setChecked(True)
    app.processEvents()
    details = widget.resolution_panel.details_text.toPlainText()
    assert '"execution_authorized": false' in details
    assert '"automatic_destructive_action": false' in details
    page.close()
