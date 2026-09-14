from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel.home_threat_cards_ui import B64SmartScanPage


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _result(
    *,
    confidence: float | None = 0.91,
    state: str = smart.STATE_COMPLETED_FINDINGS,
    coverage: str = smart.COVERAGE_COMPLETE,
) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b64-fixture-finding",
        title="Fixture suspicious item",
        severity=smart.SEVERITY_HIGH,
        category="heuristic",
        reason="Harmless B6-4 fixture evidence",
        source_check_id="files",
        path=r"C:\Fixture\sample.test",
        confidence=confidence,
        evidence={"hash": "ABC", "signals": ["fixture"]},
    )
    plan = smart.SmartScanPlan(
        provider_name="b64-fixture-provider",
        provider_profile="b64-fixture-v1",
        provider_provenance="b64_unit_test",
        checks=(
            smart.SmartScanCheck(
                "files",
                "File checks",
                "Harmless B6-4 fixture",
                True,
                "b64_unit_test",
            ),
        ),
        raw={"scope": "fixture"},
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED if state != smart.STATE_CANCELLED else smart.CHECK_CANCELLED,
        "Fixture result",
        findings=(finding,),
        evidence={"source_evidence": "preserved"},
    )
    return smart.SmartScanResult(
        session_id="session-b64",
        correlation_id="correlation-b64",
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
        recommendation="Review the findings before taking action.",
        provider_name="b64-fixture-provider",
        provider_profile="b64-fixture-v1",
        provider_provenance="b64_unit_test",
        plan=plan,
        check_results=(check,),
        raw_evidence={"provider_raw": {"fixture": True}},
    )


def test_b64_profile_and_static_authority_contract() -> None:
    assert threat.PROFILE == "v0.11.0-beta.6-b64"
    assert threat.SCHEMA == "bc-sentinel-beta6-threat-card-v1"
    contract = threat.validate_b64_presentation_contract()
    assert contract["passed"] is True
    assert contract["severity_mutation"] is False
    assert contract["confidence_inference"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False
    assert contract["guided_resolution_enabled"] is False


def test_threat_card_preserves_canonical_severity_confidence_and_order() -> None:
    result = _result(confidence=0.91)
    cards = threat.build_threat_cards(result)
    assert len(cards) == 1
    card = cards[0]
    assert card.finding_id == result.findings[0].finding_id
    assert card.severity == smart.SEVERITY_HIGH
    assert card.severity_label == "Alta"
    assert card.severity_role == "danger"
    assert card.confidence == 0.91
    assert card.confidence_label == "91%"


def test_missing_confidence_is_not_inferred() -> None:
    card = threat.build_threat_cards(_result(confidence=None))[0]
    assert card.confidence is None
    assert card.confidence_label == "Non disponibile"
    assert card.advanced_details["finding"]["confidence"] is None


def test_advanced_details_preserve_exact_finding_source_and_provider_evidence() -> None:
    result = _result()
    card = threat.build_threat_cards(result)[0]
    advanced = card.advanced_details
    assert advanced["finding"] == result.findings[0].to_dict()
    assert advanced["source_check_result"] == result.check_results[0].to_dict()
    assert advanced["provider_name"] == result.provider_name
    assert advanced["provider_profile"] == result.provider_profile
    assert advanced["provider_provenance"] == result.provider_provenance
    assert advanced["scan_raw_evidence"] == result.raw_evidence
    assert advanced["automatic_quarantine"] is False
    assert advanced["automatic_repair"] is False
    assert advanced["automatic_destructive_action"] is False


def test_cancelled_incomplete_scan_keeps_existing_finding_without_false_complete_claim() -> None:
    result = _result(state=smart.STATE_CANCELLED, coverage=smart.COVERAGE_INCOMPLETE)
    card = threat.build_threat_cards(result)[0]
    assert card.advanced_details["scan_state"] == smart.STATE_CANCELLED
    assert card.advanced_details["coverage"] == smart.COVERAGE_INCOMPLETE
    assert card.finding_id == "b64-fixture-finding"


def test_b64_scan_page_renders_card_and_per_card_advanced_details() -> None:
    app = _app()
    page = B64SmartScanPage(provider_available=True)
    result = _result()
    page.set_result(result)
    page.show()
    app.processEvents()

    assert page.threat_section.isVisible()
    assert len(page.threat_card_widgets) == 1
    widget = page.threat_card_widgets[0]
    assert widget.title_label.text() == "Fixture suspicious item"
    assert "HIGH" in widget.severity_badge.text()
    assert "91%" in widget.findChild(type(widget.severity_badge), "ThreatCardMeta").text()
    assert widget.advanced_text.isHidden()
    widget.advanced_button.setChecked(True)
    app.processEvents()
    assert widget.advanced_text.isVisible()
    assert '"provider_provenance": "b64_unit_test"' in widget.advanced_text.toPlainText()

    page.close()


def test_b64_scan_page_keeps_scan_level_advanced_details_alongside_cards() -> None:
    app = _app()
    page = B64SmartScanPage(provider_available=True)
    page.set_result(_result())
    page.show()
    app.processEvents()
    assert page.advanced_button.isVisible()
    assert len(page.threat_card_widgets) == 1
    page.close()
