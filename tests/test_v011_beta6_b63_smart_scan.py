from __future__ import annotations

import threading
import time

import pytest

from sentinel import home_smart_scan as smart


class FixtureProvider:
    def __init__(
        self,
        *,
        findings: tuple[smart.SmartScanFinding, ...] = (),
        unavailable_second: bool = False,
        raise_error: bool = False,
    ) -> None:
        self.findings = findings
        self.unavailable_second = unavailable_second
        self.raise_error = raise_error
        self.plan_calls = 0
        self.run_calls = 0

    def capabilities(self):
        return {
            "available": True,
            "accepted": True,
            "provider_name": "fixture-provider",
            "provider_profile": "fixture-v1",
            "provider_provenance": "unit_test",
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }

    def build_plan(self) -> smart.SmartScanPlan:
        self.plan_calls += 1
        return smart.SmartScanPlan(
            provider_name="fixture-provider",
            provider_profile="fixture-v1",
            provider_provenance="unit_test",
            checks=(
                smart.SmartScanCheck("files", "File checks", "Fixture file check", True, "unit_test"),
                smart.SmartScanCheck(
                    "behavior",
                    "Behavior checks",
                    "Fixture behavior check",
                    not self.unavailable_second,
                    "unit_test",
                ),
            ),
            raw={"fixture": True},
        )

    def run(self, plan, progress_callback, cancel_check):
        self.run_calls += 1
        if self.raise_error:
            raise RuntimeError("fixture provider error")
        progress_callback(smart.SmartScanProgress(20, 0, 2, "files", "Checking files"))
        results = [
            smart.SmartScanCheckResult(
                "files",
                smart.CHECK_COMPLETED,
                "File check complete",
                findings=self.findings,
                evidence={"raw_file_fixture": 1},
            )
        ]
        if self.unavailable_second:
            results.append(
                smart.SmartScanCheckResult(
                    "behavior",
                    smart.CHECK_UNAVAILABLE,
                    "Behavior provider unavailable",
                    evidence={"reason": "fixture_unavailable"},
                )
            )
        else:
            results.append(
                smart.SmartScanCheckResult(
                    "behavior",
                    smart.CHECK_COMPLETED,
                    "Behavior check complete",
                    evidence={"raw_behavior_fixture": 1},
                )
            )
        progress_callback(smart.SmartScanProgress(100, 2, 2, "behavior", "Done"))
        return smart.SmartScanProviderResult(tuple(results), {"provider_raw": "preserved"})


class BlockingProvider(FixtureProvider):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()

    def run(self, plan, progress_callback, cancel_check):
        self.run_calls += 1
        self.entered.set()
        progress_callback(smart.SmartScanProgress(10, 0, 2, "files", "Running"))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if cancel_check():
                return smart.SmartScanProviderResult(
                    (
                        smart.SmartScanCheckResult(
                            "files", smart.CHECK_CANCELLED, "Cancelled by user"
                        ),
                    ),
                    {"cancelled": True},
                )
            time.sleep(0.01)
        return super().run(plan, progress_callback, cancel_check)


def _finding() -> smart.SmartScanFinding:
    return smart.SmartScanFinding(
        finding_id="fixture-finding-1",
        title="Fixture suspicious item",
        severity=smart.SEVERITY_HIGH,
        category="fixture",
        reason="Harmless test evidence",
        source_check_id="files",
        path=r"C:\Fixture\sample.test",
        confidence=0.91,
        evidence={"hash": "ABC", "fixture": True},
    )


def test_profile_schema_and_static_safety_contract_are_b63() -> None:
    assert smart.PROFILE == "v0.11.0-beta.6-b63"
    assert smart.SCHEMA == "bc-sentinel-beta6-smart-scan-v1"
    contract = smart.validate_b63_safety_contract()
    assert contract["passed"] is True
    assert contract["startup_scan_dispatch"] is False
    assert contract["navigation_scan_dispatch"] is False
    assert contract["refresh_scan_dispatch"] is False
    assert contract["full_scan_enabled"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False


def test_default_provider_is_truthfully_unavailable_and_never_runs() -> None:
    coordinator = smart.SmartScanCoordinator()
    assert coordinator.state == smart.STATE_IDLE
    assert coordinator.is_available() is False
    result = coordinator.run_sync()
    assert result.state == smart.STATE_INCOMPLETE
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert result.findings == ()
    assert result.automatic_quarantine is False
    assert result.automatic_repair is False
    assert result.automatic_destructive_action is False


def test_constructing_coordinator_does_not_plan_or_run() -> None:
    provider = FixtureProvider()
    coordinator = smart.SmartScanCoordinator(provider)
    assert coordinator.state == smart.STATE_IDLE
    assert provider.plan_calls == 0
    assert provider.run_calls == 0
    assert coordinator.is_available() is True
    assert provider.plan_calls == 0
    assert provider.run_calls == 0


def test_complete_zero_finding_provider_yields_completed_clean() -> None:
    provider = FixtureProvider()
    coordinator = smart.SmartScanCoordinator(provider)
    result = coordinator.run_sync()
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert result.completed_checks == 2
    assert result.total_checks == 2
    assert result.findings == ()
    assert result.highest_severity == smart.SEVERITY_INFO
    assert provider.plan_calls == 1
    assert provider.run_calls == 1


def test_findings_yield_completed_findings_and_preserve_raw_evidence() -> None:
    provider = FixtureProvider(findings=(_finding(),))
    result = smart.SmartScanCoordinator(provider).run_sync()
    assert result.state == smart.STATE_COMPLETED_FINDINGS
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert len(result.findings) == 1
    assert result.highest_severity == smart.SEVERITY_HIGH
    payload = result.to_dict()
    assert payload["findings"][0]["evidence"] == {"hash": "ABC", "fixture": True}
    assert payload["raw_evidence"]["provider_result"] == {"provider_raw": "preserved"}
    assert payload["provider_provenance"] == "unit_test"


def test_unavailable_planned_check_can_never_be_reported_clean() -> None:
    result = smart.SmartScanCoordinator(FixtureProvider(unavailable_second=True)).run_sync()
    assert result.state == smart.STATE_INCOMPLETE
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert any(item.status == smart.CHECK_UNAVAILABLE for item in result.check_results)


def test_provider_exception_can_never_be_reported_clean() -> None:
    result = smart.SmartScanCoordinator(FixtureProvider(raise_error=True)).run_sync()
    assert result.state == smart.STATE_FAILED
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert "fixture provider error" in str(result.raw_evidence["error"])


def test_progress_is_monotonic_and_clamped_by_contract() -> None:
    class RegressiveProvider(FixtureProvider):
        def run(self, plan, progress_callback, cancel_check):
            self.run_calls += 1
            progress_callback(smart.SmartScanProgress(70, 1, 2, "files", "First"))
            progress_callback(smart.SmartScanProgress(35, 1, 2, "behavior", "Regressive provider"))
            return smart.SmartScanProviderResult(
                (
                    smart.SmartScanCheckResult("files", smart.CHECK_COMPLETED, "ok"),
                    smart.SmartScanCheckResult("behavior", smart.CHECK_COMPLETED, "ok"),
                )
            )

    seen: list[int] = []
    result = smart.SmartScanCoordinator(RegressiveProvider()).run_sync(
        lambda progress: seen.append(progress.percent)
    )
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert seen == sorted(seen)
    assert all(0 <= value <= 100 for value in seen)


def test_duplicate_start_is_refused_while_running() -> None:
    provider = BlockingProvider()
    coordinator = smart.SmartScanCoordinator(provider)
    holder: list[smart.SmartScanResult] = []
    thread = threading.Thread(target=lambda: holder.append(coordinator.run_sync()), daemon=True)
    thread.start()
    assert provider.entered.wait(timeout=1.0)
    with pytest.raises(RuntimeError, match="smart_scan_already_running"):
        coordinator.run_sync()
    assert coordinator.request_cancel() is True
    thread.join(timeout=2.0)
    assert holder and holder[0].state == smart.STATE_CANCELLED


def test_explicit_cancellation_is_terminal_and_non_destructive() -> None:
    provider = BlockingProvider()
    coordinator = smart.SmartScanCoordinator(provider)
    holder: list[smart.SmartScanResult] = []
    thread = threading.Thread(target=lambda: holder.append(coordinator.run_sync()), daemon=True)
    thread.start()
    assert provider.entered.wait(timeout=1.0)
    assert coordinator.request_cancel() is True
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    result = holder[0]
    assert result.state == smart.STATE_CANCELLED
    assert result.automatic_quarantine is False
    assert result.automatic_repair is False
    assert result.automatic_destructive_action is False


def test_provider_requesting_destructive_authority_is_rejected_before_run() -> None:
    class UnsafeProvider(FixtureProvider):
        def capabilities(self):
            payload = dict(super().capabilities())
            payload["automatic_quarantine"] = True
            return payload

    provider = UnsafeProvider()
    coordinator = smart.SmartScanCoordinator(provider)
    contract = coordinator.capabilities()
    assert contract["passed"] is False
    assert "forbidden_provider_authority:automatic_quarantine" in contract["failures"]
    result = coordinator.run_sync()
    assert result.state == smart.STATE_FAILED
    assert provider.run_calls == 0


def test_provider_cannot_return_unplanned_check() -> None:
    class ExtraResultProvider(FixtureProvider):
        def run(self, plan, progress_callback, cancel_check):
            self.run_calls += 1
            return smart.SmartScanProviderResult(
                (
                    smart.SmartScanCheckResult("files", smart.CHECK_COMPLETED, "ok"),
                    smart.SmartScanCheckResult("behavior", smart.CHECK_COMPLETED, "ok"),
                    smart.SmartScanCheckResult("surprise", smart.CHECK_COMPLETED, "not planned"),
                )
            )

    result = smart.SmartScanCoordinator(ExtraResultProvider()).run_sync()
    assert result.state == smart.STATE_FAILED
    assert result.raw_evidence["error"] == "provider_returned_unplanned_checks"
    assert result.raw_evidence["unexpected"] == ["surprise"]


def test_finding_confidence_and_source_are_validated() -> None:
    with pytest.raises(ValueError, match="confidence_out_of_range"):
        smart.SmartScanFinding(
            finding_id="x",
            title="x",
            severity=smart.SEVERITY_LOW,
            category="fixture",
            reason="fixture",
            source_check_id="files",
            confidence=1.5,
        ).validate()

    finding = _finding()
    with pytest.raises(ValueError, match="finding_source_mismatch"):
        smart.SmartScanCheckResult(
            "behavior", smart.CHECK_COMPLETED, "bad source", findings=(finding,)
        ).validate()


def test_terminal_result_serialization_preserves_safety_flags_and_plan() -> None:
    payload = smart.SmartScanCoordinator(FixtureProvider(findings=(_finding(),))).run_sync().to_dict()
    assert payload["schema"] == smart.SCHEMA
    assert payload["profile"] == smart.PROFILE
    assert payload["automatic_quarantine"] is False
    assert payload["automatic_repair"] is False
    assert payload["automatic_destructive_action"] is False
    assert [item["check_id"] for item in payload["plan"]["checks"]] == ["files", "behavior"]
