from __future__ import annotations

"""B6-3 Smart Scan orchestration contract.

This module intentionally owns orchestration only. It does not invent a scanner,
quarantine files, terminate processes, repair the system, or grant new write
authority. A real scan can run only through an explicitly supplied provider that
implements the accepted read-only Smart Scan provider contract.
"""

from dataclasses import asdict, dataclass, field
from threading import Event, RLock
from time import monotonic, time
from typing import Callable, Final, Mapping, Protocol
from uuid import uuid4

PROFILE: Final[str] = "v0.11.0-beta.6-b63"
SCHEMA: Final[str] = "bc-sentinel-beta6-smart-scan-v1"

STATE_IDLE: Final[str] = "IDLE"
STATE_PLANNED: Final[str] = "PLANNED"
STATE_RUNNING: Final[str] = "RUNNING"
STATE_COMPLETED_CLEAN: Final[str] = "COMPLETED_CLEAN"
STATE_COMPLETED_FINDINGS: Final[str] = "COMPLETED_FINDINGS"
STATE_INCOMPLETE: Final[str] = "INCOMPLETE"
STATE_FAILED: Final[str] = "FAILED"
STATE_CANCELLED: Final[str] = "CANCELLED"

TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {
        STATE_COMPLETED_CLEAN,
        STATE_COMPLETED_FINDINGS,
        STATE_INCOMPLETE,
        STATE_FAILED,
        STATE_CANCELLED,
    }
)

CHECK_COMPLETED: Final[str] = "COMPLETED"
CHECK_UNAVAILABLE: Final[str] = "UNAVAILABLE"
CHECK_SKIPPED: Final[str] = "SKIPPED"
CHECK_FAILED: Final[str] = "FAILED"
CHECK_CANCELLED: Final[str] = "CANCELLED"
CHECK_STATUSES: Final[frozenset[str]] = frozenset(
    {CHECK_COMPLETED, CHECK_UNAVAILABLE, CHECK_SKIPPED, CHECK_FAILED, CHECK_CANCELLED}
)

SEVERITY_INFO: Final[str] = "INFO"
SEVERITY_LOW: Final[str] = "LOW"
SEVERITY_MEDIUM: Final[str] = "MEDIUM"
SEVERITY_HIGH: Final[str] = "HIGH"
SEVERITY_CRITICAL: Final[str] = "CRITICAL"
SEVERITIES: Final[tuple[str, ...]] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
_SEVERITY_RANK: Final[dict[str, int]] = {name: index for index, name in enumerate(SEVERITIES)}

COVERAGE_COMPLETE: Final[str] = "COMPLETE"
COVERAGE_INCOMPLETE: Final[str] = "INCOMPLETE"


@dataclass(frozen=True)
class SmartScanCheck:
    check_id: str
    label: str
    purpose: str
    available: bool
    provenance: str
    work_units: int = 1
    raw: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.check_id.strip():
            raise ValueError("smart_scan_check_id_required")
        if not self.label.strip():
            raise ValueError("smart_scan_check_label_required")
        if int(self.work_units) < 0:
            raise ValueError("smart_scan_work_units_must_be_non_negative")
        if not self.provenance.strip():
            raise ValueError("smart_scan_check_provenance_required")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SmartScanPlan:
    provider_name: str
    provider_profile: str
    provider_provenance: str
    checks: tuple[SmartScanCheck, ...]
    raw: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.provider_name.strip():
            raise ValueError("smart_scan_provider_name_required")
        if not self.provider_profile.strip():
            raise ValueError("smart_scan_provider_profile_required")
        if not self.provider_provenance.strip():
            raise ValueError("smart_scan_provider_provenance_required")
        seen: set[str] = set()
        for check in self.checks:
            check.validate()
            if check.check_id in seen:
                raise ValueError(f"smart_scan_duplicate_check:{check.check_id}")
            seen.add(check.check_id)

    @property
    def available_checks(self) -> tuple[SmartScanCheck, ...]:
        return tuple(check for check in self.checks if check.available)

    @property
    def unavailable_checks(self) -> tuple[SmartScanCheck, ...]:
        return tuple(check for check in self.checks if not check.available)

    def to_dict(self) -> dict:
        self.validate()
        return {
            "provider_name": self.provider_name,
            "provider_profile": self.provider_profile,
            "provider_provenance": self.provider_provenance,
            "checks": [check.to_dict() for check in self.checks],
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class SmartScanFinding:
    finding_id: str
    title: str
    severity: str
    category: str
    reason: str
    source_check_id: str
    path: str = ""
    process: str = ""
    indicator: str = ""
    confidence: float | None = None
    evidence: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("smart_scan_finding_id_required")
        if self.severity not in SEVERITIES:
            raise ValueError(f"smart_scan_unknown_severity:{self.severity}")
        if not self.source_check_id.strip():
            raise ValueError("smart_scan_finding_source_required")
        if self.confidence is not None and not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("smart_scan_confidence_out_of_range")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SmartScanCheckResult:
    check_id: str
    status: str
    summary: str
    findings: tuple[SmartScanFinding, ...] = field(default_factory=tuple)
    evidence: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.check_id.strip():
            raise ValueError("smart_scan_result_check_id_required")
        if self.status not in CHECK_STATUSES:
            raise ValueError(f"smart_scan_unknown_check_status:{self.status}")
        for finding in self.findings:
            finding.validate()
            if finding.source_check_id != self.check_id:
                raise ValueError("smart_scan_finding_source_mismatch")

    def to_dict(self) -> dict:
        self.validate()
        return {
            "check_id": self.check_id,
            "status": self.status,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class SmartScanProviderResult:
    check_results: tuple[SmartScanCheckResult, ...]
    raw_evidence: dict = field(default_factory=dict)

    def validate(self) -> None:
        seen: set[str] = set()
        for result in self.check_results:
            result.validate()
            if result.check_id in seen:
                raise ValueError(f"smart_scan_duplicate_result:{result.check_id}")
            seen.add(result.check_id)

    def to_dict(self) -> dict:
        self.validate()
        return {
            "check_results": [result.to_dict() for result in self.check_results],
            "raw_evidence": dict(self.raw_evidence),
        }


@dataclass(frozen=True)
class SmartScanProgress:
    percent: int
    completed_checks: int
    total_checks: int
    current_check_id: str = ""
    message: str = ""

    def validate(self) -> None:
        if not (0 <= int(self.percent) <= 100):
            raise ValueError("smart_scan_progress_out_of_range")
        if int(self.completed_checks) < 0 or int(self.total_checks) < 0:
            raise ValueError("smart_scan_progress_negative_counts")
        if int(self.completed_checks) > int(self.total_checks):
            raise ValueError("smart_scan_progress_completed_exceeds_total")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SmartScanResult:
    session_id: str
    correlation_id: str
    state: str
    started_at: float
    finished_at: float
    elapsed_ms: float
    coverage: str
    completed_checks: int
    total_checks: int
    findings: tuple[SmartScanFinding, ...]
    highest_severity: str
    summary: str
    recommendation: str
    provider_name: str
    provider_profile: str
    provider_provenance: str
    plan: SmartScanPlan
    check_results: tuple[SmartScanCheckResult, ...]
    raw_evidence: dict
    automatic_quarantine: bool = False
    automatic_repair: bool = False
    automatic_destructive_action: bool = False

    def validate(self) -> None:
        if self.state not in TERMINAL_STATES:
            raise ValueError(f"smart_scan_result_not_terminal:{self.state}")
        if self.coverage not in {COVERAGE_COMPLETE, COVERAGE_INCOMPLETE}:
            raise ValueError(f"smart_scan_unknown_coverage:{self.coverage}")
        if self.highest_severity not in SEVERITIES:
            raise ValueError(f"smart_scan_unknown_highest_severity:{self.highest_severity}")
        if self.automatic_quarantine or self.automatic_repair or self.automatic_destructive_action:
            raise ValueError("smart_scan_destructive_authority_forbidden")
        self.plan.validate()
        for finding in self.findings:
            finding.validate()
        for result in self.check_results:
            result.validate()

    def to_dict(self) -> dict:
        self.validate()
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "coverage": self.coverage,
            "completed_checks": self.completed_checks,
            "total_checks": self.total_checks,
            "findings_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "highest_severity": self.highest_severity,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "provider_name": self.provider_name,
            "provider_profile": self.provider_profile,
            "provider_provenance": self.provider_provenance,
            "plan": self.plan.to_dict(),
            "check_results": [result.to_dict() for result in self.check_results],
            "raw_evidence": dict(self.raw_evidence),
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }


class SmartScanProvider(Protocol):
    def capabilities(self) -> Mapping[str, object]: ...

    def build_plan(self) -> SmartScanPlan: ...

    def run(
        self,
        plan: SmartScanPlan,
        progress_callback: Callable[[SmartScanProgress], None],
        cancel_check: Callable[[], bool],
    ) -> SmartScanProviderResult: ...


class UnavailableSmartScanProvider:
    """Fail-closed default while the full live runtime bridge is not synchronized."""

    name = "BC Sentinel live runtime"
    profile = "unavailable-live-provider"
    provenance = "github_delta_runtime_boundary"

    def __init__(self, reason: str = "live_runtime_provider_not_synchronized") -> None:
        self.reason = str(reason)

    def capabilities(self) -> Mapping[str, object]:
        return {
            "available": False,
            "accepted": False,
            "provider_name": self.name,
            "provider_profile": self.profile,
            "provider_provenance": self.provenance,
            "reason": self.reason,
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }

    def build_plan(self) -> SmartScanPlan:
        return SmartScanPlan(
            provider_name=self.name,
            provider_profile=self.profile,
            provider_provenance=self.provenance,
            checks=(
                SmartScanCheck(
                    check_id="live_runtime",
                    label="Live protection scan provider",
                    purpose="Run the accepted live Smart Scan checks from the complete Windows runtime.",
                    available=False,
                    provenance=self.provenance,
                    work_units=0,
                    raw={"reason": self.reason},
                ),
            ),
            raw={"reason": self.reason},
        )

    def run(
        self,
        plan: SmartScanPlan,
        progress_callback: Callable[[SmartScanProgress], None],
        cancel_check: Callable[[], bool],
    ) -> SmartScanProviderResult:
        raise RuntimeError(self.reason)


def _capability_contract(provider: SmartScanProvider) -> dict:
    raw = dict(provider.capabilities() or {})
    return {
        "available": raw.get("available") is True,
        "accepted": raw.get("accepted") is True,
        "provider_name": str(raw.get("provider_name") or ""),
        "provider_profile": str(raw.get("provider_profile") or ""),
        "provider_provenance": str(raw.get("provider_provenance") or ""),
        "reason": str(raw.get("reason") or ""),
        "automatic_quarantine": bool(raw.get("automatic_quarantine", False)),
        "automatic_repair": bool(raw.get("automatic_repair", False)),
        "automatic_destructive_action": bool(raw.get("automatic_destructive_action", False)),
        "raw": raw,
    }


def validate_provider_capabilities(provider: SmartScanProvider) -> dict:
    contract = _capability_contract(provider)
    failures: list[str] = []
    if not contract["provider_name"]:
        failures.append("provider_name_missing")
    if not contract["provider_profile"]:
        failures.append("provider_profile_missing")
    if not contract["provider_provenance"]:
        failures.append("provider_provenance_missing")
    for key in ("automatic_quarantine", "automatic_repair", "automatic_destructive_action"):
        if contract[key]:
            failures.append(f"forbidden_provider_authority:{key}")
    if contract["available"] and not contract["accepted"]:
        failures.append("available_provider_must_be_accepted")
    return {**contract, "passed": not failures, "failures": failures}


def _highest_severity(findings: tuple[SmartScanFinding, ...]) -> str:
    if not findings:
        return SEVERITY_INFO
    return max((finding.severity for finding in findings), key=lambda item: _SEVERITY_RANK[item])


def _recommendation(state: str) -> tuple[str, str]:
    if state == STATE_COMPLETED_CLEAN:
        return (
            "Smart Scan completed with no findings in the checks that ran.",
            "No immediate action is required from this scan. Keep protection enabled.",
        )
    if state == STATE_COMPLETED_FINDINGS:
        return (
            "Smart Scan completed and found items that need review.",
            "Review the findings before taking action.",
        )
    if state == STATE_INCOMPLETE:
        return (
            "Smart Scan could not complete every planned check.",
            "Review coverage and retry, or use System & Recovery when appropriate.",
        )
    if state == STATE_FAILED:
        return (
            "Smart Scan could not complete because the scan provider failed.",
            "Review the error details and retry when the provider is available.",
        )
    if state == STATE_CANCELLED:
        return (
            "Smart Scan was cancelled.",
            "No remediation was performed. Start a new scan when ready.",
        )
    raise ValueError(f"smart_scan_unknown_terminal_state:{state}")


class SmartScanCoordinator:
    """Thread-safe, GUI-independent Smart Scan state machine."""

    def __init__(self, provider: SmartScanProvider | None = None) -> None:
        self.provider: SmartScanProvider = provider or UnavailableSmartScanProvider()
        self._lock = RLock()
        self._cancel = Event()
        self._state = STATE_IDLE
        self._last_result: SmartScanResult | None = None
        self._active_session_id = ""
        self._last_progress = 0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def last_result(self) -> SmartScanResult | None:
        with self._lock:
            return self._last_result

    def capabilities(self) -> dict:
        return validate_provider_capabilities(self.provider)

    def is_available(self) -> bool:
        contract = self.capabilities()
        return bool(contract["passed"] and contract["available"] and contract["accepted"])

    def request_cancel(self) -> bool:
        with self._lock:
            if self._state != STATE_RUNNING:
                return False
            self._cancel.set()
            return True

    def _new_ids(self) -> tuple[str, str]:
        token = uuid4().hex.upper()
        return f"B63-{token[:16]}", token[16:36]

    def _progress_wrapper(
        self,
        callback: Callable[[SmartScanProgress], None] | None,
        total_checks: int,
    ) -> Callable[[SmartScanProgress], None]:
        def emit(progress: SmartScanProgress) -> None:
            progress.validate()
            normalized = SmartScanProgress(
                percent=max(self._last_progress, min(100, int(progress.percent))),
                completed_checks=min(max(0, int(progress.completed_checks)), max(0, total_checks)),
                total_checks=max(0, total_checks),
                current_check_id=str(progress.current_check_id or ""),
                message=str(progress.message or ""),
            )
            normalized.validate()
            self._last_progress = normalized.percent
            if callback is not None:
                callback(normalized)

        return emit

    def run_sync(
        self,
        progress_callback: Callable[[SmartScanProgress], None] | None = None,
    ) -> SmartScanResult:
        """Run exactly one explicitly requested Smart Scan in the calling worker thread."""
        with self._lock:
            if self._state == STATE_RUNNING:
                raise RuntimeError("smart_scan_already_running")
            self._cancel.clear()
            self._last_progress = 0
            session_id, correlation_id = self._new_ids()
            self._active_session_id = session_id
            self._state = STATE_PLANNED

        started_wall = time()
        started_perf = monotonic()
        capabilities = self.capabilities()

        try:
            plan = self.provider.build_plan()
            plan.validate()
        except Exception as exc:
            plan = UnavailableSmartScanProvider(
                reason=f"plan_error:{type(exc).__name__}"
            ).build_plan()
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_FAILED,
                plan=plan,
                check_results=(),
                raw_evidence={"error": f"{type(exc).__name__}: {exc}"},
            )

        if not capabilities["passed"]:
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_FAILED,
                plan=plan,
                check_results=(),
                raw_evidence={"provider_contract": capabilities},
            )

        if not (capabilities["available"] and capabilities["accepted"]):
            unavailable_results = tuple(
                SmartScanCheckResult(
                    check_id=check.check_id,
                    status=CHECK_UNAVAILABLE,
                    summary="Check unavailable through the current accepted provider boundary.",
                    evidence={"plan": check.to_dict()},
                )
                for check in plan.checks
            )
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_INCOMPLETE,
                plan=plan,
                check_results=unavailable_results,
                raw_evidence={"provider_contract": capabilities},
            )

        if not plan.checks or not plan.available_checks:
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_INCOMPLETE,
                plan=plan,
                check_results=tuple(
                    SmartScanCheckResult(
                        check_id=check.check_id,
                        status=CHECK_UNAVAILABLE,
                        summary="Planned check is unavailable.",
                        evidence={"plan": check.to_dict()},
                    )
                    for check in plan.checks
                ),
                raw_evidence={"reason": "no_available_checks"},
            )

        with self._lock:
            self._state = STATE_RUNNING
        emit = self._progress_wrapper(progress_callback, len(plan.checks))
        emit(SmartScanProgress(0, 0, len(plan.checks), message="Smart Scan started."))

        try:
            provider_result = self.provider.run(plan, emit, self._cancel.is_set)
            provider_result.validate()
        except Exception as exc:
            if self._cancel.is_set():
                return self._finish(
                    session_id=session_id,
                    correlation_id=correlation_id,
                    started_wall=started_wall,
                    started_perf=started_perf,
                    state=STATE_CANCELLED,
                    plan=plan,
                    check_results=(),
                    raw_evidence={"cancelled_during_provider_error": type(exc).__name__},
                )
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_FAILED,
                plan=plan,
                check_results=(),
                raw_evidence={"error": f"{type(exc).__name__}: {exc}"},
            )

        results_by_id = {item.check_id: item for item in provider_result.check_results}
        planned_ids = {check.check_id for check in plan.checks}
        unexpected = sorted(set(results_by_id) - planned_ids)
        if unexpected:
            return self._finish(
                session_id=session_id,
                correlation_id=correlation_id,
                started_wall=started_wall,
                started_perf=started_perf,
                state=STATE_FAILED,
                plan=plan,
                check_results=provider_result.check_results,
                raw_evidence={
                    "error": "provider_returned_unplanned_checks",
                    "unexpected": unexpected,
                    "provider": provider_result.raw_evidence,
                },
            )

        if self._cancel.is_set() or any(
            result.status == CHECK_CANCELLED for result in provider_result.check_results
        ):
            state = STATE_CANCELLED
        else:
            complete = (
                not plan.unavailable_checks
                and planned_ids == set(results_by_id)
                and all(results_by_id[check_id].status == CHECK_COMPLETED for check_id in planned_ids)
            )
            findings = tuple(
                finding
                for result in provider_result.check_results
                for finding in result.findings
            )
            if not complete:
                state = STATE_INCOMPLETE
            elif findings:
                state = STATE_COMPLETED_FINDINGS
            else:
                state = STATE_COMPLETED_CLEAN

        return self._finish(
            session_id=session_id,
            correlation_id=correlation_id,
            started_wall=started_wall,
            started_perf=started_perf,
            state=state,
            plan=plan,
            check_results=provider_result.check_results,
            raw_evidence={
                "provider_contract": capabilities,
                "provider_result": dict(provider_result.raw_evidence),
            },
        )

    def _finish(
        self,
        *,
        session_id: str,
        correlation_id: str,
        started_wall: float,
        started_perf: float,
        state: str,
        plan: SmartScanPlan,
        check_results: tuple[SmartScanCheckResult, ...],
        raw_evidence: dict,
    ) -> SmartScanResult:
        finished = time()
        findings = tuple(
            finding for result in check_results for finding in result.findings
        )
        completed = sum(1 for result in check_results if result.status == CHECK_COMPLETED)
        total = len(plan.checks)
        coverage = (
            COVERAGE_COMPLETE
            if state in {STATE_COMPLETED_CLEAN, STATE_COMPLETED_FINDINGS}
            else COVERAGE_INCOMPLETE
        )
        summary, recommendation = _recommendation(state)
        result = SmartScanResult(
            session_id=session_id,
            correlation_id=correlation_id,
            state=state,
            started_at=started_wall,
            finished_at=finished,
            elapsed_ms=round((monotonic() - started_perf) * 1000.0, 3),
            coverage=coverage,
            completed_checks=completed,
            total_checks=total,
            findings=findings,
            highest_severity=_highest_severity(findings),
            summary=summary,
            recommendation=recommendation,
            provider_name=plan.provider_name,
            provider_profile=plan.provider_profile,
            provider_provenance=plan.provider_provenance,
            plan=plan,
            check_results=check_results,
            raw_evidence=dict(raw_evidence),
            automatic_quarantine=False,
            automatic_repair=False,
            automatic_destructive_action=False,
        )
        result.validate()
        with self._lock:
            self._state = state
            self._last_result = result
            self._active_session_id = ""
        return result


def validate_b63_safety_contract(provider: SmartScanProvider | None = None) -> dict:
    """Static B6-3 authority contract; does not plan or run a scan."""
    selected = provider or UnavailableSmartScanProvider()
    capability = validate_provider_capabilities(selected)
    failures = list(capability["failures"])
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "provider_available": bool(capability["available"] and capability["accepted"]),
        "provider_contract": capability,
        "startup_scan_dispatch": False,
        "navigation_scan_dispatch": False,
        "refresh_scan_dispatch": False,
        "full_scan_enabled": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_process_termination": False,
        "automatic_file_delete": False,
        "registry_write_authority": False,
        "boot_write_authority": False,
        "unlock_authority": False,
        "write_mount_authority": False,
        "format_authority": False,
        "reimage_authority": False,
        "automatic_destructive_action": False,
    }
