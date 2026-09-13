from __future__ import annotations

"""Compatibility hardening for the historical StaticScanner runtime used by B6-3.

The synchronized B6-3 adapter intentionally does not modify the historical
scanner itself.  This module patches only the adapter boundary so that the
verified v0.10-era ``FileReport`` shape can be interpreted truthfully and so
Unicode file names cannot crash the child JSON transport on Windows.

Unknown assessment levels still fail closed.  No remediation authority is
introduced here.
"""

from collections.abc import Mapping
from typing import Any

from sentinel import home_smart_scan as smart

_COMPAT_MARKER = "_b63_runtime_compat_applied"
_CLEAN_LEVELS = frozenset({"SAFE", "CLEAN", "BENIGN", "ALLOWED"})
_FINDING_LEVELS = frozenset(
    {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "SUSPICIOUS",
        "MALICIOUS",
        "INFECTED",
        "THREAT",
        "DANGER",
    }
)


def _assessment_reason(assessment: Mapping[str, object]) -> str:
    reasons = assessment.get("reasons")
    if isinstance(reasons, (list, tuple)):
        clean = [str(item).strip() for item in reasons if str(item).strip()]
        if clean:
            return "; ".join(clean[:3])

    signals = assessment.get("signals")
    if isinstance(signals, (list, tuple)):
        for signal in signals:
            if isinstance(signal, Mapping):
                reason = str(signal.get("reason") or "").strip()
                if reason:
                    return reason
    return ""


def _assessment_title(assessment: Mapping[str, object], level: str) -> str:
    signals = assessment.get("signals")
    if isinstance(signals, (list, tuple)):
        for signal in signals:
            if isinstance(signal, Mapping):
                key = str(signal.get("key") or "").strip()
                if key:
                    return f"Static scanner assessment: {key}"
    return f"Static scanner assessment: {level}"


def _assessment_severity(level: str) -> str:
    if level == "CRITICAL":
        return smart.SEVERITY_CRITICAL
    if level in {"HIGH", "MALICIOUS", "INFECTED", "THREAT", "DANGER"}:
        return smart.SEVERITY_HIGH
    if level in {"MEDIUM", "SUSPICIOUS"}:
        return smart.SEVERITY_MEDIUM
    if level == "LOW":
        return smart.SEVERITY_LOW
    return smart.SEVERITY_INFO


def apply(module: Any) -> Any:
    """Patch one imported ``sentinel.smart_scan_live_provider`` module in place.

    Re-applying is idempotent.  The patch only changes adapter interpretation
    and transport encoding; scanner execution, scope, cancellation and safety
    authority remain owned by the existing adapter/runtime.
    """

    if bool(getattr(module, _COMPAT_MARKER, False)):
        return module

    original_runtime_env = getattr(module, "_runtime_env", None)
    original_report_evidence = getattr(module, "_report_evidence", None)
    if not callable(original_runtime_env) or not callable(original_report_evidence):
        raise RuntimeError("live_provider_compat_target_missing_expected_hooks")

    def runtime_env(binding: object) -> dict[str, str]:
        env = dict(original_runtime_env(binding))
        # Keep the child protocol ASCII-safe.  json.dumps(..., ensure_ascii=False)
        # may contain arbitrary Unicode file names; backslashreplace converts
        # them into valid JSON \uXXXX escapes instead of crashing under cp1252.
        env["PYTHONIOENCODING"] = "ascii:backslashreplace"
        env["PYTHONUTF8"] = "1"
        return env

    def report_evidence(payload: Mapping[str, object]) -> tuple[bool, bool, str, str, str]:
        recognized, finding, severity, title, reason = original_report_evidence(payload)
        if recognized:
            return recognized, finding, severity, title, reason

        assessment = payload.get("assessment")
        if not isinstance(assessment, Mapping):
            return recognized, finding, severity, title, reason

        level = str(assessment.get("level") or "").strip().upper()
        if not level:
            return recognized, finding, severity, title, reason

        assessment_reason = _assessment_reason(assessment)
        if level in _CLEAN_LEVELS:
            return (
                True,
                False,
                smart.SEVERITY_INFO,
                "Static scanner report",
                assessment_reason,
            )

        if level in _FINDING_LEVELS:
            return (
                True,
                True,
                _assessment_severity(level),
                _assessment_title(assessment, level),
                assessment_reason or "The existing StaticScanner returned a non-safe assessment.",
            )

        # Unknown historical assessment vocabulary must never become CLEAN.
        return False, False, smart.SEVERITY_INFO, "Static scanner report", ""

    setattr(module, "_runtime_env", runtime_env)
    setattr(module, "_report_evidence", report_evidence)
    setattr(module, _COMPAT_MARKER, True)
    return module
