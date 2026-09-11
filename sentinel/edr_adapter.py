from __future__ import annotations

from time import time
from typing import Any

from .edr import EdrPipeline, EdrTelemetryEvent


def _event_timestamp(event: Any, data: dict[str, Any]) -> float:
    """Return a retention-safe event timestamp without rewriting valid telemetry time."""
    raw = getattr(event, "ts", None)
    if raw in (None, "", 0, 0.0):
        raw = data.get("ts")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 0.0
    if value <= 0.0 or value != value or value == float("inf") or value == float("-inf"):
        return time()
    return value


def telemetry_from_security_event(event: Any) -> EdrTelemetryEvent:
    """Convert the existing BC Sentinel SecurityEvent shape without importing it.

    The adapter intentionally uses duck typing so the EDR foundation does not
    create an import cycle with the current core event pipeline.
    """
    data = dict(getattr(event, "data", {}) or {})
    return EdrTelemetryEvent(
        category=str(getattr(event, "category", "") or data.get("category") or "unknown"),
        pid=int(getattr(event, "pid", 0) or data.get("pid") or 0),
        ppid=int(getattr(event, "ppid", 0) or data.get("ppid") or 0),
        process_name=str(getattr(event, "process_name", "") or data.get("process_name") or ""),
        process_path=str(getattr(event, "process_path", "") or data.get("process_path") or ""),
        command_line=str(data.get("command_line") or data.get("cmdline") or ""),
        path=str(getattr(event, "path", "") or data.get("path") or ""),
        remote_domain=str(data.get("remote_domain") or data.get("domain") or ""),
        remote_address=str(data.get("remote_address") or data.get("remote_addr") or data.get("address") or ""),
        remote_port=int(data.get("remote_port") or data.get("port") or 0),
        sha256=str(data.get("sha256") or data.get("file_sha256") or ""),
        signature_status=str(data.get("signature_status") or data.get("authenticode_status") or ""),
        publisher=str(data.get("publisher") or data.get("signer") or ""),
        user_sid=str(data.get("user_sid") or data.get("sid") or ""),
        session_id=int(data.get("session_id") if data.get("session_id") is not None else -1),
        integrity_level=str(data.get("integrity_level") or ""),
        source=str(data.get("source") or "security_event"),
        data=data,
        ts=_event_timestamp(event, data),
    )


class EdrEventAdapter:
    def __init__(self, pipeline: EdrPipeline):
        self.pipeline = pipeline

    def ingest_security_event(self, event: Any) -> dict:
        return self.pipeline.ingest(telemetry_from_security_event(event))
