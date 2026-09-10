from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from .config import EDR_DB_PATH
from .edr import EdrPipeline, EdrTelemetryStore
from .edr_adapter import EdrEventAdapter
from .edr_hunting import EdrHuntingService

EDR_SERVICE_PROFILE = "v0.11.0-beta.2"


@dataclass(frozen=True, slots=True)
class EdrInboxNotification:
    incident_id: str
    severity: str
    score: int
    confidence: float
    title: str
    reason_count: int
    event_count: int
    automatic_destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "title": self.title,
            "reason_count": self.reason_count,
            "event_count": self.event_count,
            "automatic_destructive_action": self.automatic_destructive_action,
            "source": "edr",
            "profile": EDR_SERVICE_PROFILE,
        }


class EdrServiceBridge:
    """Service-owned EDR runtime facade for BC Sentinel v0.11 Beta2.

    The bridge intentionally contains no Windows service or transport code. It
    owns one durable EDR store/pipeline/hunting instance and exposes bounded
    read operations that the existing authenticated Named Pipe dispatcher can
    call. The optional inbox callback is a notification surface only; it cannot
    kill processes, delete files, quarantine content or isolate the host.
    """

    READ_OPERATIONS = frozenset({
        "edr_status",
        "edr_timeline",
        "edr_incidents",
        "edr_incident_evidence",
        "edr_root_cause",
        "edr_hunt",
        "edr_process_tree",
        "edr_retention_policy",
    })
    PRIVILEGED_OPERATIONS = frozenset({"edr_update_retention"})

    def __init__(
        self,
        *,
        db_path: str | Path = EDR_DB_PATH,
        retention_days: int = 7,
        max_events: int = 100_000,
        correlation_window_seconds: int = 90,
        inbox_callback: Callable[[dict[str, Any]], Any] | None = None,
    ):
        retention_seconds = max(1, int(retention_days)) * 24 * 3600
        self.store = EdrTelemetryStore(
            db_path,
            retention_seconds=retention_seconds,
            max_events=max_events,
        )
        self.pipeline = EdrPipeline(
            self.store,
            window_seconds=max(10, int(correlation_window_seconds)),
        )
        self.adapter = EdrEventAdapter(self.pipeline)
        self.hunting = EdrHuntingService(self.store)
        self.inbox_callback = inbox_callback
        self._lock = RLock()
        self._ingested = 0
        self._ingest_errors = 0
        self._inbox_notifications = 0
        self._inbox_errors = 0
        self._last_notified_occurrence: dict[str, int] = {}

    def ingest_security_event(self, event: Any) -> dict[str, Any]:
        """Ingest one existing SecurityEvent without breaking the protection path.

        EDR enrichment must never become a reason for realtime protection to stop.
        Failures are reported in bridge status and returned to the caller.
        """
        try:
            result = self.adapter.ingest_security_event(event)
            with self._lock:
                self._ingested += int(bool(result.get("stored")))
            incident = result.get("incident")
            if isinstance(incident, dict):
                self._surface_incident(incident)
            return result
        except Exception as exc:
            with self._lock:
                self._ingest_errors += 1
            return {
                "stored": False,
                "disposition": "edr_bridge_error",
                "event_id": "",
                "incident": None,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def _surface_incident(self, incident: dict[str, Any]) -> None:
        if self.inbox_callback is None:
            return
        incident_id = str(incident.get("incident_id") or "")
        severity = str(incident.get("severity") or "").upper()
        score = int(incident.get("score") or 0)
        if not incident_id.startswith("BCEDR-") or severity != "HIGH" or score < 70:
            return
        if bool(incident.get("automatic_destructive_action")) or bool(incident.get("host_isolation")):
            return

        occurrence = max(1, int(incident.get("occurrences") or 1))
        with self._lock:
            previous = self._last_notified_occurrence.get(incident_id, 0)
            if occurrence <= previous:
                return
            self._last_notified_occurrence[incident_id] = occurrence

        notice = EdrInboxNotification(
            incident_id=incident_id,
            severity=severity,
            score=score,
            confidence=float(incident.get("confidence") or 0.0),
            title="EDR incident requires review",
            reason_count=len(list(incident.get("reasons") or [])),
            event_count=len(list(incident.get("event_ids") or [])),
        ).to_dict()
        try:
            self.inbox_callback(notice)
            with self._lock:
                self._inbox_notifications += 1
        except Exception:
            with self._lock:
                self._inbox_errors += 1

    @staticmethod
    def _payload(payload: Any) -> dict[str, Any]:
        if payload is None:
            return {}
        if not isinstance(payload, dict):
            raise ValueError("EDR operation payload must be an object")
        return dict(payload)

    def dispatch_read(self, operation: str, payload: Any = None) -> dict[str, Any]:
        op = str(operation or "").strip().casefold()
        if op not in self.READ_OPERATIONS:
            raise ValueError("unsupported EDR read operation")
        data = self._payload(payload)

        if op == "edr_status":
            return self.status()
        if op == "edr_timeline":
            return self.hunting.timeline(
                pid=data.get("pid"),
                category=data.get("category"),
                since=data.get("since"),
                until=data.get("until"),
                limit=data.get("limit", 100),
                cursor=data.get("cursor"),
            )
        if op == "edr_incidents":
            limit = max(1, min(int(data.get("limit", 100)), 500))
            return {
                "profile": EDR_SERVICE_PROFILE,
                "items": self.store.incidents(status=data.get("status"), limit=limit),
                "limit": limit,
            }
        if op == "edr_incident_evidence":
            return self.hunting.incident_evidence(
                str(data.get("incident_id") or ""),
                limit=data.get("limit", 100),
                cursor=data.get("cursor"),
            )
        if op == "edr_root_cause":
            return self.hunting.root_cause(str(data.get("incident_id") or ""))
        if op == "edr_hunt":
            return self.hunting.hunt(
                str(data.get("indicator") or ""),
                kind=str(data.get("kind") or "auto"),
                since=data.get("since"),
                until=data.get("until"),
                limit=data.get("limit", 100),
                cursor=data.get("cursor"),
            )
        if op == "edr_process_tree":
            since = data.get("since")
            tree = self.store.process_tree(since=float(since) if since is not None else None)
            nodes = [dict(node) for _, node in sorted(tree.items())]
            return {"profile": EDR_SERVICE_PROFILE, "nodes": nodes, "count": len(nodes)}
        if op == "edr_retention_policy":
            return self.hunting.retention_policy()
        raise AssertionError("unreachable EDR read operation")

    def dispatch_privileged(self, operation: str, payload: Any = None) -> dict[str, Any]:
        op = str(operation or "").strip().casefold()
        if op not in self.PRIVILEGED_OPERATIONS:
            raise ValueError("unsupported EDR privileged operation")
        data = self._payload(payload)
        return self.hunting.update_retention(
            retention_seconds=data.get("retention_seconds"),
            max_events=data.get("max_events"),
            prune=bool(data.get("prune", True)),
        )

    def status(self) -> dict[str, Any]:
        base = self.pipeline.status()
        with self._lock:
            counters = {
                "service_ingested": self._ingested,
                "service_ingest_errors": self._ingest_errors,
                "inbox_notifications": self._inbox_notifications,
                "inbox_errors": self._inbox_errors,
            }
        base.update({
            "service_profile": EDR_SERVICE_PROFILE,
            "service_owned_store": True,
            "authenticated_ipc_required": True,
            "read_operations": sorted(self.READ_OPERATIONS),
            "privileged_operations": sorted(self.PRIVILEGED_OPERATIONS),
            "automatic_process_kill": False,
            "automatic_file_delete": False,
            "automatic_host_isolation": False,
            "cloud_required": False,
            **counters,
        })
        return base
