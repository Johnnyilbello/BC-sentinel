from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
import ipaddress
import json
from pathlib import PureWindowsPath
import re
from typing import Any

from .edr import EdrTelemetryStore

EDR_HUNT_PROFILE = "v0.11.0-beta.2"
MAX_PAGE_SIZE = 500
MAX_ROOT_CAUSE_PIDS = 256
MIN_RETENTION_SECONDS = 60.0
MAX_RETENTION_SECONDS = 90.0 * 24.0 * 3600.0
MIN_MAX_EVENTS = 100
MAX_MAX_EVENTS = 1_000_000
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class EdrHuntQueryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class HuntIndicator:
    kind: str
    value: str


class EdrHuntingService:
    """Indexed retrospective hunting over the durable Beta1 telemetry store.

    This layer is intentionally read-mostly and non-destructive. SQLite JSON
    expression indexes make already-persisted Beta1 events huntable without a
    destructive schema migration or a duplicate telemetry database.
    """

    _INDEXES = {
        "sha256": "idx_edr_events_hunt_sha256",
        "domain": "idx_edr_events_hunt_domain",
        "address": "idx_edr_events_hunt_address",
        "path": "idx_edr_events_hunt_path",
    }

    def __init__(self, store: EdrTelemetryStore):
        self.store = store
        self._ensure_indexes()

    @staticmethod
    def _json_expr(field: str) -> str:
        return f"lower(coalesce(json_extract(payload_json, '$.{field}'), ''))"

    def _ensure_indexes(self) -> None:
        with self.store._connect() as con:
            try:
                con.execute("SELECT json_extract('{\"ok\":1}', '$.ok')").fetchone()
            except Exception as exc:  # pragma: no cover - platform capability guard
                raise RuntimeError("SQLite JSON support is required for indexed EDR hunting") from exc

            con.execute(
                f"CREATE INDEX IF NOT EXISTS {self._INDEXES['sha256']} "
                f"ON edr_events({self._json_expr('sha256')})"
            )
            con.execute(
                f"CREATE INDEX IF NOT EXISTS {self._INDEXES['domain']} "
                f"ON edr_events({self._json_expr('remote_domain')})"
            )
            con.execute(
                f"CREATE INDEX IF NOT EXISTS {self._INDEXES['address']} "
                f"ON edr_events({self._json_expr('remote_address')})"
            )
            con.execute(
                f"CREATE INDEX IF NOT EXISTS {self._INDEXES['path']} "
                f"ON edr_events({self._json_expr('path')})"
            )

    @staticmethod
    def _encode_cursor(ts: float, event_id: str) -> str:
        payload = json.dumps(
            {"ts": round(float(ts), 6), "event_id": str(event_id)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[float, str] | None:
        if not cursor:
            return None
        try:
            raw = str(cursor)
            raw += "=" * (-len(raw) % 4)
            payload = json.loads(urlsafe_b64decode(raw.encode("ascii")).decode("utf-8"))
            ts = float(payload["ts"])
            event_id = str(payload["event_id"])
            if not event_id.startswith("BCE-"):
                raise ValueError("invalid event id")
            return ts, event_id
        except Exception as exc:
            raise EdrHuntQueryError("invalid EDR pagination cursor") from exc

    @staticmethod
    def _bounded_limit(limit: int) -> int:
        try:
            value = int(limit)
        except (TypeError, ValueError) as exc:
            raise EdrHuntQueryError("limit must be an integer") from exc
        return max(1, min(value, MAX_PAGE_SIZE))

    @staticmethod
    def _normalize_path(value: str) -> str:
        text = str(value or "").strip().replace("/", "\\")
        if not text:
            raise EdrHuntQueryError("path indicator cannot be empty")
        try:
            return str(PureWindowsPath(text)).casefold()
        except Exception as exc:
            raise EdrHuntQueryError("invalid path indicator") from exc

    @classmethod
    def normalize_indicator(cls, indicator: str, *, kind: str = "auto") -> HuntIndicator:
        raw = str(indicator or "").strip()
        if not raw:
            raise EdrHuntQueryError("indicator cannot be empty")

        requested = str(kind or "auto").strip().casefold()
        allowed = {"auto", "sha256", "domain", "address", "path"}
        if requested not in allowed:
            raise EdrHuntQueryError(f"unsupported indicator kind: {requested}")

        if requested == "auto":
            if _SHA256_RE.fullmatch(raw):
                requested = "sha256"
            else:
                try:
                    ipaddress.ip_address(raw)
                    requested = "address"
                except ValueError:
                    if "\\" in raw or "/" in raw or (len(raw) >= 2 and raw[1] == ":"):
                        requested = "path"
                    else:
                        requested = "domain"

        if requested == "sha256":
            if not _SHA256_RE.fullmatch(raw):
                raise EdrHuntQueryError("sha256 indicator must contain exactly 64 hexadecimal characters")
            return HuntIndicator("sha256", raw.casefold())

        if requested == "address":
            try:
                return HuntIndicator("address", ipaddress.ip_address(raw).compressed.casefold())
            except ValueError as exc:
                raise EdrHuntQueryError("invalid IP address indicator") from exc

        if requested == "path":
            return HuntIndicator("path", cls._normalize_path(raw))

        domain = raw.rstrip(".").casefold()
        if not domain or any(ch.isspace() for ch in domain) or "/" in domain or "\\" in domain:
            raise EdrHuntQueryError("invalid domain indicator")
        return HuntIndicator("domain", domain)

    @staticmethod
    def _time_clauses(*, since: float | None, until: float | None) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if since is not None:
            clauses.append("ts >= ?")
            args.append(float(since))
        if until is not None:
            clauses.append("ts <= ?")
            args.append(float(until))
        if since is not None and until is not None and float(since) > float(until):
            raise EdrHuntQueryError("since must be less than or equal to until")
        return clauses, args

    def _page_query(
        self,
        *,
        clauses: list[str],
        args: list[Any],
        limit: int,
        cursor: str | None,
    ) -> dict[str, Any]:
        page_limit = self._bounded_limit(limit)
        cursor_value = self._decode_cursor(cursor)
        if cursor_value is not None:
            clauses = list(clauses) + ["(ts > ? OR (ts = ? AND event_id > ?))"]
            args = list(args) + [cursor_value[0], cursor_value[0], cursor_value[1]]

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = (
            "SELECT event_id, ts, payload_json FROM edr_events"
            + where
            + " ORDER BY ts ASC, event_id ASC LIMIT ?"
        )
        query_args = list(args) + [page_limit + 1]
        with self.store._connect() as con:
            rows = con.execute(sql, tuple(query_args)).fetchall()

        has_more = len(rows) > page_limit
        visible = rows[:page_limit]
        items = [json.loads(str(row["payload_json"])) for row in visible]
        next_cursor = None
        if has_more and visible:
            last = visible[-1]
            next_cursor = self._encode_cursor(float(last["ts"]), str(last["event_id"]))
        return {
            "profile": EDR_HUNT_PROFILE,
            "items": items,
            "limit": page_limit,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }

    def timeline(
        self,
        *,
        pid: int | None = None,
        category: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        clauses, args = self._time_clauses(since=since, until=until)
        if pid is not None:
            clauses.append("pid = ?")
            args.append(int(pid))
        if category:
            clauses.append("category = ?")
            args.append(str(category))
        return self._page_query(clauses=clauses, args=args, limit=limit, cursor=cursor)

    def hunt(
        self,
        indicator: str,
        *,
        kind: str = "auto",
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        normalized = self.normalize_indicator(indicator, kind=kind)
        field_by_kind = {
            "sha256": "sha256",
            "domain": "remote_domain",
            "address": "remote_address",
            "path": "path",
        }
        field = field_by_kind[normalized.kind]
        clauses, args = self._time_clauses(since=since, until=until)
        clauses.insert(0, f"{self._json_expr(field)} = ?")
        args.insert(0, normalized.value)
        page = self._page_query(clauses=clauses, args=args, limit=limit, cursor=cursor)
        page["indicator"] = {"kind": normalized.kind, "value": normalized.value}
        return page

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        value = str(incident_id or "").strip()
        if not value.startswith("BCEDR-"):
            raise EdrHuntQueryError("invalid EDR incident id")
        with self.store._connect() as con:
            row = con.execute(
                "SELECT payload_json FROM edr_incidents WHERE incident_id = ?",
                (value,),
            ).fetchone()
        return json.loads(str(row["payload_json"])) if row else None

    def incident_evidence(
        self,
        incident_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        if incident is None:
            return {
                "profile": EDR_HUNT_PROFILE,
                "incident_id": str(incident_id),
                "items": [],
                "limit": self._bounded_limit(limit),
                "has_more": False,
                "next_cursor": None,
            }

        event_ids = [str(item) for item in incident.get("event_ids", []) if str(item).startswith("BCE-")]
        if not event_ids:
            return {
                "profile": EDR_HUNT_PROFILE,
                "incident_id": str(incident_id),
                "items": [],
                "limit": self._bounded_limit(limit),
                "has_more": False,
                "next_cursor": None,
            }

        placeholders = ",".join("?" for _ in event_ids)
        page = self._page_query(
            clauses=[f"event_id IN ({placeholders})"],
            args=event_ids,
            limit=limit,
            cursor=cursor,
        )
        page["incident_id"] = str(incident_id)
        return page

    def root_cause(self, incident_id: str) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        if incident is None:
            return {
                "profile": EDR_HUNT_PROFILE,
                "incident_id": str(incident_id),
                "root_pids": [],
                "nodes": [],
                "edges": [],
                "truncated": False,
            }

        pids = sorted({int(pid) for pid in incident.get("pids", []) if int(pid) > 0})
        truncated = len(pids) > MAX_ROOT_CAUSE_PIDS
        pids = pids[:MAX_ROOT_CAUSE_PIDS]
        pid_set = set(pids)
        if not pids:
            return {
                "profile": EDR_HUNT_PROFILE,
                "incident_id": str(incident_id),
                "root_pids": [],
                "nodes": [],
                "edges": [],
                "truncated": truncated,
            }

        placeholders = ",".join("?" for _ in pids)
        with self.store._connect() as con:
            rows = con.execute(
                "SELECT pid, ppid, process_name, process_path, MAX(ts) AS last_ts "
                f"FROM edr_events WHERE category = 'process' AND pid IN ({placeholders}) "
                "GROUP BY pid, ppid, process_name, process_path ORDER BY last_ts ASC",
                tuple(pids),
            ).fetchall()

        latest: dict[int, dict[str, Any]] = {}
        for row in rows:
            pid = int(row["pid"])
            latest[pid] = {
                "pid": pid,
                "ppid": int(row["ppid"] or 0),
                "process_name": str(row["process_name"] or ""),
                "process_path": str(row["process_path"] or ""),
                "last_ts": float(row["last_ts"] or 0.0),
            }

        nodes = [latest[pid] for pid in pids if pid in latest]
        edges = [
            {"parent_pid": int(node["ppid"]), "child_pid": int(node["pid"])}
            for node in nodes
            if int(node["ppid"]) in pid_set
        ]
        root_pids = sorted(
            int(node["pid"])
            for node in nodes
            if int(node["ppid"]) not in pid_set
        )
        return {
            "profile": EDR_HUNT_PROFILE,
            "incident_id": str(incident_id),
            "root_pids": root_pids,
            "nodes": nodes,
            "edges": edges,
            "truncated": truncated,
        }

    def retention_policy(self) -> dict[str, Any]:
        return {
            "profile": EDR_HUNT_PROFILE,
            "retention_seconds": float(self.store.retention_seconds),
            "max_events": int(self.store.max_events),
            "bounds": {
                "min_retention_seconds": MIN_RETENTION_SECONDS,
                "max_retention_seconds": MAX_RETENTION_SECONDS,
                "min_max_events": MIN_MAX_EVENTS,
                "max_max_events": MAX_MAX_EVENTS,
            },
        }

    def update_retention(
        self,
        *,
        retention_seconds: float | None = None,
        max_events: int | None = None,
        prune: bool = True,
    ) -> dict[str, Any]:
        if retention_seconds is not None:
            retention = float(retention_seconds)
            if not (MIN_RETENTION_SECONDS <= retention <= MAX_RETENTION_SECONDS):
                raise EdrHuntQueryError("retention_seconds is outside the allowed bounds")
            self.store.retention_seconds = retention
        if max_events is not None:
            maximum = int(max_events)
            if not (MIN_MAX_EVENTS <= maximum <= MAX_MAX_EVENTS):
                raise EdrHuntQueryError("max_events is outside the allowed bounds")
            self.store.max_events = maximum
        if prune:
            self.store.prune()
        policy = self.retention_policy()
        policy["pruned"] = bool(prune)
        policy["automatic_destructive_action"] = False
        return policy

    def status(self) -> dict[str, Any]:
        return {
            "profile": EDR_HUNT_PROFILE,
            "indexed_hunting": True,
            "timeline_pagination": True,
            "incident_evidence_navigation": True,
            "root_cause_view": True,
            "retention_administration": True,
            "max_page_size": MAX_PAGE_SIZE,
            "automatic_process_kill": False,
            "automatic_file_delete": False,
            "automatic_host_isolation": False,
            "cloud_required": False,
        }
