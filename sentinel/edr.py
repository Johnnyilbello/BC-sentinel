from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from threading import RLock
from time import time
from typing import Any, Iterable

EDR_PROFILE = "v0.11.0-beta.1"
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
LOLBINS = {
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "wmic.exe", "cmstp.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
USER_WRITABLE_HINTS = ("\\downloads\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\")


@dataclass(slots=True)
class EdrTelemetryEvent:
    category: str
    pid: int = 0
    ppid: int = 0
    process_name: str = ""
    process_path: str = ""
    command_line: str = ""
    path: str = ""
    remote_domain: str = ""
    remote_address: str = ""
    remote_port: int = 0
    sha256: str = ""
    signature_status: str = ""
    publisher: str = ""
    user_sid: str = ""
    session_id: int = -1
    integrity_level: str = ""
    source: str = "local"
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time)
    event_id: str = ""

    def material(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "pid": int(self.pid or 0),
            "ppid": int(self.ppid or 0),
            "process_name": self.process_name,
            "process_path": self.process_path,
            "command_line": self.command_line,
            "path": self.path,
            "remote_domain": self.remote_domain,
            "remote_address": self.remote_address,
            "remote_port": int(self.remote_port or 0),
            "sha256": self.sha256,
            "signature_status": self.signature_status,
            "publisher": self.publisher,
            "user_sid": self.user_sid,
            "session_id": int(self.session_id),
            "integrity_level": self.integrity_level,
            "source": self.source,
            "data": dict(self.data or {}),
            "ts": round(float(self.ts), 6),
        }

    def ensure_id(self) -> str:
        if not self.event_id:
            payload = json.dumps(self.material(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self.event_id = "BCE-" + sha256(payload.encode("utf-8")).hexdigest()[:24].upper()
        return self.event_id

    def to_dict(self) -> dict[str, Any]:
        self.ensure_id()
        out = self.material()
        out["event_id"] = self.event_id
        return out


@dataclass(slots=True)
class EdrSignal:
    family: str
    code: str
    weight: int
    reason: str
    evidence: str = ""
    deterministic: bool = False


@dataclass(slots=True)
class EdrIncident:
    incident_id: str
    score: int
    severity: str
    confidence: float
    event_ids: list[str]
    pids: list[int]
    signal_codes: list[str]
    evidence_families: list[str]
    reasons: list[str]
    first_seen: float
    last_seen: float
    occurrences: int = 1
    status: str = "open"
    automatic_destructive_action: bool = False
    host_isolation: bool = False
    response_mode: str = "operator_review"
    profile: str = EDR_PROFILE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EdrTelemetryStore:
    """Persistent, bounded local EDR telemetry store.

    The store is intentionally local-only and non-destructive. It uses SQLite,
    stable event IDs, deduplication, retention, and a bounded in-memory flood
    guard. Every write is explicit and queryable.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        retention_seconds: float = 7 * 24 * 3600,
        max_events: int = 100_000,
        flood_window_seconds: float = 5.0,
        max_events_per_pid_window: int = 250,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_seconds = max(60.0, float(retention_seconds))
        self.max_events = max(100, int(max_events))
        self.flood_window_seconds = max(0.25, float(flood_window_seconds))
        self.max_events_per_pid_window = max(5, int(max_events_per_pid_window))
        self._lock = RLock()
        self._rate: dict[tuple[int, str], deque[float]] = defaultdict(deque)
        self._dropped_flood = 0
        self._duplicates = 0
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10.0)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def _init_schema(self) -> None:
        with self._connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS edr_events (
                    event_id TEXT PRIMARY KEY,
                    ts REAL NOT NULL,
                    category TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    process_path TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_edr_events_ts ON edr_events(ts);
                CREATE INDEX IF NOT EXISTS idx_edr_events_pid_ts ON edr_events(pid, ts);
                CREATE INDEX IF NOT EXISTS idx_edr_events_ppid_ts ON edr_events(ppid, ts);
                CREATE TABLE IF NOT EXISTS edr_incidents (
                    incident_id TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    occurrences INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_edr_incidents_last_seen ON edr_incidents(last_seen);
                """
            )

    def _flood_allowed(self, event: EdrTelemetryEvent) -> bool:
        now = float(event.ts or time())
        key = (int(event.pid or 0), str(event.category or "unknown").casefold())
        q = self._rate[key]
        cutoff = now - self.flood_window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.max_events_per_pid_window:
            self._dropped_flood += 1
            return False
        q.append(now)
        return True

    def ingest(self, event: EdrTelemetryEvent) -> tuple[bool, str]:
        event.ensure_id()
        with self._lock:
            if not self._flood_allowed(event):
                return False, "flood_guard"
            payload = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            try:
                with self._connect() as con:
                    con.execute(
                        "INSERT INTO edr_events(event_id,ts,category,pid,ppid,process_name,process_path,payload_json) VALUES(?,?,?,?,?,?,?,?)",
                        (
                            event.event_id, float(event.ts), str(event.category), int(event.pid or 0), int(event.ppid or 0),
                            str(event.process_name or ""), str(event.process_path or ""), payload,
                        ),
                    )
            except sqlite3.IntegrityError:
                self._duplicates += 1
                return False, "duplicate"
            self.prune(now=float(event.ts or time()))
            return True, "stored"

    def prune(self, *, now: float | None = None) -> None:
        current = float(now or time())
        cutoff = current - self.retention_seconds
        with self._connect() as con:
            con.execute("DELETE FROM edr_events WHERE ts < ?", (cutoff,))
            row = con.execute("SELECT COUNT(*) AS n FROM edr_events").fetchone()
            count = int(row["n"] if row else 0)
            overflow = count - self.max_events
            if overflow > 0:
                con.execute(
                    "DELETE FROM edr_events WHERE event_id IN (SELECT event_id FROM edr_events ORDER BY ts ASC LIMIT ?)",
                    (overflow,),
                )

    def query_events(
        self,
        *,
        pid: int | None = None,
        category: str | None = None,
        since: float | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if pid is not None:
            clauses.append("pid = ?")
            args.append(int(pid))
        if category:
            clauses.append("category = ?")
            args.append(str(category))
        if since is not None:
            clauses.append("ts >= ?")
            args.append(float(since))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = "SELECT payload_json FROM edr_events" + where + " ORDER BY ts ASC LIMIT ?"
        args.append(max(1, min(int(limit), 5000)))
        with self._connect() as con:
            rows = con.execute(sql, tuple(args)).fetchall()
        return [json.loads(str(r["payload_json"])) for r in rows]

    def process_tree(self, *, since: float | None = None) -> dict[int, dict[str, Any]]:
        events = self.query_events(category="process", since=since, limit=5000)
        nodes: dict[int, dict[str, Any]] = {}
        for e in events:
            pid = int(e.get("pid") or 0)
            if not pid:
                continue
            node = nodes.setdefault(pid, {"pid": pid, "ppid": 0, "name": "", "path": "", "children": []})
            node.update({
                "ppid": int(e.get("ppid") or 0),
                "name": str(e.get("process_name") or ""),
                "path": str(e.get("process_path") or ""),
            })
        for pid, node in list(nodes.items()):
            parent = int(node.get("ppid") or 0)
            if parent and parent in nodes and pid not in nodes[parent]["children"]:
                nodes[parent]["children"].append(pid)
        return nodes

    def save_incident(self, incident: EdrIncident) -> EdrIncident:
        with self._connect() as con:
            row = con.execute("SELECT payload_json FROM edr_incidents WHERE incident_id = ?", (incident.incident_id,)).fetchone()
            if row:
                old = json.loads(str(row["payload_json"]))
                incident.first_seen = float(old.get("first_seen", incident.first_seen))
                incident.occurrences = int(old.get("occurrences", 1)) + 1
            payload = json.dumps(incident.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            con.execute(
                """INSERT INTO edr_incidents(incident_id,first_seen,last_seen,score,severity,status,occurrences,payload_json)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(incident_id) DO UPDATE SET
                     last_seen=excluded.last_seen, score=excluded.score, severity=excluded.severity,
                     status=excluded.status, occurrences=excluded.occurrences, payload_json=excluded.payload_json""",
                (
                    incident.incident_id, incident.first_seen, incident.last_seen, incident.score,
                    incident.severity, incident.status, incident.occurrences, payload,
                ),
            )
        return incident

    def incidents(self, *, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT payload_json FROM edr_incidents"
        args: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            args.append(str(status))
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(max(1, min(int(limit), 2000)))
        with self._connect() as con:
            rows = con.execute(sql, tuple(args)).fetchall()
        return [json.loads(str(r["payload_json"])) for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._connect() as con:
            events = int(con.execute("SELECT COUNT(*) FROM edr_events").fetchone()[0])
            incidents = int(con.execute("SELECT COUNT(*) FROM edr_incidents").fetchone()[0])
        return {
            "profile": EDR_PROFILE,
            "events": events,
            "incidents": incidents,
            "duplicates": int(self._duplicates),
            "flood_dropped": int(self._dropped_flood),
            "retention_seconds": self.retention_seconds,
            "max_events": self.max_events,
            "cloud_required": False,
            "automatic_destructive_action": False,
        }


class EdrCorrelationEngine:
    """Explainable multi-signal EDR correlation.

    A single heuristic family is capped below HIGH. HIGH requires at least three
    independent evidence families, or deterministic evidence plus another
    independent family. The engine never kills, deletes, blocks or isolates.
    """

    def __init__(self, store: EdrTelemetryStore, *, window_seconds: float = 90.0):
        self.store = store
        self.window_seconds = max(10.0, float(window_seconds))

    @staticmethod
    def _name(value: str) -> str:
        return Path(str(value or "").replace("/", "\\")).name.casefold()

    @staticmethod
    def _text(event: dict[str, Any]) -> str:
        data = event.get("data") or {}
        return " ".join(str(v) for v in (
            event.get("process_name", ""), event.get("process_path", ""), event.get("command_line", ""),
            event.get("path", ""), event.get("remote_domain", ""), event.get("remote_address", ""),
            data.get("url", ""), data.get("origin", ""), data.get("verdict", ""),
        ) if v).casefold()

    def _family_pids(self, event: EdrTelemetryEvent) -> set[int]:
        pids = {int(event.pid or 0), int(event.ppid or 0)} - {0}
        tree = self.store.process_tree(since=float(event.ts) - self.window_seconds)
        cur = int(event.pid or 0)
        seen: set[int] = set()
        for _ in range(8):
            if not cur or cur in seen:
                break
            seen.add(cur)
            pids.add(cur)
            node = tree.get(cur)
            cur = int((node or {}).get("ppid") or 0)
        changed = True
        while changed and len(pids) < 64:
            changed = False
            for pid, node in tree.items():
                if int(node.get("ppid") or 0) in pids and pid not in pids:
                    pids.add(pid)
                    changed = True
        return pids

    def assess(self, event: EdrTelemetryEvent) -> EdrIncident | None:
        since = float(event.ts) - self.window_seconds
        family_pids = self._family_pids(event)
        recent = self.store.query_events(since=since, limit=5000)
        chain = [e for e in recent if int(e.get("pid") or 0) in family_pids or int(e.get("ppid") or 0) in family_pids]
        if not chain:
            return None

        signals: list[EdrSignal] = []
        families: set[str] = set()
        deterministic = False

        for e in chain:
            category = str(e.get("category") or "").casefold()
            proc = self._name(str(e.get("process_name") or e.get("process_path") or ""))
            text = self._text(e)
            data = e.get("data") or {}

            if category == "download":
                signals.append(EdrSignal("delivery", "browser_download", 12, "Download osservato nella catena processo/browser.", str(data.get("url") or e.get("path") or "")))
                families.add("delivery")
                if bool(data.get("signed_ioc") or data.get("malicious_origin")):
                    signals.append(EdrSignal("deterministic", "download_signed_ioc", 42, "Origine download qualificata da IOC firmato.", str(data.get("url") or ""), True))
                    families.add("deterministic"); deterministic = True

            if category == "process":
                path = str(e.get("process_path") or e.get("path") or "").replace("/", "\\").casefold()
                cmd = str(e.get("command_line") or "").casefold()
                if proc in SCRIPT_HOSTS | LOLBINS and any(x in cmd for x in ("-enc", "encodedcommand", "downloadstring", "invoke-webrequest", "http://", "https://", "javascript:")):
                    signals.append(EdrSignal("execution", "script_or_lolbin_suspicious", 24, "Interprete/LOLBin usa parametri compatibili con delivery o evasione.", proc))
                    families.add("execution")
                if path and any(h in path for h in USER_WRITABLE_HINTS):
                    signals.append(EdrSignal("execution", "execution_user_writable", 12, "Esecuzione da percorso user-writable/download/temp.", path))
                    families.add("execution")
                parent = str(data.get("parent_name") or "").casefold()
                if parent in BROWSERS and proc in SCRIPT_HOSTS | LOLBINS:
                    signals.append(EdrSignal("process_chain", "browser_to_interpreter", 18, "Browser ha avviato interprete/LOLBin nella stessa catena.", f"{parent}->{proc}"))
                    families.add("process_chain")
                verdict_score = int(data.get("file_verdict_score") or 0)
                if bool(data.get("qualified_file_verdict") or data.get("yara_malicious")) or verdict_score >= 70:
                    signals.append(EdrSignal("deterministic", "qualified_file_verdict", 46, "Verdetto file deterministico qualifica l'esecuzione.", str(e.get("sha256") or ""), True))
                    families.add("deterministic"); deterministic = True

            if category in {"network", "dns"}:
                if bool(data.get("signed_ioc") or data.get("signed_domain_ioc")):
                    signals.append(EdrSignal("deterministic", "signed_network_ioc", 46, "Connessione/DNS coincide con IOC firmato.", str(e.get("remote_domain") or e.get("remote_address") or ""), True))
                    families.add("deterministic"); deterministic = True
                elif bool(data.get("suspicious_domain")):
                    signals.append(EdrSignal("network", "suspicious_network_context", 16, "Contesto rete sospetto correlato al processo.", str(e.get("remote_domain") or "")))
                    families.add("network")

            if category == "persistence":
                signals.append(EdrSignal("persistence", "persistence_change", 24, "Modifica di persistenza osservata nella catena.", str(e.get("path") or data.get("key") or "")))
                families.add("persistence")

            if category == "file" and bool(data.get("executed_after_download")):
                signals.append(EdrSignal("delivery", "download_to_execution", 22, "File scaricato osservato successivamente in esecuzione.", str(e.get("path") or "")))
                families.add("delivery")

        if not signals:
            return None

        unique: dict[tuple[str, str, str], EdrSignal] = {}
        for s in signals:
            unique[(s.family, s.code, s.evidence)] = s
        signals = list(unique.values())
        raw_score = max(0, min(100, sum(max(0, int(s.weight)) for s in signals)))
        independent = len(families)
        score = raw_score
        if independent <= 1 and not deterministic:
            score = min(score, 49)
        elif independent <= 2 and not deterministic:
            score = min(score, 69)
        qualified_high = bool((independent >= 3 and score >= 70) or (deterministic and independent >= 2 and score >= 70))
        if score >= 70 and not qualified_high:
            score = 69
        if score < 50:
            return None

        severity = "HIGH" if score >= 70 else "MEDIUM"
        confidence = min(0.99, 0.35 + (0.10 * independent) + (0.15 if deterministic else 0.0))
        event_ids = sorted({str(e.get("event_id") or "") for e in chain if e.get("event_id")})
        pids = sorted({int(e.get("pid") or 0) for e in chain if int(e.get("pid") or 0)})
        fingerprint_material = {
            "families": sorted(families),
            "signal_codes": sorted({s.code for s in signals}),
            "pids": pids[:16],
        }
        fingerprint = json.dumps(fingerprint_material, sort_keys=True, separators=(",", ":"))
        incident_id = "BCEDR-" + sha256(fingerprint.encode("utf-8")).hexdigest()[:20].upper()
        first_seen = min(float(e.get("ts") or event.ts) for e in chain)
        incident = EdrIncident(
            incident_id=incident_id,
            score=int(score),
            severity=severity,
            confidence=round(float(confidence), 3),
            event_ids=event_ids,
            pids=pids,
            signal_codes=sorted({s.code for s in signals}),
            evidence_families=sorted(families),
            reasons=[s.reason for s in signals],
            first_seen=first_seen,
            last_seen=float(event.ts),
        )
        return self.store.save_incident(incident)


class EdrPipeline:
    def __init__(self, store: EdrTelemetryStore, *, window_seconds: float = 90.0):
        self.store = store
        self.engine = EdrCorrelationEngine(store, window_seconds=window_seconds)

    def ingest(self, event: EdrTelemetryEvent) -> dict[str, Any]:
        stored, disposition = self.store.ingest(event)
        incident = self.engine.assess(event) if stored else None
        return {
            "stored": bool(stored),
            "disposition": disposition,
            "event_id": event.ensure_id(),
            "incident": incident.to_dict() if incident else None,
        }

    def ingest_mapping(self, payload: dict[str, Any]) -> dict[str, Any]:
        allowed = {f.name for f in EdrTelemetryEvent.__dataclass_fields__.values()}
        event = EdrTelemetryEvent(**{k: v for k, v in payload.items() if k in allowed})
        return self.ingest(event)

    def status(self) -> dict[str, Any]:
        stats = self.store.stats()
        stats.update({
            "enabled": True,
            "mode": "detection_first_persistent",
            "process_tree": True,
            "process_file_correlation": True,
            "dns_network_correlation": True,
            "download_execution_correlation": True,
            "incident_persistence": True,
            "single_heuristic_high": False,
            "automatic_process_kill": False,
            "automatic_file_delete": False,
            "automatic_host_isolation": False,
            "cloud_required": False,
        })
        return stats
