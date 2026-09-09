from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from threading import RLock
from time import time
from typing import Iterable

from .core.events import SecurityEvent

HIGH_RISK_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

OFFICE_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}

BROWSERS = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "opera.exe",
    "brave.exe",
}

NETWORK_NOISE_CLIENTS = BROWSERS | {
    "steam.exe", "epicgameslauncher.exe", "onedrive.exe", "dropbox.exe",
    "teams.exe", "discord.exe", "spotify.exe", "code.exe", "devenv.exe",
    "git.exe", "python.exe", "pythonw.exe", "node.exe", "npm.exe",
    "docker.exe", "com.docker.backend.exe", "wsl.exe", "ssh.exe", "curl.exe",
}

DOWNLOADER_HINTS = (
    "invoke-webrequest",
    "iwr ",
    "curl ",
    "wget ",
    "bitsadmin",
    "certutil",
    "start-bitstransfer",
)

ENCODED_HINTS = (
    "-enc ",
    "-encodedcommand",
    "frombase64string",
)

TEMP_HINTS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\temp\\",
)

STAGE_ORDER = {
    "initial_execution": 10,
    "script_execution": 20,
    "payload_delivery": 30,
    "file_modification": 40,
    "network_activity": 50,
    "persistence": 60,
    "impact": 70,
}


@dataclass(slots=True)
class CorrelationResult:
    score_delta: int = 0
    reasons: list[str] = field(default_factory=list)
    chain: str = ""
    confidence: float = 0.0
    severity: str = "none"
    stages: list[str] = field(default_factory=list)
    evidence_families: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)
    incident_id: str = ""
    total_score: int = 0

    def bounded(self) -> "CorrelationResult":
        self.score_delta = max(0, min(75, int(self.score_delta)))
        self.total_score = max(0, min(100, int(self.total_score)))
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        return self


class EventDeduplicator:
    def __init__(self, ttl_seconds: float = 2.0, max_keys: int = 5000):
        self.ttl_seconds = float(ttl_seconds)
        self.max_keys = int(max_keys)
        self._seen: dict[tuple, float] = {}
        self._lock = RLock()

    @staticmethod
    def _data_fingerprint(event: SecurityEvent) -> tuple:
        data = event.data or {}
        return (
            str(data.get("remote_addr") or "").casefold(),
            int(data.get("remote_port") or 0),
            str(data.get("cmdline") or data.get("command_line") or "").casefold(),
            str(data.get("value") or "").casefold(),
            float(data.get("process_create_time") or data.get("create_time") or 0.0),
        )

    def _key(self, event: SecurityEvent) -> tuple:
        return (
            event.category,
            event.action,
            int(event.pid or 0),
            int(event.ppid or 0),
            (event.path or "").casefold(),
            (event.process_name or "").casefold(),
            event.source,
            self._data_fingerprint(event),
        )

    def allow(self, event: SecurityEvent, now: float | None = None) -> bool:
        now = float(now or time())
        key = self._key(event)

        with self._lock:
            last = self._seen.get(key)
            allowed = last is None or (now - last) > self.ttl_seconds

            # Suppressed duplicates do not extend the TTL window. Otherwise a
            # continuous burst could become invisible forever.
            if allowed:
                self._seen[key] = now

            if len(self._seen) > self.max_keys:
                cutoff = now - self.ttl_seconds * 4
                self._seen = {
                    k: ts for k, ts in self._seen.items()
                    if ts >= cutoff
                }

            return allowed


class BehavioralCorrelationEngine:
    """Behavioral Correlation Engine 2.0.

    Correlates time-ordered, independent user-space evidence across a process
    and its ancestry. The engine is deliberately advisory: it never kills,
    blocks, deletes, quarantines, or changes an original detector verdict.

    Design goals:
    - correlate sequence/context/timing rather than isolated events;
    - bridge parent/child telemetry without merging unrelated PIDs;
    - cap duplicate evidence families (diminishing returns);
    - preserve conservative false-positive behavior for noisy legitimate apps;
    - return an explainable incident/sequence payload for UI and persistence.
    """

    def __init__(
        self,
        window_seconds: float = 45.0,
        max_events_per_pid: int = 160,
        max_global_events: int = 2500,
    ):
        self.window_seconds = float(window_seconds)
        self.max_events_per_pid = int(max_events_per_pid)
        self._events: dict[int, deque[SecurityEvent]] = defaultdict(
            lambda: deque(maxlen=self.max_events_per_pid)
        )
        self._global: deque[SecurityEvent] = deque(maxlen=max(250, int(max_global_events)))
        self._lock = RLock()

    @staticmethod
    def _name(value: str) -> str:
        return Path(value or "").name.casefold()

    @staticmethod
    def _normalized_path(value: str) -> str:
        return str(value or "").replace("/", "\\").casefold().strip()

    @staticmethod
    def _text(event: SecurityEvent) -> str:
        data = event.data or {}
        return " ".join(
            str(x) for x in (
                event.path,
                event.process_path,
                event.process_name,
                data.get("cmdline", ""),
                data.get("command_line", ""),
                data.get("chain", ""),
                data.get("value", ""),
                data.get("previous", ""),
                data.get("remote_addr", ""),
                data.get("remote_domain", ""),
            )
            if x
        ).casefold()

    @staticmethod
    def _event_stage(event: SecurityEvent) -> str:
        text = BehavioralCorrelationEngine._text(event)
        proc = BehavioralCorrelationEngine._name(event.process_name or event.process_path)
        if event.category in {"persistence", "antispyware"}:
            return "persistence"
        if event.category == "network":
            return "network_activity"
        if event.category == "file":
            return "file_modification"
        if event.category == "process":
            if proc in HIGH_RISK_INTERPRETERS or any(x in text for x in ENCODED_HINTS):
                return "script_execution"
            if any(x in text for x in DOWNLOADER_HINTS):
                return "payload_delivery"
            return "initial_execution"
        return ""

    @staticmethod
    def _describe_event(event: SecurityEvent) -> str:
        proc = BehavioralCorrelationEngine._name(event.process_name or event.process_path) or "processo"
        if event.category == "process":
            suffix = ""
            path = event.process_path or event.path
            if path:
                suffix = f" ({Path(path).name})"
            return f"Avvio {proc}{suffix}"
        if event.category == "file":
            name = Path(event.path).name if event.path else "file"
            return f"File {event.action}: {name}"
        if event.category == "network":
            data = event.data or {}
            remote = data.get("remote_domain") or data.get("remote_addr") or event.path or "endpoint"
            port = data.get("remote_port")
            return f"Rete: {proc} → {remote}{':' + str(port) if port else ''}"
        if event.category == "persistence":
            return f"Persistenza {event.action}: {event.path or 'Windows startup'}"
        return f"{event.category}:{event.action}"

    def _recent_for_pids(self, pids: set[int], now: float) -> list[SecurityEvent]:
        cutoff = now - self.window_seconds
        out: list[SecurityEvent] = []
        seen_ids: set[int] = set()
        with self._lock:
            for pid in pids:
                if not pid:
                    continue
                for e in self._events.get(int(pid), ()):
                    if float(e.ts or 0) >= cutoff and id(e) not in seen_ids:
                        out.append(e)
                        seen_ids.add(id(e))
        out.sort(key=lambda e: float(e.ts or 0))
        return out

    def _recent_global(self, now: float) -> list[SecurityEvent]:
        cutoff = now - self.window_seconds
        with self._lock:
            return [e for e in self._global if float(e.ts or 0) >= cutoff]

    def _remember(self, event: SecurityEvent) -> None:
        pid = int(event.pid or 0)
        with self._lock:
            if pid:
                self._events[pid].append(event)
            self._global.append(event)

    @staticmethod
    def _incident_id(now: float, ancestry: list, linked_pid: int = 0) -> str:
        root_pid = int(linked_pid or 0)
        root_create = 0.0
        if ancestry:
            root = ancestry[-1]
            root_pid = int(getattr(root, "pid", root_pid) or root_pid)
            root_create = float(getattr(root, "create_time", 0.0) or 0.0)
        # The bucket is intentionally wider than the correlation window so a
        # chain remains stable while it is still actionable, without surviving
        # PID reuse indefinitely.
        bucket = int(now // 300)
        raw = f"{root_pid}:{root_create:.6f}:{bucket}".encode("utf-8")
        return "BCI-" + sha256(raw).hexdigest()[:12].upper()

    @staticmethod
    def _severity(total_score: int, confidence: float) -> str:
        if total_score >= 85 and confidence >= 0.78:
            return "critical"
        if total_score >= 60 and confidence >= 0.68:
            return "high"
        if total_score >= 45:
            return "medium"
        if total_score > 0:
            return "low"
        return "none"

    @staticmethod
    def _path_matches_payload(path: str, candidate: str) -> bool:
        a = BehavioralCorrelationEngine._normalized_path(path)
        b = BehavioralCorrelationEngine._normalized_path(candidate)
        return bool(a and b and a == b)

    def assess(self, event: SecurityEvent, ancestry: Iterable | None = None) -> CorrelationResult:
        now = float(event.ts or time())
        pid = int(event.pid or 0)
        text = self._text(event)
        proc = self._name(event.process_name or event.process_path)

        ancestry_nodes = list(ancestry or [])
        ancestry_names = [
            self._name(getattr(node, "name", "") or "")
            for node in ancestry_nodes
            if getattr(node, "name", "")
        ]
        family_pids = {pid}
        family_pids.update(
            int(getattr(node, "pid", 0) or 0)
            for node in ancestry_nodes
            if getattr(node, "pid", 0)
        )
        if event.ppid:
            family_pids.add(int(event.ppid))

        parent = ancestry_names[1] if len(ancestry_names) > 1 else ""
        recent = self._recent_for_pids(family_pids, now)
        # A global-window scan is needed only for PID-less persistence linking.
        # Keeping it off the hot process/file/network path is important for
        # high-volume real-time telemetry.
        global_recent = (
            self._recent_global(now)
            if event.category in {"persistence", "antispyware"} and not pid
            else []
        )

        reasons: list[str] = []
        family_points: dict[str, int] = {}
        family_confidence: dict[str, float] = {}
        stages: set[str] = set()
        linked_pid = pid

        def add(
            family: str,
            points: int,
            reason: str,
            confidence: float,
            stage: str = "",
        ) -> None:
            # Duplicate evidence from the same family gets diminishing returns:
            # only the strongest observation in a family contributes to score.
            family_points[family] = max(family_points.get(family, 0), int(points))
            family_confidence[family] = max(family_confidence.get(family, 0.0), float(confidence))
            if reason not in reasons:
                reasons.append(reason)
            if stage:
                stages.add(stage)

        # ---- isolated/contextual evidence (family-capped) ----
        if proc in HIGH_RISK_INTERPRETERS:
            if parent in OFFICE_PROCESSES:
                add("suspicious_parent", 18, f"Catena Office → {proc}", 0.85, "script_execution")
            elif parent in BROWSERS:
                add("suspicious_parent", 10, f"Browser → interprete script ({proc})", 0.72, "script_execution")

        if proc in {"powershell.exe", "pwsh.exe"} and any(x in text for x in ENCODED_HINTS):
            add("encoded_script", 18, "PowerShell con comando codificato", 0.90, "script_execution")

        if any(x in text for x in DOWNLOADER_HINTS):
            add("downloader", 12, "Comando compatibile con download da rete", 0.75, "payload_delivery")

        if event.category == "process" and event.action == "start":
            path = (event.process_path or event.path or "").casefold()
            if any(h in path for h in TEMP_HINTS):
                add("temp_execution", 8, "Esecuzione da directory temporanea", 0.65, "initial_execution")

        if event.category == "network" and event.action == "connect":
            stages.add("network_activity")
            if proc in HIGH_RISK_INTERPRETERS:
                add("script_network", 8, f"Interprete script con connessione di rete ({proc})", 0.68, "network_activity")

            remote = str((event.data or {}).get("remote_addr") or "")
            same_remote = sum(
                1 for e in recent
                if e.category == "network"
                and e.action == "connect"
                and str((e.data or {}).get("remote_addr") or "") == remote
            )
            if remote and same_remote >= 4 and proc not in NETWORK_NOISE_CLIENTS:
                add("repeated_endpoint", 8, "Connessioni ripetitive allo stesso endpoint", 0.62, "network_activity")

            endpoint_status = str((event.data or {}).get("endpoint_status") or "").casefold()
            if endpoint_status in {"malicious", "blocked"}:
                # Reputation already contributes to event.score. It is retained
                # as an independent family for convergence, but not double-scored.
                add("known_bad_reputation", 0, "Endpoint con reputazione locale malevola", 0.96, "network_activity")
            elif endpoint_status in {"suspicious", "watch"}:
                add("suspicious_reputation", 0, "Endpoint presente nella watchlist locale", 0.76, "network_activity")

        if event.category == "persistence":
            add("persistence", 8, "Modifica a meccanismo di persistenza Windows", 0.70, "persistence")
            if any(h in text for h in TEMP_HINTS):
                add("persistence_risky_path", 10, "Persistenza riferita a percorso temporaneo", 0.82, "persistence")

        if event.category == "antispyware":
            add("antispyware_persistence", 8, "Finding antispyware su meccanismo di persistenza", 0.76, "persistence")
            data = event.data or {}
            if data.get("user_writable"):
                add("antispyware_user_writable", 10, "Persistenza antispyware in percorso modificabile dall'utente", 0.82, "persistence")
            if str(data.get("signature_status") or "").casefold() == "notsigned":
                add("antispyware_unsigned", 8, "Target di persistenza antispyware non firmato", 0.74, "persistence")

        if event.category == "file" and any(k in event.action for k in ("write", "create")):
            stages.add("file_modification")

        if event.category == "file" and any(k in event.action for k in ("rename", "delete")):
            stages.add("file_modification")
            burst = sum(
                1 for e in recent
                if e.category == "file"
                and any(k in e.action for k in ("rename", "delete", "write"))
            )
            if burst >= 12:
                add("file_burst", 12, "Burst di modifiche file correlate allo stesso processo", 0.78, "impact")

        # ---- sequence-aware cross-event evidence ----
        family_events = recent + [event]
        family_events.sort(key=lambda e: float(e.ts or 0))

        encoded_events = [e for e in family_events if any(x in self._text(e) for x in ENCODED_HINTS)]
        downloader_events = [e for e in family_events if any(x in self._text(e) for x in DOWNLOADER_HINTS)]
        file_writes = [
            e for e in family_events
            if e.category == "file" and any(k in e.action for k in ("write", "create"))
        ]
        network_events = [
            e for e in family_events
            if e.category == "network" and e.action == "connect"
        ]
        persistence_events = [e for e in family_events if e.category in {"persistence", "antispyware"}]

        # A freshly written payload being executed is much stronger than a
        # generic "file write happened recently" heuristic.
        if event.category == "process" and event.action == "start":
            exe_path = event.process_path or event.path
            prior_file_writes = [e for e in file_writes if e is not event and float(e.ts or 0) <= now]
            matching_write = next(
                (e for e in reversed(prior_file_writes) if self._path_matches_payload(e.path, exe_path)),
                None,
            )
            if matching_write:
                add("written_payload_execution", 16, "Payload scritto di recente e poi eseguito", 0.88, "initial_execution")

        # Parent/ancestor downloader/script activity can explain a child payload
        # execution, even when the child has a different PID.
        if event.category == "process" and event.action == "start" and pid:
            prior_download = [e for e in downloader_events if float(e.ts or 0) < now]
            if prior_download and any(h in (event.process_path or event.path or "").casefold() for h in TEMP_HINTS):
                add("download_to_exec", 14, "Download recente → esecuzione payload temporaneo", 0.86, "payload_delivery")

        # Generic write→network convergence is only useful for non-noisy clients
        # or high-risk interpreters. This preserves the browser/developer FP gate.
        prior_file_writes = [e for e in file_writes if e is not event and float(e.ts or 0) <= now]
        if event.category == "network" and prior_file_writes:
            if proc not in NETWORK_NOISE_CLIENTS or proc in HIGH_RISK_INTERPRETERS:
                add("write_to_network", 6, "Connessione di rete correlata a scrittura file recente", 0.60, "network_activity")

        # Strong, ordered chains. Ordering is required: labels alone are not a detection.
        if encoded_events and network_events:
            first_encoded = min(float(e.ts or 0) for e in encoded_events)
            first_network = min(float(e.ts or 0) for e in network_events)
            if first_network >= first_encoded:
                add("encoded_to_network", 12, "Sequenza: script codificato → connessione di rete", 0.88, "network_activity")

        if downloader_events and file_writes:
            first_download = min(float(e.ts or 0) for e in downloader_events)
            later_write = any(float(e.ts or 0) >= first_download for e in file_writes)
            if later_write:
                add("download_to_write", 10, "Sequenza: download → scrittura payload", 0.82, "payload_delivery")

        if network_events and persistence_events:
            first_network = min(float(e.ts or 0) for e in network_events)
            later_persistence = any(float(e.ts or 0) >= first_network for e in persistence_events)
            if later_persistence:
                add("network_to_persistence", 12, "Sequenza: attività di rete → persistenza", 0.84, "persistence")

        # PID-less persistence events can still be correlated when their value
        # directly references a process/path observed inside the active window.
        if event.category in {"persistence", "antispyware"} and not pid:
            persistence_text = text
            for prior in reversed(global_recent):
                candidate = self._normalized_path(prior.process_path)
                candidate_name = self._name(prior.process_path or prior.process_name)
                if candidate and candidate in self._normalized_path(persistence_text):
                    linked_pid = int(prior.pid or 0)
                    add("persistence_process_link", 10, "Persistenza collegata direttamente a un processo recente", 0.86, "persistence")
                    break
                if candidate_name and len(candidate_name) >= 6 and candidate_name in persistence_text:
                    linked_pid = int(prior.pid or 0)
                    add("persistence_process_link", 6, "Persistenza collegata a un eseguibile recente", 0.70, "persistence")
                    break

        # ---- convergence bonus with diminishing returns ----
        # Zero-point reputation families count only when at least one behavioral
        # family is present; they never create a behavioral alert by themselves.
        scored_families = {k for k, v in family_points.items() if v > 0}
        corroborating = {
            k for k in family_points
            if k in {"known_bad_reputation", "suspicious_reputation"}
        }
        independent_count = len(scored_families | (corroborating if scored_families else set()))

        base_delta = sum(family_points.values())
        convergence_bonus = 0
        if independent_count >= 3:
            convergence_bonus += 8
            reasons.append("Convergenza di almeno 3 famiglie di segnali indipendenti")
        if independent_count >= 4:
            convergence_bonus += 6
        if independent_count >= 5:
            convergence_bonus += 4
        if independent_count >= 6:
            convergence_bonus += 2

        delta = base_delta + convergence_bonus

        # Noisy clients require a stronger non-network reason before a sequence
        # bonus is allowed to turn weak cache/network activity into risk.
        if proc in NETWORK_NOISE_CLIENTS and proc not in HIGH_RISK_INTERPRETERS:
            strong_non_network = any(
                family_points.get(k, 0) >= 10
                for k in {
                    "encoded_script", "downloader", "suspicious_parent",
                    "written_payload_execution", "persistence", "antispyware_persistence",
                    "persistence_risky_path", "antispyware_user_writable", "file_burst", "download_to_exec",
                }
            )
            if not strong_non_network:
                for weak in ("repeated_endpoint", "write_to_network"):
                    family_points.pop(weak, None)
                base_delta = sum(family_points.values())
                scored_families = {k for k, v in family_points.items() if v > 0}
                independent_count = len(scored_families)
                convergence_bonus = 8 if independent_count >= 3 else 0
                delta = base_delta + convergence_bonus

        confidence = max(family_confidence.values(), default=0.0)
        if independent_count >= 3:
            confidence = max(confidence, min(0.96, 0.62 + independent_count * 0.055))

        # Include stages observed in the sequence, not merely current-event stage.
        for e in family_events:
            stage = self._event_stage(e)
            if stage:
                stages.add(stage)

        chain = ""
        if ancestry_names:
            chain = " → ".join(reversed(ancestry_names))

        sequence_events = family_events[-8:]
        sequence = [self._describe_event(e) for e in sequence_events]
        # Deduplicate adjacent identical sequence labels while preserving order.
        compact_sequence: list[str] = []
        for item in sequence:
            if not compact_sequence or compact_sequence[-1] != item:
                compact_sequence.append(item)

        total_score = min(100, int(event.score or 0) + max(0, int(delta)))
        severity = self._severity(total_score, confidence)
        incident_id = self._incident_id(now, ancestry_nodes, linked_pid=linked_pid)

        self._remember(event)

        return CorrelationResult(
            score_delta=delta,
            reasons=list(dict.fromkeys(reasons)),
            chain=chain,
            confidence=confidence,
            severity=severity,
            stages=sorted(stages, key=lambda x: STAGE_ORDER.get(x, 999)),
            evidence_families=sorted(family_points),
            sequence=compact_sequence,
            incident_id=incident_id,
            total_score=total_score,
        ).bounded()
