from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
import time

from .scoring import Signal, assess


CANARY_NAME = ".bc_sentinel_canary.txt"
CANARY_CONTENT = (
    "BC Sentinel managed ransomware canary.\n"
    "This harmless file is intentionally monitored. Do not edit it.\n"
).encode()

STRONG_SIGNAL_KEYS = {
    "honeypot_touched",
    "entropy_spike",
    "mass_extension_change",
}


@dataclass(slots=True)
class FsEvent:
    ts: float
    kind: str
    path: str
    source_path: str = ""
    process_hint: str = ""
    entropy_delta: float = 0.0
    honeypot: bool = False
    extension_changed: bool = False


class HoneypotManager:
    """Creates harmless hidden canaries only in ransomware-protected user folders."""

    def __init__(self, folders: list[str]):
        self.folders = [Path(x) for x in folders]
        self.paths: set[str] = set()

    def deploy(self) -> set[str]:
        for folder in self.folders:
            try:
                if not folder.exists() or not folder.is_dir():
                    continue

                p = folder / CANARY_NAME
                if not p.exists():
                    p.write_bytes(CANARY_CONTENT)

                self.paths.add(str(p.resolve()).lower())

                if __import__("os").name == "nt":
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x2)  # HIDDEN
                    except Exception:
                        pass
            except OSError:
                continue
        return set(self.paths)

    def is_canary(self, path: str) -> bool:
        try:
            return str(Path(path).resolve()).lower() in self.paths
        except OSError:
            return False


class RansomwareHeuristic:
    """Conservative user-space correlation engine.

    v0.1.6 intentionally treats raw file bursts as telemetry, not a reason to
    frighten the user. A HIGH/CRITICAL user alert requires at least one strong
    independent signal such as a canary touch, entropy spike or mass extension
    mutation.
    """

    def __init__(self, window_seconds: int = 8):
        self.window = window_seconds
        self.events: deque[FsEvent] = deque()

    def push(self, event: FsEvent):
        now = event.ts or time.time()
        self.events.append(event)
        while self.events and now - self.events[0].ts > self.window:
            self.events.popleft()
        return self.assess()

    def assess(self):
        ev = list(self.events)
        signals: list[Signal] = []

        modified = sum(e.kind in {"modified", "created"} for e in ev)
        renamed = sum(e.kind == "renamed" for e in ev)
        deleted = sum(e.kind == "deleted" for e in ev)
        honeypots = sum(e.honeypot for e in ev)
        entropy_spikes = sum(e.entropy_delta >= 1.0 for e in ev)
        extension_changes = sum(e.extension_changed for e in ev)

        # Burst-only evidence is deliberately low-weight.
        if modified >= 40:
            signals.append(Signal(
                "mass_file_modification",
                18,
                "Molti file sono stati modificati in pochi secondi.",
            ))

        if renamed >= 20:
            signals.append(Signal(
                "mass_rename",
                15,
                "Sono stati rinominati molti file rapidamente.",
            ))

        if deleted >= 20:
            signals.append(Signal(
                "mass_delete",
                12,
                "Sono stati eliminati molti file rapidamente.",
            ))

        # Strong evidence.
        if extension_changes >= 10:
            signals.append(Signal(
                "mass_extension_change",
                30,
                "Molti file hanno cambiato estensione in un intervallo molto breve.",
            ))

        if entropy_spikes >= 10:
            signals.append(Signal(
                "entropy_spike",
                35,
                "Diversi file mostrano un aumento rapido dell'entropia.",
            ))

        if honeypots:
            signals.append(Signal(
                "honeypot_touched",
                55,
                "Un file-esca protetto da BC Sentinel è stato modificato.",
            ))

        # Correlation bonus: useful for classification, but never a strong
        # independent signal by itself.
        burst_keys = {
            s.key for s in signals
            if s.key in {"mass_file_modification", "mass_rename", "mass_delete"}
        }
        if len(burst_keys) >= 3:
            signals.append(Signal(
                "ransomware_correlation",
                10,
                "Più pattern di attività file anomala coincidono.",
            ))

        if any(s.key in STRONG_SIGNAL_KEYS for s in signals) and burst_keys:
            signals.append(Signal(
                "strong_ransomware_correlation",
                10,
                "Un segnale forte coincide con un burst anomalo di operazioni sui file.",
            ))

        return assess(signals)

    @staticmethod
    def has_strong_signal(assessment) -> bool:
        return any(s.key in STRONG_SIGNAL_KEYS for s in assessment.signals)

    def should_alert(self, assessment) -> bool:
        return assessment.score >= 70 and self.has_strong_signal(assessment)
