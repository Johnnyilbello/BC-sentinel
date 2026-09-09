from __future__ import annotations
from pathlib import Path
import time
from .config import RULES_DIR, PROGRAM_DATA_DIR
from .scoring import Signal
from .path_security import has_reparse_component, is_reparse_point

THREAT_YARA_DIR = PROGRAM_DATA_DIR / "Protection" / "ThreatIntelligence" / "active-yara"


class YaraEngine:
    def __init__(self, rules_dir: Path = RULES_DIR, threat_rules_dir: Path | None = None):
        self.rules_dir = Path(rules_dir)
        self.threat_rules_dir = Path(threat_rules_dir) if threat_rules_dir is not None else THREAT_YARA_DIR
        self.available = False
        self.rules = None
        self.error = None
        self._snapshot: tuple = ()
        self._last_refresh_check = 0.0
        self._refresh_interval = 2.0
        self._compile_rules(force=True)

    def _rule_files(self) -> list[tuple[str, Path]]:
        out: list[tuple[str, Path]] = []
        for prefix, root in (("builtin", self.rules_dir), ("threat", self.threat_rules_dir)):
            try:
                if prefix == "threat" and root.exists() and (is_reparse_point(root) or has_reparse_component(root, include_leaf=True)):
                    files = []
                else:
                    files = sorted(root.glob("*.yar")) if root.exists() else []
            except OSError:
                files = []
            for idx, path in enumerate(files):
                out.append((f"{prefix}_{idx}_{path.stem}", path))
        return out

    @staticmethod
    def _snapshot_for(files: list[tuple[str, Path]]) -> tuple:
        rows = []
        for namespace, path in files:
            try:
                st = path.stat()
                rows.append((namespace, str(path), int(st.st_mtime_ns), int(st.st_size)))
            except OSError:
                rows.append((namespace, str(path), 0, -1))
        return tuple(rows)

    def _compile_rules(self, *, force: bool = False) -> None:
        try:
            import yara
            files = self._rule_files()
            snapshot = self._snapshot_for(files)
            if not force and snapshot == self._snapshot:
                return
            if files:
                mapping = {namespace: str(path) for namespace, path in files}
                self.rules = yara.compile(filepaths=mapping)
                self.available = True
                self.error = None
            else:
                self.rules = None
                self.available = False
                self.error = None
            self._snapshot = snapshot
        except Exception as exc:
            # Fail safe: retain the previously compiled known-good rules if
            # refresh fails, and surface the error for diagnostics.
            self.error = str(exc)
            if self.rules is None:
                self.available = False

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if (now - self._last_refresh_check) < self._refresh_interval:
            return
        self._last_refresh_check = now
        self._compile_rules(force=False)

    def scan_data(self, data: bytes, timeout: int = 3) -> list[Signal]:
        """Scan already-read bytes without reopening the file.

        v0.8 also hot-reloads a machine-owned signed-threat YARA directory.
        If refresh compilation fails, the last known compiled rules remain in
        memory rather than dropping protection.
        """
        self._maybe_refresh()
        if not self.available or not self.rules:
            return []
        try:
            matches = self.rules.match(data=bytes(data), timeout=timeout)
        except Exception:
            return []
        out = []
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            weight = int(meta.get("weight", 15))
            desc = str(meta.get("description", f"YARA: {match.rule}"))
            out.append(Signal(f"yara:{match.rule}", weight, desc, "yara"))
        return out

    def scan(self, path: str, timeout: int = 3) -> list[Signal]:
        self._maybe_refresh()
        if not self.available or not self.rules:
            return []
        try:
            matches = self.rules.match(path, timeout=timeout)
        except Exception:
            return []
        out = []
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            weight = int(meta.get("weight", 15))
            desc = str(meta.get("description", f"YARA: {match.rule}"))
            out.append(Signal(f"yara:{match.rule}", weight, desc, "yara"))
        return out
