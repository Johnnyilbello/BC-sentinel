from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .config import POTENTIALLY_EXECUTABLE, Settings
from .database import Database
from .scanner import StaticScanner, is_self_managed_path
from .reputation import ReputationEngine
from .path_security import canonical_path, is_reparse_point
from .ransomware import RansomwareHeuristic, HoneypotManager, FsEvent
from .core.events import ProcessAttribution


class RealtimeMonitor:
    def __init__(
        self,
        settings: Settings | None = None,
        db: Database | None = None,
        callback=None,
        ransomware_callback=None,
        correlator=None,
    ):
        self.settings = settings or Settings.defaults()
        self.db = db or Database()
        self.reputation = ReputationEngine(self.db)
        self.scanner = StaticScanner(
            self.settings, reputation_engine=self.reputation, db=self.db
        )
        self.callback = callback
        self.ransomware_callback = ransomware_callback
        self.correlator = correlator

        self._observer = None
        self._debounce: dict[str, float] = {}
        self._recent_hashes: dict[str, float] = {}
        self._scan_lock = threading.RLock()

        self.ransomware = RansomwareHeuristic()
        self.canaries = HoneypotManager(self.settings.ransomware_dirs)
        self.canaries.deploy()

        self._started_monotonic = time.monotonic()
        self._last_ransomware_alert = 0.0
        self._last_ransomware_log = 0.0

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            return False

        outer = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    outer._fs_event("created", event.src_path)
                    outer._queue_scan(event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    outer._fs_event("modified", event.src_path)
                    outer._queue_scan(event.src_path)

            def on_deleted(self, event):
                if not event.is_directory:
                    outer._fs_event("deleted", event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    outer._fs_event(
                        "renamed",
                        event.dest_path,
                        source_path=event.src_path,
                    )
                    outer._queue_scan(event.dest_path)

        obs = Observer()
        handler = Handler()
        scheduled = 0

        # Static real-time scanning still watches the configured locations,
        # including Temp/AppData. Ransomware scoring is filtered separately.
        for raw in self.settings.monitored_dirs:
            p = Path(raw)
            if p.exists() and p.is_dir():
                try:
                    obs.schedule(handler, str(p), recursive=True)
                    scheduled += 1
                except OSError:
                    continue

        if not scheduled:
            return False

        self._started_monotonic = time.monotonic()
        obs.start()
        self._observer = obs
        return True

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None

    @staticmethod
    def _is_under(path: str, roots: list[str]) -> bool:
        try:
            p = Path(path).expanduser().resolve(strict=False)
        except OSError:
            return False

        for raw in roots:
            try:
                root = Path(raw).expanduser().resolve(strict=False)
                p.relative_to(root)
                return True
            except (OSError, ValueError):
                continue
        return False

    def _is_ransomware_path(self, path: str) -> bool:
        if not self._is_under(path, self.settings.ransomware_dirs):
            return False

        if is_self_managed_path(path):
            return False

        # Extra local exclusions for noisy dev/package/build trees if a user
        # happens to place BC Sentinel or another project inside Documents/Desktop.
        lowered = str(path).lower().replace("/", "\\")
        noisy_parts = (
            "\\.venv\\",
            "\\venv\\",
            "\\__pycache__\\",
            "\\node_modules\\",
            "\\.git\\",
            "\\dist\\",
            "\\build\\",
        )
        return not any(part in lowered for part in noisy_parts)

    def _fs_event(self, kind: str, path: str, source_path: str = ""):
        if not self.settings.ransomware_enabled:
            return

        # Ignore startup/install churn while the application and Python packages
        # finish initializing.
        if (
            time.monotonic() - self._started_monotonic
            < max(0, int(self.settings.ransomware_startup_grace_seconds))
        ):
            return

        if not self._is_ransomware_path(path):
            return

        extension_changed = False
        if kind == "renamed" and source_path:
            try:
                extension_changed = (
                    Path(source_path).suffix.lower() != Path(path).suffix.lower()
                )
            except Exception:
                extension_changed = False

        attribution = self.correlator.attribute(path, max_age=4.0) if self.correlator is not None else ProcessAttribution()
        result = self.ransomware.push(FsEvent(
            ts=time.time(),
            kind=kind,
            path=path,
            source_path=source_path,
            process_hint=attribution.name or attribution.path,
            honeypot=self.canaries.is_canary(path) or (bool(source_path) and self.canaries.is_canary(source_path)),
            extension_changed=extension_changed,
        ))

        now = time.monotonic()

        # SUSPICIOUS+ telemetry may be logged, but avoid hammering the DB.
        if result.score >= 50 and now - self._last_ransomware_log > 30:
            self._last_ransomware_log = now
            self.db.execute(
                """
                INSERT INTO behavior_events(category,source,detail_json,score)
                VALUES(?,?,?,?)
                """,
                (
                    "ransomware",
                    path,
                    json.dumps({
                        "reasons": result.reasons,
                        "strong_signal": self.ransomware.has_strong_signal(result),
                        "process": attribution.to_dict(),
                    }),
                    result.score,
                ),
            )

        # User-facing alert requires a strong signal + HIGH/CRITICAL score.
        if (
            self.ransomware.should_alert(result)
            and now - self._last_ransomware_alert > 60
        ):
            self._last_ransomware_alert = now
            if self.ransomware_callback:
                try:
                    self.ransomware_callback(path, result, attribution)
                except TypeError:
                    self.ransomware_callback(path, result)

    def _queue_scan(self, path: str):
        p = Path(path)

        if p.name == ".bc_sentinel_canary.txt":
            return
        if p.suffix.lower() not in POTENTIALLY_EXECUTABLE:
            return
        if is_self_managed_path(p) or is_reparse_point(p):
            return
        try:
            if self.db.is_path_allowlisted(str(p)):
                return
        except (OSError, ValueError):
            pass

        key = canonical_path(p)
        now = time.monotonic()
        with self._scan_lock:
            if now - self._debounce.get(key, 0) < 2.0:
                return
            self._debounce[key] = now
        threading.Thread(
            target=self._scan_when_stable,
            args=(path,),
            name="BCS-RealtimeScan",
            daemon=True,
        ).start()

    def _scan_when_stable(self, path: str):
        p = Path(path)
        last = None
        stable = None

        # Wait for writers to settle, but do not treat mtime+size as content
        # identity. A malicious writer can restore both values after changing
        # executable bytes. The 2-second event debounce already collapses event
        # storms; every accepted executable event receives a real content scan.
        for _ in range(8):
            try:
                st = p.stat()
                fingerprint = (int(st.st_mtime_ns), int(st.st_size))
            except OSError:
                return

            if fingerprint == last:
                stable = fingerprint
                break

            last = fingerprint
            time.sleep(0.15)

        if stable is None:
            return

        try:
            report = self.scanner.scan_file(p)
        except Exception:
            return

        signed_ioc = self.db.match_ioc_hash(report.sha256) if hasattr(self.db, "match_ioc_hash") else None
        if signed_ioc is None and self.db.is_allowlisted(report.path, report.sha256):
            return

        now = time.monotonic()
        last = self._recent_hashes.get(report.sha256, 0.0)

        if now - last < 600:
            return

        self._recent_hashes[report.sha256] = now

        if len(self._recent_hashes) > 2048:
            self._recent_hashes = {
                h: ts
                for h, ts in self._recent_hashes.items()
                if now - ts < 600
            }

        a = report.assessment

        inserted = self.db.add_detection(
            report.path,
            report.sha256,
            a.score,
            a.level,
            json.dumps(a.reasons),
            "logged",
            dedupe_minutes=10,
        )

        if inserted and self.callback and a.score >= 50:
            self.callback(report)
