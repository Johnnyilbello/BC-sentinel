from __future__ import annotations

from collections import OrderedDict, deque
import os
from threading import Condition, Lock, Thread
from time import monotonic, thread_time
from weakref import WeakKeyDictionary


class CoalescingEventHandlerProxy:
    """Low-CPU watchdog dispatch boundary for BC Sentinel.

    Watchdog's Windows observer thread must stay cheap: it receives filesystem
    notifications and should not execute BC Sentinel's heavier scan/correlation
    pipeline inline. This proxy therefore moves forwarded events to one daemon
    worker and quiet-period debounces repeated file ``modified`` notifications.

    Multiple watchdog roots in one RealtimeMonitor use the same underlying
    handler. Construction is therefore shared per live inner handler so those
    roots feed one BCS-RealtimeDispatch worker instead of creating one worker
    per root. This changes scheduling overhead only; it does not remove watched
    roots or suppress security event classes.

    Security invariants:
    - create, move, delete and other non-modified events are never intentionally
      dropped; they are queued immediately;
    - directory-only ``modified`` metadata noise is dropped because watchdog
      also emits the concrete child file event;
    - repeated file ``modified`` notifications are collapsed only while the
      same path is still changing, then one final event is forwarded after the
      short quiet window;
    - if an internal defensive bound is reached, the event is forwarded
      synchronously rather than discarded.

    Modified deadlines use one ordered entry per path. Because every deadline is
    ``monotonic() + fixed_window``, new/extended deadlines are naturally
    non-decreasing. Moving an updated path to the end therefore preserves exact
    quiet-period semantics without heap stale entries or full-map rescans.

    Lightweight runtime diagnostics attribute CPU spent inside the wrapped
    realtime handler by monitored-root category and watchdog event type. Root
    detection includes structural Windows path recognition so a LocalSystem
    service can still classify the interactive user's Downloads/Desktop/etc.
    The worker name carries the dominant bucket and path group for the external
    benchmark. Diagnostics never suppress or rewrite security events.
    """

    DEFAULT_MODIFIED_WINDOW_SECONDS = 0.50
    DEFAULT_MAX_IMMEDIATE_EVENTS = 4096
    DEFAULT_MAX_PENDING_MODIFIED = 4096

    _registry_lock = Lock()
    _instances_by_inner: WeakKeyDictionary = WeakKeyDictionary()

    def __new__(cls, inner, *args, **kwargs):
        try:
            with cls._registry_lock:
                existing = cls._instances_by_inner.get(inner)
                if existing is not None and not bool(getattr(existing, "_closed", False)):
                    return existing
                instance = super().__new__(cls)
                cls._instances_by_inner[inner] = instance
                return instance
        except TypeError:
            return super().__new__(cls)

    def __init__(
        self,
        inner,
        *,
        modified_window_seconds: float = DEFAULT_MODIFIED_WINDOW_SECONDS,
        max_immediate_events: int = DEFAULT_MAX_IMMEDIATE_EVENTS,
        max_pending_modified: int = DEFAULT_MAX_PENDING_MODIFIED,
    ) -> None:
        if bool(getattr(self, "_initialized", False)):
            self.shared_reuses += 1
            return

        self._initialized = True
        self._inner = inner
        self._modified_window_seconds = max(0.0, float(modified_window_seconds))
        self._max_immediate_events = max(128, int(max_immediate_events))
        self._max_pending_modified = max(128, int(max_pending_modified))

        self._cv = Condition()
        self._diag_lock = Lock()
        self._immediate = deque()
        self._pending_modified: OrderedDict[str, tuple[float, object]] = OrderedDict()
        self._stopping = False
        self._closed = False

        self.received = 0
        self.forwarded = 0
        self.coalesced = 0
        self.directory_modified_dropped = 0
        self.queue_fallbacks = 0
        self.worker_errors = 0
        self.scheduler_deadline_updates = 0
        self.scheduler_reorders = 0
        self.worker_waits = 0
        self.shared_reuses = 0

        self._forward_counts: dict[str, int] = {}
        self._forward_cpu_seconds: dict[str, float] = {}
        self._forward_detail_cpu_seconds: dict[str, float] = {}
        self._dominant_bucket = "none"
        self._dominant_bucket_cpu_seconds = 0.0
        self._dominant_detail = "none"
        self._dominant_detail_cpu_seconds = 0.0
        self._diagnostic_roots = self._build_diagnostic_roots()

        self._worker = Thread(
            target=self._run,
            name="BCS-RealtimeDispatch",
            daemon=True,
        )
        self._worker.start()

    @staticmethod
    def _normalize_path(raw: str) -> str:
        if not raw:
            return ""
        try:
            return os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(raw))))
        except Exception:
            return os.path.normcase(str(raw))

    @staticmethod
    def _windows_parts(raw: str) -> list[str]:
        text = str(raw or "").replace("/", "\\")
        return [part for part in text.split("\\") if part]

    @classmethod
    def _build_diagnostic_roots(cls) -> list[tuple[str, str]]:
        home = os.path.expanduser("~")
        candidates = (
            ("Downloads", os.path.join(home, "Downloads")),
            ("Desktop", os.path.join(home, "Desktop")),
            ("Documents", os.path.join(home, "Documents")),
            ("Temp", os.getenv("TEMP", "")),
            ("AppData", os.getenv("APPDATA", "")),
        )
        roots: list[tuple[str, str]] = []
        seen: set[str] = set()
        for label, raw in candidates:
            normalized = cls._normalize_path(raw)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            roots.append((label, normalized))
        roots.sort(key=lambda item: len(item[1]), reverse=True)
        return roots

    @classmethod
    def _structural_root_label(cls, raw_path: str) -> str | None:
        parts = [part.casefold() for part in cls._windows_parts(raw_path)]
        if not parts:
            return None

        for marker, label in (
            ("downloads", "Downloads"),
            ("desktop", "Desktop"),
            ("documents", "Documents"),
        ):
            if marker in parts:
                return label

        for index, part in enumerate(parts):
            if part != "appdata":
                continue
            if index + 2 < len(parts) and parts[index + 1] == "local" and parts[index + 2] == "temp":
                return "Temp"
            if index + 1 < len(parts) and parts[index + 1] == "roaming":
                return "AppData"
        return None

    def _diagnostic_root_label(self, raw_path: str) -> str:
        structural = self._structural_root_label(raw_path)
        if structural:
            return structural

        path = self._normalize_path(raw_path)
        for label, root in self._diagnostic_roots:
            if path == root or path.startswith(root + os.sep):
                return label
        return "Other"

    @classmethod
    def _diagnostic_path_group(cls, raw_path: str, root_label: str) -> str:
        parts = cls._windows_parts(raw_path)
        if not parts:
            return "unknown"
        folded = [part.casefold() for part in parts]

        marker_candidates = {
            "Downloads": ("downloads",),
            "Desktop": ("desktop",),
            "Documents": ("documents",),
            "AppData": ("roaming",),
            "Temp": ("temp",),
        }
        markers = marker_candidates.get(root_label, ())
        for marker in markers:
            if marker in folded:
                index = folded.index(marker)
                if index + 1 < len(parts):
                    child = parts[index + 1]
                    return child[:36] if child else root_label
                return root_label

        if len(parts) >= 2:
            parent = parts[-2]
            return parent[:36] if parent else "Other"
        return parts[-1][:36] or "Other"

    def _diagnostic_identity(self, event) -> tuple[str, str]:
        event_type = str(getattr(event, "event_type", "") or "unknown").lower()
        raw_path = str(getattr(event, "src_path", "") or getattr(event, "dest_path", "") or "")
        root_label = self._diagnostic_root_label(raw_path)
        bucket = f"{root_label}:{event_type}"
        group = self._diagnostic_path_group(raw_path, root_label)
        detail = f"{bucket}|{group}"
        return bucket, detail

    def _record_forward_diagnostic(self, bucket: str, detail: str, cpu_seconds: float) -> None:
        cpu = max(0.0, float(cpu_seconds))
        with self._diag_lock:
            self._forward_counts[bucket] = self._forward_counts.get(bucket, 0) + 1
            total_cpu = self._forward_cpu_seconds.get(bucket, 0.0) + cpu
            self._forward_cpu_seconds[bucket] = total_cpu
            detail_cpu = self._forward_detail_cpu_seconds.get(detail, 0.0) + cpu
            self._forward_detail_cpu_seconds[detail] = detail_cpu

            if total_cpu >= self._dominant_bucket_cpu_seconds:
                self._dominant_bucket = bucket
                self._dominant_bucket_cpu_seconds = total_cpu
            if detail_cpu >= self._dominant_detail_cpu_seconds:
                self._dominant_detail = detail
                self._dominant_detail_cpu_seconds = detail_cpu
                try:
                    self._worker.name = f"BCS-RealtimeDispatch[{detail}]"
                except Exception:
                    pass

    def dispatch(self, event):
        self.received += 1
        event_type = str(getattr(event, "event_type", "") or "").lower()
        is_directory = bool(getattr(event, "is_directory", False))

        if is_directory and event_type == "modified":
            self.directory_modified_dropped += 1
            return None

        if not is_directory and event_type == "modified":
            path = str(getattr(event, "src_path", "") or "")
            if path and self._modified_window_seconds > 0.0:
                deadline = monotonic() + self._modified_window_seconds
                fallback = None
                with self._cv:
                    if self._closed:
                        fallback = event
                    else:
                        was_empty = not self._pending_modified
                        already_pending = path in self._pending_modified
                        if already_pending:
                            self.coalesced += 1
                        elif len(self._pending_modified) >= self._max_pending_modified:
                            fallback = event
                            self.queue_fallbacks += 1

                        if fallback is None:
                            self._pending_modified[path] = (deadline, event)
                            self.scheduler_deadline_updates += 1
                            if already_pending:
                                self._pending_modified.move_to_end(path)
                                self.scheduler_reorders += 1
                            if was_empty:
                                self._cv.notify()
                if fallback is None:
                    return None
                return self._forward(fallback)

        fallback = None
        with self._cv:
            if self._closed:
                fallback = event
            elif len(self._immediate) >= self._max_immediate_events:
                fallback = event
                self.queue_fallbacks += 1
            else:
                self._immediate.append(event)
                self._cv.notify()

        if fallback is not None:
            return self._forward(fallback)
        return None

    def close(self, timeout: float = 2.0) -> None:
        with self._cv:
            if self._closed:
                return
            self._stopping = True
            self._cv.notify_all()
        self._worker.join(timeout=max(0.0, float(timeout)))
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def status(self) -> dict[str, object]:
        with self._cv:
            base = {
                "received": int(self.received),
                "forwarded": int(self.forwarded),
                "coalesced": int(self.coalesced),
                "directory_modified_dropped": int(self.directory_modified_dropped),
                "queue_fallbacks": int(self.queue_fallbacks),
                "worker_errors": int(self.worker_errors),
                "immediate_pending": len(self._immediate),
                "modified_pending": len(self._pending_modified),
                "scheduler_order_entries": len(self._pending_modified),
                "scheduler_deadline_updates": int(self.scheduler_deadline_updates),
                "scheduler_reorders": int(self.scheduler_reorders),
                "dispatch_sharing_profile": "shared_by_inner_v1",
                "shared_reuses": int(self.shared_reuses),
                "scheduler_heap_entries": 0,
                "scheduler_heap_pushes": 0,
                "scheduler_stale_pops": 0,
                "scheduler_compactions": 0,
                "worker_waits": int(self.worker_waits),
                "worker_alive": bool(self._worker.is_alive()),
            }
        with self._diag_lock:
            base.update(
                {
                    "diagnostic_profile": "root_event_path_cpu_v2",
                    "diagnostic_dominant_bucket": self._dominant_bucket,
                    "diagnostic_dominant_cpu_seconds": round(self._dominant_bucket_cpu_seconds, 6),
                    "diagnostic_dominant_detail": self._dominant_detail,
                    "diagnostic_dominant_detail_cpu_seconds": round(self._dominant_detail_cpu_seconds, 6),
                    "diagnostic_forward_counts": dict(sorted(self._forward_counts.items())),
                    "diagnostic_forward_cpu_seconds": {
                        key: round(value, 6)
                        for key, value in sorted(self._forward_cpu_seconds.items())
                    },
                    "diagnostic_detail_cpu_seconds": {
                        key: round(value, 6)
                        for key, value in sorted(self._forward_detail_cpu_seconds.items())
                    },
                }
            )
        return base

    def _run(self) -> None:
        while True:
            event = None
            with self._cv:
                while event is None:
                    if self._immediate:
                        event = self._immediate.popleft()
                        break

                    now = monotonic()
                    due_deadline = None
                    if self._pending_modified:
                        path, (deadline, pending_event) = next(iter(self._pending_modified.items()))
                        due_deadline = deadline
                        if self._stopping or deadline <= now:
                            self._pending_modified.pop(path, None)
                            event = pending_event
                            break

                    if self._stopping and not self._pending_modified:
                        self._closed = True
                        return

                    self.worker_waits += 1
                    if due_deadline is None:
                        self._cv.wait()
                    else:
                        self._cv.wait(timeout=max(0.0, due_deadline - now))

            try:
                self._forward(event)
            except Exception:
                self.worker_errors += 1

    def _forward(self, event):
        bucket, detail = self._diagnostic_identity(event)
        cpu_started = thread_time()
        try:
            result = self._inner.dispatch(event)
            self.forwarded += 1
            return result
        finally:
            self._record_forward_diagnostic(bucket, detail, thread_time() - cpu_started)
