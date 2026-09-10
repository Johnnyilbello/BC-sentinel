from __future__ import annotations

from collections import deque
from threading import Condition, Thread
from time import monotonic


class CoalescingEventHandlerProxy:
    """Low-CPU watchdog dispatch boundary for BC Sentinel.

    Watchdog's Windows observer thread must stay cheap: it receives filesystem
    notifications and should not execute BC Sentinel's heavier scan/correlation
    pipeline inline. This proxy therefore moves forwarded events to one daemon
    worker and quiet-period debounces repeated file ``modified`` notifications.

    Security invariants:
    - create, move, delete and other non-modified events are never intentionally
      dropped; they are queued immediately;
    - directory-only ``modified`` metadata noise is dropped because watchdog
      also emits the concrete child file event;
    - repeated file ``modified`` notifications are collapsed only while the
      same path is still changing, then one final event is forwarded after the
      short quiet window;
    - if the immediate queue ever reaches its defensive bound, the event is
      forwarded synchronously rather than discarded.
    """

    DEFAULT_MODIFIED_WINDOW_SECONDS = 0.50
    DEFAULT_MAX_IMMEDIATE_EVENTS = 4096
    DEFAULT_MAX_PENDING_MODIFIED = 4096

    def __init__(
        self,
        inner,
        *,
        modified_window_seconds: float = DEFAULT_MODIFIED_WINDOW_SECONDS,
        max_immediate_events: int = DEFAULT_MAX_IMMEDIATE_EVENTS,
        max_pending_modified: int = DEFAULT_MAX_PENDING_MODIFIED,
    ) -> None:
        self._inner = inner
        self._modified_window_seconds = max(0.0, float(modified_window_seconds))
        self._max_immediate_events = max(128, int(max_immediate_events))
        self._max_pending_modified = max(128, int(max_pending_modified))

        self._cv = Condition()
        self._immediate = deque()
        self._pending_modified: dict[str, tuple[float, object]] = {}
        self._stopping = False
        self._closed = False

        self.received = 0
        self.forwarded = 0
        self.coalesced = 0
        self.directory_modified_dropped = 0
        self.queue_fallbacks = 0
        self.worker_errors = 0

        self._worker = Thread(
            target=self._run,
            name="BCS-RealtimeDispatch",
            daemon=True,
        )
        self._worker.start()

    def dispatch(self, event):
        """Accept a watchdog event without doing heavy realtime work inline."""
        self.received += 1
        event_type = str(getattr(event, "event_type", "") or "").lower()
        is_directory = bool(getattr(event, "is_directory", False))

        if is_directory and event_type == "modified":
            self.directory_modified_dropped += 1
            return None

        if not is_directory and event_type == "modified":
            path = str(getattr(event, "src_path", "") or "")
            if path and self._modified_window_seconds > 0.0:
                now = monotonic()
                deadline = now + self._modified_window_seconds
                fallback = None
                with self._cv:
                    if self._closed:
                        fallback = event
                    else:
                        if path in self._pending_modified:
                            self.coalesced += 1
                        elif len(self._pending_modified) >= self._max_pending_modified:
                            fallback = event
                            self.queue_fallbacks += 1
                        if fallback is None:
                            self._pending_modified[path] = (deadline, event)
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
        """Flush queued work once and stop the worker; safe to call repeatedly."""
        with self._cv:
            if self._closed:
                return
            self._stopping = True
            self._cv.notify_all()
        self._worker.join(timeout=max(0.0, float(timeout)))
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def status(self) -> dict[str, int | bool]:
        with self._cv:
            return {
                "received": int(self.received),
                "forwarded": int(self.forwarded),
                "coalesced": int(self.coalesced),
                "directory_modified_dropped": int(self.directory_modified_dropped),
                "queue_fallbacks": int(self.queue_fallbacks),
                "worker_errors": int(self.worker_errors),
                "immediate_pending": len(self._immediate),
                "modified_pending": len(self._pending_modified),
                "worker_alive": bool(self._worker.is_alive()),
            }

    def _run(self) -> None:
        while True:
            event = None
            with self._cv:
                while event is None:
                    if self._immediate:
                        event = self._immediate.popleft()
                        break

                    now = monotonic()
                    due_path = None
                    due_deadline = None
                    for path, (deadline, _) in self._pending_modified.items():
                        if due_deadline is None or deadline < due_deadline:
                            due_path = path
                            due_deadline = deadline

                    if due_path is not None and (self._stopping or due_deadline <= now):
                        _, event = self._pending_modified.pop(due_path)
                        break

                    if self._stopping and not self._pending_modified:
                        self._closed = True
                        return

                    if due_deadline is None:
                        self._cv.wait()
                    else:
                        self._cv.wait(timeout=max(0.0, due_deadline - now))

            try:
                self._forward(event)
            except Exception:
                # Preserve the observer/worker lifetime. The wrapped BC Sentinel
                # handler owns its normal error/reporting policy; this counter is
                # diagnostic evidence if an unexpected exception escapes it.
                self.worker_errors += 1

    def _forward(self, event):
        result = self._inner.dispatch(event)
        self.forwarded += 1
        return result
