from __future__ import annotations

from collections import deque
import heapq
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

    The modified-event scheduler uses a min-heap with lazy invalidation. This
    preserves the same debounce semantics without rescanning every pending path
    after each notification, which is important on Windows roots with high
    background filesystem churn.
    """

    DEFAULT_MODIFIED_WINDOW_SECONDS = 0.50
    DEFAULT_MAX_IMMEDIATE_EVENTS = 4096
    DEFAULT_MAX_PENDING_MODIFIED = 4096
    _HEAP_COMPACT_MIN_ENTRIES = 1024
    _HEAP_COMPACT_RATIO = 4

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
        self._pending_modified: dict[str, tuple[float, int, object]] = {}
        self._modified_heap: list[tuple[float, int, str]] = []
        self._sequence = 0
        self._stopping = False
        self._closed = False

        self.received = 0
        self.forwarded = 0
        self.coalesced = 0
        self.directory_modified_dropped = 0
        self.queue_fallbacks = 0
        self.worker_errors = 0
        self.scheduler_heap_pushes = 0
        self.scheduler_stale_pops = 0
        self.scheduler_compactions = 0
        self.worker_waits = 0

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
                deadline = monotonic() + self._modified_window_seconds
                fallback = None
                with self._cv:
                    if self._closed:
                        fallback = event
                    else:
                        was_empty = not self._pending_modified
                        if path in self._pending_modified:
                            self.coalesced += 1
                        elif len(self._pending_modified) >= self._max_pending_modified:
                            fallback = event
                            self.queue_fallbacks += 1

                        if fallback is None:
                            self._sequence += 1
                            sequence = self._sequence
                            self._pending_modified[path] = (deadline, sequence, event)
                            heapq.heappush(self._modified_heap, (deadline, sequence, path))
                            self.scheduler_heap_pushes += 1
                            self._maybe_compact_heap_locked()

                            # A first pending modified event must wake an idle worker.
                            # Later events use the same fixed debounce window and can
                            # only have deadlines >= the earliest existing deadline.
                            # Repeated same-path modifications therefore do not need to
                            # wake the worker on every extension; a stale heap entry will
                            # be discarded lazily when its old deadline is reached.
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
                "scheduler_heap_entries": len(self._modified_heap),
                "scheduler_heap_pushes": int(self.scheduler_heap_pushes),
                "scheduler_stale_pops": int(self.scheduler_stale_pops),
                "scheduler_compactions": int(self.scheduler_compactions),
                "worker_waits": int(self.worker_waits),
                "worker_alive": bool(self._worker.is_alive()),
            }

    def _maybe_compact_heap_locked(self) -> None:
        pending = len(self._pending_modified)
        if pending <= 0:
            self._modified_heap.clear()
            return
        threshold = max(
            self._HEAP_COMPACT_MIN_ENTRIES,
            pending * self._HEAP_COMPACT_RATIO,
        )
        if len(self._modified_heap) <= threshold:
            return
        self._modified_heap = [
            (deadline, sequence, path)
            for path, (deadline, sequence, _event) in self._pending_modified.items()
        ]
        heapq.heapify(self._modified_heap)
        self.scheduler_compactions += 1

    def _discard_stale_heap_entries_locked(self) -> None:
        while self._modified_heap:
            deadline, sequence, path = self._modified_heap[0]
            current = self._pending_modified.get(path)
            if current is not None and current[0] == deadline and current[1] == sequence:
                return
            heapq.heappop(self._modified_heap)
            self.scheduler_stale_pops += 1

    def _run(self) -> None:
        while True:
            event = None
            with self._cv:
                while event is None:
                    if self._immediate:
                        event = self._immediate.popleft()
                        break

                    self._discard_stale_heap_entries_locked()
                    now = monotonic()
                    due_deadline = None

                    if self._modified_heap:
                        deadline, sequence, path = self._modified_heap[0]
                        due_deadline = deadline
                        if self._stopping or deadline <= now:
                            heapq.heappop(self._modified_heap)
                            current = self._pending_modified.get(path)
                            if current is not None and current[0] == deadline and current[1] == sequence:
                                _, _, event = self._pending_modified.pop(path)
                                break
                            self.scheduler_stale_pops += 1
                            continue

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
                # Preserve the observer/worker lifetime. The wrapped BC Sentinel
                # handler owns its normal error/reporting policy; this counter is
                # diagnostic evidence if an unexpected exception escapes it.
                self.worker_errors += 1

    def _forward(self, event):
        result = self._inner.dispatch(event)
        self.forwarded += 1
        return result
