from __future__ import annotations

from time import monotonic


class CoalescingEventHandlerProxy:
    """Lightweight pre-filter for watchdog event storms.

    The native Windows observer still receives every filesystem notification.
    We only avoid forwarding low-value duplicate work into BC Sentinel's heavier
    realtime pipeline:

    - directory ``modified`` notifications are redundant with the concrete
      child file events that watchdog also emits;
    - repeated ``modified`` notifications for the same file inside a very short
      window are coalesced;
    - create, move, delete and other event families are always forwarded.

    The debounce window is intentionally far shorter than BC Sentinel's existing
    higher-level observer debounce, so this layer reduces dispatch overhead
    without becoming a new security decision boundary.
    """

    DEFAULT_MODIFIED_WINDOW_SECONDS = 0.35
    DEFAULT_MAX_TRACKED_PATHS = 4096
    _PRUNE_AFTER_SECONDS = 2.0

    def __init__(
        self,
        inner,
        *,
        modified_window_seconds: float = DEFAULT_MODIFIED_WINDOW_SECONDS,
        max_tracked_paths: int = DEFAULT_MAX_TRACKED_PATHS,
    ) -> None:
        self._inner = inner
        self._modified_window_seconds = max(0.0, float(modified_window_seconds))
        self._max_tracked_paths = max(128, int(max_tracked_paths))
        self._modified_seen: dict[str, float] = {}
        self.forwarded = 0
        self.coalesced = 0
        self.directory_modified_dropped = 0

    def dispatch(self, event):
        event_type = str(getattr(event, "event_type", "") or "").lower()
        is_directory = bool(getattr(event, "is_directory", False))

        # Windows generates parent-directory metadata notifications for ordinary
        # file activity. The concrete child file event remains available and is
        # the security-relevant object BC Sentinel needs to scan/correlate.
        if is_directory and event_type == "modified":
            self.directory_modified_dropped += 1
            return None

        if not is_directory and event_type == "modified":
            path = str(getattr(event, "src_path", "") or "")
            if path:
                now = monotonic()
                previous = self._modified_seen.get(path)
                if previous is not None and (now - previous) < self._modified_window_seconds:
                    self.coalesced += 1
                    return None
                self._modified_seen[path] = now
                self._prune(now)

        self.forwarded += 1
        return self._inner.dispatch(event)

    def _prune(self, now: float) -> None:
        if len(self._modified_seen) <= self._max_tracked_paths:
            return
        cutoff = now - self._PRUNE_AFTER_SECONDS
        self._modified_seen = {
            path: seen_at
            for path, seen_at in self._modified_seen.items()
            if seen_at >= cutoff
        }
        if len(self._modified_seen) > self._max_tracked_paths:
            # Keep the newest entries only. Sorting is rare and bounded to event
            # storms; ordinary operation never reaches this path.
            newest = sorted(self._modified_seen.items(), key=lambda item: item[1], reverse=True)
            self._modified_seen = dict(newest[: self._max_tracked_paths])
