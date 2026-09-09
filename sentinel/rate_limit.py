from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import threading
import time
from typing import Hashable


@dataclass(slots=True, frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: float
    limit: int
    window_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": bool(self.allowed),
            "remaining": int(self.remaining),
            "retry_after_seconds": round(float(self.retry_after_seconds), 3),
            "limit": int(self.limit),
            "window_seconds": float(self.window_seconds),
        }


class SlidingWindowRateLimiter:
    """Small in-process limiter for privileged/IPC abuse resistance.

    The limiter is deliberately local to the Protection Service. It never relies
    on wall-clock time or network state, and each decision is keyed by the
    transport-authenticated Windows identity supplied by the named pipe layer.
    """

    def __init__(self, *, clock=None):
        self._clock = clock or time.monotonic
        self._events: dict[Hashable, deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()
        self._blocked = 0

    def check(self, key: Hashable, *, limit: int, window_seconds: float) -> RateLimitDecision:
        limit = max(1, int(limit))
        window = max(0.1, float(window_seconds))
        now = float(self._clock())
        cutoff = now - window
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                self._blocked += 1
                retry = max(0.0, window - (now - bucket[0])) if bucket else window
                return RateLimitDecision(False, 0, retry, limit, window)
            bucket.append(now)
            remaining = max(0, limit - len(bucket))
            return RateLimitDecision(True, remaining, 0.0, limit, window)

    def record_failure(self, key: Hashable, *, limit: int, window_seconds: float) -> RateLimitDecision:
        return self.check(("failure", key), limit=limit, window_seconds=window_seconds)

    def metrics(self) -> dict[str, int]:
        with self._lock:
            active = sum(1 for values in self._events.values() if values)
            return {"active_buckets": int(active), "blocked": int(self._blocked)}
