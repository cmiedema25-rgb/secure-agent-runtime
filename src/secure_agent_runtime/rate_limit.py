from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class FixedWindowRateLimiter:
    """Thread-safe sliding-window limiter suitable for a single-process demo runtime."""

    def __init__(self, limit: int = 30, window_seconds: float = 60.0) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("invalid rate limit configuration")
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True
