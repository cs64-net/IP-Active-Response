"""Simple in-memory rate limiter for login attempts — no account lockout."""

import threading
import time
from typing import Dict, List


class RateLimiter:
    """Sliding-window rate limiter keyed by IP address.

    Parameters
    ----------
    max_attempts : int
        Maximum number of requests allowed within *window_seconds*.
    window_seconds : int
        Length of the sliding window in seconds.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_rate_limited(self, key: str) -> bool:
        """Return True if *key* has exceeded the rate limit."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._attempts.get(key, [])
            # Prune old entries
            timestamps = [t for t in timestamps if t > cutoff]
            self._attempts[key] = timestamps
            return len(timestamps) >= self.max_attempts

    def record_attempt(self, key: str) -> None:
        """Record a login attempt for *key*."""
        now = time.time()
        with self._lock:
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key].append(now)

    def remaining(self, key: str) -> int:
        """Return how many attempts remain for *key* in the current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = self._attempts.get(key, [])
            recent = [t for t in timestamps if t > cutoff]
            return max(0, self.max_attempts - len(recent))

    def retry_after(self, key: str) -> int:
        """Return seconds until the oldest attempt in the window expires."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = self._attempts.get(key, [])
            recent = sorted(t for t in timestamps if t > cutoff)
            if not recent:
                return 0
            return max(1, int((recent[0] + self.window_seconds) - now) + 1)
