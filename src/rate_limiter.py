"""Per-user sliding-window rate limiter."""

import os
import time
from collections import defaultdict
from threading import Lock

# Production defaults
_PROD_MAX_REQUESTS = 10
_PROD_WINDOW_SECONDS = 60

# Test mode for security scanning (Garak, PromptFoo)
_TEST_MAX_REQUESTS = 100_000
_TEST_WINDOW_SECONDS = 600


def _is_test_mode() -> bool:
    return os.environ.get("SECURERAG_RATE_MODE", "").lower() == "test"


DEFAULT_MAX_REQUESTS = _TEST_MAX_REQUESTS if _is_test_mode() else _PROD_MAX_REQUESTS
DEFAULT_WINDOW_SECONDS = _TEST_WINDOW_SECONDS if _is_test_mode() else _PROD_WINDOW_SECONDS


class RateLimitExceeded(Exception):
    """Raised when a user exceeds their query rate limit."""

    def __init__(self, user_id: str, retry_after: float) -> None:
        self.user_id = user_id
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for user {user_id}. "
            f"Retry after {retry_after:.1f}s."
        )


class RateLimiter:
    """Sliding-window rate limiter keyed by user ID.

    Tracks timestamps of recent requests per user and rejects new
    requests once the window is full. Thread-safe.
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, user_id: str) -> None:
        """Check if user_id is within rate limits. Raises RateLimitExceeded if not."""
        now = time.monotonic()
        cutoff = now - self._window_seconds

        with self._lock:
            timestamps = self._requests[user_id]
            self._requests[user_id] = [t for t in timestamps if t > cutoff]
            timestamps = self._requests[user_id]

            if len(timestamps) >= self._max_requests:
                retry_after = timestamps[0] - cutoff
                raise RateLimitExceeded(user_id, retry_after)

            timestamps.append(now)
