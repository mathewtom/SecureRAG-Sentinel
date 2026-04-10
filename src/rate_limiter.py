"""Per-user sliding-window rate limiter."""

import os
import time
from collections import defaultdict
from threading import Lock

# Production defaults
_PROD_MAX_REQUESTS = 10
_PROD_WINDOW_SECONDS = 60


def _is_test_mode() -> bool:
    return os.environ.get("SECURERAG_RATE_MODE", "").lower() == "test"


# In test mode (SECURERAG_RATE_MODE=test), default construction disables
# the limiter entirely — `check()` becomes a no-op. This is what dev and
# security-scan runs (Garak, promptfoo iterative red-team) want: hundreds
# of requests per minute with zero 429s masking real defense behavior.
# Explicit construction `RateLimiter(max_requests=N, ...)` is unaffected,
# so unit tests of the mechanism still pass their own limits.
DEFAULT_MAX_REQUESTS: int | None = None if _is_test_mode() else _PROD_MAX_REQUESTS
DEFAULT_WINDOW_SECONDS: float = _PROD_WINDOW_SECONDS


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
        max_requests: int | None = DEFAULT_MAX_REQUESTS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, user_id: str) -> None:
        """Check if user_id is within rate limits. Raises RateLimitExceeded if not.

        If max_requests is None (test mode default), the limiter is disabled
        and all requests pass through without bookkeeping.
        """
        if self._max_requests is None:
            return

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
