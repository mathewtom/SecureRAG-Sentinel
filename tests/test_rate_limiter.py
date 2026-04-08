"""Tests for per-user rate limiter."""

import time

import pytest

from src.rate_limiter import RateLimiter, RateLimitExceeded


class TestRateLimiter:

    def test_allows_requests_within_limit(self) -> None:
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            limiter.check("E001")

    def test_blocks_after_limit_exceeded(self) -> None:
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("E001")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("E001")
        assert exc_info.value.user_id == "E001"
        assert exc_info.value.retry_after > 0

    def test_separate_limits_per_user(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("E001")
        limiter.check("E001")

        with pytest.raises(RateLimitExceeded):
            limiter.check("E001")
        limiter.check("E002")

    def test_window_expiry_allows_new_requests(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=0.1)
        limiter.check("E001")
        limiter.check("E001")

        with pytest.raises(RateLimitExceeded):
            limiter.check("E001")

        time.sleep(0.15)
        limiter.check("E001")

    def test_retry_after_is_positive(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=30)
        limiter.check("E001")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("E001")
        assert 0 < exc_info.value.retry_after <= 30

    def test_error_message_contains_user_id(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        limiter.check("E003")

        with pytest.raises(RateLimitExceeded, match="E003"):
            limiter.check("E003")


class TestRateLimiterModeSelection:

    def test_production_defaults(self, monkeypatch) -> None:
        monkeypatch.delenv("SECURERAG_RATE_MODE", raising=False)
        import importlib
        import src.rate_limiter as rl_mod
        importlib.reload(rl_mod)
        assert rl_mod.DEFAULT_MAX_REQUESTS == 10
        assert rl_mod.DEFAULT_WINDOW_SECONDS == 60

    def test_test_mode_defaults(self, monkeypatch) -> None:
        monkeypatch.setenv("SECURERAG_RATE_MODE", "test")
        import importlib
        import src.rate_limiter as rl_mod
        importlib.reload(rl_mod)
        assert rl_mod.DEFAULT_MAX_REQUESTS == 100_000
        assert rl_mod.DEFAULT_WINDOW_SECONDS == 600

    def test_test_mode_case_insensitive(self, monkeypatch) -> None:
        monkeypatch.setenv("SECURERAG_RATE_MODE", "Test")
        import importlib
        import src.rate_limiter as rl_mod
        importlib.reload(rl_mod)
        assert rl_mod.DEFAULT_MAX_REQUESTS == 100_000
