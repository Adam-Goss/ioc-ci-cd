"""Tests for rate limiter."""

import asyncio
import time

import pytest

from src.rate_limiter import RateLimitExhaustedError, RateLimiterConfig, TokenBucketRateLimiter


class TestRateLimiterConfig:
    """Tests for RateLimiterConfig dataclass."""

    def test_config_creation(self):
        """Test config object creation."""
        config = RateLimiterConfig(
            requests_per_minute=60,
            daily_budget=1000,
            name="test_source"
        )

        assert config.requests_per_minute == 60
        assert config.daily_budget == 1000
        assert config.name == "test_source"

    def test_config_unlimited_budget(self):
        """Test config with unlimited daily budget."""
        config = RateLimiterConfig(
            requests_per_minute=100,
            daily_budget=0,  # 0 = unlimited
            name="unlimited"
        )

        assert config.daily_budget == 0


class TestTokenBucketRateLimiter:
    """Tests for TokenBucketRateLimiter."""

    @pytest.mark.asyncio
    async def test_single_acquire(self):
        """Test acquiring a single token."""
        config = RateLimiterConfig(requests_per_minute=60, name="test")
        limiter = TokenBucketRateLimiter(config)

        # Should succeed immediately
        await limiter.acquire()
        assert limiter.daily_count == 1

    @pytest.mark.asyncio
    async def test_multiple_acquires(self):
        """Test acquiring multiple tokens."""
        config = RateLimiterConfig(requests_per_minute=60, name="test")
        limiter = TokenBucketRateLimiter(config)

        # Acquire 5 tokens
        for _ in range(5):
            await limiter.acquire()

        assert limiter.daily_count == 5

    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Test that tokens are refilled over time."""
        config = RateLimiterConfig(requests_per_minute=60, name="test")
        limiter = TokenBucketRateLimiter(config)

        # Exhaust initial tokens
        for _ in range(int(config.requests_per_minute)):
            await limiter.acquire()

        # Tokens should be very low now
        assert limiter.tokens < 1

        # Wait for refill (1 second = 1 token at 60 req/min)
        await asyncio.sleep(1.1)

        # Should be able to acquire again without blocking
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should complete quickly (not block)
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_rate_limiting_blocks(self):
        """Test that acquire blocks when tokens exhausted."""
        # Very low rate: 6 req/min = 1 req every 10 seconds
        config = RateLimiterConfig(requests_per_minute=6, name="test")
        limiter = TokenBucketRateLimiter(config)

        # Exhaust initial tokens
        for _ in range(6):
            await limiter.acquire()

        # Next acquire should block
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should have blocked for approximately 10 seconds
        # (with some tolerance for timing precision)
        assert elapsed > 8  # At least 8 seconds

    @pytest.mark.asyncio
    async def test_daily_budget_exhausted(self):
        """Test that daily budget is enforced."""
        config = RateLimiterConfig(
            requests_per_minute=100,
            daily_budget=5,
            name="test"
        )
        limiter = TokenBucketRateLimiter(config)

        # Acquire 4 tokens (one below budget limit)
        for _ in range(4):
            await limiter.acquire()

        # 5th acquire should raise exception (budget is 5, and check is >=)
        with pytest.raises(RateLimitExhaustedError) as exc_info:
            await limiter.acquire()

        assert "daily budget of 5 exhausted" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_unlimited_daily_budget(self):
        """Test that unlimited budget (0) works."""
        config = RateLimiterConfig(
            requests_per_minute=100,
            daily_budget=0,  # Unlimited
            name="test"
        )
        limiter = TokenBucketRateLimiter(config)

        # Should be able to acquire many tokens
        for _ in range(200):
            await limiter.acquire()

        # No exception should be raised
        assert limiter.daily_count == 200

    @pytest.mark.asyncio
    async def test_concurrent_acquires(self):
        """Test concurrent token acquisition from multiple tasks."""
        config = RateLimiterConfig(requests_per_minute=60, name="test")
        limiter = TokenBucketRateLimiter(config)

        async def acquire_token():
            await limiter.acquire()

        # Launch 10 concurrent tasks
        await asyncio.gather(*[acquire_token() for _ in range(10)])

        assert limiter.daily_count == 10

    @pytest.mark.asyncio
    async def test_max_tokens_cap(self):
        """Test that tokens don't exceed max_tokens."""
        config = RateLimiterConfig(requests_per_minute=60, name="test")
        limiter = TokenBucketRateLimiter(config)

        # Wait for potential refill
        await asyncio.sleep(2)

        # Tokens should be capped at max_tokens
        assert limiter.tokens <= limiter.max_tokens
