"""Token bucket rate limiter for API calls."""

import asyncio
import time
from dataclasses import dataclass


class RateLimitExhaustedError(Exception):
    """Raised when daily budget is exhausted."""

    pass


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiter."""

    requests_per_minute: float
    daily_budget: int = 0  # 0 = unlimited
    name: str = "default"


class TokenBucketRateLimiter:
    """Async token bucket rate limiter."""

    def __init__(self, config: RateLimiterConfig):
        """Initialize the rate limiter."""
        self.config = config
        self.tokens = config.requests_per_minute
        self.max_tokens = config.requests_per_minute
        self.last_refill = time.monotonic()
        self.daily_count = 0
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """
        Acquire a token for making a request.

        Raises:
            RateLimitExhaustedError: If daily budget is exhausted
        """
        async with self.lock:
            # Refill tokens based on elapsed time
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.max_tokens, self.tokens + elapsed * (self.max_tokens / 60.0)
            )
            self.last_refill = now

            # Wait if we don't have enough tokens
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / (self.max_tokens / 60.0)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1

            # Check daily budget
            self.daily_count += 1
            if self.config.daily_budget and self.daily_count >= self.config.daily_budget:
                raise RateLimitExhaustedError(
                    f"{self.config.name}: daily budget of {self.config.daily_budget} exhausted"
                )


# Default rate limit configurations for each source
RATE_LIMITS = {
    "virustotal": RateLimiterConfig(
        requests_per_minute=4, daily_budget=500, name="virustotal"
    ),
    "abuseipdb": RateLimiterConfig(
        requests_per_minute=60, daily_budget=1000, name="abuseipdb"
    ),
    "otx": RateLimiterConfig(requests_per_minute=150, daily_budget=0, name="otx"),
}
