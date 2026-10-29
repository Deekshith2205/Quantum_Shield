"""Scanner Rate Limiting and Concurrency Management.

Provides:
- In-memory per-client IP sliding window rate limiting (default 10 scans / minute).
- Asynchronous scan concurrency bounding (default 5 concurrent scans).
"""

import asyncio
import time
import math
from typing import Dict, List, Tuple


class InMemoryRateLimiter:
    """
    Sliding-window per-client rate limiter.
    Keeps timestamps of recent requests per client IP.
    """

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = {}

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """
        Checks whether the client IP is allowed to proceed with a scan.

        Returns:
            (True, 0) if allowed.
            (False, retry_after_seconds) if rate limit exceeded.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Get existing timestamps and purge expired
        timestamps = self._history.get(client_ip, [])
        valid_timestamps = [t for t in timestamps if t > cutoff]

        if len(valid_timestamps) >= self.max_requests:
            # Rate limit exceeded. Compute retry-after based on oldest timestamp in window
            oldest = valid_timestamps[0]
            retry_after = max(1, math.ceil(self.window_seconds - (now - oldest)))
            self._history[client_ip] = valid_timestamps
            return False, retry_after

        # Record this request
        valid_timestamps.append(now)
        self._history[client_ip] = valid_timestamps
        return True, 0

    def reset(self):
        """Clears all recorded rate limit history (useful for test suites)."""
        self._history.clear()


# Default instances
DEFAULT_RATE_LIMITER = InMemoryRateLimiter(max_requests=10, window_seconds=60.0)
MAX_CONCURRENT_SCANS = 5
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

