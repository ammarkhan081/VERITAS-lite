"""Thread-safe campaign step and token budget tracking."""

from __future__ import annotations

import threading


class BudgetTracker:
    """Tracks remaining campaign steps and tokens under a lock."""

    def __init__(self, max_steps: int, max_tokens: int) -> None:
        """Initialize counters and limits."""
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self._steps = 0
        self._tokens = 0
        self._lock = threading.Lock()

    def charge_step(self) -> bool:
        """Increment the step counter unless the step budget is already exhausted."""
        with self._lock:
            if self._steps >= self.max_steps:
                return False
            self._steps += 1
            return True

    def charge_tokens(self, n: int) -> bool:
        """Add ``n`` tokens unless the charge would exceed the token budget."""
        with self._lock:
            if self._tokens >= self.max_tokens or self._tokens + n > self.max_tokens:
                return False
            self._tokens += n
            return True

    def is_exhausted(self) -> bool:
        """Return True if either the step or token limit has been reached."""
        with self._lock:
            return self._steps >= self.max_steps or self._tokens >= self.max_tokens

    def remaining_steps(self) -> int:
        """Return unused steps, floored at zero."""
        with self._lock:
            return max(0, self.max_steps - self._steps)

    def remaining_tokens(self) -> int:
        """Return unused tokens, floored at zero."""
        with self._lock:
            return max(0, self.max_tokens - self._tokens)

    def summary(self) -> dict:
        """Return a snapshot of usage, remaining budget, and exhaustion state."""
        with self._lock:
            return {
                "steps_used": self._steps,
                "tokens_used": self._tokens,
                "steps_remaining": max(0, self.max_steps - self._steps),
                "tokens_remaining": max(0, self.max_tokens - self._tokens),
                "exhausted": self._steps >= self.max_steps or self._tokens >= self.max_tokens,
            }
