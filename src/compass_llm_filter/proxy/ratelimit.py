"""In-memory rate limiter (sliding window) для защиты эндпоинтов от DoS."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    """Ограничитель запросов по ключу (IP или токену) с плавающим окном (sliding window)."""

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._records: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            queue = self._records[key]
            # Удаляем запросы старше окна
            cutoff = now - self.window_seconds
            while queue and queue[0] < cutoff:
                queue.popleft()

            if len(queue) < self.max_requests:
                queue.append(now)
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._records.clear()
