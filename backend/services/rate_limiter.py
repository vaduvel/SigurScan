"""Sliding-window rate limiting for the public API.

Primary backend: Upstash Redis (REST), so the limit is shared across all
serverless instances. Fallback: per-instance in-memory buckets ("best effort"),
used when Upstash is not configured or unreachable. The active backend is
reported in /health as `rate_limit_backend` so the fallback is never silent.

Limits are enforced per identity and per path:
- identity "key:<sha256-prefix>" when the request carries an API key
  (the raw key never reaches Redis), plus
- identity "ip:<client-ip>" always.
"""

import hashlib
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

import requests

UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
UPSTASH_TIMEOUT_SECONDS = float(os.getenv("UPSTASH_TIMEOUT_SECONDS", "1.5"))

RATE_LIMIT_WINDOW_SECONDS = 60

_memory_buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_memory_lock = threading.Lock()


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    backend: str  # "upstash" | "memory_best_effort"
    identity: str = ""


def is_upstash_configured() -> bool:
    return bool(UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN)


def backend_mode() -> str:
    return "upstash" if is_upstash_configured() else "memory_best_effort"


def reset_memory_buckets() -> None:
    """Test helper: clears the in-memory fallback state."""
    with _memory_lock:
        _memory_buckets.clear()


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]


def _identities(api_key: Optional[str], client_ip: str) -> List[str]:
    identities = []
    if api_key:
        identities.append(f"key:{_hash_api_key(api_key)}")
    identities.append(f"ip:{client_ip or 'anonymous'}")
    return identities


def _run_upstash_pipeline(commands: List[List[str]]) -> List[Dict[str, object]]:
    response = requests.post(
        f"{UPSTASH_REDIS_REST_URL}/pipeline",
        json=commands,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
        timeout=UPSTASH_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def _check_upstash(identity: str, path: str, limit_per_minute: int) -> bool:
    now_ms = int(time.time() * 1000)
    window_ms = RATE_LIMIT_WINDOW_SECONDS * 1000
    redis_key = f"sigurscan:rl:{identity}:{path}"
    member = f"{now_ms}-{os.urandom(4).hex()}"
    results = _run_upstash_pipeline(
        [
            ["ZREMRANGEBYSCORE", redis_key, "0", str(now_ms - window_ms)],
            ["ZADD", redis_key, str(now_ms), member],
            ["ZCARD", redis_key],
            ["PEXPIRE", redis_key, str(window_ms)],
        ]
    )
    count = int(results[2].get("result", 0))
    return count <= limit_per_minute


def _check_memory(identity: str, path: str, limit_per_minute: int) -> bool:
    now = time.time()
    with _memory_lock:
        bucket = _memory_buckets[(identity, path)]
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= limit_per_minute:
            return False
        bucket.append(now)
    return True


def check_sync(
    api_key: Optional[str],
    client_ip: str,
    path: str,
    limit_per_minute: int,
) -> RateLimitDecision:
    """Checks every applicable identity; the most restrictive answer wins.

    Upstash errors fail open to the in-memory fallback so a Redis outage can
    slow abuse response but never block legitimate scans.
    """
    used_memory_fallback = False
    for identity in _identities(api_key, client_ip):
        if is_upstash_configured():
            try:
                if not _check_upstash(identity, path, limit_per_minute):
                    return RateLimitDecision(False, RATE_LIMIT_WINDOW_SECONDS, "upstash", identity)
                continue
            except Exception:
                used_memory_fallback = True
        else:
            used_memory_fallback = True
        if not _check_memory(identity, path, limit_per_minute):
            return RateLimitDecision(False, RATE_LIMIT_WINDOW_SECONDS, "memory_best_effort", identity)
    backend = "memory_best_effort" if used_memory_fallback else "upstash"
    return RateLimitDecision(True, 0, backend)
