"""Simple in-memory rate limiter for the AgentGuard API.

Limits: 100 requests per minute per JWT token (keyed by role).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Annotated

from fastapi import Depends, HTTPException, status

from api.auth import TokenPayload, get_current_user

RATE_LIMIT = 100  # requests per window
RATE_WINDOW = 60  # seconds

_request_log: dict[str, deque[float]] = defaultdict(deque)


def check_rate_limit(
    user: Annotated[TokenPayload, Depends(get_current_user)],
) -> TokenPayload:
    """FastAPI dependency: enforce rate limit per role/user."""
    key = user.sub
    now = time.time()
    window = _request_log[key]

    # Prune old entries
    while window and window[0] < now - RATE_WINDOW:
        window.popleft()

    if len(window) >= RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
        )

    window.append(now)
    return user
