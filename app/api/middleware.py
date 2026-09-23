"""Request-level controls.

SentinelFlow's API accepts attacker-controlled JSON by design, so three things
are enforced before a request reaches a route:

* **A request ID**, attached to the response and to every log line for that
  request. It is what lets an operator find the detail behind a generic 500.
* **A body size limit**, checked against ``Content-Length`` *and* enforced while
  reading, because a chunked request does not declare its length and would
  otherwise bypass the check entirely.
* **A coarse rate limit**, per client address. It is a guard against a runaway
  importer, not a substitute for a gateway: it is per-process and resets when
  the process does.

Security headers are added on the way out. They matter more once the dashboard
exists, but setting them at the edge means there is no page that can forget.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)

RequestHandler = Callable[[Request], Awaitable[Response]]

#: Applied to every response. A page cannot opt out of these by forgetting them.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # No remote origins at all: every asset the dashboard uses is served from
    # this process, so a script injected through event data has nowhere to send
    # anything and nothing external to pull in.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request ID, log the outcome, and set security headers."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id
        started = time.perf_counter()

        response = await call_next(request)

        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)

        logger.info(
            "%s %s -> %s in %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            extra={"request_id": request_id},
        )
        return response


class BodySizeLimitMiddleware:
    """Reject request bodies larger than the configured limit.

    Written as raw ASGI rather than ``BaseHTTPMiddleware`` so the body can be
    counted as it streams. Checking ``Content-Length`` alone is not enough: a
    chunked request does not send one, and trusting a header supplied by the
    caller is exactly the kind of check that looks like a control and is not.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await self._refuse(send, declared)
            return

        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge(received)
            return message

        try:
            await self.app(scope, counting_receive, send)
        except _BodyTooLarge as exc:
            logger.warning("rejected a request body of at least %s bytes", exc.size)
            await self._refuse(send, exc.size)

    async def _refuse(self, send: Send, size: int) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "error": "too_large",
                "detail": (
                    f"request body is at least {size:,} bytes, which exceeds the "
                    f"{self.max_bytes:,} byte limit"
                ),
                "request_id": None,
            },
        )
        await response(_REFUSAL_SCOPE, _no_receive, send)


class _BodyTooLarge(Exception):
    def __init__(self, size: int) -> None:
        super().__init__(size)
        self.size = size


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


#: The response is written directly to ``send``, so the scope only needs a type.
_REFUSAL_SCOPE: Scope = {"type": "http"}


async def _no_receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A sliding-window limit per client address.

    Coarse on purpose. Its job is to stop a misconfigured importer from filling
    the database in a loop, not to withstand a determined attacker - which a
    per-process counter never could.
    """

    def __init__(self, app: ASGIApp, per_minute: int) -> None:
        super().__init__(app)
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if self.per_minute <= 0:
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = self._hits[client]
        while window and now - window[0] > 60:
            window.popleft()

        if len(window) >= self.per_minute:
            retry_after = int(60 - (now - window[0])) + 1
            logger.warning("rate limit reached for %s", client)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limited",
                    "detail": f"more than {self.per_minute} requests in a minute",
                    "request_id": getattr(request.state, "request_id", None),
                },
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)
        return await call_next(request)


def install_middleware(app: FastAPI, settings: Settings) -> None:
    """Attach middleware in the order requests should meet it."""
    if settings.api_rate_limit_per_minute > 0:
        app.add_middleware(RateLimitMiddleware, per_minute=settings.api_rate_limit_per_minute)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
