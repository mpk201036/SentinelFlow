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
* **No cross-site writes.** A web page on another origin - including another
  port on localhost - must not be able to make the analyst's browser change
  anything here. See :class:`CrossSiteWriteGuard`.

Security headers are added on the way out. They matter more once the dashboard
exists, but setting them at the edge means there is no page that can forget.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

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
    # same-origin rather than no-referrer: nothing is sent to other sites, but
    # the console's own form posts keep a real Origin header. Under
    # no-referrer, browsers send "Origin: null" even for same-origin posts,
    # which is indistinguishable from a sandboxed attacker page.
    "Referrer-Policy": "same-origin",
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


#: Methods that change state. GET and HEAD never do here.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def cross_site_problem(request: Request) -> str | None:
    """Why a state-changing request looks cross-site, or None if it does not.

    Browsers label every request with ``Sec-Fetch-Site`` and send ``Origin`` on
    every POST, so a request from another site says so. Clients that are not
    browsers (curl, scripts, the test client) send neither and are not
    affected: the threat is a page making the analyst's browser act, not a
    local tool the analyst runs on purpose.

    ``same-site`` is refused too. For a console on ``localhost:8000``, any
    other port on ``localhost`` is "same site", and a development server on
    port 3000 is exactly the kind of page that should not be able to close
    alerts.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        # Set by the browser, never by the page, so when present it decides.
        # Origin can be "null" on a genuine same-origin post (see the
        # Referrer-Policy note above), so it is only the fallback.
        return None if site.lower() in ("same-origin", "none") else f"Sec-Fetch-Site is {site}"
    # Browsers too old for fetch metadata still send Origin on every POST.
    origin = request.headers.get("origin")
    if origin is not None:
        if origin == "null":
            return "Origin is null"
        host = request.headers.get("host", "")
        if urlsplit(origin).netloc.lower() != host.lower():
            return "Origin does not match Host"
    return None


class CrossSiteWriteGuard(BaseHTTPMiddleware):
    """Refuse state-changing requests that a browser marks as cross-site.

    This covers every write, including endpoints with no body at all (triage,
    correlate, AI analysis), which a plain HTML form on any site could
    otherwise trigger. The console's forms carry a CSRF token as well; this
    guard is what protects the parts of the API a token cannot reach.
    """

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if request.method in UNSAFE_METHODS:
            problem = cross_site_problem(request)
            if problem is not None:
                logger.warning(
                    "refused a cross-site %s %s: %s", request.method, request.url.path, problem
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "cross_site_request",
                        "detail": (
                            "Changes must come from the SentinelFlow console itself or from a "
                            "client that is not a web page."
                        ),
                        "request_id": getattr(request.state, "request_id", None),
                    },
                )
        return await call_next(request)


def install_middleware(app: FastAPI, settings: Settings) -> None:
    """Attach middleware in the order requests should meet it.

    Starlette runs the last one added first, so requests meet: body size limit,
    request context and security headers, cross-site guard, rate limit.
    """
    if settings.api_rate_limit_per_minute > 0:
        app.add_middleware(RateLimitMiddleware, per_minute=settings.api_rate_limit_per_minute)
    app.add_middleware(CrossSiteWriteGuard)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
