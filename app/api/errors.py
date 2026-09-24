"""Error handling that does not leak internals.

An exception handler is a disclosure surface. The default behaviour of most
frameworks — return the traceback, or return ``str(exc)`` — hands an attacker
file paths, library versions and sometimes fragments of data.

Every unexpected failure here becomes the same generic 500 with a request ID.
The detail goes to the log, where an operator can find it by that ID, and
nowhere else. Expected failures (a bad path, a missing record, a file that is
too large) return a specific, useful message, because those are the caller's
own mistakes and telling them is the point.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.core.paths import FileTooLargeError, UnsafePathError
from app.ingestion.adapters import UnknownAdapterError
from app.services.workflow import RecordNotFoundError, StaleDecisionError, WorkflowError

logger = get_logger(__name__)


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _json(request: Request, code: int, error: str, detail: str | None = None) -> JSONResponse:
    body = {"error": error, "detail": detail, "request_id": _request_id(request)}
    return JSONResponse(status_code=code, content=body)


def register_error_handlers(app: FastAPI) -> None:
    """Attach handlers that return structured, non-revealing errors."""

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in exc.errors()[:5]
        ]
        return _json(
            request,
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "; ".join(problems) or "the request body could not be validated",
        )

    @app.exception_handler(UnknownAdapterError)
    async def _unknown_adapter(request: Request, exc: UnknownAdapterError) -> JSONResponse:
        return _json(request, status.HTTP_400_BAD_REQUEST, "unknown_source", str(exc))

    @app.exception_handler(UnsafePathError)
    async def _unsafe_path(request: Request, exc: UnsafePathError) -> JSONResponse:
        # The message names the permitted roots, which is fine: the caller
        # already supplied a path, and refusing without saying why is unhelpful.
        logger.warning("refused a path outside the permitted directories: %s", exc)
        return _json(request, status.HTTP_400_BAD_REQUEST, "unsafe_path", str(exc))

    @app.exception_handler(FileTooLargeError)
    async def _too_large(request: Request, exc: FileTooLargeError) -> JSONResponse:
        return _json(request, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "too_large", str(exc))

    # Workflow refusals carry messages written for the analyst, so they are
    # returned as they are. Order matters: StaleDecisionError is a WorkflowError.
    @app.exception_handler(StaleDecisionError)
    async def _stale(request: Request, exc: StaleDecisionError) -> JSONResponse:
        return _json(request, status.HTTP_409_CONFLICT, "stale_decision", str(exc))

    @app.exception_handler(WorkflowError)
    async def _refused(request: Request, exc: WorkflowError) -> JSONResponse:
        return _json(request, status.HTTP_422_UNPROCESSABLE_CONTENT, "decision_refused", str(exc))

    @app.exception_handler(RecordNotFoundError)
    async def _missing(request: Request, exc: RecordNotFoundError) -> JSONResponse:
        return _json(request, status.HTTP_404_NOT_FOUND, "not_found", str(exc))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _json(request, exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Logged in full, returned as nothing. The request ID is the bridge.
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return _json(
            request,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "The request could not be completed. The failure has been logged with this request id.",
        )
