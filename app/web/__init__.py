"""The analyst console.

formatting  display filters; none of them builds markup
charts      SVG geometry, computed here so the CSP never needs relaxing
views       server-rendered pages over the same pipeline as the API
actions     the forms: every change an analyst makes from the browser
csrf        signed double-submit tokens for those forms
"""

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from app.core.logging import get_logger
from app.web import actions, csrf
from app.web.views import STATIC_DIR, TEMPLATE_DIR, form_rejected, router, templates

__all__ = ["STATIC_DIR", "TEMPLATE_DIR", "install_console", "router", "templates"]

logger = get_logger(__name__)


def install_console(app: FastAPI) -> None:
    """Mount the console on ``app``: pages, forms, static files and CSRF handling."""
    app.state.csrf_secret = csrf.new_secret()
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(router)
    app.include_router(actions.router)

    @app.exception_handler(csrf.CsrfError)
    async def _csrf_rejected(request: Request, exc: csrf.CsrfError) -> Response:
        logger.warning("refused a console form on %s: %s", request.url.path, exc)
        return form_rejected(request)
