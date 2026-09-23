"""FastAPI application factory.

A factory function rather than a module-level instance lets tests and the CLI
create the app with different settings without importing side effects.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app import __version__
from app.api.errors import register_error_handlers
from app.api.middleware import install_middleware
from app.api.routes import alerts, events, incidents, operations, rules
from app.core.config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    app = FastAPI(
        title="SentinelFlow",
        version=__version__,
        description=(
            "AI-Assisted Security Alert Triage — deterministic pipeline, "
            "advisory AI, human confirms."
        ),
        docs_url="/docs" if cfg.api_docs_enabled else None,
        redoc_url="/redoc" if cfg.api_docs_enabled else None,
        openapi_url="/openapi.json" if cfg.api_docs_enabled else None,
    )

    install_middleware(app, cfg)
    register_error_handlers(app)

    app.include_router(operations.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")

    return app
