"""FastAPI application factory.

A factory function rather than a module-level instance lets tests and the CLI
create the app with different settings without importing side effects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from app import __version__
from app.api.errors import register_error_handlers
from app.api.middleware import install_middleware
from app.api.routes import alerts, events, incidents, operations, rules
from app.core.config import Settings, get_settings
from app.database.session import create_db_engine
from app.web import STATIC_DIR
from app.web import router as console_router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application around one set of settings and one database.

    The app owns both: they live on ``app.state`` and every request dependency
    reads them from there, so what the factory is given is what the handlers
    use. The engine is disposed when the app shuts down.
    """
    cfg = settings or get_settings()
    engine = create_db_engine(cfg)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
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

    app.state.settings = cfg
    app.state.engine = engine
    app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    install_middleware(app, cfg)
    register_error_handlers(app)

    app.include_router(operations.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")

    # The analyst console: same process, same pipeline, same security headers.
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(console_router)

    return app
