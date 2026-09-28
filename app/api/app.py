"""FastAPI application factory.

A factory function rather than a module-level instance lets tests and the CLI
create the app with different settings without importing side effects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from app import __version__
from app.ai.providers import ProviderConfigurationError, build_provider
from app.api.dependencies import AIState
from app.api.docs import install_docs
from app.api.errors import register_error_handlers
from app.api.middleware import install_middleware
from app.api.routes import ai, alerts, audit, events, incidents, operations, rules
from app.core.config import Settings, get_settings
from app.database.session import create_db_engine
from app.web import install_console


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application around one set of settings and one database.

    The app owns both: they live on ``app.state`` and every request dependency
    reads them from there, so what the factory is given is what the handlers
    use. The engine is disposed when the app shuts down.
    """
    cfg = settings or get_settings()
    engine = create_db_engine(cfg)
    ai_state = _build_ai_state(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()
        # Read from app.state, not the closure, so a provider swapped in
        # after construction (tests do this) is the one that gets closed.
        provider = app.state.ai.provider
        if provider is not None:
            provider.close()

    app = FastAPI(
        lifespan=lifespan,
        title="SentinelFlow",
        version=__version__,
        description=(
            "AI-Assisted Security Alert Triage — deterministic pipeline, "
            "advisory AI, human confirms."
        ),
        # The docs page is installed below, on a policy of its own; see app/api/docs.py.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if cfg.api_docs_enabled else None,
    )

    app.state.settings = cfg
    app.state.engine = engine
    app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    app.state.ai = ai_state

    install_middleware(app, cfg)
    register_error_handlers(app)

    app.include_router(operations.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")
    app.include_router(ai.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")

    # The analyst console: same process, same pipeline, same security headers.
    install_console(app)
    if cfg.api_docs_enabled and app.openapi_url:
        install_docs(app, app.openapi_url)

    return app


def _build_ai_state(settings: Settings) -> AIState:
    """The provider, or why there is none. Never raises: AI is optional."""
    if not settings.ai_active:
        return AIState(provider=None, problem=DISABLED_MESSAGE)
    try:
        return AIState(provider=build_provider(settings))
    except ProviderConfigurationError as exc:
        return AIState(provider=None, problem=str(exc))


DISABLED_MESSAGE = (
    "AI is disabled. SentinelFlow is complete without it. To enable a local model, set "
    "SENTINELFLOW_AI_ENABLED=true and SENTINELFLOW_AI_PROVIDER=ollama."
)
