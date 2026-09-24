"""AI status. Analysis itself is requested per alert, under /alerts."""

from __future__ import annotations

from fastapi import APIRouter

from app.ai.prompts import PROMPT_VERSION
from app.api import schemas
from app.api.dependencies import AIDep, SettingsDep

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/status", response_model=schemas.AIStatusOut)
def ai_status(ai: AIDep, settings: SettingsDep) -> schemas.AIStatusOut:
    """Whether a model can be asked, and if not, what to change.

    Makes no network call when AI is disabled. When it is enabled, asks the
    local provider for its version and installed models, with a short timeout.
    """
    if ai.provider is None:
        return schemas.AIStatusOut(
            enabled=False,
            provider=settings.ai_provider.value,
            prompt_version=PROMPT_VERSION,
            problem=ai.problem,
        )
    status = ai.provider.status()
    return schemas.AIStatusOut(
        enabled=True,
        provider=status.provider,
        model=status.model,
        endpoint=status.endpoint,
        local=status.local,
        reachable=status.reachable,
        model_installed=status.model_installed,
        version=status.version,
        installed_models=list(status.installed_models),
        prompt_version=PROMPT_VERSION,
        problem=status.problem,
    )
