"""Model providers. Today, one: a local Ollama server.

A provider does one thing: send a :class:`~app.ai.prompts.Prompt` and return
the model's raw text. It knows nothing about alerts, storage or severity, and
the service that calls it treats what comes back as untrusted input.

The Ollama client is configured for a machine that holds security evidence:

* **No redirects.** A redirect could forward the evidence to another host
  after the URL check has passed.
* **No proxy settings from the environment** (``trust_env=False``). An
  ``HTTP_PROXY`` variable set for some other tool must not quietly route alert
  evidence through a proxy.
* **Bounded response.** The body is read up to a fixed size and abandoned
  beyond it.
* **Loopback only, unless told otherwise.** :func:`build_provider` refuses a
  remote URL unless ``ai_allow_remote_provider`` is set. See
  :attr:`app.core.config.Settings.ai_endpoint_problem`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

import httpx

from app import __version__
from app.ai.output import OUTPUT_SCHEMA
from app.ai.prompts import Prompt
from app.core.config import AIProvider, Settings, is_loopback_host

#: Largest reply body accepted from the provider.
MAX_RESPONSE_BYTES = 1_000_000
#: Context window requested. Evidence is capped well below this.
CONTEXT_TOKENS = 8_192
#: Ceiling on generated tokens. A reply that needs more is looping.
MAX_OUTPUT_TOKENS = 2_048
STATUS_TIMEOUT_SECONDS = 3.0


class ProviderError(Exception):
    """The provider did not produce a usable reply. The message is analyst-facing."""


class ProviderUnavailableError(ProviderError):
    """The provider could not be reached, or the model is not installed."""


class ProviderConfigurationError(ProviderError):
    """The configuration forbids contacting the provider."""


@dataclass(frozen=True)
class ProviderReply:
    content: str
    model: str
    duration_ms: int | None


@dataclass(frozen=True)
class ProviderStatus:
    """What an operator needs to know to get AI working, or to know it is off."""

    provider: str
    model: str
    endpoint: str
    local: bool
    reachable: bool
    model_installed: bool
    version: str | None = None
    installed_models: tuple[str, ...] = field(default_factory=tuple)
    problem: str | None = None

    @property
    def ready(self) -> bool:
        return self.reachable and self.model_installed and self.problem is None


@runtime_checkable
class ModelProvider(Protocol):
    """Anything that can answer a prompt."""

    name: str
    model: str

    def complete(self, prompt: Prompt) -> ProviderReply: ...

    def status(self) -> ProviderStatus: ...

    def close(self) -> None: ...


class OllamaProvider:
    """Talks to Ollama's ``/api/chat`` endpoint with a JSON-schema constrained reply."""

    name = "ollama"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_seconds: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds)),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": f"SentinelFlow/{__version__}"},
        )

    # ------------------------------------------------------------------
    def request_body(self, prompt: Prompt) -> dict[str, Any]:
        """The exact JSON sent to Ollama. Separate so tests can inspect it."""
        return {
            "model": self.model,
            "stream": False,
            # Reasoning models otherwise spend the time budget thinking aloud.
            "think": False,
            "format": OUTPUT_SCHEMA,
            "options": {
                "temperature": 0,
                "seed": 0,
                "num_ctx": CONTEXT_TOKENS,
                "num_predict": MAX_OUTPUT_TOKENS,
            },
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }

    def complete(self, prompt: Prompt) -> ProviderReply:
        started = time.monotonic()
        payload = self._post("/api/chat", self.request_body(prompt))

        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("the model returned an empty reply")

        total = payload.get("total_duration")
        duration_ms = (
            int(total) // 1_000_000
            if isinstance(total, int) and total >= 0
            else int((time.monotonic() - started) * 1000)
        )
        model = payload.get("model")
        return ProviderReply(
            content=content,
            model=model if isinstance(model, str) and model else self.model,
            duration_ms=duration_ms,
        )

    def status(self) -> ProviderStatus:
        local = is_loopback_host(httpx.URL(self.base_url).host)
        base = ProviderStatus(
            provider=self.name,
            model=self.model,
            endpoint=self.base_url,
            local=local,
            reachable=False,
            model_installed=False,
        )
        try:
            version = self._get("/api/version").get("version")
            tags = self._get("/api/tags").get("models", [])
        except ProviderError as exc:
            return replace(base, problem=str(exc))

        installed = tuple(
            str(entry.get("name"))
            for entry in tags
            if isinstance(entry, dict) and entry.get("name")
        )
        has_model = _model_installed(self.model, installed)
        return replace(
            base,
            reachable=True,
            version=str(version) if version else None,
            installed_models=installed,
            model_installed=has_model,
            problem=None
            if has_model
            else f"model {self.model!r} is not installed. Run: ollama pull {self.model}",
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------
    def _get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path, timeout=STATUS_TIMEOUT_SECONDS)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, body=body)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """One bounded request. Every failure becomes a ProviderError."""
        try:
            with self._client.stream(
                method,
                path,
                json=body,
                timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
            ) as response:
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ProviderError(
                            f"the reply was larger than {MAX_RESPONSE_BYTES:,} bytes"
                        )
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(self._unreachable(exc)) from None
        return self._decode(response, b"".join(chunks))

    def _decode(self, response: httpx.Response, body: bytes) -> dict[str, Any]:
        if response.is_redirect:
            raise ProviderError("the provider answered with a redirect, which is not followed")
        try:
            payload: Any = json.loads(body) if body else {}
        except (ValueError, RecursionError):
            payload = None
        error = payload.get("error", "") if isinstance(payload, dict) else ""
        if response.status_code == 404 and "not found" in str(error):
            raise ProviderUnavailableError(
                f"model {self.model!r} is not installed. Run: ollama pull {self.model}"
            )
        if response.status_code != 200:
            raise ProviderError(f"the provider returned HTTP {response.status_code}")
        if not isinstance(payload, dict):
            raise ProviderError("the provider returned something other than a JSON object")
        return payload

    def _unreachable(self, exc: httpx.HTTPError) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return f"no reply from {self.base_url} within {self.timeout_seconds:g}s"
        return f"could not reach {self.base_url} ({type(exc).__name__})"


def build_provider(settings: Settings) -> ModelProvider | None:
    """The configured provider, or None when AI is off.

    Raises :class:`ProviderConfigurationError` when AI is on but the
    configuration forbids using the provider, so the reason can be shown
    rather than the feature silently not working.
    """
    if not settings.ai_active:
        return None
    problem = settings.ai_endpoint_problem
    if problem is not None:
        raise ProviderConfigurationError(problem)
    if settings.ai_provider is AIProvider.OLLAMA:
        return OllamaProvider(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            timeout_seconds=settings.ai_timeout_seconds,
        )
    raise ProviderConfigurationError(  # pragma: no cover - enum is exhaustive today
        f"unsupported AI provider {settings.ai_provider.value!r}"
    )


def _model_installed(model: str, installed: tuple[str, ...]) -> bool:
    """Ollama lists ``llama3.1:8b``; a bare ``llama3.1`` means ``:latest``."""
    wanted = model if ":" in model else f"{model}:latest"
    return wanted in installed or model in installed
