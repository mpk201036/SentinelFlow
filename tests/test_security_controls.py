"""Stage 15 - request-level controls that had never been exercised by a test.

Every earlier test ran with rate limiting off, and sent bodies with a
Content-Length. So the rate limiter, the streamed-body limit and the generic
500 handler were documented controls with no evidence behind them. These tests
drive each one through the real middleware stack.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import middleware
from app.api.app import create_app
from app.core.config import Settings
from app.core.paths import UnsafePathError
from app.database import repository
from app.database.session import session_scope

pytestmark = pytest.mark.integration


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": "2026-09-23T13:42:10Z",
        "source": "canonical",
        "event_type": "process_creation",
        "hostname": "WIN-SEC-01",
        "process_name": "cmd.exe",
    }
    event.update(overrides)
    return event


def _event_count(settings: Settings) -> int:
    with session_scope(settings) as session:
        return repository.count_events(session)


# ===========================================================================
# Rate limiting
# ===========================================================================
@pytest.fixture
def limited(global_db: Settings) -> Iterator[tuple[TestClient, Settings]]:
    settings = global_db.model_copy(update={"api_rate_limit_per_minute": 3})
    with TestClient(create_app(settings)) as client:
        yield client, settings


class TestRateLimit:
    def test_the_request_after_the_limit_is_refused_with_a_retry_time(
        self, limited: tuple[TestClient, Settings]
    ) -> None:
        client, _ = limited
        assert [client.get("/api/v1/health").status_code for _ in range(3)] == [200] * 3
        refused = client.get("/api/v1/health")
        assert refused.status_code == 429
        assert refused.json()["error"] == "rate_limited"
        assert 1 <= int(refused.headers["retry-after"]) <= 61

    def test_each_client_address_has_its_own_budget(self, global_db: Settings) -> None:
        settings = global_db.model_copy(update={"api_rate_limit_per_minute": 2})
        app = create_app(settings)
        with (
            TestClient(app, client=("192.0.2.10", 5000)) as first,
            TestClient(app, client=("192.0.2.11", 5000)) as second,
        ):
            assert [first.get("/api/v1/health").status_code for _ in range(3)] == [200, 200, 429]
            assert second.get("/api/v1/health").status_code == 200

    def test_the_window_slides(
        self, limited: tuple[TestClient, Settings], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, _ = limited
        clock = [1_000.0]
        monkeypatch.setattr(middleware.time, "monotonic", lambda: clock[0])
        for _ in range(3):
            client.get("/api/v1/health")
        assert client.get("/api/v1/health").status_code == 429
        clock[0] += 61
        assert client.get("/api/v1/health").status_code == 200

    def test_a_limit_of_zero_means_off(self, global_db: Settings) -> None:
        settings = global_db.model_copy(update={"api_rate_limit_per_minute": 0})
        with TestClient(create_app(settings)) as client:
            assert {client.get("/api/v1/health").status_code for _ in range(20)} == {200}


# ===========================================================================
# Body size
# ===========================================================================
@pytest.fixture
def small(global_db: Settings) -> Iterator[tuple[TestClient, Settings]]:
    settings = global_db.model_copy(
        update={"max_upload_bytes": 2_048, "api_rate_limit_per_minute": 0}
    )
    with TestClient(create_app(settings)) as client:
        yield client, settings


def _chunks(total: int, size: int = 256) -> Iterator[bytes]:
    """A JSON body sent in pieces, with no Content-Length: chunked transfer."""
    padding = "x" * max(0, total - 120)
    body = (
        '{"source": "canonical", "events": [{"timestamp": "2026-09-23T13:42:10Z", '
        f'"source": "canonical", "hostname": "WIN-SEC-01", "event_message": "{padding}"'
        "}]}"
    ).encode()
    for start in range(0, len(body), size):
        yield body[start : start + size]


class TestBodySize:
    def test_a_declared_oversized_body_is_refused_before_it_is_read(
        self, small: tuple[TestClient, Settings]
    ) -> None:
        client, settings = small
        response = client.post(
            "/api/v1/events",
            content=b"{" + b" " * 4_000 + b"}",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert _event_count(settings) == 0

    def test_a_streamed_body_without_content_length_is_counted_and_cut_off(
        self, small: tuple[TestClient, Settings]
    ) -> None:
        """The case the middleware exists for: chunked bodies declare no length."""
        client, settings = small
        response = client.post(
            "/api/v1/events",
            content=_chunks(10_000),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["error"] == "too_large"
        assert _event_count(settings) == 0

    def test_a_streamed_body_under_the_limit_is_accepted(
        self, small: tuple[TestClient, Settings]
    ) -> None:
        client, settings = small
        response = client.post(
            "/api/v1/events",
            content=_chunks(600),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 201, response.text
        assert _event_count(settings) == 1


# ===========================================================================
# Errors that reveal nothing
# ===========================================================================
def _with_failing_routes(settings: Settings) -> FastAPI:
    app = create_app(settings)

    @app.get("/api/v1/_explode")
    def explode() -> None:
        raise RuntimeError("database password is hunter2 at /srv/sentinelflow/secrets")

    @app.get("/api/v1/_path")
    def path() -> None:
        raise UnsafePathError("/etc/passwd is outside the permitted directories")

    return app


class TestErrors:
    def test_an_unexpected_error_is_a_generic_500_with_a_request_id(
        self, global_db: Settings, caplog: pytest.LogCaptureFixture
    ) -> None:
        settings = global_db.model_copy(update={"api_rate_limit_per_minute": 0})
        with TestClient(_with_failing_routes(settings), raise_server_exceptions=False) as client:
            response = client.get("/api/v1/_explode")
        assert response.status_code == 500
        body = response.json()
        assert body["error"] == "internal_error"
        assert "hunter2" not in response.text and "/srv" not in response.text
        assert body["request_id"] and body["request_id"] == response.headers["x-request-id"]
        assert "hunter2" in caplog.text  # logged in full, returned as nothing

    def test_a_refused_path_is_a_400(self, global_db: Settings) -> None:
        settings = global_db.model_copy(update={"api_rate_limit_per_minute": 0})
        with TestClient(_with_failing_routes(settings)) as client:
            response = client.get("/api/v1/_path")
        assert response.status_code == 400
        assert response.json()["error"] == "unsafe_path"


# ===========================================================================
# Every response carries the security headers
# ===========================================================================
class TestHeadersEverywhere:
    def _assert_headers(self, response: Any) -> None:
        for header in ("x-content-type-options", "x-frame-options", "content-security-policy"):
            assert header in response.headers, (response.status_code, header)

    def test_ordinary_responses(self, small: tuple[TestClient, Settings]) -> None:
        client, _ = small
        for path in ("/", "/api/v1/health", "/static/console.css", "/nope", "/api/v1/nope"):
            self._assert_headers(client.get(path))

    def test_refusals_from_the_outer_middleware(
        self, small: tuple[TestClient, Settings], global_db: Settings
    ) -> None:
        client, _ = small
        self._assert_headers(
            client.post(
                "/api/v1/events",
                content=_chunks(10_000),
                headers={"Content-Type": "application/json"},
            )
        )
        self._assert_headers(
            client.patch(
                "/api/v1/alerts/00000000-0000-4000-8000-000000000000",
                json={},
                headers={"Sec-Fetch-Site": "cross-site"},
            )
        )
        settings = global_db.model_copy(update={"api_rate_limit_per_minute": 1})
        with TestClient(create_app(settings)) as limited_client:
            limited_client.get("/api/v1/health")
            self._assert_headers(limited_client.get("/api/v1/health"))
