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


# ===========================================================================
# DNS rebinding: the server answers only to its own names
# ===========================================================================
#: What a DNS-rebinding page's requests look like. The page re-points its own
#: domain at 127.0.0.1, so to the browser SentinelFlow *is* that page: requests
#: are same-origin and pass the cross-site guard. Only Host gives it away.
REBINDING = {
    "Host": "rebind.attacker.example:8000",
    "Origin": "http://rebind.attacker.example:8000",
    "Sec-Fetch-Site": "same-origin",
}


@pytest.fixture
def served(global_db: Settings) -> Iterator[tuple[TestClient, Settings]]:
    settings = global_db.model_copy(update={"allowed_hosts": ["sentinel.lab.internal"]})
    with TestClient(create_app(settings)) as client:
        yield client, settings


class TestHostGuard:
    """Stage 18 security pass. Before it, both requests below were served."""

    def test_a_rebinding_page_cannot_read(self, served: tuple[TestClient, Settings]) -> None:
        client, _ = served
        response = client.get("/api/v1/alerts", headers=REBINDING)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_host"
        assert "content-security-policy" in response.headers  # refusals are hardened too

    def test_a_rebinding_page_cannot_write(self, served: tuple[TestClient, Settings]) -> None:
        client, settings = served
        before = _event_count(settings)
        response = client.post(
            "/api/v1/events", headers=REBINDING, json={"source": "canonical", "events": [_event()]}
        )
        assert response.status_code == 400
        assert _event_count(settings) == before

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1:8000",
            "localhost:8000",
            "LOCALHOST",
            "[::1]:8000",
            "127.0.0.2",
            "sentinel.lab.internal",
        ],
    )
    def test_this_machine_and_configured_names_are_served(
        self, served: tuple[TestClient, Settings], host: str
    ) -> None:
        client, _ = served
        assert client.get("/api/v1/health", headers={"Host": host}).status_code == 200

    @pytest.mark.parametrize(
        "host",
        [
            "localhost.attacker.example",  # look-alikes
            "127.0.0.1.attacker.example",
            "sentinel.lab.internal.attacker.example",
            "0.0.0.0:8000",  # a wildcard is not an address anyone reaches
            "",
            "[::1",
            "user@127.0.0.1",
        ],
    )
    def test_every_other_name_is_refused(
        self, served: tuple[TestClient, Settings], host: str
    ) -> None:
        client, _ = served
        assert client.get("/api/v1/health", headers={"Host": host}).status_code == 400

    def test_the_console_is_guarded_too(self, served: tuple[TestClient, Settings]) -> None:
        client, _ = served
        assert client.get("/", headers=REBINDING).status_code == 400

    def test_a_wildcard_cannot_switch_the_guard_off(self) -> None:
        with pytest.raises(ValueError, match="wildcards are refused"):
            Settings(_env_file=None, allowed_hosts="*")
        with pytest.raises(ValueError, match="wildcards are refused"):
            Settings(_env_file=None, allowed_hosts="*.lab.internal")

    def test_the_bind_address_is_answered_but_a_wildcard_bind_is_not(self) -> None:
        assert "10.0.0.8" in Settings(_env_file=None, api_host="10.0.0.8").trusted_hosts()
        assert "0.0.0.0" not in Settings(_env_file=None, api_host="0.0.0.0").trusted_hosts()

    @pytest.mark.parametrize(
        ("header", "name"),
        [
            ("localhost:8000", "localhost"),
            ("[::1]:8000", "::1"),
            ("::1", "::1"),
            ("Example.LAB", "example.lab"),
            ("[::1", ""),
        ],
    )
    def test_the_name_is_read_from_the_header(self, header: str, name: str) -> None:
        assert middleware.host_name(header) == name


# ===========================================================================
# API docs: off by default; on a narrow policy of their own when on
# ===========================================================================
class TestApiDocs:
    def test_off_by_default(self, global_db: Settings) -> None:
        assert Settings(_env_file=None).api_docs_enabled is False
        with TestClient(create_app(global_db)) as client:
            for path in ("/docs", "/redoc", "/openapi.json"):
                assert client.get(path).status_code == 404, path

    def test_when_on_the_page_has_its_own_narrow_policy(self, global_db: Settings) -> None:
        import base64
        import hashlib
        import re

        from app.api.docs import SWAGGER_UI_VERSION

        settings = global_db.model_copy(update={"api_docs_enabled": True})
        with TestClient(create_app(settings)) as client:
            page = client.get("/docs")
            console = client.get("/rules")
            assert client.get("/redoc").status_code == 404  # two more third-party hosts
        policy = page.headers["content-security-policy"]
        assert policy.startswith("default-src 'none';")
        assert "script-src https://cdn.jsdelivr.net 'sha256-" in policy
        assert "'unsafe-inline'" not in policy.split("script-src", 1)[1].split(";", 1)[0]
        assert "connect-src 'self'" in policy
        # The one inline script is allowed by its exact hash, and nothing else is.
        (inline,) = re.findall(r"<script>(.*?)</script>", page.text, re.DOTALL)
        digest = base64.b64encode(hashlib.sha256(inline.encode()).digest()).decode()
        assert f"'sha256-{digest}'" in policy
        # One pinned version, not whatever "5.x" becomes; no favicon from elsewhere.
        assert f"swagger-ui-dist@{SWAGGER_UI_VERSION}/" in page.text
        assert "fastapi.tiangolo.com" not in page.text
        # And the console keeps its own policy.
        assert console.headers["content-security-policy"].startswith(
            "default-src 'self'; script-src 'self';"
        )


# ===========================================================================
# The database file is private to its owner
# ===========================================================================
@pytest.mark.skipif(__import__("os").name != "posix", reason="mode bits are POSIX")
class TestDatabaseFile:
    def test_a_new_database_is_owner_only(self, tmp_path: Any) -> None:
        from app.database.session import create_db_engine

        path = tmp_path / "new.db"
        create_db_engine(Settings(_env_file=None, database_url=f"sqlite:///{path}")).dispose()
        assert path.stat().st_mode & 0o777 == 0o600

    def test_an_existing_readable_database_is_tightened(self, tmp_path: Any) -> None:
        from app.database.session import create_db_engine

        path = tmp_path / "old.db"
        path.touch(mode=0o644)
        path.chmod(0o644)
        create_db_engine(Settings(_env_file=None, database_url=f"sqlite:///{path}")).dispose()
        assert path.stat().st_mode & 0o777 == 0o600
