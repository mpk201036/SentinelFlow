"""Interactive API docs: off by default, and under a policy of their own when on.

Swagger UI is a script bundle served from a CDN. The console's
Content-Security-Policy allows no script this process did not serve, so under
that policy the page cannot run. Relaxing it for the whole application would
let a CDN's code act with the analyst's browser everywhere, which is what the
policy exists to prevent. Instead this one page gets a narrow policy of its own:
scripts only from the CDN, its single inline start-up script by hash, requests
back to this server only, and nothing else. The bundle is pinned to one
published version rather than following whatever "5.x" becomes.
"""

from __future__ import annotations

import base64
import hashlib
import re

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse

SWAGGER_UI_VERSION = "5.17.14"
CDN = "https://cdn.jsdelivr.net"
SWAGGER_JS = f"{CDN}/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"
SWAGGER_CSS = f"{CDN}/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui.css"

_INLINE_SCRIPT_RE = re.compile(rb"<script>(.*?)</script>", re.DOTALL)


def docs_policy(page: bytes) -> str:
    """The Content-Security-Policy for the docs page, allowing only what it uses."""
    hashes = " ".join(
        f"'sha256-{base64.b64encode(hashlib.sha256(script).digest()).decode()}'"
        for script in _INLINE_SCRIPT_RE.findall(page)
    )
    return (
        f"default-src 'none'; script-src {CDN} {hashes}; "
        # Swagger UI sets style attributes as it renders; styles cannot run code.
        f"style-src {CDN} 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )


def install_docs(app: FastAPI, openapi_url: str) -> None:
    """Serve Swagger UI at /docs. ReDoc is not offered: it pulls from two more hosts."""
    page = bytes(
        get_swagger_ui_html(
            openapi_url=openapi_url,
            title=f"{app.title} API",
            swagger_js_url=SWAGGER_JS,
            swagger_css_url=SWAGGER_CSS,
            swagger_favicon_url="/static/favicon.svg",
        ).body
    )
    policy = docs_policy(page)

    @app.get("/docs", include_in_schema=False)
    def docs() -> HTMLResponse:
        return HTMLResponse(page, headers={"Content-Security-Policy": policy})
