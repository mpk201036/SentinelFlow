"""CSRF protection for the console's forms.

The console now has forms that close alerts and confirm incidents, so a page
on another site must not be able to submit them in the analyst's browser.
Two independent layers stop that:

1. :class:`~app.api.middleware.CrossSiteWriteGuard` refuses any write a browser
   marks as cross-site, using ``Sec-Fetch-Site`` and ``Origin``.
2. Every form carries a token, checked here: the **signed double-submit**
   pattern. A random value lives in an ``HttpOnly``, ``SameSite=Strict``
   cookie. The form carries an HMAC of that value under a secret that exists
   only in this process. A request is accepted only if the two agree.

An attacker's page cannot read the cookie, cannot compute the HMAC without
the secret, and with ``SameSite=Strict`` its cross-site request does not even
carry the cookie. No server-side session is needed.

The secret is generated when the app starts. Restarting the server therefore
invalidates any form already on screen, and the analyst is told to reload -
a fair price for having no secret on disk to protect.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from fastapi import Request
from starlette.responses import Response

COOKIE_NAME = "sf_csrf"
FIELD_NAME = "csrf_token"

#: ``secrets.token_urlsafe(32)``: 43 characters from the URL-safe alphabet.
_COOKIE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class CsrfError(Exception):
    """A form submission that could not be verified. Nothing was changed."""


def new_secret() -> bytes:
    return secrets.token_bytes(32)


def sign(secret: bytes, cookie: str) -> str:
    return hmac.new(secret, cookie.encode("ascii"), hashlib.sha256).hexdigest()


def cookie_from(request: Request) -> str | None:
    value = request.cookies.get(COOKIE_NAME)
    return value if value and _COOKIE_RE.fullmatch(value) else None


def form_token(request: Request) -> tuple[str, str | None]:
    """The token to put in forms, and a new cookie to set if the browser has none."""
    cookie = cookie_from(request)
    issued = None
    if cookie is None:
        cookie = issued = secrets.token_urlsafe(32)
    return sign(request.app.state.csrf_secret, cookie), issued


def set_cookie(response: Response, value: str, *, secure: bool) -> None:
    response.set_cookie(
        COOKIE_NAME,
        value,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )


async def verify_csrf(request: Request) -> None:
    """FastAPI dependency for every console form. Raises CsrfError on any mismatch."""
    form = await request.form()
    submitted = form.get(FIELD_NAME)
    cookie = cookie_from(request)
    if not isinstance(submitted, str) or cookie is None:
        raise CsrfError("missing token")
    expected = sign(request.app.state.csrf_secret, cookie)
    # Compared as bytes: compare_digest refuses non-ASCII str, and the
    # submitted value is whatever the request says it is.
    if not hmac.compare_digest(submitted.encode("utf-8"), expected.encode("ascii")):
        raise CsrfError("token does not match")
