"""Double-submit CSRF protection for cookie-authenticated state changes."""

import hmac
import secrets

from fastapi import Request

CSRF_COOKIE_NAME = "fm_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"


def token() -> str:
    return secrets.token_urlsafe(32)


def valid(request: Request) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE_NAME)
    header = request.headers.get(CSRF_HEADER_NAME)
    return bool(cookie and header and hmac.compare_digest(cookie, header))
