"""Defense-in-depth structured-log redaction for Restricted credential fields."""

import logging
import re
from collections.abc import Mapping
from typing import Any, cast

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"x-auth-access-token|x-auth-refresh-token|authorization)(\s*[:=]\s*)"
    r"(?:bearer\s+|basic\s+)?([^\s,;}\]]+)"
)
_AUTH_VALUE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "client_secret",
        "api_key",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "x-auth-access-token",
        "x-auth-refresh-token",
    }
)


def redact_text(value: str) -> str:
    """Remove common credential assignments and authorization schemes from free text."""
    assigned = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value
    )
    return _AUTH_VALUE.sub(lambda match: f"{match.group(1)} [REDACTED]", assigned)


def redact_value(value: Any, key: str | None = None) -> Any:
    """Recursively redact structured values without serializing arbitrary objects."""
    if key and key.lower() in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        typed_value = cast("Mapping[object, Any]", value)
        return {
            str(item_key): redact_value(item, str(item_key))
            for item_key, item in typed_value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


class SecretRedactionFilter(logging.Filter):
    """Redact messages, formatting arguments, and structured logging extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Render first so replacing an assignment value cannot leave stale %-style
        # arguments behind and break the logging handler.
        record.msg = redact_text(record.getMessage())
        record.args = ()
        protected = set(logging.makeLogRecord({}).__dict__)
        for key in set(record.__dict__) - protected:
            record.__dict__[key] = redact_value(record.__dict__[key], key)
        return True
