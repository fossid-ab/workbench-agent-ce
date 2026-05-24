"""
API-layer redaction for log-safe rendering of HTTP payloads and responses.

This module masks sensitive values inside the request/response shapes the API
client handles: nested ``dict``/``list`` JSON and free-form response bodies.

"""

import json
from typing import Any

REDACTED_VALUE = "***REDACTED***"

SENSITIVE_FIELDS = frozenset(
    {
        "api_key",
        "api_token",
        "authorization",
        "key",
        "password",
        "secret",
        "token",
    }
)

SENSITIVE_SUFFIXES = ("_token", "_password", "_secret", "_key")


__all__ = [
    "REDACTED_VALUE",
    "SENSITIVE_FIELDS",
    "SENSITIVE_SUFFIXES",
    "redact_sensitive_data",
    "redact_text",
    "redact_response_text",
]


def _is_sensitive_name(name: str) -> bool:
    """Return True if ``name`` matches the API-layer sensitive-name policy."""
    lower = name.lower()
    if lower in SENSITIVE_FIELDS:
        return True
    return any(lower.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def redact_sensitive_data(value: Any) -> Any:
    """
    Return a copy of ``value`` with sensitive fields masked for logging.

    Walks nested ``dict``/``list`` structures and replaces the value of any
    key that matches the sensitive-name policy with :data:`REDACTED_VALUE`.
    Scalars and unknown types are returned unchanged.
    """
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if _is_sensitive_name(str(key)):
                redacted[key] = REDACTED_VALUE
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted

    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]

    return value


def redact_text(text: str, *sensitive_values: str) -> str:
    """
    Mask known sensitive values inside a free-form (non-JSON) log string.

    Used as a fallback when a response body cannot be parsed as JSON. Empty
    sensitive values are skipped so an unset token does not turn every empty
    substring into the placeholder.
    """
    redacted_text = text
    for sensitive_value in sensitive_values:
        if sensitive_value:
            redacted_text = redacted_text.replace(
                sensitive_value, REDACTED_VALUE
            )
    return redacted_text


def redact_response_text(text: str, *sensitive_values: str) -> str:
    """
    Mask sensitive fields in an HTTP response body before debug logging.

    Attempts JSON parsing first so structured fields can be redacted by name;
    falls back to literal substring replacement for non-JSON payloads.
    """
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return redact_text(text, *sensitive_values)

    return json.dumps(redact_sensitive_data(parsed))
