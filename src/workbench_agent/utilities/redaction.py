"""
CLI-layer redaction for debug logging of parsed arguments.

The helper here operates on an ``argparse.Namespace`` produced by the CLI
parser and returns a dict safe to pass to ``logger.debug``. It does not touch
HTTP payloads or response bodies — those are the API layer's responsibility.
"""

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
    "redact_cli_args_for_logging",
]


def _is_sensitive_name(name: str) -> bool:
    """Return True if ``name`` matches the CLI-layer sensitive-name policy."""
    lower = name.lower()
    if lower in SENSITIVE_FIELDS:
        return True
    return any(lower.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def redact_cli_args_for_logging(parsed_args: object) -> dict[str, Any]:
    """
    Build a shallow copy of an ``argparse`` namespace safe for debug logging.

    Attribute names matching the sensitive-name policy have their values
    replaced with :data:`REDACTED_VALUE`. ``None`` values are preserved so
    consumers can still distinguish "flag was not provided" from "flag was
    provided and redacted".
    """
    out: dict[str, Any] = dict(vars(parsed_args))
    for key, value in list(out.items()):
        if value is None:
            continue
        if _is_sensitive_name(str(key)):
            out[key] = REDACTED_VALUE
    return out
