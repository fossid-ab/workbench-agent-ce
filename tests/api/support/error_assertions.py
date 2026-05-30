"""Helpers for asserting API client error handling."""

from typing import Any, Callable, Optional, Pattern, Union

import pytest

from workbench_agent.api.exceptions import ApiError


MatchType = Optional[Union[str, Pattern[str]]]


def assert_api_error(
    callable_fn: Callable[[], Any],
    *,
    match: MatchType = None,
    message_contains: Optional[str] = None,
) -> ApiError:
    """
    Assert that callable raises ApiError with optional message checks.

    Returns:
        The caught ApiError for further inspection.
    """
    with pytest.raises(ApiError) as exc_info:
        callable_fn()

    err = exc_info.value
    assert err.message, "ApiError should have a non-empty message"

    if match is not None:
        if isinstance(match, str):
            assert match in err.message
        else:
            assert match.search(err.message)

    if message_contains is not None:
        assert message_contains in err.message

    return err


def assert_api_error_details_status_zero(err: ApiError) -> None:
    """Assert API error response used status '0' when details are present."""
    details = err.details or {}
    if "status" in details:
        assert details["status"] == "0", (
            f"Expected API status '0' in details, got {details['status']!r}"
        )
