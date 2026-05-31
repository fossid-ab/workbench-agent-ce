"""Components API error handling and response interpretation."""

from typing import Any, Dict, Optional

from workbench_agent.api.exceptions import ApiError


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> None:
    """Raise ApiError when response status is not success."""
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def is_missing_component_information(response: Dict[str, Any]) -> bool:
    """
    True when get_information succeeded but no component exists.

    Workbench 2026.1 returns status "1" with data null for unknown components.
    """
    return (
        response.get("status") == "1"
        and response.get("data") is None
    )


def optional_str(value: Any) -> Optional[str]:
    """Coerce optional pagination fields to strings for the API."""
    if value is None:
        return None
    return str(value)
