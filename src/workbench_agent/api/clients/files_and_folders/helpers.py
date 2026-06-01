"""Files and folders API error handling and path rules."""

from typing import Any, Dict, Set

from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.utils.path_encoding import encode_path

# Actions that send a plain relative path (not base64-encoded).
PLAIN_PATH_ACTIONS: Set[str] = frozenset({"remove_component_identification"})


def path_for_action(action: str, relative_path: str) -> str:
    """
    Return the path value to send in the API payload for the given action.

    See ``quirks.md`` for the remove_component_identification exception.
    """
    if action in PLAIN_PATH_ACTIONS:
        return relative_path
    return encode_path(relative_path)


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> None:
    """Raise ApiError when response status is not success."""
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def flag_str(value: Any) -> str:
    """Convert bool/int flags to API '0' / '1' strings."""
    if value in (True, 1, "1"):
        return "1"
    return "0"
