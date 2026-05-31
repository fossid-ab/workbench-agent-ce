"""Users API error handling and response normalization."""

import logging
from typing import Any, Dict, List, NoReturn

from workbench_agent.api.exceptions import ApiError

logger = logging.getLogger("workbench-agent")

USER_NOT_FOUND_MARKERS = (
    "User not found",
    "username_not_valid",
    "user does not exist",
)


def is_user_not_found(error_msg: str, response: Dict[str, Any]) -> bool:
    """True when the API indicates the searched user does not exist."""
    if error_msg and any(m in error_msg for m in USER_NOT_FOUND_MARKERS):
        return True
    data = response.get("data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                code = item.get("code", "")
                if "username_not_valid" in code:
                    return True
    return False


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> NoReturn:
    """Raise ApiError when response status is not success."""
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def normalize_permissions_list_data(
    data: Any,
    *,
    operation: str,
) -> List[Dict[str, Any]]:
    """
    Normalize list / map / single-object ``data`` to a list of permission dicts.

    Live servers may return an array or a map keyed by permission id.
    """
    if data is None:
        logger.warning(
            "users.%s: success but ``data`` is null or absent", operation
        )
        return []
    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            logger.warning(
                "users.%s: list contains non-dict elements: %s",
                operation,
                data,
            )
            return [x for x in data if isinstance(x, dict)]
        return data
    if isinstance(data, dict):
        if not data:
            return []
        if all(isinstance(v, dict) for v in data.values()):
            return list(data.values())
        return [data]
    logger.warning(
        "users.%s: unexpected 'data' type: %s", operation, type(data)
    )
    return []
