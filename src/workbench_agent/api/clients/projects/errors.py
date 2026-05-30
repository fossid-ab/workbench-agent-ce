"""Projects API error handling and response interpretation."""

from typing import Any, Dict, Optional

from workbench_agent.api.exceptions import ApiError, ProjectNotFoundError

NOT_FOUND_MARKERS = (
    "Project code does not exist",
    "Project does not exist",
    "project_does_not_exist",
    "row_not_found",
)


def is_project_not_found(error_msg: str) -> bool:
    """True when the API error text indicates the project does not exist."""
    if not error_msg:
        return False
    return any(marker in error_msg for marker in NOT_FOUND_MARKERS)


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> None:
    """Raise ApiError when response status is not success."""
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def raise_project_not_found(project_code: str) -> None:
    raise ProjectNotFoundError(f"Project '{project_code}' not found")


def try_raise_parsing_request_error(
    response: Dict[str, Any],
    *,
    context: str,
    project_code: Optional[str] = None,
) -> bool:
    """
    Handle ``RequestData.Base.issues_while_parsing_request`` for create/update.

    Returns True if an ApiError was raised.
    """
    error_msg = response.get("error", "")
    if error_msg != "RequestData.Base.issues_while_parsing_request":
        return False

    data = response.get("data", [])
    if not isinstance(data, list) or not data:
        return False

    error_code = data[0].get("code", "")
    field = (
        data[0].get("message_parameters", {}).get("fieldname", "unknown")
    )

    if "not_valid_date_string" in error_code:
        target = (
            f"project '{project_code}'"
            if project_code
            else "project"
        )
        raise ApiError(
            f"Failed to update {target}: Invalid date format for '{field}'. "
            f"Please provide a valid date string (e.g., '2025-12-31')",
            details=response,
        )

    if error_code == "RequestData.Base.mandatory_field_missing":
        raise ApiError(
            f"Failed to update project: Missing required field '{field}'",
            details=response,
        )

    return False


def try_raise_create_parsing_request_error(
    response: Dict[str, Any],
    *,
    project_name: str,
) -> bool:
    """Create-specific parsing errors (date validation). Returns True if raised."""
    error_msg = response.get("error", "")
    if error_msg != "RequestData.Base.issues_while_parsing_request":
        return False

    data = response.get("data", [])
    if not isinstance(data, list) or not data:
        return False

    error_code = data[0].get("code", "")
    if "not_valid_date_string" in error_code:
        field = (
            data[0]
            .get("message_parameters", {})
            .get("fieldname", "date")
        )
        raise ApiError(
            f"Failed to create project '{project_name}':"
            f"Invalid date format for '{field}'."
            f"Please use a valid date string (e.g., '2025-12-31')",
            details=response,
        )
    return False
