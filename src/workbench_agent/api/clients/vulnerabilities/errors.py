"""Vulnerabilities API error handling and wire-format helpers."""

from typing import Any, Dict, Optional, Union

from workbench_agent.api.exceptions import ApiError


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> None:
    """Raise ApiError when response status is not success."""
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def flag_str(value: Union[bool, int, str]) -> str:
    """Coerce boolean flags to ``"0"`` / ``"1"`` for the API."""
    return "1" if value in (True, 1, "1") else "0"


def optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def build_list_payload(
    *,
    project_code: Optional[str] = None,
    scan_code: Optional[str] = None,
    search_value: Optional[str] = None,
    records_per_page: Optional[Union[int, str]] = None,
    page: Optional[Union[int, str]] = None,
    count_results: Optional[Union[bool, int, str]] = None,
) -> Dict[str, Any]:
    """Build ``list_vulnerabilities`` request ``data`` per API spec."""
    data: Dict[str, Any] = {}
    if project_code is not None:
        data["project_code"] = project_code
    if scan_code is not None:
        data["scan_code"] = scan_code
    if search_value is not None:
        data["search_value"] = search_value
    if records_per_page is not None:
        data["records_per_page"] = optional_str(records_per_page)
    if page is not None:
        data["page"] = optional_str(page)
    if count_results is not None:
        data["count_results"] = flag_str(count_results)
    return data
