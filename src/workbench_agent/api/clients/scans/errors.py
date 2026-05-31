"""Scans API error handling and response normalization."""

import logging
from typing import Any, Dict, List, Optional

from workbench_agent.api.exceptions import ApiError, ScanNotFoundError

logger = logging.getLogger("workbench-agent")

SCAN_NOT_FOUND_MARKERS = (
    "Scan not found",
    "row_not_found",
)

FILENAME_NOT_VALID_CODE = "RequestData.Traits.PathTrait.filename_is_not_valid"
PARSING_REQUEST_ERROR = "RequestData.Base.issues_while_parsing_request"


def is_scan_not_found(error_msg: str) -> bool:
    """True when the API error text indicates the scan does not exist."""
    if not error_msg:
        return False
    return any(marker in error_msg for marker in SCAN_NOT_FOUND_MARKERS)


def raise_scan_not_found(scan_code: str) -> None:
    raise ScanNotFoundError(f"Scan '{scan_code}' not found")


def raise_on_failed_response(
    response: Dict[str, Any],
    *,
    error_context: str,
) -> None:
    error_msg = response.get("error", f"Unexpected response: {response}")
    raise ApiError(f"{error_context}: {error_msg}", details=response)


def parse_list_scans_data(data: Any) -> List[Dict[str, Any]]:
    """
    Normalize ``list_scans`` ``data``: dict keyed by id → list of scan dicts.
    """
    if isinstance(data, dict):
        scan_list: List[Dict[str, Any]] = []
        for scan_id, scan_details in data.items():
            if isinstance(scan_details, dict):
                try:
                    scan_details["id"] = int(scan_id)
                except ValueError:
                    logger.warning(
                        "Non-integer scan ID key found: %s", scan_id
                    )
                    scan_details["id"] = scan_id
                if "code" not in scan_details:
                    logger.warning(
                        "Scan details for ID %s missing 'code' field",
                        scan_id,
                    )
                scan_list.append(scan_details)
            else:
                logger.warning(
                    "Unexpected format for scan details with ID %s",
                    scan_id,
                )
        return scan_list
    if isinstance(data, list) and not data:
        return []
    logger.warning("Unexpected data format for list_scans: %s", type(data))
    return []


def normalize_git_status_data(data: Any) -> Dict[str, Any]:
    """Always return a dict for git clone status ``data``."""
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        return {"data": data}
    logger.warning(
        "Unexpected response type from git status API: %s", type(data)
    )
    return {"data": str(data)}


def normalize_check_status_data(
    data: Any,
    *,
    process_type: str,
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """Normalize ``check_status`` ``data`` to a dict."""
    if isinstance(data, dict):
        return data
    if isinstance(data, bool):
        if process_type == "DELETE_SCAN":
            if data is True:
                out: Dict[str, Any] = {
                    "progress_state": "FINISHED",
                    "is_finished": True,
                }
                msg = response.get("message")
                if isinstance(msg, str) and msg:
                    out["message"] = msg
                return out
            return {
                "progress_state": "FAILED",
                "is_finished": True,
            }
        return {"status": str(data)}
    if isinstance(data, str):
        return {"status": data}
    return {"status": str(data)}


def is_remove_uploaded_filename_not_found(
    response: Dict[str, Any],
    *,
    filename: Optional[str],
) -> bool:
    """True when remove_uploaded_content failed because the path does not exist."""
    if not filename:
        return False
    if response.get("error") != PARSING_REQUEST_ERROR:
        return False
    data = response.get("data", [])
    if not isinstance(data, list) or not data:
        return False
    error_code = data[0].get("code", "") if isinstance(data[0], dict) else ""
    return error_code == FILENAME_NOT_VALID_CODE
