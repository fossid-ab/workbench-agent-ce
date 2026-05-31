"""Upload HTTP response handling."""

import logging
from typing import Any, Dict

import requests

from workbench_agent.api.exceptions import ApiError

logger = logging.getLogger("workbench-agent")

HEADER_SCAN_CODE = "FOSSID-SCAN-CODE"
HEADER_FILE_NAME = "FOSSID-FILE-NAME"
HEADER_UPLOAD_TYPE = "FOSSID-UPLOAD-TYPE"
UPLOAD_TYPE_DEPENDENCY_ANALYSIS = "dependency_analysis"


def validate_standard_upload_response(response: requests.Response) -> None:
    """
    Validate a non-chunked upload HTTP response.

    Successful uploads return HTTP 200 with optional JSON ``status: "1"``.
    """
    if response.status_code != 200:
        raise ApiError(
            f"Upload failed with status {response.status_code}: {response.text}"
        )
    try:
        response_data: Dict[str, Any] = response.json()
    except ValueError:
        logger.debug("Standard upload completed (no JSON response)")
        return
    status = str(response_data.get("status", "0"))
    if status != "1":
        error_msg = response_data.get("error", "Unknown error")
        raise ApiError(f"Upload failed: {error_msg}")


def validate_chunk_upload_response(
    response: requests.Response,
    chunk_number: int,
    retry_count: int,
    *,
    max_retries: int,
) -> None:
    """
    Validate a chunked upload HTTP response.

    Raises ApiError with a retriable message when status != 200 and retries
    remain; raises a terminal ApiError when retries are exhausted.
    """
    if response.status_code == 200:
        logger.debug("Chunk %s uploaded successfully", chunk_number)
        return

    if retry_count < max_retries:
        logger.warning(
            "Chunk %s returned status %s, retrying... "
            "(attempt %s/%s)",
            chunk_number,
            response.status_code,
            retry_count + 1,
            max_retries + 1,
        )
        raise ApiError(
            f"Chunk {chunk_number} upload failed with status "
            f"{response.status_code}"
        )

    logger.error(
        "Chunk %s failed after %s attempts with status %s",
        chunk_number,
        max_retries + 1,
        response.status_code,
    )
    raise ApiError(
        f"Chunk {chunk_number} upload failed with status "
        f"{response.status_code} after {max_retries + 1} attempts"
    )
