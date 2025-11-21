"""
QuickScanClient - Handles quick scan operations for individual files.
"""

import json
import logging
from typing import Any, Dict, List

from workbench_agent.api.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class QuickScanClient:
    """
    Quick Scan API client using composition pattern.

    Handles quick scan operations for individual files without creating
    a full scan in the Workbench system.

    Example:
        >>> quick_scan = QuickScanClient(base_api)
        >>> results = quick_scan.scan_one_file(file_content_b64, limit=1, sensitivity=10)
    """

    def __init__(self, base_api):
        """
        Initialize QuickScanClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("QuickScanClient initialized")

    def scan_one_file(
        self, file_content_b64: str, limit: int = 1, sensitivity: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Perform a quick scan of a single file using base64 content.

        Args:
            file_content_b64: Base64-encoded file content
            limit: Max number of results to consider
            sensitivity: Snippet detection sensitivity

        Returns:
            List of parsed quick scan result dictionaries

        Raises:
            ApiError: If the API call fails or unexpected response received

        Note:
            **Response handling:**
            - Older Workbench versions may return "classification" field (array)
            - Newer Workbench versions return "noise" field (object)

            This method normalizes the response to always use "noise" field
            for consistency across versions.
        """
        logger.debug(
            "Initiating quick scan (limit=%s, sensitivity=%s)...",
            limit,
            sensitivity,
        )

        payload = {
            "group": "quick_scan",
            "action": "scan_one_file",
            "data": {
                "file_content": file_content_b64,
                "limit": str(limit),
                "sensitivity": str(sensitivity),
            },
        }

        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get(
                "error", f"Unexpected response: {response}"
            )
            raise ApiError(
                f"Quick scan failed: {error_msg}", details=response
            )

        results_raw = response.get("data", [])
        if not isinstance(results_raw, list):
            logger.warning(
                "Quick scan returned unexpected data format: %s",
                type(results_raw),
            )
            return []

        parsed_results: List[Dict[str, Any]] = []
        for item in results_raw:
            if isinstance(item, dict):
                result = item
            elif isinstance(item, str):
                try:
                    result = json.loads(item)
                except json.JSONDecodeError:
                    logger.warning(
                        "Failed to parse quick scan result item as JSON; "
                        "skipping"
                    )
                    continue
            else:
                continue

            # Normalize legacy format: convert "classification" array to "noise" object
            if "classification" in result and "noise" not in result:
                logger.debug(
                    "Normalizing legacy quick scan response "
                    "(classification → noise)"
                )
                # Convert legacy "classification" array to "noise" object
                result["noise"] = {
                    "classification": result.pop("classification")
                }

            parsed_results.append(result)

        logger.debug(
            "Quick scan returned %d parsed results", len(parsed_results)
        )
        return parsed_results
