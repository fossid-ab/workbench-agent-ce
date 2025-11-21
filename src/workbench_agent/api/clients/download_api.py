"""
DownloadClient - Handles file downloads from Workbench.

This client provides:
- Report downloads (scan and project reports)
- Future: Additional download operations from the 'download' API group
"""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from workbench_agent.exceptions import ValidationError

if TYPE_CHECKING:
    from workbench_agent.api.helpers.base_api import BaseAPI

logger = logging.getLogger("workbench-agent")


class DownloadClient:
    """
    Downloads API client using composition pattern.

    Handles all file download operations from the 'download' API group.

    This client provides low-level download operations. For domain-specific
    report downloads, use ReportService which provides additional business
    logic and convenience methods.

    Example:
        >>> downloads = DownloadClient(base_api)
        >>> response = downloads.download_report("scans", 12345)
        >>> response = downloads.download_report("projects", 67890)
    """

    # Download Constants
    DEFAULT_DOWNLOAD_TIMEOUT = 1800  # 30 minutes for large files

    def __init__(self, base_api: "BaseAPI"):
        """
        Initialize DownloadClient.

        Args:
            base_api: BaseAPI instance for HTTP requests
        """
        self._api = base_api
        logger.debug("DownloadClient initialized")

    def download_report(
        self,
        report_entity: str,
        process_id: int,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Download a generated report file.

        This method handles downloading reports for both scans and
        projects that were generated asynchronously. The report must
        have been previously generated and the process must be complete.

        Args:
            report_entity: Either "scans" or "projects"
            process_id: Process queue ID from report generation
            timeout: Custom timeout in seconds
                (defaults to DEFAULT_DOWNLOAD_TIMEOUT)

        Returns:
            Response dict with "_raw_response" key containing the
            requests.Response object with the report file content

        Raises:
            ApiError: If download fails or report doesn't exist
            NetworkError: If there are network issues
            ValidationError: If report_entity is invalid

        Example:
            >>> # After generating a report asynchronously
            >>> process_id = reports.generate_project_report(
            ...     "MyProject", "xlsx"
            ... )
            >>> # Wait for completion...
            >>> response = downloads.download_report(
            ...     "projects", process_id
            ... )
            >>> # Save the file
            >>> with open("report.xlsx", "wb") as f:
            ...     f.write(response["_raw_response"].content)
        """
        if report_entity not in ("scans", "projects"):
            raise ValidationError(
                f"Invalid report_entity '{report_entity}'. Must be "
                f"either 'scans' or 'projects'."
            )

        logger.debug(
            f"Downloading {report_entity} report for process ID "
            f"{process_id}..."
        )

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "report_entity": report_entity,
                "process_id": str(process_id),
            },
        }

        # Use extended timeout for large file downloads
        actual_timeout = (
            timeout
            if timeout is not None
            else self.DEFAULT_DOWNLOAD_TIMEOUT
        )

        return self._api._send_request(payload, timeout=actual_timeout)
