"""
DownloadClient - Download files from Workbench.

"""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from workbench_agent.api.exceptions import ValidationError

if TYPE_CHECKING:
    from workbench_agent.api.base_api import BaseAPI

logger = logging.getLogger("workbench-agent")


class DownloadClient:
    """
    Downloads API client.

    Handles download operations from the 'download' API group.

    This client provides low-level operations. For report downloads,
    ReportService provides additional functionality.

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

    # ===== DOWNLOAD A REPORT =====

    def download_report(
        self,
        report_entity: str,
        process_id: int,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Download a generated report.

        This method handles downloading async reports from both scans and
        projects. The report generation process must be complete.

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

        logger.debug(f"Downloading {report_entity} report for process ID " f"{process_id}...")

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "report_entity": report_entity,
                "process_id": str(process_id),
            },
        }

        # Use extended timeout for large file downloads
        actual_timeout = timeout if timeout is not None else self.DEFAULT_DOWNLOAD_TIMEOUT

        return self._api._send_request(payload, timeout=actual_timeout)

    # ===== DOWNLOAD A PROJECT'S POLICY JSON =====

    def get_project_policy(self, project_code: str) -> Dict[str, Any]:
        """
        Download the project's license policy as JSON.

        The server responds with a plain text body containing a JSON array
        of license rules (id, blocked, reason, …).
        Use `PolicyService.download_project_policy_json` to parse it.

        Args:
            project_code: Project code (not display name)

        Returns:
            Dict with ``_raw_response`` (``requests.Response``) on success

        Raises:
            ApiError: If the download fails
            NetworkError: If there are network issues
        """
        logger.debug(
            "Downloading license policy JSON for project '%s'",
            project_code,
        )
        payload = {
            "group": "download",
            "action": "licenses_policy_info",
            "data": {
                "project_code": project_code,
            },
        }
        return self._api._send_request(payload)
