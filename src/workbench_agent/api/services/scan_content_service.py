"""
ScanContentService - Server-side scan target content (clear paths, Git fetch).

"""

import logging
from typing import TYPE_CHECKING, Optional

from workbench_agent.api.utils.process_waiter import StatusResult

if TYPE_CHECKING:
    from workbench_agent.api.clients.scans import ScansClient
    from workbench_agent.api.services.status_check_service import (
        StatusCheckService,
    )

logger = logging.getLogger("workbench-agent")


class ScanContentService:
    """
    Orchestrates scan-target content on the Workbench server.

    Handlers use this service instead of calling ``ScansClient`` directly.
    """

    def __init__(
        self,
        scans_client: "ScansClient",
        status_check_service: "StatusCheckService",
    ) -> None:
        self._scans = scans_client
        self._status_check = status_check_service
        logger.debug("ScanContentService initialized")

    def remove_uploaded_content(
        self, scan_code: str, filename: Optional[str] = None
    ) -> bool:
        """
        Remove uploaded content from a scan (all or a specific path).

        Args:
            scan_code: Scan code
            filename: Relative path, or blank for entire scan
        """
        logger.debug(
            "Removing uploaded content for scan '%s' (path=%r)",
            scan_code,
            filename,
        )
        return self._scans.remove_uploaded_content(scan_code, filename)

    def download_content_from_git(self, scan_code: str) -> bool:
        """Start Git clone/download for the scan's configured repository."""
        logger.debug("Initiating Git Clone for scan '%s'", scan_code)
        return self._scans.download_content_from_git(scan_code)

    def check_git_clone_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 3,
    ) -> StatusResult:
        """Git clone status (and optional wait), via ``StatusCheckService``."""
        return self._status_check.check_git_clone_status(
            scan_code,
            wait=wait,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    def download_git_and_wait(
        self,
        scan_code: str,
        *,
        wait_retry_count: int,
        wait_retry_interval: int = 3,
    ) -> StatusResult:
        """
        Trigger Git download then wait until clone reaches a terminal state.
        """
        self.download_content_from_git(scan_code)
        return self.check_git_clone_status(
            scan_code,
            wait=True,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )
