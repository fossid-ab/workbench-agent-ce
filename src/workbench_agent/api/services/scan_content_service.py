"""
ScanContentService - Handles Workbench File Operations before processing.

Use this service to interact with files in Workbench before scan or import.
Supports file uploads, archive extraction, file deletion, and Git operations.
Scanning operations live in ``ScanOperationsService``.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import TYPE_CHECKING, Dict, Optional

from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.exceptions import FileSystemError

if TYPE_CHECKING:
    from workbench_agent.api.clients.scans import ScansClient
    from workbench_agent.api.services.status_check_service import (
        StatusCheckService,
    )

logger = logging.getLogger("workbench-agent")


class ScanContentService:
    """
    Manage files in a scan's directory on the Workbench server.

    Example:
        >>> content = ScanContentService(scans, uploads, status_check)
        >>> content.upload_scan_target(scan_code, "/path/to/source.zip")
        >>> content.extract_archives(scan_code, True, True)
        >>> content.download_git_and_wait(scan_code, wait_retry_count=360)
    """

    CHUNKED_UPLOAD_THRESHOLD = 7 * 1024 * 1024  # 7MB

    def __init__(
        self,
        scans_client: "ScansClient",
        uploads_client,
        status_check_service: "StatusCheckService",
    ) -> None:
        self._scans = scans_client
        self._uploads = uploads_client
        self._status_check = status_check_service
        logger.debug("ScanContentService initialized")

    # ===== UPLOADS =====

    def _validate_upload_file(self, path: str, label: str) -> None:
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"{label} does not exist: {path}")

    def _upload_headers(
        self, scan_code: str, path: str, *, upload_type: Optional[str] = None
    ) -> Dict[str, str]:
        upload_basename = os.path.basename(path)
        headers = {
            "FOSSID-SCAN-CODE": base64.b64encode(
                scan_code.encode()
            ).decode("utf-8"),
            "FOSSID-FILE-NAME": base64.b64encode(
                upload_basename.encode()
            ).decode("utf-8"),
            "Accept": "*/*",
        }
        if upload_type is not None:
            headers["FOSSID-UPLOAD-TYPE"] = upload_type
        return headers

    def _upload_file(self, path: str, headers: Dict[str, str]) -> None:
        file_size = os.path.getsize(path)
        if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
            logger.debug(
                "File size (%.2f MB) exceeds %.0f MB threshold; "
                "using chunked upload.",
                file_size / (1024 * 1024),
                self.CHUNKED_UPLOAD_THRESHOLD / (1024 * 1024),
            )
            self._uploads.upload_file_chunked(path, headers)
        else:
            logger.debug("Using standard (non-chunked) upload.")
            self._uploads.upload_file_standard(path, headers)

    def upload_scan_target(self, scan_code: str, path: str) -> None:
        """Upload a scan target archive or hash file into the scan directory."""
        self._validate_upload_file(path, "Scan target file")
        self._upload_file(path, self._upload_headers(scan_code, path))

    def upload_da_results(self, scan_code: str, path: str) -> None:
        """Upload a dependency analysis results file for later import processing."""
        self._validate_upload_file(
            path, "Dependency analysis results file"
        )
        self._upload_file(
            path,
            self._upload_headers(
                scan_code, path, upload_type="dependency_analysis"
            ),
        )

    def upload_sbom_file(self, scan_code: str, path: str) -> None:
        """Upload an SBOM file for later import processing."""
        self._validate_upload_file(path, "SBOM file")
        self._upload_file(path, self._upload_headers(scan_code, path))

    # ===== SERVER-SIDE ARCHIVE EXTRACTION =====

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
        extract_to_directory: bool = False,
        filename: Optional[str] = None,
    ) -> bool:
        """Trigger server-side archive extraction for uploaded scan content."""
        logger.info("Extracting archives for scan '%s'...", scan_code)

        payload_data = {
            "scan_code": scan_code,
            "recursively_extract_archives": (
                str(recursively_extract_archives).lower()
            ),
            "jar_file_extraction": str(jar_file_extraction).lower(),
            "extract_to_directory": "1" if extract_to_directory else "0",
        }
        if filename is not None:
            payload_data["filename"] = filename

        logger.debug(
            "Built extract archives payload with %d parameters for scan '%s'",
            len(payload_data),
            scan_code,
        )
        return self._scans.extract_archives(payload_data)

    def extract_archives_and_wait(
        self,
        scan_code: str,
        *,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
        extract_to_directory: bool = False,
        filename: Optional[str] = None,
        wait_retry_count: int,
        wait_retry_interval: int = 5,
    ) -> StatusResult:
        """Extract archives then wait until extraction reaches a terminal state."""
        self.extract_archives(
            scan_code,
            recursively_extract_archives,
            jar_file_extraction,
            extract_to_directory=extract_to_directory,
            filename=filename,
        )
        return self._status_check.check_extract_archives_status(
            scan_code,
            wait=True,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    # ===== GIT CLONE OPERATIONS =====

    def download_content_from_git(self, scan_code: str) -> bool:
        """Start Git clone/download for the scan's configured repository."""
        logger.debug("Initiating Git Clone for scan '%s'", scan_code)
        return self._scans.download_content_from_git(scan_code)

    def download_git_and_wait(
        self,
        scan_code: str,
        *,
        wait_retry_count: int,
        wait_retry_interval: int = 3,
    ) -> StatusResult:
        """
        Trigger Git download then wait until clone reaches a terminal state.

        Polls via ``StatusCheckService.check_git_clone_status``.
        """
        self.download_content_from_git(scan_code)
        return self._status_check.check_git_clone_status(
            scan_code,
            wait=True,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    # ===== SERVER-SIDE FILE OPERATIONS =====

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

