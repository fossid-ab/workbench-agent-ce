"""
UploadService - Handles upload business logic and orchestration.

This service provides:
- Upload scan targets (files/directories with zip creation)
- Upload dependency analysis results
- Upload SBOM files

The service handles business logic and payload construction:
- Service layer: File preparation, header building, archive creation
- Client layer: Raw HTTP API calls

Example:
    >>> upload_service = UploadService(uploads_client)
    >>> upload_service.upload_scan_target(scan_code, "/path/to/source")
    >>> upload_service.upload_da_results(scan_code, "results.json")
"""

import base64
import logging
import os
import shutil

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.exceptions import FileSystemError, WorkbenchAgentError
from workbench_agent.utilities.prep_upload_archive import UploadArchivePrep

logger = logging.getLogger("workbench-agent")


class UploadService:
    """
    Service for upload operations.

    This service handles business logic for:
    - Preparing files for upload (creating zip archives for directories)
    - Building appropriate headers based on upload type
    - Deciding upload strategy (chunked vs standard) based on file size
    - Managing temporary files and cleanup

    Architecture:
    - Service layer: File preparation, header building, upload strategy decision
    - Client layer: Raw HTTP API calls (standard and chunked implementations)

    Example:
        >>> upload_service = UploadService(uploads_client)
        >>>
        >>> # Upload a scan target (file or directory)
        >>> upload_service.upload_scan_target(
        ...     scan_code="scan_code",
        ...     path="/path/to/source"
        ... )
        >>>
        >>> # Upload dependency analysis results
        >>> upload_service.upload_da_results(
        ...     scan_code="scan_code",
        ...     path="/path/to/da_results.json"
        ... )
        >>>
        >>> # Upload SBOM file
        >>> upload_service.upload_sbom_file(
        ...     scan_code="scan_code",
        ...     path="/path/to/sbom.json"
        ... )
    """

    # Upload strategy constants (business logic)
    # Files larger than this threshold will use chunked upload
    # This can be configured by Workbench admins via PHP/server settings
    CHUNKED_UPLOAD_THRESHOLD = 16 * 1024 * 1024  # 16MB

    def __init__(self, uploads_client):
        """
        Initialize UploadService.

        Args:
            uploads_client: UploadsClient instance for raw API calls
        """
        self._uploads = uploads_client
        logger.debug("UploadService initialized")

    # ===== PUBLIC API =====

    def upload_scan_target(self, scan_code: str, path: str) -> None:
        """
        Upload a file or directory (as zip) to a scan.

        This method handles:
        - Validating path existence
        - Creating zip archive for directories
        - Building appropriate headers
        - Delegating to UploadsClient for HTTP operations
        - Cleaning up temporary files

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the file or directory to upload

        Raises:
            FileSystemError: If path doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues
            WorkbenchAgentError: If an unexpected error occurs

        Example:
            >>> upload_service.upload_scan_target("SCAN123", "/path/to/source")
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Path does not exist: {path}")

        archive_path = None
        temp_dir = None

        try:
            upload_path = path
            if os.path.isdir(path):
                print(
                    "The path provided is a directory. Compressing for upload..."
                )
                archive_path = UploadArchivePrep.create_zip_archive(path)
                upload_path = archive_path
                temp_dir = os.path.dirname(archive_path)
                print("\nArchive prepared! Starting upload...")

            upload_basename = os.path.basename(upload_path)
            name_b64 = base64.b64encode(upload_basename.encode()).decode(
                "utf-8"
            )
            scan_code_b64 = base64.b64encode(scan_code.encode()).decode(
                "utf-8"
            )

            headers = {
                "FOSSID-SCAN-CODE": scan_code_b64,
                "FOSSID-FILE-NAME": name_b64,
                "Accept": "*/*",
            }

            # Decide upload strategy based on file size (business logic)
            file_size = os.path.getsize(upload_path)
            if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
                logger.debug(
                    f"File size ({file_size / (1024 * 1024):.2f} MB) exceeds "
                    f"threshold ({self.CHUNKED_UPLOAD_THRESHOLD / (1024 * 1024):.0f} MB), "
                    f"using chunked upload."
                )
                self._uploads.upload_file_chunked(upload_path, headers)
            else:
                logger.debug("Using standard (non-chunked) upload.")
                self._uploads.upload_file_standard(upload_path, headers)

        except (ApiError, NetworkError):
            # Re-raise known exceptions
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            raise WorkbenchAgentError(
                f"An unexpected error occurred during the upload process: {e}"
            ) from e

        finally:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def upload_da_results(self, scan_code: str, path: str) -> None:
        """
        Upload a dependency analysis result file to a scan.

        This method handles:
        - Validating file existence
        - Building appropriate headers (including FOSSID-UPLOAD-TYPE)
        - Delegating to UploadsClient for HTTP operations

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the dependency analysis results file

        Raises:
            FileSystemError: If file doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues

        Example:
            >>> upload_service.upload_da_results(
            ...     "SCAN123",
            ...     "/path/to/da_results.json"
            ... )
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(
                f"Dependency analysis results file does not exist: {path}"
            )

        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode(
            "utf-8"
        )
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode(
            "utf-8"
        )

        headers = {
            "FOSSID-SCAN-CODE": scan_code_b64,
            "FOSSID-FILE-NAME": name_b64,
            "FOSSID-UPLOAD-TYPE": "dependency_analysis",
            "Accept": "*/*",
        }

        # Decide upload strategy based on file size (business logic)
        file_size = os.path.getsize(path)
        if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
            logger.debug(
                f"File size ({file_size / (1024 * 1024):.2f} MB) exceeds "
                f"threshold ({self.CHUNKED_UPLOAD_THRESHOLD / (1024 * 1024):.0f} MB), "
                f"using chunked upload."
            )
            self._uploads.upload_file_chunked(path, headers)
        else:
            logger.debug("Using standard (non-chunked) upload.")
            self._uploads.upload_file_standard(path, headers)

    def upload_sbom_file(self, scan_code: str, path: str) -> None:
        """
        Upload an SBOM file to a scan.

        This method handles:
        - Validating file existence
        - Building appropriate headers
        - Delegating to UploadsClient for HTTP operations

        Args:
            scan_code: Code of the scan to upload to
            path: Path to the SBOM file to upload

        Raises:
            FileSystemError: If file doesn't exist
            ApiError: If upload fails
            NetworkError: If there are network issues

        Example:
            >>> upload_service.upload_sbom_file("SCAN123", "/path/to/sbom.json")
        """
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileSystemError(f"SBOM file does not exist: {path}")

        upload_basename = os.path.basename(path)
        name_b64 = base64.b64encode(upload_basename.encode()).decode(
            "utf-8"
        )
        scan_code_b64 = base64.b64encode(scan_code.encode()).decode(
            "utf-8"
        )

        headers = {
            "FOSSID-SCAN-CODE": scan_code_b64,
            "FOSSID-FILE-NAME": name_b64,
            "Accept": "*/*",
        }

        # Decide upload strategy based on file size (business logic)
        file_size = os.path.getsize(path)
        if file_size > self.CHUNKED_UPLOAD_THRESHOLD:
            logger.debug(
                f"File size ({file_size / (1024 * 1024):.2f} MB) exceeds "
                f"threshold ({self.CHUNKED_UPLOAD_THRESHOLD / (1024 * 1024):.0f} MB), "
                f"using chunked upload."
            )
            self._uploads.upload_file_chunked(path, headers)
        else:
            logger.debug("Using standard (non-chunked) upload.")
            self._uploads.upload_file_standard(path, headers)
