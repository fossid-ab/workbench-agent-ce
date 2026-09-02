"""
Custom exceptions for Workbench API SDK.

This module defines the exception hierarchy for the Workbench API client SDK.
All SDK exceptions inherit from WorkbenchApiError to catch SDK-specific errors.

When distributed as an independent SDK, consumers can catch these exceptions
to handle API-related errors gracefully.
"""

from typing import Optional


class WorkbenchApiError(Exception):
    """Base class for all Workbench API SDK errors.

    All custom exceptions in this module should inherit from this class.

    Attributes:
        message: A human-readable error message
        code: An optional error code for programmatic handling
        details: Optional additional error details
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)


class ApiError(WorkbenchApiError):
    """Represents an error returned by the Workbench API.

    This is raised when the API returns an error or when there's an
    issue that isn't network-related.

    Example:
        try:
            response = api.get_scan(scan_id)
        except ApiError as e:
            logger.error(f"API error: {e.message} (code: {e.code})")
    """


class UnsupportedStatusCheck(ApiError):
    """Raised when a status check operation is not supported by Workbench.

    This exception is raised when the connected Workbench version does not
    support checking the status of an operation.

    Examples:
        >>> raise UnsupportedStatusCheck("EXTRACT_ARCHIVES not supported",
        ...  details={"operation": "EXTRACT_ARCHIVES", "scan_code": "scan123"})
    """


class NetworkError(WorkbenchApiError):
    """Represents a network-level error during API communication.

    This includes connection errors, timeouts, and other network issues.

    Example:
        try:
            response = api.upload_file(file_path)
        except NetworkError as e:
            logger.error(f"Network error: {e.message}")
    """


class AuthenticationError(ApiError):
    """Raised when authentication with the Workbench API fails.

    This includes invalid credentials, expired tokens, and other
    authentication-related errors.

    Example:
        try:
            api.authenticate()
        except AuthenticationError as e:
            logger.error(f"Authentication failed: {e.message}")
    """


class NotFoundError(ApiError):
    """Base class for errors when an entity is not found via the API.

    This is raised when attempting to access a resource that doesn't exist.
    """


class ScanNotFoundError(NotFoundError):
    """Raised when a scan is not found.

    Example:
        try:
            scan = api.get_scan("non_existent")
        except ScanNotFoundError as e:
            logger.error(f"Scan not found: {e.message}")
    """


class ProjectNotFoundError(NotFoundError):
    """Raised when a project is not found.

    Example:
        try:
            project = api.get_project("non_existent")
        except ProjectNotFoundError as e:
            logger.error(f"Project not found: {e.message}")
    """


class ScanWrongProjectError(WorkbenchApiError):
    """Raised when a scan code exists but not under the requested project."""

    def __init__(
        self,
        *,
        scan_code: str,
        requested_project_code: str,
        actual_project_code: Optional[str] = None,
    ):
        self.scan_code = scan_code
        self.requested_project_code = requested_project_code
        self.actual_project_code = actual_project_code
        if actual_project_code and actual_project_code != requested_project_code:
            message = (
                f"Scan code '{scan_code}' already exists in project "
                f"'{actual_project_code}', not in '{requested_project_code}'."
            )
        else:
            message = (
                f"Scan code '{scan_code}' already exists in Workbench but does "
                f"not belong to project '{requested_project_code}'."
            )
        super().__init__(message, code="scan_wrong_project")


class ProcessError(WorkbenchApiError):
    """Raised for failures during background Workbench processes.

    This includes errors during scanning, report generation, and other
    long-running operations tracked via the API.

    Example:
        try:
            api.wait_for_scan(
                "SCAN", scan_code, max_tries, wait_time
            )
        except ProcessError as e:
            logger.error(f"Process failed: {e.message}")
    """


class ProcessTimeoutError(ProcessError):
    """Raised when waiting for a process times out.

    Example:
        try:
            api.wait_for_scan(
                "SCAN", scan_code, max_tries, wait_time
            )
        except ProcessTimeoutError as e:
            logger.error(f"Scan timed out: {e.message}")
    """


class CompatibilityError(WorkbenchApiError):
    """Raised when there's a compatibility issue with the Workbench API.

    This includes:
    - SDK version incompatibility with Workbench server version
    - Scan incompatibility (e.g., reusing a Git scan for code upload)
    - Operation incompatibility with current state

    Examples:
        >>> # SDK version compatibility
        >>> raise CompatibilityError(
        ...     "Workbench version 24.2.0 is not compatible with this SDK. "
        ...     "SDK requires Workbench 24.3.0 or later."
        ... )
        >>>
        >>> # Scan reusability compatibility
        >>> raise CompatibilityError(
        ...     "Existing scan 'scan123' is configured for Git and cannot be "
        ...     "reused for code upload operations."
        ... )
    """


class ValidationError(WorkbenchApiError):
    """Raised when SDK input validation fails.

    Includes invalid parameters, unsupported option combinations, and
    local validation before API calls.
    """


class FileSystemError(WorkbenchApiError):
    """Raised for local file or directory errors during SDK operations.

    Includes missing paths, permission failures, and other filesystem issues
    encountered while preparing uploads or report output.
    """
