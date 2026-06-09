"""
API client package for interacting with the Workbench API.

This package works as a standalone SDK for interacting with the Workbench API.
"""

from workbench_agent.api.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    FileSystemError,
    NetworkError,
    NotFoundError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    UnsupportedStatusCheck,
    ValidationError,
    WorkbenchApiError,
)
from workbench_agent.api.workbench_client import WorkbenchClient

__all__ = [
    "WorkbenchClient",
    # Exceptions
    "WorkbenchApiError",
    "ApiError",
    "NetworkError",
    "AuthenticationError",
    "NotFoundError",
    "ScanNotFoundError",
    "ProjectNotFoundError",
    "ProcessError",
    "ProcessTimeoutError",
    "UnsupportedStatusCheck",
    "CompatibilityError",
    "ValidationError",
    "FileSystemError",
]
