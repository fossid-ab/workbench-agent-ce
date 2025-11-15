"""
Workbench API client package for interacting with the FossID Workbench API.

This package can be used as a standalone SDK for interacting with the Workbench API.
"""

from workbench_agent.api.workbench_client import WorkbenchClient
from workbench_agent.api.exceptions import (
    WorkbenchApiError,
    ApiError,
    NetworkError,
    AuthenticationError,
    NotFoundError,
    ScanNotFoundError,
    ProjectNotFoundError,
    ResourceExistsError,
    ScanExistsError,
    ProjectExistsError,
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
    CompatibilityError,
)

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
    "ResourceExistsError",
    "ScanExistsError",
    "ProjectExistsError",
    "ProcessError",
    "ProcessTimeoutError",
    "UnsupportedStatusCheck",
    "CompatibilityError",
]
