"""
Custom exceptions for Workbench Agent.

This module defines the exception hierarchy for the Workbench Agent CLI.
Shared SDK exceptions are defined in ``workbench_agent.api.exceptions``
and re-exported here for backward compatibility.
"""

from typing import Optional

from workbench_agent.api.exceptions import FileSystemError, ValidationError


class WorkbenchAgentError(Exception):
    """Base class for all Workbench Agent CLI application errors.

    All custom exceptions in this module should inherit from this class.
    This allows for easy catching of any application-specific error.

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


class ConfigurationError(WorkbenchAgentError):
    """Raised for invalid configuration or command-line arguments.

    This includes missing required parameters, invalid parameter values,
    and configuration file errors.

    Example:
        try:
            validate_config(config)
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e.message}")
    """


__all__ = [
    "WorkbenchAgentError",
    "ValidationError",
    "ConfigurationError",
    "FileSystemError",
]
