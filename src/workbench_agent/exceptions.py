"""
Custom exceptions for Workbench Agent CLI application.

This module defines the exception hierarchy for the Workbench Agent CLI application.
All application-level exceptions inherit from WorkbenchAgentError.

Note: API/SDK-level exceptions are defined in workbench_agent.api.exceptions.
"""

from typing import Optional


class WorkbenchAgentError(Exception):
    """Base class for all Workbench Agent CLI application errors.

    All custom exceptions in this module should inherit from this class.
    This allows for easy catching of any application-specific error.

    Attributes:
        message: A human-readable error message
        code: An optional error code for programmatic handling
        details: Optional additional error details
    """

    def __init__(self, message: str, code: Optional[str] = None, details: Optional[dict] = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(WorkbenchAgentError):
    """Raised when input validation fails.

    This includes invalid file formats, unsupported options, and other
    validation-related errors.

    Example:
        try:
            validate_input_file(file_path)
        except ValidationError as e:
            logger.error(f"Validation error: {e.message}")
    """

    pass


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

    pass


class FileSystemError(WorkbenchAgentError):
    """Raised for errors related to local file/directory operations.

    This includes file not found, permission denied, and other filesystem-related
    errors.

    Example:
        try:
            process_directory(path)
        except FileSystemError as e:
            logger.error(f"File system error: {e.message}")
    """

    pass
