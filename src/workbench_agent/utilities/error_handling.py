"""
Error handling utilities for the Workbench Agent.

This module contains functions for standardized error handling and formatting
across all CLI handlers.
"""

import argparse
import functools
import logging
from typing import Callable

from workbench_agent.api.exceptions import (
    ApiError,
    AuthenticationError,
    CompatibilityError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
)
from workbench_agent.exceptions import (
    ConfigurationError,
    FileSystemError,
    ValidationError,
    WorkbenchAgentError,
)

logger = logging.getLogger("workbench-agent")


def format_and_print_error(
    error: Exception, context: str, params: argparse.Namespace
):
    """
    Formats and prints a standardized error message for CLI users.

    This centralized function handles consistent error formatting across
    all error scenarios, providing rich, helpful output to users.

    Args:
        error: The exception that occurred
        context: Context where error occurred ("cli", "init", or command name)
        params: Command line parameters
    """
    logger.debug(
        f"Formatting error from context '{context}': {type(error).__name__}"
    )
    command = getattr(params, "command", "unknown")

    # Get error details if available (for our custom errors)
    error_message = getattr(error, "message", str(error))
    error_code = getattr(error, "code", None)
    error_details = getattr(error, "details", {})

    # Determine if this is a read-only operation
    read_only_commands = {"show-results", "evaluate-gates", "download-reports"}
    is_read_only = command in read_only_commands

    # Add context-specific help based on error type
    # Note: Check AuthenticationError before ApiError since AuthenticationError inherits from ApiError
    if isinstance(error, AuthenticationError):
        print("\n❌ Authentication failed")
        print(f"   {error_message}")
        print("\n💡 Please check:")
        print("   • Your API credentials are correct")
        print("   • You have the necessary permissions")

    elif isinstance(error, ProjectNotFoundError):
        if is_read_only:
            print("\n❌ Cannot continue: The requested project does not exist")
            print(
                f"   Project '{getattr(params, 'project_name', 'unknown')}' was not found in your Workbench instance."
            )
            print("\n💡 Please check:")
            print("   • The project name is spelled correctly")
            print("   • The project exists in your Workbench instance")
            print("   • You have access to the project")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(
                f"  → Project '{getattr(params, 'project_name', 'unknown')}' was not found"
            )

    elif isinstance(error, ScanNotFoundError):
        if is_read_only:
            print("\n❌ Cannot continue: The requested scan does not exist")
            scan_name = getattr(params, "scan_name", "unknown")
            project_name = getattr(params, "project_name", None)

            if project_name:
                print(
                    f"   Scan '{scan_name}' was not found in project '{project_name}'."
                )
            else:
                print(
                    f"   Scan '{scan_name}' was not found in your Workbench instance."
                )

            print("\n💡 Please check:")
            print("   • The scan name is spelled correctly")
            if project_name:
                print(f"   • The scan exists in the '{project_name}' project")
            else:
                print("   • The scan exists in your Workbench instance")
                print(
                    "   • Consider specifying --project-name if the scan is in a specific project"
                )
            print("   • You have access to the scan")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(
                f"  → Scan '{getattr(params, 'scan_name', 'unknown')}' was not found"
            )
            if hasattr(params, "project_name"):
                print(
                    f"  → Check the scan name or verify it exists in project '{params.project_name}'"
                )
            else:
                print(
                    "  → Check the scan name or specify --project-name if it exists in a specific project"
                )

    elif isinstance(error, NetworkError):
        print("\n❌ Network connectivity issue")
        print(f"   {error_message}")
        print("\n💡 Please check:")
        print("   • The Workbench server is accessible")
        print(
            f"   • The API URL is correct: {getattr(params, 'api_url', '<not specified>')}"
        )

    elif isinstance(error, ApiError):
        # Check for credential errors first
        if "user_not_found_or_api_key_is_not_correct" in error_message:
            print("\n❌ Invalid credentials")
            print("   The username or API token provided is incorrect.")
            print("\n💡 Please check:")
            print(
                f"   • Your username: {getattr(params, 'api_user', '<not specified>')}"
            )
            print("   • Your API token is correct and not expired")
            print("   • Your account has access to the Workbench instance")
            print(
                f"   • The API URL is correct: {getattr(params, 'api_url', '<not specified>')}"
            )
            return  # Exit early to avoid showing generic API error details

        print("\n❌ Workbench API error")
        print(f"   {error_message}")

        if error_code:
            print(f"   Error code: {error_code}")

            # Special handling for Git repository access errors
            if error_code == "git_repository_access_error":
                print("\n💡 Git repository access issue:")
                print(
                    "   • Check that the Git URL is correct and accessible from the Workbench server"
                )
                print(
                    "   • Ensure any required authentication is properly configured"
                )
            else:
                print(
                    "\n💡 The Workbench API reported an issue with your request"
                )

    elif isinstance(error, ProcessTimeoutError):
        print("\n❌ Operation timed out")
        print(f"   {error_message}")
        print("\n💡 Consider increasing the timeout values:")
        print(
            f"   • --scan-number-of-tries (current: {getattr(params, 'scan_number_of_tries', 'default')})"
        )
        print(
            f"   • --scan-wait-time (current: {getattr(params, 'scan_wait_time', 'default')})"
        )

    elif isinstance(error, ProcessError):
        print("\n❌ Workbench process error")
        print(f"   {error_message}")
        print("\n💡 A Workbench process failed to complete successfully")

    elif isinstance(error, FileSystemError):
        print("\n❌ File system error")
        print(f"   {error_message}")
        print("\n💡 Please check:")
        print("   • File permissions are correct")
        print("   • All specified paths exist")
        if hasattr(params, "path"):
            print(f"   • Path specified: {params.path}")

    elif isinstance(error, ValidationError):
        print("\n❌ Invalid input or configuration")
        print(f"   {error_message}")
        print("\n💡 Please check your command-line arguments and input files")

    elif isinstance(error, ConfigurationError):
        print("\n❌ Configuration error")
        print(f"   {error_message}")
        print("\n💡 Please check your command-line arguments and configuration")

    elif isinstance(error, CompatibilityError):
        print("\n❌ Compatibility issue")
        print(f"   {error_message}")
        print(
            "\n💡 The requested operation is not compatible with the scan's current state"
        )

    else:
        # Generic error formatting for unexpected errors
        print(f"\n❌ Error executing '{command}' command: {error_message}")

    # Show error code if available (and not already shown)
    if error_code and not isinstance(error, (ApiError, ProcessTimeoutError)):
        print(f"\nError code: {error_code}")

    # Show details in verbose mode
    if getattr(params, "verbose", False) and error_details:
        print("\nDetailed error information:")
        for key, value in error_details.items():
            print(f"  • {key}: {value}")

    # Add help text only for non-read-only operations or when in verbose mode
    if not is_read_only or getattr(params, "verbose", False):
        print("\nFor more details, run with --log DEBUG for verbose output")


def handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    A decorator that wraps handler functions with standardized error handling.

    This wrapper ensures consistent error handling across all handlers by:
    - Logging all exceptions with full context
    - Wrapping unexpected exceptions in WorkbenchAgentError
    - Re-raising exceptions for main.py to format and handle

    Error Handling Flow:
    --------------------
    1. Handler raises an exception
    2. Decorator catches and logs the exception
    3. Decorator re-raises the exception (or wrapped version)
    4. main.py catches, formats with format_and_print_error(), and determines exit code:
       - Exit 2: ValidationError, ConfigurationError, AuthenticationError (user-fixable)
       - Exit 1: All other errors (runtime issues)

    This pattern ensures:
    - All errors are formatted consistently in one place (main.py)
    - Handlers don't need try/except blocks for error handling
    - Clear separation: handlers handle logic, main.py handles presentation
    - Exit codes are determined centrally

    Args:
        handler_func: The handler function to wrap

    Returns:
        The wrapped handler function with error handling

    Example:
        @handler_error_wrapper
        def handle_scan(workbench, params):
            # Implementation without try/except blocks
            # Any exceptions will be caught, logged, and re-raised
            ...
    """

    @functools.wraps(handler_func)
    def wrapper(workbench, params):
        try:
            # Get the handler name for better logging
            handler_name = handler_func.__name__
            command_name = (
                params.command if hasattr(params, "command") else "unknown"
            )
            logger.debug(
                f"Starting {handler_name} for command '{command_name}'"
            )

            # Call the actual handler function
            return handler_func(workbench, params)

        except (
            AuthenticationError,  # Before ApiError (inherits from ApiError)
            ProjectNotFoundError,  # Before ApiError (inherits from NotFoundError → ApiError)
            ScanNotFoundError,  # Before ApiError (inherits from NotFoundError → ApiError)
            ProcessTimeoutError,  # Before ProcessError (inherits from ProcessError)
            # Now the base classes and independent exceptions
            ValidationError,
            ConfigurationError,
            FileSystemError,
            CompatibilityError,
            ApiError,
            NetworkError,
            ProcessError,
        ) as e:
            # Expected exceptions - log and re-raise for main.py to format
            logger.debug(
                f"Expected error in {handler_func.__name__}: {type(e).__name__}: {getattr(e, 'message', str(e))}"
            )
            raise

        except Exception as e:
            # Unexpected errors - log, wrap, and re-raise
            logger.error(
                f"Unexpected error in {handler_func.__name__}: {e}",
                exc_info=True,
            )

            # Wrap in WorkbenchAgentError with context
            raise WorkbenchAgentError(
                f"Unexpected error: {str(e)}",
                details={"error": str(e), "handler": handler_func.__name__},
            ) from e

    return wrapper
