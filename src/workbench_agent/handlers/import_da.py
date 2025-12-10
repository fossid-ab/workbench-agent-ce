# workbench_agent/handlers/import_da.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import (
    ProcessError,
    ProcessTimeoutError,
)
from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.post_import_summary import print_import_summary

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_import_da(
    client: "WorkbenchClient", params: argparse.Namespace
) -> bool:
    """
    Handler for the 'import-da' command.

    Imports dependency analysis results from a file into a scan. This
    allows pre-analyzed dependency data to be imported without running
    a full scan.

    Workflow:
    1. Validates file path
    2. Resolves/creates project and scan
    3. Ensures scan is idle
    4. Uploads dependency analysis file
    5. Triggers import process
    6. Waits for completion
    7. Displays results

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to dependency analysis file
            - project_name: Name of the project
            - scan_name: Name of the scan

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If parameters are invalid
        FileSystemError: If file doesn't exist
        WorkbenchAgentError: If import fails
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Initialize timing dictionary
    durations = {"dependency_analysis": 0.0}

    # Note: Path existence, file type, and filename validation
    # are handled at CLI layer (cli/validators.py)

    # Resolve project and scan (find or create)
    print("\n--- Project and Scan Checks ---")
    print("Checking target Project and Scan...")
    _, scan_code, scan_is_new = client.resolver.resolve_project_and_scan(
        project_name=params.project_name,
        scan_name=params.scan_name,
        params=params,
    )

    # Ensure scan is idle before starting dependency analysis import
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if not scan_is_new:
        print("\nEnsuring Scan is idle before starting import...")
        try:
            client.waiting.wait_for_da(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except Exception as e:
            logger.debug(f"Dependency analysis check skipped: {e}")
    else:
        logger.debug(
            "Skipping idle checks - new scan is guaranteed to be idle"
        )

    # Upload dependency analysis file
    print("\n--- Uploading Dependency Analysis File ---")
    try:
        client.upload_service.upload_da_results(
            scan_code=scan_code, path=params.path
        )
        print("Dependency analysis results uploaded successfully!")
    except Exception as e:
        logger.error(
            f"Failed to upload dependency analysis file for "
            f"'{scan_code}': {e}",
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Failed to upload dependency analysis file: {e}",
            details={"error": str(e)},
        ) from e

    # Start dependency analysis import
    print("\n--- Starting Dependency Analysis Import ---")

    try:
        client.scan_operations.start_da_import(scan_code=scan_code)
        print("Dependency analysis import initiated successfully.")
    except Exception as e:
        logger.error(
            f"Failed to start dependency analysis import for "
            f"'{scan_code}': {e}",
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Failed to start dependency analysis import: {e}",
            details={"error": str(e)},
        ) from e

    # Wait for dependency analysis to complete
    da_completed = False
    try:
        print("\nWaiting for Dependency Analysis import to complete...")
        # Use optimized 3-second wait interval for import-only mode
        dependency_analysis_status = client.waiting.wait_for_da(
            scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=3,  # Faster for import-only mode
        )

        # Store the DA import duration
        durations["dependency_analysis"] = (
            dependency_analysis_status.duration or 0.0
        )
        da_completed = True

        print("Dependency Analysis import completed successfully.")

    except ProcessTimeoutError:
        logger.error(
            f"Error during dependency analysis import for "
            f"'{scan_code}': timeout",
            exc_info=True,
        )
        raise
    except ProcessError:
        logger.error(
            f"Error during dependency analysis import for "
            f"'{scan_code}': process error",
            exc_info=True,
        )
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error during dependency analysis import for "
            f"'{scan_code}': {e}",
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Error during dependency analysis import: {e}",
            details={"error": str(e)},
        ) from e

    # Show import summary (includes Workbench link)
    if da_completed:
        print_import_summary(
            client,
            params,
            scan_code,
            da_completed,
            durations,
            show_summary=getattr(params, "show_summary", False),
        )
    else:
        # Import didn't complete, just show link
        print_import_summary(
            client,
            params,
            scan_code,
            False,
            durations,
            show_summary=False,
        )

    return da_completed
