# workbench_agent/handlers/show_results.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
)
from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.post_scan_summary import fetch_display_save_results

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_show_results(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the 'show-results' command.

    Fetches and displays results for an existing scan without running a new
    scan. This is useful for viewing results from previously completed scans
    or monitoring ongoing scans.

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - project_name: Name of the project containing the scan
            - scan_name: Name of the scan to display results for
            - show_*: Flags controlling which results to display
            - scan_number_of_tries: Max attempts to wait for scan completion
            - scan_wait_time: Interval between completion checks

    Returns:
        bool: True if the operation was successful

    Raises:
        ValidationError: If no --show-* flags are provided
        ProjectNotFoundError: If project doesn't exist
        ScanNotFoundError: If scan doesn't exist

    Note:
        This is a read-only operation that doesn't create or modify
        projects or scans. It will wait for in-progress scans to complete
        before displaying results.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Note: --show-* flag validation is done at CLI layer (cli/validators.py)
    # We trust that at least one flag is provided

    # Resolve project and scan (find only - don't create)
    print("\nResolving scan for results display...")
    logger.info(f"Looking for scan '{params.scan_name}' in project " f"'{params.project_name}'")

    # Use explicit resolver API (read-only)
    project_code = client.resolver.find_project(params.project_name)
    logger.debug(f"Found project: {project_code}")

    scan_code, scan_id = client.resolver.find_scan(params.scan_name, params.project_name)
    logger.debug(f"Found scan: {scan_code} (ID: {scan_id})")

    # Ensure scan processes are idle before fetching results
    print("\nEnsuring scans finished before showing results...")
    try:
        # Check if KB scan is complete
        logger.debug("Checking KB scan completion status...")
        try:
            client.waiting.wait_for_scan(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except UnsupportedStatusCheck as e:
            # Older Workbench versions might not support status checking
            logger.warning(f"Status check not supported: {e}. Continuing...")

        # Check if dependency analysis is complete (if applicable)
        logger.debug("Checking dependency analysis completion status...")
        try:
            client.waiting.wait_for_da(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except UnsupportedStatusCheck as e:
            # Dependency analysis might not exist or be supported
            logger.debug(f"Dependency analysis check not available: {e}")

    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        logger.warning(
            f"Could not verify scan completion for '{scan_code}': {e}. " f"Proceeding anyway."
        )
        print("\nWarning: Could not verify scan completion status. " "Results may be incomplete.")

    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    fetch_display_save_results(client, params, scan_code)

    logger.info("Results displayed successfully")
    return True
