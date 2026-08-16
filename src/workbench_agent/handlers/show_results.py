# workbench_agent/handlers/show_results.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.section import print_section
from workbench_agent.utilities.pre_flight_checks import (
    show_results_pre_flight_check,
)
from workbench_agent.utilities.result_utilities import (
    fetch_display_save_results,
)

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
    print_section(f"Running {params.command.upper()} Command")

    # Note: --show-* flag validation is done at CLI layer (cli/validators.py)
    # We trust that at least one flag is provided

    # Resolve project and scan (find only - don't create)
    print("Resolving scan for results display...")
    logger.info(f"Looking for scan '{params.scan_name}' in project " f"'{params.project_name}'")

    # Use explicit resolver API (read-only)
    project_code, scan = client.resolver.find_project_and_scan(
        params.project_name,
        params.scan_name,
    )
    scan_code = scan.code
    scan_id = scan.id
    logger.debug(f"Found project: {project_code}, scan: {scan_code} (ID: {scan_id})")

    # Ensure scan processes are idle before fetching results
    show_results_pre_flight_check(client, scan_code, params)

    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    fetch_display_save_results(client, params, scan_code)

    logger.info("Results displayed successfully")
    return True
