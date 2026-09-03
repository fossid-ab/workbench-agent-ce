# workbench_agent/handlers/show_results.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.resolve_project_scan import (
    resolve_project_and_scan,
    target_label,
)
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
    project_label = target_label(params, "project")
    scan_label = target_label(params, "scan")
    logger.info(f"Looking for scan '{scan_label}' in project '{project_label}'")

    targets = resolve_project_and_scan(client, params, allow_create=False)
    project_code = targets.project_code
    scan_code = targets.scan_code
    scan_info = targets.scan_info or client.scans.get_information(scan_code)
    scan_id = int(scan_info.get("id", scan_info.get("scan_id", 0)))
    logger.debug(f"Found project: {project_code}, scan: {scan_code} (ID: {scan_id})")

    # Ensure scan processes are idle before fetching results
    show_results_pre_flight_check(client, scan_code, params)

    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    fetch_display_save_results(client, params, scan_code, project_code=project_code)

    logger.info("Results displayed successfully")
    return True
