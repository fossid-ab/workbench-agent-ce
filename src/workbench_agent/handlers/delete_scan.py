"""Handler for the delete-scan command."""

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.section import print_section

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")

# Delete jobs usually finish quickly; poll often (not --scan-wait-time).
DELETE_SCAN_POLL_INTERVAL_SEC = 2

PERMISSION_DENIED_MESSAGE = (
    "Your user does not have permission to delete this scan. "
    "Verify your permissions or try again with a different user."
)


@handler_error_wrapper
def handle_delete_scan(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Delete an existing scan after resolving project/scan names and permissions.

    Args:
        client: Workbench API client
        params: Parsed CLI including project_name, scan_name,
            delete_identifications, scan_number_of_tries

    Returns:
        True on successful deletion job completion
    """
    print_section(f"Running {params.command.upper()} Command")

    print_section("Resolving scan")
    logger.info(
        "Looking up scan '%s' in project '%s'",
        params.scan_name,
        params.project_name,
    )
    _, scan = client.resolver.find_project_and_scan(
        params.project_name,
        params.scan_name,
    )
    scan_code = scan.code
    logger.debug("Resolved scan_code=%s", scan_code)

    if not client.user_permissions.can_delete_scan(scan_code):
        raise WorkbenchAgentError(PERMISSION_DENIED_MESSAGE)

    print_section("Deleting scan")
    result = client.scan_deletion.delete_scan(
        scan_code,
        delete_identifications=params.delete_identifications,
        wait_retry_count=params.scan_number_of_tries,
        wait_retry_interval=DELETE_SCAN_POLL_INTERVAL_SEC,
    )

    if not result.success:
        msg = result.error_message or result.status or "unknown error"
        raise WorkbenchAgentError(
            f"Scan deletion did not complete successfully: {msg}",
            details={"status": result.status, "raw_data": result.raw_data},
        )

    print(f"\nScan '{params.scan_name}' (code: {scan_code}) was deleted " "successfully.")
    if result.duration is not None:
        print(f"Duration (server-reported): {result.duration:.1f}s")
    return True
