# workbench_agent/handlers/scan_git.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.pre_flight_checks import (
    scan_git_pre_flight_check,
)
from workbench_agent.utilities.resolve_project_scan import (
    find_or_create_project_and_scan,
)
from workbench_agent.utilities.scan_workflows import (
    execute_scan_workflow,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_scan_git(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-git' command.

    This handler performs a complete Git-based scanning workflow:
    1. Resolves/creates project and scan
    2. Ensures scan is idle
    3. Clones Git repository
    4. Removes .git directory
    5. Runs scans, waiting if needed

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - project_name: Name of the project
            - scan_name: Name of the scan
            - git_url: Git repository URL
            - git_branch/git_tag/git_commit: Git reference
            - Various scan configuration options

    Returns:
        bool: True if the operation completed successfully

    Raises:
        WorkbenchAgentError: If Git clone fails
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    durations: dict = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "git_clone": 0.0,
    }

    # ===== STEP 1: Resolve project and scan =====
    print("\n--- Project and Scan Checks ---")
    print("Checking target Project and Scan...")
    _, scan_code, scan_is_new = find_or_create_project_and_scan(
        client,
        params,
    )

    # ===== STEP 2: Pre-Flight Checks =====
    print("\n--- Pre-Flight Checks ---")
    scan_git_pre_flight_check(client, scan_code, scan_is_new, params)

    # ===== STEP 3: Git Clone =====
    print("\n--- Cloning the Target Repo ---")
    print("Starting Git Clone...")

    try:
        git_clone_result = client.scan_content.download_git_and_wait(
            scan_code,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=3,
        )
        durations["git_clone"] = git_clone_result.duration or 0.0
        print("Git Clone Completed.")
    except Exception as e:
        logger.error(
            f"Failed to clone Git repository for " f"'{scan_code}': {e}",
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Failed to clone Git repository: {e}",
            details={"error": str(e)},
        ) from e

    # ===== STEP 4: Remove .git Directory =====
    print("\nRemoving .git directory to optimize scan...")
    try:
        if client.scan_content.remove_uploaded_content(scan_code, ".git/"):
            print("Successfully removed .git directory.")
    except Exception as e:
        logger.warning(f"Error removing .git directory: {e}. " f"Continuing with scan...")
        print(f"Warning: Error removing .git directory: {e}. " f"Continuing with scan...")

    # ===== STEP 5: Run Scans =====
    print("\n--- Scan Operations ---")
    return execute_scan_workflow(client, params, scan_code, durations)
