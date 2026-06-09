# workbench_agent/handlers/scan.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import ProcessError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.pre_flight_checks import scan_pre_flight_check
from workbench_agent.utilities.resolve_project_scan import (
    find_or_create_project_and_scan,
)
from workbench_agent.utilities.scan_workflows import (
    execute_scan_workflow,
)
from workbench_agent.utilities.upload_data_prep import prepare_scan_target

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_scan(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan' command.

    This handler orchestrates the most common use case:
    upload a codebase to Workbench and analyze it.

    Workflow:
        1. Resolve/create project and scan
        2. Ensure scan is idle (wait for ongoing operations)
        3. Clear existing scan content
        4. Upload code archive
        5. Extract archives (if applicable)
        6. Run scans, wait, and display results

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to code archive/directory to scan
            - project_name: Name of the project
            - scan_name: Name of the scan
            - Various scan configuration options

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If inputs are invalid
        FileSystemError: If path doesn't exist
        ProjectNotFoundError: If project resolution fails
        ScanNotFoundError: If scan resolution fails
        ProcessError: If scan operations fail
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    durations: dict = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "extraction_duration": 0.0,
    }

    # Path existence is validated at CLI layer (cli/validators.py)

    # ===== STEP 1: Resolve project and scan =====
    print("\n--- Project and Scan Checks ---")
    print("Checking target Project and Scan...")
    _, scan_code, scan_is_new = find_or_create_project_and_scan(
        client,
        params,
    )

    # ===== STEP 2: Pre-Flight Checks =====
    print("\n--- Pre-Flight Checks ---")
    scan_pre_flight_check(client, scan_code, scan_is_new, params)

    # ===== STEP 3: Clear Existing Content =====
    if not scan_is_new and not params.incremental_upload:
        print("\nClearing existing scan content...")
        try:
            client.scan_content.remove_uploaded_content(scan_code, "")
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning(f"Failed to clear existing scan content: {e}")
            print(f"Warning: Could not clear existing scan content: {e}")
            print("Continuing with upload...")
    elif params.incremental_upload and not scan_is_new:
        print("Incremental Upload - existing content will be kept.")
    else:
        logger.debug("Skipping content clear - new scan is empty")

    # ===== STEP 4: Upload code =====
    print("\n--- Preparing Scan Target ---")
    with prepare_scan_target(params.path) as upload_path:
        print("\nUploading Code to Workbench...")
        client.scan_content.upload_scan_target(scan_code, upload_path)

    # ===== STEP 5: Extract archives =====
    print("\nExtracting Uploaded Archive...")
    extraction_triggered = client.scan_content.extract_archives(
        scan_code=scan_code,
        recursively_extract_archives=(params.recursively_extract_archives),
        jar_file_extraction=params.jar_file_extraction,
    )

    if extraction_triggered:
        extraction_result = client.status_check.check_extract_archives_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=5,
        )
        durations["extraction_duration"] = extraction_result.duration or 0.0

        if extraction_result.status in {"FAILED", "CANCELLED"}:
            error_msg = (
                extraction_result.error_message
                or "Archive extraction failed. " "Scan can not continue."
            )
            raise ProcessError(f"Archive extraction failed for scan " f"'{scan_code}': {error_msg}")
    else:
        print("No archives to extract. Continuing with scan...")

    # ===== STEP 6: Run Scans =====
    print("\n--- Running Scans ---")
    return execute_scan_workflow(client, params, scan_code, durations)
