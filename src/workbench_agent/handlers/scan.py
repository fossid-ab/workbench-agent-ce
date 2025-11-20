# workbench_agent/handlers/scan.py

import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.post_scan_summary import (
    fetch_display_save_results,
    print_operation_summary,
)
from workbench_agent.utilities.scan_workflows import determine_scans_to_run

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_scan(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan' command.

    This is the core handler that orchestrates the most common use case:
    uploading and scanning a codebase to identify licenses, components,
    and optionally dependencies/vulnerabilities.

    Workflow:
        1. Validate inputs (path exists, parameters valid)
        2. Validate and translate ID reuse arguments
        3. Resolve/create project and scan
        4. Ensure scan is idle (wait for any ongoing operations)
        5. Clear existing scan content
        6. Upload code archive
        7. Extract archives (if applicable)
        8. Run KB scan (and/or dependency analysis)
        9. Wait for completion (unless --no-wait)
       10. Display results (if requested)

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to code archive/directory to scan
            - project_name: Name of the project
            - scan_name: Name of the scan
            - limit: Maximum number of matches per file
            - sensitivity: Snippet detection sensitivity
            - autoid_*: Automatic identification flags
            - reuse_*: Identification reuse options
            - run_dependency_analysis: Whether to run dependency analysis
            - dependency_analysis_only: Skip KB scan, only run DA
            - no_wait: Exit without waiting for completion
            - show_*: Result display flags

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If inputs are invalid
        FileSystemError: If path doesn't exist
        ProjectNotFoundError: If project resolution fails
        ScanNotFoundError: If scan resolution fails
        ProcessError: If scan operations fail

    Note:
        The handler automatically adapts to different Workbench versions:
        - Older versions: May not support status checking for all operations
        - Newer versions: Full status checking and progress tracking
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Initialize timing dictionary
    durations = {"kb_scan": 0.0, "dependency_analysis": 0.0, "extraction_duration": 0.0}

    # Note: Path existence is validated at CLI layer (cli/validators.py)
    # We trust that params.path exists and is accessible

    # Resolve project and scan (find or create)
    print("\n--- Project and Scan Checks ---")
    print("Checking target Project and Scan...")
    project_code, scan_code, scan_is_new = client.resolver.resolve_project_and_scan(
        project_name=params.project_name,
        scan_name=params.scan_name,
        params=params,
    )

    # Assert scan is idle before uploading code
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if not scan_is_new:
        print("\nEnsuring the Scan is idle before uploading code...")
        # Check each process type individually (new API pattern)
        try:
            # Check status first to inform user if extraction is running
            extract_status = client.status_check.check_extract_archives_status(scan_code)
            if extract_status.status == "RUNNING":
                print(
                    "\nA prior Archive Extraction operation is in progress, "
                    "waiting for it to complete."
                )
            client.waiting.wait_for_extract_archives(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except Exception as e:
            logger.debug(f"Extract archives check skipped: {e}")

        try:
            # Check status first to inform user if scan is already running
            scan_status = client.status_check.check_scan_status(scan_code)
            if scan_status.status == "RUNNING":
                print("\nA prior Scan operation is in progress, " "waiting for it to complete.")
            client.waiting.wait_for_scan(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except Exception as e:
            logger.debug(f"Scan status check skipped: {e}")

        try:
            # Check status first to inform user if DA is already running
            da_status = client.status_check.check_dependency_analysis_status(scan_code)
            if da_status.status == "RUNNING":
                print(
                    "\nA prior Dependency Analysis operation is in progress, "
                    "waiting for it to complete."
                )
            client.waiting.wait_for_da(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )
        except Exception as e:
            logger.debug(f"Dependency analysis check skipped: {e}")
    else:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")

    # Clear existing scan content (skip for new scans - they're empty)
    if not scan_is_new:
        print("\nClearing existing scan content...")
        try:
            client.scans.remove_uploaded_content(scan_code, "")
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning(f"Failed to clear existing scan content: {e}")
            print(f"Warning: Could not clear existing scan content: {e}")
            print("Continuing with upload...")
    else:
        logger.debug("Skipping content clear - new scan is empty")

    # Upload code to scan
    print("\nUploading Code to Workbench...")
    client.uploads.upload_scan_target(scan_code, params.path)

    # Handle archive extraction
    print("\nExtracting Uploaded Archive...")
    extraction_triggered = client.scan_operations.start_archive_extraction(
        scan_code=scan_code,
        recursively_extract_archives=params.recursively_extract_archives,
        jar_file_extraction=params.jar_file_extraction,
    )

    if extraction_triggered:
        extraction_status = client.waiting.wait_for_extract_archives(
            scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=5,
        )
        durations["extraction_duration"] = extraction_status.duration or 0.0
    else:
        print("No archives to extract. Continuing with scan...")

    # Determine which scan operations to run
    scan_operations = determine_scans_to_run(params)

    # Initialize completion tracking
    da_completed = False

    # Handle dependency analysis only mode
    if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
        print("\nStarting Dependency Analysis only (skipping KB scan)...")
        client.scan_operations.start_da_only(scan_code)

        # Handle no-wait mode
        if getattr(params, "no_wait", False):
            print("Dependency Analysis has been started.")
            print("\nExiting without waiting for completion (--no-wait mode).")
            return True

        # Wait for dependency analysis to complete
        try:
            dependency_analysis_status = client.waiting.wait_for_da(
                scan_code,
                max_tries=params.scan_number_of_tries,
                wait_interval=params.scan_wait_time,
            )

            # Store the duration
            durations["dependency_analysis"] = dependency_analysis_status.duration or 0.0
            da_completed = True

            # Show scan summary and operation details
            print_operation_summary(params, da_completed, durations)

            # Show scan results if any were requested
            if any(
                [
                    params.show_licenses,
                    params.show_components,
                    params.show_dependencies,
                    params.show_scan_metrics,
                    params.show_policy_warnings,
                    params.show_vulnerabilities,
                ]
            ):
                fetch_display_save_results(client, params, scan_code)

            return True

        except Exception as e:
            logger.error(f"Error waiting for dependency analysis to complete: {e}", exc_info=True)
            print(f"\nError: Dependency analysis failed: {e}")
            return False

    # Start the KB scan (only if run_kb_scan is True)
    if scan_operations["run_kb_scan"]:
        print("\nStarting Scan Process...")

        # Resolve ID reuse parameters (if any)
        id_reuse_type, id_reuse_specific_code = client.resolver.resolve_id_reuse(
            id_reuse_any=getattr(params, "reuse_any_identification", False),
            id_reuse_my=getattr(params, "reuse_my_identifications", False),
            id_reuse_project_name=getattr(params, "reuse_project_ids", None),
            id_reuse_scan_name=getattr(params, "reuse_scan_ids", None),
            current_project_name=params.project_name,
        )

        # Run scan with resolved ID reuse parameters
        client.scan_operations.start_scan(
            scan_code=scan_code,
            limit=params.limit,
            sensitivity=params.sensitivity,
            autoid_file_licenses=params.autoid_file_licenses,
            autoid_file_copyrights=params.autoid_file_copyrights,
            autoid_pending_ids=params.autoid_pending_ids,
            delta_scan=params.delta_scan,
            id_reuse_type=id_reuse_type,
            id_reuse_specific_code=id_reuse_specific_code,
            run_dependency_analysis=scan_operations["run_dependency_analysis"],
            replace_existing_identifications=getattr(
                params, "replace_existing_identifications", False
            ),
            scan_failed_only=getattr(params, "scan_failed_only", False),
            full_file_only=getattr(params, "full_file_only", False),
            advanced_match_scoring=getattr(params, "advanced_match_scoring", True),
            match_filtering_threshold=getattr(params, "match_filtering_threshold", None),
            scan_host=getattr(params, "scan_host", None),
        )

        # Check if we should wait for completion
        if getattr(params, "no_wait", False):
            print("\nScan started successfully.")

            if scan_operations["run_dependency_analysis"]:
                print("Dependency Analysis will run after KB scan.")

            print("\nExiting without waiting for completion (--no-wait mode).")
            return True
        else:
            # Determine which processes to wait for
            process_types_to_wait = ["SCAN"]
            if scan_operations["run_dependency_analysis"]:
                process_types_to_wait.append("DEPENDENCY_ANALYSIS")

            print(f"\nWaiting for {', '.join(process_types_to_wait)} to complete...")

            try:
                # Wait for KB scan completion (with file tracking)
                kb_scan_status = client.waiting.wait_for_scan(
                    scan_code,
                    max_tries=params.scan_number_of_tries,
                    wait_interval=params.scan_wait_time,
                    should_track_files=True,
                )
                durations["kb_scan"] = kb_scan_status.duration or 0.0

                # Wait for dependency analysis if requested
                if scan_operations["run_dependency_analysis"]:
                    print("\nWaiting for Dependency Analysis to complete...")
                    try:
                        dependency_analysis_status = client.waiting.wait_for_da(
                            scan_code,
                            max_tries=params.scan_number_of_tries,
                            wait_interval=params.scan_wait_time,
                        )
                        durations["dependency_analysis"] = (
                            dependency_analysis_status.duration or 0.0
                        )
                        da_completed = True
                    except Exception as da_error:
                        logger.warning(f"Error in dependency analysis: {da_error}")
                        print(
                            f"\nWarning: Error waiting for dependency "
                            f"analysis to complete: {da_error}"
                        )
                        da_completed = False
                else:
                    da_completed = False

            except Exception as e:
                logger.error(f"Error waiting for processes to complete: {e}")
                print(f"\nError: Failed to wait for processes to complete: {e}")
                da_completed = False

        # Show scan summary and operation details
        print_operation_summary(params, da_completed, durations)

        # Show scan results if any were requested
        if any(
            [
                params.show_licenses,
                params.show_components,
                params.show_dependencies,
                params.show_scan_metrics,
                params.show_policy_warnings,
                params.show_vulnerabilities,
            ]
        ):
            fetch_display_save_results(client, params, scan_code)

        return True

    # Fallback return for any unhandled cases
    return True
