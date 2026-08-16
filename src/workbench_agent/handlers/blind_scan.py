import argparse
import logging
import os
from typing import TYPE_CHECKING

from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.section import print_section
from workbench_agent.utilities.pre_flight_checks import (
    blind_scan_pre_flight_check,
)
from workbench_agent.utilities.resolve_project_scan import (
    find_or_create_project_and_scan,
)
from workbench_agent.utilities.scan_workflows import (
    execute_scan_workflow,
)
from workbench_agent.utilities.toolbox_wrapper import (
    ToolboxWrapper,
    resolve_fossid_toolbox_path,
    validate_fossid_file,
)
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_blind_scan(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the 'blind-scan' command.

    Allows scanning without uploading source code to Workbench.

    For a provided path, use Toolbox to generate hashes,
    upload the hash file, then run the scan.

    Alternatively, accepts a pre-generated .fossid file,
    skipping the Toolbox hashing step.

    Workflow:
    1. Detects input type (.fossid file vs directory)
    2a. If .fossid file: validates file schema
    2b. If directory: validates Toolbox, generate hashes, validate schema
    3. Resolves/creates project and scan in Workbench
    4. Uploads hash file to Workbench
    5. Runs scans, waits, and displays results
    6. Cleans up temporary hash file (only if generated)

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Directory to hash, or pre-generated .fossid file
            - Various scan configuration options

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If required parameters are invalid
        FileSystemError: If specified paths don't exist
        ProcessError: If Toolbox execution fails
    """
    print_section(f"Running {params.command.upper()} Command")

    durations: dict = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
    }

    # ===== STEP 1: Detect input type =====
    # Path existence is validated at CLI layer (cli/validators.py)
    is_pregenerated = os.path.isfile(params.path) and params.path.endswith(".fossid")

    hash_file_path = None
    should_cleanup = False

    try:
        if is_pregenerated:
            print("Validating pre-generated .fossid file...")
            validate_fossid_file(params.path)
            hash_file_path = params.path
            print("Validation successful. Skipping hash generation.")
        else:
            # ===== STEP 2: Validate Toolbox and generate hashes =====
            logger.debug("Validating FossID Toolbox...")
            toolbox_wrapper = ToolboxWrapper(
                toolbox_path=resolve_fossid_toolbox_path(
                    getattr(params, "fossid_toolbox_path", None)
                ),
                timeout=str(getattr(params, "fossid_toolbox_timeout", 300)),
            )

            version = toolbox_wrapper.get_version()
            toolbox_wrapper.validate_toolbox_version(version)

            enable_lac = not getattr(params, "skip_lac_extraction", False)

            print("Hashing Target Path with Toolbox...")
            hash_file_path = toolbox_wrapper.generate_hashes(
                path=params.path,
                run_dependency_analysis=getattr(params, "run_dependency_analysis", False),
                enable_lac_extraction=enable_lac,
            )
            should_cleanup = True

            print("\nValidating generated .fossid file...")
            validate_fossid_file(hash_file_path)
            print("Validation successful.")

        # ===== STEP 3: Resolve/create project and scan =====
        print_section("Project and Scan Checks")
        _, scan_code, scan_is_new = find_or_create_project_and_scan(
            client,
            params,
        )

        if not scan_is_new:
            blind_scan_pre_flight_check(client, scan_code, params)
        else:
            logger.debug("Skipping idle checks - new scan is guaranteed to be idle")

        if not scan_is_new:
            print("\nClearing existing scan content...")
            try:
                client.scan_content.remove_uploaded_content(scan_code, "")
                print("Successfully cleared existing scan content.")
            except Exception as e:
                logger.warning(f"Failed to clear existing scan content: {e}")
                print("Continuing with hash upload...")
        else:
            logger.debug("Skipping content clear - new scan is empty")

        # ===== STEP 4: Upload hash file =====
        print("\nUploading hashes to Workbench...")
        client.scan_content.upload_scan_target(scan_code, hash_file_path)
        print("Hashes uploaded successfully!")

        # ===== STEP 5: Run scans, wait, display results =====
        return execute_scan_workflow(client, params, scan_code, durations)

    finally:
        # ===== STEP 6: Clean up temporary hash file =====
        if should_cleanup:
            cleanup_temp_path(hash_file_path)
