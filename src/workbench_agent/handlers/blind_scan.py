import argparse
import json
import logging
import os
import shutil
from typing import TYPE_CHECKING, Optional

from workbench_agent.exceptions import ValidationError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.pre_flight_checks import (
    blind_scan_pre_flight_check,
)
from workbench_agent.utilities.scan_workflows import (
    execute_scan_workflow,
)
from workbench_agent.utilities.toolbox_wrapper import ToolboxWrapper
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def resolve_fossid_toolbox_path(configured: Optional[str]) -> str:
    """
    Return the path to the fossid-toolbox executable.

    If ``configured`` is set, it is used as-is. Otherwise ``fossid-toolbox``
    is resolved via the process environment PATH (``shutil.which``).
    """
    if configured:
        return configured
    resolved = shutil.which("fossid-toolbox")
    if not resolved:
        raise ValidationError(
            "fossid-toolbox not found in PATH. Install FossID Toolbox or "
            "pass --fossid-toolbox-path with the path to the executable."
        )
    return resolved


def validate_fossid_file(file_path: str) -> None:
    """
    Validate the encoding and schema of a pre-generated .fossid file.

    The file must be valid UTF-8.
    Each line must be a JSON object containing at minimum:
    - path (str): Relative file path
    - size (int): File size in bytes
    - hashes_ffm (list): Hash objects, each with format (int) and data (str)

    Args:
        file_path: Path to the .fossid file to validate

    Raises:
        ValidationError: If the file is not UTF-8, is empty, or has invalid
            schema
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError as e:
        raise ValidationError(
            f"The .fossid file '{file_path}' is not valid UTF-8 "
            f"(byte {e.start}: {e.reason}). Re-generate it with "
            f"fossid-toolbox or re-encode it as UTF-8."
        ) from e
    except Exception as e:
        raise ValidationError(
            f"Failed to read .fossid file '{file_path}': {e}"
        ) from e

    if not lines or all(line.strip() == "" for line in lines):
        raise ValidationError(
            f"The .fossid file '{file_path}' is empty."
        )

    required_fields = {"path": str, "size": int, "hashes_ffm": list}

    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValidationError(
                f"Invalid JSON on line {line_num} of "
                f"'{file_path}': {e}"
            ) from e

        if not isinstance(entry, dict):
            raise ValidationError(
                f"Line {line_num} of '{file_path}' is not a JSON object."
            )

        for field, expected_type in required_fields.items():
            if field not in entry:
                raise ValidationError(
                    f"Line {line_num} of '{file_path}' is missing "
                    f"required field '{field}'."
                )
            if not isinstance(entry[field], expected_type):
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': '{field}' must "
                    f"be {expected_type.__name__}."
                )

        for i, hash_entry in enumerate(entry["hashes_ffm"]):
            if not isinstance(hash_entry, dict):
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': "
                    f"'hashes_ffm[{i}]' must be an object."
                )
            if "format" not in hash_entry or "data" not in hash_entry:
                raise ValidationError(
                    f"Line {line_num} of '{file_path}': "
                    f"'hashes_ffm[{i}]' must have 'format' and "
                    f"'data' fields."
                )

    non_empty = sum(1 for line in lines if line.strip())
    logger.info(
        f"Validated .fossid file '{file_path}': {non_empty} entries."
    )


@handler_error_wrapper
def handle_blind_scan(
    client: "WorkbenchClient", params: argparse.Namespace
) -> bool:
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
    2b. If directory: validates Toolbox and generates hashes
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
    print(f"\n--- Running {params.command.upper()} Command ---")

    durations: dict = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
    }

    # ===== STEP 1: Detect input type =====
    # Path existence is validated at CLI layer (cli/validators.py)
    is_pregenerated = (
        os.path.isfile(params.path)
        and params.path.endswith(".fossid")
    )

    hash_file_path = None
    should_cleanup = False

    try:
        if is_pregenerated:
            print("\nValidating pre-generated .fossid file...")
            validate_fossid_file(params.path)
            hash_file_path = params.path
            print("Validation successful. Skipping hash generation.")
        else:
            # ===== STEP 2: Validate Toolbox and generate hashes =====
            print("\nValidating FossID Toolbox...")
            toolbox_wrapper = ToolboxWrapper(
                toolbox_path=resolve_fossid_toolbox_path(
                    getattr(params, "fossid_toolbox_path", None)
                ),
            )

            version = toolbox_wrapper.get_version()
            print(f"Using {version}")

            print("\nHashing Target Path with Toolbox...")
            hash_file_path = toolbox_wrapper.generate_hashes(
                path=params.path,
                run_dependency_analysis=getattr(
                    params, "run_dependency_analysis", False
                ),
            )
            should_cleanup = True

        # ===== STEP 3: Resolve/create project and scan =====
        print("\n--- Project and Scan Checks ---")
        print("Checking target Project and Scan...")
        _, scan_code, scan_is_new = (
            client.resolver.find_or_create_project_and_scan(
                project_name=params.project_name,
                scan_name=params.scan_name,
                params=params,
            )
        )

        blind_scan_pre_flight_check(
            client, scan_code, scan_is_new, params
        )

        if not scan_is_new:
            print("\nClearing existing scan content...")
            try:
                client.scan_content.remove_uploaded_content(scan_code, "")
                print("Successfully cleared existing scan content.")
            except Exception as e:
                logger.warning(
                    f"Failed to clear existing scan content: {e}"
                )
                print("Continuing with hash upload...")
        else:
            logger.debug(
                "Skipping content clear - new scan is empty"
            )

        # ===== STEP 4: Upload hash file =====
        print("\nUploading hashes to Workbench...")
        client.upload_service.upload_scan_target(
            scan_code, hash_file_path
        )
        print("Hashes uploaded successfully!")

        # ===== STEP 5: Run scans, wait, display results =====
        return execute_scan_workflow(
            client, params, scan_code, durations
        )

    finally:
        # ===== STEP 6: Clean up temporary hash file =====
        if should_cleanup:
            cleanup_temp_path(hash_file_path)
