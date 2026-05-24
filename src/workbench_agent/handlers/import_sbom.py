# workbench_agent/handlers/import_sbom.py

import argparse
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, Tuple

from workbench_agent.api.exceptions import (
    ProcessError,
    ProcessTimeoutError,
)
from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.post_import_summary import print_import_summary
from workbench_agent.utilities.pre_flight_checks import (
    import_sbom_pre_flight_check,
)
from workbench_agent.utilities.sbom_validator import SBOMValidator
from workbench_agent.utilities.upload_data_prep import cleanup_temp_path

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _validate_sbom_file(file_path: str) -> Tuple[str, str, Dict, Any]:
    """
    Validates SBOM file and returns format information and parsed document.

    Args:
        file_path: Path to the SBOM file to validate

    Returns:
        tuple[str, str, Dict, Any]: (format, version, metadata,
            parsed_document)

    Raises:
        ValidationError: If SBOM validation fails
        FileSystemError: If file doesn't exist or can't be read
        Exception: If an unexpected error occurs
    """
    try:
        (
            sbom_format,
            version,
            metadata,
            parsed_document,
        ) = SBOMValidator.validate_sbom_file(file_path)
        logger.debug(
            f"SBOM validation successful: {sbom_format} v{version}"
        )
        return sbom_format, version, metadata, parsed_document
    except Exception as e:
        logger.error(f"SBOM validation failed for '{file_path}': {e}")
        raise


def _prepare_sbom_for_upload(
    file_path: str,
    sbom_format: str,
    parsed_document: Any,
    workbench_version: str = "",
) -> Tuple[str, bool]:
    """
    Prepares SBOM file for upload, converting format if needed.

    Args:
        file_path: Original file path
        sbom_format: Detected SBOM format
        parsed_document: Parsed document from validation
        workbench_version: Connected Workbench version for SPDX JSON gating

    Returns:
        tuple[str, bool]: (upload_path, temp_file_created)

    Raises:
        ValidationError: If preparation/conversion fails
        Exception: If an unexpected error occurs
    """
    try:
        upload_path = SBOMValidator.prepare_sbom_for_upload(
            file_path,
            sbom_format,
            parsed_document,
            workbench_version,
        )
        temp_file_created = upload_path != file_path
        logger.debug(
            f"SBOM preparation successful: upload_path={upload_path}, "
            f"converted={temp_file_created}"
        )
        return upload_path, temp_file_created
    except Exception as e:
        logger.error(f"SBOM preparation failed for '{file_path}': {e}")
        raise


def _print_validation_summary(
    sbom_format: str, version: str, metadata: Dict
):
    """Prints a summary of the SBOM validation results."""
    print("SBOM validation successful:")
    print(f"  Format: {sbom_format.upper()}")
    print(f"  Version: {version}")
    if sbom_format == "cyclonedx":
        print(
            f"  Components: {metadata.get('components_count', 'Unknown')}"
        )
        if metadata.get("serial_number"):
            print(f"  Serial Number: {metadata['serial_number']}")
    elif sbom_format == "spdx":
        print(f"  Document Name: {metadata.get('name', 'Unknown')}")
        print(f"  Packages: {metadata.get('packages_count', 'Unknown')}")
        print(f"  Files: {metadata.get('files_count', 'Unknown')}")


@handler_error_wrapper
def handle_import_sbom(
    client: "WorkbenchClient", params: argparse.Namespace
) -> bool:
    """
    Handler for the 'import-sbom' command.

    Imports SBOM (Software Bill of Materials) data from a file into a scan.
    Supports both CycloneDX and SPDX formats with automatic validation.
    SPDX JSON is uploaded directly on Workbench 2025.2.0+; older servers
    receive an automatic JSON-to-RDF conversion before upload.

    Workflow:
    1. Validates SBOM file format and content
    2. Prepares/converts SBOM for upload if needed
    3. Resolves/creates project and scan
    4. Ensures scan is idle
    5. Uploads SBOM file
    6. Triggers import process
    7. Waits for completion
    8. Displays results

    Args:
        client: The Workbench API client instance
        params: Command line parameters including:
            - path: Path to SBOM file (CycloneDX or SPDX)
            - project_name: Name of the project
            - scan_name: Name of the scan

    Returns:
        bool: True if the operation completed successfully

    Raises:
        ValidationError: If SBOM validation fails
        WorkbenchAgentError: If import fails
        ProcessError: If process fails
        ProcessTimeoutError: If process times out
        Exception: If an unexpected error occurs
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Track upload path for cleanup
    upload_path = None
    temp_file_created = False

    try:
        # Validate SBOM file FIRST - before any project/scan creation
        print("\n--- Validating SBOM File ---")
        (
            sbom_format,
            version,
            metadata,
            parsed_document,
        ) = _validate_sbom_file(params.path)
        _print_validation_summary(sbom_format, version, metadata)

        # Prepare SBOM file for upload (convert if needed)
        print("\n--- Preparing SBOM for Upload ---")
        upload_path, temp_file_created = _prepare_sbom_for_upload(
            params.path,
            sbom_format,
            parsed_document,
            client.get_workbench_version(),
        )

        if temp_file_created:
            print(
                f"  Converted for upload: "
                f"{os.path.basename(upload_path)}"
            )
        else:
            print("  Using original file format")

        # Resolve project and scan (find or create)
        print("\n--- Project and Scan Checks ---")
        print("Checking target Project and Scan...")
        _, scan_code, scan_is_new = (
            client.resolver.find_or_create_project_and_scan(
                project_name=params.project_name,
                scan_name=params.scan_name,
                params=params,
                import_from_report=True,
            )
        )

        # Ensure scan is idle before starting SBOM import
        import_sbom_pre_flight_check(client, scan_code, scan_is_new, params)

        # Upload SBOM file using the prepared upload path
        print("\n--- Uploading SBOM File ---")
        try:
            client.upload_service.upload_sbom_file(
                scan_code=scan_code, path=upload_path
            )
            print(f"SBOM uploaded successfully from: {upload_path}")
        except Exception as e:
            logger.error(
                f"Failed to upload SBOM file for '{scan_code}': {e}",
                exc_info=True,
            )
            raise WorkbenchAgentError(
                f"Failed to upload SBOM file: {e}",
                details={"error": str(e)},
            ) from e

        # Start SBOM import
        print("\n--- Starting SBOM Import ---")

        try:
            client.scan_operations.start_sbom_import(scan_code=scan_code)
            print("SBOM import initiated successfully.")
        except Exception as e:
            logger.error(
                f"Failed to start SBOM import for '{scan_code}': {e}",
                exc_info=True,
            )
            raise WorkbenchAgentError(
                f"Failed to start SBOM import: {e}",
                details={"error": str(e)},
            ) from e

        # Wait for SBOM import to complete
        sbom_completed = False
        try:
            print("\nWaiting for SBOM import to complete...")
            # Use optimized 3-second wait interval for import mode
            client.status_check.check_report_import_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=3,  # Faster for import mode
            )

            sbom_completed = True

            print("SBOM import completed successfully.")

        except ProcessTimeoutError:
            logger.error(
                f"Error during SBOM import for '{scan_code}': timeout",
                exc_info=True,
            )
            raise
        except ProcessError:
            logger.error(
                f"Error during SBOM import for '{scan_code}': process error",
                exc_info=True,
            )
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error during SBOM import for "
                f"'{scan_code}': {e}",
                exc_info=True,
            )
            raise WorkbenchAgentError(
                f"Error during SBOM import: {e}",
                details={"error": str(e)},
            ) from e

        # Show import summary (includes Workbench link)
        if sbom_completed:
            print_import_summary(
                client,
                params,
                scan_code,
                sbom_completed,
                show_summary=getattr(params, "show_summary", False),
            )
        else:
            # Import didn't complete, just show link
            print_import_summary(
                client,
                params,
                scan_code,
                False,
                show_summary=False,
            )

        return sbom_completed

    finally:
        # Clean up temporary file if one was created
        if temp_file_created:
            cleanup_temp_path(upload_path)
