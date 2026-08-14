"""
Pre-flight check utilities for ensuring scans are idle before operations.

These functions help handlers avoid impacting running operations.
"""

import argparse
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def scan_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    scan_is_new: bool,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the scan handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new scan operation. Checks for:
    - Archive extraction operations
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        scan_is_new: Whether this is a new scan (new scans are guaranteed
            to be idle, so checks are skipped)
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if scan_is_new:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")
        return

    print("Ensuring the Scan is Idle...")

    # Check each process type individually
    try:
        # Check if extraction is active
        extract_status = client.status_check.check_extract_archives_status(scan_code)
        if extract_status.is_active:
            print(
                "\nA prior Archive Extraction operation is in progress, "
                "waiting for it to complete."
            )
            client.status_check.check_extract_archives_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Extract archives check skipped: {e}")

    try:
        # Check if scan is active
        scan_status = client.status_check.check_scan_status(scan_code)
        if scan_status.is_active:
            print("\nA prior Scan operation is in progress, " "waiting for it to complete.")
            client.status_check.check_scan_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Scan status check skipped: {e}")

    try:
        # Check if DA is active
        da_status = client.status_check.check_dependency_analysis_status(scan_code)
        if da_status.is_active:
            print(
                "\nA prior Dependency Analysis operation is in progress, "
                "waiting for it to complete."
            )
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Dependency analysis check skipped: {e}")


def scan_git_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    scan_is_new: bool,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the scan-git handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new git clone operation. Checks for:
    - Git clone operations
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        scan_is_new: Whether this is a new scan (new scans are guaranteed
            to be idle, so checks are skipped)
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if scan_is_new:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")
        return

    print("Ensuring the Scan is Idle...")

    # Check each process type individually
    try:
        # Check if git clone is active
        git_status = client.status_check.check_git_clone_status(scan_code)
        if git_status.is_active:
            print("\nA prior Git Clone operation is in progress, " "waiting for it to complete...")
            client.status_check.check_git_clone_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Git clone status check skipped: {e}")

    try:
        # Check if scan is active
        scan_status = client.status_check.check_scan_status(scan_code)
        if scan_status.is_active:
            print("\nA prior Scan operation is in progress, " "waiting for it to complete.")
            client.status_check.check_scan_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Scan status check skipped: {e}")

    try:
        # Check if DA is active
        da_status = client.status_check.check_dependency_analysis_status(scan_code)
        if da_status.is_active:
            print(
                "\nA prior Dependency Analysis operation is in progress, "
                "waiting for it to complete."
            )
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Dependency analysis check skipped: {e}")


def blind_scan_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    scan_is_new: bool,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the blind-scan handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new blind scan operation. Checks for:
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        scan_is_new: Whether this is a new scan (new scans are guaranteed
            to be idle, so checks are skipped)
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if scan_is_new:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")
        return

    print("Ensuring the Scan is Idle...")

    # Check each process type individually
    try:
        # Check if scan is active
        scan_status = client.status_check.check_scan_status(scan_code)
        if scan_status.is_active:
            print("\nA prior Scan operation is in progress, " "waiting for it to complete.")
            client.status_check.check_scan_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Scan status check skipped: {e}")

    try:
        # Check if DA is active
        da_status = client.status_check.check_dependency_analysis_status(scan_code)
        if da_status.is_active:
            print(
                "\nA prior Dependency Analysis operation is in "
                "progress, waiting for it to complete."
            )
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Dependency analysis check skipped: {e}")


def import_da_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    scan_is_new: bool,
    params: argparse.Namespace,
    *,
    quiet: bool = False,
) -> None:
    """
    Performs pre-flight checks for the import-da handler.

    Ensures that existing scans don't have any running dependency analysis
    operations that would be interrupted by a new import operation.

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        scan_is_new: Whether this is a new scan (new scans are guaranteed
            to be idle, so checks are skipped)
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if scan_is_new:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")
        return

    if quiet:
        logger.debug("Ensuring scan is idle before DA import...")
    else:
        print("\nEnsuring Scan is Idle...")

    try:
        # Check if DA is active and wait if needed
        da_status = client.status_check.check_dependency_analysis_status(scan_code)
        if da_status.is_active:
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Dependency analysis check skipped: {e}")


def import_sbom_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    scan_is_new: bool,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the import-sbom handler.

    Ensures that existing scans don't have any running report import
    operations that would be interrupted by a new SBOM import operation.

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        scan_is_new: Whether this is a new scan (new scans are guaranteed
            to be idle, so checks are skipped)
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    # Skip idle checks for new scans (they're guaranteed to be idle)
    if scan_is_new:
        logger.debug("Skipping idle checks - new scan is guaranteed to be idle")
        return

    print("\nEnsuring the Scan is Idle...")

    try:
        # Check if report import is active and wait if needed
        import_status = client.status_check.check_report_import_status(scan_code)
        if import_status.is_active:
            client.status_check.check_report_import_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
    except Exception as e:
        logger.debug(f"Report import check skipped: {e}")


def show_results_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the show-results handler.

    Ensures that scan processes are complete before displaying results.
    This is a read-only operation, so it always checks (no scan_is_new
    parameter needed).

    Checks for:
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    print("\nEnsuring Scans are Complete...")

    try:
        # Check if KB scan is complete
        logger.debug("Checking KB scan completion status...")
        try:
            # Check if scan is active
            scan_status = client.status_check.check_scan_status(scan_code)
            if scan_status.is_active:
                print("\nKB Scan is still in progress, " "waiting for it to complete...")
                client.status_check.check_scan_status(
                    scan_code,
                    wait=True,
                    wait_retry_count=params.scan_number_of_tries,
                    wait_retry_interval=params.scan_wait_time,
                )
        except Exception as e:
            # Older Workbench versions might not support status checking
            logger.debug(f"Scan status check not available: {e}")

        # Check if dependency analysis is complete (if applicable)
        logger.debug("Checking dependency analysis completion status...")
        try:
            # Check if DA is active
            da_status = client.status_check.check_dependency_analysis_status(scan_code)
            if da_status.is_active:
                print(
                    "\nDependency Analysis is still in progress, " "waiting for it to complete..."
                )
                client.status_check.check_dependency_analysis_status(
                    scan_code,
                    wait=True,
                    wait_retry_count=params.scan_number_of_tries,
                    wait_retry_interval=params.scan_wait_time,
                )
        except Exception as e:
            # Dependency analysis might not exist or be supported
            logger.debug(f"Dependency analysis check not available: {e}")

    except Exception as e:
        logger.warning(
            f"Could not verify scan completion for '{scan_code}': {e}. " f"Proceeding anyway."
        )
        print("\nWarning: Could not verify scan completion status. " "Results may be incomplete.")


def evaluate_gates_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the evaluate-gates handler.

    Ensures that scan processes are complete before evaluating gates.
    This is a read-only operation, so it always checks (no scan_is_new
    parameter needed).

    Checks for:
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts

    Raises:
        ProcessTimeoutError: If scan processes don't complete in time
        ApiError: If API operations fail
        NetworkError: If network operations fail
    """
    print("\nEnsuring Scans are Complete...")

    # Errors propagate to the caller; the gates handler is responsible
    # for translating them into the right exit status.
    scan_status = client.status_check.check_scan_status(scan_code)
    if scan_status.is_active:
        print("KB Scan is still in progress, " "waiting for it to complete...")
        client.status_check.check_scan_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=params.scan_wait_time,
        )

    da_status = client.status_check.check_dependency_analysis_status(scan_code)
    if da_status.is_active:
        print("Dependency Analysis is still in progress, " "waiting for it to complete...")
        client.status_check.check_dependency_analysis_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=params.scan_wait_time,
        )

    logger.info("Verified all scans are idle. Checking gates...")


def download_reports_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the download-reports handler.

    Ensures that scans are complete before generating reports.
    Only applies to scan-scope reports.

    Checks for:
    - KB scan operations
    - Dependency analysis operations

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts

    Note:
        This function is designed to be called only for scan-scope reports.
        Project-scope reports don't require scan completion checks.
    """
    print("\nEnsuring Scans are Complete...")

    # Wait for KB scan
    try:
        scan_status = client.status_check.check_scan_status(scan_code)
        if scan_status.is_active:
            print("\nKB Scan is still in progress, " "waiting for it to complete...")
            client.status_check.check_scan_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
        print("KB Scan has completed successfully.")
    except Exception as e:
        print(f"\nWarning: KB Scan did not complete in time: {e}")
        print("Reports may be incomplete.")
        logger.warning(
            f"Generating reports for scan '{scan_code}' with " f"incomplete KB scan: {e}"
        )

    # Wait for dependency analysis
    try:
        da_status = client.status_check.check_dependency_analysis_status(scan_code)
        if da_status.is_active:
            print("\nDependency Analysis is still in progress, " "waiting for it to complete...")
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
        print("Dependency Analysis has completed successfully.")
    except Exception as e:
        print(f"\nWarning: Dependency Analysis did not complete in time: {e}")
        print("Reports may have incomplete dependency information.")
        logger.warning(f"Generating reports for scan '{scan_code}' with " f"incomplete DA: {e}")
