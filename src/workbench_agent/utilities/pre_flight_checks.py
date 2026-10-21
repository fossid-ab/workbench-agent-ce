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
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the scan handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new scan operation. Checks for:
    - Archive extraction operations
    - KB scan operations
    - Dependency analysis operations

    Callers skip this for new scans (they are guaranteed idle).

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
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
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the scan-git handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new git clone operation. Checks for:
    - Git clone operations
    - KB scan operations
    - Dependency analysis operations

    Callers skip this for new scans (they are guaranteed idle).

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
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
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the blind-scan handler.

    Ensures that existing scans don't have any running operations that
    would be interrupted by a new blind scan operation. Checks for:
    - KB scan operations
    - Dependency analysis operations

    Callers skip this for new scans (they are guaranteed idle).

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
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
    params: argparse.Namespace,
    *,
    quiet: bool = False,
) -> None:
    """
    Performs pre-flight checks for the import-da handler.

    Ensures that existing scans don't have any running dependency analysis
    operations that would be interrupted by a new import operation.

    Callers skip this for new scans (they are guaranteed idle).

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
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
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the import-sbom handler.

    Ensures that existing scans don't have any running report import
    operations that would be interrupted by a new SBOM import operation.

    Callers skip this for new scans (they are guaranteed idle).

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
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


def _wait_for_kb_and_da_idle(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Wait until KB scan and dependency analysis are idle.

    Shared by read-command pre-flight checks. Timeout, API, and network
    errors propagate so callers do not continue with unverified results.
    """
    print("\nEnsuring Scans are Complete...")

    scan_status = client.status_check.check_scan_status(scan_code)
    if scan_status.is_active:
        print("KB Scan is still in progress, waiting for it to complete...")
        client.status_check.check_scan_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=params.scan_wait_time,
        )
    print("KB Scan has completed successfully.")

    da_status = client.status_check.check_dependency_analysis_status(scan_code)
    if da_status.is_active:
        print("Dependency Analysis is still in progress, waiting for it to complete...")
        client.status_check.check_dependency_analysis_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=params.scan_wait_time,
        )
    print("Dependency Analysis has completed successfully.")

    logger.info("Verified scan '%s' is idle for read operations.", scan_code)


def show_results_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the show-results handler.

    Waits for KB scan and dependency analysis. Errors propagate so results
    are not fetched from an unverified scan.

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts
    """
    _wait_for_kb_and_da_idle(client, scan_code, params)


def evaluate_gates_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the evaluate-gates handler.

    Waits for KB scan and dependency analysis. Errors propagate; the gates
    handler maps them to a failed command result without running gates.

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
    _wait_for_kb_and_da_idle(client, scan_code, params)


def download_reports_pre_flight_check(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> None:
    """
    Performs pre-flight checks for the download-reports handler.

    Waits for KB scan and dependency analysis before scan-scope reports.
    Errors propagate so reports are not generated from an unverified scan.

    Args:
        client: The Workbench API client instance
        scan_code: Code of the scan to check
        params: Command line parameters containing:
            - scan_number_of_tries: Maximum attempts for waiting
            - scan_wait_time: Seconds to wait between attempts

    Note:
        Call only for scan-scope reports. Project-scope reports do not use
        this check today.
    """
    _wait_for_kb_and_da_idle(client, scan_code, params)
