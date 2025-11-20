"""
WaitingService - Convenience waiting methods for common operations.

This service provides high-level waiting methods for Workbench operations.
It composes StatusCheckService with generic waiting infrastructure to
provide simple one-line methods for handlers.

Architecture:
    Handler → WaitingService → StatusCheckService → Clients

"""

import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from workbench_agent.api.exceptions import (
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
)
from workbench_agent.api.utils.process_waiter import StatusResult, WaitResult

logger = logging.getLogger("workbench-agent")


class WaitingService:
    """
    High-level waiting service for Workbench async operations.

    This service provides one-line methods for waiting on async operations.

    Example:
        >>> service = WaitingService(status_check_service)
        >>>
        >>> # Simple waiting
        >>> result = service.wait_for_scan("scan_123")
        >>> result = service.wait_for_da("scan_123")
    """

    def __init__(self, status_check_service):
        """
        Initialize WaitingService.

        Args:
            status_check_service: StatusCheckService for status checking
        """
        self._status_check = status_check_service
        logger.debug("WaitingService initialized")

    # =========================================================================
    # SCAN OPERATIONS (4 methods)
    # =========================================================================

    def wait_for_scan(
        self,
        scan_code: str,
        max_tries: int = 360,
        wait_interval: int = 10,
        should_track_files: bool = False,
    ) -> WaitResult:
        """
        Wait for a KB scan operation to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)
            should_track_files: Show detailed file progress (default: False)

        Returns:
            WaitResult: Result with final status and duration

        Example:
            >>> result = service.wait_for_scan("scan_123")
            >>> result = service.wait_for_scan(
            ...     "scan_123",
            ...     should_track_files=True
            ... )
        """
        check_func = lambda: self._status_check.check_scan_status(scan_code)

        # Create custom progress callback if file tracking requested
        progress_callback = None
        if should_track_files:
            progress_callback = self._create_scan_progress_callback(scan_code)

        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"KB Scan '{scan_code}'",
            progress_callback=progress_callback,
        )

    def wait_for_da(
        self, scan_code: str, max_tries: int = 360, wait_interval: int = 10
    ) -> WaitResult:
        """
        Wait for dependency analysis to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration
        """
        check_func = lambda: self._status_check.check_dependency_analysis_status(scan_code)
        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Dependency Analysis '{scan_code}'",
        )

    def wait_for_extract_archives(
        self, scan_code: str, max_tries: int = 360, wait_interval: int = 10
    ) -> WaitResult:
        """
        Wait for archive extraction to complete.

        This method gracefully handles older Workbench versions that don't
        support extraction status checking by using a fixed 5-second wait.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration
        """
        try:
            check_func = lambda: self._status_check.check_extract_archives_status(scan_code)
            return self._wait_for_completion(
                check_function=check_func,
                max_tries=max_tries,
                wait_interval=wait_interval,
                operation_name=f"Extract Archives '{scan_code}'",
            )
        except UnsupportedStatusCheck:
            # Graceful degradation for Workbench < 25.1.0
            logger.info(
                "Archive extraction status checking not supported on this "
                "Workbench version, using fallback wait (5 seconds)"
            )
            print("Using fallback wait for archive extraction (5 seconds)...")
            time.sleep(5)
            return WaitResult(status_data={}, duration=None, success=True)

    def wait_for_report_import(
        self, scan_code: str, max_tries: int = 360, wait_interval: int = 10
    ) -> WaitResult:
        """
        Wait for SBOM/SPDX report import to complete.

        Args:
            scan_code: Code of the scan to check
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration
        """
        check_func = lambda: self._status_check.check_report_import_status(scan_code)
        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Report Import '{scan_code}'",
        )

    # =========================================================================
    # REPORT OPERATIONS (2 methods)
    # =========================================================================

    def wait_for_scan_report_completion(
        self,
        scan_code: str,
        process_id: int,
        max_tries: int = 360,
        wait_interval: int = 10,
    ) -> WaitResult:
        """
        Wait for scan report generation to complete.

        Args:
            scan_code: Code of the scan
            process_id: Process queue ID from report generation
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration
        """
        check_func = lambda: self._status_check.check_scan_report_status(scan_code, process_id)
        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Scan Report '{scan_code}'",
        )

    def wait_for_project_report_completion(
        self,
        project_code: str,
        process_id: int,
        max_tries: int = 360,
        wait_interval: int = 10,
    ) -> WaitResult:
        """
        Wait for project report generation to complete.

        Args:
            project_code: Code of the project
            process_id: Process queue ID from report generation
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration

        Raises:
            UnsupportedStatusCheck: If Workbench < 23.1.0
        """
        check_func = lambda: self._status_check.check_project_report_status(
            process_id, project_code
        )
        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Project Report '{project_code}'",
        )

    # =========================================================================
    # GIT OPERATIONS (1 method)
    # =========================================================================

    def wait_for_git_clone(
        self, scan_code: str, max_tries: int = 360, wait_interval: int = 10
    ) -> WaitResult:
        """
        Wait for git clone operation to complete.

        Args:
            scan_code: Code of the scan
            max_tries: Maximum attempts before timeout (default: 360)
            wait_interval: Seconds between attempts (default: 10)

        Returns:
            WaitResult: Result with final status and duration
        """
        check_func = lambda: self._status_check.check_git_clone_status(scan_code)
        return self._wait_for_completion(
            check_function=check_func,
            max_tries=max_tries,
            wait_interval=wait_interval,
            operation_name=f"Git Clone '{scan_code}'",
        )

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _create_scan_progress_callback(self, scan_code: str):
        """
        Create a stateful progress callback for scan file tracking.

        This replicates the old _handle_scan_progress() behavior with
        smart printing that only shows details on changes or periodic
        intervals.

        Args:
            scan_code: Code of the scan (for display purposes)

        Returns:
            Callable: Progress callback function
        """

        class ScanProgressTracker:
            """Stateful progress tracker for scan operations."""

            def __init__(self):
                self.last_status = None
                self.last_state = None
                self.last_step = None

            def callback(self, status_result, attempt, max_tries):
                """Progress callback that tracks file progress."""
                # Extract progress information
                raw_data = status_result.raw_data
                current_state = raw_data.get("state", "")
                current_step = raw_data.get("current_step", "")
                percentage = raw_data.get("percentage_done", "")

                # File tracking
                total_files = raw_data.get("total_files", 0)
                current_file = raw_data.get("current_file", 0)

                # Determine if we should print details
                should_print = (
                    attempt == 1  # First check
                    or attempt % 10 == 0  # Periodic (every ~minute)
                    or status_result.status != self.last_status
                    or current_state != self.last_state
                    or current_step != self.last_step
                )

                if should_print:
                    # Build detailed status message
                    msg = f"\nScan '{scan_code}' status: "
                    msg += status_result.status

                    if current_state:
                        msg += f" ({current_state})"

                    # Show file progress if available
                    if total_files and int(total_files) > 0:
                        msg += f" - File {current_file}/{total_files}"
                        if percentage:
                            msg += f" ({percentage})"
                    elif percentage:
                        msg += f" - Progress: {percentage}"

                    if current_step:
                        msg += f" - Step: {current_step}"

                    msg += f". Attempt {attempt}/{max_tries}"
                    print(msg, end="", flush=True)

                    # Update tracking state
                    self.last_status = status_result.status
                    self.last_state = current_state
                    self.last_step = current_step
                else:
                    # Just show a dot for non-significant updates
                    print(".", end="", flush=True)

        tracker = ScanProgressTracker()
        return tracker.callback

    # =========================================================================
    # CORE WAITING INFRASTRUCTURE (private methods)
    # =========================================================================

    def _wait_for_completion(
        self,
        check_function: Callable[[], StatusResult],
        max_tries: int,
        wait_interval: int,
        operation_name: str,
        progress_callback: Optional[Callable[[StatusResult, int, int], None]] = None,
    ) -> WaitResult:
        """
        Generic waiting engine for async operations.

        This is the core waiting infrastructure that handles retry logic,
        timeout detection, and progress reporting. It delegates actual
        status checking to the provided function.

        Args:
            check_function: Function that returns StatusResult when called
            max_tries: Maximum number of attempts before timeout
            wait_interval: Seconds to wait between attempts
            operation_name: Human-readable name for logging/messages
            progress_callback: Optional callback for custom progress
                reporting. Called with (StatusResult, attempt, max_tries).

        Returns:
            WaitResult with final status and duration

        Raises:
            ProcessTimeoutError: If max_tries exceeded
            ProcessError: If operation fails
            UnsupportedStatusCheck: If status check not supported
        """
        logger.info(f"Waiting for {operation_name} to complete...")
        attempts = 0
        last_status = None

        while attempts < max_tries:
            attempts += 1

            try:
                # Call the provided status check function
                result = check_function()

                # Log status changes
                if result.status != last_status:
                    logger.debug(f"{operation_name} status: {result.status}")
                    last_status = result.status

                # Use custom progress callback if provided
                if progress_callback:
                    progress_callback(result, attempts, max_tries)
                else:
                    # Default progress reporting
                    if attempts % 6 == 0:  # Every minute if interval=10
                        elapsed = attempts * wait_interval
                        print(
                            f"{operation_name} in progress... "
                            f"({elapsed}s elapsed, status: {result.status})"
                        )

                # Check if complete
                if result.is_finished:
                    if result.is_failed:
                        error_msg = result.error_message or "Operation failed"
                        logger.error(f"{operation_name} failed: {error_msg}")
                        return WaitResult(
                            status_data=result.raw_data,
                            duration=self._extract_server_duration(result.raw_data),
                            success=False,
                            error_message=error_msg,
                        )

                    # Success!
                    duration = self._extract_server_duration(result.raw_data)
                    if duration:
                        logger.info(
                            "%s completed successfully (%.2fs)",
                            operation_name,
                            duration,
                        )
                        print(f"\n{operation_name} completed successfully " f"({duration:.1f}s)")
                    else:
                        logger.info("%s completed successfully", operation_name)
                        print(f"\n{operation_name} completed successfully")

                    return WaitResult(
                        status_data=result.raw_data,
                        duration=duration,
                        success=True,
                    )

                # Not complete yet, wait
                if attempts < max_tries:
                    time.sleep(wait_interval)

            except UnsupportedStatusCheck:
                # This version doesn't support status checking
                # Re-raise so caller can handle
                raise
            except Exception as e:
                logger.warning(
                    f"Error checking {operation_name} status " f"(attempt {attempts}): {e}"
                )
                if attempts >= max_tries:
                    raise ProcessError(f"Failed to check {operation_name} status: {e}") from e
                time.sleep(wait_interval)

        # Timeout
        timeout_seconds = max_tries * wait_interval
        raise ProcessTimeoutError(
            f"{operation_name} did not complete within "
            f"{timeout_seconds}s ({max_tries} attempts)"
        )

    def _extract_server_duration(self, raw_data: Dict[str, Any]) -> Optional[float]:
        """
        Extract actual process duration from server timestamps.

        This attempts to calculate server-side duration from
        started/finished timestamps if available in the response.

        Args:
            raw_data: Raw response data from the API

        Returns:
            float: Server-side duration in seconds, or None if unavailable
        """
        if not isinstance(raw_data, dict):
            return None

        # Check if this is a git operation response format
        # Git responses look like: {"data": "FINISHED"}
        if len(raw_data) == 1 and "data" in raw_data and isinstance(raw_data["data"], str):
            logger.debug("Git operation detected - no server duration available")
            return None

        started = raw_data.get("started")
        finished = raw_data.get("finished")

        if not started or not finished:
            return None

        try:
            # Parse timestamps in format "2025-08-08 00:43:31"
            started_dt = datetime.strptime(started, "%Y-%m-%d %H:%M:%S")
            finished_dt = datetime.strptime(finished, "%Y-%m-%d %H:%M:%S")

            server_duration = (finished_dt - started_dt).total_seconds()
            logger.debug(
                "Extracted server duration: %.2fs " "(started: %s, finished: %s)",
                server_duration,
                started,
                finished,
            )
            return server_duration

        except (ValueError, TypeError) as e:
            logger.debug("Could not parse server timestamps: %s", e)
            return None
