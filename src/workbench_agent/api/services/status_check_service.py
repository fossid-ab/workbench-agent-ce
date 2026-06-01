"""
StatusCheckService - Status checking and waiting for Workbench processes.

This service provides specialized status checking methods for different
processes with optional waiting. Each status checker has its own
method that knows how to extract a normalized status from that
operation's specific response format.

With wait=True, the service polls until the operation reaches a terminal
state (FINISHED, FAILED, or CANCELLED).

Architecture:
    Handler → StatusCheckService → Clients (ScansClient, ProjectsClient)
"""

import logging
import time
from typing import Any, Dict, Union

from workbench_agent.api.exceptions import UnsupportedStatusCheck
from workbench_agent.api.utils.process_waiter import (
    StatusResult,
    wait_for_completion,
)

logger = logging.getLogger("workbench-agent")


class StatusCheckService:
    """
    Service for checking status and waiting for async Workbench operations.

    This service provides specialized status checking methods for each
    operation type. It handles the complexity of different response
    formats and normalizes them into consistent StatusResult objects.

    With wait=True, methods poll until the operation reaches a terminal
    state (FINISHED, FAILED, or CANCELLED) and return StatusResult with
    duration populated.

    Six-State Model:
    - NEW: Operation hasn't been requested yet (idle)
    - QUEUED: Operation requested, waiting to start (active)
    - RUNNING: Operation actively running (active)
    - FINISHED: Operation completed successfully (terminal)
    - FAILED: Operation failed (terminal)
    - CANCELLED: Operation was cancelled (terminal)

    Supported Operations:
    - Git clone
    - KB scan
    - Dependency analysis
    - Archive extraction
    - Report import
    - Report generation (scan and project)

    Example:
        >>> service = StatusCheckService(scans_client, projects_client)
        >>>
        >>> # Check scan status (one-time check)
        >>> result = service.check_scan_status("scan_123")
        >>> print(result.status)  # "RUNNING"
        >>> print(result.is_active)  # True
        >>>
        >>> # Wait for scan to complete
        >>> result = service.check_scan_status("scan_123", wait=True)
        >>> print(result.status)  # "FINISHED"
        >>> print(result.success)  # True
        >>> print(result.duration)  # 45.2 (seconds)
    """

    def __init__(self, scans_client, projects_client):
        """
        Initialize StatusCheckService.

        Args:
            scans_client: ScansClient for scan-related status checks
            projects_client: ProjectsClient for project report checks
        """
        self._scans = scans_client
        self._projects = projects_client
        logger.debug("StatusCheckService initialized")

    # =====================================================================
    # STATUS ACCESSOR METHODS
    # =====================================================================

    def _git_status_accessor(
        self, data: Union[Dict[str, Any], str]
    ) -> str:
        """
        Status accessor for git clone operations.

        Git clone operations have a response format where the API wrapper
        returns {"status": "1", "data": "NOT FINISHED", ...}, and the client
        normalizes string responses to {"data": "NOT FINISHED"}.

        The actual git clone status is in the 'data' field as a string:
        - "NOT STARTED" - operation hasn't started yet
        - "NOT FINISHED" - operation is in progress
        - "FINISHED" - operation completed

        Normalization rules (six-state model):
        - "NOT STARTED" → "NEW" (operation not requested)
        - "NOT FINISHED" → "RUNNING" (in progress)
        - "FINISHED" → "FINISHED" (completed)
        - Extract from 'data' field (the git clone status string)
        - If 'data' key missing, treat as "UNKNOWN"

        Args:
            data: Response data dict (clients normalize string responses
                to {"data": <status_string>})

        Returns:
            Normalized status string (NEW, QUEUED, RUNNING, FINISHED,
            FAILED, CANCELLED)
        """
        try:
            if isinstance(data, str):
                raw_status = data.upper()
            elif isinstance(data, dict):
                # Extract status from 'data' field (contains the clone status)
                raw_status = str(data.get("data", "UNKNOWN")).upper()
            else:
                raise ValueError(f"Unexpected git status: {type(data)}")

            # Treat "NOT STARTED" as NEW (process hasn't been requested)
            if raw_status == "NOT STARTED":
                logger.debug(
                    "Git operation status is NOT STARTED - "
                    "treating as NEW"
                )
                return "NEW"

            # Normalize "NOT FINISHED" to "RUNNING" for consistency
            if raw_status == "NOT FINISHED":
                logger.debug(
                    "Git operation status is NOT FINISHED - "
                    "treating as RUNNING"
                )
                return "RUNNING"

            return raw_status

        except Exception as e:
            logger.warning(f"Error processing git status data: {e}")
            return "ACCESS_ERROR"

    def _standard_scan_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Status accessor for standard scan operations.

        Standard scan operations have complex response formats with
        different status indicators. This method handles multiple status
        sources and provides consistent normalization to the six-state model.

        Status Priority Order:
        1. progress_state (for REPORT_GENERATION operations)
        2. is_finished flag (boolean completion indicator)
        3. status field (standard operations)
        4. Fallback to "UNKNOWN"

        Six-State Normalization:
        - "NEW" → "NEW" (preserve - operation not requested)
        - "QUEUED", "PENDING" → "QUEUED"
        - "RUNNING", "IN_PROGRESS" → "RUNNING"
        - "FINISHED", "COMPLETE" → "FINISHED"
        - "FAILED", "ERROR" → "FAILED"
        - "CANCELLED" → "CANCELLED"
        - is_finished=true + non-failure → "FINISHED"
        - is_finished=true + failure → "FAILED" or "CANCELLED"

        Args:
            data: Response data dictionary from scans->check_status

        Returns:
            Normalized status string (NEW, QUEUED, RUNNING, FINISHED,
            FAILED, CANCELLED)
        """
        try:
            # Check progress_state first (used by REPORT_GENERATION)
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()
                # Preserve NEW state (don't normalize to FINISHED)
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Scan progress_state is NEW - preserving NEW state"
                    )
                    return "NEW"
                return progress_state_upper

            # Check is_finished flag (boolean completion indicator)
            is_finished = data.get("is_finished")
            if is_finished is not None:
                # Handle both boolean and string representations
                if (isinstance(is_finished, bool) and is_finished) or (
                    isinstance(is_finished, str)
                    and is_finished.lower() in ("1", "true")
                ):
                    # is_finished=true, but we need to check if it's a failure
                    status_field = data.get("status", "").upper()
                    if status_field in {"FAILED", "ERROR"}:
                        return "FAILED"
                    elif status_field == "CANCELLED":
                        return "CANCELLED"
                    else:
                        return "FINISHED"
                # If is_finished exists but is False/0, continue checking

            # Fall back to status field (standard operations)
            status = data.get("status")
            if status:
                status_upper = str(status).upper()
                # Preserve NEW state (don't normalize to FINISHED)
                if status_upper == "NEW":
                    logger.debug("Scan status is NEW - preserving NEW state")
                    return "NEW"
                return status_upper

            # No status information found
            logger.warning(
                f"No status information found in scan data: {data}"
            )
            return "UNKNOWN"

        except Exception as e:
            logger.warning(f"Error processing scan status data: {e}")
            return "ACCESS_ERROR"

    def _project_report_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Status accessor for project report operations.

        Project report operations use a simpler response format with
        just 'progress_state'. Unlike scan operations, they don't have
        'is_finished' flags or complex status structures.

        Six-State Normalization:
        - "NEW" → "NEW" (preserve - operation not requested)
        - progress_state uppercased for other states

        Args:
            data: Response data from projects->check_status

        Returns:
            Normalized status string (NEW, QUEUED, RUNNING, FINISHED,
            FAILED, CANCELLED)
        """
        try:
            # Project reports primarily use progress_state field
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()
                # Preserve NEW state (don't normalize to FINISHED)
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Project report progress_state is NEW - "
                        "preserving NEW state"
                    )
                    return "NEW"
                return progress_state_upper

            # No progress_state found
            logger.warning(
                f"No progress_state in project report data: {data}"
            )
            return "UNKNOWN"

        except Exception as e:
            logger.warning(
                f"Error processing project report status data: {e}"
            )
            return "ACCESS_ERROR"

    # =====================================================================
    # PRIVATE STATUS COLLECTION METHODS
    # =====================================================================

    def _get_git_clone_status(self, scan_code: str) -> StatusResult:
        """Collect git clone status without waiting."""
        status_data = self._scans.check_status_download_content_from_git(
            scan_code
        )
        normalized_status = self._git_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_scan_status(self, scan_code: str) -> StatusResult:
        """Collect KB scan status without waiting."""
        status_data = self._scans.check_status(scan_code, "SCAN")
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_dependency_analysis_status(
        self, scan_code: str
    ) -> StatusResult:
        """Collect dependency analysis status without waiting."""
        status_data = self._scans.check_status(
            scan_code, "DEPENDENCY_ANALYSIS"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_extract_archives_status(self, scan_code: str) -> StatusResult:
        """Collect archive extraction status without waiting."""
        status_data = self._scans.check_status(scan_code, "EXTRACT_ARCHIVES")
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_report_import_status(self, scan_code: str) -> StatusResult:
        """Collect report import status without waiting."""
        status_data = self._scans.check_status(scan_code, "REPORT_IMPORT")
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_scan_report_status(
        self, scan_code: str, process_id: int
    ) -> StatusResult:
        """Collect scan report generation status without waiting."""
        status_data = self._scans.check_status(
            scan_code, "REPORT_GENERATION", process_id=str(process_id)
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _get_project_report_status(
        self, process_id: int, project_code: str
    ) -> StatusResult:
        """Collect project report generation status without waiting."""
        raw_status_data = self._projects.check_status(
            process_id=int(process_id), process_type="REPORT_GENERATION"
        )
        normalized_status = self._project_report_status_accessor(
            raw_status_data
        )
        return StatusResult(
            status=normalized_status,
            raw_data=raw_status_data,
        )

    def _get_delete_scan_status(
        self, scan_code: str, process_id: int
    ) -> StatusResult:
        """Collect scan deletion status without waiting.

        Uses ``process_id`` and omits ``scan_code`` in the payload.
        After deletion the scan no longer exists and including ``scan_code``
        causes ``row_not_found`` on ``check_status``.
        """
        status_data = self._scans.check_status(
            None, "DELETE_SCAN", process_id=process_id
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    # =====================================================================
    # PUBLIC STATUS CHECKING METHODS (with optional waiting)
    # =====================================================================

    # --- GIT OPERATIONS ---

    def check_git_clone_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 3,
    ) -> StatusResult:
        """
        Check the status of a Git clone operation.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 3, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_git_clone_status(scan_code),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Git Clone '{scan_code}'",
            )

        return self._get_git_clone_status(scan_code)

    # --- SCAN OPERATIONS ---

    def check_scan_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
        should_track_files: bool = False,
    ) -> StatusResult:
        """
        Check the status of a KB scan operation.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)
            should_track_files: Show detailed file progress when waiting
                (default: False, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated and
            status will be terminal (FINISHED, FAILED, or CANCELLED).
        """
        if wait:
            progress_callback = None
            if should_track_files:
                progress_callback = self._create_scan_progress_callback(
                    scan_code
                )

            return wait_for_completion(
                check_function=lambda: self._get_scan_status(scan_code),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"KB Scan '{scan_code}'",
                progress_callback=progress_callback,
            )

        return self._get_scan_status(scan_code)

    def check_dependency_analysis_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a dependency analysis operation.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_dependency_analysis_status(
                    scan_code
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Dependency Analysis '{scan_code}'",
            )

        return self._get_dependency_analysis_status(scan_code)

    def check_extract_archives_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of an archive extraction operation.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        try:
            if wait:
                return wait_for_completion(
                    check_function=lambda: self._get_extract_archives_status(
                        scan_code
                    ),
                    max_tries=wait_retry_count,
                    wait_interval=wait_retry_interval,
                    operation_name=f"Extract Archives '{scan_code}'",
                )

            return self._get_extract_archives_status(scan_code)
        except UnsupportedStatusCheck:
            # Graceful degradation for Workbench < 25.1.0
            if wait:
                logger.info(
                    "Archive extraction status checking not supported on "
                    "this Workbench version, using fallback wait (5 seconds)"
                )
                print(
                    "Using fallback wait for archive extraction "
                    "(5 seconds)..."
                )
                time.sleep(5)
                return StatusResult(
                    status="FINISHED",
                    raw_data={},
                    duration=None,
                    success=True,
                )
            else:
                # Re-raise if not waiting
                raise

    def check_report_import_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a report import operation.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_report_import_status(
                    scan_code
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Report Import '{scan_code}'",
            )

        return self._get_report_import_status(scan_code)

    # --- NOTICE EXTRACTION OPERATIONS ---

    def _get_notice_extract_status_oneshot(
        self, scan_code: str, notice_type: str
    ) -> StatusResult:
        """Single check_status poll for a NOTICE_EXTRACT_* process type."""
        status_data = self._scans.check_status(scan_code, notice_type)
        normalized_status = self._standard_scan_status_accessor(status_data)
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )

    def _check_notice_extract_status(
        self,
        scan_code: str,
        notice_type: str,
        wait: bool,
        wait_retry_count: int,
        wait_retry_interval: int,
    ) -> StatusResult:
        """Shared wait / no-wait implementation for notice extract status."""
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_notice_extract_status_oneshot(
                    scan_code, notice_type
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=(
                    f"Notice Extract '{notice_type}' on '{scan_code}'"
                ),
            )
        return self._get_notice_extract_status_oneshot(
            scan_code, notice_type
        )

    def check_notice_extract_file_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a notice file extraction operation.

        Uses ``scans -> check_status`` with type ``NOTICE_EXTRACT_FILE``.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10)

        Returns:
            StatusResult with notice extract file status information.
            When wait=True, duration will be populated.
        """
        return self._check_notice_extract_status(
            scan_code,
            "NOTICE_EXTRACT_FILE",
            wait,
            wait_retry_count,
            wait_retry_interval,
        )

    def check_notice_extract_component_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a notice component extraction operation.

        Uses ``scans -> check_status`` with type ``NOTICE_EXTRACT_COMPONENT``.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10)

        Returns:
            StatusResult with notice extract component status.
            When wait=True, duration will be populated.
        """
        return self._check_notice_extract_status(
            scan_code,
            "NOTICE_EXTRACT_COMPONENT",
            wait,
            wait_retry_count,
            wait_retry_interval,
        )

    def check_notice_extract_aggregate_status(
        self,
        scan_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a notice aggregate extraction operation.

        Uses ``scans -> check_status`` with type ``NOTICE_EXTRACT_AGGREGATE``.

        Args:
            scan_code: Code of the scan to check
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10)

        Returns:
            StatusResult with notice extract aggregate status.
            When wait=True, duration will be populated.
        """
        return self._check_notice_extract_status(
            scan_code,
            "NOTICE_EXTRACT_AGGREGATE",
            wait,
            wait_retry_count,
            wait_retry_interval,
        )

    # --- REPORT OPERATIONS ---

    def check_scan_report_status(
        self,
        scan_code: str,
        process_id: int,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a scan report generation operation.

        Args:
            scan_code: Code of the scan
            process_id: Process ID of the report generation
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_scan_report_status(
                    scan_code, process_id
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Scan Report '{scan_code}'",
            )

        return self._get_scan_report_status(scan_code, process_id)

    def check_project_report_status(
        self,
        process_id: int,
        project_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of a project report generation operation.

        Args:
            process_id: Process ID of the report generation
            project_code: Code of the project (for logging)
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 10, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_project_report_status(
                    process_id, project_code
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Project Report '{project_code}'",
            )

        return self._get_project_report_status(process_id, project_code)

    # --- DELETE OPERATIONS ---

    def check_delete_scan_status(
        self,
        scan_code: str,
        process_id: int,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 2,
    ) -> StatusResult:
        """
        Check the status of a scan deletion operation.

        Args:
            scan_code: Code of the scan
            process_id: Process ID of the delete operation
            wait: If True, wait until operation reaches terminal state
            wait_retry_count: Maximum attempts when waiting (default: 360,
                only used if wait=True)
            wait_retry_interval: Seconds between attempts when waiting
                (default: 2, only used if wait=True)

        Returns:
            StatusResult. When wait=True, duration will be populated.
        """
        if wait:
            return wait_for_completion(
                check_function=lambda: self._get_delete_scan_status(
                    scan_code, process_id
                ),
                max_tries=wait_retry_count,
                wait_interval=wait_retry_interval,
                operation_name=f"Delete Scan '{scan_code}'",
            )

        return self._get_delete_scan_status(scan_code, process_id)

    # =====================================================================
    # WAITING INFRASTRUCTURE
    # =====================================================================

    def _create_scan_progress_callback(self, scan_code: str):
        """
        Create a stateful progress callback for scan file tracking.

        This creates a callback that tracks and displays scan progress
        with printing that shows details on changes or periodic intervals.

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
