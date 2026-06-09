"""
Process waiting data structures and utilities.

This module is used throughout waiting infrastructure to provide
interfaces for status checking and wait result reporting.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("workbench-agent")


@dataclass
class StatusResult:
    """
    Result from a status check or waiting operation.

    This unified result type represents the state of an async operation,
    whether from a one-time status check or after waiting for completion.

    Six-State Model:
        - NEW: Operation hasn't been requested yet
        - QUEUED: Operation requested, waiting to start
        - RUNNING: Operation actively running
        - FINISHED: Operation completed successfully
        - FAILED: Operation failed
        - CANCELLED: Operation was cancelled

    Attributes:
        status: Normalized status string (NEW, QUEUED, RUNNING, FINISHED,
            FAILED, CANCELLED)
        raw_data: Original response data from the API
        duration: Server-side duration in seconds (only set after waiting)
        is_finished: True if operation has completed (success or failure)
        is_failed: True if operation failed or was cancelled
        success: True if operation completed successfully (backward compat)
        error_message: Optional error message if operation failed
        progress_info: Optional progress information (percentage, files, etc.)
        is_idle: True if operation is idle (safe to start new operations)
        is_active: True if operation is active (QUEUED or RUNNING)
        is_terminal: True if operation is done (FINISHED, FAILED, CANCELLED)
    """

    status: str
    raw_data: Dict[str, Any]
    duration: Optional[float] = None
    is_finished: bool = False
    is_failed: bool = False
    success: bool = True
    error_message: Optional[str] = None
    progress_info: Optional[Dict[str, Any]] = None
    is_idle: bool = False
    is_active: bool = False
    is_terminal: bool = False

    def __post_init__(self):
        """Auto-calculate derived fields from status and raw_data."""
        normalized_status = self.status.upper()

        # Normalize to one of the six states
        if normalized_status in {"FAILED", "ERROR"}:
            self.status = "FAILED"
            self.is_failed = True
            self.is_finished = True
        elif normalized_status == "CANCELLED":
            self.status = "CANCELLED"
            self.is_failed = True  # CANCELLED is a form of failure
            self.is_finished = True
        elif normalized_status in {"FINISHED", "COMPLETE"}:
            # Only FINISHED if not already marked as failed
            if not self.is_failed:
                self.status = "FINISHED"
                self.is_finished = True
                self.is_failed = False
            else:
                # Already marked as failed, keep as FAILED
                self.status = "FAILED"
                self.is_finished = True
        elif normalized_status in {"RUNNING", "IN_PROGRESS"}:
            self.status = "RUNNING"
            self.is_finished = False
            self.is_failed = False
        elif normalized_status in {"QUEUED", "PENDING"}:
            self.status = "QUEUED"
            self.is_finished = False
            self.is_failed = False
        elif normalized_status == "NEW":
            self.status = "NEW"
            self.is_finished = False
            self.is_failed = False
        else:
            # Unknown - default to RUNNING for safety
            self.status = "RUNNING"
            self.is_finished = False
            self.is_failed = False

        # Set helper properties
        self.is_idle = self.status in {
            "NEW",
            "FINISHED",
            "FAILED",
            "CANCELLED",
        }
        self.is_active = self.status in {"QUEUED", "RUNNING"}
        self.is_terminal = self.status in {
            "FINISHED",
            "FAILED",
            "CANCELLED",
        }

        # Set success flag (backward compatibility)
        if self.status in {"FAILED", "CANCELLED"}:
            self.success = False
        elif self.status == "FINISHED":
            self.success = True
        # NEW, QUEUED, RUNNING default to True

        # Auto-extract error message
        if self.is_failed and not self.error_message:
            self.error_message = self.raw_data.get(
                "error",
                self.raw_data.get("message", self.raw_data.get("info", "")),
            )

        # Auto-extract progress information
        if not self.progress_info:
            progress_data = {}
            for key in [
                "state",
                "current_step",
                "percentage_done",
                "total_files",
                "current_file",
            ]:
                if key in self.raw_data:
                    progress_data[key] = self.raw_data[key]
            self.progress_info = progress_data if progress_data else None


# =============================================================================
# WAITING INFRASTRUCTURE UTILITIES
# =============================================================================


def extract_server_duration(raw_data: Any) -> Optional[float]:
    """
    Extract process duration from server timestamps.

    This utility extracts server-side duration from started/finished
    timestamps in the response.

    Args:
        raw_data: Raw response data from the API

    Returns:
        Server-side duration in seconds, or None if unavailable
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
            "Extracted server duration: %.2fs (started: %s, finished: %s)",
            server_duration,
            started,
            finished,
        )
        return server_duration

    except (ValueError, TypeError) as e:
        logger.debug("Could not parse server timestamps: %s", e)
        return None


def wait_for_completion(
    check_function: Callable[[], StatusResult],
    max_tries: int,
    wait_interval: int,
    operation_name: str,
    progress_callback: Optional[Callable[[StatusResult, int, int], None]] = None,
) -> StatusResult:
    """
    Generic waiting engine for async operations.

    This is the core waiting infrastructure that handles retry logic,
    timeout detection, and progress reporting. Waits until the operation
    reaches a terminal state (FINISHED, FAILED, or CANCELLED).

    Args:
        check_function: Function that returns StatusResult when called
        max_tries: Maximum number of attempts before timeout
        wait_interval: Seconds to wait between attempts
        operation_name: Human-readable name for logging/messages
        progress_callback: Optional callback for custom progress
            reporting. Called with (StatusResult, attempt, max_tries).

    Returns:
        StatusResult with final terminal status and duration

    Raises:
        ProcessTimeoutError: If max_tries exceeded
        ProcessError: If status check fails (not operation failure)
        UnsupportedStatusCheck: If status check not supported

    Note:
        This function does NOT raise exceptions for FAILED or CANCELLED
        states. It returns StatusResult with success=False and appropriate
        status. Callers should check the result status or success flag.
    """
    # Import here to avoid circular imports
    from workbench_agent.api.exceptions import (
        ProcessError,
        ProcessTimeoutError,
        UnsupportedStatusCheck,
    )

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
                    logger.info(
                        "%s in progress... (%ss elapsed, status: %s)",
                        operation_name,
                        elapsed,
                        result.status,
                    )

                # Check if complete (terminal state)
            if result.is_terminal:
                # Extract server duration
                duration = extract_server_duration(result.raw_data)
                result.duration = duration

                if result.is_failed:
                    error_msg = result.error_message or "Operation failed"
                    logger.error(f"{operation_name} failed: {error_msg}")
                    return result

                # Success!
                if duration:
                    logger.info(
                        "%s completed successfully (%.2fs)",
                        operation_name,
                        duration,
                    )
                    logger.info(f"\n{operation_name} completed successfully " f"({duration:.1f}s)")
                else:
                    logger.info("%s completed successfully", operation_name)
                    logger.info(f"\n{operation_name} completed successfully")

                return result

            # Not complete yet, wait
            if attempts < max_tries:
                time.sleep(wait_interval)

        except UnsupportedStatusCheck:
            # This version doesn't support status checking
            # Re-raise so caller can handle
            raise
        except Exception as e:
            logger.warning(f"Error checking {operation_name} status " f"(attempt {attempts}): {e}")
            if attempts >= max_tries:
                raise ProcessError(f"Failed to check {operation_name} status: {e}") from e
            time.sleep(wait_interval)

    # Timeout
    timeout_seconds = max_tries * wait_interval
    raise ProcessTimeoutError(
        f"{operation_name} did not complete within " f"{timeout_seconds}s ({max_tries} attempts)"
    )
