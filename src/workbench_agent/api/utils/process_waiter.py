"""
Process waiting data structures.

This module defines standard data structures used throughout the waiting
infrastructure. These classes provide consistent interfaces for status
checking and wait result reporting.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class StatusResult:
    """
    Result from a status check operation.

    This is the standardized format that status checkers return to indicate
    the current state of an async operation. It provides all information
    needed by the waiting infrastructure to determine next steps.

    Attributes:
        status: Normalized status string (e.g., "FINISHED", "RUNNING",
            "QUEUED", "FAILED")
        raw_data: Original response data from the API
        is_finished: True if operation has completed (success or failure)
        is_failed: True if operation failed
        error_message: Optional error message if operation failed
        progress_info: Optional progress information (percentage, files, etc.)
    """

    status: str
    raw_data: Dict[str, Any]
    is_finished: bool = False
    is_failed: bool = False
    error_message: Optional[str] = None
    progress_info: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Auto-calculate derived fields from status and raw_data."""
        normalized_status = self.status.upper()

        # Auto-detect failure (check this first since failed states are also finished)
        if not self.is_failed:
            self.is_failed = normalized_status in {
                "FAILED",
                "CANCELLED",
                "ERROR",
            }

        # Auto-detect completion (includes both success and failure states)
        if not self.is_finished:
            self.is_finished = normalized_status in {
                "FINISHED",
                "FAILED",
                "CANCELLED",
                "ERROR",
            }

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


@dataclass
class WaitResult:
    """
    Result from a waiting operation.

    This structure encapsulates the outcome of waiting for an async
    operation to complete, including final status, duration, and any
    error information.

    Attributes:
        status_data: Final status data from the completed operation
        duration: Server-side duration in seconds (if available)
        success: True if operation completed successfully
        error_message: Error message if operation failed
    """

    status_data: Dict[str, Any]
    duration: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
