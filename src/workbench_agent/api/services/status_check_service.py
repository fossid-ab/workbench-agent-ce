"""
StatusCheckService - Status checking for async Workbench operations.

This service provides specialized status checking methods for different
operation types. Each operation has its own dedicated method that knows
how to extract and normalize status from that operation's specific
response format.

The service focuses purely on status checking - waiting logic is handled
by WaitingService which composes this service.

Architecture:
    WaitingService → StatusCheckService → Clients (ScansClient, ProjectsClient)
"""
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Union

from workbench_agent.api.utils.process_waiter import StatusResult

logger = logging.getLogger("workbench-agent")


class StatusCheckService:
    """
    Service for checking status of async Workbench operations.
    
    This service provides specialized status checking methods for each
    operation type. It handles the complexity of different response
    formats and normalizes them into consistent StatusResult objects.
    
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
        >>> # Check scan status
        >>> result = service.check_scan_status("scan_123")
        >>> print(result.status)  # "RUNNING"
        >>> print(result.is_finished)  # False
        >>> 
        >>> # Check git clone status
        >>> result = service.check_git_clone_status("scan_123")
        >>> print(result.is_finished)  # True
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
        
        Normalization rules:
        - "NOT STARTED" → "FINISHED" (idle state)
        - "NOT FINISHED" → "RUNNING" (in progress)
        - "FINISHED" → "FINISHED" (completed)
        - Extract from 'data' field (the git clone status string)
        - If 'data' key missing, treat as "UNKNOWN"
        
        Args:
            data: Response data dict (clients normalize string responses
                to {"data": <status_string>})
            
        Returns:
            Normalized uppercase status string
        """
        try:
            if isinstance(data, str):
                raw_status = data.upper()
            elif isinstance(data, dict):
                # Extract status from 'data' field (contains the git clone status string)
                raw_status = str(data.get("data", "UNKNOWN")).upper()
            else:
                logger.warning(
                    f"Unexpected data type for git status: {type(data)}"
                )
                return "ACCESS_ERROR"
            
            # CRITICAL: Treat "NOT STARTED" as idle/finished state
            # A "NOT STARTED" process hasn't started yet, so it's
            # effectively idle
            if raw_status == "NOT STARTED":
                logger.debug(
                    "Git operation status is NOT STARTED - "
                    "treating as idle"
                )
                return "FINISHED"
            
            # Normalize "NOT FINISHED" to "RUNNING" for consistency
            if raw_status == "NOT FINISHED":
                logger.debug(
                    "Git operation status is NOT FINISHED - "
                    "treating as running"
                )
                return "RUNNING"
            
            return raw_status
        
        except Exception as e:
            logger.warning(f"Error processing git status data: {e}")
            return "ACCESS_ERROR"
    
    def _standard_scan_status_accessor(
        self, data: Dict[str, Any]
    ) -> str:
        """
        Status accessor for standard scan operations.
        
        Standard scan operations have complex response formats with
        different status indicators. This method handles multiple status
        sources and provides consistent normalization.
        
        Status Priority Order:
        1. progress_state (for REPORT_GENERATION operations)
        2. is_finished flag (boolean completion indicator)
        3. status field (standard operations)
        4. Fallback to "UNKNOWN"
        
        Normalization rules:
        - "NEW" → "FINISHED" (idle state)
        - is_finished=1/true → "FINISHED"
        - All statuses uppercased
        
        Args:
            data: Response data dictionary from scans->check_status
            
        Returns:
            Normalized uppercase status string
        """
        try:
            # Check progress_state first (used by REPORT_GENERATION)
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()
                
                # CRITICAL: Treat "NEW" as idle/finished state
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Scan progress_state is NEW - treating as idle"
                    )
                    return "FINISHED"
                
                return progress_state_upper
            
            # Check is_finished flag (boolean completion indicator)
            is_finished = data.get("is_finished")
            if is_finished is not None:
                # Handle both boolean and string representations
                if (isinstance(is_finished, bool) and is_finished) or (
                    isinstance(is_finished, str) and
                    is_finished.lower() in ("1", "true")
                ):
                    return "FINISHED"
                # If is_finished exists but is False/0, continue checking
            
            # Fall back to status field (standard operations)
            status = data.get("status")
            if status:
                status_upper = str(status).upper()
                
                # CRITICAL: Treat "NEW" as idle/finished state
                if status_upper == "NEW":
                    logger.debug(
                        "Scan status is NEW - treating as idle"
                    )
                    return "FINISHED"
                
                return status_upper
            
            # No status information found
            logger.warning(
                f"No status information found in scan data: {data}"
            )
            return "UNKNOWN"
        
        except Exception as e:
            logger.warning(f"Error processing scan status data: {e}")
            return "ACCESS_ERROR"
    
    def _project_report_status_accessor(
        self, data: Dict[str, Any]
    ) -> str:
        """
        Status accessor for project report operations.
        
        Project report operations use a simpler response format with
        just 'progress_state'. Unlike scan operations, they don't have
        'is_finished' flags or complex status structures.
        
        Normalization rules:
        - "NEW" → "FINISHED" (idle state)
        - progress_state uppercased
        
        Args:
            data: Response data from projects->check_status
            
        Returns:
            Normalized uppercase status string
        """
        try:
            # Project reports primarily use progress_state field
            progress_state = data.get("progress_state")
            if progress_state:
                progress_state_upper = str(progress_state).upper()
                
                # CRITICAL: Treat "NEW" as idle/finished state
                if progress_state_upper == "NEW":
                    logger.debug(
                        "Project report progress_state is NEW - "
                        "treating as idle"
                    )
                    return "FINISHED"
                
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
    # SPECIALIZED STATUS CHECKING METHODS
    # =====================================================================
    
    # --- GIT OPERATIONS ---
    
    def check_git_clone_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a Git clone operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with git clone status information
        """
        # Get raw status data from the API (always returns dict)
        status_data = self._scans.check_status_download_content_from_git(
            scan_code
        )
        
        # Extract and normalize status
        normalized_status = self._git_status_accessor(status_data)
        
        # Create standardized result
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    # --- SCAN OPERATIONS ---
    
    def check_scan_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a KB scan operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with scan status information
        """
        status_data = self._scans.check_status(scan_code, "SCAN")
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_dependency_analysis_status(
        self, scan_code: str
    ) -> StatusResult:
        """
        Check the status of a dependency analysis operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with dependency analysis status information
        """
        status_data = self._scans.check_status(
            scan_code, "DEPENDENCY_ANALYSIS"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_extract_archives_status(
        self, scan_code: str
    ) -> StatusResult:
        """
        Check the status of an archive extraction operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with archive extraction status information
        """
        status_data = self._scans.check_status(
            scan_code, "EXTRACT_ARCHIVES"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_report_import_status(self, scan_code: str) -> StatusResult:
        """
        Check the status of a report import operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with report import status information
        """
        status_data = self._scans.check_status(
            scan_code, "REPORT_IMPORT"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    # --- NOTICE EXTRACTION OPERATIONS ---
    
    def check_notice_extract_file_status(
        self, scan_code: str
    ) -> StatusResult:
        """
        Check the status of a notice file extraction operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with notice extract file status information
        """
        status_data = self._scans.check_status(
            scan_code, "NOTICE_EXTRACT_FILE"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_notice_extract_component_status(
        self, scan_code: str
    ) -> StatusResult:
        """
        Check the status of a notice component extraction operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with notice extract component status
        """
        status_data = self._scans.check_status(
            scan_code, "NOTICE_EXTRACT_COMPONENT"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_notice_extract_aggregate_status(
        self, scan_code: str
    ) -> StatusResult:
        """
        Check the status of a notice aggregate extraction operation.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            StatusResult with notice extract aggregate status
        """
        status_data = self._scans.check_status(
            scan_code, "NOTICE_EXTRACT_AGGREGATE"
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    # --- REPORT OPERATIONS ---
    
    def check_scan_report_status(
        self, scan_code: str, process_id: int
    ) -> StatusResult:
        """
        Check the status of a scan report generation operation.
        
        Args:
            scan_code: Code of the scan
            process_id: Process ID of the report generation
            
        Returns:
            StatusResult with scan report generation status
        """
        status_data = self._scans.check_status(
            scan_code, "REPORT_GENERATION", process_id=str(process_id)
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    def check_project_report_status(
        self, process_id: int, project_code: str
    ) -> StatusResult:
        """
        Check the status of a project report generation operation.
        
        Args:
            process_id: Process ID of the report generation
            project_code: Code of the project (for logging)
            
        Returns:
            StatusResult with project report generation status
        """
        # Call the projects API for project report status
        raw_status_data = self._projects.check_project_report_status(
            process_id=int(process_id), project_code=project_code
        )
        normalized_status = self._project_report_status_accessor(
            raw_status_data
        )
        
        return StatusResult(
            status=normalized_status,
            raw_data=raw_status_data,
        )
    
    # --- DELETE OPERATIONS ---
    
    def check_delete_scan_status(
        self, scan_code: str, process_id: int
    ) -> StatusResult:
        """
        Check the status of a scan deletion operation.
        
        Args:
            scan_code: Code of the scan
            process_id: Process ID of the delete operation
            
        Returns:
            StatusResult with delete scan status information
        """
        status_data = self._scans.check_status(
            scan_code, "DELETE_SCAN", process_id=str(process_id)
        )
        normalized_status = self._standard_scan_status_accessor(status_data)
        
        return StatusResult(
            status=normalized_status,
            raw_data=status_data,
        )
    
    # =====================================================================
    # UTILITY METHODS
    # =====================================================================
    
    def extract_server_duration(
        self, raw_data: Dict[str, Any]
    ) -> Optional[float]:
        """
        Extract actual process duration from server timestamps.
        
        This method only works for scan operations that have started/
        finished timestamps. Git operations use a different response
        format and don't provide duration information.
        
        Args:
            raw_data: Raw response data from the API
            
        Returns:
            Server-side duration in seconds, or None if unavailable
        """
        if not isinstance(raw_data, dict):
            return None
        
        # Check if this is a git operation response format
        # Git responses look like: {"data": "FINISHED"}
        if (len(raw_data) == 1 and "data" in raw_data and
                isinstance(raw_data["data"], str)):
            logger.debug(
                "Git operation detected - no server duration available"
            )
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
                f"Extracted server duration: {server_duration:.2f}s "
                f"(started: {started}, finished: {finished})"
            )
            return server_duration
        
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse server timestamps: {e}")
            return None
