"""
ScanOperationsService - Handles scan execution operations.

This service provides:
- Scan execution with validation and version awareness
- Archive extraction orchestration
- Dependency analysis orchestration

The service handles business logic and payload construction:
- Service layer: Payload building, orchestration
- Client layer: Raw HTTP API calls
"""

import logging
from typing import Optional

logger = logging.getLogger("workbench-agent")


class ScanOperationsService:
    """
    Service for scan execution operations.

    This service handles business logic for:
    - Running KB scans with ID reuse resolution
    - Extracting archives
    - Starting dependency analysis
    - ID reuse name→code resolution

    Architecture:
    - Service layer: Payload building, orchestration
    - Client layer: Raw HTTP API calls

    Example:
        >>> scan_ops = ScanOperationsService(scans_client, resolver_service)
        >>>
        >>> # Start a scan (ID reuse resolution happens automatically)
        >>> scan_ops.start_scan(
        ...     scan_code="scan_code",
        ...     limit=10,
        ...     sensitivity=6,
        ...     autoid_file_licenses=True,
        ...     id_reuse_project_name="MyProject"  # Resolved automatically
        ... )
        >>>
        >>> # Start archive extraction
        >>> scan_ops.start_archive_extraction(
        ...     scan_code="scan_code",
        ...     recursively_extract_archives=True,
        ...     jar_file_extraction=True
        ... )
    """

    def __init__(self, scans_client, resolver_service):
        """
        Initialize ScanOperationsService.

        Args:
            scans_client: ScansClient instance for raw API calls
            resolver_service: ResolverService instance for name→code resolution
        """
        self._scans = scans_client
        self._resolver = resolver_service
        logger.debug("ScanOperationsService initialized")

    # ===== PUBLIC API =====

    def start_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        autoid_file_licenses: bool,
        autoid_file_copyrights: bool,
        autoid_pending_ids: bool,
        delta_scan: bool,
        id_reuse_type: Optional[str] = None,
        id_reuse_specific_code: Optional[str] = None,
        run_dependency_analysis: Optional[bool] = None,
        replace_existing_identifications: bool = False,
        scan_failed_only: bool = False,
        full_file_only: bool = False,
        advanced_match_scoring: bool = True,
        match_filtering_threshold: Optional[int] = None,
        scan_host: Optional[str] = None,
    ):
        """
        Start a KB scan with resolved ID reuse parameters.

        This method converts Python-friendly parameter names/types to API
        format and delegates to ScansClient. ID reuse should be resolved
        beforehand using resolver.resolve_id_reuse().

        Args:
            scan_code: The code of the scan to run
            limit: Maximum number of results to consider
            sensitivity: Scan sensitivity level (0-10)
            autoid_file_licenses: Whether to auto-identify file licenses
            autoid_file_copyrights: Whether to auto-identify file copyrights
            autoid_pending_ids: Whether to auto-identify pending IDs
            delta_scan: Whether to run a delta scan
            id_reuse_type: Type of ID reuse ("any", "only_me",
                "specific_project", "specific_scan")
            id_reuse_specific_code: Code for specific_project/specific_scan
                reuse (if applicable)
            run_dependency_analysis: Whether to run dependency analysis
            replace_existing_identifications: Whether to replace existing IDs
            scan_failed_only: Whether to only scan files that failed
            full_file_only: Whether to return only full file matches
            advanced_match_scoring: Whether to use advanced match scoring
            match_filtering_threshold: Minimum snippet length for filtering
            scan_host: Specify which scan server to use

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> # Resolve ID reuse first
            >>> id_type, id_code = resolver.resolve_id_reuse(...)
            >>> # Start scan with Python-friendly parameter names
            >>> scan_ops.start_scan(
            ...     scan_code="SCAN123",
            ...     limit=10,
            ...     sensitivity=6,
            ...     autoid_file_licenses=True,
            ...     id_reuse_type=id_type,
            ...     id_reuse_specific_code=id_code
            ... )
        """
        logger.info(f"Starting scan for '{scan_code}'...")

        # Build payload with API field names and string conversion
        payload_data = {
            "scan_code": scan_code,
            "limit": str(limit),
            "sensitivity": str(sensitivity),
            "auto_identification_detect_declaration": (
                "1" if autoid_file_licenses else "0"
            ),
            "auto_identification_detect_copyright": (
                "1" if autoid_file_copyrights else "0"
            ),
            "auto_identification_resolve_pending_ids": (
                "1" if autoid_pending_ids else "0"
            ),
            "delta_only": "1" if delta_scan else "0",
            "replace_existing_identifications": (
                "1" if replace_existing_identifications else "0"
            ),
            "scan_failed_only": "1" if scan_failed_only else "0",
            "full_file_only": "1" if full_file_only else "0",
            "advanced_match_scoring": (
                "1" if advanced_match_scoring else "0"
            ),
        }

        # Add ID reuse parameters (already resolved)
        if id_reuse_type:
            payload_data["reuse_identification"] = "1"
            payload_data["identification_reuse_type"] = id_reuse_type
            if id_reuse_specific_code:
                payload_data["specific_code"] = id_reuse_specific_code

        # Add dependency analysis parameter if specified
        if run_dependency_analysis is not None:
            payload_data["run_dependency_analysis"] = (
                "1" if run_dependency_analysis else "0"
            )

        # Add match filtering threshold if specified
        if match_filtering_threshold is not None:
            payload_data["match_filtering_threshold"] = str(
                match_filtering_threshold
            )

        # Add scan_host parameter if provided
        if scan_host is not None:
            payload_data["scan_host"] = scan_host

        logger.debug(
            f"Built run scan payload with {len(payload_data)} parameters "
            f"for scan '{scan_code}'"
        )

        # Delegate to client for API call
        return self._scans.run(payload_data)

    def start_archive_extraction(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
        extract_to_directory: bool = False,
        filename: Optional[str] = None,
    ) -> bool:
        """
        Start archive extraction for a scan with validation.

        This method builds the payload and delegates to ScansClient.

        Args:
            scan_code: Code of the scan to extract archives for
            recursively_extract_archives: Whether to recursively extract
            jar_file_extraction: Whether to extract JAR files
            extract_to_directory: Whether to extract to a directory
                (default: False - extracts to flat structure)
            filename: Specific filename to extract (optional, extracts
                all if not specified)

        Returns:
            True if extraction was triggered successfully

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.info(f"Extracting archives for scan '{scan_code}'...")

        # Build payload
        payload_data = {
            "scan_code": scan_code,
            "recursively_extract_archives": (
                str(recursively_extract_archives).lower()
            ),
            "jar_file_extraction": str(jar_file_extraction).lower(),
            "extract_to_directory": "1" if extract_to_directory else "0",
        }

        # Add optional filename parameter if provided
        if filename is not None:
            payload_data["filename"] = filename

        logger.debug(
            f"Built extract archives payload with "
            f"{len(payload_data)} parameters for scan '{scan_code}'"
        )

        # Delegate to client
        return self._scans.extract_archives(payload_data)

    def start_da_only(self, scan_code: str):
        """
        Start dependency analysis only (without KB scan).

        Args:
            scan_code: Code of the scan to run dependency analysis for

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> scan_ops.start_da_only("SCAN123")
        """
        logger.info(f"Starting dependency analysis for '{scan_code}'...")

        payload_data = {
            "scan_code": scan_code,
            "import_only": "0",
        }

        logger.debug(
            f"Built dependency analysis payload for scan '{scan_code}'"
        )

        # Delegate to client
        return self._scans.run_dependency_analysis(payload_data)

    def start_da_import(self, scan_code: str):
        """
        Import dependency analysis results (import-only mode).

        This method imports pre-analyzed dependency analysis results
        without running the analysis.

        Args:
            scan_code: Code of the scan to import dependency analysis
                results for

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> scan_ops.start_da_import("SCAN123")
        """
        logger.info(
            f"Importing dependency analysis results for '{scan_code}'..."
        )

        payload_data = {
            "scan_code": scan_code,
            "import_only": "1",
        }

        logger.debug(
            f"Built dependency analysis import payload for scan '{scan_code}'"
        )

        # Delegate to client
        return self._scans.run_dependency_analysis(payload_data)

    def start_sbom_import(self, scan_code: str):
        """
        Start SBOM report import into a scan.

        This method delegates to the ScansClient import_report method.

        Args:
            scan_code: Code of the scan to import SBOM into

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> scan_ops.start_sbom_import("SCAN123")
        """
        logger.info(f"Starting SBOM import for '{scan_code}'...")
        return self._scans.import_report(scan_code)
