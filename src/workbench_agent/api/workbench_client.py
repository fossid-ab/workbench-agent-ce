"""
WorkbenchClient - Main API client using composition pattern.

This is the primary API client for interacting with FossID Workbench.
It uses composition to organize functionality into domain-specific clients
and orchestration services.

Usage:
    >>> from workbench_agent.api.workbench_client import (
    ...     WorkbenchClient
    ... )
    >>>
    >>> # Initialize client
    >>> workbench = WorkbenchClient(
    ...     api_url="https://workbench.example.com/api.php",
    ...     api_user="username",
    ...     api_token="token"
    ... )
    >>>
    >>> # Use domain clients for direct API operations
    >>> projects = workbench.projects.list_projects()
    >>> scan_info = workbench.scans.get_information(scan_code)
    >>> workbench.uploads.upload_scan_target(
    ...     scan_code, "/path/to/source"
    ... )
    >>>
    >>> # Use services for high-level orchestration
    >>> p_code, s_code, is_new = (
    ...     workbench.resolver.resolve_project_and_scan(
    ...         "MyProject", "MyScan", params
    ...     )
    ... )
    >>> workbench.scan_operations.start_scan(
    ...     scan_code, limit=10, sensitivity=6
    ... )
    >>> process_id = workbench.reports.generate_project_report(
    ...     project_code, "xlsx"
    ... )
"""

import logging

from packaging import version as packaging_version

from workbench_agent.api.clients import (
    DownloadClient,
    InternalClient,
    ProjectsClient,
    QuickScanClient,
    ScansClient,
    UploadsClient,
    VulnerabilitiesClient,
)
from workbench_agent.api.exceptions import CompatibilityError
from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.services import (
    ReportService,
    ResolverService,
    ResultsService,
    ScanOperationsService,
    StatusCheckService,
    WaitingService,
)

logger = logging.getLogger("workbench-agent")


class WorkbenchClient:
    """
    Main Workbench API client providing access to Workbench
    functionality through domain-specific clients and services:

    **Clients (Direct API operations):**
    - `projects`: Project management (list, create, update, reports)
    - `scans`: Scan operations (list, create, update, run, results)
    - `uploads`: File uploads (scan targets, DA, SBOM)
    - `downloads`: File downloads (reports, etc.)
    - `vulnerabilities`: Vulnerability queries
    - `quick_scan`: Quick file scanning
    - `internal`: Internal/config operations

    **Services (High-level orchestration):**
    - `resolver`: Resolve project/scan names to codes, create if needed
    - `status_check`: Check status of async operations (specialized methods)
    - `reports`: Report generation with validation and waiting
    - `results`: Fetch and aggregate scan results
    - `scan_operations`: Scan execution with standardized behavior
    - `waiting`: Convenient waiting methods for async operations

    Example:
        >>> workbench = WorkbenchClient(api_url, api_user, api_token)
        >>>
        >>> # Direct API operations via clients
        >>> all_projects = workbench.projects.list_projects()
        >>> scan_info = workbench.scans.get_information(scan_code)
        >>> workbench.uploads.upload_scan_target(scan_code, "./src")
        >>>
        >>> # High-level workflows via services
        >>> p_code, s_code, is_new = (
        ...     workbench.resolver.resolve_project_and_scan(
        ...         "MyProject", "MyScan", params
        ...     )
        ... )
        >>> process_id = workbench.reports.generate_project_report(
        ...     project_code, "xlsx"
        ... )
        >>> workbench.scan_operations.start_scan(
        ...     scan_code, limit=10, sensitivity=6
        ... )
        >>>
        >>> # Wait for operations to complete
        >>> result = workbench.waiting.wait_for_scan(scan_code)

    Note:
        This client is designed for a specific Workbench version range.
        Version compatibility is managed at the application level rather
        than through runtime version detection.
    """

    def __init__(
        self,
        api_url: str,
        api_user: str,
        api_token: str,
    ):
        """
        Initialize WorkbenchClient with composition-based architecture.

        The client automatically checks Workbench server version compatibility
        on initialization. The SDK version should correspond to the Workbench
        API version it supports.

        Args:
            api_url: URL to the Workbench API endpoint
                (e.g., https://server/api.php)
            api_user: API username
            api_token: API authentication token

        Raises:
            CompatibilityError: If Workbench version doesn't match SDK expectations

        Example:
            >>> # SDK checks server compatibility automatically
            >>> workbench = WorkbenchClient(
            ...     api_url="https://workbench.fossid.com/api.php",
            ...     api_user="my_username",
            ...     api_token="my_api_token"
            ... )
        """
        logger.info("Initializing WorkbenchClient (composition-based)")

        # Core infrastructure - BaseAPI handles all HTTP communication
        self._base_api = BaseAPI(api_url, api_user, api_token)
        logger.debug(f"BaseAPI initialized with URL: {self._base_api.api_url}")

        # Initialize InternalClient first (needed for version check)
        self.internal = InternalClient(self._base_api)

        # Check Workbench server version compatibility
        self._check_version_compatibility()

        # Initialize domain-specific clients
        # Each client handles a specific domain of operations
        logger.debug("Initializing API clients...")

        self.projects = ProjectsClient(self._base_api)
        self.scans = ScansClient(self._base_api)
        self.uploads = UploadsClient(self._base_api)
        self.downloads = DownloadClient(self._base_api)
        self.vulnerabilities = VulnerabilitiesClient(self._base_api)
        self.quick_scan = QuickScanClient(self._base_api)

        logger.debug("API clients initialized successfully")

        # Initialize orchestration services
        # Services coordinate multiple clients for complex workflows
        logger.debug("Initializing orchestration services...")

        self.resolver = ResolverService(projects_client=self.projects, scans_client=self.scans)

        self.status_check = StatusCheckService(
            scans_client=self.scans, projects_client=self.projects
        )

        self.reports = ReportService(
            projects_client=self.projects,
            scans_client=self.scans,
            downloads_client=self.downloads,
        )

        self.results = ResultsService(
            scans_client=self.scans, vulnerabilities_client=self.vulnerabilities
        )

        self.scan_operations = ScanOperationsService(
            scans_client=self.scans, resolver_service=self.resolver
        )

        self.waiting = WaitingService(status_check_service=self.status_check)

        logger.debug("Orchestration services initialized successfully")
        logger.info("WorkbenchClient initialization complete")

    # ===== PRIVATE METHODS =====

    def _check_version_compatibility(self) -> None:
        """
        Check that the Workbench server version is compatible with this SDK.

        This SDK version corresponds to Workbench API version and validates
        that the connected server is compatible.

        Raises:
            CompatibilityError: If Workbench version is incompatible
            ApiError: If version detection fails
            NetworkError: If connection fails

        Note:
            SDK versioning should match Workbench versioning. For example:
            - workbench-sdk 24.3.x → Workbench 24.3.x
            - workbench-sdk 25.1.x → Workbench 25.1.x
        """
        # This SDK version's minimum compatible Workbench version
        MINIMUM_VERSION = "24.3.0"

        try:
            logger.info("Checking Workbench server version compatibility...")
            config_data = self.internal.get_config()
            workbench_version = config_data.get("version", "Unknown")

            if workbench_version == "Unknown":
                raise CompatibilityError(
                    "Could not determine Workbench version. "
                    "Please ensure you are connected to a valid "
                    "Workbench instance.",
                    details={"config_data": config_data},
                )

            logger.debug(f"Detected Workbench server version: {workbench_version}")

            # Parse and compare versions
            try:
                # Handle version strings that might have extra info
                # (e.g., "24.3.0-beta", "2025.2.0#19347124129")
                # Extract just the version number part
                version_str = workbench_version.split()[0]  # Remove anything after space
                version_str = version_str.split("-")[0]  # Remove anything after dash
                version_str = version_str.split("#")[0]  # Remove build metadata after hash

                parsed_version = packaging_version.parse(version_str)
                min_version = packaging_version.parse(MINIMUM_VERSION)

                if parsed_version < min_version:
                    raise CompatibilityError(
                        f"Workbench server version {workbench_version} is not "
                        f"compatible with this SDK. "
                        f"SDK requires Workbench {MINIMUM_VERSION} or later.",
                        details={
                            "detected_version": workbench_version,
                            "sdk_minimum_version": MINIMUM_VERSION,
                            "parsed_version": str(parsed_version),
                        },
                    )

                logger.info(
                    f"Version compatibility check passed: "
                    f"Server {workbench_version} >= SDK minimum {MINIMUM_VERSION}"
                )

            except packaging_version.InvalidVersion as e:
                # If version string can't be parsed, log warning but allow connection
                logger.warning(
                    f"Could not parse Workbench version "
                    f"'{workbench_version}': {e}. "
                    f"Proceeding with caution. Expected format: X.Y.Z"
                )

        except Exception as e:
            # Let CompatibilityError bubble up
            if e.__class__.__name__ == "CompatibilityError":
                raise
            # Wrap other errors
            from workbench_agent.api.exceptions import ApiError, NetworkError

            if isinstance(e, (ApiError, NetworkError)):
                raise
            else:
                raise ApiError(
                    f"Failed to check Workbench version compatibility: {e}",
                    details={"error": str(e)},
                ) from e

    # ===== PUBLIC PROPERTIES =====

    @property
    def api_url(self) -> str:
        """
        Get the configured API URL.

        Returns:
            The full API URL (e.g., https://server/api.php)
        """
        return self._base_api.api_url

    @property
    def api_user(self) -> str:
        """
        Get the configured API username.

        Returns:
            The API username
        """
        return self._base_api.api_user

    # ===== PUBLIC METHODS =====

    def get_workbench_version(self) -> str:
        """
        Get the Workbench server version.

        Returns:
            Version string (e.g., "2025.2.0#19347124129", "24.3.0")

        Raises:
            ApiError: If unable to fetch version from server

        Example:
            >>> client = WorkbenchClient(url, user, token, check_version=False)
            >>> version = client.get_workbench_version()
            >>> print(f"Connected to Workbench {version}")
        """
        config_data = self.internal.get_config()
        return config_data.get("version", "Unknown")

    @property
    def api_token(self) -> str:
        """
        Get the configured API token.

        Returns:
            The API token/key
        """
        return self._base_api.api_token

    @property
    def session(self):
        """
        Get the underlying requests.Session object.

        This is exposed primarily for testing purposes to allow mocking
        of HTTP requests.

        Returns:
            The requests.Session instance for HTTP communication
        """
        return self._base_api.session

    # ===== CONVENIENCE METHODS =====

    def __repr__(self) -> str:
        """
        String representation of the client.

        Returns:
            A string describing the client and its connection
        """
        return f"<WorkbenchClient(url={self._base_api.api_url})>"

    def __str__(self) -> str:
        """
        Human-readable string representation.

        Returns:
            A friendly description of the client
        """
        return f"WorkbenchClient connected to {self._base_api.api_url}"
