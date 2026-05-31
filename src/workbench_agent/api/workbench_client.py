"""
WorkbenchClient - Main API client for FossID Workbench.

Functionality is organized into domain-specific clients and services.

"""

import logging

from packaging import version as packaging_version

from workbench_agent.api.utils.version import normalize_workbench_version

from workbench_agent.api.clients import (
    ComponentsClient,
    DownloadClient,
    FilesAndFoldersClient,
    InternalClient,
    ProjectsClient,
    QuickScanClient,
    ScansClient,
    UploadsClient,
    UsersClient,
    VulnerabilitiesClient,
)
from workbench_agent.api.exceptions import CompatibilityError
from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.services import (
    QuickScanService,
    ReportService,
    ResolverService,
    ResultsService,
    ScanContentService,
    ScanDeletionService,
    ScanOperationsService,
    StatusCheckService,
    UploadService,
    UserPermissionsService
)

logger = logging.getLogger("workbench-agent")


class WorkbenchClient:
    """
    Main Workbench API client provides Workbench
    functionality through clients and services:

    **Clients (Direct API operations):**
    - `projects`: Project management (list, create, update, reports)
    - `scans`: Scan operations (list, create, update, run, results)
    - `uploads`: File uploads (scan targets, DA, SBOM)
    - `downloads`: File downloads (reports, etc.)
    - `vulnerabilities`: Vulnerability queries
    - `quick_scan`: Quick file scanning
    - `users`: User lookup and listing permissions for a user
    - `internal`: Internal/config operations
    - `components`: Component catalog (list, create, usage)
    - `files_and_folders`: File identification and audit operations

    **Services (High-level orchestration):**
    - `resolver`: Resolve project/scan names to codes, create if needed
    - `status_check`: Check status of async operations (specialized methods)
    - `scan_content`: Manages scan content on the Workbench Server
    - `reports`: Report generation with validation and waiting
    - `results`: Fetch and aggregate scan results
    - `scan_operations`: Scan execution with standardized behavior
    - `scan_deletion`: Queue scan delete and wait until complete
    - `user_permissions`: Check Workbench permissions for the API user
    - `upload_service`: File upload operations
    - `quick_scan_service`: Quick single-file scan

    Example:
        >>> workbench = WorkbenchClient(api_url, api_user, api_token)
        >>>
        >>> # Direct API operations via clients
        >>> all_projects = workbench.projects.list_projects()
        >>> scan_info = workbench.scans.get_information(scan_code)
        >>> workbench.upload_service.upload_scan_target(
        ...     scan_code, "./source.zip"
        ... )
        >>>
        >>> # High-level workflows via services
        >>> p_code, s_code, is_new = (
        ...     workbench.resolver.find_or_create_project_and_scan(
        ...         "MyProject", "MyScan", params
        ...     )
        ... )
        >>> process_id = workbench.reports.generate_project_report(
        ...     project_code, "xlsx"
        ... )
        >>> workbench.scan_operations.start_scan(
        ...     scan_code, limit=10, sensitivity=6
        ... )

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
        Initialize WorkbenchClient. The client checks Workbench server
        version on initialization to determine compatibility.

        Args:
            api_url: URL to the Workbench API endpoint
                (e.g., https://server/api.php)
            api_user: API username
            api_token: API authentication token

        Raises:
            CompatibilityError: If Workbench version doesn't match expectations

        Example:
            >>> # SDK checks server compatibility automatically
            >>> workbench = WorkbenchClient(
            ...     api_url="https://workbench.fossid.com/api.php",
            ...     api_user="my_username",
            ...     api_token="my_api_token"
            ... )
        """
        logger.info("Initializing WorkbenchClient")

        # Core infrastructure - BaseAPI handles all HTTP communication
        self._base_api = BaseAPI(api_url, api_user, api_token)
        logger.debug(
            f"BaseAPI initialized with URL: {self._base_api.api_url}"
        )

        # Initialize InternalClient first (needed for version check)
        self.internal = InternalClient(self._base_api)

        # Check Workbench server version compatibility (also caches version)
        self._workbench_version = ""
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
        self.users = UsersClient(self._base_api)
        self.components = ComponentsClient(self._base_api)
        self.files_and_folders = FilesAndFoldersClient(self._base_api)

        logger.debug("API clients initialized.")

        # Initialize orchestration services
        # Services coordinate multiple clients for complex workflows
        logger.debug("Initializing Services...")

        self.resolver = ResolverService(
            projects_client=self.projects, scans_client=self.scans
        )

        self.status_check = StatusCheckService(
            scans_client=self.scans, projects_client=self.projects
        )

        self.scan_content = ScanContentService(
            scans_client=self.scans,
            status_check_service=self.status_check,
        )

        self.quick_scan_service = QuickScanService(
            quick_scan_client=self.quick_scan
        )

        self.reports = ReportService(
            projects_client=self.projects,
            scans_client=self.scans,
            downloads_client=self.downloads,
            status_check_service=self.status_check,
            workbench_version=self._workbench_version,
        )

        self.results = ResultsService(
            scans_client=self.scans,
            vulnerabilities_client=self.vulnerabilities,
            workbench_version=self._workbench_version,
        )

        self.scan_operations = ScanOperationsService(
            scans_client=self.scans, resolver_service=self.resolver
        )

        self.scan_deletion = ScanDeletionService(
            scans_client=self.scans,
            status_check_service=self.status_check,
        )

        self.upload_service = UploadService(uploads_client=self.uploads)

        self.user_permissions = UserPermissionsService(
            users_client=self.users,
            scans_client=self.scans,
            api_user=self._base_api.api_user,
        )

        logger.debug("Services initialized.")
        logger.info("WorkbenchClient initialization complete!")

    # ===== PRIVATE METHODS =====

    def _check_version_compatibility(self) -> None:
        """
        Check that the Workbench version is compatible with this SDK.

        Raises:
            CompatibilityError: If Workbench version is incompatible
            ApiError: If version detection fails
            NetworkError: If connection fails

        """
        # This SDK version's minimum compatible Workbench version
        MINIMUM_VERSION = "24.3.0"

        try:
            logger.info(
                "Checking Workbench version compatibility..."
            )
            config_data = self.internal.get_config()
            workbench_version = config_data.get("version", "Unknown")

            if workbench_version == "Unknown":
                raise CompatibilityError(
                    "Could not determine Workbench version. "
                    "Please ensure you are connected to a valid "
                    "Workbench instance.",
                    details={"config_data": config_data},
                )

            logger.debug(
                f"Detected Workbench version: {workbench_version}"
            )

            # Parse and compare versions
            try:
                version_str = normalize_workbench_version(workbench_version)
                if not version_str:
                    raise packaging_version.InvalidVersion(workbench_version)
                self._workbench_version = version_str

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
                    f"Server {workbench_version} >= minimum {MINIMUM_VERSION}"
                )

            except packaging_version.InvalidVersion as e:
                # If version string can't be parsed, log warning but continue
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
            from workbench_agent.api.exceptions import (
                ApiError,
                NetworkError,
            )

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

        Returns the MAJOR.MINOR.PATCH version cached during initialization
        (e.g. ``"2026.1.0"``).  Falls back to a fresh call if cache is empty.

        Returns:
            Normalized version string (e.g., "2026.1.0", "2025.2.0")

        Raises:
            ApiError: If unable to fetch version from server

        Example:
            >>> client = WorkbenchClient(url, user, token)
            >>> version = client.get_workbench_version()
            >>> print(f"Connected to Workbench {version}")
        """
        if self._workbench_version:
            return self._workbench_version
        config_data = self.internal.get_config()
        raw = config_data.get("version", "Unknown")
        normalized = normalize_workbench_version(str(raw))
        return normalized or str(raw)

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

        This is exposed primarily for testing to allow mocking HTTP requests.

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
