"""
ResultsService - Handles fetching scan results.

This service provides methods for retrieving various types of scan results
including licenses, components, dependencies, vulnerabilities, metrics, and
policy warnings. It also provides methods for generating Workbench UI links.
"""

import argparse
import logging
from typing import Any, Dict, List

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")


class WorkbenchLinks:
    """
    Helper class providing property-based access to Workbench UI links.

    This class is returned by ResultsService.workbench_links() and provides
    convenient property access to different Workbench views.

    Example:
        >>> links = results_service.workbench_links(scan_id=123)
        >>> print(links.pending['url'])
        >>> print(links.scan['message'])
    """

    def __init__(self, api_url: str, scan_id: int):
        """
        Initialize WorkbenchLinks.

        Args:
            api_url: The Workbench API URL (includes /api.php)
            scan_id: The scan ID
        """
        self._api_url = api_url
        self._scan_id = scan_id
        self._base_url = api_url.replace("/api.php", "").rstrip("/")

    def _build_link(
        self, view_param: str = None, message: str = ""
    ) -> Dict[str, str]:
        """Build a single link URL and message."""
        url = (
            f"{self._base_url}/index.html?"
            f"form=main_interface&action=scanview&sid={self._scan_id}"
        )
        if view_param:
            url += f"&current_view={view_param}"
        return {"url": url, "message": message}

    @property
    def scan(self) -> Dict[str, str]:
        """Link to the main scan view."""
        return self._build_link(
            view_param="all_items", message="View this Scan in Workbench"
        )

    @property
    def pending(self) -> Dict[str, str]:
        """Link to pending items view."""
        return self._build_link(
            view_param="pending_items",
            message="Review Pending IDs in Workbench",
        )

    @property
    def identified(self) -> Dict[str, str]:
        """Link to identified components view."""
        return self._build_link(
            view_param="mark_as_identified",
            message="View Identified Components in Workbench",
        )

    @property
    def dependencies(self) -> Dict[str, str]:
        """Link to dependencies view."""
        return self._build_link(
            view_param="dependency_analysis",
            message="View Dependencies in Workbench",
        )

    @property
    def policy(self) -> Dict[str, str]:
        """Link to policy warnings view."""
        return self._build_link(
            view_param="mark_as_identified",
            message="Review policy warnings in Workbench",
        )

    @property
    def vulnerabilities(self) -> Dict[str, str]:
        """Link to vulnerable components view."""
        return self._build_link(
            view_param="mark_as_identified",
            message="Review Vulnerable Components in Workbench",
        )


class ResultsService:
    """
    Service for fetching scan results.

    This service orchestrates result fetching from the Workbench API,
    providing both granular methods for individual result types and
    a high-level method for fetching all requested results based on
    command-line parameters.

    Example:
        >>> results_service = ResultsService(scans_client, vulns_client)
        >>>
        >>> # Fetch specific result types
        >>> licenses = results_service.get_identified_licenses(scan_code)
        >>> vulns = results_service.get_vulnerabilities(scan_code)
        >>>
        >>> # Fetch all results based on params
        >>> all_results = results_service.fetch_results(scan_code, params)
    """

    def __init__(self, scans_client, vulnerabilities_client):
        """
        Initialize ResultsService.

        Args:
            scans_client: ScansClient instance for scan-related results
            vulnerabilities_client: VulnerabilitiesClient for vulnerability
                data
        """
        self._scans = scans_client
        self._vulnerabilities = vulnerabilities_client
        logger.debug("ResultsService initialized")

    # ===== WORKBENCH UI LINKS =====

    def workbench_links(self, scan_id: int) -> WorkbenchLinks:
        """
        Get a WorkbenchLinks object for property-based link access.

        Args:
            scan_id: The scan ID

        Returns:
            WorkbenchLinks instance with properties for different views

        Example:
            >>> links = results_service.workbench_links(scan_id=123)
            >>> print(links.pending['url'])
            >>> print(links.scan['message'])
        """
        api_url = self._scans._api.api_url
        return WorkbenchLinks(api_url, scan_id)

    # ===== PUBLIC API - INDIVIDUAL RESULT FETCHERS =====

    def get_identified_licenses(
        self, scan_code: str, unique: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get identified licenses from KB scanning.

        Args:
            scan_code: Code of the scan to fetch licenses from
            unique: If True, returns only unique licenses (default: True)

        Returns:
            List of license dictionaries with identifier and name

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> licenses = results_service.get_identified_licenses(
            ...     "SCAN123"
            ... )
            >>> for lic in licenses:
            ...     print(f"{lic['identifier']}: {lic['name']}")
        """
        logger.debug(
            f"Fetching identified licenses for scan '{scan_code}' "
            f"(unique={unique})"
        )
        licenses: List[Dict[str, Any]] = (
            self._scans.get_scan_identified_licenses(
                scan_code, unique=unique
            )
        )
        logger.debug(f"Retrieved {len(licenses)} licenses")
        return licenses

    def get_identified_components(
        self, scan_code: str
    ) -> List[Dict[str, Any]]:
        """
        Get identified components from KB scanning.

        Args:
            scan_code: Code of the scan to fetch components from

        Returns:
            List of component dictionaries with name and version

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> components = results_service.get_identified_components(
            ...     "SCAN123"
            ... )
            >>> for comp in components:
            ...     print(f"{comp['name']} {comp['version']}")
        """
        logger.debug(
            f"Fetching identified components for scan '{scan_code}'"
        )
        components: List[Dict[str, Any]] = (
            self._scans.get_scan_identified_components(scan_code)
        )
        logger.debug(f"Retrieved {len(components)} components")
        return components

    def get_dependencies(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get dependency analysis results.

        Args:
            scan_code: Code of the scan to fetch dependencies from

        Returns:
            List of dependency dictionaries with name, version, license, etc.

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> deps = results_service.get_dependencies("SCAN123")
            >>> for dep in deps:
            ...     print(
            ...         f"{dep['name']} {dep['version']} "
            ...         f"({dep['license_identifier']})"
            ...     )
        """
        logger.debug(
            f"Fetching dependency analysis results for scan '{scan_code}'"
        )
        dependencies: List[Dict[str, Any]] = (
            self._scans.get_dependency_analysis_results(scan_code)
        )
        logger.debug(f"Retrieved {len(dependencies)} dependencies")
        return dependencies

    def get_vulnerabilities(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a scan.

        Args:
            scan_code: Code of the scan to fetch vulnerabilities from

        Returns:
            List of vulnerability dictionaries with CVE, severity,
            component info, etc.

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> vulns = results_service.get_vulnerabilities("SCAN123")
            >>> for vuln in vulns:
            ...     print(
            ...         f"{vuln['cve']}: {vuln['severity']} - "
            ...         f"{vuln['component_name']}"
            ...     )
        """
        logger.debug(f"Fetching vulnerabilities for scan '{scan_code}'")
        vulnerabilities: List[Dict[str, Any]] = (
            self._vulnerabilities.list_vulnerabilities(scan_code)
        )
        logger.debug(f"Retrieved {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def get_scan_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Get scan file metrics (total files, pending, identified, no match).

        Args:
            scan_code: Code of the scan to fetch metrics from

        Returns:
            Dictionary with metric counts:
            - total: Total files scanned
            - pending_identification: Files pending identification
            - identified_files: Files identified
            - without_matches: Files without matches

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> metrics = results_service.get_scan_metrics("SCAN123")
            >>> print(f"Total files: {metrics['total']}")
            >>> print(f"Pending: {metrics['pending_identification']}")
        """
        logger.debug(f"Fetching scan metrics for scan '{scan_code}'")
        metrics: Dict[str, Any] = self._scans.get_scan_folder_metrics(
            scan_code
        )
        logger.debug("Retrieved scan metrics")
        return metrics

    def get_policy_warnings(self, scan_code: str) -> Dict[str, Any]:
        """
        Get policy warnings counter for a scan.

        Args:
            scan_code: Code of the scan to fetch policy warnings from

        Returns:
            Dictionary with policy warning counts:
            - policy_warnings_total: Total number of policy warnings
            - identified_files_with_warnings: Files with warnings
            - dependencies_with_warnings: Dependencies with warnings

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist

        Example:
            >>> warnings = results_service.get_policy_warnings("SCAN123")
            >>> print(
            ...     f"Total warnings: "
            ...     f"{warnings['policy_warnings_total']}"
            ... )
        """
        logger.debug(
            f"Fetching policy warnings counter for scan '{scan_code}'"
        )
        warnings: Dict[str, Any] = self._scans.get_policy_warnings_counter(
            scan_code
        )
        logger.debug("Retrieved policy warnings counter")
        return warnings

    # ===== HIGH-LEVEL ORCHESTRATOR =====

    def fetch_results(
        self, scan_code: str, params: argparse.Namespace
    ) -> Dict[str, Any]:
        """
        Fetch all requested results based on command-line parameters.

        This high-level method orchestrates fetching multiple result types
        based on the --show-* flags in the command-line parameters. It
        gracefully handles errors for individual result types, logging
        warnings and continuing to fetch other results.

        Args:
            scan_code: Code of the scan to fetch results from
            params: Command-line parameters containing --show-* flags:
                - show_licenses: Fetch identified licenses and DA licenses
                - show_components: Fetch identified components
                - show_dependencies: Fetch dependency analysis results
                - show_scan_metrics: Fetch scan file metrics
                - show_policy_warnings: Fetch policy warnings counter
                - show_vulnerabilities: Fetch vulnerabilities

        Returns:
            Dictionary containing requested results:
            - dependency_analysis: List of dependencies (if requested)
            - kb_licenses: List of licenses (if requested)
            - kb_components: List of components (if requested)
            - scan_metrics: Metrics dictionary (if requested)
            - policy_warnings: Warnings dictionary (if requested)
            - vulnerabilities: List of vulnerabilities (if requested)

        Example:
            >>> params = argparse.Namespace(
            ...     show_licenses=True,
            ...     show_vulnerabilities=True,
            ...     show_components=False,
            ...     show_dependencies=False,
            ...     show_scan_metrics=False,
            ...     show_policy_warnings=False
            ... )
            >>> results = results_service.fetch_results("SCAN123", params)
            >>> print(f"Found {len(results['kb_licenses'])} licenses")
            >>> print(f"Found {len(results['vulnerabilities'])} vulns")
        """
        logger.debug(
            f"Fetching requested results for scan '{scan_code}' "
            f"based on --show-* flags"
        )

        # Determine what to fetch based on flags
        should_fetch_licenses = getattr(params, "show_licenses", False)
        should_fetch_components = getattr(params, "show_components", False)
        should_fetch_dependencies = getattr(
            params, "show_dependencies", False
        )
        should_fetch_metrics = getattr(params, "show_scan_metrics", False)
        should_fetch_policy = getattr(
            params, "show_policy_warnings", False
        )
        should_fetch_vulnerabilities = getattr(
            params, "show_vulnerabilities", False
        )

        # Early exit if nothing requested
        if not any(
            [
                should_fetch_licenses,
                should_fetch_components,
                should_fetch_dependencies,
                should_fetch_metrics,
                should_fetch_policy,
                should_fetch_vulnerabilities,
            ]
        ):
            logger.debug(
                "No results requested - all --show-* flags are False"
            )
            return {}

        logger.debug("=== Fetching Requested Results ===")
        collected_results: Dict[str, Any] = {}

        # Fetch dependency analysis (needed for licenses and dependencies)
        if should_fetch_licenses or should_fetch_dependencies:
            try:
                da_results = self.get_dependencies(scan_code)
                if da_results:
                    collected_results["dependency_analysis"] = da_results
                    logger.info(
                        f"Fetched {len(da_results)} dependency analysis "
                        f"results"
                    )
            except (ApiError, NetworkError) as e:
                logger.warning(
                    f"Could not fetch Dependency Analysis results: {e}"
                )
                print(
                    f"Warning: Could not fetch Dependency Analysis "
                    f"results: {e}"
                )

        # Fetch KB licenses
        if should_fetch_licenses:
            try:
                kb_licenses = self.get_identified_licenses(scan_code)
                if kb_licenses:
                    # Sort by identifier for consistent display
                    collected_results["kb_licenses"] = sorted(
                        kb_licenses,
                        key=lambda x: x.get("identifier", "").lower(),
                    )
                    logger.info(f"Fetched {len(kb_licenses)} KB licenses")
            except (ApiError, NetworkError) as e:
                logger.warning(
                    f"Could not fetch KB Identified Licenses: {e}"
                )
                print(
                    f"Warning: Could not fetch KB Identified Licenses: {e}"
                )

        # Fetch KB components
        if should_fetch_components:
            try:
                kb_components = self.get_identified_components(scan_code)
                if kb_components:
                    # Sort by name and version
                    collected_results["kb_components"] = sorted(
                        kb_components,
                        key=lambda x: (
                            x.get("name", "").lower(),
                            x.get("version", ""),
                        ),
                    )
                    logger.info(
                        f"Fetched {len(kb_components)} KB components"
                    )
            except (ApiError, NetworkError) as e:
                logger.warning(
                    f"Could not fetch KB Identified Scan Components: {e}"
                )
                print(
                    f"Warning: Could not fetch KB Identified Scan "
                    f"Components: {e}"
                )

        # Fetch scan metrics
        if should_fetch_metrics:
            try:
                metrics = self.get_scan_metrics(scan_code)
                if metrics:
                    collected_results["scan_metrics"] = metrics
                    logger.info("Fetched scan metrics")
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.warning(f"Could not fetch Scan File Metrics: {e}")
                print(f"Warning: Could not fetch Scan File Metrics: {e}")

        # Fetch policy warnings
        if should_fetch_policy:
            try:
                warnings = self.get_policy_warnings(scan_code)
                if warnings:
                    collected_results["policy_warnings"] = warnings
                    logger.info("Fetched policy warnings counter")
            except (ApiError, NetworkError) as e:
                logger.warning(
                    f"Could not fetch Scan Policy Warnings: {e}"
                )
                print(
                    f"Warning: Could not fetch Scan Policy Warnings: {e}"
                )

        # Fetch vulnerabilities
        if should_fetch_vulnerabilities:
            try:
                vulnerabilities = self.get_vulnerabilities(scan_code)
                if vulnerabilities:
                    collected_results["vulnerabilities"] = vulnerabilities
                    logger.info(
                        f"Fetched {len(vulnerabilities)} vulnerabilities"
                    )
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.warning(f"Could not fetch Vulnerabilities: {e}")
                print(f"Warning: Could not fetch Vulnerabilities: {e}")

        logger.debug(
            f"Completed fetching results. "
            f"Retrieved {len(collected_results)} result types."
        )
        return collected_results
