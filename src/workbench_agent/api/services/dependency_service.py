"""
DependencyService - Manage Dependency Analysis results in Workbench.

Use this service to review, add, update, and remove dependencies from a scan.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Union

logger = logging.getLogger("workbench-agent")


class DependencyService:
    """
    Service for operating on dependency analysis results.

    Example:
        >>> svc = DependencyService(client.scans, client.component_catalog)
        >>> deps = svc.list_dependencies(scan_code)
        >>> svc.add_dependency(
        ...     scan_code, "my-lib", "1.0.0", "pkg:generic/my-lib@1.0.0", "MIT"
        ... )
        >>> svc.remove_dependency(scan_code, "my-lib", "1.0.0")
    """

    def __init__(self, scans_client, component_catalog) -> None:
        self._scans = scans_client
        self._catalog = component_catalog
        logger.debug("DependencyService initialized")

    # ===== READ =====

    def list_dependencies(self, scan_code: str) -> List[Dict[str, Any]]:
        """Return dependency analysis rows for a scan."""
        logger.debug("Listing dependency analysis results for scan '%s'", scan_code)
        return self._scans.get_dependency_analysis_results(scan_code)

    # ===== WRITE =====

    def add_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        package_id: str,
        license_identifier: str,
        *,
        supplier_name: str | None = None,
        projects_and_scopes: str | None = None,
        detailed_dependency_info: str | None = None,
        include_in_report: bool | int | str | None = None,
    ) -> Dict[str, Any]:
        """
        Manually add a dependency to a scan's dependency analysis results.

        Ensures the component exists in the Workbench catalog first via
        ``ComponentService.resolve``.
        """
        license_id = license_identifier.strip()
        if not license_id:
            raise ValueError("license_identifier is required to add a dependency")

        logger.info(
            "Adding dependency '%s' %r to scan '%s'",
            component_name,
            component_version,
            scan_code,
        )
        self._catalog.resolve(
            component_name,
            component_version,
            license_id,
            supplier_name=supplier_name,
            purl=package_id,
        )
        return self._scans.add_dependency_analysis_results(
            scan_code,
            component_name,
            component_version,
            package_id,
            projects_and_scopes=projects_and_scopes,
            detailed_dependency_info=detailed_dependency_info,
            include_in_report=include_in_report,
        )

    def update_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        *,
        package_id: str | None = None,
        projects_and_scopes: str | None = None,
        detailed_dependency_info: str | None = None,
        include_in_report: bool | int | str | None = None,
    ) -> Dict[str, Any]:
        """Update an existing dependency analysis row."""
        logger.info(
            "Updating dependency '%s' %r on scan '%s'",
            component_name,
            component_version,
            scan_code,
        )
        return self._scans.update_dependency_analysis_results(
            scan_code,
            component_name,
            component_version,
            package_id=package_id,
            projects_and_scopes=projects_and_scopes,
            detailed_dependency_info=detailed_dependency_info,
            include_in_report=include_in_report,
        )

    def set_include_in_report(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        include_in_report: Union[bool, int, str],
        *,
        package_id: str | None = None,
    ) -> Dict[str, Any]:
        """Toggle whether a dependency is included in reports."""
        return self.update_dependency(
            scan_code,
            component_name,
            component_version,
            package_id=package_id,
            include_in_report=include_in_report,
        )

    def remove_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
    ) -> bool:
        """Remove a dependency row from dependency analysis results."""
        logger.info(
            "Removing dependency '%s' %r from scan '%s'",
            component_name,
            component_version,
            scan_code,
        )
        return self._scans.remove_dependency_analysis_results(
            scan_code,
            component_name,
            component_version,
        )
