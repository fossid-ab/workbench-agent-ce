"""
DependencyService - Dependency analysis result orchestration.

Coordinates ``ScansClient`` and ``ComponentService`` dependency analysis
read/write operations for reviewing, adding, updating, and removing dependency
rows.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from workbench_agent.api.utils.dependency_helpers import (
    find_dependency,
    parse_include_in_report,
)

logger = logging.getLogger("workbench-agent")


class DependencyService:
    """
    Service for scan dependency analysis workflows.

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
        logger.debug(
            "Listing dependency analysis results for scan '%s'", scan_code
        )
        return self._scans.get_dependency_analysis_results(scan_code)

    def get_dependencies(self, scan_code: str) -> List[Dict[str, Any]]:
        """Alias for ``list_dependencies`` (scan result summaries)."""
        return self.list_dependencies(scan_code)

    def get_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
    ) -> Optional[Dict[str, Any]]:
        """Return one dependency row by name and version, or ``None``."""
        return find_dependency(
            self.list_dependencies(scan_code),
            component_name,
            component_version,
        )

    def summarize_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
    ) -> Dict[str, Any]:
        """Return a compact summary for one dependency row."""
        row = self.get_dependency(scan_code, component_name, component_version)
        if row is None:
            return {
                "scan_code": scan_code,
                "component_name": component_name,
                "component_version": str(component_version),
                "found": False,
            }
        return {
            "scan_code": scan_code,
            "component_name": component_name,
            "component_version": str(component_version),
            "found": True,
            "package_id": row.get("package_id"),
            "include_in_report": parse_include_in_report(
                row.get("include_in_report")
            ),
            "component_id": row.get("component_id"),
        }

    # ===== WRITE =====

    def add_dependency(
        self,
        scan_code: str,
        component_name: str,
        component_version: str,
        package_id: str,
        license_identifier: str,
        *,
        supplier_name: Optional[str] = None,
        projects_and_scopes: Optional[str] = None,
        detailed_dependency_info: Optional[str] = None,
        include_in_report: Optional[Union[bool, int, str]] = None,
    ) -> Dict[str, Any]:
        """
        Add a dependency row to dependency analysis results.

        Ensures the component exists in the Workbench catalog first via
        ``ComponentService.resolve``.
        """
        license_id = license_identifier.strip()
        if not license_id:
            raise ValueError(
                "license_identifier is required to add a dependency"
            )

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
        package_id: Optional[str] = None,
        projects_and_scopes: Optional[str] = None,
        detailed_dependency_info: Optional[str] = None,
        include_in_report: Optional[Union[bool, int, str]] = None,
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
        package_id: Optional[str] = None,
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
