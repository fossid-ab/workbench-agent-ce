"""
ResolverService - Resolves project and scan names to codes.

This service provides machine-readable lookup and create operations for
projects and scans based on user-provided names.

CE orchestration (CLI params, compatibility, terminal output) lives in
``workbench_agent.utilities.resolve_project_scan``.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from workbench_agent.api.exceptions import (
    ApiError,
    ProjectNotFoundError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")


@dataclass(frozen=True)
class ResolvedScan:
    """Scan resolved by name, including listing metadata for reuse checks."""

    code: str
    id: int
    info: dict


@dataclass
class ResolutionResult:
    """Outcome of a find-or-create project and scan workflow."""

    project_code: str
    scan_code: str
    project_created: bool
    scan_is_new: bool
    scan_info: Optional[dict] = None


class ResolverService:
    """
    Service for resolving project and scan names to codes.

    This service orchestrates ProjectsClient and ScansClient to handle
    lookup and creation by name. Returns structured data only.

    Public API:

    **Read-only (raises if not found):**
        >>> resolver.find_project("MyProject")
        >>> pc, scan = resolver.find_project_and_scan("MyProject", "MyScan")

    **Create:**
        >>> resolver.create_project("MyProject")
        >>> scan = resolver.create_scan("PROJ", "MyScan", scan_data)

    **Find or create:**
        >>> result = resolver.find_or_create("MyProject", "MyScan", scan_data)
    """

    def __init__(self, projects_client, scans_client):
        """
        Initialize ResolverService.

        Args:
            projects_client: ProjectsClient instance
            scans_client: ScansClient instance
        """
        self.projects = projects_client
        self.scans = scans_client
        logger.debug("ResolverService initialized")

    # ===== PUBLIC API (read-only by name) =====

    def find_project(self, project_name: str) -> str:
        """
        Resolve a project code from its name (read-only).

        Args:
            project_name: Human-readable project name

        Returns:
            Project code string

        Raises:
            ProjectNotFoundError: If project not found
            ApiError: If there are API issues
        """
        return self._find_project(project_name)

    def find_scan(
        self,
        scan_name: str,
        *,
        project_name: Optional[str] = None,
        project_code: Optional[str] = None,
    ) -> ResolvedScan:
        """
        Resolve a scan by name within a project (read-only).

        Provide ``project_code`` to skip project lookup; otherwise pass
        ``project_name``.

        Returns:
            ResolvedScan with code, id, and listing metadata (``info``)

        Raises:
            ProjectNotFoundError: If the project does not exist
            ScanNotFoundError: If the scan does not exist in that project
        """
        return self._find_scan_in_project(
            scan_name,
            project_name=project_name,
            project_code=project_code,
        )

    def find_scan_globally(self, scan_name: str) -> ResolvedScan:
        """
        Resolve a scan by name across all projects (read-only, heavy).

        Raises:
            ScanNotFoundError: If no matching scan exists
        """
        return self._find_scan_globally(scan_name)

    def find_project_and_scan(self, project_name: str, scan_name: str) -> Tuple[str, ResolvedScan]:
        """
        Resolve project and scan names to codes in one pass.

        Returns:
            Tuple of ``(project_code, ResolvedScan)``
        """
        project_code = self._find_project(project_name)
        scan = self._find_scan_in_project(
            scan_name,
            project_name=project_name,
            project_code=project_code,
        )
        return project_code, scan

    def create_project(
        self,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
    ) -> str:
        """
        Create a new project.

        Returns:
            Project code of the created project
        """
        logger.debug(f"Creating project '{project_name}'...")
        project_code = self.projects.create(
            project_name=project_name,
            product_code=product_code,
            product_name=product_name,
            description=description,
            comment=comment,
            limit_date=limit_date,
            jira_project_key=jira_project_key,
        )
        return str(project_code)

    def create_scan(
        self,
        project_code: str,
        scan_name: str,
        scan_data: dict,
    ) -> ResolvedScan:
        """
        Create a new scan in a project.

        Args:
            project_code: Project code to create the scan in
            scan_name: Name for the new scan
            scan_data: API payload fields (excluding project_code/scan_name)

        Returns:
            ResolvedScan for the created scan
        """
        logger.debug(f"Creating scan '{scan_name}' in project '{project_code}'...")

        payload = {
            "project_code": project_code,
            "scan_name": scan_name,
            **scan_data,
        }
        self.scans.create(payload)

        scan_list = self.projects.get_all_scans(project_code)
        scan = next((s for s in scan_list if s.get("name") == scan_name), None)
        if scan:
            logger.debug(
                f"Created scan '{scan_name}' with code '{scan['code']}' " f"and ID {scan['id']}"
            )
            return self._resolved_scan_from_row(scan)

        raise ApiError(f"Failed to retrieve scan '{scan_name}' after creation")

    def find_or_create(
        self,
        project_name: str,
        scan_name: str,
        scan_data: dict,
    ) -> ResolutionResult:
        """
        Find or create a project and scan by name.

        Args:
            project_name: Name of the project
            scan_name: Name of the scan
            scan_data: Fields for scan creation when the scan is missing

        Returns:
            ResolutionResult with codes and creation flags
        """
        project_created = False
        try:
            project_code = self._find_project(project_name)
        except ProjectNotFoundError:
            project_code = self.create_project(project_name=project_name)
            project_created = True

        scan_is_new = False
        scan_info: Optional[dict] = None
        try:
            resolved = self._find_scan_in_project(
                scan_name,
                project_name=project_name,
                project_code=project_code,
            )
            scan_code = resolved.code
            scan_info = resolved.info
        except ScanNotFoundError:
            resolved = self.create_scan(
                project_code=project_code,
                scan_name=scan_name,
                scan_data=scan_data,
            )
            scan_code = resolved.code
            scan_is_new = True

        return ResolutionResult(
            project_code=project_code,
            scan_code=scan_code,
            project_created=project_created,
            scan_is_new=scan_is_new,
            scan_info=scan_info,
        )

    # ===== PRIVATE LOOKUP HELPERS =====

    @staticmethod
    def _resolved_scan_from_row(scan: dict) -> ResolvedScan:
        return ResolvedScan(
            code=str(scan["code"]),
            id=int(scan["id"]),
            info=dict(scan),
        )

    def _find_project(self, project_name: str) -> str:
        """Resolve project name to code; raises ``ProjectNotFoundError``."""
        logger.debug(f"Looking up project '{project_name}'...")
        projects = self.projects.list_projects()
        project = next(
            (p for p in projects if p.get("project_name") == project_name),
            None,
        )

        if project:
            project_code = project["project_code"]
            logger.debug(f"Found project '{project_name}' " f"with code '{project_code}'")
            return str(project_code)

        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def _find_scan_in_project(
        self,
        scan_name: str,
        *,
        project_name: Optional[str] = None,
        project_code: Optional[str] = None,
    ) -> ResolvedScan:
        """Find a scan by name within a project (read-only)."""
        if project_name is None and project_code is None:
            raise ValueError("_find_scan_in_project requires project_name or project_code")

        log_project = project_name or project_code or "?"
        logger.debug(f"Looking up scan '{scan_name}' in project '{log_project}'...")

        if project_code is None:
            assert project_name is not None
            project_code = self._find_project(project_name)
        else:
            logger.debug(f"Using project_code '{project_code}' " f"(skipping project lookup)")

        scan_list = self.projects.get_all_scans(project_code)
        scan = next((s for s in scan_list if s.get("name") == scan_name), None)
        if scan:
            logger.debug(
                f"Found scan '{scan_name}' with code '{scan['code']}' "
                f"and ID {scan['id']} in project '{log_project}'"
            )
            return self._resolved_scan_from_row(scan)

        raise ScanNotFoundError(
            f"Scan '{scan_name}' not found in project " f"'{project_name or project_code}'"
        )

    def _find_scan_globally(self, scan_name: str) -> ResolvedScan:
        """Resolve a scan by name across all projects (read-only, heavy)."""
        logger.debug(f"Looking up scan '{scan_name}' globally...")
        all_scans = self.scans.list_scans()
        scan = next((s for s in all_scans if s.get("name") == scan_name), None)
        if scan:
            logger.debug(
                f"Found scan '{scan_name}' with code '{scan['code']}' "
                f"and ID {scan['id']} (global search)"
            )
            return self._resolved_scan_from_row(scan)

        raise ScanNotFoundError(f"Scan '{scan_name}' not found")
