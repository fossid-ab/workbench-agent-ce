"""
ResolverService — find/create composers for Workbench project and scan targets.

Print-free orchestration over ``ProjectsClient`` and ``ScansClient``.
CLI formatting lives in ``workbench_agent.utilities.resolve_project_scan``.

Name lookup uses ``list_projects()`` / ``get_all_scans()`` (heavy). Code lookup
uses ``get_information`` and project-scoped scan lists where possible.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from workbench_agent.api.exceptions import (
    ApiError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ScanWrongProjectError,
)
from workbench_agent.api.clients.scans.helpers import is_scan_not_found
from workbench_agent.services.types import ResolvedScan, ResolvedTargets

logger = logging.getLogger("workbench-agent")


def _strip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _require_exactly_one(
    *,
    name: Optional[str],
    code: Optional[str],
    entity: str,
) -> None:
    has_name = name is not None
    has_code = code is not None
    if has_name == has_code:
        raise ValueError(
            f"{entity} lookup requires exactly one of name= or code= "
            f"(got name={name!r}, code={code!r})"
        )


def _is_scan_not_found_error(error: BaseException) -> bool:
    """True when an API/client error indicates the scan does not exist."""
    if isinstance(error, ScanNotFoundError):
        return True
    if isinstance(error, ApiError):
        error_msg = error.message
        if error.details:
            error_msg = str(error.details.get("error", error_msg))
        return is_scan_not_found(error_msg)
    return False


def _project_code_from_scan_info(info: dict) -> Optional[str]:
    for key in ("project_code", "project", "projectCode"):
        value = info.get(key)
        if value:
            return str(value)
    return None


class ResolverService:
    """
    Service for resolving project and scan identifiers to codes.

    Supports human-readable names (default) and optional customer-supplied
    internal codes. Composers accept ``allow_create`` to distinguish
    find-or-create (write handlers) from lookup-only (read handlers).
    """

    def __init__(self, projects_client, scans_client):
        self.projects = projects_client
        self.scans = scans_client
        logger.debug("ResolverService initialized")

    # ===== Unified find API =====

    def find_project(
        self,
        project_name: Optional[str] = None,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
    ) -> str:
        """
        Resolve a project code (read-only).

        Accepts positional ``project_name`` or keyword ``name=`` / ``code=``.
        """
        resolved_name = _strip(name if name is not None else project_name)
        resolved_code = _strip(code)
        if resolved_name and resolved_code:
            raise ValueError("Provide project name or code, not both")
        if resolved_code:
            return self._find_project_by_code(resolved_code)
        if resolved_name:
            return self._find_project_by_name(resolved_name)
        raise ValueError("Project name or code is required")

    def find_scan(
        self,
        scan_name: Optional[str] = None,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
        project_name: Optional[str] = None,
        project_code: Optional[str] = None,
    ) -> ResolvedScan:
        """
        Resolve a scan within a project (read-only).

        Accepts positional ``scan_name`` or keyword ``name=`` / ``code=``.
        """
        resolved_name = _strip(name if name is not None else scan_name)
        resolved_code = _strip(code)
        resolved_project_code = _strip(project_code)

        if resolved_name and resolved_code:
            raise ValueError("Provide scan name or code, not both")

        if resolved_project_code is None and project_name:
            resolved_project_code = self._find_project_by_name(project_name)
        elif resolved_project_code is None and not resolved_code:
            raise ValueError("find_scan requires project_name or project_code")

        if resolved_code:
            if resolved_project_code is None:
                return self._find_scan_by_code_global(resolved_code)
            return self._find_scan_by_code_in_project(
                resolved_code,
                resolved_project_code,
            )

        assert resolved_name is not None
        if resolved_project_code is None:
            return self._find_scan_globally(resolved_name)
        return self._find_scan_by_name_in_project(
            resolved_name,
            resolved_project_code,
            project_name=project_name,
        )

    def find_scan_globally(self, scan_name: str) -> ResolvedScan:
        """Resolve a scan by name across all projects (read-only, heavy)."""
        return self._find_scan_globally(scan_name)

    # ===== Create API =====

    def create_project(
        self,
        project_name: Optional[str] = None,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
    ) -> str:
        """Create a project; optional ``code`` supplies a customer project code."""
        display_name = _strip(name if name is not None else project_name)
        project_code = _strip(code)
        if not display_name:
            display_name = project_code
        if not display_name:
            raise ValueError("Project name or code is required for create")

        logger.debug("Creating project %r (code=%r)...", display_name, project_code)
        created_code = self.projects.create(
            project_name=display_name,
            project_code=project_code,
            product_code=product_code,
            product_name=product_name,
            description=description
            or ("Automatically created by Workbench Agent" if project_code else None),
            comment=comment,
            limit_date=limit_date,
            jira_project_key=jira_project_key,
        )
        if project_code:
            return str(project_code)
        return str(created_code)

    def create_scan(
        self,
        project_code: str,
        scan_name: str,
        scan_data: dict,
        *,
        scan_code: Optional[str] = None,
    ) -> ResolvedScan:
        """Create a scan; optional ``scan_code`` supplies a customer scan code."""
        logger.debug(
            "Creating scan %r in project %r (code=%r)...",
            scan_name,
            project_code,
            scan_code,
        )

        payload = {
            "project_code": project_code,
            "scan_name": scan_name,
            **scan_data,
        }
        if scan_code:
            payload["scan_code"] = scan_code
        self.scans.create(payload)

        if scan_code:
            info = self.scans.get_information(scan_code)
            return ResolvedScan(
                code=str(scan_code),
                id=int(info.get("id", info.get("scan_id", 0))),
                info=dict(info),
            )

        scan_list = self.projects.get_all_scans(project_code)
        scan = next((s for s in scan_list if s.get("name") == scan_name), None)
        if scan:
            return self._resolved_scan_from_row(scan)

        raise ApiError(f"Failed to retrieve scan '{scan_name}' after creation")

    # ===== Find-or-create composers =====

    def find_or_create_project(
        self,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
        allow_create: bool = True,
    ) -> Tuple[str, bool]:
        """Find or create a project by name or code."""
        _require_exactly_one(name=_strip(name), code=_strip(code), entity="Project")
        resolved_name = _strip(name)
        resolved_code = _strip(code)
        try:
            if resolved_code:
                return self._find_project_by_code(resolved_code), False
            assert resolved_name is not None
            return self._find_project_by_name(resolved_name), False
        except ProjectNotFoundError:
            if not allow_create:
                raise
            if resolved_code:
                created = self.create_project(name=resolved_code, code=resolved_code)
                return created, True
            assert resolved_name is not None
            return self.create_project(name=resolved_name), True

    def find_or_create_scan(
        self,
        project_code: str,
        *,
        name: Optional[str] = None,
        code: Optional[str] = None,
        scan_data: Optional[dict] = None,
        allow_create: bool = True,
    ) -> Tuple[ResolvedScan, bool]:
        """Find or create a scan by name or code within a project."""
        _require_exactly_one(name=_strip(name), code=_strip(code), entity="Scan")
        resolved_name = _strip(name)
        resolved_code = _strip(code)
        scan_data = scan_data or {}

        try:
            if resolved_code:
                return (
                    self._find_scan_by_code_in_project(resolved_code, project_code),
                    False,
                )
            assert resolved_name is not None
            return (
                self._find_scan_by_name_in_project(resolved_name, project_code),
                False,
            )
        except ScanNotFoundError:
            pass
        except ApiError as exc:
            if not _is_scan_not_found_error(exc):
                raise

        if not allow_create:
            label = resolved_code or resolved_name
            raise ScanNotFoundError(f"Scan '{label}' not found in project '{project_code}'")
        display_name = resolved_name or resolved_code
        assert display_name is not None
        created = self.create_scan(
            project_code,
            display_name,
            scan_data,
            scan_code=resolved_code,
        )
        return created, True

    def resolve_targets(
        self,
        *,
        project_name: Optional[str] = None,
        project_code: Optional[str] = None,
        scan_name: Optional[str] = None,
        scan_code: Optional[str] = None,
        scan_data: Optional[dict] = None,
        allow_create: bool = True,
        scan_required: bool = True,
    ) -> ResolvedTargets:
        """
        Resolve CLI-style project/scan inputs to codes.

        Exactly one project identifier and (when ``scan_required``) one scan
        identifier must be supplied by the caller (validated at CLI layer).
        """
        scan_data = scan_data or {}

        project_code_out, project_created = self.find_or_create_project(
            name=_strip(project_name),
            code=_strip(project_code),
            allow_create=allow_create,
        )

        if not scan_required:
            return ResolvedTargets(
                project_code=project_code_out,
                scan_code="",
                project_created=project_created,
                scan_is_new=False,
                scan_info=None,
            )

        resolved_scan, scan_is_new = self.find_or_create_scan(
            project_code_out,
            name=_strip(scan_name),
            code=_strip(scan_code),
            scan_data=scan_data,
            allow_create=allow_create,
        )

        return ResolvedTargets(
            project_code=project_code_out,
            scan_code=resolved_scan.code,
            project_created=project_created,
            scan_is_new=scan_is_new,
            scan_info=None if scan_is_new else resolved_scan.info,
        )

    # ===== Private lookup helpers =====

    @staticmethod
    def _resolved_scan_from_row(scan: dict) -> ResolvedScan:
        return ResolvedScan(
            code=str(scan["code"]),
            id=int(scan["id"]),
            info=dict(scan),
        )

    def _find_project_by_name(self, project_name: str) -> str:
        logger.debug("Looking up project by name %r...", project_name)
        projects = self.projects.list_projects()
        project = next(
            (p for p in projects if p.get("project_name") == project_name),
            None,
        )
        if project:
            code = str(project["project_code"])
            logger.debug("Found project %r with code %r", project_name, code)
            return code
        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def _find_project_by_code(self, project_code: str) -> str:
        logger.debug("Looking up project by code %r...", project_code)
        try:
            self.projects.get_information(project_code)
        except ProjectNotFoundError:
            raise
        except ApiError as exc:
            raise ProjectNotFoundError(f"Project '{project_code}' not found") from exc
        logger.debug("Found project with code %r", project_code)
        return project_code

    def _find_scan_by_name_in_project(
        self,
        scan_name: str,
        project_code: str,
        *,
        project_name: Optional[str] = None,
    ) -> ResolvedScan:
        log_project = project_name or project_code
        logger.debug(
            "Looking up scan %r by name in project %r...",
            scan_name,
            log_project,
        )
        scan_list = self.projects.get_all_scans(project_code)
        scan = next((s for s in scan_list if s.get("name") == scan_name), None)
        if scan:
            return self._resolved_scan_from_row(scan)
        raise ScanNotFoundError(
            f"Scan '{scan_name}' not found in project '{log_project}'"
        )

    def _find_scan_by_code_in_project(
        self,
        scan_code: str,
        project_code: str,
    ) -> ResolvedScan:
        logger.debug(
            "Looking up scan %r by code in project %r...",
            scan_code,
            project_code,
        )
        scan_list = self.projects.get_all_scans(project_code)
        scan = next((s for s in scan_list if str(s.get("code")) == scan_code), None)
        if scan:
            return self._resolved_scan_from_row(scan)

        # Scan may exist globally but under a different project.
        try:
            global_scan = self._find_scan_by_code_global(scan_code)
        except (ScanNotFoundError, ApiError) as exc:
            if isinstance(exc, ApiError) and not _is_scan_not_found_error(exc):
                raise
            raise ScanNotFoundError(
                f"Scan '{scan_code}' not found in project '{project_code}'"
            ) from None

        actual_project_code = _project_code_from_scan_info(global_scan.info)
        if actual_project_code is None:
            actual_project_code = self._lookup_scan_project_code(scan_code)

        raise ScanWrongProjectError(
            scan_code=scan_code,
            requested_project_code=project_code,
            actual_project_code=actual_project_code,
        )

    def _find_scan_by_code_global(self, scan_code: str) -> ResolvedScan:
        logger.debug("Looking up scan by code %r...", scan_code)
        info = self.scans.get_information(scan_code)
        return ResolvedScan(
            code=str(scan_code),
            id=int(info.get("id", info.get("scan_id", 0))),
            info=dict(info),
        )

    def _find_scan_globally(self, scan_name: str) -> ResolvedScan:
        logger.debug("Looking up scan %r globally...", scan_name)
        all_scans = self.scans.list_scans()
        scan = next((s for s in all_scans if s.get("name") == scan_name), None)
        if scan:
            return self._resolved_scan_from_row(scan)
        raise ScanNotFoundError(f"Scan '{scan_name}' not found")

    def _lookup_scan_project_code(self, scan_code: str) -> Optional[str]:
        """Best-effort project lookup when scan info lacks project association."""
        for row in self.scans.list_scans():
            if str(row.get("code")) != scan_code:
                continue
            project_code = _project_code_from_scan_info(row)
            if project_code:
                return project_code
        return None
