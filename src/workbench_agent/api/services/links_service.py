"""
LinksService - Version-aware Workbench UI deep links for a scan.
"""

from __future__ import annotations

import logging
from typing import Dict

from packaging import version as packaging_version

from workbench_agent.api.exceptions import ApiError

logger = logging.getLogger("workbench-agent")

NUI_MIN_VERSION = "2026.1.0"


class WorkbenchLinks:
    """
    Workbench UI links for a scan (legacy or NUI URL format).

    Returned by ``LinksService.workbench_links()`` and
    ``LinksService.get_workbench_links()``.

    For Workbench >= 26.1.0, links use ``/nui/scans/{id}/...`` paths.
    For older versions, ``index.html`` query-parameter format is used.
    """

    def __init__(
        self, api_url: str, scan_id: int, workbench_version: str = ""
    ):
        self._api_url = api_url
        self._scan_id = scan_id
        self._base_url = api_url.replace("/api.php", "").rstrip("/")
        self._nui = self._should_use_nui(workbench_version)

    @staticmethod
    def _should_use_nui(version_string: str) -> bool:
        """Return True when *version_string* indicates >= 2026.1.0."""
        if not version_string:
            return False
        try:
            return packaging_version.parse(
                version_string
            ) >= packaging_version.parse(NUI_MIN_VERSION)
        except packaging_version.InvalidVersion:
            return False

    def _build_link(
        self, view_param: str = None, message: str = ""
    ) -> Dict[str, str]:
        url = (
            f"{self._base_url}/index.html?"
            f"form=main_interface&action=scanview&sid={self._scan_id}"
        )
        if view_param:
            url += f"&current_view={view_param}"
        return {"url": url, "message": message}

    def _build_nui_link(
        self, path: str, message: str = ""
    ) -> Dict[str, str]:
        url = f"{self._base_url}/nui/scans/{self._scan_id}/{path}"
        return {"url": url, "message": message}

    @property
    def scan(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "audit/all", message="View this Scan in Workbench"
            )
        return self._build_link(
            view_param="all_items", message="View this Scan in Workbench"
        )

    @property
    def pending(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "audit/pending",
                message="Review Pending IDs in Workbench",
            )
        return self._build_link(
            view_param="pending_items",
            message="Review Pending IDs in Workbench",
        )

    @property
    def identified(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "audit/identified",
                message="View Identified Components in Workbench",
            )
        return self._build_link(
            view_param="mark_as_identified",
            message="View Identified Components in Workbench",
        )

    @property
    def dependencies(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "audit/dependencies",
                message="View Dependencies in Workbench",
            )
        return self._build_link(
            view_param="dependency_analysis",
            message="View Dependencies in Workbench",
        )

    @property
    def policy(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "risk-review/license-review",
                message="Review policy warnings in Workbench",
            )
        return self._build_link(
            view_param="mark_as_identified",
            message="Review policy warnings in Workbench",
        )

    @property
    def vulnerabilities(self) -> Dict[str, str]:
        if self._nui:
            return self._build_nui_link(
                "risk-review/security-review",
                message="Review Vulnerable Components in Workbench",
            )
        return self._build_link(
            view_param="mark_as_identified",
            message="Review Vulnerable Components in Workbench",
        )


class LinksService:
    """
    Build version-aware Workbench UI deep links for scans.

    Not backed by a Workbench API group; uses ``api_url``, ``scan_id``, and
    server version only. Resolves ``scan_code`` via ``ScansClient`` when needed.
    """

    def __init__(
        self,
        scans_client,
        api_url: str,
        workbench_version: str = "",
    ) -> None:
        self._scans = scans_client
        self._api_url = api_url
        self._workbench_version = workbench_version
        logger.debug("LinksService initialized")

    def workbench_links(self, scan_id: int) -> WorkbenchLinks:
        """Return link properties for a numeric scan id."""
        return WorkbenchLinks(
            self._api_url,
            scan_id,
            workbench_version=self._workbench_version,
        )

    def get_workbench_links(self, scan_code: str) -> WorkbenchLinks:
        """Resolve ``scan_code`` to id and return ``WorkbenchLinks``."""
        scan_info = self._scans.get_information(scan_code)
        scan_id = scan_info.get("id")
        if not scan_id:
            raise ApiError(f"Scan '{scan_code}' has no ID")
        return self.workbench_links(int(scan_id))
