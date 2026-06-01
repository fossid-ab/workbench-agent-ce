"""
PolicyService - License policy operations for scans and projects.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Union

from workbench_agent.api.exceptions import ApiError

logger = logging.getLogger("workbench-agent")


class PolicyService:
    """
    Read and operate on license policies at scan and project scopes.

    Supports policy warnings counting
    Project aggregates use ``get_project_*_policy_warnings`` /
    ``ProjectsClient.get_policy_warnings_info``. Full policy export uses
    ``download_project_policy_json`` / ``DownloadClient.get_project_policy``.
    """

    def __init__(self, scans_client, projects_client, downloads_client) -> None:
        self._scans = scans_client
        self._projects = projects_client
        self._downloads = downloads_client
        logger.debug("PolicyService initialized")

    # ===== SCAN-LEVEL POLICY OPERATIONS =====

    def get_policy_warnings(self, scan_code: str) -> Dict[str, Any]:
        """
        Return per-scan policy warning counts (summary only).

        Keys include ``policy_warnings_total``,
        ``identified_files_with_warnings``, and ``dependencies_with_warnings``.
        """
        logger.debug(
            "Fetching policy warnings counter for scan '%s'", scan_code
        )
        warnings = self._scans.get_policy_warnings_counter(scan_code)
        logger.debug("Retrieved policy warnings counter")
        return warnings

    def get_scan_identification_policy_warnings_info(
        self, scan_code: str
    ) -> Dict[str, Any]:
        """
        Policy rules and per-rule ``findings`` from scan file identifications.

        Returns ``policy_warnings_list`` (may be empty).
        """
        return self._scans.get_policy_warnings_info(
            scan_code, warning_type="identifications"
        )

    def get_scan_dependency_policy_warnings_info(
        self, scan_code: str
    ) -> Dict[str, Any]:
        """Policy rules and findings from dependency analysis only."""
        return self._scans.get_policy_warnings_info(
            scan_code, warning_type="dependencies"
        )

    def get_scan_policy_warnings_info_all(
        self, scan_code: str
    ) -> Dict[str, Any]:
        """Policy rules and findings from identifications and dependencies."""
        return self._scans.get_policy_warnings_info(
            scan_code, warning_type="all"
        )

    # ===== PROJECT-LEVEL POLICY OPERATIONS =====

    def get_project_identification_policy_warnings(
        self, project_code: str
    ) -> Dict[str, Any]:
        """
        Project policy warnings from scan file identifications only.

        Returns ``scans_with_warnings``, ``warnings_counter``, and
        ``scans_list`` (affected scans).
        """
        return self._projects.get_policy_warnings_info(
            project_code, warning_type="identifications"
        )

    def get_project_dependency_policy_warnings(
        self, project_code: str
    ) -> Dict[str, Any]:
        """Project policy warnings from dependency analysis only."""
        return self._projects.get_policy_warnings_info(
            project_code, warning_type="dependencies"
        )

    def get_project_policy_warnings_all(
        self, project_code: str
    ) -> Dict[str, Any]:
        """Project policy warnings from identifications and dependencies."""
        return self._projects.get_policy_warnings_info(
            project_code, warning_type="all"
        )

    # ===== DOWNLOAD PROJECT POLICY JSON =====

    def download_project_policy_json(
        self, project_code: str
    ) -> Union[List[Any], Dict[str, Any]]:
        """
        Download and parse the project's license policy JSON.

        Returns a list of license rule objects (``id``, ``blocked``,
        ``reason``, …) as returned by ``download -> licenses_policy_info``.
        """
        logger.debug(
            "Downloading project policy JSON for '%s'", project_code
        )
        response = self._downloads.get_project_policy(project_code)
        raw = response.get("_raw_response")
        if raw is not None:
            try:
                parsed = json.loads(raw.content)
            except (ValueError, TypeError) as exc:
                raise ApiError(
                    f"Invalid project policy JSON for '{project_code}': {exc}"
                ) from exc
            logger.debug("Parsed project policy JSON from download body")
            return parsed

        if isinstance(response, dict) and "data" in response:
            data = response["data"]
            if isinstance(data, (dict, list)):
                return data

        if isinstance(response, (dict, list)):
            return response

        raise ApiError(
            f"Unexpected project policy response for '{project_code}'"
        )
