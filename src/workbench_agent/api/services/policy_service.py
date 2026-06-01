"""
PolicyService - License policy warning reads for scans and projects.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("workbench-agent")


class PolicyService:
    """
    Read license policy warning counters and project-level aggregates.

    Scan-level counts use ``ScansClient.get_policy_warnings_counter``.
    Project-level summaries use ``ProjectsClient.get_policy_warnings_info``.

    Example:
        >>> svc = PolicyService(client.scans, client.projects)
        >>> svc.get_policy_warnings(scan_code)
        >>> svc.get_project_policy_warnings_all(project_code)
    """

    def __init__(self, scans_client, projects_client) -> None:
        self._scans = scans_client
        self._projects = projects_client
        logger.debug("PolicyService initialized")

    def get_policy_warnings(self, scan_code: str) -> Dict[str, Any]:
        """
        Return per-scan policy warning counts.

        Keys include ``policy_warnings_total``,
        ``identified_files_with_warnings``, and ``dependencies_with_warnings``.
        """
        logger.debug(
            "Fetching policy warnings counter for scan '%s'", scan_code
        )
        warnings = self._scans.get_policy_warnings_counter(scan_code)
        logger.debug("Retrieved policy warnings counter")
        return warnings

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
        """
        Project policy warnings from dependency analysis only.
        """
        return self._projects.get_policy_warnings_info(
            project_code, warning_type="dependencies"
        )

    def get_project_policy_warnings_all(
        self, project_code: str
    ) -> Dict[str, Any]:
        """
        Project policy warnings from identifications and dependencies.
        """
        return self._projects.get_policy_warnings_info(
            project_code, warning_type="all"
        )
