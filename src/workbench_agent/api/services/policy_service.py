"""
PolicyService - License policy warning counts for a scan.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("workbench-agent")


class PolicyService:
    """
    Read license policy warning counters for a scan.

    Example:
        >>> svc = PolicyService(client.scans)
        >>> warnings = svc.get_policy_warnings(scan_code)
        >>> warnings["policy_warnings_total"]
    """

    def __init__(self, scans_client) -> None:
        self._scans = scans_client
        logger.debug("PolicyService initialized")

    def get_policy_warnings(self, scan_code: str) -> Dict[str, Any]:
        """
        Return policy warning counts for a scan.

        Keys include ``policy_warnings_total``,
        ``identified_files_with_warnings``, and ``dependencies_with_warnings``.
        """
        logger.debug(
            "Fetching policy warnings counter for scan '%s'", scan_code
        )
        warnings = self._scans.get_policy_warnings_counter(scan_code)
        logger.debug("Retrieved policy warnings counter")
        return warnings
