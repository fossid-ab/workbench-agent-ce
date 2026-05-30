"""
UserPermissionsService - Resolve if the API user can perform operations.

Uses :class:`~workbench_agent.api.clients.users.UsersClient` and
:class:`~workbench_agent.api.clients.scans.ScansClient` so handlers can
check permissions (e.g. ``can_delete_scan``) before running an operation.
"""

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("workbench-agent")

# Permission `code` values from Workbench (users / get_user_permissions_list).
PERMISSION_SCAN_DELETE_ANY = "SCAN_DELETE_ANY"


class UserPermissionsService:
    """
    Service to check permissions for the configured API user.

    Permissions are fetched lazily via ``get_user_permissions_list`` using
    ``searched_username`` (the same string as ``--api-user``).

    Example:
        >>> svc = UserPermissionsService(users, scans, api_user="alice@corp")
        >>> if svc.can_delete_scan(scan_code):
        ...     scan_deletion.delete_scan(scan_code)
    """

    def __init__(self, users_client, scans_client, api_user: str):
        self._users = users_client
        self._scans = scans_client
        self._api_user = api_user
        self._cache: Optional[List[Dict[str, Any]]] = None
        logger.debug("UserPermissionsService initialized for %s", api_user)

    @property
    def api_user(self) -> str:
        """Username whose permissions are evaluated (the API user)."""
        return self._api_user

    def invalidate_cache(self) -> None:
        """Clear cached permission rows (e.g. for tests)."""
        self._cache = None

    def _permission_rows(self) -> List[Dict[str, Any]]:
        if self._cache is None:
            self._cache = self._users.get_user_permissions_list(
                searched_username=self._api_user,
            )
            logger.debug(
                "Loaded %d permission row(s) for %s",
                len(self._cache),
                self._api_user,
            )
        return self._cache

    def permission_codes(self) -> Set[str]:
        """Set of ``code`` strings present for the API user."""
        codes: Set[str] = set()
        for row in self._permission_rows():
            code = row.get("code")
            if isinstance(code, str) and code:
                codes.add(code)
        return codes

    def has_permission_code(self, code: str) -> bool:
        """Return True if the API user has this permission ``code``."""
        return code in self.permission_codes()

    def can_delete_scan(self, scan_code: str) -> bool:
        """
        Return True if the API user may delete this scan.

        **Yes** if **either** is true:

        1. ``scans/get_information`` → ``username`` equals the configured API
           user (``--api-user``), after stripping whitespace.
        2. The user has global scan delete permission (``SCAN_DELETE_ANY``).

        Owner match is checked first so typical ``own scan`` deletes need only
        one API call (``get_information``) and never load permission rows.

        Raises:
            ScanNotFoundError: If ``scan_code`` does not exist.
            ApiError: If the users or scans API calls fail.
        """
        scan_info = self._scans.get_information(scan_code)
        api = self._api_user.strip()
        v = scan_info.get("username")
        if isinstance(v, str) and v.strip() == api:
            return True
        return self.has_permission_code(PERMISSION_SCAN_DELETE_ANY)
