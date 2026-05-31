"""
ScanDeletionService - Queue scan deletion and wait until the job completes.

Orchestrates :class:`~workbench_agent.api.clients.scans.ScansClient`
``delete`` with :class:`~workbench_agent.api.services.status_check_service.StatusCheckService`
``check_delete_scan_status`` (polling).

Authorization is **not** enforced here: callers should use
:class:`~workbench_agent.api.services.user_permissions.UserPermissionsService`
(``can_delete_scan``) before ``delete_scan`` when the operation must respect
Workbench permissions.
"""

import logging
from typing import Any, Dict, Optional

from workbench_agent.api.exceptions import ApiError, ScanNotFoundError
from workbench_agent.api.utils.process_waiter import StatusResult

logger = logging.getLogger("workbench-agent")


def _is_delete_scan_not_found_error(details: Optional[Dict[str, Any]]) -> bool:
    """True when scans/delete failed because the scan row does not exist."""
    if not isinstance(details, dict):
        return False
    err = str(details.get("error", ""))
    if "row_not_found" in err or "Scan not found" in err:
        return True
    msg = str(details.get("message", ""))
    if "not found" in msg.lower() and "scans" in msg.lower():
        return True
    mp = details.get("message_parameters")
    if isinstance(mp, dict):
        return (
            mp.get("table") == "scans"
            and mp.get("rowidentifier") == "scan_code"
        )
    return False


def _process_id_from_delete_response(response: Dict[str, Any]) -> int:
    data = response.get("data")
    if not isinstance(data, dict):
        raise ApiError(
            "Delete scan response missing data object",
            details=response,
        )
    pid = data.get("process_id")
    if pid is None:
        raise ApiError(
            "Delete scan response missing process_id",
            details=response,
        )
    return int(pid)


class ScanDeletionService:
    """
    Queue deletion of a scan and wait until the background job finishes.

        Expects ``scan_code`` to already be resolved by the caller (e.g. handler).
        Does not check delete permission; see ``UserPermissionsService``.

    Example:
        >>> svc = ScanDeletionService(scans_client, status_check_service)
        >>> result = svc.delete_scan("my_scan_code")
        >>> assert result.success
    """

    def __init__(self, scans_client, status_check_service):
        self._scans = scans_client
        self._status_check = status_check_service
        logger.debug("ScanDeletionService initialized")

    def delete_scan(
        self,
        scan_code: str,
        *,
        delete_identifications: bool = True,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 2,
    ) -> StatusResult:
        """
        Queue ``scans/delete`` and poll until deletion completes or fails.

        Args:
            scan_code: Scan code (already resolved)
            delete_identifications: Maps to API ``delete_identifications`` ``1``/``0``
            wait_retry_count: Max status polls when waiting
            wait_retry_interval: Seconds between polls (default 2)

        Returns:
            StatusResult: Terminal state when the delete job completes

        Raises:
            ScanNotFoundError: If the scan does not exist (invalid code)
            ApiError: On API failures or malformed responses
        """
        logger.info(f"Deleting scan '{scan_code}'...")

        try:
            response = self._scans.delete(
                scan_code,
                delete_identifications=delete_identifications,
            )
        except ApiError as e:
            if _is_delete_scan_not_found_error(e.details):
                raise ScanNotFoundError(
                    f"Scan '{scan_code}' not found",
                    details=e.details,
                ) from e
            raise

        process_id = _process_id_from_delete_response(response)
        logger.debug(
            f"Delete job queued for '{scan_code}', process_id={process_id}"
        )

        return self._status_check.check_delete_scan_status(
            scan_code,
            process_id,
            wait=True,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )
