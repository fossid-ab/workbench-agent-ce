"""VulnerabilitiesClient - vulnerability and VEX Workbench API operations."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Union

from workbench_agent.api.exceptions import ApiError

from . import errors

logger = logging.getLogger("workbench-agent")


class VulnerabilitiesClient:
    """
    Vulnerabilities API client (group: vulnerabilities).

    Request/response fields: ``clients/vulnerabilities/schema.md``.
    Server quirks: ``clients/vulnerabilities/quirks.md``.

    Example:
        >>> client = VulnerabilitiesClient(base_api)
        >>> page = client.list_vulnerabilities(scan_code=scan_code, page=1)
        >>> info = client.get_information("CVE-2021-20089")
    """

    _GROUP = "vulnerabilities"

    def __init__(self, base_api):
        self._api = base_api
        logger.debug("VulnerabilitiesClient initialized")

    def _request(
        self,
        action: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        error_context: str,
    ) -> Dict[str, Any]:
        payload = {
            "group": self._GROUP,
            "action": action,
            "data": data or {},
        }
        response = self._api._send_request(payload)
        if response.get("status") == "1":
            return response
        errors.raise_on_failed_response(
            response, error_context=error_context
        )

    def list_vulnerabilities(
        self,
        *,
        scan_code: Optional[str] = None,
        project_code: Optional[str] = None,
        search_value: Optional[str] = None,
        records_per_page: Optional[Union[int, str]] = None,
        page: Optional[Union[int, str]] = None,
        count_results: Optional[Union[bool, int, str]] = None,
    ) -> Any:
        """
        Single ``list_vulnerabilities`` API call.

        Returns the response ``data`` object as-is: ``{count_results: N}``,
        ``{list: [...]}``, or other shapes per ``schema.md``. For a full
        flattened list across pages, use ``VulnerabilityService``.
        """
        response = self._request(
            "list_vulnerabilities",
            errors.build_list_payload(
                scan_code=scan_code,
                project_code=project_code,
                search_value=search_value,
                records_per_page=records_per_page,
                page=page,
                count_results=count_results,
            ),
            error_context="Failed to list vulnerabilities",
        )
        return response.get("data")

    def count_vulnerabilities(
        self,
        *,
        scan_code: Optional[str] = None,
        project_code: Optional[str] = None,
        search_value: Optional[str] = None,
    ) -> int:
        """Return ``count_results`` from one count-only list call."""
        data = self.list_vulnerabilities(
            scan_code=scan_code,
            project_code=project_code,
            search_value=search_value,
            count_results=True,
        )
        if isinstance(data, dict) and "count_results" in data:
            return int(data["count_results"])
        return 0

    def get_information(self, cve: str) -> Dict[str, Any]:
        """
        Return KB CVE details and scan-level VEX rows for a CVE id.

        Returns the ``data`` object (``cve`` list and
        ``component_vulnerability_in_scans`` list).
        """
        response = self._request(
            "get_information",
            {"cve": cve},
            error_context=f"Failed to get vulnerability information for {cve!r}",
        )
        data = response.get("data")
        if isinstance(data, dict):
            return data
        raise ApiError(
            f"Unexpected get_information response for {cve!r}",
            details=response,
        )

    def create_vulnerability_exploitability(
        self,
        scan_code: str,
        component_id: int,
        cve: str,
        *,
        vuln_exp_status: Optional[str] = None,
        vuln_exp_justification: Optional[str] = None,
        vuln_exp_response: Optional[str] = None,
        vuln_exp_details: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a VEX (vulnerability exploitability) statement for a scan row.

        Returns:
            Dict with ``id`` and optional ``message`` from the API body.
        """
        payload: Dict[str, Any] = {
            "scan_code": scan_code,
            "component_id": int(component_id),
            "cve": cve,
        }
        if vuln_exp_status is not None:
            payload["vuln_exp_status"] = vuln_exp_status
        if vuln_exp_justification is not None:
            payload["vuln_exp_justification"] = vuln_exp_justification
        if vuln_exp_response is not None:
            payload["vuln_exp_response"] = vuln_exp_response
        if vuln_exp_details is not None:
            payload["vuln_exp_details"] = vuln_exp_details

        response = self._request(
            "vulnerability_exploitability_create",
            payload,
            error_context=(
                f"Failed to create vulnerability exploitability for {cve!r} "
                f"on scan '{scan_code}'"
            ),
        )
        result: Dict[str, Any] = {}
        if isinstance(response.get("data"), dict):
            result.update(response["data"])
        if "message" in response:
            result["message"] = response["message"]
        return result

    def update_vulnerability_exploitability(
        self,
        vuln_exp_id: int,
        *,
        vuln_exp_status: Optional[str] = None,
        vuln_exp_justification: Optional[str] = None,
        vuln_exp_response: Optional[str] = None,
        vuln_exp_details: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an existing VEX statement by id."""
        payload: Dict[str, Any] = {"vuln_exp_id": int(vuln_exp_id)}
        if vuln_exp_status is not None:
            payload["vuln_exp_status"] = vuln_exp_status
        if vuln_exp_justification is not None:
            payload["vuln_exp_justification"] = vuln_exp_justification
        if vuln_exp_response is not None:
            payload["vuln_exp_response"] = vuln_exp_response
        if vuln_exp_details is not None:
            payload["vuln_exp_details"] = vuln_exp_details

        response = self._request(
            "vulnerability_exploitability_update",
            payload,
            error_context=(
                f"Failed to update vulnerability exploitability id {vuln_exp_id}"
            ),
        )
        return {
            "message": response.get("message"),
            "data": response.get("data"),
        }

    def import_vulnerability_exploitability_from_scan(
        self,
        scan_code_from: str,
        scan_code_to: str,
        *,
        override_vex: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """
        Copy VEX statements from one scan to another.

        Returns:
            Dict with ``data`` (list) and ``message`` from the API.
        """
        response = self._request(
            "import_vulnerability_exploitability_from_scan",
            {
                "scan_code_from": scan_code_from,
                "scan_code_to": scan_code_to,
                "override_vex": errors.flag_str(override_vex),
            },
            error_context=(
                "Failed to import vulnerability exploitability from "
                f"{scan_code_from!r} to {scan_code_to!r}"
            ),
        )
        data = response.get("data")
        return {
            "data": data if isinstance(data, list) else [],
            "message": response.get("message"),
        }
