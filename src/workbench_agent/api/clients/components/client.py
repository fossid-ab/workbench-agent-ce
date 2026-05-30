"""ComponentsClient - component catalog Workbench API operations."""

import logging
from typing import Any, Dict, List, Optional, Union

from workbench_agent.api.exceptions import ApiError

from . import errors

logger = logging.getLogger("workbench-agent")


class ComponentsClient:
    """
    Components API client (group: components).

    Request/response fields: ``clients/components/schema.md``.
    Server quirks: ``clients/components/quirks.md``.

    Example:
        >>> client = ComponentsClient(base_api)
        >>> components = client.list_components()
        >>> info = client.get_information("openssl", "1.1.1")
    """

    _GROUP = "components"

    def __init__(self, base_api):
        """
        Initialize ComponentsClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("ComponentsClient initialized")

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

    def list_components(
        self,
        *,
        name: Optional[str] = None,
        count_results: Optional[Union[bool, int, str]] = None,
        records_per_page: Optional[Union[int, str]] = None,
        page: Optional[Union[int, str]] = None,
        order_by: Optional[str] = None,
        direction: Optional[str] = None,
    ) -> Any:
        """
        List components in the catalog with optional filtering and pagination.

        Optional ``data`` fields: ``name``, ``count_results``, ``records_per_page``,
        ``page``, ``order_by``, ``direction`` — see ``schema.md``.

        Args:
            name: MySQL pattern filter (optional).
            count_results: If truthy, return count only (wire: ``"0"``/``"1"``).
            records_per_page: Page size (coerced to string).
            page: Page number (coerced to string).
            order_by: Sort field (``version``, ``name``, ``license_name``, …).
            direction: ``ASC`` or ``DESC``.

        Returns:
            List of components, ``{count_results: N}``, a count string, or ``null``.
        """
        data: Dict[str, Any] = {}
        if name is not None:
            data["name"] = name
        if count_results is not None:
            data["count_results"] = (
                "1" if count_results in (True, 1, "1") else "0"
            )
        if records_per_page is not None:
            data["records_per_page"] = errors.optional_str(records_per_page)
        if page is not None:
            data["page"] = errors.optional_str(page)
        if order_by is not None:
            data["order_by"] = order_by
        if direction is not None:
            data["direction"] = direction

        response = self._request(
            "list_components",
            data,
            error_context="Failed to list components",
        )
        return response.get("data")

    def list_by_usage(
        self,
        *,
        page: Optional[int] = None,
        records_per_page: Optional[int] = None,
        search_value: Optional[str] = None,
        usage_equal_or_above: Optional[int] = None,
        order_by: Optional[str] = None,
        direction: Optional[str] = None,
        count_results: Optional[Union[bool, int]] = None,
    ) -> Dict[str, Any]:
        """
        List components ranked by usage with pagination metadata.

        Optional ``data`` fields: ``page``, ``records_per_page``, ``search_value``,
        ``usage_equal_or_above``, ``order_by``, ``direction``, ``count_results``
        — see ``schema.md``.

        Returns:
            Dict with ``total_count``, ``page``, ``list``, ``next_page``, etc.
        """
        data: Dict[str, Any] = {}
        if page is not None:
            data["page"] = page
        if records_per_page is not None:
            data["records_per_page"] = records_per_page
        if search_value is not None:
            data["search_value"] = search_value
        if usage_equal_or_above is not None:
            data["usage_equal_or_above"] = usage_equal_or_above
        if order_by is not None:
            data["order_by"] = order_by
        if direction is not None:
            data["direction"] = direction
        if count_results is not None:
            data["count_results"] = 1 if count_results in (True, 1) else 0

        response = self._request(
            "list_by_usage",
            data,
            error_context="Failed to list components by usage",
        )
        result = response.get("data")
        if isinstance(result, dict):
            return result
        raise ApiError(
            "Unexpected list_by_usage data format",
            details=response,
        )

    def get_information(
        self,
        component_name: str,
        component_version: Optional[str] = None,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
        """
        Get detailed information for a component.

        Required: ``component_name``. Optional: ``component_version`` (omit for
        all versions) — see ``schema.md``.

        Returns:
            Dict (version given), list of dicts (version omitted), or ``None`` if
            not found (quirks.md — not an exception).
        """
        data: Dict[str, Any] = {"component_name": component_name}
        if component_version is not None:
            data["component_version"] = component_version

        response = self._request(
            "get_information",
            data,
            error_context=(
                f"Failed to get information for component '{component_name}'"
            ),
        )
        return response.get("data")

    def create(
        self,
        name: str,
        version: str,
        license_identifier: str,
        *,
        cpe: Optional[str] = None,
        package_size: Optional[str] = None,
        package_size_binary: Optional[str] = None,
        commits_nro: Optional[str] = None,
        contributors_nro: Optional[str] = None,
        releases_nro: Optional[str] = None,
        bugs_nro: Optional[str] = None,
        fixed_bugs_nro: Optional[str] = None,
        community_size: Optional[str] = None,
        purl: Optional[str] = None,
        url: Optional[str] = None,
        supplier_url: Optional[str] = None,
        community_url: Optional[str] = None,
        download_url: Optional[str] = None,
        download_url_binary: Optional[str] = None,
        package_md5: Optional[str] = None,
        package_sha1: Optional[str] = None,
        comment: Optional[str] = None,
        description: Optional[str] = None,
        repository_download_path_binary: Optional[str] = None,
        copyright: Optional[str] = None,
        attribution_acknowledgement: Optional[str] = None,
        warranty_liability_exclusions: Optional[str] = None,
        known_bugs: Optional[str] = None,
        known_vulnerabilities: Optional[str] = None,
        change_log: Optional[str] = None,
        platform: Optional[str] = None,
        programming_language: Optional[str] = None,
        binary_md5: Optional[str] = None,
        binary_sha1: Optional[str] = None,
        sup_com_name: Optional[str] = None,
        sha256: Optional[str] = None,
        binary_sha256: Optional[str] = None,
        release_date: Optional[str] = None,
        built_date: Optional[str] = None,
        community_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new component in the Workbench catalog.

        Required: ``name``, ``version``, ``license_identifier``. All other spec
        fields are optional keyword args — see ``schema.md`` (full list).

        Returns:
            ``{"data": {component_id, …}, "message": …}`` when the API includes
            a message.

        Raises:
            ApiError: If the API returns an error.
        """
        data: Dict[str, Any] = {
            "name": name,
            "version": version,
            "license_identifier": license_identifier,
        }
        for key, value in (
            ("cpe", cpe),
            ("package_size", package_size),
            ("package_size_binary", package_size_binary),
            ("commits_nro", commits_nro),
            ("contributors_nro", contributors_nro),
            ("releases_nro", releases_nro),
            ("bugs_nro", bugs_nro),
            ("fixed_bugs_nro", fixed_bugs_nro),
            ("community_size", community_size),
            ("purl", purl),
            ("url", url),
            ("supplier_url", supplier_url),
            ("community_url", community_url),
            ("download_url", download_url),
            ("download_url_binary", download_url_binary),
            ("package_md5", package_md5),
            ("package_sha1", package_sha1),
            ("comment", comment),
            ("description", description),
            ("repository_download_path_binary", repository_download_path_binary),
            ("copyright", copyright),
            ("attribution_acknowledgement", attribution_acknowledgement),
            ("warranty_liability_exclusions", warranty_liability_exclusions),
            ("known_bugs", known_bugs),
            ("known_vulnerabilities", known_vulnerabilities),
            ("change_log", change_log),
            ("platform", platform),
            ("programming_language", programming_language),
            ("binary_md5", binary_md5),
            ("binary_sha1", binary_sha1),
            ("sup_com_name", sup_com_name),
            ("sha256", sha256),
            ("binary_sha256", binary_sha256),
            ("release_date", release_date),
            ("built_date", built_date),
            ("community_status", community_status),
        ):
            if value is not None:
                data[key] = value

        response = self._request(
            "create",
            data,
            error_context=f"Failed to create component '{name}' '{version}'",
        )
        result: Dict[str, Any] = {"data": response.get("data")}
        if "message" in response:
            result["message"] = response["message"]
        return result

    def delete(self, name: str, version: str) -> bool:
        """
        Delete a component by name and version.

        Returns:
            bool from API data field.
        """
        response = self._request(
            "delete",
            {"name": name, "version": version},
            error_context=f"Failed to delete component '{name}' '{version}'",
        )
        data = response.get("data")
        if isinstance(data, bool):
            return data
        return bool(data)

    def get_usage(
        self,
        *,
        component_id: Optional[int] = None,
        project_id: Optional[int] = None,
        from_api: Optional[Union[bool, int]] = None,
        page: Optional[int] = None,
        records_per_page: Optional[int] = None,
        direction: Optional[str] = None,
        order_by: Optional[str] = None,
        search_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get paginated scan/project usage for a component.

        Optional ``data`` fields: ``component_id``, ``project_id``, ``from_api``,
        ``page``, ``records_per_page``, ``direction``, ``order_by``,
        ``search_value`` — see ``schema.md``.

        Returns:
            Dict with ``page``, ``list`` (array), and on 2026.1 ``records_total``.
        """
        data: Dict[str, Any] = {}
        if component_id is not None:
            data["component_id"] = component_id
        if project_id is not None:
            data["project_id"] = project_id
        if from_api is not None:
            data["from_api"] = 1 if from_api in (True, 1) else 0
        if page is not None:
            data["page"] = page
        if records_per_page is not None:
            data["records_per_page"] = records_per_page
        if direction is not None:
            data["direction"] = direction
        if order_by is not None:
            data["order_by"] = order_by
        if search_value is not None:
            data["search_value"] = search_value

        response = self._request(
            "get_usage",
            data,
            error_context="Failed to get component usage",
        )
        result = response.get("data")
        if isinstance(result, dict):
            return result
        raise ApiError(
            "Unexpected get_usage data format",
            details=response,
        )

    def get_usage_count(self, component_id: int) -> Dict[str, int]:
        """
        Get identification and dependency usage counts for a component.

        Returns:
            Dict with identifications_usage_count and dependency_usage_count.
        """
        response = self._request(
            "get_usage_count",
            {"id": component_id},
            error_context=(
                f"Failed to get usage count for component id {component_id}"
            ),
        )
        result = response.get("data")
        if isinstance(result, dict):
            return result
        raise ApiError(
            "Unexpected get_usage_count data format",
            details=response,
        )
