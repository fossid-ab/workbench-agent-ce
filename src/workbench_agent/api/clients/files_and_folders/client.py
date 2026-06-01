"""FilesAndFoldersClient - scan file identification and folder operations."""

import logging
from typing import Any, Dict, List, Optional, Union

from workbench_agent.api.exceptions import ApiError

from . import helpers

logger = logging.getLogger("workbench-agent")


class FilesAndFoldersClient:
    """
    Files and folders API client (group: files_and_folders).

    Request/response fields: ``clients/files_and_folders/schema.md``.
    Server quirks: ``clients/files_and_folders/quirks.md``.

    Example:
        >>> client = FilesAndFoldersClient(base_api)
        >>> info = client.get_identification(scan_code, "src/main.c")
    """

    def __init__(self, base_api):
        """
        Initialize FilesAndFoldersClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("FilesAndFoldersClient initialized")

    encode_path = staticmethod(helpers.encode_path)
    decode_path = staticmethod(helpers.decode_path)

    def get_folder_content(
        self,
        scan_code: str,
        path: str,
        *,
        show_all: Union[bool, int, str] = True,
        source_code_only: Union[bool, int, str] = False,
    ) -> List[Dict[str, Any]]:
        """
        List files and subdirectories under a folder in a scan.

        Required: ``scan_code``, ``path`` (base64-encoded automatically).
        Pass a top-level sample folder (e.g. ``OpenFastPath``) — there is no
        scan-root ``"."`` path on Project Sample Mix scans.
        ``show_all``: ``True``/``"1"`` lists all files; ``False``/``"0"`` lists
        only pending identification. ``source_code_only``: ``True``/``"1"``
        excludes non-source files.

        Returns a list of tree nodes (directories include ``children``; files
        include ``icon``). See ``quirks.md``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_folder_content",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("get_folder_content", path),
                    "show_all": helpers.flag_str(show_all),
                    "source_code_only": helpers.flag_str(source_code_only),
                },
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, list):
                return result
            if result is None:
                return []
            raise ApiError(
                "Unexpected get_folder_content data format",
                details={"data": result},
            )
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get folder content for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return []

    def get_folder_content_metrics(
        self,
        scan_code: str,
        path: str,
    ) -> Dict[str, Any]:
        """
        Get identification statistics for a folder in a scan.

        Returns a dict with ``total``, ``pending_identification``,
        ``identified_files``, and ``without_matches``. See ``schema.md`` and
        ``quirks.md``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_folder_content_metrics",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action(
                        "get_folder_content_metrics", path
                    ),
                },
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, dict):
                return result
            raise ApiError(
                "Unexpected get_folder_content_metrics data format",
                details={"data": result},
            )
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get folder content metrics for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def get_folder_components_ranking(
        self,
        scan_code: str,
        path: str,
    ) -> Union[List[Dict[str, Any]], bool]:
        """
        Rank identified components under a folder by occurrence count.

        Returns a list of component rows sorted by ``amount`` (descending),
        scoped to the given folder path. Each row describes an identified
        artifact (``artifact``, ``version``, ``author``, licenses, etc.) with
        ``amount`` (total hits in the folder) and
        ``amount_per_artifact_version`` (hits for that name+version pair).

        Returns ``False`` when ``path`` is a file, not a folder. See ``quirks.md``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_folder_components_ranking",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action(
                        "get_folder_components_ranking", path
                    ),
                },
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, list) or result is False:
                return result
            raise ApiError(
                "Unexpected get_folder_components_ranking data format",
                details={"data": result},
            )
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get folder components ranking for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return False

    def get_folder_extensions_ranking(
        self,
        scan_code: str,
        path: str,
        *,
        current_view: Optional[str] = None,
    ) -> Union[List[Dict[str, Any]], bool]:
        """
        Rank file extensions under a folder by file count.

        Returns a list of rows (``file_extension``, ``amount``, ``id``) sorted
        by ``amount`` descending, scoped to the given folder path. An empty
        ``file_extension`` counts extensionless files.

        Optional ``current_view`` filters which files are counted:
        ``show_all``, ``all_items``, ``pending_items``,
        ``mark_as_identified``, ``without_matches``. Omit to use the server
        default (same as ``show_all`` on Workbench 2026.1).

        Returns ``False`` when ``path`` is a file or the view has no data.
        See ``quirks.md``.
        """
        data: Dict[str, Any] = {
            "scan_code": scan_code,
            "path": helpers.path_for_action(
                "get_folder_extensions_ranking", path
            ),
        }
        if current_view is not None:
            data["current_view"] = current_view

        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_folder_extensions_ranking",
                "data": data,
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, list) or result is False:
                return result
            raise ApiError(
                "Unexpected get_folder_extensions_ranking data format",
                details={"data": result},
            )
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get folder extensions ranking for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return False

    def get_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """
        Get identification information for a file.

        Required: ``scan_code``, ``path`` (encoded automatically). Returns
        ``data`` only (top-level ``message`` omitted) — see ``schema.md``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_identification",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("get_identification", path),
                },
            }
        )
        if response.get("status") == "1":
            return response.get("data")
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def set_identification_copyright(
        self,
        scan_code: str,
        path: str,
        copyright: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """
        Set copyright on a file or folder (recursive when ``is_directory``).

        Required: ``scan_code``, ``path``, ``copyright``. ``is_directory``:
        ``"0"``/``"1"`` (default file). Returns ``{"data", "message"}``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "set_identification_copyright",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action(
                        "set_identification_copyright", path
                    ),
                    "is_directory": helpers.flag_str(is_directory),
                    "copyright": copyright,
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to set copyright for '{path}' in scan '{scan_code}'"
            ),
        )
        return {}

    def add_license_identification(
        self,
        scan_code: str,
        path: str,
        license_identifier: str,
        identification_on: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """
        Add a file or snippet license identification.

        Required: ``scan_code``, ``path``, ``license_identifier``,
        ``identification_on`` (``'file'`` or ``'snippet'``), ``is_directory``.
        """
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "add_license_identification",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action(
                        "add_license_identification", path
                    ),
                    "license_identifier": license_identifier,
                    "identification_on": identification_on,
                    "is_directory": helpers.flag_str(is_directory),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to add license identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def set_identification_component(
        self,
        scan_code: str,
        path: str,
        component_name: str,
        component_version: str,
        *,
        is_directory: Union[bool, int, str] = False,
        supplier_name: Optional[str] = None,
        preserve_existing_identifications: Union[bool, int, str] = True,
    ) -> Dict[str, Any]:
        """Associate a file or folder with an existing catalog component."""
        data: Dict[str, Any] = {
            "scan_code": scan_code,
            "path": helpers.path_for_action("set_identification_component", path),
            "is_directory": helpers.flag_str(is_directory),
            "component_name": component_name,
            "component_version": component_version,
            "preserve_existing_identifications": helpers.flag_str(
                preserve_existing_identifications
            ),
        }
        if supplier_name is not None:
            data["supplier_name"] = supplier_name

        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "set_identification_component",
                "data": data,
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to set component identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def get_fossid_results(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Get FossID scan match candidates for a file (max 10)."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_fossid_results",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("get_fossid_results", path),
                },
            }
        )
        if response.get("status") == "1":
            return response.get("data")
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get FossID results for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def get_matched_lines(
        self,
        scan_code: str,
        path: str,
        client_result_id: str,
    ) -> Dict[str, Any]:
        """Get matched lines for a partial FossID match."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_matched_lines",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("get_matched_lines", path),
                    "client_result_id": client_result_id,
                },
            }
        )
        if response.get("status") == "1":
            return response.get("data")
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get matched lines for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def add_file_comment(
        self,
        scan_code: str,
        path: str,
        comment: str,
        *,
        is_important: Union[bool, int, str] = False,
        include_in_report: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """Add a comment to a file."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "add_file_comment",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("add_file_comment", path),
                    "comment": comment,
                    "is_important": helpers.flag_str(is_important),
                    "include_in_report": helpers.flag_str(include_in_report),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to add comment for '{path}' in scan '{scan_code}'"
            ),
        )
        return {}

    def get_file_comments(
        self, scan_code: str, path: str
    ) -> List[Dict[str, Any]]:
        """Get comments associated with a file."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_file_comments",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("get_file_comments", path),
                },
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, list):
                return result
            if result is None:
                return []
            raise ApiError(
                "Unexpected get_file_comments data format",
                details={"data": result},
            )
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to get comments for '{path}' in scan '{scan_code}'"
            ),
        )
        return []

    def edit_file_comment(
        self,
        scan_code: str,
        comment_id: Union[int, str],
        *,
        comment: Optional[str] = None,
        is_important: Optional[Union[bool, int, str]] = None,
        include_in_report: Optional[Union[bool, int, str]] = None,
    ) -> Dict[str, Any]:
        """Edit an existing file comment."""
        data: Dict[str, Any] = {
            "scan_code": scan_code,
            "comment_id": str(comment_id),
        }
        if comment is not None:
            data["comment"] = comment
        if is_important is not None:
            data["is_important"] = helpers.flag_str(is_important)
        if include_in_report is not None:
            data["include_in_report"] = helpers.flag_str(include_in_report)

        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "edit_file_comment",
                "data": data,
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to edit comment {comment_id} in scan '{scan_code}'"
            ),
        )
        return {}

    def delete_file_comment(
        self,
        scan_code: str,
        comment_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete a file comment."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "delete_file_comment",
                "data": {
                    "scan_code": scan_code,
                    "comment_id": str(comment_id),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to delete comment {comment_id} in scan '{scan_code}'"
            ),
        )
        return {}

    def mark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """Mark a file or folder as identified (audit complete)."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "mark_as_identified",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("mark_as_identified", path),
                    "is_directory": helpers.flag_str(is_directory),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to mark '{path}' as identified in scan '{scan_code}'"
            ),
        )
        return {}

    def unmark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """Unmark a file or folder as identified."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "unmark_as_identified",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action("unmark_as_identified", path),
                    "is_directory": helpers.flag_str(is_directory),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to unmark '{path}' identified in scan '{scan_code}'"
            ),
        )
        return {}

    def change_distribution_status(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Toggle distributed / not distributed for a file."""
        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "change_distribution_status",
                "data": {
                    "scan_code": scan_code,
                    "path": helpers.path_for_action(
                        "change_distribution_status", path
                    ),
                },
            }
        )
        if response.get("status") == "1":
            return {
                "data": response.get("data"),
                "message": response.get("message"),
            }
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to change distribution status for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return {}

    def remove_component_identification(
        self,
        scan_code: str,
        path: str,
        *,
        component_name: Optional[str] = None,
        component_version: Optional[str] = None,
    ) -> bool:
        """
        Remove component identifications from a file (not licenses/copyright).

        Path encoding: see quirks.md (plain path for this action).
        """
        data: Dict[str, Any] = {
            "scan_code": scan_code,
            "path": helpers.path_for_action(
                "remove_component_identification", path
            ),
        }
        if component_name is not None:
            data["component_name"] = component_name
        if component_version is not None:
            data["component_version"] = component_version

        response = self._api._send_request(
            {
                "group": "files_and_folders",
                "action": "remove_component_identification",
                "data": data,
            }
        )
        if response.get("status") == "1":
            result = response.get("data")
            if isinstance(result, bool):
                return result
            return bool(result)
        helpers.raise_on_failed_response(
            response,
            error_context=(
                f"Failed to remove component identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        return False
