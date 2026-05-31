"""FilesAndFoldersClient - scan file identification and folder operations."""

import logging
from typing import Any, Dict, List, Optional, Union

from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.utils.path_encoding import encode_path

from . import errors

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

    _GROUP = "files_and_folders"

    def __init__(self, base_api):
        """
        Initialize FilesAndFoldersClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("FilesAndFoldersClient initialized")

    encode_path = staticmethod(encode_path)

    def _request(
        self,
        action: str,
        data: Dict[str, Any],
        *,
        error_context: str,
        include_message: bool = False,
    ) -> Union[Any, Dict[str, Any]]:
        payload = {
            "group": self._GROUP,
            "action": action,
            "data": data,
        }
        response = self._api._send_request(payload)
        if response.get("status") == "1":
            if include_message:
                return {
                    "data": response.get("data"),
                    "message": response.get("message"),
                }
            return response.get("data")
        errors.raise_on_failed_response(
            response, error_context=error_context
        )
        return None  # unreachable

    def get_folder_content(
        self,
        scan_code: str,
        path: str = ".",
        *,
        show_all: Union[bool, int, str] = True,
        source_code_only: Union[bool, int, str] = False,
    ) -> List[Dict[str, Any]]:
        """
        List files and subdirectories under a folder in a scan.

        Required: ``scan_code``, ``path`` (base64-encoded automatically).
        ``show_all``: ``True``/``"1"`` lists all files; ``False``/``"0"`` lists
        only pending identification. ``source_code_only``: ``True``/``"1"``
        excludes non-source files.

        Returns a list of tree nodes (directories include ``children``; files
        include ``icon``). Use ``path="."`` for the scan root — an empty path
        is rejected by the server. See ``quirks.md``.
        """
        result = self._request(
            "get_folder_content",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("get_folder_content", path),
                "show_all": errors.flag_str(show_all),
                "source_code_only": errors.flag_str(source_code_only),
            },
            error_context=(
                f"Failed to get folder content for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        if isinstance(result, list):
            return result
        if result is None:
            return []
        raise ApiError(
            "Unexpected get_folder_content data format",
            details={"data": result},
        )

    def get_folder_content_metrics(
        self,
        scan_code: str,
        path: str = ".",
    ) -> Dict[str, Any]:
        """
        Get identification statistics for a folder in a scan.

        Returns a dict with ``total``, ``pending_identification``,
        ``identified_files``, and ``without_matches``. Use ``path="."`` for the
        scan root. See ``schema.md`` and ``quirks.md``.
        """
        result = self._request(
            "get_folder_content_metrics",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action(
                    "get_folder_content_metrics", path
                ),
            },
            error_context=(
                f"Failed to get folder content metrics for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        if isinstance(result, dict):
            return result
        raise ApiError(
            "Unexpected get_folder_content_metrics data format",
            details={"data": result},
        )

    def get_folder_components_ranking(
        self,
        scan_code: str,
        path: str = ".",
    ) -> Union[List[Dict[str, Any]], bool]:
        """
        Rank identified components under a folder by occurrence count.

        Returns a list of component rows sorted by ``amount`` (descending),
        scoped to the given folder path. Each row describes an identified
        artifact (``artifact``, ``version``, ``author``, licenses, etc.) with
        ``amount`` (total hits in the folder) and
        ``amount_per_artifact_version`` (hits for that name+version pair).

        Returns ``False`` when ``path`` is a file, not a folder. Use
        ``path="."`` for the scan root. See ``quirks.md``.
        """
        result = self._request(
            "get_folder_components_ranking",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action(
                    "get_folder_components_ranking", path
                ),
            },
            error_context=(
                f"Failed to get folder components ranking for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        if isinstance(result, list) or result is False:
            return result
        raise ApiError(
            "Unexpected get_folder_components_ranking data format",
            details={"data": result},
        )

    def get_folder_extensions_ranking(
        self,
        scan_code: str,
        path: str = ".",
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
            "path": errors.path_for_action(
                "get_folder_extensions_ranking", path
            ),
        }
        if current_view is not None:
            data["current_view"] = current_view

        result = self._request(
            "get_folder_extensions_ranking",
            data,
            error_context=(
                f"Failed to get folder extensions ranking for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        if isinstance(result, list) or result is False:
            return result
        raise ApiError(
            "Unexpected get_folder_extensions_ranking data format",
            details={"data": result},
        )

    def get_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """
        Get identification information for a file.

        Required: ``scan_code``, ``path`` (encoded automatically). Returns
        ``data`` only (top-level ``message`` omitted) — see ``schema.md``.
        """
        return self._request(
            "get_identification",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("get_identification", path),
            },
            error_context=(
                f"Failed to get identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )

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
        return self._request(
            "set_identification_copyright",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action(
                    "set_identification_copyright", path
                ),
                "is_directory": errors.flag_str(is_directory),
                "copyright": copyright,
            },
            error_context=(
                f"Failed to set copyright for '{path}' in scan '{scan_code}'"
            ),
            include_message=True,
        )

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
        return self._request(
            "add_license_identification",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action(
                    "add_license_identification", path
                ),
                "license_identifier": license_identifier,
                "identification_on": identification_on,
                "is_directory": errors.flag_str(is_directory),
            },
            error_context=(
                f"Failed to add license identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
            include_message=True,
        )

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
            "path": errors.path_for_action("set_identification_component", path),
            "is_directory": errors.flag_str(is_directory),
            "component_name": component_name,
            "component_version": component_version,
            "preserve_existing_identifications": errors.flag_str(
                preserve_existing_identifications
            ),
        }
        if supplier_name is not None:
            data["supplier_name"] = supplier_name

        return self._request(
            "set_identification_component",
            data,
            error_context=(
                f"Failed to set component identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def get_fossid_results(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Get FossID scan match candidates for a file (max 10)."""
        return self._request(
            "get_fossid_results",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("get_fossid_results", path),
            },
            error_context=(
                f"Failed to get FossID results for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )

    def get_matched_lines(
        self,
        scan_code: str,
        path: str,
        client_result_id: str,
    ) -> Dict[str, Any]:
        """Get matched lines for a partial FossID match."""
        return self._request(
            "get_matched_lines",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("get_matched_lines", path),
                "client_result_id": client_result_id,
            },
            error_context=(
                f"Failed to get matched lines for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )

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
        return self._request(
            "add_file_comment",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("add_file_comment", path),
                "comment": comment,
                "is_important": errors.flag_str(is_important),
                "include_in_report": errors.flag_str(include_in_report),
            },
            error_context=(
                f"Failed to add comment for '{path}' in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def get_file_comments(
        self, scan_code: str, path: str
    ) -> List[Dict[str, Any]]:
        """Get comments associated with a file."""
        result = self._request(
            "get_file_comments",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("get_file_comments", path),
            },
            error_context=(
                f"Failed to get comments for '{path}' in scan '{scan_code}'"
            ),
        )
        if isinstance(result, list):
            return result
        if result is None:
            return []
        raise ApiError(
            "Unexpected get_file_comments data format",
            details={"data": result},
        )

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
            data["is_important"] = errors.flag_str(is_important)
        if include_in_report is not None:
            data["include_in_report"] = errors.flag_str(include_in_report)

        return self._request(
            "edit_file_comment",
            data,
            error_context=(
                f"Failed to edit comment {comment_id} in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def delete_file_comment(
        self,
        scan_code: str,
        comment_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete a file comment."""
        return self._request(
            "delete_file_comment",
            {
                "scan_code": scan_code,
                "comment_id": str(comment_id),
            },
            error_context=(
                f"Failed to delete comment {comment_id} in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def mark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """Mark a file or folder as identified (audit complete)."""
        return self._request(
            "mark_as_identified",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("mark_as_identified", path),
                "is_directory": errors.flag_str(is_directory),
            },
            error_context=(
                f"Failed to mark '{path}' as identified in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def unmark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: Union[bool, int, str] = False,
    ) -> Dict[str, Any]:
        """Unmark a file or folder as identified."""
        return self._request(
            "unmark_as_identified",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action("unmark_as_identified", path),
                "is_directory": errors.flag_str(is_directory),
            },
            error_context=(
                f"Failed to unmark '{path}' identified in scan '{scan_code}'"
            ),
            include_message=True,
        )

    def change_distribution_status(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Toggle distributed / not distributed for a file."""
        return self._request(
            "change_distribution_status",
            {
                "scan_code": scan_code,
                "path": errors.path_for_action(
                    "change_distribution_status", path
                ),
            },
            error_context=(
                f"Failed to change distribution status for '{path}' "
                f"in scan '{scan_code}'"
            ),
            include_message=True,
        )

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
            "path": errors.path_for_action(
                "remove_component_identification", path
            ),
        }
        if component_name is not None:
            data["component_name"] = component_name
        if component_version is not None:
            data["component_version"] = component_version

        result = self._request(
            "remove_component_identification",
            data,
            error_context=(
                f"Failed to remove component identification for '{path}' "
                f"in scan '{scan_code}'"
            ),
        )
        if isinstance(result, bool):
            return result
        return bool(result)
