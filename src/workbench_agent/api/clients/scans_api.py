"""
ScansClient - Handles all scan-related Workbench API operations.

This is the largest client with methods for:
- Listing and managing scans
- Running KB scans andDependency analysis
- Git operations
- Archive extraction
- Status checking
- Report generation
"""

import logging
from typing import Any, Dict, List, Optional

from workbench_agent.api.exceptions import (
    ApiError,
    ScanExistsError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")


class ScansClient:
    """
    Scans API client.

    Provides comprehensive scan management functionality including:
    - Scan CRUD operations
    - KB scanning with configurable parameters
    - Dependency analysis
    - Git repository imports
    - Process status checking
    - Report generation

    Example:
        >>> scans = ScansClient(base_api)
        >>> scan_list = scans.list()
        >>> scans.run(scan_code, limit=10, sensitivity=6)
    """

    def __init__(self, base_api):
        """
        Initialize ScansClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("ScansClient initialized")

    # ===== LIST & INFO OPERATIONS =====

    def list(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans.

        Alias for list_scans() to provide cleaner new-style API.

        Returns:
            List of scan dictionaries
        """
        return self.list_scans()

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans.

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans...")
        payload = {"group": "scans", "action": "list_scans", "data": {}}
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # API returns a dict {id: {details}}, convert to list
            if isinstance(data, dict):
                scan_list = []
                for scan_id, scan_details in data.items():
                    if isinstance(scan_details, dict):
                        try:
                            scan_details["id"] = int(scan_id)
                        except ValueError:
                            logger.warning(f"Non-integer scan ID key found: {scan_id}")
                            scan_details["id"] = scan_id

                        if "code" not in scan_details:
                            logger.warning(f"Scan details for ID {scan_id} missing 'code' field")
                        scan_list.append(scan_details)
                    else:
                        logger.warning(f"Unexpected format for scan details with ID {scan_id}")
                logger.debug(f"Successfully listed {len(scan_list)} scans.")
                return scan_list
            elif isinstance(data, list) and not data:
                logger.debug("Successfully listed 0 scans (API returned empty list).")
                return []
            else:
                logger.warning(f"Unexpected data format: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning("API returned success for list_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list scans: {error_msg}", details=response)

    def get_scan_information(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a scan.

        Args:
            scan_code: Code of the scan to get information for

        Returns:
            Dict[str, Any]: Dictionary containing scan information

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching information for scan '{scan_code}'...")
        payload = {"group": "scans", "action": "get_information", "data": {"scan_code": scan_code}}
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "row_not_found" in error_msg or "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get information for scan '{scan_code}': {error_msg}", details=response
            )

    def get_scan_folder_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves scan folder metrics (total files, pending, identified, no match).

        Args:
            scan_code: Code of the scan to get metrics for

        Returns:
            Dict[str, Any]: Dictionary containing the metrics counts

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching folder metrics for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_folder_metrics",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if (
            response.get("status") == "1"
            and "data" in response
            and isinstance(response["data"], dict)
        ):
            logger.debug(f"Successfully fetched folder metrics for scan '{scan_code}'.")
            return response["data"]
        elif response.get("status") == "1":
            logger.warning(
                f"Unexpected data format for scan folder metrics: {response.get('data')}"
            )
            raise ApiError(
                f"Unexpected data format received for scan folder metrics: {response.get('data')}",
                details=response,
            )
        else:
            error_msg = response.get("error", "Unknown API error")
            if "row_not_found" in error_msg:
                logger.warning(f"Scan '{scan_code}' not found when fetching folder metrics.")
                raise ScanNotFoundError(f"Scan '{scan_code}' not found.")
            else:
                logger.error(
                    f"API error fetching folder metrics for scan '{scan_code}': {error_msg}"
                )
                raise ApiError(f"Failed to get scan folder metrics: {error_msg}", details=response)

    def get_scan_identified_components(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets identified components from KB scanning.

        Args:
            scan_code: Code of the scan to get components from

        Returns:
            List[Dict[str, Any]]: List of identified components

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return list(data.values()) if isinstance(data, dict) else []
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error retrieving identified components from scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_identified_licenses(
        self, scan_code: str, unique: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get the list of identified licenses for a scan.

        Args:
            scan_code: Code of the scan to get licenses from
            unique: If True, returns unique licenses (identifier, name).
                   If False, returns all licenses with file paths
                   (identifier, name, local_path). Default: True.

        Returns:
            List[Dict[str, Any]]: List of identified licenses.
                When unique=True: [{"identifier": str, "name": str}, ...]
                When unique=False: [{"identifier": str, "name": str,
                                    "local_path": str}, ...]

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues

        Example:
            >>> # Get unique licenses only
            >>> licenses = scans.get_scan_identified_licenses("scan_code")
            >>> # Get all licenses with file paths
            >>> licenses = scans.get_scan_identified_licenses("scan_code",
            ...                                                unique=False)
        """
        logger.debug(
            f"Fetching identified licenses for scan '{scan_code}' " f"(unique={unique})..."
        )

        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1" if unique else "0",
            },
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                result_type = "unique licenses" if unique else "licenses with paths"
                logger.debug(
                    f"Successfully fetched {len(data)} {result_type} " f"for scan '{scan_code}'."
                )
                return data
            else:
                logger.warning(f"Unexpected data type for licenses: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning(
                "API returned success for get_scan_identified_licenses " "but no 'data' key."
            )
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting identified licenses for scan '{scan_code}': " f"{error_msg}",
                details=response,
            )

    def get_dependency_analysis_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets dependency analysis results.

        Args:
            scan_code: Code of the scan to get results from

        Returns:
            List[Dict[str, Any]]: List of dependency analysis results

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return data if isinstance(data, list) else []
        elif response.get("status") == "1":
            logger.info(
                f"Dependency Analysis results requested for '{scan_code}', but no 'data' key."
            )
            return []
        else:
            error_msg = response.get("error", "")
            if "Dependency analysis has not been run" in error_msg:
                logger.info(f"Dependency analysis has not been run for '{scan_code}'.")
                return []
            elif "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            else:
                raise ApiError(
                    f"Error getting dependency analysis results for scan '{scan_code}': {error_msg}",
                    details=response,
                )

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Retrieves pending files for a scan.

        Args:
            scan_code: Code of the scan to check

        Returns:
            Dict[str, str]: Dictionary of pending files

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching files with Pending IDs for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(f"The scan {scan_code} has {len(data)} files pending ID.")
                return data
            elif isinstance(data, list) and not data:
                logger.info(f"Pending files API returned empty list for scan '{scan_code}'.")
                return {}
            else:
                logger.warning(f"Pending files API returned unexpected data type: {type(data)}")
                return {}
        elif response.get("status") == "1":
            logger.info(
                f"Pending files API returned success but no 'data' key for scan '{scan_code}'."
            )
            return {}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {}

    def get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Gets the count of policy warnings for a specific scan.

        Args:
            scan_code: Code of the scan to get policy warnings for

        Returns:
            Dict[str, Any]: The policy warnings counter data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting scan policy warnings counter for '{scan_code}': {error_msg}",
                details=response,
            )

    # ===== SCAN MANAGEMENT OPERATIONS =====

    def create_scan(self, data: Dict[str, Any]) -> int:
        """
        Create a new scan with the provided data.

        Args:
            data: Data payload for the scan creation request. Required fields:
                - scan_code (str): Code of the scan
                - scan_name (str): Name of the scan
                Optional fields:
                - project_code (str): Code of the project to assign scan to
                - description (str): Scan description
                - comment (str): Scan comment
                - target_path (str): Path accessible from server
                - git_repo_url (str): Git repository URL
                - git_branch (str): Git branch, tag, or commit
                - git_depth (str): Git clone depth (integer as string)
                - git_ref_type (str): "branch", "tag", or "commit"
                - jar_file_extraction (str): "always", "never", or "if_no_fullmatch"
                - import_from_report (str): "0" or "1"

        Returns:
            int: The ID of the newly created scan

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
            ScanExistsError: If a scan with this name already exists
        """
        scan_name = data.get("scan_name", "unknown")
        logger.debug(f"Creating scan '{scan_name}' via API")

        payload = {"group": "scans", "action": "create", "data": data}

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1" and "data" in response:
                scan_id = response["data"].get("scan_id")
                if scan_id is None:
                    raise ApiError(
                        f"Scan created but no scan_id returned for '{scan_name}'",
                        details=response,
                    )
                logger.debug(f"Successfully created scan '{scan_name}' with ID {scan_id}")
                return int(scan_id)
            else:
                error_msg = response.get("error", "Unknown error")
                raise ApiError(
                    f"Failed to create scan '{scan_name}': {error_msg}", details=response
                )
        except ApiError as e:
            if "Scan code already exists" in str(e) or "code_already_exists" in str(e):
                logger.debug(f"Scan '{scan_name}' already exists.")
                raise ScanExistsError(
                    f"Scan '{scan_name}' already exists",
                    details=getattr(e, "details", None),
                ) from e
            raise

    def update_scan(
        self,
        scan_code: str,
        scan_name: Optional[str] = None,
        project_code: Optional[str] = None,
        description: Optional[str] = None,
        target_path: Optional[str] = None,
        git_repo_url: Optional[str] = None,
        git_branch: Optional[str] = None,
        git_tag: Optional[str] = None,
        git_commit: Optional[str] = None,
        git_depth: Optional[int] = None,
        jar_file_extraction: Optional[str] = None,
    ) -> bool:
        """
        Updates an existing scan with new parameters.

        Args:
            scan_code: Code of the scan to update
            scan_name: Optional new name for the scan
            project_code: Optional new project code
            description: Optional new description
            target_path: Optional target path
            git_repo_url: Optional Git repository URL
            git_branch: Optional Git branch name
            git_tag: Optional Git tag name
            git_commit: Optional Git commit hash
            git_depth: Optional Git clone depth
            jar_file_extraction: Optional JAR extraction setting

        Returns:
            True if the scan was successfully updated

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
            ScanNotFoundError: If the scan doesn't exist
        """
        logger.debug(f"Updating scan '{scan_code}'")

        payload_data = {"scan_code": scan_code}

        # Add only provided parameters
        if scan_name is not None:
            payload_data["scan_name"] = scan_name
        if project_code is not None:
            payload_data["project_code"] = project_code
        if description is not None:
            payload_data["description"] = description
        if target_path is not None:
            payload_data["target_path"] = target_path
        if jar_file_extraction is not None:
            payload_data["jar_file_extraction"] = jar_file_extraction

        # Handle Git parameters
        git_ref_value = None
        git_ref_type = None

        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
        elif git_commit:
            git_ref_value = git_commit
            git_ref_type = "commit"

        if git_repo_url is not None:
            payload_data["git_repo_url"] = git_repo_url

        if git_ref_value:
            payload_data["git_branch"] = git_ref_value
            if git_ref_type:
                payload_data["git_ref_type"] = git_ref_type

        if git_depth is not None:
            payload_data["git_depth"] = str(git_depth)

        payload = {"group": "scans", "action": "update", "data": payload_data}

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully updated scan '{scan_code}'")
                return True
            else:
                logger.warning(f"Unexpected response when updating scan: {response}")
                error_msg = response.get("error", "Unknown error")
                raise ApiError(f"Failed to update scan: {error_msg}", details=response)
        except ApiError as e:
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                logger.debug(f"Scan '{scan_code}' not found.")
                raise ScanNotFoundError(
                    f"Scan '{scan_code}' not found", details=getattr(e, "details", None)
                )
            raise

    # ===== GIT OPERATIONS =====

    def download_content_from_git(self, scan_code: str) -> bool:
        """
        Initiates the Git clone process for a scan.

        Args:
            scan_code: The code of the scan to download Git content for

        Returns:
            True if the Git clone was successfully initiated

        Raises:
            ApiError: If the API call fails
            NetworkError: If there's a network issue
        """
        logger.debug(f"Initiating Git clone for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "download_content_from_git",
            "data": {"scan_code": scan_code},
        }

        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            raise ApiError(f"Failed to initiate download from Git: {error_msg}", details=response)

        logger.debug("Successfully started Git Clone.")
        return True

    def check_status_download_content_from_git(self, scan_code: str) -> Dict[str, Any]:
        """
        Check Git clone status for a scan.

        The API wrapper returns {"status": "1", "data": "NOT FINISHED", ...}
        where 'status' is the API success indicator and 'data' contains the
        git clone status string ("NOT STARTED", "NOT FINISHED", or "FINISHED").

        This method normalizes the response to always return a dict:
        - If API returns a string in 'data', wraps it as {"data": <string>}
        - If API returns a dict in 'data', returns it as-is

        Args:
            scan_code: Code of the scan to check

        Returns:
            dict: Git clone status response data, always in dict format.
                For string responses, returns {"data": <status_string>}.
                For dict responses, returns the dict as-is.

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "check_status_download_content_from_git",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # Normalize: always return a dict
            if isinstance(data, dict):
                return data
            elif isinstance(data, str):
                # Wrap string responses in dict for consistency
                return {"data": data}
            else:
                # Unexpected type - wrap it
                logger.warning(f"Unexpected response type from git status API: {type(data)}")
                return {"data": str(data)}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve Git clone status for scan '{scan_code}': {error_msg}",
                details=response,
            )

    # ===== SCAN EXECUTION OPERATIONS =====

    def remove_uploaded_content(self, scan_code: str, filename: Optional[str] = None) -> bool:
        """
        Removes uploaded content from a scan.

        Args:
            scan_code: Code of the scan to remove content from
            filename: Relative path of file or directory to remove.
                     If None or empty string, entire scan directory is removed.

        Returns:
            bool: True if the operation was successful

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        if filename:
            logger.debug(f"Removing '{filename}' from scan '{scan_code}'...")
        else:
            logger.debug(f"Removing entire scan directory for scan '{scan_code}'...")

        data = {"scan_code": scan_code}
        if filename:
            data["filename"] = filename

        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": data,
        }

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1":
                if filename:
                    logger.debug(f"Successfully removed '{filename}' from scan '{scan_code}'.")
                else:
                    logger.debug(f"Successfully removed entire directory for scan '{scan_code}'.")
                return True
            else:
                error_msg = response.get("error", "Unknown error")

                # Check if this is the specific "file not found" error
                if error_msg == "RequestData.Base.issues_while_parsing_request" and filename:
                    data = response.get("data", [])
                    if isinstance(data, list) and len(data) > 0:
                        error_code = data[0].get("code", "")
                        if error_code == "RequestData.Traits.PathTrait.filename_is_not_valid":
                            logger.warning(
                                f"File '{filename}' does not exist in scan '{scan_code}'."
                            )
                            return True  # Non-fatal - file doesn't exist anyway

                # Handle other errors
                if "Scan not found" in error_msg or "row_not_found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")

                # Build error message based on whether filename was provided
                if filename:
                    error_detail = (
                        f"Failed to remove '{filename}' from scan '{scan_code}': {error_msg}"
                    )
                else:
                    error_detail = f"Failed to remove content from scan '{scan_code}': {error_msg}"

                raise ApiError(error_detail, details=response)
        except (ScanNotFoundError, ApiError):
            raise
        except Exception as e:
            if filename:
                logger.error(
                    f"Unexpected error removing '{filename}' from scan '{scan_code}': {e}",
                    exc_info=True,
                )
                error_msg = (
                    f"Failed to remove '{filename}' from scan '{scan_code}': Unexpected error"
                )
            else:
                logger.error(
                    f"Unexpected error removing content from scan '{scan_code}': {e}", exc_info=True
                )
                error_msg = f"Failed to remove content from scan '{scan_code}': Unexpected error"

            raise ApiError(error_msg, details={"error": str(e)})

    def extract_archives_raw(self, payload_data: Dict[str, Any]) -> bool:
        """
        Low-level method to extract archives using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        ScanOperationsService.extract_archives() which provides validation
        and business logic.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - recursively_extract_archives: "1" or "0"
                - jar_file_extraction: "1" or "0"
                - extract_to_directory: Optional "1" or "0"
                - filename: Optional specific file to extract

        Returns:
            True if extraction was triggered successfully

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.debug(f"Extracting archives for scan '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": payload_data,
        }

        response = self._api._send_request(payload)
        if response.get("status") == "1":
            logger.debug(f"Archive extraction operation queued for scan '{scan_code}'.")
            return True
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Archive extraction failed for scan '{scan_code}': " f"{error_msg}",
                details=response,
            )

    def run_scan_raw(self, payload_data: Dict[str, Any]):
        """
        Low-level method to run a scan using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        ScanOperationsService.run_scan() which provides validation,
        parameter transformation, and version awareness.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - limit: Maximum number of results
                - sensitivity: Scan sensitivity level
                - auto_identification_* fields
                - reuse_identification fields
                - Other scan configuration parameters

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.info(f"Starting scan for '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "run",
            "data": payload_data,
        }

        try:
            response = self._api._send_request(payload)
            if response.get("status") == "1":
                print(f"KB Scan initiated for scan '{scan_code}'.")
                return
            else:
                error_msg = response.get("error", "Unknown error")
                if "Scan not found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                raise ApiError(
                    f"Failed to run scan '{scan_code}': {error_msg}",
                    details=response,
                )
        except (ScanNotFoundError, ApiError):
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error trying to run scan '{scan_code}': {e}",
                exc_info=True,
            )
            raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def start_dependency_analysis_raw(self, payload_data: Dict[str, Any]):
        """
        Low-level method to start dependency analysis using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        ScanOperationsService.start_dependency_analysis() which provides
        validation and business logic.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - import_only: "0" or "1"

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scan_code = payload_data.get("scan_code", "unknown")
        logger.info(f"Starting dependency analysis for '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": payload_data,
        }

        response = self._api._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            raise ApiError(
                f"Failed to start dependency analysis for '{scan_code}': " f"{error_msg}",
                details=response,
            )
        logger.info(f"Dependency analysis for '{scan_code}' started successfully.")

    # ===== STATUS & MONITORING =====

    def check_status(
        self, scan_code: str, process_type: str, process_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Check the status of a scan operation.

        This is a convenience wrapper around check_status_raw() that builds
        the payload automatically. Always returns a dict.

        Args:
            scan_code: Code of the scan to check
            process_type: Type of process (SCAN, DEPENDENCY_ANALYSIS,
                EXTRACT_ARCHIVES, REPORT_IMPORT, etc.)
            process_id: Optional process ID (for report operations)

        Returns:
            dict: Operation status data, always in dict format

        Raises:
            ScanNotFoundError: If scan doesn't exist
            ApiError: If status check fails

        Example:
            >>> status = scans.check_status("scan_123", "SCAN")
            >>> status = scans.check_status("scan_123", "DEPENDENCY_ANALYSIS")
        """
        payload_data = {
            "scan_code": scan_code,
            "type": process_type,
        }
        if process_id is not None:
            payload_data["process_id"] = str(process_id)

        return self.check_status_raw(payload_data)

    def check_status_raw(self, payload_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Low-level method to check scan operation status using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        check_status() which provides a simpler interface.

        This method always returns a dict, normalizing any non-dict responses
        from the API into a consistent dict format.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - type: Operation type (SCAN, EXTRACT_ARCHIVES, etc.)
                - process_id: Optional process ID
                - delay_response: Optional delay in seconds

        Returns:
            dict: The operation status data, always in dict format.
                If API returns a non-dict, it will be wrapped appropriately.

        Raises:
            ScanNotFoundError: If scan doesn't exist
            ApiError: If status check fails

        Example:
            >>> # Build payload manually (not recommended)
            >>> payload_data = {
            ...     "scan_code": "scan_code",
            ...     "type": "SCAN"
            ... }
            >>> status = scans.check_status_raw(payload_data)
            >>>
            >>> # Recommended: Use check_status() instead
            >>> status = scans.check_status("scan_code", "SCAN")
        """
        scan_code = payload_data.get("scan_code", "unknown")
        operation_type = payload_data.get("type", "UNKNOWN")

        logger.debug(f"Checking {operation_type} status for scan '{scan_code}'...")

        payload = {
            "group": "scans",
            "action": "check_status",
            "data": payload_data,
        }

        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # Normalize: always return a dict
            if isinstance(data, dict):
                return data
            elif isinstance(data, str):
                # Wrap string responses in dict for consistency
                logger.warning(
                    f"API returned string instead of dict for {operation_type} "
                    f"status (scan '{scan_code}')"
                )
                return {"status": data}
            else:
                # Unexpected type - wrap it
                logger.warning(
                    f"Unexpected response type from {operation_type} status API: " f"{type(data)}"
                )
                return {"status": str(data)}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve {operation_type} status for "
                f"scan '{scan_code}': {error_msg}",
                details=response,
            )

    # ===== REPORT OPERATIONS =====

    def generate_scan_report_raw(self, payload_data: Dict[str, Any]):
        """
        Low-level method to generate a scan report using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        ReportService.generate_scan_report() which provides validation,
        version awareness, and automatic async/sync determination.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - scan_code: Code of the scan
                - report_type: Type of report
                - async: "0" or "1"
                - Other optional parameters

        Returns:
            Union[int, requests.Response]: Process queue ID for async
                reports, or raw response for sync reports

        Raises:
            ScanNotFoundError: If scan doesn't exist
            ApiError: If report generation fails

        Example:
            >>> # Build payload manually (not recommended)
            >>> payload_data = {
            ...     "scan_code": "scan_code",
            ...     "report_type": "xlsx",
            ...     "async": "1"
            ... }
            >>> process_id = scans.generate_scan_report_raw(payload_data)
            >>>
            >>> # Recommended: Use ReportService instead
            >>> process_id = client.reports.generate_scan_report(
            ...     "scan_code", "xlsx"
            ... )
        """
        scan_code = payload_data.get("scan_code", "unknown")

        logger.debug(
            f"Generating report for scan '{scan_code}' "
            f"(type={payload_data.get('report_type')})..."
        )

        payload = {
            "group": "scans",
            "action": "generate_report",
            "data": payload_data,
        }
        response_data = self._api._send_request(payload)

        if "_raw_response" in response_data:
            raw_response = response_data["_raw_response"]
            logger.info(f"Synchronous report generation completed for " f"scan '{scan_code}'.")
            return raw_response
        elif (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested (async) for "
                f"scan '{scan_code}'. Process ID: {process_id}"
            )
            return int(process_id)
        else:
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to request report generation for " f"scan '{scan_code}': {error_msg}",
                details=response_data,
            )

    def import_report(self, scan_code: str):
        """
        Imports an SBOM report into a scan.

        Args:
            scan_code: Code of the scan to import the report into

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.info(f"Starting SBOM report import for '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "import_report",
            "data": {"scan_code": scan_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown API error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to start SBOM report import for '{scan_code}': {error_msg}",
                details=response,
            )
        logger.info(f"SBOM import for '{scan_code}' started successfully.")
