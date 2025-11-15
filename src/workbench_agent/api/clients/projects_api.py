"""
ProjectsClient - Handles all project-related Workbench API operations.

This client provides identical functionality to ProjectsAPI but uses
composition instead of inheritance.
"""

import logging
from typing import Any, Dict, List, Optional

from workbench_agent.api.exceptions import (
    ApiError,
    ProjectExistsError,
    ProjectNotFoundError,
)

logger = logging.getLogger("workbench-agent")


class ProjectsClient:
    """
    Projects API client using composition pattern.

    Handles all project-related operations including:
    - Listing projects
    - Creating projects
    - Getting project scans
    - Generating project reports

    Example:
        >>> projects = ProjectsClient(base_api)
        >>> all_projects = projects.list()
        >>> project_code = projects.create("MyProject")
    """

    def __init__(self, base_api):
        """
        Initialize ProjectsClient.

        Args:
            base_api: BaseAPI instance for making HTTP requests
        """
        self._api = base_api
        logger.debug("ProjectsClient initialized")

    def list(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all projects.

        Alias for list_projects() to provide cleaner new-style API.

        Returns:
            List of project dictionaries

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        return self.list_projects()

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all projects.

        Returns:
            List[Dict[str, Any]]: List of project dictionaries.

            **Version-aware response fields:**

            **All versions (< 23.3.0):**
            - id: Project ID (int)
            - project_code: Unique project code (str)
            - project_name: Project name (str)

            **Extended response (>= 23.3.0):**
            - id: Project ID (int)
            - creator: Creator user ID (int)
            - project_code: Unique project code (str)
            - project_name: Project name (str)
            - limit_date: Project deadline (str or null)
            - product_code: Associated product code (str)
            - product_name: Associated product name (str)
            - description: Project description (str)
            - comment: Project comment (str)
            - is_archived: Whether project is archived (bool)
            - jira_project_key: Associated JIRA project key (str)
            - created: Creation timestamp (str, "YYYY-MM-DD HH:MM:SS")
            - updated: Last update timestamp (str or null)
            - scans: Number of scans in project (int)
            - policy_rules: Number of policy rules (int)
            - warnings: Number of warnings (int)

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues

        Note:
            The response format varies by Workbench version. The method handles both
            minimal (< 23.3.0) and extended (>= 23.3.0) response formats automatically.
        """
        logger.debug("Listing all projects...")

        payload = {"group": "projects", "action": "list_projects", "data": {}}
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} projects.")
                return data
            else:
                logger.warning(
                    f"API returned success for list_projects but 'data' was not a list: {type(data)}"
                )
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list projects: {error_msg}", details=response)

    def get_information(self, project_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a specific project.

        Args:
            project_code: Code of the project to get information for

        Returns:
            Dict[str, Any]: Project information including owner details, dates, etc.

        Raises:
            ProjectNotFoundError: If the project doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching information for project '{project_code}'...")
        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {"project_code": project_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            logger.debug(f"Successfully fetched information for project '{project_code}'.")
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            raise ApiError(
                f"Failed to get information for project '{project_code}': {error_msg}",
                details=response,
            )

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans within a specific project.

        Args:
            project_code: Code of the project to get scans for

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Listing scans for the '{project_code}' project...")
        payload = {
            "group": "projects",
            "action": "get_all_scans",
            "data": {"project_code": project_code},
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} scans for project '{project_code}'.")
                return data
            else:
                logger.warning(
                    f"API returned success for get_all_scans but 'data' was not a list: {type(data)}"
                )
                return []
        elif response.get("status") == "1":
            logger.warning("API returned success for get_all_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            # Treat project not found as empty list of scans
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                logger.warning(f"Project '{project_code}' not found when trying to list its scans.")
                return []
            else:
                raise ApiError(
                    f"Failed to list scans for project '{project_code}': {error_msg}",
                    details=response,
                )

    def create(
        self,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
    ) -> str:
        """
        Create a new project in Workbench.

        Alias for create_project() to provide cleaner new-style API.

        Args:
            project_name: Name of the project to create
            product_code: Optional product code
            product_name: Optional product name
            description: Optional description
            comment: Optional comment
            limit_date: Optional deadline date (must be valid date string, e.g., "2025-12-31")
            jira_project_key: Optional JIRA project key for integration

        Returns:
            The project code of the created project

        Raises:
            ProjectExistsError: If a project with this name already exists
            ApiError: If project creation fails (e.g., invalid date format)
            NetworkError: If there are network issues
        """
        return self.create_project(
            project_name,
            product_code,
            product_name,
            description,
            comment,
            limit_date,
            jira_project_key,
        )

    def create_project(
        self,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
    ) -> str:
        """
        Create a new project in Workbench.

        Args:
            project_name: Name of the project to create
            product_code: Optional product code
            product_name: Optional product name (human-readable application name)
            description: Optional description
            comment: Optional comment
            limit_date: Optional deadline date (must be valid date string, e.g., "2025-12-31")
            jira_project_key: Optional JIRA project key for integration

        Returns:
            The project code of the created project (auto-generated as {project_name}_{project_id})

        Raises:
            ProjectExistsError: If a project with this name already exists
            ApiError: If project creation fails (e.g., invalid date format for limit_date)
            NetworkError: If there are network issues

        Note:
            - The project_code is auto-generated by Workbench from the project_name
            - If limit_date is provided, it must be a valid date string or the API will return:
              "RequestData.Base.field_contains_not_valid_date_string"
        """
        try:
            # First check if project exists
            projects = self.list_projects()
            for project in projects:
                if project.get("name") == project_name:
                    raise ProjectExistsError(f"Project '{project_name}' already exists")

            # Create the project with additional metadata
            payload_data = {"project_name": project_name}

            # Add optional metadata fields
            if product_code:
                payload_data["product_code"] = product_code
            if product_name:
                payload_data["product_name"] = product_name
            if description:
                payload_data["description"] = description
            if comment:
                payload_data["comment"] = comment
            if limit_date:
                payload_data["limit_date"] = limit_date
            if jira_project_key:
                payload_data["jira_project_key"] = jira_project_key

            payload = {"group": "projects", "action": "create", "data": payload_data}
            response = self._api._send_request(payload)

            if response.get("status") == "1":
                project_code = response.get("data", {}).get("project_code")
                if not project_code:
                    raise ApiError("Project created but no code returned", details=response)
                return project_code
            else:
                error_msg = response.get("error", "Unknown error")

                # Provide helpful error message for date validation issues
                if error_msg == "RequestData.Base.issues_while_parsing_request":
                    data = response.get("data", [])
                    if isinstance(data, list) and len(data) > 0:
                        error_code = data[0].get("code", "")
                        if "not_valid_date_string" in error_code:
                            field = data[0].get("message_parameters", {}).get("fieldname", "date")
                            raise ApiError(
                                f"Failed to create project '{project_name}': Invalid date format for '{field}'. "
                                f"Please provide a valid date string (e.g., '2025-12-31')",
                                details=response,
                            )

                raise ApiError(
                    f"Failed to create project '{project_name}': {error_msg}", details=response
                )

        except ProjectExistsError:
            raise
        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(f"Failed to create project '{project_name}'", details={"error": str(e)})

    def update_project(
        self,
        project_code: str,
        project_name: str,
        product_code: Optional[str] = None,
        product_name: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        limit_date: Optional[str] = None,
        jira_project_key: Optional[str] = None,
        new_project_owner: Optional[str] = None,
    ) -> int:
        """
        Update an existing project in Workbench.

        Args:
            project_code: Code of the project to update (required)
            project_name: New name for the project (required)
            product_code: Optional product code
            product_name: Optional product name
            description: Optional description
            comment: Optional comment
            limit_date: Optional deadline date (must be valid date string, e.g., "2025-12-31")
            jira_project_key: Optional JIRA project key for integration
            new_project_owner: Optional username to change project ownership

        Returns:
            The project ID of the updated project

        Raises:
            ProjectNotFoundError: If the project doesn't exist
            ApiError: If project update fails (e.g., invalid date format, missing required field)
            NetworkError: If there are network issues

        Note:
            - Both project_code and project_name are required
            - project_code identifies which project to update
            - project_name can be used to rename the project
            - If limit_date is provided, it must be a valid date string
        """
        logger.debug(f"Updating project '{project_code}'...")

        # Build payload with required fields
        payload_data = {
            "project_code": project_code,
            "project_name": project_name,
        }

        # Add optional metadata fields
        if product_code is not None:
            payload_data["product_code"] = product_code
        if product_name is not None:
            payload_data["product_name"] = product_name
        if description is not None:
            payload_data["description"] = description
        if comment is not None:
            payload_data["comment"] = comment
        if limit_date is not None:
            payload_data["limit_date"] = limit_date
        if jira_project_key is not None:
            payload_data["jira_project_key"] = jira_project_key
        if new_project_owner is not None:
            payload_data["new_project_owner"] = new_project_owner

        payload = {"group": "projects", "action": "update", "data": payload_data}
        response = self._api._send_request(payload)

        if response.get("status") == "1":
            project_id = response.get("data", {}).get("project_id")
            if not project_id:
                raise ApiError("Project updated but no ID returned", details=response)
            logger.debug(f"Successfully updated project '{project_code}' (ID: {project_id}).")
            return int(project_id)
        else:
            error_msg = response.get("error", "Unknown error")

            # Handle missing mandatory field errors
            if error_msg == "RequestData.Base.issues_while_parsing_request":
                data = response.get("data", [])
                if isinstance(data, list) and len(data) > 0:
                    error_code = data[0].get("code", "")

                    # Invalid date format
                    if "not_valid_date_string" in error_code:
                        field = data[0].get("message_parameters", {}).get("fieldname", "date")
                        raise ApiError(
                            f"Failed to update project '{project_code}': Invalid date format for '{field}'. "
                            f"Please provide a valid date string (e.g., '2025-12-31')",
                            details=response,
                        )

                    # Missing mandatory field
                    if error_code == "RequestData.Base.mandatory_field_missing":
                        field = data[0].get("message_parameters", {}).get("fieldname", "unknown")
                        raise ApiError(
                            f"Failed to update project: Missing required field '{field}'",
                            details=response,
                        )

            # Check for project not found
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")

            raise ApiError(
                f"Failed to update project '{project_code}': {error_msg}", details=response
            )

    def generate_project_report_raw(self, payload_data: Dict[str, Any]) -> int:
        """
        Low-level method to generate a project report using pre-built payload.

        This is a raw API method. For most use cases, prefer using
        ReportService.generate_project_report() which provides validation,
        version awareness, and parameter handling.

        Args:
            payload_data: Pre-built payload data dictionary containing:
                - project_code: Code of the project
                - report_type: Type of report
                - async: Always "1" for project reports
                - Other optional parameters

        Returns:
            int: Process queue ID for async report generation

        Raises:
            ProjectNotFoundError: If project doesn't exist
            ApiError: If report generation fails

        Example:
            >>> # Build payload manually (not recommended)
            >>> payload_data = {
            ...     "project_code": "project_code",
            ...     "report_type": "xlsx",
            ...     "async": "1"
            ... }
            >>> process_id = projects.generate_project_report_raw(payload_data)
            >>>
            >>> # Recommended: Use ReportService instead
            >>> process_id = client.reports.generate_project_report(
            ...     "project_code", "xlsx"
            ... )
        """
        project_code = payload_data.get("project_code", "unknown")

        logger.debug(
            f"Generating report for project '{project_code}' "
            f"(type={payload_data.get('report_type')})..."
        )

        payload = {
            "group": "projects",
            "action": "generate_report",
            "data": payload_data,
        }
        response_data = self._api._send_request(payload)

        if (
            response_data.get("status") == "1"
            and "data" in response_data
            and "process_queue_id" in response_data["data"]
        ):
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(
                f"Report generation requested for project "
                f"'{project_code}'. Process ID: {process_id}"
            )
            return int(process_id)
        else:
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            raise ApiError(
                f"Failed to request report generation for project "
                f"'{project_code}': {error_msg}",
                details=response_data,
            )

    def check_project_report_status(self, process_id: int, project_code: str) -> Dict[str, Any]:
        """
        Checks the status of an asynchronous project report generation process.

        Args:
            process_id: Process queue ID from generate_project_report()
            project_code: Code of the project (for logging)

        Returns:
            Dict with status information

        Raises:
            ApiError: If status check fails
            NetworkError: If there are network issues
        """
        logger.debug(
            f"Checking report generation status for process {process_id} (project '{project_code}')..."
        )
        payload = {
            "group": "projects",
            "action": "check_status",
            "data": {
                "process_id": str(process_id),
                "type": "REPORT_GENERATION",
            },
        }
        response = self._api._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(
                f"Failed to check report status for process {process_id} (project '{project_code}'): {error_msg}",
                details=response,
            )
