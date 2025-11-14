"""
ReportService - Handles report generation, validation, and download operations.

This service provides:
- Report type validation
- Version-aware payload building
- Automatic async/sync determination
- Report download and save functionality
"""
import json
import logging
import os
import re
from typing import Any, Dict, Optional, Union

import requests

from workbench_agent.exceptions import (
    ApiError,
    FileSystemError,
    ValidationError,
)

logger = logging.getLogger("workbench-agent")


class ReportService:
    """
    Service for handling all report-related operations.

    This service acts as a facade for report generation across projects
    and scans, providing:
    - Centralized report type validation
    - Version-aware parameter handling
    - Payload building with automatic async/sync determination
    - Report download and save functionality

    Example:
        >>> report_service = ReportService(
        ...     projects_client, scans_client
        ... )
        >>> # Generate project report
        >>> process_id = report_service.generate_project_report(
        ...     "project_code", "xlsx", include_dep_det_info=True
        ... )
        >>> # Generate scan report
        >>> result = report_service.generate_scan_report(
        ...     "scan_code", "html"
        ... )
    """

    # Report type constants
    PROJECT_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx"}
    SCAN_REPORT_TYPES = {
        "html",
        "dynamic_top_matched_components",
        "xlsx",
        "spdx",
        "spdx_lite",
        "cyclone_dx",
        "string_match",
    }
    # Reports that require async processing
    ASYNC_REPORT_TYPES = {
        "xlsx",
        "spdx",
        "spdx_lite",
        "cyclone_dx",
    }

    # File extension mapping for saving reports
    EXTENSION_MAP = {
        "xlsx": "xlsx",
        "spdx": "rdf",
        "spdx_lite": "xlsx",
        "cyclone_dx": "json",
        "html": "html",
        "dynamic_top_matched_components": "html",
        "string_match": "xlsx",
        "basic": "txt",
    }

    def __init__(self, projects_client, scans_client):
        """
        Initialize ReportService.

        Args:
            projects_client: ProjectsClient instance for project operations
            scans_client: ScansClient instance for scan operations
        """
        self._projects = projects_client
        self._scans = scans_client
        logger.debug("ReportService initialized")

    # ===== VALIDATION METHODS =====

    def validate_project_report_type(self, report_type: str) -> None:
        """
        Validate that report type is supported for projects.

        Args:
            report_type: Report type to validate

        Raises:
            ValidationError: If report type is not supported for projects
        """
        if report_type not in self.PROJECT_REPORT_TYPES:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for "
                f"project reports. Valid types: "
                f"{', '.join(sorted(self.PROJECT_REPORT_TYPES))}"
            )

    def validate_scan_report_type(self, report_type: str) -> None:
        """
        Validate that report type is supported for scans.

        Args:
            report_type: Report type to validate

        Raises:
            ValidationError: If report type is not supported for scans
        """
        if report_type not in self.SCAN_REPORT_TYPES:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for "
                f"scan reports. Valid types: "
                f"{', '.join(sorted(self.SCAN_REPORT_TYPES))}"
            )

    def is_async_report_type(self, report_type: str) -> bool:
        """
        Determine if report type requires async generation.

        Args:
            report_type: Report type to check

        Returns:
            bool: True if report type is async, False otherwise
        """
        return report_type in self.ASYNC_REPORT_TYPES

    # ===== PAYLOAD BUILDING METHODS =====

    def build_project_report_payload(
        self,
        project_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
        report_content_type: Optional[str] = None,
        include_dep_det_info: bool = False,
    ) -> Dict[str, Any]:
        """
        Build payload for project report generation.

        Args:
            project_code: Code of the project
            report_type: Type of report (xlsx, spdx, spdx_lite, cyclone_dx)
            selection_type: Optional license filter
            selection_view: Optional view filter
            disclaimer: Optional disclaimer text
            include_vex: Include VEX data
            report_content_type: Optional content type for xlsx reports
            include_dep_det_info: Include detailed dependency info

        Returns:
            Dict containing the request payload data

        Raises:
            ValidationError: If report type is invalid
        """
        # Validate report type
        self.validate_project_report_type(report_type)

        logger.debug(
            f"Building project report payload: "
            f"project={project_code}, type={report_type}"
        )

        # Build base payload
        payload_data = {
            "project_code": project_code,
            "report_type": report_type,
            "async": "1",  # Project reports are always async
        }

        # Add optional filtering parameters
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer

        # Add Excel-specific parameters
        if report_content_type:
            payload_data["report_content_type"] = report_content_type

        # Add include_vex parameter for CycloneDX and Excel reports
        if report_type in ["cyclone_dx", "xlsx"]:
            payload_data["include_vex"] = include_vex

        # Add include_dep_det_info parameter if requested
        if include_dep_det_info:
            payload_data["include_dep_det_info"] = include_dep_det_info

        return payload_data

    def build_scan_report_payload(
        self,
        scan_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
        include_dep_det_info: bool = False,
        async_mode: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Build payload for scan report generation.

        Args:
            scan_code: Code of the scan
            report_type: Type of report (html, xlsx, spdx, etc.)
            selection_type: Optional license filter
            selection_view: Optional view filter
            disclaimer: Optional disclaimer text
            include_vex: Include VEX data
            include_dep_det_info: Include detailed dependency info
            async_mode: Override async behavior (None = auto-determine)

        Returns:
            Dict containing the request payload data

        Raises:
            ValidationError: If report type is invalid
        """
        # Validate report type
        self.validate_scan_report_type(report_type)

        logger.debug(
            f"Building scan report payload: "
            f"scan={scan_code}, type={report_type}"
        )

        # Determine async mode
        if async_mode is None:
            use_async = self.is_async_report_type(report_type)
        else:
            use_async = async_mode

        async_value = "1" if use_async else "0"

        # Build base payload
        payload_data = {
            "scan_code": scan_code,
            "report_type": report_type,
            "async": async_value,
        }

        # Add optional filtering parameters
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer

        # Add include_vex parameter for CycloneDX and Excel reports
        if report_type in ["cyclone_dx", "xlsx"]:
            payload_data["include_vex"] = include_vex

        # Add include_dep_det_info parameter for Excel reports
        if include_dep_det_info:
            if report_type == "xlsx":
                payload_data["include_dep_det_info"] = include_dep_det_info
            else:
                logger.warning(
                    f"include_dep_det_info is only supported for Excel "
                    f"(xlsx) reports, ignoring for report type "
                    f"'{report_type}'"
                )

        return payload_data

    # ===== REPORT GENERATION METHODS =====

    def generate_project_report(
        self,
        project_code: str,
        report_type: str,
        **options,
    ) -> int:
        """
        Generate a project report with validation.

        This is a convenience method that builds the payload and calls
        the ProjectsClient.

        Args:
            project_code: Code of the project
            report_type: Type of report
            **options: Additional options (selection_type, selection_view,
                disclaimer, include_vex, report_content_type,
                include_dep_det_info)

        Returns:
            int: Process queue ID for async report generation

        Raises:
            ValidationError: If report type is invalid
            ProjectNotFoundError: If project doesn't exist
            ApiError: If report generation fails
        """
        # Build payload with validation
        payload_data = self.build_project_report_payload(
            project_code, report_type, **options
        )

        logger.info(
            f"Generating project report: project={project_code}, "
            f"type={report_type}"
        )

        # Delegate to the client's raw method
        return self._projects.generate_project_report_raw(payload_data)

    def generate_scan_report(
        self,
        scan_code: str,
        report_type: str,
        **options,
    ):
        """
        Generate a scan report with validation.

        This is a convenience method that builds the payload and calls
        the ScansClient.

        Args:
            scan_code: Code of the scan
            report_type: Type of report
            **options: Additional options (selection_type, selection_view,
                disclaimer, include_vex, include_dep_det_info, async_mode)

        Returns:
            Union[int, requests.Response]: Process queue ID for async
                reports, or raw response for sync reports

        Raises:
            ValidationError: If report type is invalid
            ScanNotFoundError: If scan doesn't exist
            ApiError: If report generation fails
        """
        # Build payload with validation
        payload_data = self.build_scan_report_payload(
            scan_code, report_type, **options
        )

        logger.info(
            f"Generating scan report: scan={scan_code}, "
            f"type={report_type}"
        )

        # Delegate to the client's raw method
        return self._scans.generate_scan_report_raw(payload_data)

    # ===== REPORT DOWNLOAD AND SAVE METHODS =====

    def download_project_report(self, process_id: int):
        """
        Download a generated project report.

        Args:
            process_id: Process queue ID from generate_project_report()

        Returns:
            Response object with report content

        Raises:
            ApiError: If download fails
        """
        logger.debug(
            f"Downloading project report for process ID {process_id}..."
        )
        
        # Use the base API's download functionality with proper endpoint
        base_api = self._projects._api

        payload = {
            "group": "download",  # Downloads use "download" group
            "action": "download_report",
            "data": {
                "report_entity": "projects",
                "process_id": str(process_id),
            },
        }

        # Downloads can be large and take time - use extended timeout
        return base_api._send_request(payload, timeout=1800)

    def download_scan_report(self, process_id: int):
        """
        Download a generated scan report.

        Args:
            process_id: Process queue ID from generate_scan_report()

        Returns:
            Response object with report content

        Raises:
            ApiError: If download fails
        """
        logger.debug(
            f"Downloading scan report for process ID {process_id}..."
        )
        
        # Use the base API's download functionality with proper endpoint
        base_api = self._projects._api

        payload = {
            "group": "download",  # Downloads use "download" group
            "action": "download_report",
            "data": {
                "report_entity": "scans",
                "process_id": str(process_id),
            },
        }

        # Downloads can be large and take time - use extended timeout
        return base_api._send_request(payload, timeout=1800)

    def save_report(
        self,
        response_or_content: Union[
            requests.Response, str, bytes, dict, list
        ],
        output_dir: str,
        name_component: str,
        report_type: str,
        scope: str = "scan",
    ) -> str:
        """
        Save report content to disk with proper formatting.

        Args:
            response_or_content: Response object or direct content
            output_dir: Directory to save report to
            name_component: Name component (scan/project name)
            report_type: Type of report (xlsx, spdx, etc.)
            scope: Either "scan" or "project"

        Returns:
            str: Path to saved file

        Raises:
            ValidationError: If parameters are invalid
            FileSystemError: If file operations fail
        """
        if not output_dir:
            raise ValidationError(
                "Output directory is not specified for saving report."
            )
        if not name_component:
            raise ValidationError(
                "Name component (scan/project name) is not specified "
                "for saving report."
            )
        if not report_type:
            raise ValidationError(
                "Report type is not specified for saving report."
            )

        filename = ""
        content_to_write: Union[str, bytes] = b""
        write_mode = "wb"

        # Handle wrapped Response objects from base_api
        if (
            isinstance(response_or_content, dict)
            and "_raw_response" in response_or_content
        ):
            response_or_content = response_or_content["_raw_response"]

        if isinstance(response_or_content, requests.Response):
            response = response_or_content

            # Generate filename based on format
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            ext = self.EXTENSION_MAP.get(
                report_type.lower(), "txt"
            )
            filename = f"{safe_scope}-{safe_name}-{safe_type}.{ext}"

            logger.debug(f"Generated filename: {filename}")

            try:
                content_to_write = response.content
            except Exception as e:
                raise FileSystemError(
                    f"Failed to read content from response object: {e}"
                )

            content_type = response.headers.get("content-type", "").lower()
            if (
                "text" in content_type
                or "json" in content_type
                or "html" in content_type
            ):
                write_mode = "w"
                try:
                    content_to_write = content_to_write.decode(
                        response.encoding or "utf-8", errors="replace"
                    )
                except Exception:
                    logger.warning(
                        f"Could not decode response content as text, "
                        f"writing as binary. Content-Type: {content_type}"
                    )
                    write_mode = "wb"
            else:
                write_mode = "wb"

        elif isinstance(response_or_content, (dict, list)):
            # Handle direct JSON data
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            filename = f"{safe_scope}-{safe_name}-{safe_type}.json"
            try:
                content_to_write = json.dumps(response_or_content, indent=2)
                write_mode = "w"
            except TypeError as e:
                raise ValidationError(
                    f"Failed to serialize provided dictionary/list to "
                    f"JSON: {e}"
                )

        elif isinstance(response_or_content, str):
            # Handle direct string content
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            filename = f"{safe_scope}-{safe_name}-{safe_type}.txt"
            content_to_write = response_or_content
            write_mode = "w"

        elif isinstance(response_or_content, bytes):
            # Handle direct bytes content
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            filename = f"{safe_scope}-{safe_name}-{safe_type}.bin"
            content_to_write = response_or_content
            write_mode = "wb"

        else:
            raise ValidationError(
                f"Unsupported content type for saving: "
                f"{type(response_or_content)}"
            )

        filepath = os.path.join(output_dir, filename)

        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.error(
                f"Failed to create output directory '{output_dir}': {e}",
                exc_info=True,
            )
            raise FileSystemError(
                f"Could not create output directory '{output_dir}': {e}"
            ) from e

        try:
            if write_mode == "w":
                with open(filepath, write_mode, encoding="utf-8") as f:
                    f.write(content_to_write)
            else:
                with open(filepath, write_mode) as f:
                    f.write(content_to_write)

            print(f"Successfully saved to: {filepath}")
            logger.info(f"Successfully saved report to {filepath}")
            return filepath

        except IOError as e:
            logger.error(
                f"Failed to write report to {filepath}: {e}",
                exc_info=True,
            )
            raise FileSystemError(
                f"Failed to write report to '{filepath}': {e}"
            ) from e
        except Exception as e:
            logger.error(
                f"Unexpected error writing report to {filepath}: {e}",
                exc_info=True,
            )
            raise FileSystemError(
                f"Unexpected error writing report to '{filepath}': {e}"
            ) from e

