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
from typing import Any, Dict, Optional, Set, Union

import requests
from packaging import version as packaging_version

from workbench_agent.api.exceptions import FileSystemError, ValidationError
from workbench_agent.api.utils import report_definitions
from workbench_agent.api.utils.process_waiter import StatusResult

logger = logging.getLogger("workbench-agent")


class ReportService:
    """
    Service for handling all report-related operations.

    This service acts as a facade for report generation across projects
    and scans, providing:
    - Centralized report type validation
    - Parameter validation based on report type capabilities
    - Version-aware parameter handling
    - Payload building with automatic async/sync determination
    - Report download and save functionality

    Example:
        >>> report_service = ReportService(
        ...     projects_client, scans_client, downloads_client
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

    REPORT_DEFS = report_definitions.REPORT_DEFS
    ASYNC_REPORT_TYPES = report_definitions.ASYNC_REPORT_TYPES
    NOTICE_REPORT_TYPE_MAP = report_definitions.NOTICE_REPORT_TYPE_MAP
    NOTICE_REPORT_TYPES = report_definitions.NOTICE_REPORT_TYPES
    MIN_VERSION_FOR_FIELDS = report_definitions.MIN_VERSION_FOR_FIELDS
    MIN_VERSION_FOR_REPORT_TYPES = report_definitions.MIN_VERSION_FOR_REPORT_TYPES
    EXTENSION_MAP = report_definitions.EXTENSION_MAP

    def __init__(
        self,
        projects_client,
        scans_client,
        downloads_client,
        status_check_service=None,
        workbench_version: str = "",
    ):
        """
        Initialize ReportService.

        Args:
            projects_client: ProjectsClient instance for project operations
            scans_client: ScansClient instance for scan operations
            downloads_client: DownloadClient instance for download operations
            status_check_service: Optional StatusCheckService for wait/poll
            workbench_version: Connected Workbench version string for gating
        """
        self._projects = projects_client
        self._scans = scans_client
        self._downloads = downloads_client
        self._status_check = status_check_service
        self._workbench_version = workbench_version
        logger.debug("ReportService initialized")

    @classmethod
    def report_types_for_scope(cls, scope: str) -> Set[str]:
        """
        Report type strings valid for ``scan`` or ``project`` scope,
        derived from ``REPORT_DEFS``.
        """
        if scope == "scan":
            return {rt for rt, d in cls.REPORT_DEFS.items() if "scan" in d["scopes"]}
        if scope == "project":
            return {rt for rt, d in cls.REPORT_DEFS.items() if "project" in d["scopes"]}
        raise ValidationError(f"Invalid report scope '{scope}'. " f"Expected 'scan' or 'project'.")

    # ===== VERSION HELPERS =====

    def _meets_min_version(self, min_version: str) -> bool:
        """
        True if Workbench meets min_version, or version unknown.
        """
        if not min_version or not self._workbench_version:
            return True
        try:
            return packaging_version.parse(self._workbench_version) >= packaging_version.parse(
                min_version
            )
        except Exception:
            return True

    def _is_field_supported(self, field_name: str) -> bool:
        min_v = self.MIN_VERSION_FOR_FIELDS.get(field_name, "")
        return self._meets_min_version(min_v)

    def is_report_type_supported(self, report_type: str) -> bool:
        """
        Return whether the connected Workbench version supports this type.

        Unknown or unparseable server versions return True (API decides).
        """
        min_v = self.MIN_VERSION_FOR_REPORT_TYPES.get(report_type, "")
        if not min_v:
            return True
        return self._meets_min_version(min_v)

    def _ensure_report_version_supported(self, report_type: str) -> None:
        """
        Raise ValidationError if this report type needs a newer Workbench.
        """
        min_v = self.MIN_VERSION_FOR_REPORT_TYPES.get(report_type)
        if not min_v or not self._workbench_version:
            return
        if self._meets_min_version(min_v):
            return
        raise ValidationError(
            f"Report type '{report_type}' requires Workbench >= {min_v}; "
            f"connected server is {self._workbench_version}."
        )

    def validate_report_type(self, report_type: str, scope: str) -> None:
        """
        Validate a report type for scope and connected Workbench version.

        Raises:
            ValidationError: If invalid for scope or Workbench version
        """
        if scope == "scan":
            self.validate_scan_report_type(report_type)
        elif scope == "project":
            self.validate_project_report_type(report_type)
        else:
            raise ValidationError(
                f"Invalid report scope '{scope}'. " f"Expected 'scan' or 'project'."
            )

    def resolve_report_types(
        self,
        scope: str,
        report_type_param: str,
        *,
        server_version: Optional[str] = None,
    ) -> Set[str]:
        """
        Resolve CLI-style report type input for a scope.

        ``ALL`` expands to all types valid for the scope, dropping types
        not supported by the connected Workbench version (with warnings).
        Comma-separated values are validated and returned as a set.

        Args:
            scope: ``scan`` or ``project``
            report_type_param: ``ALL`` or comma-separated report types
            server_version: Optional override for log messages and gating
                context (defaults to ``self._workbench_version`` set at init).
                Handlers omit this; use for tests or special cases only.

        Returns:
            Set of report type strings to generate/download

        Raises:
            ValidationError: If scope is invalid or an explicit type fails
                validation
        """
        sv = server_version if server_version is not None else self._workbench_version
        display_version = sv if sv else "unknown"

        # Validates scope and returns types allowed for that scope
        full_set = self.report_types_for_scope(scope)

        raw = report_type_param.strip()
        if raw.upper() == "ALL":
            skipped = {rt for rt in full_set if not self.is_report_type_supported(rt)}
            for rt in sorted(skipped):
                min_v = self.MIN_VERSION_FOR_REPORT_TYPES.get(rt, "?")
                logger.warning(
                    f"Skipping '{rt}' from ALL: requires Workbench >= {min_v}, "
                    f"server is {display_version}"
                )
            return full_set - skipped

        requested = {p.strip().lower() for p in raw.split(",") if p.strip()}
        for rt in requested:
            self.validate_report_type(rt, scope)
        return requested

    def _report_capabilities(self, report_type: str) -> Dict[str, Any]:
        """
        Return the ``capabilities`` dict for ``report_type``, or empty dict
        if unknown (API validates unknown types).
        """
        d = self.REPORT_DEFS.get(report_type)
        if not d:
            return {}
        caps = d.get("capabilities")
        return caps if isinstance(caps, dict) else {}

    # ===== VALIDATION METHODS =====

    def _validate_report_parameters(
        self,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: Optional[bool] = None,
        include_dep_det_info: Optional[bool] = None,
        report_content_type: Optional[str] = None,
    ) -> None:
        """
        Validate that parameters are supported by the report type.

        Logs warnings for unsupported parameters that were explicitly
        provided. This helps users understand which parameters will be
        ignored by the API.

        Args:
            report_type: Type of report being generated
            selection_type: License selection filter
            selection_view: View filter
            disclaimer: Disclaimer text
            include_vex: VEX inclusion flag
            include_dep_det_info: Detailed dependency info flag
            report_content_type: Excel report content type
        """
        capabilities = self._report_capabilities(report_type)
        if not capabilities:
            # Unknown report type - let the API validate it
            logger.debug(f"Unknown report type '{report_type}', " f"skipping parameter validation")
            return

        # Check each parameter against capabilities
        if selection_type is not None and not capabilities["supports_selection_type"]:
            logger.warning(
                f"selection_type is not supported for '{report_type}' "
                f"reports and will be ignored"
            )

        if selection_view is not None and not capabilities["supports_selection_view"]:
            logger.warning(
                f"selection_view is not supported for '{report_type}' "
                f"reports and will be ignored"
            )

        if disclaimer is not None and not capabilities["supports_disclaimer"]:
            logger.warning(
                f"disclaimer is not supported for '{report_type}' " f"reports and will be ignored"
            )

        if include_vex is not None and not capabilities["supports_vex"]:
            logger.warning(
                f"include_vex is not supported for '{report_type}' " f"reports and will be ignored"
            )

        if include_dep_det_info and not capabilities["supports_dep_det_info"]:
            logger.warning(
                f"include_dep_det_info is only supported for Excel "
                f"reports, ignoring for '{report_type}'"
            )

        if report_content_type is not None and not capabilities["supports_report_content_type"]:
            logger.warning(
                f"report_content_type is only supported for Excel "
                f"reports, ignoring for '{report_type}'"
            )

    def validate_project_report_type(self, report_type: str) -> None:
        """
        Validate that report type is supported for projects.

        Args:
            report_type: Report type to validate

        Raises:
            ValidationError: If report type is not supported for projects
        """
        allowed = self.report_types_for_scope("project")
        if report_type not in allowed:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for "
                f"project reports. Valid types: "
                f"{', '.join(sorted(allowed))}"
            )
        self._ensure_report_version_supported(report_type)

    def validate_scan_report_type(self, report_type: str) -> None:
        """
        Validate that report type is supported for scans.

        Args:
            report_type: Report type to validate

        Raises:
            ValidationError: If report type is not supported for scans
        """
        allowed = self.report_types_for_scope("scan")
        if report_type not in allowed:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for "
                f"scan reports. Valid types: "
                f"{', '.join(sorted(allowed))}"
            )
        self._ensure_report_version_supported(report_type)

    def is_async_report_type(self, report_type: str) -> bool:
        """
        Whether this report type uses async generation (same for scan and
        project scopes).

        Args:
            report_type: Report type to check

        Returns:
            bool: True if report type is async, False otherwise
        """
        d = self.REPORT_DEFS.get(report_type)
        if d is None:
            return report_type in self.ASYNC_REPORT_TYPES
        return bool(d["is_async"])

    def _apply_common_report_payload_fields(
        self,
        payload_data: Dict[str, Any],
        report_type: str,
        capabilities: Dict[str, Any],
        *,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
        include_dep_det_info: bool = False,
        report_content_type: Optional[str] = None,
    ) -> None:
        """Mutates ``payload_data`` with optional fields when supported."""
        if selection_type and capabilities.get("supports_selection_type"):
            payload_data["selection_type"] = selection_type
        if selection_view and capabilities.get("supports_selection_view"):
            payload_data["selection_view"] = selection_view
        if disclaimer and capabilities.get("supports_disclaimer"):
            payload_data["disclaimer"] = disclaimer

        if report_content_type and capabilities.get("supports_report_content_type"):
            payload_data["report_content_type"] = report_content_type

        if capabilities.get("supports_vex"):
            if self._is_field_supported("include_vex"):
                payload_data["include_vex"] = include_vex
            else:
                logger.warning(
                    f"include_vex requires Workbench >= "
                    f"{self.MIN_VERSION_FOR_FIELDS['include_vex']}; "
                    f"field omitted (server: {self._workbench_version})"
                )

        if include_dep_det_info and capabilities.get("supports_dep_det_info"):
            if self._is_field_supported("include_dep_det_info"):
                payload_data["include_dep_det_info"] = include_dep_det_info
            else:
                logger.warning(
                    f"include_dep_det_info requires Workbench >= "
                    f"{self.MIN_VERSION_FOR_FIELDS['include_dep_det_info']}; "
                    f"field omitted (server: {self._workbench_version})"
                )

    def _build_payload(
        self,
        scope: str,
        resource_code: str,
        report_type: str,
        *,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
        include_dep_det_info: bool = False,
        report_content_type: Optional[str] = None,
        async_mode: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Shared scan/project report payload builder.

        Raises:
            ValidationError: If scope or report type is invalid
        """
        if scope not in ("scan", "project"):
            raise ValidationError(
                f"Invalid report scope '{scope}'. " f"Expected 'scan' or 'project'."
            )

        if scope == "project":
            self.validate_project_report_type(report_type)
        else:
            self.validate_scan_report_type(report_type)

        defs = self.REPORT_DEFS.get(report_type)
        if defs is not None and scope not in defs["scopes"]:
            raise ValidationError(
                f"Report type '{report_type}' is not supported for " f"{scope} scope."
            )

        self._validate_report_parameters(
            report_type=report_type,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
            include_vex=include_vex if include_vex is not True else None,
            include_dep_det_info=include_dep_det_info,
            report_content_type=report_content_type,
        )

        capabilities = self._report_capabilities(report_type)

        if scope == "project":
            logger.debug(
                f"Building project report payload: " f"project={resource_code}, type={report_type}"
            )
            payload_data: Dict[str, Any] = {
                "project_code": resource_code,
                "report_type": report_type,
                "async": "1",
            }
        else:
            logger.debug(
                f"Building scan report payload: " f"scan={resource_code}, type={report_type}"
            )
            if async_mode is None:
                use_async = self.is_async_report_type(report_type)
            else:
                use_async = async_mode
            async_value = "1" if use_async else "0"
            payload_data = {
                "scan_code": resource_code,
                "report_type": report_type,
                "async": async_value,
            }

        self._apply_common_report_payload_fields(
            payload_data,
            report_type,
            capabilities,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
            include_vex=include_vex,
            include_dep_det_info=include_dep_det_info,
            report_content_type=report_content_type,
        )

        return payload_data

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
        return self._build_payload(
            "project",
            project_code,
            report_type,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
            include_vex=include_vex,
            include_dep_det_info=include_dep_det_info,
            report_content_type=report_content_type,
        )

    def build_scan_report_payload(
        self,
        scan_code: str,
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
        include_dep_det_info: bool = False,
        report_content_type: Optional[str] = None,
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
            report_content_type: Report content type (for Excel/HTML)
            async_mode: Override async behavior (None = auto-determine)

        Returns:
            Dict containing the request payload data

        Raises:
            ValidationError: If report type is invalid
        """
        return self._build_payload(
            "scan",
            scan_code,
            report_type,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
            include_vex=include_vex,
            include_dep_det_info=include_dep_det_info,
            report_content_type=report_content_type,
            async_mode=async_mode,
        )

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
        if report_type in self.NOTICE_REPORT_TYPES:
            raise ValidationError(
                f"Report type '{report_type}' is a notice extract report. "
                f"Use generate_notice_extract() and related methods instead."
            )
        # Build payload with validation
        payload_data = self.build_project_report_payload(project_code, report_type, **options)

        logger.info(f"Generating project report: project={project_code}, " f"type={report_type}")

        # Delegate to the client's raw method
        return self._projects.generate_report(payload_data)

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
        if report_type in self.NOTICE_REPORT_TYPES:
            raise ValidationError(
                f"Report type '{report_type}' is a notice extract report. "
                f"Use generate_notice_extract() and related methods instead."
            )
        # Build payload with validation
        payload_data = self.build_scan_report_payload(scan_code, report_type, **options)

        logger.info(f"Generating scan report: scan={scan_code}, " f"type={report_type}")

        # Delegate to the client's raw method
        return self._scans.generate_report(payload_data)

    @staticmethod
    def _filter_report_generation_options(
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Strip kwargs not accepted by payload builders / generate methods."""
        allowed = {
            "selection_type",
            "selection_view",
            "disclaimer",
            "include_vex",
            "include_dep_det_info",
            "report_content_type",
            "async_mode",
        }
        return {k: v for k, v in options.items() if k in allowed}

    def run_and_download_report(
        self,
        scope: str,
        report_type: str,
        output_dir: str,
        name_component: str,
        *,
        scan_code: Optional[str] = None,
        project_code: Optional[str] = None,
        wait_retry_count: int = 60,
        wait_retry_interval: int = 3,
        **report_options: Any,
    ) -> str:
        """
        Generate one report, wait when needed, download, and save to disk.

        Intended for SDK users; CLI handlers may call this per report type
        while retaining outer orchestration (loops, summaries).

        Notice extract types use the notice extract API (scan scope only).

        Args:
            scope: ``scan`` or ``project``
            report_type: Report type string
            output_dir: Directory for saved file
            name_component: Filename fragment (e.g. scan or project name)
            scan_code: Required when ``scope`` is ``scan``
            project_code: Required when ``scope`` is ``project``
            wait_retry_count: Max polls when waiting for async / notice jobs
            wait_retry_interval: Seconds between polls when waiting
            **report_options: Passed to generate (e.g. ``selection_type``,
                ``include_vex``, ``async_mode``)

        Returns:
            Path to the saved file

        Raises:
            ValidationError: Invalid scope, codes, or report type
            RuntimeError: If ``status_check_service`` is not configured but
                waiting is required
        """
        if scope not in ("scan", "project"):
            raise ValidationError(
                f"Invalid report scope '{scope}'. " f"Expected 'scan' or 'project'."
            )
        if scope == "scan" and not scan_code:
            raise ValidationError("scan_code is required for scan-scoped reports.")
        if scope == "project" and not project_code:
            raise ValidationError("project_code is required for project-scoped reports.")

        opts = self._filter_report_generation_options(dict(report_options))

        if report_type in self.NOTICE_REPORT_TYPES:
            if scope != "scan":
                raise ValidationError(
                    f"Report type '{report_type}' is only supported for " f"scan scope."
                )
            if self._status_check is None:
                raise RuntimeError("status_check_service is not configured on ReportService")
            notice_api = self.NOTICE_REPORT_TYPE_MAP[report_type]
            self.generate_notice_extract(scan_code, notice_api)
            self.check_notice_extract_status(
                scan_code,
                notice_api,
                wait=True,
                wait_retry_count=wait_retry_count,
                wait_retry_interval=wait_retry_interval,
            )
            response = self.download_notice_extract(scan_code, notice_api)
            return self.save_report(
                response,
                output_dir,
                name_component,
                report_type,
                scope=scope,
            )

        is_async = self.is_async_report_type(report_type)

        if is_async:
            if self._status_check is None:
                raise RuntimeError("status_check_service is not configured on ReportService")
            if scope == "project":
                process_id = self.generate_project_report(project_code, report_type, **opts)
                self.check_project_report_status(
                    process_id=process_id,
                    project_code=project_code,
                    wait=True,
                    wait_retry_count=wait_retry_count,
                    wait_retry_interval=wait_retry_interval,
                )
                response = self.download_project_report(process_id)
            else:
                process_id = self.generate_scan_report(scan_code, report_type, **opts)
                self.check_scan_report_status(
                    scan_code=scan_code,
                    process_id=process_id,
                    wait=True,
                    wait_retry_count=wait_retry_count,
                    wait_retry_interval=wait_retry_interval,
                )
                response = self.download_scan_report(process_id)
        else:
            if scope == "project":
                response = self.generate_project_report(project_code, report_type, **opts)
            else:
                response = self.generate_scan_report(scan_code, report_type, **opts)

        return self.save_report(
            response,
            output_dir,
            name_component,
            report_type,
            scope=scope,
        )

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
        logger.debug(f"Downloading project report for process ID {process_id}...")

        # Delegate to the downloads client
        return self._downloads.download_report("projects", process_id)

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
        logger.debug(f"Downloading scan report for process ID {process_id}...")

        # Delegate to the downloads client
        return self._downloads.download_report("scans", process_id)

    # ===== STATUS CHECKING METHODS =====

    def check_scan_report_status(
        self,
        scan_code: str,
        process_id: int,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check scan report generation status (delegates to StatusCheckService).

        Raises:
            RuntimeError: If status_check_service was not configured
        """
        if self._status_check is None:
            raise RuntimeError("status_check_service is not configured on ReportService")
        logger.debug(
            f"Checking scan report status: scan={scan_code}, "
            f"process_id={process_id}, wait={wait}"
        )
        return self._status_check.check_scan_report_status(
            scan_code,
            process_id,
            wait=wait,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    def check_project_report_status(
        self,
        process_id: int,
        project_code: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check the status of an asynchronous project report generation.

        Args:
            process_id: Process queue ID from generate_project_report()
            project_code: Code of the project (for logging context)
            wait: If True, poll until terminal state
            wait_retry_count: Max polls when wait=True
            wait_retry_interval: Seconds between polls when wait=True

        Returns:
            StatusResult with normalized status

        Raises:
            RuntimeError: If status_check_service was not configured
            ApiError: If status check fails

        Example:
            >>> process_id = reports.generate_project_report(
            ...     "MyProject", "xlsx"
            ... )
            >>> status = reports.check_project_report_status(
            ...     process_id, "MyProject"
            ... )
        """
        if self._status_check is None:
            raise RuntimeError("status_check_service is not configured on ReportService")
        logger.debug(
            f"Checking report generation status for process {process_id} "
            f"(project '{project_code}')..."
        )
        return self._status_check.check_project_report_status(
            process_id,
            project_code,
            wait=wait,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    # ===== NOTICE EXTRACT METHODS =====

    def generate_notice_extract(self, scan_code: str, notice_type: str) -> bool:
        """
        Start notice file generation for a scan (notice_extract_run).

        Args:
            scan_code: Scan code
            notice_type: NOTICE_EXTRACT_FILE, NOTICE_EXTRACT_COMPONENT,
                or NOTICE_EXTRACT_AGGREGATE
        """
        return self._scans.notice_extract_run(scan_code, notice_type)

    def check_notice_extract_status(
        self,
        scan_code: str,
        notice_type: str,
        wait: bool = False,
        wait_retry_count: int = 360,
        wait_retry_interval: int = 10,
    ) -> StatusResult:
        """
        Check notice extract status via check_status (delegates by type).

        Args:
            scan_code: Scan code
            notice_type: NOTICE_EXTRACT_FILE, NOTICE_EXTRACT_COMPONENT,
                or NOTICE_EXTRACT_AGGREGATE
            wait: Poll until terminal state when True
            wait_retry_count: Max polls when wait is True
            wait_retry_interval: Seconds between polls when wait is True
        """
        if self._status_check is None:
            raise RuntimeError("status_check_service is not configured on ReportService")
        schk = self._status_check
        dispatch = {
            "NOTICE_EXTRACT_FILE": schk.check_notice_extract_file_status,
            "NOTICE_EXTRACT_COMPONENT": (schk.check_notice_extract_component_status),
            "NOTICE_EXTRACT_AGGREGATE": (schk.check_notice_extract_aggregate_status),
        }
        if notice_type not in dispatch:
            raise ValidationError(
                f"Unknown notice extract type '{notice_type}'. "
                f"Expected one of: {', '.join(sorted(dispatch))}"
            )
        return dispatch[notice_type](
            scan_code,
            wait=wait,
            wait_retry_count=wait_retry_count,
            wait_retry_interval=wait_retry_interval,
        )

    def download_notice_extract(
        self, scan_code: str, notice_type: str
    ) -> Union[requests.Response, str]:
        """Download notice file text (notice_extract_download)."""
        return self._scans.notice_extract_download(scan_code, notice_type)

    def save_report(
        self,
        response_or_content: Union[requests.Response, str, bytes, dict, list],
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
            raise ValidationError("Output directory is not specified for saving report.")
        if not name_component:
            raise ValidationError(
                "Name component (scan/project name) is not specified " "for saving report."
            )
        if not report_type:
            raise ValidationError("Report type is not specified for saving report.")

        filename = ""
        content_to_write: Union[str, bytes] = b""
        write_mode = "wb"

        # Handle wrapped Response objects from base_api
        if isinstance(response_or_content, dict) and "_raw_response" in response_or_content:
            response_or_content = response_or_content["_raw_response"]

        if isinstance(response_or_content, requests.Response):
            response = response_or_content

            # Generate filename based on format
            safe_name = re.sub(r"[^\w\-]+", "_", name_component)
            safe_scope = scope
            safe_type = re.sub(r"[^\w\-]+", "_", report_type)
            ext = self.EXTENSION_MAP.get(report_type.lower(), "txt")
            filename = f"{safe_scope}-{safe_name}-{safe_type}.{ext}"

            logger.debug(f"Generated filename: {filename}")

            try:
                content_to_write = response.content
            except Exception as e:
                raise FileSystemError(f"Failed to read content from response object: {e}")

            content_type = response.headers.get("content-type", "").lower()
            if "text" in content_type or "json" in content_type or "html" in content_type:
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
                    f"Failed to serialize provided dictionary/list to " f"JSON: {e}"
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
                f"Unsupported content type for saving: " f"{type(response_or_content)}"
            )

        filepath = os.path.join(output_dir, filename)

        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.error(
                f"Failed to create output directory '{output_dir}': {e}",
                exc_info=True,
            )
            raise FileSystemError(f"Could not create output directory '{output_dir}': {e}") from e

        try:
            if write_mode == "w":
                with open(filepath, write_mode, encoding="utf-8") as f:
                    f.write(content_to_write)
            else:
                with open(filepath, write_mode) as f:
                    f.write(content_to_write)

            logger.info(f"Successfully saved report to {filepath}")
            return filepath

        except IOError as e:
            logger.error(
                f"Failed to write report to {filepath}: {e}",
                exc_info=True,
            )
            raise FileSystemError(f"Failed to write report to '{filepath}': {e}") from e
        except Exception as e:
            logger.error(
                f"Unexpected error writing report to {filepath}: {e}",
                exc_info=True,
            )
            raise FileSystemError(f"Unexpected error writing report to '{filepath}': {e}") from e
