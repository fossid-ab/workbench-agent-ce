"""
ResolverService - Resolves project and scan names to codes.

This service provides logic for finding or creating
projects and scans based on user-provided names.

The service provides both:
- Low-level explicit methods (find_*, create_*) for precise control
- High-level convenience methods (resolve_*) for "find or create" pattern
- ID reuse resolution (resolving ID reuse source names to codes)
"""

import argparse
import logging
from typing import Optional, Tuple

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError,
)

logger = logging.getLogger("workbench-agent")


class ResolverService:
    """
    Service for resolving project and scan names to codes.

    This service orchestrates ProjectsClient and ScansClient to handle
    the common workflow of looking up or creating projects and scans
    by name.

    Public API:

    **Find only (raises if not found):**
        >>> resolver.find_project("MyProject")
        >>> resolver.find_scan("MyScan", "MyProject")

    **Resolve (find or create both project and scan):**
        >>> project_code, scan_code, is_new = (
        ...     resolver.resolve_project_and_scan(
        ...         "MyProject", "MyScan", params
        ...     )
        ... )

    Usage Guidelines:
    - Use find_* for read-only operations
      (show-results, evaluate-gates, download-reports)
    - Use resolve_project_and_scan() for operations that may create
      (scan, scan-git, blind-scan, import-sbom, import-da)
    """

    def __init__(self, projects_client, scans_client):
        """
        Initialize ResolverService.

        Args:
            projects_client: ProjectsClient instance
            scans_client: ScansClient instance
        """
        self.projects = projects_client
        self.scans = scans_client
        logger.debug("ResolverService initialized")

    # ===== PUBLIC API =====

    def find_project(self, project_name: str) -> str:
        """
        Find a project by name. Raises if not found.

        Use this when you need to ensure a project exists without
        creating it. Good for read-only operations like show-results,
        evaluate-gates.

        Args:
            project_name: Name of the project to find

        Returns:
            str: Project code

        Raises:
            ProjectNotFoundError: If project not found
            ApiError: If there are API issues

        Example:
            >>> # For read-only operations - explicit intent
            >>> project_code = resolver.find_project("MyProject")
        """
        logger.debug(f"Looking up project '{project_name}'...")
        projects = self.projects.list_projects()
        project = next((p for p in projects if p.get("project_name") == project_name), None)

        if project:
            project_code = project["project_code"]
            logger.debug(f"Found project '{project_name}' " f"with code '{project_code}'")
            return str(project_code)

        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def find_scan(self, scan_name: str, project_name: Optional[str] = None) -> Tuple[str, int]:
        """
        Find a scan by name. Raises if not found.

        Performance-optimized: Prefers project-scoped search (efficient)
        over global scan list (heavy operation).

        Use this when you need to ensure a scan exists without
        creating it. Good for read-only operations like show-results,
        evaluate-gates.


        Args:
            scan_name: Name of the scan to find
            project_name: Optional project name to search within.
                         If provided, searches within that project only
                         (uses efficient projects->get_all_scans).
                         If None, searches globally using scans->list_scans
                         (heavy operation - avoid if possible).

        Returns:
            Tuple[str, int]: (scan_code, scan_id)

        Raises:
            ScanNotFoundError: If scan not found
            ProjectNotFoundError: If project_name specified but not found
            ApiError: If there are API issues

        Example:
            >>> # Find scan in specific project (efficient - ALWAYS PREFERRED)
            >>> scan_code, scan_id = resolver.find_scan(
            ...     "MyScan", "MyProject"
            ... )

            >>> # Find scan globally (heavy - rarely needed)
            >>> scan_code, scan_id = resolver.find_scan("MyScan")
        """
        if project_name:
            # Efficient path: Search within specific project
            # Flow: project_name → [list_projects] → project_code →
            #       [get_all_scans] → scan list
            logger.debug(f"Looking up scan '{scan_name}' " f"in project '{project_name}'...")

            # Step 1: Resolve project_name to project_code
            # This requires projects->list_projects
            project_code = self.find_project(project_name)

            # Step 2: Get scans for this specific project
            # This uses projects->get_all_scans (efficient, scoped)
            scan_list = self.projects.get_project_scans(project_code)

            # Step 3: Find exact scan match
            scan = next((s for s in scan_list if s.get("name") == scan_name), None)
            if scan:
                logger.debug(
                    f"Found scan '{scan_name}' with code '{scan['code']}' "
                    f"and ID {scan['id']} in project '{project_name}'"
                )
                return scan["code"], int(scan["id"])

            # Scan not found in this project
            raise ScanNotFoundError(f"Scan '{scan_name}' not found in project '{project_name}'")
        else:
            # Heavy path: Global search across all scans
            # Uses scans->list_scans (memory intensive!)
            # Rarely needed - most use cases should provide project_name
            logger.debug(
                f"Looking up scan '{scan_name}' globally " f"(using heavy scans->list_scans)..."
            )
            logger.warning(
                "Global scan search is memory intensive! "
                "Consider providing project_name if known."
            )
            all_scans = self.scans.list_scans()
            scan = next((s for s in all_scans if s.get("name") == scan_name), None)
            if scan:
                logger.debug(
                    f"Found scan '{scan_name}' with code '{scan['code']}' "
                    f"and ID {scan['id']} (global search)"
                )
                return scan["code"], int(scan["id"])

            raise ScanNotFoundError(f"Scan '{scan_name}' not found")

    def resolve_project_and_scan(
        self,
        project_name: str,
        scan_name: str,
        params: argparse.Namespace,
        import_from_report: bool = False,
    ) -> Tuple[str, str, bool]:
        """
        Resolve project and scan (find or create both).

        This convenience method combines project and scan resolution in one
        call and provides user-friendly feedback on what was created/found.
        It also automatically validates scan compatibility for existing scans.

        Args:
            project_name: Name of the project
            scan_name: Name of the scan
            params: Command-line parameters (used for scan creation)
            import_from_report: Whether scan is for SBOM import

        Returns:
            Tuple[str, str, bool]: (project_code, scan_code, scan_is_new)
                where scan_is_new indicates if the scan was just created

        Raises:
            CompatibilityError: If existing scan is incompatible with operation

        Example:
            >>> project_code, scan_code, scan_is_new = (
            ...     resolver.resolve_project_and_scan(
            ...         "MyProject", "MyScan", params
            ...     )
            ... )
            # Prints: "✓ Created new Project and Scan"
            # Or: "✓ Found existing Project, created new Scan"
            # Or: "✓ Found existing Project and Scan"
            # Or: "Checking scan compatibility..." +
            #     "✓ Compatibility check passed"
        """
        # Try to find project
        project_created = False
        try:
            project_code = self.find_project(project_name)
        except ProjectNotFoundError:
            project_code = self._create_project(project_name=project_name)
            project_created = True

        # Try to find scan
        scan_is_new = False
        try:
            scan_code, _ = self.find_scan(scan_name=scan_name, project_name=project_name)
        except ScanNotFoundError:
            scan_code, _ = self._create_scan(
                scan_name=scan_name,
                project_code=project_code,
                params=params,
                import_from_report=import_from_report,
            )
            scan_is_new = True

        # Provide user feedback based on what happened
        # Note: "project created + scan exists" is impossible
        # (new project is empty)
        if project_created and scan_is_new:
            print("✓ Created new Project and Scan")
        elif scan_is_new:
            print("✓ Created New Scan in Existing Project")
        else:
            print("✓ Found existing Project and Scan")

        # Validate scan compatibility for existing scans
        # (new scans are always compatible, so skip the check)
        if not scan_is_new:
            print("Checking scan compatibility...")
            self.ensure_scan_compatible(scan_code, params.command, params)
            print("✓ Compatibility check passed")
        else:
            logger.debug("Skipping compatibility check - new scan is always compatible")

        return project_code, scan_code, scan_is_new

    # ===== PRIVATE METHODS =====

    def _create_project(
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
        Internal: Create a new project.

        This is a private method. Use resolve_project_and_scan() instead
        for the standard workflow.

        Args:
            project_name: Name for the new project
            product_code: Optional product code
            product_name: Optional product name
            description: Optional description
            comment: Optional comment
            limit_date: Optional deadline (format: "YYYY-MM-DD")
            jira_project_key: Optional JIRA project key

        Returns:
            str: Project code of the created project

        Raises:
            ProjectExistsError: If project already exists
            ApiError: If creation fails
        """
        logger.debug(f"Creating project '{project_name}'...")
        print(f"Creating project '{project_name}'...")

        project_code = self.projects.create_project(
            project_name=project_name,
            product_code=product_code,
            product_name=product_name,
            description=description,
            comment=comment,
            limit_date=limit_date,
            jira_project_key=jira_project_key,
        )
        return str(project_code)

    def _create_scan(
        self,
        scan_name: str,
        project_code: str,
        params: argparse.Namespace,
        import_from_report: bool = False,
    ) -> Tuple[str, int]:
        """
        Internal: Create a new scan in a project.

        This is a private method. Use resolve_project_and_scan() instead.

        Args:
            scan_name: Name for the new scan
            project_code: Project code (not name) to create scan in
                         Caller must resolve project_name → project_code
            params: Command-line parameters (used to extract scan config)
            import_from_report: Whether this scan is for SBOM import

        Returns:
            Tuple[str, int]: (scan_code, scan_id) of the created scan

        Raises:
            ProjectNotFoundError: If project doesn't exist
            ApiError: If scan creation fails
        """
        logger.debug(f"Creating scan '{scan_name}' in project '{project_code}'...")
        print(f"Creating scan '{scan_name}' in project '{project_code}'...")

        # Build scan data from parameters
        scan_data = {
            "project_code": project_code,
            "scan_name": scan_name,
        }

        # Add optional parameters if provided
        if hasattr(params, "description") and params.description:
            scan_data["description"] = params.description

        if hasattr(params, "target_path") and params.target_path:
            scan_data["target_path"] = params.target_path

        # Note: CLI parameter is --git-url (becomes params.git_url)
        # but API expects git_repo_url
        if hasattr(params, "git_url") and params.git_url:
            scan_data["git_repo_url"] = params.git_url

        if hasattr(params, "git_branch") and params.git_branch:
            scan_data["git_branch"] = params.git_branch
            scan_data["git_ref_type"] = "branch"
        elif hasattr(params, "git_tag") and params.git_tag:
            scan_data["git_branch"] = params.git_tag
            scan_data["git_ref_type"] = "tag"
        elif hasattr(params, "git_commit") and params.git_commit:
            scan_data["git_branch"] = params.git_commit
            scan_data["git_ref_type"] = "commit"

        if hasattr(params, "git_depth") and params.git_depth is not None:
            scan_data["git_depth"] = str(params.git_depth)

        # For SBOM import, we don't need to prepare for scanning
        if import_from_report:
            scan_data["import_from_report"] = "1"

        # Create the scan
        self.scans.create_scan(scan_data)

        # Fetch the created scan to return its details
        scan_list = self.projects.get_project_scans(project_code)
        scan = next((s for s in scan_list if s.get("name") == scan_name), None)
        if scan:
            logger.debug(
                f"Created scan '{scan_name}' with code '{scan['code']}' " f"and ID {scan['id']}"
            )
            return scan["code"], int(scan["id"])

        raise ApiError(f"Failed to retrieve scan '{scan_name}' after creation")

    # ===== VALIDATION METHODS =====

    def ensure_scan_compatible(
        self, scan_code: str, operation: str, params: argparse.Namespace
    ) -> None:
        """
        Validate that a scan is compatible with the requested operation.

        This is part of the "resolution" process - ensuring the resolved
        scan resource is actually usable for the intended purpose.

        Args:
            scan_code: Code of the scan to validate
            operation: Type of operation ("scan", "scan-git", "import-da",
                "import-sbom", "blind-scan")
            params: Command line parameters for context

        Raises:
            CompatibilityError: If scan is incompatible with the operation

        Note:
            This method is graceful - if the scan cannot be fetched or
            API errors occur, it logs warnings and continues rather than
            failing hard.
        """
        logger.debug(
            f"Verifying scan '{scan_code}' is compatible with operation " f"'{operation}'..."
        )

        # Fetch scan information
        try:
            existing_scan_info = self.scans.get_scan_information(scan_code)
        except ScanNotFoundError:
            logger.warning(f"Scan '{scan_code}' not found during compatibility check.")
            return
        except (ApiError, NetworkError) as e:
            logger.warning(f"Error fetching scan information during compatibility " f"check: {e}")
            print(f"Warning: Could not verify scan compatibility due to API " f"error: {e}")
            return

        # Extract existing scan configuration
        existing_git_repo = existing_scan_info.get(
            "git_repo_url", existing_scan_info.get("git_url")
        )
        existing_git_ref_value = existing_scan_info.get("git_branch")
        existing_git_ref_type = existing_scan_info.get("git_ref_type")
        existing_is_from_report = existing_scan_info.get("is_from_report", "0")
        existing_is_report_scan = existing_is_from_report in [
            "1",
            1,
            True,
            "true",
        ]

        # Extract current operation parameters
        current_git_url = getattr(params, "git_url", None)
        current_git_branch = getattr(params, "git_branch", None)
        current_git_tag = getattr(params, "git_tag", None)
        current_git_ref_type = (
            "tag" if current_git_tag else ("branch" if current_git_branch else None)
        )
        current_git_ref_value = current_git_tag if current_git_tag else current_git_branch

        error_message = None

        # Validate compatibility based on operation type
        if operation == "scan" or operation == "blind-scan":
            if existing_is_report_scan:
                error_message = (
                    f"Scan '{scan_code}' was created for SBOM import and "
                    f"cannot be reused for code upload via --path."
                )
            elif existing_git_repo:
                error_message = (
                    f"Scan '{scan_code}' was created for Git scanning "
                    f"(Repo: {existing_git_repo}) and cannot be reused for "
                    f"code upload via --path."
                )

        elif operation == "scan-git":
            if existing_is_report_scan:
                error_message = (
                    f"Scan '{scan_code}' was created for SBOM import and "
                    f"cannot be reused for Git scanning."
                )
            elif not existing_git_repo:
                error_message = (
                    f"Scan '{scan_code}' was created for code upload "
                    f"(using --path) and cannot be reused for Git scanning."
                )
            elif existing_git_repo != current_git_url:
                error_message = (
                    f"Scan '{scan_code}' already exists but is configured "
                    f"for a different Git repository "
                    f"(Existing: '{existing_git_repo}', "
                    f"Requested: '{current_git_url}'). "
                    f"Please use a different --scan-name to create a new "
                    f"scan."
                )
            elif (
                current_git_ref_type
                and existing_git_ref_type
                and existing_git_ref_type.lower() != current_git_ref_type.lower()
            ):
                error_message = (
                    f"Scan '{scan_code}' exists with ref type "
                    f"'{existing_git_ref_type}', but current command "
                    f"specified ref type '{current_git_ref_type}'. "
                    f"Please use a different --scan-name or use a matching "
                    f"ref type."
                )
            elif existing_git_ref_value != current_git_ref_value:
                error_message = (
                    f"Scan '{scan_code}' already exists for "
                    f"{existing_git_ref_type or 'ref'} "
                    f"'{existing_git_ref_value}', "
                    f"but current command specified "
                    f"{current_git_ref_type or 'ref'} "
                    f"'{current_git_ref_value}'. "
                    f"Please use a different --scan-name or use the "
                    f"matching ref."
                )

        elif operation == "import-da":
            if existing_is_report_scan:
                error_message = (
                    f"Scan '{scan_code}' was created for SBOM import and "
                    f"cannot be reused for dependency analysis import."
                )

        elif operation == "import-sbom":
            if not existing_is_report_scan:
                error_message = (
                    f"Scan '{scan_code}' was not created for SBOM import "
                    f"and cannot be reused for SBOM import. Only scans "
                    f"created with 'import-sbom' can be reused for SBOM "
                    f"operations."
                )

        # Raise error if incompatible
        if error_message:
            print("\nError: Incompatible scan usage detected.")
            logger.error(f"Compatibility check failed for scan '{scan_code}': " f"{error_message}")
            raise CompatibilityError(
                f"Incompatible usage for existing scan '{scan_code}': " f"{error_message}"
            )

        # Log success
        logging.info("Compatibility check passed! Proceeding...")
        if operation == "scan-git" and existing_git_repo:
            ref_display = f"{existing_git_ref_type or 'ref'} '{existing_git_ref_value}'"
            logger.debug(
                f"Reusing existing scan '{scan_code}' configured for Git "
                f"repository '{existing_git_repo}' ({ref_display})."
            )
        elif operation in ("scan", "blind-scan") and not existing_git_repo:
            logger.debug(f"Reusing existing scan '{scan_code}' configured for code " f"upload.")
        elif operation == "import-da":
            logger.debug(f"Reusing existing scan '{scan_code}' for DA import.")
        elif operation == "import-sbom":
            logger.debug(
                f"Reusing existing scan '{scan_code}' for SBOM import "
                f"(report scan: {existing_is_report_scan})."
            )

    # ===== ID REUSE RESOLUTION =====

    def resolve_id_reuse(
        self,
        id_reuse_any: bool = False,
        id_reuse_my: bool = False,
        id_reuse_project_name: Optional[str] = None,
        id_reuse_scan_name: Optional[str] = None,
        current_project_name: Optional[str] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve ID reuse parameters (name→code resolution).

        This method handles ID reuse resolution with graceful degradation:
        - Simple cases (any/my) need no resolution
        - Complex cases (project/scan) automatically resolve names→codes
        - If resolution fails, warns and returns None (allows scan to continue)

        Args:
            id_reuse_any: Reuse any existing identification from the system
            id_reuse_my: Only reuse identifications made by the current user
            id_reuse_project_name: Reuse IDs from specific project (by name)
            id_reuse_scan_name: Reuse IDs from specific scan (by name)
            current_project_name: Current project name
                (for scan resolution optimization)

        Returns:
            Tuple of (id_reuse_type, id_reuse_specific_code):
            - id_reuse_type: "any", "only_me", "specific_project",
              "specific_scan", or None
            - id_reuse_specific_code: Code for specific_project/specific_scan,
              or None

        Note:
            Uses graceful degradation - if resolution fails, warns and
            returns None (allows scan to continue without ID reuse).

        Example:
            >>> id_type, id_code = resolver.resolve_id_reuse(
            ...     id_reuse_project_name="MyProject",
            ...     current_project_name="CurrentProject"
            ... )
        """
        # Simple cases - no resolution needed
        if id_reuse_any:
            logger.info("ID reuse: any")
            return "any", None

        if id_reuse_my:
            logger.info("ID reuse: only_me")
            return "only_me", None

        # Complex cases - need name→code resolution
        if id_reuse_project_name:
            return self._resolve_project_reuse(id_reuse_project_name)
        elif id_reuse_scan_name:
            return self._resolve_scan_reuse(id_reuse_scan_name, current_project_name)

        # No ID reuse requested
        return None, None

    def _resolve_project_reuse(self, project_name: str) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve project reuse - warn and return None if fails.

        Uses graceful degradation: if resolution fails, logs warning and
        returns None rather than blocking the scan.
        """
        try:
            project_code = self.find_project(project_name)
            logger.info(f"ID reuse: project '{project_name}' → '{project_code}'")
            print(f"✓ Successfully validated ID reuse project '{project_name}'")
            return "specific_project", project_code
        except Exception as e:
            self._handle_reuse_failure("project", project_name, e)
            return None, None

    def _resolve_scan_reuse(
        self,
        scan_name: str,
        current_project_name: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve scan reuse - warn and return None if fails.

        Uses optimized resolution (tries current project first, then global).
        Uses graceful degradation: if resolution fails, logs warning and
        returns None rather than blocking the scan.
        """
        try:
            # Try current project first (efficient - common case)
            # Most ID reuse is within the same project
            if current_project_name:
                logger.debug(
                    f"Looking for ID reuse source scan '{scan_name}' "
                    f"(checking project '{current_project_name}' first, "
                    f"then global if needed)"
                )
                try:
                    scan_code, _ = self.find_scan(scan_name, current_project_name)
                    logger.info(
                        f"Found ID reuse source scan '{scan_name}' in current "
                        f"project '{current_project_name}'."
                    )
                except ScanNotFoundError:
                    # Not in current project, try global search
                    logger.debug(
                        f"Scan '{scan_name}' not found in project "
                        f"'{current_project_name}', trying global search..."
                    )
                    scan_code, _ = self.find_scan(scan_name, None)
                    logger.info(
                        f"Found ID reuse source scan '{scan_name}' via global "
                        f"search (scan is in a different project)"
                    )
            else:
                # No current project - try global search directly
                scan_code, _ = self.find_scan(scan_name, None)

            logger.info(f"ID reuse: scan '{scan_name}' → '{scan_code}'")
            print(f"✓ Successfully validated ID reuse scan '{scan_name}'")
            return "specific_scan", scan_code
        except Exception as e:
            self._handle_reuse_failure("scan", scan_name, e)
            return None, None

    def _handle_reuse_failure(self, reuse_type: str, name: str, error: Exception) -> None:
        """
        Handle ID reuse resolution failure with consistent messaging.

        Logs warning and prints user-friendly message. Does NOT raise
        exception - allows scan to continue without ID reuse
        (graceful degradation).
        """
        logger.warning(
            f"ID reuse validation failed: {reuse_type} '{name}' - "
            f"{type(error).__name__}: {error}. Continuing without ID reuse."
        )
        print(
            f"⚠️  Warning: ID reuse {reuse_type} '{name}' not found. "
            "Continuing scan without ID reuse."
        )
