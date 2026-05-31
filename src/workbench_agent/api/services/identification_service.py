"""
IdentificationService - Scan file identification orchestration.

Coordinates ``FilesAndFoldersClient`` and ``ComponentsClient`` for reviewing
KB matches and writing identifications in Workbench.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional, Union

from workbench_agent.api.utils.identification_helpers import (
    build_snippet_comment,
    find_first_match,
    fossid_match_to_component_fields,
    parse_distribution_status,
    parse_identifying_done,
    summarize_identification_state,
)

logger = logging.getLogger("workbench-agent")


class IdentificationService:
    """
    Service for scan file identification workflows.

    Example:
        >>> svc = IdentificationService(
        ...     client.files_and_folders, client.components
        ... )
        >>> info = svc.get_identification(scan_code, "src/main.c")
        >>> matches = svc.get_matches(scan_code, "src/main.c")
        >>> svc.ensure_component_from_match(matches["74"])
        >>> svc.identify_component_to_file(
        ...     scan_code, "src/main.c", "ofp", "1.1", supplier_name="OpenFastPath"
        ... )
    """

    def __init__(self, files_and_folders_client, components_client) -> None:
        self._files = files_and_folders_client
        self._components = components_client
        logger.debug("IdentificationService initialized")

    # ===== READ / REVIEW =====

    def get_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Return current identification data for a scan file."""
        logger.debug(
            "Getting identification for '%s' in scan '%s'", path, scan_code
        )
        return self._files.get_identification(scan_code, path)

    def summarize_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Return a summary of identification state for a file."""
        data = self.get_identification(scan_code, path)
        summary = summarize_identification_state(data)
        summary["path"] = path
        summary["scan_code"] = scan_code
        return summary

    def get_matches(self, scan_code: str, path: str) -> Dict[str, Any]:
        """Return FossID match candidates for a file (max 10)."""
        logger.debug(
            "Getting FossID matches for '%s' in scan '%s'", path, scan_code
        )
        return self._files.get_fossid_results(scan_code, path)

    def get_matched_content(
        self,
        scan_code: str,
        path: str,
        client_result_id: str,
    ) -> Dict[str, Any]:
        """Return matched lines for a partial FossID match."""
        return self._files.get_matched_lines(
            scan_code, path, client_result_id
        )

    def get_file_comments(
        self, scan_code: str, path: str
    ) -> list:
        """Return auditor comments attached to a scan file."""
        return self._files.get_file_comments(scan_code, path)

    def explore_folder(
        self,
        scan_code: str,
        path: str = ".",
        *,
        pending_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Folder discovery snapshot for agents: tree entries, extensions, components.

        Wraps ``get_folder_content``, ``get_folder_extensions_ranking``, and
        ``get_folder_components_ranking`` for a single folder path.
        """
        view = "pending_items" if pending_only else "show_all"
        components = self._files.get_folder_components_ranking(
            scan_code, path
        )
        extensions = self._files.get_folder_extensions_ranking(
            scan_code, path, current_view=view
        )
        return {
            "path": path,
            "scan_code": scan_code,
            "entries": self._files.get_folder_content(
                scan_code,
                path,
                show_all=not pending_only,
            ),
            "extensions": extensions if isinstance(extensions, list) else [],
            "components": components if isinstance(components, list) else [],
        }

    # ===== COMPONENT LIFECYCLE =====

    def find_component(
        self,
        component_name: str,
        component_version: Optional[str] = None,
    ) -> Optional[Union[Dict[str, Any], list]]:
        """Return catalog component information, or ``None`` if missing."""
        return self._components.get_information(
            component_name, component_version
        )

    def ensure_component_from_match(
        self,
        match: Mapping[str, Any],
        *,
        license_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ensure the component described by a FossID match exists in Workbench.

        Creates the catalog entry when missing; returns field metadata either way.
        """
        fields = fossid_match_to_component_fields(
            match, license_identifier=license_identifier
        )
        return self.ensure_component(**fields)

    def ensure_component(
        self,
        component_name: str,
        component_version: str,
        license_identifier: str,
        *,
        supplier_name: Optional[str] = None,
        purl: Optional[str] = None,
        url: Optional[str] = None,
        cpe: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ensure a catalog component exists; create it when absent.

        Returns:
            Dict with ``component_name``, ``component_version``, ``created`` bool,
            and optional ``create_response``.
        """
        name = component_name.strip()
        version = component_version.strip()
        license_id = license_identifier.strip()
        if not name or not version:
            raise ValueError("component_name and component_version are required")
        if not license_id:
            raise ValueError("license_identifier is required to create a component")

        existing = self.find_component(name, version)
        if existing is not None:
            catalog_supplier = (
                existing.get("supplier_name")
                if isinstance(existing, dict)
                else None
            )
            resolved_supplier = catalog_supplier or supplier_name
            logger.debug(
                "Component '%s' v%s already exists in catalog (supplier=%r)",
                name,
                version,
                resolved_supplier,
            )
            return {
                "component_name": name,
                "component_version": version,
                "supplier_name": resolved_supplier,
                "created": False,
            }

        logger.info("Creating catalog component '%s' v%s", name, version)
        create_kwargs: Dict[str, Any] = {
            "name": name,
            "version": version,
            "license_identifier": license_id,
        }
        if supplier_name:
            create_kwargs["sup_com_name"] = supplier_name
        if purl:
            create_kwargs["purl"] = purl
        if url:
            create_kwargs["url"] = url
        if cpe:
            create_kwargs["cpe"] = cpe

        create_response = self._components.create(**create_kwargs)
        return {
            "component_name": name,
            "component_version": version,
            "supplier_name": supplier_name,
            "created": True,
            "create_response": create_response,
        }

    def identify_component_to_file(
        self,
        scan_code: str,
        path: str,
        component_name: str,
        component_version: str,
        *,
        supplier_name: Optional[str] = None,
        preserve_existing_identifications: bool = True,
    ) -> Dict[str, Any]:
        """Associate a file with a catalog component."""
        return self._files.set_identification_component(
            scan_code,
            path,
            component_name,
            component_version,
            is_directory=False,
            supplier_name=supplier_name,
            preserve_existing_identifications=preserve_existing_identifications,
        )

    def identify_component_to_folder(
        self,
        scan_code: str,
        folder_path: str,
        component_name: str,
        component_version: str,
        *,
        supplier_name: Optional[str] = None,
        preserve_existing_identifications: bool = True,
    ) -> Dict[str, Any]:
        """Associate all files under a folder with a catalog component."""
        return self._files.set_identification_component(
            scan_code,
            folder_path,
            component_name,
            component_version,
            is_directory=True,
            supplier_name=supplier_name,
            preserve_existing_identifications=preserve_existing_identifications,
        )

    def identify_whole_file_from_match(
        self,
        scan_code: str,
        path: str,
        match: Mapping[str, Any],
        *,
        add_file_license: bool = True,
        supplier_name: Optional[str] = None,
        preserve_existing_identifications: bool = True,
    ) -> Dict[str, Any]:
        """
        Ensure catalog component from a full-file FossID match and link it.

        Typical agent flow after ``get_matches``: pick a ``match_type='full'``
        entry, ensure the catalog row exists, associate it with the file, and
        optionally add the artifact license at file level.
        """
        fields = fossid_match_to_component_fields(match)
        name = fields["component_name"]
        version = fields["component_version"]
        if not name or not version:
            raise ValueError(
                "Match is missing artifact name or version for whole-file ID"
            )
        license_id = fields.get("license_identifier") or ""
        if not license_id:
            raise ValueError(
                "Match is missing artifact_license; supply a license or "
                "call ensure_component / identify_component_to_file directly"
            )

        ensured = self.ensure_component(
            name,
            version,
            license_id,
            supplier_name=supplier_name or fields.get("supplier_name"),
            purl=fields.get("purl"),
            url=fields.get("url"),
            cpe=fields.get("cpe"),
        )
        component_result = self.identify_component_to_file(
            scan_code,
            path,
            name,
            version,
            supplier_name=ensured.get("supplier_name") or supplier_name,
            preserve_existing_identifications=preserve_existing_identifications,
        )
        license_result = None
        if add_file_license:
            license_result = self.add_file_license_to_file(
                scan_code, path, license_id
            )
        return {
            "fields": fields,
            "catalog": ensured,
            "component": component_result,
            "license": license_result,
        }

    def identify_from_best_full_match(
        self,
        scan_code: str,
        path: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Pick the first ``full`` FossID match and run ``identify_whole_file_from_match``."""
        matches = self.get_matches(scan_code, path)
        match = find_first_match(matches, match_type="full")
        if match is None:
            raise ValueError(
                f"No full-file FossID match available for '{path}'"
            )
        result = self.identify_whole_file_from_match(
            scan_code, path, match, **kwargs
        )
        result["match"] = match
        return result

    # ===== LICENSES & COPYRIGHT =====

    def add_file_license_to_file(
        self,
        scan_code: str,
        path: str,
        license_identifier: str,
    ) -> Dict[str, Any]:
        """Add a file-level license identification."""
        return self._files.add_license_identification(
            scan_code,
            path,
            license_identifier,
            "file",
            is_directory=False,
        )

    def add_file_license_to_folder(
        self,
        scan_code: str,
        folder_path: str,
        license_identifier: str,
    ) -> Dict[str, Any]:
        """Add a file-level license identification recursively under a folder."""
        return self._files.add_license_identification(
            scan_code,
            folder_path,
            license_identifier,
            "file",
            is_directory=True,
        )

    def add_copyright_to_file(
        self,
        scan_code: str,
        path: str,
        copyright: str,
    ) -> Dict[str, Any]:
        """Set copyright identification on a file."""
        return self._files.set_identification_copyright(
            scan_code,
            path,
            copyright,
            is_directory=False,
        )

    def add_copyright_to_folder(
        self,
        scan_code: str,
        folder_path: str,
        copyright: str,
    ) -> Dict[str, Any]:
        """Set copyright identification on all files under a folder."""
        return self._files.set_identification_copyright(
            scan_code,
            folder_path,
            copyright,
            is_directory=True,
        )

    def identify_snippet_in_file(
        self,
        scan_code: str,
        path: str,
        license_identifier: str,
        match: Mapping[str, Any],
        client_result_id: str,
    ) -> Dict[str, Any]:
        """
        Add snippet license identification and a descriptive file comment.

        Fetches matched lines from Workbench to build the comment text.
        """
        matched_lines = self.get_matched_content(
            scan_code, path, client_result_id
        )
        comment = build_snippet_comment(match, matched_lines)
        license_result = self._files.add_license_identification(
            scan_code,
            path,
            license_identifier,
            "snippet",
            is_directory=False,
        )
        comment_result = self._files.add_file_comment(
            scan_code, path, comment
        )
        return {
            "license": license_result,
            "comment": comment_result,
            "comment_text": comment,
            "matched_lines": matched_lines,
        }

    def add_file_comment(
        self,
        scan_code: str,
        path: str,
        comment: str,
        *,
        is_important: bool = False,
        include_in_report: bool = False,
    ) -> Dict[str, Any]:
        """Add a comment to a scan file."""
        return self._files.add_file_comment(
            scan_code,
            path,
            comment,
            is_important=is_important,
            include_in_report=include_in_report,
        )

    # ===== COMPLETION & DISTRIBUTION =====

    def mark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: bool = False,
    ) -> Dict[str, Any]:
        """Mark a file or folder as identified."""
        result = self._files.mark_as_identified(
            scan_code, path, is_directory=is_directory
        )
        result["is_marked_identified"] = parse_identifying_done(
            self.get_identification(scan_code, path)
        )
        return result

    def unmark_as_identified(
        self,
        scan_code: str,
        path: str,
        *,
        is_directory: bool = False,
    ) -> Dict[str, Any]:
        """Remove identified status from a file or folder."""
        result = self._files.unmark_as_identified(
            scan_code, path, is_directory=is_directory
        )
        result["is_marked_identified"] = parse_identifying_done(
            self.get_identification(scan_code, path)
        )
        return result

    def set_distribution_status(
        self,
        scan_code: str,
        path: str,
        *,
        distributed: bool,
    ) -> Dict[str, Any]:
        """
        Set distributed / not-distributed for a file.

        Uses ``get_identification`` when possible; toggles via the API when the
        current state is unknown or differs from the requested value.
        """
        identification = self.get_identification(scan_code, path)
        current = parse_distribution_status(identification)
        if current is not None and current == distributed:
            return {
                "changed": False,
                "distributed": distributed,
                "message": "Distribution status already matches requested value.",
            }

        result = self._files.change_distribution_status(scan_code, path)
        after = parse_distribution_status(
            self.get_identification(scan_code, path)
        )
        if after is not None and after != distributed:
            result = self._files.change_distribution_status(scan_code, path)
            after = parse_distribution_status(
                self.get_identification(scan_code, path)
            )

        return {
            "changed": True,
            "distributed": after if after is not None else distributed,
            "api_response": result,
        }

    def remove_component_identification(
        self,
        scan_code: str,
        path: str,
        *,
        component_name: Optional[str] = None,
        component_version: Optional[str] = None,
    ) -> bool:
        """Remove component identification(s) from a file."""
        return self._files.remove_component_identification(
            scan_code,
            path,
            component_name=component_name,
            component_version=component_version,
        )
