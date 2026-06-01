"""
IdentificationService - Scan file identification orchestration.

Coordinates ``FilesAndFoldersClient``, ``ComponentService``, and scan-level
read APIs for reviewing KB matches and writing identifications in Workbench.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

logger = logging.getLogger("workbench-agent")


def _fossid_match_to_component_fields(
    match: Mapping[str, Any],
    *,
    license_identifier: Optional[str] = None,
) -> Dict[str, Any]:
    """Map a ``get_fossid_results`` match to catalog resolve fields."""
    component_name = str(match.get("artifact") or "").strip()
    supplier_name = str(match.get("author") or "").strip()
    version = str(match.get("version") or "").strip()
    license_id = str(match.get("artifact_license") or "").strip()
    if license_identifier is not None:
        license_id = license_identifier.strip()
    url = str(match.get("url") or "").strip()
    return {
        "component_name": component_name,
        "component_version": version,
        "supplier_name": supplier_name,
        "license_identifier": license_id,
        "purl": match.get("purl"),
        "url": url,
        "cpe": match.get("cpe"),
    }


def _line_range_from_matched_lines(
    matched_lines: Mapping[str, Any],
    *,
    prefer_local: bool = True,
) -> Optional[Tuple[int, int]]:
    """Derive an inclusive line range from ``get_matched_lines`` data."""
    key = "local_file" if prefer_local else "mirror_file"
    line_map = matched_lines.get(key)
    if not line_map:
        alt = "mirror_file" if prefer_local else "local_file"
        line_map = matched_lines.get(alt)
    if not line_map or not isinstance(line_map, Mapping):
        return None

    numeric: List[int] = []
    for line_id in line_map:
        try:
            numeric.append(int(line_id))
        except (TypeError, ValueError):
            continue
    if not numeric:
        return None
    return min(numeric), max(numeric)


def _build_snippet_comment(
    match: Mapping[str, Any],
    matched_lines: Optional[Mapping[str, Any]] = None,
    *,
    line_range: Optional[Tuple[int, int]] = None,
) -> str:
    """Build a Workbench file comment describing a snippet identification."""
    author = match.get("author") or ""
    artifact = match.get("artifact") or ""
    version = match.get("version") or ""
    origin_file = match.get("file") or ""

    if line_range is None and matched_lines is not None:
        line_range = _line_range_from_matched_lines(matched_lines)

    component_label = f"{author}/{artifact}".strip("/")
    if version:
        component_label = f"{component_label} v{version}".strip()

    if line_range:
        start, end = line_range
        range_text = f"Lines {start}-{end}"
    else:
        range_text = "Snippet match"

    origin_suffix = f" ({origin_file})" if origin_file else ""
    return f"{range_text} match {component_label}{origin_suffix}"


def _component_identification_record(
    identification: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    """Return the primary component identification object when present."""
    components = identification.get("component_identification")
    if isinstance(components, dict) and components:
        return components
    if (
        isinstance(components, list)
        and components
        and isinstance(components[0], Mapping)
    ):
        return components[0]
    return None


def _has_identification_record(identification: Mapping[str, Any]) -> bool:
    return _component_identification_record(identification) is not None


def _parse_linked_catalog_components(
    identification: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    record = _component_identification_record(identification)
    if record is None:
        return []

    linked: List[Dict[str, Any]] = []
    components = record.get("components")
    if isinstance(components, dict):
        for comp in components.values():
            if not isinstance(comp, Mapping):
                continue
            name = comp.get("name")
            if not name:
                continue
            linked.append(
                {
                    "name": str(name),
                    "version": str(comp.get("version") or ""),
                    "component_id": comp.get("component_id") or comp.get("id"),
                    "license_identifier": comp.get("license_identifier"),
                }
            )
    return linked


def _has_linked_catalog_component(identification: Mapping[str, Any]) -> bool:
    return bool(_parse_linked_catalog_components(identification))


def _parse_identifying_done(
    identification: Mapping[str, Any],
) -> Optional[bool]:
    record = _component_identification_record(identification)
    if record is None or "identifying_done" not in record:
        return None
    value = record.get("identifying_done")
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _parse_license_identifiers(
    identification: Mapping[str, Any],
) -> List[str]:
    licenses = identification.get("licenses")
    if licenses in (False, None):
        return []

    identifiers: List[str] = []
    if isinstance(licenses, dict):
        items = licenses.values()
    elif isinstance(licenses, list):
        items = licenses
    else:
        return []

    for item in items:
        if not isinstance(item, Mapping):
            continue
        for key in (
            "license_identifier",
            "identifier",
            "spdx_identifier",
            "license",
        ):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                identifiers.append(value.strip())
                break
    return identifiers


def _parse_copyright_text(identification: Mapping[str, Any]) -> Optional[str]:
    value = identification.get("copyright")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _find_first_match(
    matches: Mapping[str, Any],
    *,
    match_type: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    for entry in matches.values():
        if not isinstance(entry, dict):
            continue
        if match_type is None or entry.get("match_type") == match_type:
            return dict(entry)
    return None


def _parse_distribution_status(
    identification: Mapping[str, Any],
) -> Optional[bool]:
    record = _component_identification_record(identification)
    if record is None or "is_distributed" not in record:
        return None
    value = record.get("is_distributed")
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _has_file_license(data: Mapping[str, Any]) -> bool:
    licenses = data.get("licenses")
    if licenses is False or licenses is None:
        return False
    if isinstance(licenses, list):
        return len(licenses) > 0
    if isinstance(licenses, dict):
        return bool(licenses)
    return bool(licenses)


def _has_copyright(data: Mapping[str, Any]) -> bool:
    copyright_val = data.get("copyright")
    if copyright_val is None:
        return False
    if isinstance(copyright_val, str):
        return bool(copyright_val.strip())
    return bool(copyright_val)


def _summarize_identification_state(
    identification: Mapping[str, Any],
) -> Dict[str, Any]:
    record = _component_identification_record(identification)
    return {
        "has_identification_record": _has_identification_record(identification),
        "has_component_identification": _has_identification_record(
            identification
        ),
        "has_linked_catalog_component": _has_linked_catalog_component(
            identification
        ),
        "linked_catalog_components": _parse_linked_catalog_components(
            identification
        ),
        "has_file_license": _has_file_license(identification),
        "has_copyright": _has_copyright(identification),
        "is_marked_identified": _parse_identifying_done(identification),
        "distribution_status": _parse_distribution_status(identification),
        "license_identifiers": _parse_license_identifiers(identification),
        "copyright_text": _parse_copyright_text(identification),
        "component_record": dict(record) if record is not None else None,
        "raw": dict(identification),
    }


class IdentificationService:
    """
    Service for scan file identification workflows.

    Example:
        >>> svc = client.identification
        >>> pending = svc.get_pending_files(scan_code)
        >>> metrics = svc.get_scan_metrics(scan_code)
        >>> info = svc.get_identification(scan_code, "src/main.c")
        >>> matches = svc.get_matches(scan_code, "src/main.c")
        >>> svc.resolve_component_from_match(matches["74"])
        >>> svc.identify_component_to_file(
        ...     scan_code, "src/main.c", "ofp", "1.1", supplier_name="OpenFastPath"
        ... )
    """

    def __init__(
        self,
        files_and_folders_client,
        component_catalog,
        scans_client,
    ) -> None:
        self._files = files_and_folders_client
        self._catalog = component_catalog
        self._scans = scans_client
        logger.debug("IdentificationService initialized")

    # ===== SCAN-LEVEL READS =====

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Return files pending identification for a scan.

        Maps scan file id → relative path. Use **values** as paths for file
        APIs (auditor workflow entry point).
        """
        logger.debug(
            "Fetching pending files for scan '%s'", scan_code
        )
        return self._scans.get_pending_files(scan_code)

    def get_scan_metrics(self, scan_code: str) -> Dict[str, Any]:
        """Return scan-level file metrics (total, pending, identified, …)."""
        logger.debug(
            "Fetching scan metrics for scan '%s'", scan_code
        )
        return self._scans.get_scan_folder_metrics(scan_code)

    def get_identified_components(
        self, scan_code: str
    ) -> List[Dict[str, Any]]:
        """Return KB-identified components for a scan."""
        logger.debug(
            "Fetching identified components for scan '%s'", scan_code
        )
        return self._scans.get_scan_identified_components(scan_code)

    def get_unique_identified_licenses(
        self, scan_code: str
    ) -> List[Dict[str, Any]]:
        """Return unique identified licenses (identifier + name) for a scan."""
        logger.debug(
            "Fetching unique identified licenses for scan '%s'", scan_code
        )
        return self._scans.get_scan_identified_licenses(
            scan_code, unique=True
        )

    def get_all_identified_licenses(
        self, scan_code: str
    ) -> List[Dict[str, Any]]:
        """Return all identified licenses including file paths for a scan."""
        logger.debug(
            "Fetching all identified licenses for scan '%s'", scan_code
        )
        return self._scans.get_scan_identified_licenses(
            scan_code, unique=False
        )

    # ===== FILE-LEVEL READ / REVIEW =====

    def get_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Return current identification data for a scan file."""
        logger.debug(
            "Getting identification for '%s' in scan '%s'", path, scan_code
        )
        return self._files.get_identification(scan_code, path)

    def summarize_identification_data(
        self, identification: Mapping[str, Any]
    ) -> Dict[str, Any]:
        """
        Summarize identification fields from raw ``get_identification`` data.

        Does not decide readiness to mark identified — callers apply policy.
        """
        return _summarize_identification_state(identification)

    def summarize_identification(
        self, scan_code: str, path: str
    ) -> Dict[str, Any]:
        """Return a summary of identification state for a file."""
        data = self.get_identification(scan_code, path)
        summary = self.summarize_identification_data(data)
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
        path: str,
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
        return self._catalog.find(component_name, component_version)

    def resolve_component_from_match(
        self,
        match: Mapping[str, Any],
        *,
        license_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve the component described by a FossID match in the catalog.

        Creates the catalog entry when missing; returns field metadata either way.
        """
        fields = _fossid_match_to_component_fields(
            match, license_identifier=license_identifier
        )
        return self.resolve_component(**fields)

    def resolve_component(
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
        Resolve a catalog component by name and version; create when absent.

        ``license_identifier`` is required (see ``ComponentService.resolve``).

        Returns:
            Dict with ``component_name``, ``component_version``, ``created`` bool,
            and optional ``create_response``.
        """
        return self._catalog.resolve(
            component_name,
            component_version,
            license_identifier,
            supplier_name=supplier_name,
            purl=purl,
            url=url,
            cpe=cpe,
        )

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
        entry, resolve the catalog row, associate it with the file, and
        optionally add the artifact license at file level.
        """
        fields = _fossid_match_to_component_fields(match)
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
                "call resolve_component / identify_component_to_file directly"
            )

        resolved = self.resolve_component(
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
            supplier_name=resolved.get("supplier_name") or supplier_name,
            preserve_existing_identifications=preserve_existing_identifications,
        )
        license_result = None
        if add_file_license:
            license_result = self.add_file_license_to_file(
                scan_code, path, license_id
            )
        return {
            "fields": fields,
            "catalog": resolved,
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
        match = _find_first_match(matches, match_type="full")
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
        comment = _build_snippet_comment(match, matched_lines)
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
        result["is_marked_identified"] = _parse_identifying_done(
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
        result["is_marked_identified"] = _parse_identifying_done(
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
        current = _parse_distribution_status(identification)
        if current is not None and current == distributed:
            return {
                "changed": False,
                "distributed": distributed,
                "message": "Distribution status already matches requested value.",
            }

        result = self._files.change_distribution_status(scan_code, path)
        after = _parse_distribution_status(
            self.get_identification(scan_code, path)
        )
        if after is not None and after != distributed:
            result = self._files.change_distribution_status(scan_code, path)
            after = _parse_distribution_status(
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
