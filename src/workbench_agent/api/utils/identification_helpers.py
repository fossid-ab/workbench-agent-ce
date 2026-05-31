"""Helpers for scan file identification workflows."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Tuple


def to_workbench_path(abs_path: str, workspace_root: str) -> str:
    """
    Convert an absolute local path to a Workbench scan-relative path.

    Args:
        abs_path: Absolute or relative file path
        workspace_root: Repository / workspace root directory

    Returns:
        Forward-slash relative path suitable for files_and_folders APIs
    """
    abs_path = os.path.normpath(abs_path)
    workspace_root = os.path.normpath(workspace_root)
    if os.path.isabs(abs_path):
        rel = os.path.relpath(abs_path, workspace_root)
    else:
        rel = abs_path
    return rel.replace("\\", "/")


def fossid_match_to_component_fields(
    match: Mapping[str, Any],
    *,
    license_identifier: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Map a Workbench ``get_fossid_results`` match object to catalog fields.

    Workbench matches expose ``author``, ``artifact``, and ``version`` separately.
    ``artifact_license`` is the KB component license. ``url`` is the download URL,
    useful when creating catalog entries via ``ensure_component``.
    """
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


def line_range_from_matched_lines(
    matched_lines: Mapping[str, Any],
    *,
    prefer_local: bool = True,
) -> Optional[Tuple[int, int]]:
    """
    Derive an inclusive line range from ``get_matched_lines`` response data.

    The API returns maps of line id strings; we use numeric min/max for comments.

    With Blind Scans, ``local_file`` is an empty list for partial matches; line
    numbers are used from ``mirror_file`` instead (see ``quirks.md``).
    """
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


def build_snippet_comment(
    match: Mapping[str, Any],
    matched_lines: Optional[Mapping[str, Any]] = None,
    *,
    line_range: Optional[Tuple[int, int]] = None,
) -> str:
    """
    Build a Workbench file comment describing a snippet identification.

    Uses local matched lines when available; falls back to match metadata only.
    """
    author = match.get("author") or ""
    artifact = match.get("artifact") or ""
    version = match.get("version") or ""
    origin_file = match.get("file") or ""

    if line_range is None and matched_lines is not None:
        line_range = line_range_from_matched_lines(matched_lines)

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


def _coerce_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "distributed"}:
            return True
        if lowered in {"0", "false", "no", "not_distributed", "not distributed"}:
            return False
    return None


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


def component_identification_record(
    identification: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    """
    Return the Workbench ``component_identification`` record for a file.

    Workbench returns ``[]`` when unset, then a **dict** after the first write
    (even a file license alone). Catalog linkage is indicated separately —
    see ``has_linked_catalog_component``.
    """
    return _component_identification_record(identification)


def has_identification_record(identification: Mapping[str, Any]) -> bool:
    """True when Workbench has a ``component_identification`` record (dict/list)."""
    return _component_identification_record(identification) is not None


def has_linked_catalog_component(identification: Mapping[str, Any]) -> bool:
    """
    True when a catalog component is linked to the file identification.

    A file-level license alone creates a ``component_identification`` dict
    without catalog linkage. On 2026.1, linked components appear under
    ``component_identification.components`` (id → component dict).
    """
    return bool(parse_linked_catalog_components(identification))


def parse_linked_catalog_components(
    identification: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """
    Return catalog components linked to a file identification.

    Each entry includes ``name``, ``version``, ``component_id``, and
    ``license_identifier`` when present in the Workbench response.
    """
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


def parse_identifying_done(
    identification: Mapping[str, Any],
) -> Optional[bool]:
    """
    Parse audit-complete status from ``component_identification.identifying_done``.

    Returns ``True`` when marked identified, ``False`` when explicitly not,
    ``None`` when the field is absent.
    """
    record = _component_identification_record(identification)
    if record is None or "identifying_done" not in record:
        return None
    return _coerce_bool(record.get("identifying_done"))


def parse_license_identifiers(
    identification: Mapping[str, Any],
) -> List[str]:
    """
    Extract SPDX / license identifiers from ``get_identification`` license data.

    ``licenses`` may be ``false``, a dict keyed by id, or a list of objects.
    """
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


def parse_copyright_text(identification: Mapping[str, Any]) -> Optional[str]:
    """Return manual/autoid copyright text when set."""
    value = identification.get("copyright")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def find_matches_by_type(
    matches: Mapping[str, Any],
    match_type: str,
) -> List[Dict[str, Any]]:
    """Return FossID match objects with the given ``match_type`` (e.g. ``full``)."""
    found: List[Dict[str, Any]] = []
    for entry in matches.values():
        if isinstance(entry, dict) and entry.get("match_type") == match_type:
            found.append(dict(entry))
    return found


def find_first_match(
    matches: Mapping[str, Any],
    *,
    match_type: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the first FossID match, optionally filtered by ``match_type``."""
    for entry in matches.values():
        if not isinstance(entry, dict):
            continue
        if match_type is None or entry.get("match_type") == match_type:
            return dict(entry)
    return None


def parse_distribution_status(
    identification: Mapping[str, Any],
) -> Optional[bool]:
    """
    Best-effort parse of distributed / not-distributed from identification data.

    On Workbench 2026.1, ``is_distributed`` lives on ``component_identification``
    (``"0"`` / ``"1"`` strings), not as a top-level field.

    Returns:
        ``True`` if distributed, ``False`` if not, ``None`` if unknown.
    """
    for key in (
        "distributed",
        "is_distributed",
        "distribution_status",
        "distribution",
    ):
        if key not in identification:
            continue
        parsed = _coerce_bool(identification.get(key))
        if parsed is not None:
            return parsed
        raw = identification.get(key)
        if isinstance(raw, str):
            lowered = raw.strip().lower()
            if "not" in lowered and "distrib" in lowered:
                return False
            if "distrib" in lowered:
                return True

    record = _component_identification_record(identification)
    if record is not None and "is_distributed" in record:
        return _coerce_bool(record.get("is_distributed"))
    return None


def _has_component_identification(data: Mapping[str, Any]) -> bool:
    """Backward-compatible alias for ``has_identification_record``."""
    return has_identification_record(data)


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


def summarize_identification_state(
    identification: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Summarize identification fields for callers and automation.

    Does not decide readiness to mark identified — callers apply policy.
    """
    record = component_identification_record(identification)
    return {
        "has_identification_record": has_identification_record(identification),
        "has_component_identification": _has_component_identification(
            identification
        ),
        "has_linked_catalog_component": has_linked_catalog_component(
            identification
        ),
        "linked_catalog_components": parse_linked_catalog_components(
            identification
        ),
        "has_file_license": _has_file_license(identification),
        "has_copyright": _has_copyright(identification),
        "is_marked_identified": parse_identifying_done(identification),
        "distribution_status": parse_distribution_status(identification),
        "license_identifiers": parse_license_identifiers(identification),
        "copyright_text": parse_copyright_text(identification),
        "component_record": dict(record) if record is not None else None,
        "raw": dict(identification),
    }
