"""
Report type registry: scopes, async behavior, capabilities, and version gates.

Used by ReportService and other callers that need capability metadata.
"""

from typing import Any, Dict

# ``capabilities``: which optional generate parameters apply for this type.
REPORT_DEFS: Dict[str, Dict[str, Any]] = {
    "html": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": True,
            "supports_selection_view": True,
            "supports_vex": True,
            "supports_dep_det_info": False,
            "supports_disclaimer": True,
            "supports_report_content_type": True,
        },
    },
    "dynamic_top_matched_components": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": False,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "string_match": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": True,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "file-notices": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": False,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "component-notices": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": False,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "aggregated-notices": {
        "scopes": frozenset({"scan"}),
        "is_async": False,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": False,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "xlsx": {
        "scopes": frozenset({"scan", "project"}),
        "is_async": True,
        "capabilities": {
            "supports_selection_type": True,
            "supports_selection_view": True,
            "supports_vex": True,
            "supports_dep_det_info": True,
            "supports_disclaimer": False,
            "supports_report_content_type": True,
        },
    },
    "spdx": {
        "scopes": frozenset({"scan", "project"}),
        "is_async": True,
        "capabilities": {
            "supports_selection_type": True,
            "supports_selection_view": True,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "spdx_lite": {
        "scopes": frozenset({"scan", "project"}),
        "is_async": True,
        "capabilities": {
            "supports_selection_type": True,
            "supports_selection_view": True,
            "supports_vex": False,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
    "cyclone_dx": {
        "scopes": frozenset({"scan", "project"}),
        "is_async": True,
        "capabilities": {
            "supports_selection_type": False,
            "supports_selection_view": False,
            "supports_vex": True,
            "supports_dep_det_info": False,
            "supports_disclaimer": False,
            "supports_report_content_type": False,
        },
    },
}

ASYNC_REPORT_TYPES: set[str] = {rt for rt, d in REPORT_DEFS.items() if d["is_async"]}

# Notice file reports (scan scope): map CLI name -> API check_status type
NOTICE_REPORT_TYPE_MAP: Dict[str, str] = {
    "file-notices": "NOTICE_EXTRACT_FILE",
    "component-notices": "NOTICE_EXTRACT_COMPONENT",
    "aggregated-notices": "NOTICE_EXTRACT_AGGREGATE",
}
NOTICE_REPORT_TYPES: frozenset[str] = frozenset(NOTICE_REPORT_TYPE_MAP)

# Minimum Workbench version for specific payload fields (API changelog)
MIN_VERSION_FOR_FIELDS: Dict[str, str] = {
    "include_dep_det_info": "25.1.0",
    "include_vex": "24.3.0",
}

# Minimum Workbench version for specific report types
MIN_VERSION_FOR_REPORT_TYPES: Dict[str, str] = {
    "aggregated-notices": "25.1.0",
}

# File extension mapping for saving reports
EXTENSION_MAP: Dict[str, str] = {
    "xlsx": "xlsx",
    "spdx": "rdf",
    "spdx_lite": "xlsx",
    "cyclone_dx": "json",
    "html": "html",
    "dynamic_top_matched_components": "html",
    "string_match": "xlsx",
    "file-notices": "txt",
    "component-notices": "txt",
    "aggregated-notices": "xlsx",
}
