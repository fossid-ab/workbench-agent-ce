"""
Contract specifications for Workbench API responses.

Keys and shapes are refined as live tests validate real server behavior.
"""

from typing import Any, Dict, Set

# operation_id -> contract spec
CONTRACTS: Dict[str, Dict[str, Any]] = {
    "components.list_components": {
        "data_shape": "list_or_dict",
        "item_required_keys": {"id", "name", "version"},
        "count_only_keys": {"count_results"},
    },
    "components.list_by_usage": {
        "data_shape": "dict",
        "required_keys": {"list"},
    },
    "components.get_information": {
        "data_shape": "list_or_dict",
        "item_required_keys": {"id", "name", "version"},
    },
    "components.create": {
        "data_shape": "dict",
        "required_keys": {"component_id"},
    },
    "components.update": {
        "data_shape": "dict",
        "required_keys": {"component_id"},
    },
    "components.delete": {
        "data_shape": "bool",
    },
    "components.get_usage": {
        "data_shape": "dict",
        "required_keys": {"page", "list", "records_total"},
        "list_item_keys": {"scan_code"},
    },
    "components.get_usage_count": {
        "data_shape": "dict",
        "required_keys": {
            "identifications_usage_count",
            "dependency_usage_count",
        },
    },
    "files_and_folders.get_folder_content": {
        "data_shape": "list",
        "item_required_keys": {"id", "text", "is_directory"},
    },
    "files_and_folders.get_folder_content_metrics": {
        "data_shape": "dict",
        "required_keys": {
            "total",
            "pending_identification",
            "identified_files",
            "without_matches",
        },
    },
    "files_and_folders.get_folder_components_ranking": {
        "data_shape": "list_or_bool",
        "item_required_keys": {
            "rownum",
            "artifact",
            "version",
            "amount_per_artifact_version",
            "amount",
            "fcrid",
        },
    },
    "files_and_folders.get_folder_extensions_ranking": {
        "data_shape": "list_or_bool",
        "item_required_keys": {"id", "file_extension", "amount"},
    },
    "files_and_folders.get_identification": {
        "data_shape": "dict",
        "required_keys": set(),
    },
    "files_and_folders.get_fossid_results": {
        "data_shape": "dict",
    },
    "files_and_folders.get_file_comments": {
        "data_shape": "list",
        "item_required_keys": {"id", "comment"},
    },
    "files_and_folders.add_license_identification": {
        "data_shape": "dict",
        "required_keys": {"identification_id"},
    },
    "files_and_folders.get_matched_lines": {
        "data_shape": "dict",
    },
    "files_and_folders.remove_component_identification": {
        "data_shape": "bool",
    },
    "files_and_folders.write_null_data": {
        "data_shape": "null",
    },
    "projects.list_projects": {
        "data_shape": "list",
        "item_required_keys": {"id", "project_code", "project_name"},
    },
    "projects.get_information": {
        "data_shape": "dict",
        "required_keys": {"id", "project_code", "project_name"},
    },
    "projects.get_all_scans": {
        "data_shape": "list",
        "item_required_keys": {"id", "code", "name"},
    },
    "projects.create": {
        "data_shape": "dict",
        "required_keys": {"project_code"},
    },
    "projects.update": {
        "data_shape": "dict",
        "required_keys": {"project_id"},
    },
    "projects.generate_report": {
        "data_shape": "dict",
        "required_keys": {"process_queue_id"},
    },
    "projects.check_status": {
        "data_shape": "dict",
    },
    "users.get_information": {
        "data_shape": "dict",
        "required_keys": {"id", "username"},
    },
    "scans.get_information": {
        "data_shape": "dict",
        "required_keys": {"id", "code", "name"},
    },
    "scans.get_folder_metrics": {
        "data_shape": "dict",
        "required_keys": {
            "total",
            "pending_identification",
            "identified_files",
            "without_matches",
        },
    },
    "scans.get_pending_files": {
        "data_shape": "dict",
    },
    "scans.get_scan_identified_licenses": {
        "data_shape": "list",
        "item_required_keys": {"identifier", "name"},
    },
    "scans.get_scan_identified_components": {
        "data_shape": "list_or_dict",
    },
    "scans.get_dependency_analysis_results": {
        "data_shape": "list",
    },
    "scans.get_policy_warnings_counter": {
        "data_shape": "dict",
        "required_keys": {
            "policy_warnings_total",
            "identified_files_with_warnings",
            "dependencies_with_warnings",
        },
    },
    "scans.create": {
        "data_shape": "dict",
        "required_keys": {"scan_id"},
    },
    "scans.list_scans": {
        "data_shape": "list",
        "item_required_keys": {"id", "code"},
    },
    "scans.delete": {
        "data_shape": "dict",
        "required_keys": {"process_id"},
    },
    "scans.check_status": {
        "data_shape": "dict",
    },
    "users.get_user_permissions_list": {
        "data_shape": "list",
        "item_required_keys": {"id", "code", "group"},
    },
}
