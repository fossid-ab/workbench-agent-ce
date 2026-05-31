"""
Expected API ``data`` keys for ProjectsClient methods.

Used by payload unit tests to catch drift from ``schema.md``.
"""

from typing import Dict, FrozenSet, Tuple

# method_name -> (required_keys, optional_keys sent only when provided)
PROJECTS_REQUEST_MANIFEST: Dict[str, Tuple[FrozenSet[str], FrozenSet[str]]] = {
    "list_projects": (frozenset(), frozenset()),
    "get_information": (frozenset({"project_code"}), frozenset()),
    "get_all_scans": (frozenset({"project_code"}), frozenset()),
    "create": (
        frozenset({"project_name"}),
        frozenset({
            "product_code",
            "product_name",
            "description",
            "comment",
            "limit_date",
            "jira_project_key",
        }),
    ),
    "update": (
        frozenset({"project_code", "project_name"}),
        frozenset({
            "product_code",
            "product_name",
            "description",
            "comment",
            "limit_date",
            "jira_project_key",
            "new_project_owner",
        }),
    ),
    "check_status": (frozenset({"process_id", "type"}), frozenset()),
}
