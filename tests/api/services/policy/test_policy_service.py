"""Unit tests for PolicyService."""

from unittest.mock import MagicMock

from workbench_agent.api.services.policy_service import PolicyService

SAMPLE_PROJECT_WARNINGS = {
    "scans_with_warnings": 2,
    "warnings_counter": 112,
    "scans_list": [
        {"id": 1, "scan_name": "one", "scan_code": "one"},
        {"id": 2, "scan_name": "two", "scan_code": "two"},
    ],
}


def test_get_policy_warnings_delegates_to_scans_client():
    scans = MagicMock()
    projects = MagicMock()
    scans.get_policy_warnings_counter.return_value = {
        "policy_warnings_total": 3,
        "identified_files_with_warnings": 1,
        "dependencies_with_warnings": 2,
    }
    service = PolicyService(scans, projects)

    result = service.get_policy_warnings("SCAN1")

    assert result["policy_warnings_total"] == 3
    scans.get_policy_warnings_counter.assert_called_once_with("SCAN1")
    projects.get_policy_warnings_info.assert_not_called()


def test_get_project_identification_policy_warnings():
    scans = MagicMock()
    projects = MagicMock()
    projects.get_policy_warnings_info.return_value = SAMPLE_PROJECT_WARNINGS
    service = PolicyService(scans, projects)

    result = service.get_project_identification_policy_warnings("PRJ1")

    assert result == SAMPLE_PROJECT_WARNINGS
    projects.get_policy_warnings_info.assert_called_once_with(
        "PRJ1", warning_type="identifications"
    )


def test_get_project_dependency_policy_warnings():
    scans = MagicMock()
    projects = MagicMock()
    projects.get_policy_warnings_info.return_value = SAMPLE_PROJECT_WARNINGS
    service = PolicyService(scans, projects)

    service.get_project_dependency_policy_warnings("PRJ1")

    projects.get_policy_warnings_info.assert_called_once_with(
        "PRJ1", warning_type="dependencies"
    )


def test_get_project_policy_warnings_all():
    scans = MagicMock()
    projects = MagicMock()
    projects.get_policy_warnings_info.return_value = SAMPLE_PROJECT_WARNINGS
    service = PolicyService(scans, projects)

    service.get_project_policy_warnings_all("PRJ1")

    projects.get_policy_warnings_info.assert_called_once_with(
        "PRJ1", warning_type="all"
    )
