"""Unit tests for PolicyService."""

from unittest.mock import MagicMock

import pytest
import requests

from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.services.policy_service import PolicyService

SAMPLE_PROJECT_WARNINGS = {
    "scans_with_warnings": 2,
    "warnings_counter": 112,
    "scans_list": [
        {"scan_id": 1, "scan_name": "one", "scan_code": "one"},
    ],
}


def _policy_service(scans=None, projects=None, downloads=None):
    return PolicyService(
        scans or MagicMock(),
        projects or MagicMock(),
        downloads or MagicMock(),
    )


SAMPLE_SCAN_POLICY_INFO = {
    "policy_warnings_list": [
        {
            "id": 13,
            "type": "license",
            "findings": 30,
            "license_info": {
                "rule_lic_identifier": "BSD-3-Clause",
            },
        }
    ]
}


def test_get_policy_warnings_delegates_to_scans_client():
    scans = MagicMock()
    projects = MagicMock()
    scans.get_policy_warnings_counter.return_value = {
        "policy_warnings_total": 3,
        "identified_files_with_warnings": 1,
        "dependencies_with_warnings": 2,
    }
    service = _policy_service(scans=scans, projects=projects)

    result = service.get_policy_warnings("SCAN1")

    assert result["policy_warnings_total"] == 3
    scans.get_policy_warnings_counter.assert_called_once_with("SCAN1")
    scans.get_policy_warnings_info.assert_not_called()


def test_get_scan_identification_policy_warnings_info():
    scans = MagicMock()
    projects = MagicMock()
    scans.get_policy_warnings_info.return_value = SAMPLE_SCAN_POLICY_INFO
    service = _policy_service(scans=scans, projects=projects)

    result = service.get_scan_identification_policy_warnings_info("SCAN1")

    assert result == SAMPLE_SCAN_POLICY_INFO
    scans.get_policy_warnings_info.assert_called_once_with("SCAN1", warning_type="identifications")


def test_get_scan_dependency_policy_warnings_info():
    scans = MagicMock()
    projects = MagicMock()
    scans.get_policy_warnings_info.return_value = {"policy_warnings_list": []}
    service = _policy_service(scans=scans, projects=projects)

    service.get_scan_dependency_policy_warnings_info("SCAN1")

    scans.get_policy_warnings_info.assert_called_once_with("SCAN1", warning_type="dependencies")


def test_get_scan_policy_warnings_info_all():
    scans = MagicMock()
    projects = MagicMock()
    scans.get_policy_warnings_info.return_value = SAMPLE_SCAN_POLICY_INFO
    service = _policy_service(scans=scans, projects=projects)

    service.get_scan_policy_warnings_info_all("SCAN1")

    scans.get_policy_warnings_info.assert_called_once_with("SCAN1", warning_type="all")


def test_get_project_identification_policy_warnings():
    scans = MagicMock()
    projects = MagicMock()
    projects.get_policy_warnings_info.return_value = SAMPLE_PROJECT_WARNINGS
    service = _policy_service(scans=scans, projects=projects)

    result = service.get_project_identification_policy_warnings("PRJ1")

    assert result == SAMPLE_PROJECT_WARNINGS
    projects.get_policy_warnings_info.assert_called_once_with(
        "PRJ1", warning_type="identifications"
    )


def test_download_project_policy_json_parses_raw_body():
    downloads = MagicMock()
    raw = MagicMock(spec=requests.Response)
    raw.content = b'[{"id":"MIT","blocked":false,"reason":""}]'
    downloads.get_project_policy.return_value = {"_raw_response": raw}
    service = _policy_service(downloads=downloads)

    result = service.download_project_policy_json("PRJ1")

    assert result == [{"id": "MIT", "blocked": False, "reason": ""}]
    downloads.get_project_policy.assert_called_once_with("PRJ1")


def test_download_project_policy_json_invalid_body_raises():
    downloads = MagicMock()
    raw = MagicMock(spec=requests.Response)
    raw.content = b"not json"
    downloads.get_project_policy.return_value = {"_raw_response": raw}
    service = _policy_service(downloads=downloads)

    with pytest.raises(ApiError, match="Invalid project policy JSON"):
        service.download_project_policy_json("PRJ1")
