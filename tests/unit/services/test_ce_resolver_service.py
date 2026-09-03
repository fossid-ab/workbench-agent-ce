"""Tests for CE ResolverService."""

import pytest

from workbench_agent.api.exceptions import (
    ApiError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ScanWrongProjectError,
)
from workbench_agent.services.resolver_service import ResolverService
from workbench_agent.services.types import ResolvedTargets


def _scan_row(**overrides):
    row = {
        "name": "test_scan",
        "code": "TEST_SCAN",
        "id": "123",
        "is_from_report": "0",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    row.update(overrides)
    return row


@pytest.fixture
def mock_projects_client(mocker):
    client = mocker.MagicMock()
    client.list_projects.return_value = [
        {
            "name": "test_project",
            "code": "TEST_PROJECT",
            "project_name": "test_project",
            "project_code": "TEST_PROJECT",
        }
    ]
    client.get_all_scans.return_value = [_scan_row()]
    client.create.return_value = "TEST_PROJECT"
    client.get_information.return_value = {"project_code": "PROJ123"}
    return client


@pytest.fixture
def mock_scans_client(mocker):
    client = mocker.MagicMock()
    client.list_scans.return_value = [_scan_row()]
    client.get_information.return_value = {
        "id": 456,
        "code": "SCAN456",
        "name": "TestScan",
    }
    return client


@pytest.fixture
def resolver_service(mock_projects_client, mock_scans_client):
    return ResolverService(mock_projects_client, mock_scans_client)


def test_find_project_existing(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"},
    ]
    assert resolver_service.find_project("TestProject") == "PROJ123"


def test_find_project_not_found(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "OtherProject", "project_code": "PROJ456"}
    ]
    with pytest.raises(ProjectNotFoundError, match="Project 'NonExistent' not found"):
        resolver_service.find_project("NonExistent")


def test_find_project_by_code(resolver_service, mock_projects_client):
    assert resolver_service.find_project(code="PROJ123") == "PROJ123"
    mock_projects_client.get_information.assert_called_once_with("PROJ123")


def test_find_project_and_scan_existing(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="TestScan", code="SCAN456", id=789),
    ]
    project_code = resolver_service.find_project("TestProject")
    scan = resolver_service.find_scan(name="TestScan", project_code=project_code)
    assert project_code == "PROJ123"
    assert scan.code == "SCAN456"


def test_find_scan_by_code_in_project(resolver_service, mock_projects_client):
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="TestScan", code="SCAN456", id=789),
    ]
    scan = resolver_service.find_scan(code="SCAN456", project_code="PROJ123")
    assert scan.code == "SCAN456"


def test_find_scan_wrong_project(resolver_service, mock_projects_client, mock_scans_client):
    mock_projects_client.get_all_scans.return_value = []
    mock_scans_client.get_information.return_value = {
        "id": 1,
        "code": "SCAN456",
        "name": "Scan",
        "project_code": "OTHER_PROJ",
    }
    mock_scans_client.list_scans.return_value = [
        {"code": "SCAN456", "id": "1", "name": "Scan", "project_code": "OTHER_PROJ"},
    ]

    with pytest.raises(ScanWrongProjectError, match="already exists in project 'OTHER_PROJ'"):
        resolver_service.find_scan(code="SCAN456", project_code="PROJ123")


def test_find_or_create_never_creates_when_disabled(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = []
    with pytest.raises(ProjectNotFoundError):
        resolver_service.find_or_create_project(name="Missing", allow_create=False)


def test_resolve_targets_both_exist(resolver_service, mock_projects_client):
    row = _scan_row(name="TestScan", code="SCAN456", id=789)
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [row]
    result = resolver_service.resolve_targets(
        project_name="TestProject",
        scan_name="TestScan",
        scan_data={},
    )
    assert result == ResolvedTargets(
        project_code="PROJ123",
        scan_code="SCAN456",
        project_created=False,
        scan_is_new=False,
        scan_info=row,
    )


def test_create_scan_with_known_code(resolver_service, mock_scans_client):
    mock_scans_client.get_information.return_value = {
        "id": 888,
        "code": "SCAN999",
        "name": "NewScan",
    }
    scan = resolver_service.create_scan(
        "PROJ123",
        "NewScan",
        {},
        scan_code="SCAN999",
    )
    assert scan.code == "SCAN999"
    assert scan.id == 888


def test_create_scan_missing_after_create(resolver_service, mock_projects_client):
    mock_projects_client.get_all_scans.return_value = []
    with pytest.raises(ApiError, match="Failed to retrieve scan 'NewScan' after creation"):
        resolver_service.create_scan("PROJ123", "NewScan", {})


def test_find_or_create_scan_wrong_project_does_not_create(
    resolver_service,
    mock_projects_client,
    mock_scans_client,
):
    mock_projects_client.get_all_scans.return_value = []
    mock_scans_client.get_information.return_value = {
        "id": 1,
        "code": "SCAN456",
        "project_code": "OTHER_PROJ",
    }

    with pytest.raises(ScanWrongProjectError):
        resolver_service.find_or_create_scan(
            "PROJ123",
            code="SCAN456",
            allow_create=True,
        )

    mock_scans_client.create.assert_not_called()


def test_find_or_create_scan_by_code_creates_on_missing(
    resolver_service,
    mock_projects_client,
    mock_scans_client,
):
    mock_projects_client.get_all_scans.return_value = []
    mock_scans_client.create.return_value = 1
    mock_scans_client.get_information.side_effect = [
        ScanNotFoundError("missing"),
        {"id": 42, "code": "NEW_SCAN", "name": "NEW_SCAN"},
    ]

    resolved, created = resolver_service.find_or_create_scan(
        "PROJ123",
        code="NEW_SCAN",
        scan_data={"target_path": "/tmp"},
        allow_create=True,
    )

    assert created is True
    assert resolved.code == "NEW_SCAN"
    mock_scans_client.create.assert_called_once()


def test_find_or_create_scan_by_code_treats_row_not_found_as_missing(
    resolver_service,
    mock_projects_client,
    mock_scans_client,
):
    mock_projects_client.get_all_scans.return_value = []
    mock_scans_client.get_information.side_effect = ApiError(
        "API Error: Classes.TableRepository.row_not_found",
        details={"error": "Classes.TableRepository.row_not_found"},
    )
    mock_scans_client.create.return_value = 1

    def get_information_side_effect(code):
        if mock_scans_client.create.called:
            return {"id": 42, "code": code, "name": code}
        raise ApiError(
            "API Error: Classes.TableRepository.row_not_found",
            details={"error": "Classes.TableRepository.row_not_found"},
        )

    mock_scans_client.get_information.side_effect = get_information_side_effect

    resolved, created = resolver_service.find_or_create_scan(
        "PROJ123",
        code="NEW_SCAN",
        allow_create=True,
    )

    assert created is True
    assert resolved.code == "NEW_SCAN"
    mock_scans_client.create.assert_called_once()


def test_resolve_targets_code_combo(resolver_service, mock_projects_client):
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="Build", code="BUILD_42", id=99),
    ]
    result = resolver_service.resolve_targets(
        project_code="PROJ123",
        scan_code="BUILD_42",
        allow_create=False,
    )
    assert isinstance(result, ResolvedTargets)
    assert result.project_code == "PROJ123"
    assert result.scan_code == "BUILD_42"
