"""Tests for ResolverService lookup and create operations."""

import pytest

from workbench_agent.api.exceptions import (
    ApiError,
    ProjectNotFoundError,
    ScanNotFoundError,
)
from workbench_agent.api.services.resolver_service import (
    ResolutionResult,
    ResolvedScan,
    ResolverService,
)


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
    """Mock ProjectsClient."""
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
    return client


@pytest.fixture
def mock_scans_client(mocker):
    """Mock ScansClient."""
    client = mocker.MagicMock()
    client.list_scans.return_value = [_scan_row()]
    return client


@pytest.fixture
def resolver_service(mock_projects_client, mock_scans_client):
    """Create ResolverService instance with mocked clients."""
    return ResolverService(mock_projects_client, mock_scans_client)


def test_find_project_existing(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"},
        {"project_name": "OtherProject", "project_code": "PROJ456"},
    ]

    result = resolver_service.find_project("TestProject")

    assert result == "PROJ123"
    mock_projects_client.list_projects.assert_called_once()


def test_find_project_not_found(resolver_service, mock_projects_client):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "OtherProject", "project_code": "PROJ456"}
    ]

    with pytest.raises(
        ProjectNotFoundError, match="Project 'NonExistent' not found"
    ):
        resolver_service.find_project("NonExistent")


def test_find_project_and_scan_existing(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="TestScan", code="SCAN456", id=789),
        _scan_row(name="OtherScan", code="SCAN789", id=101),
    ]

    pc, scan = resolver_service.find_project_and_scan(
        "TestProject", "TestScan"
    )

    assert pc == "PROJ123"
    assert scan == ResolvedScan(code="SCAN456", id=789, info=scan.info)
    assert scan.info["name"] == "TestScan"
    mock_projects_client.list_projects.assert_called_once()
    mock_projects_client.get_all_scans.assert_called_once_with("PROJ123")


def test_find_project_and_scan_not_found_in_project(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="OtherScan", code="SCAN789", id=101),
    ]

    with pytest.raises(
        ScanNotFoundError,
        match="Scan 'NonExistent' not found in project 'TestProject'",
    ):
        resolver_service.find_project_and_scan("TestProject", "NonExistent")


def test_find_project_and_scan_single_list_projects(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [
        _scan_row(name="TestScan", code="SCAN456", id=789),
    ]

    pc, scan = resolver_service.find_project_and_scan(
        "TestProject", "TestScan"
    )

    assert pc == "PROJ123"
    assert scan.code == "SCAN456"
    assert scan.id == 789
    mock_projects_client.list_projects.assert_called_once()
    mock_projects_client.get_all_scans.assert_called_once_with("PROJ123")


def test_find_scan_globally_single_result(resolver_service, mock_scans_client):
    mock_scans_client.list_scans.return_value = [
        _scan_row(
            name="GlobalScan",
            code="SCAN111",
            id=222,
            project_code="PROJ123",
        )
    ]

    scan = resolver_service.find_scan_globally("GlobalScan")

    assert scan.code == "SCAN111"
    assert scan.id == 222
    mock_scans_client.list_scans.assert_called_once()


def test_find_scan_globally_multiple_results(
    resolver_service, mock_scans_client
):
    mock_scans_client.list_scans.return_value = [
        _scan_row(
            name="DupeScan",
            code="SCAN111",
            id=222,
            project_code="PROJ123",
        ),
        _scan_row(
            name="DupeScan",
            code="SCAN333",
            id=444,
            project_code="PROJ456",
        ),
    ]

    scan = resolver_service.find_scan_globally("DupeScan")
    assert scan.code == "SCAN111"
    assert scan.id == 222


def test_find_scan_globally_not_found(resolver_service, mock_scans_client):
    mock_scans_client.list_scans.return_value = []

    with pytest.raises(
        ScanNotFoundError, match="Scan 'NotFound' not found"
    ):
        resolver_service.find_scan_globally("NotFound")


def test_create_scan_success(
    resolver_service, mock_projects_client, mock_scans_client
):
    row = _scan_row(name="NewScan", code="SCAN999", id=888)
    mock_projects_client.get_all_scans.return_value = [row]

    scan = resolver_service.create_scan(
        "PROJ123",
        "NewScan",
        {"description": "test scan", "git_repo_url": "https://example.com"},
    )

    assert scan.code == "SCAN999"
    assert scan.id == 888
    assert scan.info == row
    mock_scans_client.create.assert_called_once_with(
        {
            "project_code": "PROJ123",
            "scan_name": "NewScan",
            "description": "test scan",
            "git_repo_url": "https://example.com",
        }
    )


def test_create_scan_missing_after_create(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.get_all_scans.return_value = []

    with pytest.raises(
        ApiError, match="Failed to retrieve scan 'NewScan' after creation"
    ):
        resolver_service.create_scan("PROJ123", "NewScan", {})


def test_find_or_create_both_exist(
    resolver_service, mock_projects_client, mock_scans_client
):
    row = _scan_row(name="TestScan", code="SCAN456", id=789)
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.return_value = [row]

    result = resolver_service.find_or_create(
        "TestProject", "TestScan", scan_data={}
    )

    assert result == ResolutionResult(
        project_code="PROJ123",
        scan_code="SCAN456",
        project_created=False,
        scan_is_new=False,
        scan_info=row,
    )


def test_find_or_create_create_project(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.list_projects.return_value = []
    mock_projects_client.create.return_value = "PROJ789"
    mock_projects_client.get_all_scans.side_effect = [
        [],
        [_scan_row(name="NewScan", code="SCAN999", id=888)],
    ]

    result = resolver_service.find_or_create(
        "NewProject", "NewScan", scan_data={"description": "x"}
    )

    assert result.project_code == "PROJ789"
    assert result.scan_code == "SCAN999"
    assert result.project_created is True
    assert result.scan_is_new is True
    assert result.scan_info is None
    mock_projects_client.create.assert_called_once()
    mock_scans_client.create.assert_called_once()


def test_find_or_create_create_scan(
    resolver_service, mock_projects_client, mock_scans_client
):
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_all_scans.side_effect = [
        [],
        [_scan_row(name="NewScan", code="SCAN999", id=888)],
    ]

    result = resolver_service.find_or_create(
        "TestProject", "NewScan", scan_data={}
    )

    assert result.project_code == "PROJ123"
    assert result.scan_code == "SCAN999"
    assert result.project_created is False
    assert result.scan_is_new is True
    assert result.scan_info is None
    mock_scans_client.create.assert_called_once()
