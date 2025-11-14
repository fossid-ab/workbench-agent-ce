"""
Tests for ResolverService - scan compatibility and ID reuse resolution.

These tests were migrated from test_scan_target_validators.py to test
the new ResolverService implementation.
"""
import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.services.resolver_service import ResolverService
from workbench_agent.exceptions import (
    ApiError,
    CompatibilityError,
    NetworkError,
    ProjectNotFoundError,
    ScanNotFoundError,
)


# --- Fixtures ---
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
    client.get_project_scans.return_value = [
        {
            "name": "test_scan",
            "code": "TEST_SCAN",
            "id": "123",
            "project_code": "TEST_PROJECT",
        }
    ]
    client.create_project.return_value = "TEST_PROJECT"
    return client


@pytest.fixture
def mock_scans_client(mocker):
    """Mock ScansClient."""
    client = mocker.MagicMock()
    client.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    return client


@pytest.fixture
def resolver_service(mock_projects_client, mock_scans_client):
    """Create ResolverService instance with mocked clients."""
    return ResolverService(mock_projects_client, mock_scans_client)


@pytest.fixture
def mock_params(mocker):
    """Mock argparse.Namespace with common parameters."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.command = None
    params.project_name = None
    params.scan_name = None
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_commit = None
    params.git_depth = None
    return params


# --- Tests for ensure_scan_compatible ---
def test_ensure_scan_compatible_scan_command_success(
    resolver_service, mock_scans_client, mock_params
):
    """Test successful compatibility check for scan command."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    mock_params.command = "scan"
    # Should not raise
    resolver_service.ensure_scan_compatible("TEST_SCAN", "scan", mock_params)
    mock_scans_client.get_scan_information.assert_called_once_with("TEST_SCAN")


def test_ensure_scan_compatible_scan_git_command_success(
    resolver_service, mock_scans_client, mock_params
):
    """Test successful compatibility check for scan-git command."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None
    # Should not raise
    resolver_service.ensure_scan_compatible("TEST_SCAN", "scan-git", mock_params)
    mock_scans_client.get_scan_information.assert_called_once_with("TEST_SCAN")


def test_ensure_scan_compatible_scan_command_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test incompatible scan for scan command (has git repo)."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.command = "scan"
    with pytest.raises(CompatibilityError, match=r"cannot be reused for code upload"):
        resolver_service.ensure_scan_compatible("TEST_SCAN", "scan", mock_params)


def test_ensure_scan_compatible_scan_git_command_incompatible_url(
    resolver_service, mock_scans_client, mock_params
):
    """Test incompatible scan for scan-git command (different URL)."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.git_url = "https://github.com/example/different.git"
    mock_params.git_branch = "main"
    with pytest.raises(
        CompatibilityError, match=r"configured for a different Git repository"
    ):
        resolver_service.ensure_scan_compatible("TEST_SCAN", "scan-git", mock_params)


def test_ensure_scan_compatible_scan_git_command_incompatible_ref_type(
    resolver_service, mock_scans_client, mock_params
):
    """Test incompatible scan for scan-git command (different ref type)."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_tag = "v1.0.0"
    with pytest.raises(CompatibilityError, match=r"exists with ref type"):
        resolver_service.ensure_scan_compatible("TEST_SCAN", "scan-git", mock_params)


def test_ensure_scan_compatible_scan_not_found(
    resolver_service, mock_scans_client, mock_params
):
    """Test graceful handling when scan is not found."""
    mock_scans_client.get_scan_information.side_effect = ScanNotFoundError(
        "Scan not found"
    )
    # Should NOT raise, just log and return
    resolver_service.ensure_scan_compatible("TEST_SCAN", "scan", mock_params)


def test_ensure_scan_compatible_api_error(
    resolver_service, mock_scans_client, mock_params
):
    """Test graceful handling when API error occurs."""
    mock_scans_client.get_scan_information.side_effect = ApiError("API error")
    # Should NOT raise, just log and return
    resolver_service.ensure_scan_compatible("TEST_SCAN", "scan", mock_params)


def test_ensure_scan_compatible_network_error(
    resolver_service, mock_scans_client, mock_params
):
    """Test graceful handling when network error occurs."""
    mock_scans_client.get_scan_information.side_effect = NetworkError("Network error")
    # Should NOT raise, just log and return
    resolver_service.ensure_scan_compatible("TEST_SCAN", "scan", mock_params)


# --- Tests for import-sbom compatibility ---
def test_ensure_scan_compatible_import_sbom_with_report_scan_compatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that import-sbom can reuse SBOM import scans."""
    mock_scans_client.get_scan_information.return_value = {"is_from_report": "1"}
    # Should not raise
    resolver_service.ensure_scan_compatible("test_scan_code", "import-sbom", mock_params)


def test_ensure_scan_compatible_import_sbom_with_code_scan_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that import-sbom cannot reuse code upload scans."""
    mock_scans_client.get_scan_information.return_value = {
        "is_from_report": "0",
        "git_repo_url": None,
    }
    with pytest.raises(
        CompatibilityError,
        match="was not created for SBOM import and cannot be reused for SBOM import",
    ):
        resolver_service.ensure_scan_compatible(
            "test_scan_code", "import-sbom", mock_params
        )


def test_ensure_scan_compatible_import_sbom_with_git_scan_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that import-sbom cannot reuse git scans."""
    mock_scans_client.get_scan_information.return_value = {
        "is_from_report": "0",
        "git_repo_url": "https://github.com/test/repo.git",
    }
    with pytest.raises(
        CompatibilityError,
        match="was not created for SBOM import and cannot be reused for SBOM import",
    ):
        resolver_service.ensure_scan_compatible(
            "test_scan_code", "import-sbom", mock_params
        )


def test_ensure_scan_compatible_scan_with_report_scan_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that scan command cannot reuse SBOM import scans."""
    mock_scans_client.get_scan_information.return_value = {"is_from_report": "1"}
    with pytest.raises(
        CompatibilityError,
        match="was created for SBOM import and cannot be reused for code upload",
    ):
        resolver_service.ensure_scan_compatible("test_scan_code", "scan", mock_params)


def test_ensure_scan_compatible_scan_git_with_report_scan_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that scan-git command cannot reuse SBOM import scans."""
    mock_scans_client.get_scan_information.return_value = {"is_from_report": "1"}
    mock_params.git_url = "https://github.com/test/repo.git"
    mock_params.git_branch = "main"
    with pytest.raises(
        CompatibilityError,
        match="was created for SBOM import and cannot be reused for Git scanning",
    ):
        resolver_service.ensure_scan_compatible(
            "test_scan_code", "scan-git", mock_params
        )


def test_ensure_scan_compatible_import_da_with_report_scan_incompatible(
    resolver_service, mock_scans_client, mock_params
):
    """Test that import-da cannot reuse SBOM import scans."""
    mock_scans_client.get_scan_information.return_value = {"is_from_report": "1"}
    with pytest.raises(
        CompatibilityError,
        match="was created for SBOM import and cannot be reused for dependency analysis import",
    ):
        resolver_service.ensure_scan_compatible(
            "test_scan_code", "import-da", mock_params
        )


def test_ensure_scan_compatible_blind_scan_command_success(
    resolver_service, mock_scans_client, mock_params
):
    """Test successful compatibility check for blind-scan command."""
    mock_scans_client.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    # Should not raise (blind-scan is treated like scan)
    resolver_service.ensure_scan_compatible("TEST_SCAN", "blind-scan", mock_params)


# --- Tests for resolve_id_reuse ---
def test_resolve_id_reuse_none_when_no_params(resolver_service):
    """Test that resolve_id_reuse returns None, None when no params provided."""
    result = resolver_service.resolve_id_reuse()
    assert result == (None, None)


def test_resolve_id_reuse_any(resolver_service):
    """Test resolve_id_reuse with id_reuse_any=True."""
    result = resolver_service.resolve_id_reuse(id_reuse_any=True)
    assert result == ("any", None)


def test_resolve_id_reuse_my(resolver_service):
    """Test resolve_id_reuse with id_reuse_my=True."""
    result = resolver_service.resolve_id_reuse(id_reuse_my=True)
    assert result == ("only_me", None)


def test_resolve_id_reuse_project_success(
    resolver_service, mock_projects_client
):
    """Test successful project ID reuse resolution."""
    # find_project uses list_projects and looks for project_name match
    mock_projects_client.list_projects.return_value = [
        {"project_name": "test_project", "project_code": "TEST_PROJECT"}
    ]
    result = resolver_service.resolve_id_reuse(
        id_reuse_project_name="test_project"
    )
    assert result == ("specific_project", "TEST_PROJECT")
    mock_projects_client.list_projects.assert_called_once()


def test_resolve_id_reuse_project_not_found(
    resolver_service, mock_projects_client
):
    """Test graceful handling when project not found for ID reuse."""
    mock_projects_client.list_projects.return_value = []
    # Should return None, None (graceful degradation)
    result = resolver_service.resolve_id_reuse(
        id_reuse_project_name="nonexistent_project"
    )
    assert result == (None, None)


def test_resolve_id_reuse_scan_local_success(
    resolver_service, mock_projects_client, mock_scans_client
):
    """Test successful scan ID reuse resolution in current project."""
    # find_scan uses find_project first, then get_project_scans
    mock_projects_client.list_projects.return_value = [
        {"project_name": "test_project", "project_code": "TEST_PROJECT"}
    ]
    mock_projects_client.get_project_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    result = resolver_service.resolve_id_reuse(
        id_reuse_scan_name="test_scan", current_project_name="test_project"
    )
    assert result == ("specific_scan", "TEST_SCAN")
    # Should call list_projects for find_project, then get_project_scans
    assert mock_projects_client.list_projects.called
    assert mock_projects_client.get_project_scans.called


def test_resolve_id_reuse_scan_global_success(
    resolver_service, mock_projects_client, mock_scans_client
):
    """Test successful scan ID reuse resolution via global search."""
    # First tries current project (fails), then tries global
    mock_projects_client.list_projects.return_value = [
        {"project_name": "test_project", "project_code": "TEST_PROJECT"}
    ]
    # First call (current project) - scan not found
    mock_projects_client.get_project_scans.return_value = []
    # Second call (global search) - scan found
    mock_scans_client.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    result = resolver_service.resolve_id_reuse(
        id_reuse_scan_name="test_scan", current_project_name="test_project"
    )
    assert result == ("specific_scan", "TEST_SCAN")
    # Should try current project first, then global
    assert mock_projects_client.get_project_scans.called
    assert mock_scans_client.list_scans.called


def test_resolve_id_reuse_scan_not_found(
    resolver_service, mock_projects_client, mock_scans_client
):
    """Test graceful handling when scan not found for ID reuse."""
    # First tries current project, then global - both fail
    mock_projects_client.list_projects.return_value = [
        {"project_name": "test_project", "project_code": "TEST_PROJECT"}
    ]
    mock_projects_client.get_project_scans.return_value = []
    mock_scans_client.list_scans.return_value = []
    # Should return None, None (graceful degradation)
    result = resolver_service.resolve_id_reuse(
        id_reuse_scan_name="nonexistent_scan",
        current_project_name="test_project",
    )
    assert result == (None, None)
    # Should try both current project and global search
    assert mock_projects_client.get_project_scans.called
    assert mock_scans_client.list_scans.called


def test_resolve_id_reuse_scan_without_current_project(
    resolver_service, mock_scans_client
):
    """Test scan ID reuse resolution without current project (global only)."""
    mock_scans_client.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    result = resolver_service.resolve_id_reuse(id_reuse_scan_name="test_scan")
    assert result == ("specific_scan", "TEST_SCAN")


# --- Tests for find_project (migrated from test_project_scan_resolvers) ---
def test_find_project_existing(resolver_service, mock_projects_client):
    """Test finding an existing project."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"},
        {"project_name": "OtherProject", "project_code": "PROJ456"},
    ]

    result = resolver_service.find_project("TestProject")

    assert result == "PROJ123"
    mock_projects_client.list_projects.assert_called_once()


def test_find_project_not_found(resolver_service, mock_projects_client):
    """Test finding non-existent project raises error."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "OtherProject", "project_code": "PROJ456"}
    ]

    with pytest.raises(ProjectNotFoundError, match="Project 'NonExistent' not found"):
        resolver_service.find_project("NonExistent")


# --- Tests for find_scan (migrated from test_project_scan_resolvers) ---
def test_find_scan_existing_in_project(
    resolver_service, mock_projects_client, mock_scans_client
):
    """Test finding existing scan in specific project."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_project_scans.return_value = [
        {"name": "TestScan", "code": "SCAN456", "id": 789},
        {"name": "OtherScan", "code": "SCAN789", "id": 101},
    ]

    result_code, result_id = resolver_service.find_scan(
        scan_name="TestScan", project_name="TestProject"
    )

    assert result_code == "SCAN456"
    assert result_id == 789
    mock_projects_client.get_project_scans.assert_called_once_with("PROJ123")


def test_find_scan_not_found_in_project(
    resolver_service, mock_projects_client, mock_scans_client
):
    """Test finding non-existent scan in project raises error."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_project_scans.return_value = [
        {"name": "OtherScan", "code": "SCAN789", "id": 101}
    ]

    with pytest.raises(
        ScanNotFoundError,
        match="Scan 'NonExistent' not found in project 'TestProject'"
    ):
        resolver_service.find_scan(
            scan_name="NonExistent", project_name="TestProject"
        )


def test_find_scan_global_search_single_result(
    resolver_service, mock_scans_client
):
    """Test global scan search with single result."""
    mock_scans_client.list_scans.return_value = [
        {
            "name": "GlobalScan",
            "code": "SCAN111",
            "id": 222,
            "project_code": "PROJ123"
        }
    ]

    result_code, result_id = resolver_service.find_scan(
        scan_name="GlobalScan", project_name=None
    )

    assert result_code == "SCAN111"
    assert result_id == 222
    mock_scans_client.list_scans.assert_called_once()


def test_find_scan_global_search_multiple_results(
    resolver_service, mock_scans_client
):
    """Test global scan search with multiple results returns first match."""
    # The implementation returns the first match, not an error
    mock_scans_client.list_scans.return_value = [
        {
            "name": "DupeScan",
            "code": "SCAN111",
            "id": 222,
            "project_code": "PROJ123"
        },
        {
            "name": "DupeScan",
            "code": "SCAN333",
            "id": 444,
            "project_code": "PROJ456"
        },
    ]

    result_code, result_id = resolver_service.find_scan(
        scan_name="DupeScan", project_name=None
    )
    # Should return the first match
    assert result_code == "SCAN111"
    assert result_id == 222


def test_find_scan_global_search_not_found(resolver_service, mock_scans_client):
    """Test global scan search with no results raises error."""
    mock_scans_client.list_scans.return_value = []

    with pytest.raises(
        ScanNotFoundError, match="Scan 'NotFound' not found"
    ):
        resolver_service.find_scan(scan_name="NotFound", project_name=None)


# --- Tests for resolve_project_and_scan (migrated from test_project_scan_resolvers) ---
def test_resolve_project_and_scan_both_exist(
    resolver_service, mock_projects_client, mock_scans_client, mock_params
):
    """Test resolving when both project and scan exist."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_project_scans.return_value = [
        {"name": "TestScan", "code": "SCAN456", "id": 789}
    ]
    mock_params.command = "scan"

    project_code, scan_code, scan_is_new = (
        resolver_service.resolve_project_and_scan(
            "TestProject", "TestScan", mock_params
        )
    )

    assert project_code == "PROJ123"
    assert scan_code == "SCAN456"
    assert scan_is_new is False


def test_resolve_project_and_scan_create_project(
    resolver_service, mock_projects_client, mock_scans_client, mock_params
):
    """Test resolving when project doesn't exist."""
    # First call - project doesn't exist (find_project raises)
    mock_projects_client.list_projects.side_effect = [
        [],  # First call - project doesn't exist
        [{"project_name": "NewProject", "project_code": "PROJ789"}],  # After creation
    ]
    mock_projects_client.create_project.return_value = "PROJ789"
    # Scan doesn't exist initially, then exists after creation
    mock_projects_client.get_project_scans.side_effect = [
        [],  # First call - scan doesn't exist
        [{"name": "NewScan", "code": "SCAN999", "id": 888}],  # After creation
    ]
    mock_scans_client.create_scan.return_value = 888
    mock_params.command = "scan"

    with patch("time.sleep"):  # Mock sleep
        project_code, scan_code, scan_is_new = (
            resolver_service.resolve_project_and_scan(
                "NewProject", "NewScan", mock_params
            )
        )

    assert project_code == "PROJ789"
    assert scan_code == "SCAN999"
    assert scan_is_new is True
    mock_projects_client.create_project.assert_called_once()
    mock_scans_client.create_scan.assert_called_once()


def test_resolve_project_and_scan_create_scan(
    resolver_service, mock_projects_client, mock_scans_client, mock_params
):
    """Test resolving when scan doesn't exist."""
    mock_projects_client.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"}
    ]
    mock_projects_client.get_project_scans.side_effect = [
        [],  # First call - scan doesn't exist
        [{"name": "NewScan", "code": "SCAN999", "id": 888}],  # After creation
    ]
    mock_scans_client.create_scan.return_value = 888
    mock_params.command = "scan"

    with patch("time.sleep"):  # Mock sleep
        project_code, scan_code, scan_is_new = (
            resolver_service.resolve_project_and_scan(
                "TestProject", "NewScan", mock_params
            )
        )

    assert project_code == "PROJ123"
    assert scan_code == "SCAN999"
    assert scan_is_new is True
    mock_scans_client.create_scan.assert_called_once()

