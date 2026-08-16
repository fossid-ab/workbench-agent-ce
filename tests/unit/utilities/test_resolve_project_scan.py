"""Tests for resolve_project_scan CE utilities."""

import argparse

import pytest

from workbench_agent.api.exceptions import (
    CompatibilityError,
    ScanNotFoundError,
)
from workbench_agent.api.services.resolver_service import ResolvedScan
from workbench_agent.api.utils.scan_type import (
    ScanReuseIssue,
    ScanReuseIssueCode,
    ScanType,
)
from workbench_agent.utilities.resolve_project_scan import (
    _build_scan_create_data,
    find_or_create_project_and_scan,
    format_reuse_issue,
)


def _scan_info(**overrides):
    info = {
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
        "is_from_report": "0",
    }
    info.update(overrides)
    return info


@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.project_name = "TestProject"
    params.scan_name = "TestScan"
    params.command = "scan"
    params.description = None
    params.target_path = "/tmp/src"
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_commit = None
    params.git_depth = None
    return params


@pytest.fixture
def mock_client(mocker):
    client = mocker.MagicMock()
    client.resolver.find_project.return_value = "PROJ123"
    client.resolver.find_scan.return_value = ResolvedScan(
        code="SCAN456",
        id=789,
        info=_scan_info(),
    )
    return client


def test_build_scan_create_data_path_upload(mock_params):
    data = _build_scan_create_data(mock_params)
    assert data == {"target_path": "/tmp/src"}


def test_build_scan_create_data_git(mock_params):
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_branch = "main"
    data = _build_scan_create_data(mock_params)
    assert data["git_repo_url"] == "https://github.com/example/repo.git"
    assert data["git_branch"] == "main"
    assert data["git_ref_type"] == "branch"


def test_build_scan_create_data_sbom_import(mock_params):
    data = _build_scan_create_data(mock_params, import_from_report=True)
    assert data["import_from_report"] == "1"


def test_format_reuse_issue_upload_vs_git():
    issue = ScanReuseIssue(
        code=ScanReuseIssueCode.TYPE_MISMATCH,
        actual=ScanType.GIT,
        required=ScanType.UPLOAD,
        details={"git_repo": "https://github.com/example/repo.git"},
    )
    message = format_reuse_issue(issue, "SCAN1", "scan")
    assert "cannot be reused for code upload" in message
    assert "https://github.com/example/repo.git" in message


def test_find_or_create_existing_scan(mock_client, mock_params, capsys):
    project_code, scan_code, scan_is_new = find_or_create_project_and_scan(mock_client, mock_params)

    assert project_code == "PROJ123"
    assert scan_code == "SCAN456"
    assert scan_is_new is False
    mock_client.resolver.find_project.assert_called_once_with("TestProject")
    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Found existing Project and Scan" in output


def test_find_or_create_new_scan(mock_client, mock_params, capsys):
    mock_client.resolver.find_scan.side_effect = ScanNotFoundError("missing")
    mock_client.resolver.create_scan.return_value = ResolvedScan(
        code="SCAN999",
        id=888,
        info=_scan_info(),
    )

    project_code, scan_code, scan_is_new = find_or_create_project_and_scan(mock_client, mock_params)

    assert scan_is_new is True
    assert scan_code == "SCAN999"
    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Created New Scan in Existing Project" in output


def test_find_or_create_incompatible_scan(mock_client, mock_params, capsys):
    mock_client.resolver.find_scan.return_value = ResolvedScan(
        code="SCAN456",
        id=789,
        info=_scan_info(
            git_repo_url="https://github.com/example/repo.git",
            git_branch="main",
            git_ref_type="branch",
        ),
    )

    with pytest.raises(CompatibilityError, match="cannot be reused for code upload"):
        find_or_create_project_and_scan(mock_client, mock_params)

    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Incompatible scan usage detected" in output
