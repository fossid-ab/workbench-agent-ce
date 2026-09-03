"""Tests for resolve_project_scan CE utilities."""

import argparse

import pytest

from workbench_agent.api.exceptions import (
    CompatibilityError,
    ScanNotFoundError,
)
from workbench_agent.services.types import ResolvedScan
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


def _scan_row(**overrides):
    row = {
        "name": "TestScan",
        "code": "SCAN456",
        "id": "789",
        "is_from_report": "0",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None,
    }
    row.update(overrides)
    return row


@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.project_name = "TestProject"
    params.project_code = None
    params.scan_name = "TestScan"
    params.scan_code = None
    params.command = "scan"
    params.description = None
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_commit = None
    params.git_depth = None
    return params


@pytest.fixture
def mock_client(mocker):
    client = mocker.MagicMock()
    client.projects.list_projects.return_value = [
        {"project_name": "TestProject", "project_code": "PROJ123"},
    ]
    client.projects.get_all_scans.return_value = [_scan_row()]
    client.projects.create.return_value = "PROJ123"
    client.scans.create.return_value = 1
    client.scans.get_information.return_value = {"id": 888, "code": "SCAN999"}
    return client


def test_build_scan_create_data_empty(mock_params):
    data = _build_scan_create_data(mock_params)
    assert data == {}


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
    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Found existing Project and Scan" in output


def test_find_or_create_new_scan(mock_client, mock_params, capsys):
    mock_client.projects.get_all_scans.side_effect = [
        [],
        [_scan_row(name="TestScan", code="SCAN999", id=888)],
    ]

    project_code, scan_code, scan_is_new = find_or_create_project_and_scan(mock_client, mock_params)

    assert scan_is_new is True
    assert scan_code == "SCAN999"
    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Created New Scan in Existing Project" in output


def test_find_or_create_incompatible_scan(mock_client, mock_params, capsys):
    mock_client.projects.get_all_scans.return_value = [
        _scan_row(
            git_repo_url="https://github.com/example/repo.git",
            git_branch="main",
            git_ref_type="branch",
        ),
    ]

    with pytest.raises(CompatibilityError, match="cannot be reused for code upload"):
        find_or_create_project_and_scan(mock_client, mock_params)

    mock_client.scans.get_information.assert_not_called()
    output = capsys.readouterr().out
    assert "Incompatible scan usage detected" in output
