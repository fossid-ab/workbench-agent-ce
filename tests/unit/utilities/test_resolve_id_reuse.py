"""Tests for resolve_id_reuse CE utilities."""

import argparse

import pytest

from workbench_agent.api.exceptions import ProjectNotFoundError, ScanNotFoundError
from workbench_agent.utilities.resolve_id_reuse import resolve_id_reuse


@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.project_name = "Test Project"
    params.project_code = None
    params.reuse_any_identification = False
    params.reuse_my_identifications = False
    params.reuse_project_ids = None
    params.reuse_scan_ids = None
    return params


@pytest.fixture
def mock_client(mocker):
    client = mocker.MagicMock()
    client.projects.list_projects.return_value = [
        {"project_name": "SourceProject", "project_code": "PROJ999"},
    ]
    client.projects.get_information.return_value = {"project_code": "PROJ999"}
    client.projects.get_all_scans.return_value = [
        {
            "name": "SourceScan",
            "code": "SCAN999",
            "id": "1",
        }
    ]
    client.scans.get_information.return_value = {
        "id": 1,
        "code": "SCAN999",
        "name": "SourceScan",
    }
    client.scans.list_scans.return_value = [
        {"name": "SourceScan", "code": "SCAN888", "id": "2"},
    ]
    return client


def test_resolve_id_reuse_any(mock_client, mock_params):
    mock_params.reuse_any_identification = True
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("any", None)


def test_resolve_id_reuse_project_by_name(mock_client, mock_params):
    mock_params.reuse_project_ids = "SourceProject"
    mock_client.projects.get_information.side_effect = ProjectNotFoundError("missing")
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("specific_project", "PROJ999")


def test_resolve_id_reuse_project_by_code(mock_client, mock_params):
    mock_params.reuse_project_ids = "PROJ999"
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("specific_project", "PROJ999")
    mock_client.projects.get_information.assert_called_with("PROJ999")


def test_resolve_id_reuse_scan_by_code(mock_client, mock_params):
    mock_params.reuse_scan_ids = "SCAN999"
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("specific_scan", "SCAN999")


def test_resolve_id_reuse_scan_in_project(mock_client, mock_params):
    mock_params.reuse_scan_ids = "SourceScan"
    mock_client.scans.get_information.side_effect = ScanNotFoundError("missing")
    result = resolve_id_reuse(
        mock_client,
        mock_params,
        target_project_code="PROJ123",
    )
    assert result == ("specific_scan", "SCAN999")


def test_resolve_id_reuse_scan_global_fallback(mock_client, mock_params, capsys):
    mock_params.reuse_scan_ids = "SourceScan"
    mock_params.project_name = "Test Project"
    mock_client.scans.get_information.side_effect = ScanNotFoundError("missing")
    mock_client.projects.list_projects.return_value = [
        {"project_name": "Test Project", "project_code": "PROJ123"},
    ]
    mock_client.projects.get_all_scans.return_value = []

    result = resolve_id_reuse(mock_client, mock_params)

    assert result == ("specific_scan", "SCAN888")
    output = capsys.readouterr().out
    assert "Searching globally" in output
