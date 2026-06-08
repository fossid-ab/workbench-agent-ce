"""Tests for resolve_id_reuse CE utilities."""

import argparse

import pytest

from workbench_agent.api.exceptions import ScanNotFoundError
from workbench_agent.api.services.resolver_service import ResolvedScan
from workbench_agent.utilities.resolve_id_reuse import resolve_id_reuse


@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.project_name = "Test Project"
    params.reuse_any_identification = False
    params.reuse_my_identifications = False
    params.reuse_project_ids = None
    params.reuse_scan_ids = None
    return params


@pytest.fixture
def mock_client(mocker):
    return mocker.MagicMock()


def test_resolve_id_reuse_any(mock_client, mock_params):
    mock_params.reuse_any_identification = True
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("any", None)


def test_resolve_id_reuse_project(mock_client, mock_params):
    mock_params.reuse_project_ids = "SourceProject"
    mock_client.resolver.find_project.return_value = "PROJ999"
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("specific_project", "PROJ999")


def test_resolve_id_reuse_scan_in_project(mock_client, mock_params):
    mock_params.reuse_scan_ids = "SourceScan"
    mock_client.resolver.find_scan.return_value = ResolvedScan(
        code="SCAN999", id=1, info={}
    )
    result = resolve_id_reuse(mock_client, mock_params)
    assert result == ("specific_scan", "SCAN999")


def test_resolve_id_reuse_scan_global_fallback(
    mock_client, mock_params, capsys
):
    mock_params.reuse_scan_ids = "SourceScan"
    mock_client.resolver.find_scan.side_effect = ScanNotFoundError("missing")
    mock_client.resolver.find_scan_globally.return_value = ResolvedScan(
        code="SCAN888", id=2, info={}
    )

    result = resolve_id_reuse(mock_client, mock_params)

    assert result == ("specific_scan", "SCAN888")
    output = capsys.readouterr().out
    assert "Searching globally" in output
    mock_client.resolver.find_scan_globally.assert_called_once_with(
        "SourceScan"
    )
