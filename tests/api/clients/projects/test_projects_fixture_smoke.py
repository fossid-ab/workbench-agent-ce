"""Unit smoke tests using recorded Workbench 2026.1.0 project response fixtures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.projects import ProjectsClient
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.contract import assert_contract, assert_data_contract
from tests.api.support.version_contracts import load_fixture

WORKBENCH_VERSION = "2026.1.0"


@pytest.fixture
def projects_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return ProjectsClient(api)


@patch.object(BaseAPI, "_send_request")
def test_list_projects_matches_fixture(mock_send, projects_client):
    fixture = load_fixture(WORKBENCH_VERSION, "projects_list_projects")
    mock_send.return_value = fixture
    data = projects_client.list_projects()
    assert len(data) >= 1
    assert_contract(
        "projects.list_projects",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )


@patch.object(BaseAPI, "_send_request")
def test_get_information_matches_fixture(mock_send, projects_client):
    fixture = load_fixture(WORKBENCH_VERSION, "projects_get_information")
    mock_send.return_value = fixture
    data = projects_client.get_information("Test_Project_723")
    assert_data_contract(
        "projects.get_information",
        data,
        workbench_version=WORKBENCH_VERSION,
    )


@patch.object(BaseAPI, "_send_request")
def test_get_all_scans_matches_fixture(mock_send, projects_client):
    fixture = load_fixture(WORKBENCH_VERSION, "projects_get_all_scans")
    mock_send.return_value = fixture
    data = projects_client.get_all_scans("Test_Project_723")
    assert_data_contract(
        "projects.get_all_scans",
        data,
        workbench_version=WORKBENCH_VERSION,
    )
