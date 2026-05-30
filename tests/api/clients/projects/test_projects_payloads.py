"""Unit tests: ProjectsClient request payloads match schema manifest."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.projects import ProjectsClient
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.projects_request_manifest import (
    PROJECTS_REQUEST_MANIFEST,
)


@pytest.fixture
def projects_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return ProjectsClient(api)


def _data_from_call(mock_send) -> dict:
    return mock_send.call_args[0][0]["data"]


@patch.object(BaseAPI, "_send_request")
def test_list_projects_sends_empty_data(mock_send, projects_client):
    mock_send.return_value = {"status": "1", "data": []}
    projects_client.list_projects()
    assert _data_from_call(mock_send) == {}


@patch.object(BaseAPI, "_send_request")
def test_get_information_payload(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"project_code": "P1"},
    }
    projects_client.get_information("P1")
    data = _data_from_call(mock_send)
    required, _optional = PROJECTS_REQUEST_MANIFEST["get_information"]
    assert required <= data.keys()
    assert data["project_code"] == "P1"


@patch.object(BaseAPI, "_send_request")
def test_get_all_scans_payload(mock_send, projects_client):
    mock_send.return_value = {"status": "1", "data": []}
    projects_client.get_all_scans("PROJ_A")
    data = _data_from_call(mock_send)
    assert data["project_code"] == "PROJ_A"


@patch.object(BaseAPI, "_send_request")
def test_create_required_and_optional_fields(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"project_code": "NEW"},
    }
    projects_client.create(
        "My Project",
        product_code="PC",
        limit_date="2025-12-31",
    )
    data = _data_from_call(mock_send)
    required, optional = PROJECTS_REQUEST_MANIFEST["create"]
    assert required <= data.keys()
    assert set(data.keys()) == required | {"product_code", "limit_date"}
    assert data["product_code"] == "PC"
    assert data["limit_date"] == "2025-12-31"
    assert "comment" not in data


@patch.object(BaseAPI, "_send_request")
def test_update_optional_fields_only_when_set(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"project_id": "1"},
    }
    projects_client.update("P1", "Renamed", comment="note")
    data = _data_from_call(mock_send)
    required, _optional = PROJECTS_REQUEST_MANIFEST["update"]
    assert required <= data.keys()
    assert data["comment"] == "note"
    assert "new_project_owner" not in data


@patch.object(BaseAPI, "_send_request")
def test_check_status_coerces_process_id_to_string(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"status": "FINISHED"},
    }
    projects_client.check_status(12345, "REPORT_GENERATION")
    data = _data_from_call(mock_send)
    assert data["process_id"] == "12345"
    assert data["type"] == "REPORT_GENERATION"


@patch.object(BaseAPI, "_send_request")
def test_generate_report_passes_payload_through(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"process_queue_id": 99},
    }
    payload = {
        "project_code": "P1",
        "report_type": "xlsx",
        "async": "1",
        "selection_type": "include_all_licenses",
    }
    projects_client.generate_report(payload)
    assert _data_from_call(mock_send) == payload
