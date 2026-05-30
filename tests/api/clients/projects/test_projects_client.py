# tests/unit/api/clients/test_projects_client.py

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import from the new client structure
from workbench_agent.api.clients.projects import ProjectsClient
from workbench_agent.api.exceptions import ApiError, ProjectNotFoundError
from workbench_agent.api.helpers.base_api import BaseAPI


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def base_api(mock_session):
    """Create a BaseAPI instance with a properly mocked session."""
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return api


@pytest.fixture
def projects_client(base_api):
    """Create a ProjectsClient instance with a properly mocked BaseAPI."""
    return ProjectsClient(base_api)


# --- Test Cases ---


# --- Test create ---
@patch.object(BaseAPI, "_send_request")
def test_create_success(mock_send, projects_client):
    # Configure the API response for project creation
    mock_send.return_value = {
        "status": "1",
        "data": {"project_code": "NEW_PROJ"},
    }

    result = projects_client.create("New Project")

    # Verify the result
    assert result == "NEW_PROJ"

    # Verify _send_request was called with correct parameters
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "create"
    assert payload["data"]["project_name"] == "New Project"


# --- Test list_projects ---
@patch.object(BaseAPI, "_send_request")
def test_list_projects_success(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {"name": "Project A", "code": "PROJ_A"},
            {"name": "Project B", "code": "PROJ_B"},
        ],
    }
    projects = projects_client.list_projects()
    assert len(projects) == 2
    assert projects[0]["name"] == "Project A"
    assert projects[1]["code"] == "PROJ_B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "list_projects"


@patch.object(BaseAPI, "_send_request")
def test_list_projects_empty(mock_send, projects_client):
    mock_send.return_value = {"status": "1", "data": []}
    projects = projects_client.list_projects()
    assert projects == []


@patch.object(BaseAPI, "_send_request")
def test_list_projects_api_error(mock_send, projects_client):
    mock_send.return_value = {"status": "0", "error": "API error"}
    with pytest.raises(
        ApiError, match="Failed to list projects: API error"
    ):
        projects_client.list_projects()


# --- Test get_all_scans ---
@patch.object(BaseAPI, "_send_request")
def test_get_all_scans_success(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {"code": "SCAN_A", "name": "Scan A"},
            {"code": "SCAN_B", "name": "Scan B"},
        ],
    }
    scans = projects_client.get_all_scans("PROJ_A")
    assert len(scans) == 2
    assert scans[0]["code"] == "SCAN_A"
    assert scans[1]["name"] == "Scan B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "get_all_scans"
    assert payload["data"]["project_code"] == "PROJ_A"


@patch.object(BaseAPI, "_send_request")
def test_get_all_scans_project_not_found(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "Project code does not exist",
    }
    scans = projects_client.get_all_scans("NONEXISTENT")
    assert scans == []


# --- Test get_information ---
@patch.object(BaseAPI, "_send_request")
def test_get_information_success(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"project_code": "PROJ_A", "project_name": "Project A"},
    }
    info = projects_client.get_information("PROJ_A")
    assert info["project_code"] == "PROJ_A"
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "get_information"


@patch.object(BaseAPI, "_send_request")
def test_get_information_project_not_found(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "Project does not exist",
    }
    with pytest.raises(ProjectNotFoundError, match="PROJ_X"):
        projects_client.get_information("PROJ_X")


@patch.object(BaseAPI, "_send_request")
def test_create_missing_project_code_in_response(mock_send, projects_client):
    mock_send.return_value = {"status": "1", "data": {}}
    with pytest.raises(ApiError, match="no code returned"):
        projects_client.create("New Project")


@patch.object(BaseAPI, "_send_request")
def test_create_invalid_limit_date(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [
            {
                "code": "RequestData.Base.field_contains_not_valid_date_string",
                "message_parameters": {"fieldname": "limit_date"},
            }
        ],
    }
    with pytest.raises(ApiError, match="Invalid date format"):
        projects_client.create("New Project", limit_date="not-a-date")


@patch.object(BaseAPI, "_send_request")
def test_update_project_not_found(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "Project does not exist",
    }
    with pytest.raises(ProjectNotFoundError):
        projects_client.update("PROJ_X", "Renamed")


@patch.object(BaseAPI, "_send_request")
def test_update_invalid_limit_date(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [
            {
                "code": "RequestData.Base.field_contains_not_valid_date_string",
                "message_parameters": {"fieldname": "limit_date"},
            }
        ],
    }
    with pytest.raises(ApiError, match="Invalid date format"):
        projects_client.update(
            "PROJ_A", "Project A", limit_date="not-a-date"
        )


@patch.object(BaseAPI, "_send_request")
def test_generate_report_project_not_found(mock_send, projects_client):
    mock_send.return_value = {
        "status": "0",
        "error": "Project does not exist",
    }
    with pytest.raises(ProjectNotFoundError):
        projects_client.generate_report(
            {
                "project_code": "PROJ_X",
                "report_type": "xlsx",
                "async": "1",
            }
        )


@patch.object(BaseAPI, "_send_request")
def test_generate_report_missing_process_queue_id(mock_send, projects_client):
    mock_send.return_value = {"status": "1", "data": {}}
    with pytest.raises(ApiError, match="Unexpected response"):
        projects_client.generate_report(
            {
                "project_code": "PROJ_A",
                "report_type": "xlsx",
                "async": "1",
            }
        )


@patch.object(BaseAPI, "_send_request")
def test_check_status_failure(mock_send, projects_client):
    mock_send.return_value = {"status": "0", "error": "Process not found"}
    with pytest.raises(ApiError, match="Process not found"):
        projects_client.check_status(99, "REPORT_GENERATION")


# --- Test project report generation ---
@patch.object(BaseAPI, "_send_request")
def test_generate_project_report_success(mock_send, projects_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"process_queue_id": 54321},
    }
    payload_data = {
        "project_code": "PROJ_A",
        "report_type": "xlsx",
        "async": "1",
        "selection_type": "include_all_licenses",
        "disclaimer": "Test disclaimer",
        "include_vex": False,
    }
    result = projects_client.generate_report(payload_data)
    assert result == 54321
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "generate_report"
    assert payload["data"]["project_code"] == "PROJ_A"
    assert payload["data"]["report_type"] == "xlsx"
    assert payload["data"]["async"] == "1"
    assert payload["data"]["selection_type"] == "include_all_licenses"
    assert payload["data"]["disclaimer"] == "Test disclaimer"
    assert payload["data"]["include_vex"] is False


@patch.object(BaseAPI, "_send_request")
def test_check_status_success(mock_send, projects_client):
    """Test successful project operation status check."""
    mock_send.return_value = {
        "status": "1",
        "data": {"status": "FINISHED", "progress": 100},
    }
    status = projects_client.check_status(
        process_id=12345, process_type="REPORT_GENERATION"
    )
    assert status["status"] == "FINISHED"
    assert status["progress"] == 100
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "projects"
    assert payload["action"] == "check_status"
    assert payload["data"]["process_id"] == "12345"
    assert payload["data"]["type"] == "REPORT_GENERATION"


# Note: download_report method moved to ReportService in the new architecture
# The old test tested ProjectsAPI.download_report() which no longer exists
# Report downloads are now handled by ReportService.download_project_report()
# This functionality is tested in test_report_service.py
