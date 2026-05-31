"""Unit tests: ProjectsClient error handling."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.projects import ProjectsClient
from workbench_agent.api.clients.projects.errors import is_project_not_found
from workbench_agent.api.exceptions import ApiError, ProjectNotFoundError
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

ERROR_RESPONSE = {
    "status": "0",
    "error": "Project does not exist",
    "operation": "projects_get_information",
}


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
@pytest.mark.parametrize(
    "method_name,call_args",
    [
        ("list_projects", ()),
        (
            "create",
            ("New Project",),
        ),
        (
            "update",
            ("PROJ_X", "Renamed"),
        ),
        (
            "generate_report",
            (
                {
                    "project_code": "PROJ_X",
                    "report_type": "xlsx",
                    "async": "1",
                },
            ),
        ),
        ("check_status", (99, "REPORT_GENERATION")),
    ],
)
def test_methods_raise_api_error_on_status_zero(
    mock_send, projects_client, method_name, call_args
):
    mock_send.return_value = ERROR_RESPONSE
    method = getattr(projects_client, method_name)
    err = assert_api_error(lambda: method(*call_args))
    assert_api_error_details_status_zero(err)


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "error_msg",
    [
        "Project does not exist",
        "Project code does not exist",
        "row_not_found in query",
    ],
)
def test_get_information_raises_project_not_found(
    mock_send, projects_client, error_msg
):
    mock_send.return_value = {"status": "0", "error": error_msg}
    with pytest.raises(ProjectNotFoundError, match="PROJ_X"):
        projects_client.get_information("PROJ_X")


@patch.object(BaseAPI, "_send_request")
def test_get_information_raises_api_error_for_other_failures(
    mock_send, projects_client
):
    mock_send.return_value = {"status": "0", "error": "Permission denied"}
    err = assert_api_error(
        lambda: projects_client.get_information("PROJ_X"),
        message_contains="Permission denied",
    )
    assert_api_error_details_status_zero(err)


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "error_msg",
    [
        "Project does not exist",
        "Project code does not exist",
        "row_not_found",
    ],
)
def test_get_all_scans_returns_empty_when_project_not_found(
    mock_send, projects_client, error_msg
):
    mock_send.return_value = {"status": "0", "error": error_msg}
    assert projects_client.get_all_scans("PROJ_X") == []


@patch.object(BaseAPI, "_send_request")
def test_get_all_scans_raises_api_error_for_other_failures(
    mock_send, projects_client
):
    mock_send.return_value = {"status": "0", "error": "Internal server error"}
    err = assert_api_error(
        lambda: projects_client.get_all_scans("PROJ_X"),
        message_contains="Internal server error",
    )
    assert_api_error_details_status_zero(err)


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "error_msg",
    [
        "Project does not exist",
        "Handler.Projects.Update.project_does_not_exist",
        "row_not_found",
    ],
)
def test_update_raises_project_not_found(mock_send, projects_client, error_msg):
    mock_send.return_value = {"status": "0", "error": error_msg}
    with pytest.raises(ProjectNotFoundError, match="PROJ_X"):
        projects_client.update("PROJ_X", "Renamed")


@patch.object(BaseAPI, "_send_request")
def test_generate_report_raises_project_not_found(mock_send, projects_client):
    mock_send.return_value = {"status": "0", "error": "Project does not exist"}
    with pytest.raises(ProjectNotFoundError):
        projects_client.generate_report(
            {
                "project_code": "PROJ_X",
                "report_type": "xlsx",
                "async": "1",
            }
        )


@patch.object(BaseAPI, "_send_request")
def test_list_projects_non_list_data_returns_empty(mock_send, projects_client):
    """When data is not a list, client returns [] (logs warning)."""
    mock_send.return_value = {"status": "1", "data": "not-a-list"}
    assert projects_client.list_projects() == []


@pytest.mark.parametrize(
    "message",
    [
        "Project does not exist",
        "Project code does not exist",
        "Handler.Projects.Update.project_does_not_exist",
        "row_not_found in table",
    ],
)
def test_is_project_not_found_helper(message):
    assert is_project_not_found(message)
    assert not is_project_not_found("")
