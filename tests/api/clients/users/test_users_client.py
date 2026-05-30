# tests/unit/api/clients/users/test_users_client.py

from unittest.mock import patch

import pytest
import requests

from workbench_agent.api.clients.users import UsersClient
from workbench_agent.api.clients.users.errors import (
    is_user_not_found,
    normalize_permissions_list_data,
)
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI


@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def base_api(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return api


@pytest.fixture
def users_client(base_api):
    return UsersClient(base_api)


@patch.object(BaseAPI, "_send_request")
def test_get_information_success(mock_send, users_client):
    mock_send.return_value = {
        "operation": "users_get_information",
        "status": "1",
        "data": {
            "id": 3,
            "username": "tomas.gonzalez@fossid.com",
            "name": "Tomas",
            "surename": "Gonzalez",
            "avatar": "",
            "email": "tomas.gonzalez@fossid.com",
            "language": "en",
            "phone": "",
            "mobile": "",
            "is_deleted": False,
        },
    }

    result = users_client.get_information("tomas.gonzalez@fossid.com")

    assert result["id"] == 3
    assert result["username"] == "tomas.gonzalez@fossid.com"
    assert result["is_deleted"] is False
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "users"
    assert payload["action"] == "get_information"
    assert payload["data"]["searched_username"] == "tomas.gonzalez@fossid.com"


@patch.object(BaseAPI, "_send_request")
def test_get_information_api_error(mock_send, users_client):
    mock_send.return_value = {"status": "0", "error": "not found"}
    with pytest.raises(ApiError, match="Failed to get information for user"):
        users_client.get_information("missing")


@patch.object(BaseAPI, "_send_request")
def test_get_information_invalid_searched_username(mock_send, users_client):
    mock_send.return_value = {
        "operation": "users_get_information",
        "status": "0",
        "data": [
            {
                "code": "RequestData.Traits.UserTrait.username_not_valid",
                "message": "The user does not exist in the database",
                "message_parameters": {"fieldname": "searched_username"},
            }
        ],
        "error": "RequestData.Base.issues_while_parsing_request",
        "message": "These issues were found while parsing the request:",
        "message_parameters": [],
    }
    with pytest.raises(
        ApiError,
        match=(
            r"Failed to get information for user 'noone@example.com': "
            r"RequestData\.Base\.issues_while_parsing_request"
        ),
    ) as raised:
        users_client.get_information("noone@example.com")
    assert (
        raised.value.details["error"]
        == "RequestData.Base.issues_while_parsing_request"
    )
    assert raised.value.details["data"][0]["code"] == (
        "RequestData.Traits.UserTrait.username_not_valid"
    )
    assert is_user_not_found(
        raised.value.details.get("error", ""),
        raised.value.details,
    )


def test_normalize_permissions_map():
    data = {
        "10": {"id": 10, "code": "SCANS_VIEW", "group": "scans"},
    }
    result = normalize_permissions_list_data(
        data, operation="get_user_permissions_list"
    )
    assert len(result) == 1
    assert result[0]["code"] == "SCANS_VIEW"


def test_get_user_permissions_list_requires_exactly_one_identifier(
    users_client,
):
    with pytest.raises(ValueError, match="exactly one"):
        users_client.get_user_permissions_list()
    with pytest.raises(ValueError, match="exactly one"):
        users_client.get_user_permissions_list(
            searched_username="u", user_id=1
        )


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_by_username(mock_send, users_client):
    mock_send.return_value = {
        "operation": "users_get_user_permissions_list",
        "status": "1",
        "data": [
            {
                "id": 1,
                "group": "Projects",
                "code": "PROJECT_ACCESS_ANY",
                "name": "Access & Search any project",
                "description": (
                    "You can search and access any existing project even "
                    "though you are not a member."
                ),
                "created": "2016-09-27 00:00:00",
                "updated": "2016-09-26 22:00:00",
                "role_id": 1,
                "status": None,
            },
        ],
    }

    result = users_client.get_user_permissions_list(
        searched_username="alice"
    )

    assert len(result) == 1
    assert result[0]["code"] == "PROJECT_ACCESS_ANY"
    assert result[0]["role_id"] == 1
    assert result[0]["status"] is None
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "get_user_permissions_list"
    assert payload["data"]["searched_username"] == "alice"


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_multiple_entries(mock_send, users_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {
                "id": 1,
                "group": "Projects",
                "code": "PROJECT_ACCESS_ANY",
                "name": "Access & Search any project",
                "description": "",
                "created": "2016-09-27 00:00:00",
                "updated": "2016-09-26 22:00:00",
                "role_id": 1,
                "status": None,
            },
            {
                "id": 25,
                "group": "FOSSID Webapp Debug",
                "code": "VIEW_DEBUG_INFORMATION",
                "name": "View System Debug Information",
                "description": "",
                "created": "2016-10-04 00:00:00",
                "updated": "2017-05-08 14:50:17",
                "role_id": None,
                "status": None,
            },
        ],
    }

    result = users_client.get_user_permissions_list(user_id=3)

    assert len(result) == 2
    assert result[1]["role_id"] is None


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_by_user_id(mock_send, users_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "10": {
                "id": 10,
                "group": "scans",
                "code": "SCANS_VIEW",
                "name": "View scans",
                "description": "",
                "created": "2024-01-01 00:00:00",
                "updated": "2024-01-01 00:00:00",
                "role_id": 2,
                "status": "1",
            },
        },
    }

    result = users_client.get_user_permissions_list(user_id=5)

    assert len(result) == 1
    assert result[0]["code"] == "SCANS_VIEW"
    payload = mock_send.call_args[0][0]
    assert payload["data"]["user_id"] == 5


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_user_not_found(mock_send, users_client):
    mock_send.return_value = {
        "operation": "users_get_user_permissions_list",
        "status": "0",
        "data": None,
        "error": "User not found",
        "message": "User not found",
        "message_parameters": [],
    }
    with pytest.raises(
        ApiError,
        match="Failed to list user permissions: User not found",
    ) as raised:
        users_client.get_user_permissions_list(searched_username="nobody@x")
    assert raised.value.details["error"] == "User not found"
    assert raised.value.details["data"] is None


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_api_error(mock_send, users_client):
    mock_send.return_value = {"status": "0", "error": "denied"}
    with pytest.raises(ApiError, match="Failed to list user permissions"):
        users_client.get_user_permissions_list(searched_username="x")
