"""Unit tests: UsersClient error handling."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.users import UsersClient
from workbench_agent.api.clients.users.errors import is_user_not_found
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)


@pytest.fixture
def users_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return UsersClient(api)


@patch.object(BaseAPI, "_send_request")
def test_get_information_parsing_error(mock_send, users_client):
    mock_send.return_value = {
        "status": "0",
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [
            {
                "code": "RequestData.Traits.UserTrait.username_not_valid",
            }
        ],
    }
    err = assert_api_error(
        lambda: users_client.get_information("nobody@example.com"),
        message_contains="issues_while_parsing_request",
    )
    assert is_user_not_found(
        err.details.get("error", ""),
        err.details,
    )
    assert_api_error_details_status_zero(err)


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_user_not_found(mock_send, users_client):
    response = {
        "status": "0",
        "error": "User not found",
        "data": None,
    }
    mock_send.return_value = response
    err = assert_api_error(
        lambda: users_client.get_user_permissions_list(
            searched_username="nobody@x"
        ),
        message_contains="User not found",
    )
    assert is_user_not_found("User not found", response)
    assert_api_error_details_status_zero(err)


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_null_data_returns_empty(
    mock_send, users_client
):
    mock_send.return_value = {"status": "1", "data": None}
    assert users_client.get_user_permissions_list(user_id=1) == []
