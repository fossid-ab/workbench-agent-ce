"""Unit tests: UsersClient request payloads match schema manifest."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.users import UsersClient
from workbench_agent.api.helpers.base_api import BaseAPI


@pytest.fixture
def users_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return UsersClient(api)


def _data_from_call(mock_send) -> dict:
    return mock_send.call_args[0][0]["data"]


@patch.object(BaseAPI, "_send_request")
def test_get_information_payload(mock_send, users_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"id": 1, "username": "alice@corp"},
    }
    users_client.get_information("alice@corp")
    data = _data_from_call(mock_send)
    assert data == {"searched_username": "alice@corp"}
    assert mock_send.call_args[0][0]["group"] == "users"


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_by_username_payload(
    mock_send, users_client
):
    mock_send.return_value = {"status": "1", "data": []}
    users_client.get_user_permissions_list(searched_username="alice")
    assert _data_from_call(mock_send) == {"searched_username": "alice"}


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_by_user_id_payload(
    mock_send, users_client
):
    mock_send.return_value = {"status": "1", "data": []}
    users_client.get_user_permissions_list(user_id=5)
    assert _data_from_call(mock_send) == {"user_id": 5}
