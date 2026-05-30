"""Unit smoke tests using recorded Workbench 2026.1.0 user response fixtures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.users import UsersClient
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.contract import assert_contract, assert_data_contract
from tests.api.support.version_contracts import load_fixture

WORKBENCH_VERSION = "2026.1.0"


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
def test_get_information_matches_fixture(mock_send, users_client):
    fixture = load_fixture(WORKBENCH_VERSION, "users_get_information")
    mock_send.return_value = fixture
    data = users_client.get_information("tomas.gonzalez@fossid.com")
    assert_contract(
        "users.get_information",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )


@patch.object(BaseAPI, "_send_request")
def test_get_user_permissions_list_matches_fixture(mock_send, users_client):
    fixture = load_fixture(
        WORKBENCH_VERSION, "users_get_user_permissions_list"
    )
    mock_send.return_value = fixture
    data = users_client.get_user_permissions_list(searched_username="alice")
    assert_contract(
        "users.get_user_permissions_list",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
