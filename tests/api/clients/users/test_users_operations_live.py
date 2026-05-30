"""
Live probes for UsersClient (error shapes and data normalization).

    set -a && source .env-cs && set +a
    pytest tests/api/clients/users/test_users_operations_live.py -v
"""

import uuid

import pytest

from workbench_agent.api.clients.users.errors import (
    is_user_not_found,
    normalize_permissions_list_data,
)
from workbench_agent.api.exceptions import ApiError

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_USER = f"invalid-user-{uuid.uuid4().hex}@no-such-domain.example"


class TestUsersLiveRawProbes:
    def test_raw_get_information_unknown_user(self, workbench_client):
        response = workbench_client.users._api._send_request(
            {
                "group": "users",
                "action": "get_information",
                "data": {"searched_username": INVALID_USER},
            }
        )
        assert response.get("status") == "0", response
        assert is_user_not_found(
            response.get("error", ""), response
        ), response.get("error")

    def test_raw_get_permissions_unknown_user(self, workbench_client):
        response = workbench_client.users._api._send_request(
            {
                "group": "users",
                "action": "get_user_permissions_list",
                "data": {"searched_username": INVALID_USER},
            }
        )
        assert response.get("status") == "0", response
        assert response.get("error") == "User not found"
        assert response.get("data") is None

    def test_permissions_map_shape_if_returned(
        self, workbench_client, api_username
    ):
        """Document whether live server returns list or map for permissions."""
        raw = workbench_client.users._api._send_request(
            {
                "group": "users",
                "action": "get_user_permissions_list",
                "data": {"searched_username": api_username},
            }
        )
        assert raw.get("status") == "1"
        data = raw.get("data")
        normalized = normalize_permissions_list_data(
            data, operation="get_user_permissions_list"
        )
        via_client = workbench_client.users.get_user_permissions_list(
            searched_username=api_username
        )
        assert len(normalized) == len(via_client)
        assert len(via_client) >= 1


@pytest.fixture(scope="session")
def api_username(workbench_config):
    return workbench_config["user"]


class TestUsersLiveClientErrors:
    def test_get_information_client_error_prefix(self, workbench_client):
        with pytest.raises(ApiError) as exc_info:
            workbench_client.users.get_information(INVALID_USER)
        assert "Failed to get information for user" in str(exc_info.value)

    def test_get_permissions_client_error_prefix(self, workbench_client):
        with pytest.raises(ApiError) as exc_info:
            workbench_client.users.get_user_permissions_list(
                searched_username=INVALID_USER
            )
        assert "Failed to list user permissions" in str(exc_info.value)
