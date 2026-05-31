"""Live negative tests for UsersClient."""

import uuid

import pytest

from workbench_agent.api.clients.users.errors import is_user_not_found
from workbench_agent.api.exceptions import ApiError
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_USER = f"invalid-user-{uuid.uuid4().hex}@no-such-domain.example"


class TestUsersErrorsLive:
    def test_get_information_unknown_user(self, workbench_client):
        err = assert_api_error(
            lambda: workbench_client.users.get_information(INVALID_USER),
            message_contains="Failed to get information",
        )
        assert_api_error_details_status_zero(err)
        assert is_user_not_found(
            err.details.get("error", ""), err.details
        )

    def test_get_user_permissions_list_unknown_user(self, workbench_client):
        err = assert_api_error(
            lambda: workbench_client.users.get_user_permissions_list(
                searched_username=INVALID_USER
            ),
            message_contains="User not found",
        )
        assert_api_error_details_status_zero(err)
