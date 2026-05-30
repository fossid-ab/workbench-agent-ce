"""Live contract tests for UsersClient (requires Workbench server)."""

import pytest

from tests.api.support.contract import assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


@pytest.fixture(scope="session")
def api_username(workbench_config):
    """Configured API user (--api-user / WORKBENCH_USER)."""
    return workbench_config["user"]


class TestUsersLiveReadOnly:
    def test_get_information_api_user(
        self, workbench_client, workbench_version, api_username
    ):
        data = workbench_client.users.get_information(api_username)
        assert_data_contract(
            "users.get_information",
            data,
            workbench_version=workbench_version,
        )
        assert data.get("username") == api_username

    def test_get_user_permissions_list_api_user(
        self, workbench_client, workbench_version, api_username
    ):
        data = workbench_client.users.get_user_permissions_list(
            searched_username=api_username
        )
        assert isinstance(data, list)
        assert_data_contract(
            "users.get_user_permissions_list",
            data,
            workbench_version=workbench_version,
        )
        assert len(data) >= 1

    def test_get_user_permissions_list_by_user_id(
        self, workbench_client, workbench_version, api_username
    ):
        info = workbench_client.users.get_information(api_username)
        user_id = info.get("id")
        assert user_id is not None
        data = workbench_client.users.get_user_permissions_list(
            user_id=int(user_id)
        )
        assert len(data) >= 1
        assert_data_contract(
            "users.get_user_permissions_list",
            data,
            workbench_version=workbench_version,
        )
