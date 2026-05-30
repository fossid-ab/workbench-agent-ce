"""Unit smoke tests using recorded Workbench 2026.1.0 response fixtures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.components import ComponentsClient
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.contract import assert_contract
from tests.api.support.version_contracts import load_fixture

WORKBENCH_VERSION = "2026.1.0"


@pytest.fixture
def components_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return ComponentsClient(api)


@patch.object(BaseAPI, "_send_request")
def test_list_components_matches_2026_1_fixture(mock_send, components_client):
    fixture = load_fixture(WORKBENCH_VERSION, "components_list_components")
    mock_send.return_value = fixture
    data = components_client.list_components()
    assert isinstance(data, list)
    assert_contract(
        "components.list_components",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )


@patch.object(BaseAPI, "_send_request")
def test_list_components_count_matches_fixture(mock_send, components_client):
    fixture = load_fixture(WORKBENCH_VERSION, "components_list_components_count")
    mock_send.return_value = fixture
    data = components_client.list_components(count_results=True)
    assert_contract(
        "components.list_components",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )


@patch.object(BaseAPI, "_send_request")
def test_get_usage_matches_2026_1_fixture(mock_send, components_client):
    fixture = load_fixture(WORKBENCH_VERSION, "components_get_usage")
    mock_send.return_value = fixture
    data = components_client.get_usage(component_id=1)
    assert_contract(
        "components.get_usage",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
