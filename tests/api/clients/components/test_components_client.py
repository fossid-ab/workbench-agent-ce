"""Unit tests for ComponentsClient."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.components import ComponentsClient
from workbench_agent.api.clients.components.errors import (
    is_missing_component_information,
)
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI


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
def test_list_components_success(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": [{"id": 1, "name": "openssl", "version": "1.1.1"}],
    }
    result = components_client.list_components()
    assert len(result) == 1
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "components"
    assert payload["action"] == "list_components"


@patch.object(BaseAPI, "_send_request")
def test_list_components_count_only(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"count_results": 42},
    }
    result = components_client.list_components(count_results=True)
    assert result["count_results"] == 42
    assert mock_send.call_args[0][0]["data"]["count_results"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_list_by_usage_success(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "total_count": 1,
            "page": 1,
            "list": [{"id": 1, "name": "lib", "version": "1.0"}],
        },
    }
    result = components_client.list_by_usage(page=1, records_per_page=10)
    assert result["total_count"] == 1
    assert len(result["list"]) == 1


@patch.object(BaseAPI, "_send_request")
def test_get_information_single(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"id": 5, "name": "openssl", "version": "3.0"},
    }
    result = components_client.get_information("openssl", "3.0")
    assert result["id"] == 5


@patch.object(BaseAPI, "_send_request")
def test_get_information_list(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {"id": 5, "name": "openssl", "version": "3.0"},
            {"id": 6, "name": "openssl", "version": "1.1"},
        ],
    }
    result = components_client.get_information("openssl")
    assert len(result) == 2


@patch.object(BaseAPI, "_send_request")
def test_create_returns_data_and_message(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "component_id": 1200,
            "component_name": "test",
            "component_version": "1.0",
            "component_license": "MIT",
        },
        "message": "Component created",
    }
    result = components_client.create(
        "test", "1.0", "MIT", cpe="cpe:2.3:a:test:1.0:*:*:*:*:*:*:*"
    )
    assert result["data"]["component_id"] == 1200
    assert result["message"] == "Component created"
    assert "cpe" in mock_send.call_args[0][0]["data"]


@patch.object(BaseAPI, "_send_request")
def test_update_returns_data_and_message(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"component_id": 1200},
        "message": "Component updated",
    }
    result = components_client.update(
        "test",
        "1.0",
        description="Updated description",
        url="https://example.com",
        comment="live test note",
    )
    assert result["data"]["component_id"] == 1200
    assert result["message"] == "Component updated"
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "update"
    assert payload["data"]["name"] == "test"
    assert payload["data"]["version"] == "1.0"
    assert payload["data"]["description"] == "Updated description"
    assert payload["data"]["url"] == "https://example.com"
    assert "license_identifier" not in payload["data"]


@patch.object(BaseAPI, "_send_request")
def test_delete_success(mock_send, components_client):
    mock_send.return_value = {"status": "1", "data": True}
    assert components_client.delete("test", "1.0") is True


@patch.object(BaseAPI, "_send_request")
def test_get_usage_list_shape(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "page": 1,
            "records_per_page": 10,
            "list": [
                {
                    "scan_code": "SC1",
                    "scan_name": "Scan",
                    "scan_id": 1,
                    "project_id": 2,
                }
            ],
        },
    }
    result = components_client.get_usage(component_id=99)
    assert isinstance(result["list"], list)


@patch.object(BaseAPI, "_send_request")
def test_get_usage_count(mock_send, components_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "identifications_usage_count": 3,
            "dependency_usage_count": 1,
        },
    }
    result = components_client.get_usage_count(10)
    assert result["identifications_usage_count"] == 3


@patch.object(BaseAPI, "_send_request")
def test_api_error(mock_send, components_client):
    mock_send.return_value = {"status": "0", "error": "Not allowed"}
    with pytest.raises(ApiError, match="Not allowed"):
        components_client.list_components()


def test_is_missing_component_information_helper():
    assert is_missing_component_information({"status": "1", "data": None})
    assert not is_missing_component_information(
        {"status": "1", "data": {"id": 1}}
    )
