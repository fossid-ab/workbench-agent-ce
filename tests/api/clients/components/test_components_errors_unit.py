"""Unit tests: ComponentsClient raises ApiError on API failures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.components import ComponentsClient
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)


@pytest.fixture
def components_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return ComponentsClient(api)


ERROR_RESPONSE = {
    "status": "0",
    "error": "Row not found in table components",
    "operation": "components_delete",
}


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "method_name,kwargs",
    [
        ("list_components", {}),
        ("list_by_usage", {}),
        (
            "get_information",
            {"component_name": "missing", "component_version": "1.0"},
        ),
        ("create", {"name": "x", "version": "1", "license_identifier": "MIT"}),
        ("delete", {"name": "x", "version": "1"}),
        ("get_usage", {"component_id": 1}),
        ("get_usage_count", {"component_id": 999}),
    ],
)
def test_methods_raise_api_error_on_status_zero(
    mock_send, components_client, method_name, kwargs
):
    mock_send.return_value = ERROR_RESPONSE
    method = getattr(components_client, method_name)
    if method_name == "get_usage_count":
        err = assert_api_error(lambda: method(kwargs["component_id"]))
    elif method_name == "create":
        err = assert_api_error(
            lambda: method(
                kwargs["name"],
                kwargs["version"],
                kwargs["license_identifier"],
            )
        )
    elif method_name == "get_information":
        err = assert_api_error(
            lambda: method(
                kwargs["component_name"],
                kwargs["component_version"],
            )
        )
    elif method_name == "delete":
        err = assert_api_error(
            lambda: method(kwargs["name"], kwargs["version"])
        )
    else:
        err = assert_api_error(lambda: method(**kwargs))

    assert_api_error_details_status_zero(err)
    assert "Row not found" in err.message
    mock_send.assert_called_once()


@patch.object(BaseAPI, "_send_request")
def test_list_by_usage_unexpected_shape_raises(mock_send, components_client):
    mock_send.return_value = {"status": "1", "data": "not-a-dict"}
    with pytest.raises(ApiError, match="Unexpected list_by_usage"):
        components_client.list_by_usage()


@patch.object(BaseAPI, "_send_request")
def test_get_usage_unexpected_shape_raises(mock_send, components_client):
    mock_send.return_value = {"status": "1", "data": []}
    with pytest.raises(ApiError, match="Unexpected get_usage"):
        components_client.get_usage(component_id=1)
