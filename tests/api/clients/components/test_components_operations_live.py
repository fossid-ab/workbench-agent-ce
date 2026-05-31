"""
Live validation for ComponentsClient (errors, quirks, full operation matrix).

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/components/test_components_operations_live.py -v
"""

import uuid

import pytest

from workbench_agent.api.clients.components.errors import (
    is_missing_component_information,
)
from workbench_agent.api.exceptions import ApiError
from tests.api.support.contract import assert_contract, assert_data_contract
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

MISSING_NAME = f"__api_missing_{uuid.uuid4().hex[:8]}__"


class TestComponentsLiveRawProbes:
    def test_raw_get_information_missing_returns_success_null(
        self, workbench_client
    ):
        response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "get_information",
                "data": {
                    "component_name": MISSING_NAME,
                    "component_version": "9.9.9",
                },
            }
        )
        assert is_missing_component_information(response), response

    def test_raw_delete_missing_component(self, workbench_client):
        response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "delete",
                "data": {"name": MISSING_NAME, "version": "0.0.0"},
            }
        )
        assert response.get("status") == "0", response
        assert "not found" in (response.get("error") or "").lower()

    def test_list_components_count_results_shape(
        self, workbench_client, workbench_version
    ):
        response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "list_components",
                "data": {"count_results": "1"},
            }
        )
        assert_contract(
            "components.list_components",
            response,
            workbench_version=workbench_version,
        )
        data = response.get("data")
        assert data is not None


class TestComponentsLiveClientErrors:
    def test_get_information_missing_returns_none_not_exception(
        self, workbench_client
    ):
        assert (
            workbench_client.components.get_information(
                MISSING_NAME, "9.9.9"
            )
            is None
        )

    def test_delete_missing_raises_api_error(self, workbench_client):
        err = assert_api_error(
            lambda: workbench_client.components.delete(
                MISSING_NAME, "0.0.0"
            ),
            message_contains="not found",
        )
        assert "Failed to delete component" in err.message

    def test_get_usage_count_missing_raises(self, workbench_client):
        err = assert_api_error(
            lambda: workbench_client.components.get_usage_count(
                999999999
            ),
            message_contains="not found",
        )
        assert "Failed to get usage count" in err.message
        assert_api_error_details_status_zero(err)

    def test_create_invalid_license(self, workbench_client, unique_component_name):
        err = assert_api_error(
            lambda: workbench_client.components.create(
                unique_component_name,
                "0.0.1-bad-license",
                "NOT_A_REAL_SPDX_IDENTIFIER_XYZ_999",
            ),
        )
        assert "Failed to create component" in err.message
        assert_api_error_details_status_zero(err)

    def test_list_by_usage_via_client(self, workbench_client, workbench_version):
        data = workbench_client.components.list_by_usage(
            page=1, records_per_page=3
        )
        assert_data_contract(
            "components.list_by_usage",
            data,
            workbench_version=workbench_version,
        )


@pytest.mark.usefixtures("allow_mutations")
class TestComponentsLiveMutationsViaClient:
    def test_create_update_get_usage_delete_cycle(
        self,
        workbench_client,
        workbench_version,
        unique_component_name,
    ):
        version = "0.0.1-live"
        result = workbench_client.components.create(
            unique_component_name,
            version,
            license_identifier="MIT",
        )
        assert result.get("data")
        assert_contract(
            "components.create",
            {
                "status": "1",
                "data": result["data"],
            },
            workbench_version=workbench_version,
        )

        update_result = workbench_client.components.update(
            unique_component_name,
            version,
            description="API live test component",
            comment="Created and updated by components operations live test",
            url="https://example.com/components-live-test",
            programming_language="Python",
        )
        assert update_result.get("data")
        assert_contract(
            "components.update",
            {
                "status": "1",
                "data": update_result["data"],
            },
            workbench_version=workbench_version,
        )

        info = workbench_client.components.get_information(
            unique_component_name, version
        )
        assert info is not None
        assert info.get("name") == unique_component_name or info.get(
            "version"
        ) == version
        assert info.get("description") == "API live test component"
        assert info.get("comment") == (
            "Created and updated by components operations live test"
        )
        assert info.get("url") == "https://example.com/components-live-test"

        comp_id = info.get("id") or update_result["data"].get(
            "component_id"
        )
        if comp_id is not None:
            usage = workbench_client.components.get_usage(
                component_id=int(comp_id),
                page=1,
                records_per_page=5,
            )
            assert_data_contract(
                "components.get_usage",
                usage,
                workbench_version=workbench_version,
            )

        assert workbench_client.components.delete(
            unique_component_name, version
        ) is True
