"""Live contract tests for ComponentsClient (requires Workbench server)."""

import pytest

from tests.api.support.contract import assert_contract, assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestComponentsLiveReadOnly:
    def test_list_components(
        self, workbench_client, workbench_version
    ):
        response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "list_components",
                "data": {"records_per_page": "5", "page": "1"},
            }
        )
        assert_contract(
            "components.list_components",
            response,
            workbench_version=workbench_version,
        )

    def test_list_by_usage(self, workbench_client, workbench_version):
        data = workbench_client.components.list_by_usage(
            page=1, records_per_page=5
        )
        assert_data_contract(
            "components.list_by_usage",
            data,
            workbench_version=workbench_version,
        )

    def test_get_information_from_list(
        self, workbench_client, workbench_version
    ):
        listed = workbench_client.components.list_components(
            records_per_page=1, page=1
        )
        if not isinstance(listed, list) or not listed:
            pytest.skip("No components in catalog to test get_information")
        first = listed[0]
        name = first.get("name")
        version = first.get("version")
        if not name:
            pytest.skip("Listed component has no name")
        data = workbench_client.components.get_information(
            name, version
        )
        assert_data_contract(
            "components.get_information",
            data,
            workbench_version=workbench_version,
        )

    def test_list_components_count_only(
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

    def test_get_usage_for_listed_component(
        self, workbench_client, workbench_version
    ):
        listed = workbench_client.components.list_components(
            records_per_page=5, page=1
        )
        if not isinstance(listed, list) or not listed:
            pytest.skip("No components in catalog for get_usage test")
        comp_id = listed[0].get("id")
        if comp_id is None:
            pytest.skip("Listed component has no id")
        data = workbench_client.components.get_usage(
            component_id=int(comp_id),
            page=1,
            records_per_page=5,
        )
        assert_data_contract(
            "components.get_usage",
            data,
            workbench_version=workbench_version,
        )

    def test_get_usage_count_if_component_exists(
        self, workbench_client, workbench_version
    ):
        listed = workbench_client.components.list_components(
            records_per_page=1, page=1
        )
        if not isinstance(listed, list) or not listed:
            pytest.skip("No components for usage count test")
        comp_id = listed[0].get("id")
        if comp_id is None:
            pytest.skip("Component has no id")
        data = workbench_client.components.get_usage_count(int(comp_id))
        assert_data_contract(
            "components.get_usage_count",
            data,
            workbench_version=workbench_version,
        )


@pytest.mark.usefixtures("allow_mutations")
class TestComponentsLiveMutations:
    def test_create_and_delete_component(
        self,
        workbench_client,
        workbench_version,
        unique_component_name,
    ):
        version = "0.0.1-test"
        create_response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "create",
                "data": {
                    "name": unique_component_name,
                    "version": version,
                    "license_identifier": "MIT",
                },
            }
        )
        assert_contract(
            "components.create",
            create_response,
            workbench_version=workbench_version,
        )
        try:
            deleted = workbench_client.components.delete(
                unique_component_name, version
            )
            assert deleted is True
        except Exception:
            workbench_client.components.delete(
                unique_component_name, version
            )
            raise
