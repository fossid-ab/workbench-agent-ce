"""Live negative tests for ComponentsClient."""

import uuid

import pytest

from workbench_agent.api.exceptions import ApiError
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestComponentsErrorsLive:
    def test_delete_nonexistent_component(self, workbench_client):
        name = f"__api_err_no_such_{uuid.uuid4().hex[:8]}__"
        err = assert_api_error(
            lambda: workbench_client.components.delete(name, "0.0.0"),
            message_contains="not found",
        )
        assert_api_error_details_status_zero(err)

    def test_get_usage_count_invalid_component_id(self, workbench_client):
        err = assert_api_error(
            lambda: workbench_client.components.get_usage_count(999999999),
            message_contains="not found",
        )
        assert_api_error_details_status_zero(err)

    def test_create_invalid_license_identifier(self, workbench_client):
        name = f"__api_err_license_{uuid.uuid4().hex[:8]}__"
        err = assert_api_error(
            lambda: workbench_client.components.create(
                name,
                "0.0.0-test",
                "NOT_A_REAL_SPDX_IDENTIFIER_XYZ_999",
            ),
        )
        assert_api_error_details_status_zero(err)
        try:
            workbench_client.components.delete(name, "0.0.0-test")
        except ApiError:
            pass

    def test_get_information_missing_component_returns_null_not_error(
        self, workbench_client
    ):
        """
        Workbench returns status 1 with data null for unknown components
        (not an ApiError).
        """
        name = f"__api_err_no_such_{uuid.uuid4().hex[:8]}__"
        data = workbench_client.components.get_information(name, "9.9.9")
        assert data is None
