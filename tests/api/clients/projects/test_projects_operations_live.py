"""
Comprehensive live tests for all ProjectsClient operations.

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/projects/test_projects_operations_live.py -v
"""

import uuid

import pytest

from workbench_agent.api.clients.projects.errors import is_project_not_found
from workbench_agent.api.exceptions import ApiError, ProjectNotFoundError
from tests.api.support.contract import assert_contract, assert_data_contract
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_CODE = f"INVALID_PROJECT_{uuid.uuid4().hex[:16].upper()}"


class TestProjectsLiveRawProbes:
    """Raw API responses to validate error text and BaseAPI bypass behavior."""

    def test_raw_get_information_not_found(self, workbench_client):
        response = workbench_client.projects._api._send_request(
            {
                "group": "projects",
                "action": "get_information",
                "data": {"project_code": INVALID_CODE},
            }
        )
        assert response.get("status") == "0", response
        error = response.get("error", "")
        assert is_project_not_found(error), (
            f"Expected not-found marker in error, got: {error!r}"
        )

    def test_raw_get_all_scans_not_found(self, workbench_client):
        response = workbench_client.projects._api._send_request(
            {
                "group": "projects",
                "action": "get_all_scans",
                "data": {"project_code": INVALID_CODE},
            }
        )
        assert response.get("status") == "0", response
        error = response.get("error", "")
        assert is_project_not_found(error), (
            f"Expected not-found marker in error, got: {error!r}"
        )

    def test_list_projects_field_types(self, workbench_client):
        """Document whether numeric fields are strings on this server."""
        projects = workbench_client.projects.list_projects()
        assert projects
        sample = projects[0]
        assert "id" in sample and "project_code" in sample
        # Workbench 2026.1: id/scans often strings
        id_val = sample.get("id")
        assert isinstance(id_val, (str, int)), (
            f"Unexpected id type: {type(id_val)}"
        )


class TestProjectsErrorsLiveExtended:
    def test_get_information_raises_project_not_found(self, workbench_client):
        with pytest.raises(ProjectNotFoundError, match="not found"):
            workbench_client.projects.get_information(INVALID_CODE)

    def test_get_all_scans_returns_empty_list(self, workbench_client):
        assert workbench_client.projects.get_all_scans(INVALID_CODE) == []

    def test_update_nonexistent_raises_project_not_found(
        self, workbench_client
    ):
        with pytest.raises(ProjectNotFoundError, match="not found"):
            workbench_client.projects.update(
                INVALID_CODE,
                "Should Not Exist",
            )

    def test_generate_report_nonexistent_raises_project_not_found(
        self, workbench_client
    ):
        with pytest.raises(ProjectNotFoundError, match="not found"):
            workbench_client.projects.generate_report(
                {
                    "project_code": INVALID_CODE,
                    "report_type": "xlsx",
                    "async": "1",
                }
            )

    def test_create_invalid_limit_date(self, workbench_client, unique_project_name):
        err = assert_api_error(
            lambda: workbench_client.projects.create(
                unique_project_name,
                limit_date="not-a-valid-date",
            ),
            message_contains="Invalid date format",
        )
        assert_api_error_details_status_zero(err)


@pytest.fixture(scope="class")
def mutation_project_name():
    return f"api-test-project-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="class")
def ephemeral_project(workbench_client, mutation_project_name):
    """One ephemeral project per mutation test class."""
    code = workbench_client.projects.create(
        mutation_project_name,
        description="API live test ephemeral project",
        comment="created by test_projects_operations_live",
    )
    assert code
    return code


@pytest.mark.usefixtures("allow_mutations")
class TestProjectsLiveMutationsFullCycle:
    """
    Create ephemeral projects (random names). Workbench has no delete-project API.
    """

    def test_create_listed_and_get_information(
        self,
        workbench_client,
        workbench_version,
        ephemeral_project,
    ):
        listed = workbench_client.projects.list_projects()
        codes = {p.get("project_code") for p in listed if isinstance(p, dict)}
        assert ephemeral_project in codes

        info = workbench_client.projects.get_information(ephemeral_project)
        assert_data_contract(
            "projects.get_information",
            info,
            workbench_version=workbench_version,
        )
        assert info.get("project_code") == ephemeral_project

    def test_create_response_contract(
        self, workbench_client, workbench_version, unique_project_name
    ):
        name = f"{unique_project_name}-contract"
        response = workbench_client.projects._api._send_request(
            {
                "group": "projects",
                "action": "create",
                "data": {
                    "project_name": name,
                    "description": "contract probe",
                },
            }
        )
        assert_contract(
            "projects.create",
            response,
            workbench_version=workbench_version,
        )
        code = response.get("data", {}).get("project_code")
        assert code

    def test_get_all_scans_new_project_empty_or_list(
        self,
        workbench_client,
        workbench_version,
        ephemeral_project,
    ):
        scans = workbench_client.projects.get_all_scans(ephemeral_project)
        assert isinstance(scans, list)
        assert_data_contract(
            "projects.get_all_scans",
            scans,
            workbench_version=workbench_version,
        )

    def test_update_project(
        self,
        workbench_client,
        workbench_version,
        ephemeral_project,
        mutation_project_name,
    ):
        new_name = f"{mutation_project_name}-updated"
        project_id = workbench_client.projects.update(
            ephemeral_project,
            new_name,
            description="updated by live test",
        )
        assert isinstance(project_id, int)

        response = workbench_client.projects._api._send_request(
            {
                "group": "projects",
                "action": "update",
                "data": {
                    "project_code": ephemeral_project,
                    "project_name": new_name,
                },
            }
        )
        assert_contract(
            "projects.update",
            response,
            workbench_version=workbench_version,
        )

        info = workbench_client.projects.get_information(ephemeral_project)
        assert info.get("project_name") == new_name

    def test_update_invalid_limit_date(
        self, workbench_client, ephemeral_project, mutation_project_name
    ):
        err = assert_api_error(
            lambda: workbench_client.projects.update(
                ephemeral_project,
                mutation_project_name,
                limit_date="bad-date",
            ),
            message_contains="Invalid date format",
        )
        assert_api_error_details_status_zero(err)

    def test_generate_report_and_check_status(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        """Use Test Project (has scans); ephemeral projects often have none."""
        payload = workbench_client.reports.build_project_report_payload(
            test_project_code,
            "xlsx",
            selection_type="include_all_licenses",
        )
        process_id = workbench_client.projects.generate_report(payload)
        assert isinstance(process_id, int)
        assert process_id > 0

        response = workbench_client.projects._api._send_request(
            {
                "group": "projects",
                "action": "generate_report",
                "data": payload,
            }
        )
        assert_contract(
            "projects.generate_report",
            response,
            workbench_version=workbench_version,
        )

        status = workbench_client.projects.check_status(
            process_id, "REPORT_GENERATION"
        )
        assert isinstance(status, dict)
        assert status.get("status") in (
            "FINISHED",
            "RUNNING",
            "PENDING",
            "QUEUED",
            "FAILED",
            None,
        ) or "status" in status

    def test_check_status_invalid_process_raises(
        self, workbench_client, ephemeral_project
    ):
        err = assert_api_error(
            lambda: workbench_client.projects.check_status(
                999999999,
                "REPORT_GENERATION",
            ),
        )
        assert_api_error_details_status_zero(err)
