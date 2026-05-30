"""Live negative tests for ProjectsClient."""

import pytest

from workbench_agent.api.exceptions import ProjectNotFoundError

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_CODE = "INVALID_PROJECT_CODE___NOT_REAL"


class TestProjectsErrorsLive:
    def test_get_information_invalid_project_code(self, workbench_client):
        with pytest.raises(ProjectNotFoundError, match="not found"):
            workbench_client.projects.get_information(INVALID_CODE)

    def test_get_all_scans_invalid_project_code_returns_empty(
        self, workbench_client
    ):
        """Missing project returns [] (not ProjectNotFoundError)."""
        scans = workbench_client.projects.get_all_scans(INVALID_CODE)
        assert scans == []
