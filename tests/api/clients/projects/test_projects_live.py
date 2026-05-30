"""Live contract tests for ProjectsClient (requires Workbench server)."""

import pytest

from tests.api.support.contract import assert_contract, assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestProjectsLiveReadOnly:
    def test_list_projects(self, workbench_client, workbench_version):
        data = workbench_client.projects.list_projects()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert_data_contract(
            "projects.list_projects",
            data,
            workbench_version=workbench_version,
        )

    def test_get_information_test_project(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        data = workbench_client.projects.get_information(test_project_code)
        assert_data_contract(
            "projects.get_information",
            data,
            workbench_version=workbench_version,
        )
        assert data.get("project_code") == test_project_code

    def test_get_all_scans_test_project(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
        test_scan_code,
    ):
        data = workbench_client.projects.get_all_scans(test_project_code)
        assert_data_contract(
            "projects.get_all_scans",
            data,
            workbench_version=workbench_version,
        )
        codes = {s.get("code") for s in data if isinstance(s, dict)}
        assert test_scan_code in codes
