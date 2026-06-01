"""Live contract tests for ProjectsClient (requires Workbench server)."""

import pytest

from tests.api.support.contract import assert_data_contract

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
        identified_test_scan_code,
    ):
        data = workbench_client.projects.get_all_scans(test_project_code)
        assert_data_contract(
            "projects.get_all_scans",
            data,
            workbench_version=workbench_version,
        )
        codes = {s.get("code") for s in data if isinstance(s, dict)}
        assert test_scan_code in codes
        assert identified_test_scan_code in codes

    def test_get_all_scans_includes_dependency_analysis_scan(
        self,
        workbench_client,
        test_project_code,
        dependency_analysis_test_scan_code,
    ):
        data = workbench_client.projects.get_all_scans(test_project_code)
        codes = {s.get("code") for s in data if isinstance(s, dict)}
        assert dependency_analysis_test_scan_code in codes


class TestProjectsPolicyWarningsLive:
    """Live validation for ``get_policy_warnings_info`` (Test Project policies)."""

    @staticmethod
    def _assert_scans_list_items(scans_list):
        assert isinstance(scans_list, list)
        assert len(scans_list) >= 1
        for item in scans_list:
            assert isinstance(item, dict)
            assert "scan_id" in item
            assert "scan_name" in item
            assert "scan_code" in item

    def test_policy_warnings_identifications(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        data = workbench_client.projects.get_policy_warnings_info(
            test_project_code, warning_type="identifications"
        )
        assert_data_contract(
            "projects.get_policy_warnings_info",
            data,
            workbench_version=workbench_version,
        )
        assert data["scans_with_warnings"] is not None
        assert int(data["scans_with_warnings"]) >= 1
        assert int(data["warnings_counter"]) >= 1
        self._assert_scans_list_items(data["scans_list"])

    def test_policy_warnings_dependencies(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        data = workbench_client.projects.get_policy_warnings_info(
            test_project_code, warning_type="dependencies"
        )
        assert_data_contract(
            "projects.get_policy_warnings_info",
            data,
            workbench_version=workbench_version,
        )
        assert "scans_list" in data
        assert "warnings_counter" in data
        assert "scans_with_warnings" in data

    def test_policy_warnings_all(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        data = workbench_client.policy.get_project_policy_warnings_all(
            test_project_code
        )
        assert_data_contract(
            "projects.get_policy_warnings_info",
            data,
            workbench_version=workbench_version,
        )
        if data["scans_list"] is not None:
            self._assert_scans_list_items(data["scans_list"])
