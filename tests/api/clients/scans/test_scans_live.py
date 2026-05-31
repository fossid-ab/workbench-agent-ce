"""
Live contract tests for ScansClient (requires Workbench server).

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    pytest tests/api/clients/scans/test_scans_live.py -m requires_workbench -v

Successful paths are fast; invalid-scan probes are in ``test_scans_errors_live.py``.
"""

import pytest

from tests.api.support.contract import assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestScansLiveReadOnly:
    def test_list_scans_includes_test_scan(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        scans = workbench_client.scans.list_scans()
        assert isinstance(scans, list)
        assert len(scans) >= 1
        codes = {s.get("code") for s in scans if isinstance(s, dict)}
        assert test_scan_code in codes
        sample = next(
            s for s in scans if isinstance(s, dict) and s.get("code") == test_scan_code
        )
        assert_data_contract(
            "scans.list_scans",
            [sample],
            workbench_version=workbench_version,
        )

    def test_get_information_test_scan(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_information(test_scan_code)
        assert_data_contract(
            "scans.get_information",
            data,
            workbench_version=workbench_version,
        )
        assert data.get("code") == test_scan_code

    def test_get_scan_folder_metrics(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_scan_folder_metrics(test_scan_code)
        assert_data_contract(
            "scans.get_folder_metrics",
            data,
            workbench_version=workbench_version,
        )

    def test_get_pending_files(
        self,
        workbench_client,
        test_scan_code,
    ):
        data = workbench_client.scans.get_pending_files(test_scan_code)
        assert isinstance(data, dict)
        assert len(data) >= 1

    def test_get_scan_identified_licenses_unique(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_scan_identified_licenses(
            test_scan_code, unique=True
        )
        assert isinstance(data, list)
        if data:
            assert_data_contract(
                "scans.get_scan_identified_licenses",
                data,
                workbench_version=workbench_version,
            )

    def test_get_scan_identified_components(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_scan_identified_components(
            test_scan_code
        )
        assert isinstance(data, list)
        assert_data_contract(
            "scans.get_scan_identified_components",
            data,
            workbench_version=workbench_version,
        )

    def test_get_dependency_analysis_results(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_dependency_analysis_results(
            test_scan_code
        )
        assert_data_contract(
            "scans.get_dependency_analysis_results",
            data,
            workbench_version=workbench_version,
        )

    def test_get_policy_warnings_counter(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        data = workbench_client.scans.get_policy_warnings_counter(
            test_scan_code
        )
        assert_data_contract(
            "scans.get_policy_warnings_counter",
            data,
            workbench_version=workbench_version,
        )

    def test_check_status_download_content_from_git_non_git_scan(
        self, workbench_client, test_scan_code
    ):
        """Test Scan is upload-based; Git status call errors without a repo."""
        info = workbench_client.scans.get_information(test_scan_code)
        if info.get("git_repo_url"):
            data = workbench_client.scans.check_status_download_content_from_git(
                test_scan_code
            )
            assert isinstance(data, dict)
            return
        from workbench_agent.api.exceptions import ApiError

        with pytest.raises(ApiError, match="git"):
            workbench_client.scans.check_status_download_content_from_git(
                test_scan_code
            )

    def test_check_status_scan_process(
        self, workbench_client, test_scan_code
    ):
        status = workbench_client.scans.check_status(test_scan_code, "SCAN")
        assert isinstance(status, dict)
