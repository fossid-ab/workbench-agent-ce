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
        workbench_version,
        test_scan_code,
        pending_files,
        pending_paths,
    ):
        """Unidentified Test Scan: paths come from scans.get_pending_files."""
        data = workbench_client.scans.get_pending_files(test_scan_code)
        assert data == pending_files
        assert_data_contract(
            "scans.get_pending_files",
            data,
            workbench_version=workbench_version,
        )
        assert len(pending_paths) >= 1
        for path in pending_paths[:5]:
            assert isinstance(path, str) and path
            assert "/" in path or "." in path
            assert not path.isdigit()
        assert set(pending_paths) == set(data.values())

    @pytest.mark.usefixtures("scan_has_identified")
    def test_get_scan_identified_licenses_unique(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
    ):
        data = workbench_client.scans.get_scan_identified_licenses(
            identified_test_scan_code, unique=True
        )
        assert isinstance(data, list)
        assert len(data) >= 1
        assert_data_contract(
            "scans.get_scan_identified_licenses",
            data,
            workbench_version=workbench_version,
        )

    @pytest.mark.usefixtures("scan_has_identified")
    def test_get_scan_identified_components(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
    ):
        data = workbench_client.scans.get_scan_identified_components(
            identified_test_scan_code
        )
        assert isinstance(data, list)
        assert len(data) >= 1
        assert_data_contract(
            "scans.get_scan_identified_components",
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

    @staticmethod
    def _assert_policy_warnings_list_items(policy_warnings_list):
        assert isinstance(policy_warnings_list, list)
        types_seen = set()
        for item in policy_warnings_list:
            assert isinstance(item, dict)
            assert "id" in item
            assert "type" in item
            assert "findings" in item
            assert "action" in item
            rule_type = item["type"]
            types_seen.add(rule_type)
            if rule_type == "license_category":
                assert item.get("license_category")
                assert item.get("license_info") is None
            elif rule_type == "license":
                assert item.get("license_info")
                assert item["license_info"].get("rule_lic_identifier")
            if item.get("license_info") is not None:
                info = item["license_info"]
                assert "rule_lic_identifier" in info
        if policy_warnings_list:
            assert types_seen <= {"license_category", "license"}

    def test_get_policy_warnings_info_identifications(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
    ):
        data = workbench_client.scans.get_policy_warnings_info(
            identified_test_scan_code, warning_type="identifications"
        )
        assert_data_contract(
            "scans.get_policy_warnings_info",
            data,
            workbench_version=workbench_version,
        )
        rules = data["policy_warnings_list"]
        self._assert_policy_warnings_list_items(rules)
        rule_types = {r["type"] for r in rules}
        assert "license_category" in rule_types
        assert "license" in rule_types

    def test_get_policy_warnings_info_via_policy_service(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
    ):
        data = workbench_client.policy.get_scan_policy_warnings_info_all(
            identified_test_scan_code
        )
        assert_data_contract(
            "scans.get_policy_warnings_info",
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


@pytest.mark.usefixtures("scan_has_da_results")
class TestScansLiveDependencyAnalysis:
    """Dependency Analysis Test Scan — DA-only import, no KB identified components."""

    def test_get_dependency_analysis_results(
        self,
        workbench_client,
        workbench_version,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        data = workbench_client.scans.get_dependency_analysis_results(
            dependency_analysis_test_scan_code
        )
        assert data == scan_has_da_results
        assert len(data) >= 1
        assert_data_contract(
            "scans.get_dependency_analysis_results",
            data,
            workbench_version=workbench_version,
        )
        first = data[0]
        assert first.get("name")
        assert "version" in first
        assert first.get("package_id")

    def test_no_kb_identified_components(
        self,
        workbench_client,
        dependency_analysis_test_scan_code,
    ):
        components = workbench_client.scans.get_scan_identified_components(
            dependency_analysis_test_scan_code
        )
        assert components == []

    def test_dependency_service_list_dependencies(
        self,
        workbench_client,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        deps = workbench_client.dependencies.list_dependencies(
            dependency_analysis_test_scan_code
        )
        assert deps == scan_has_da_results
        assert len(deps) >= 1
