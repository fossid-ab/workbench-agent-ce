"""Live DependencyService tests — read and write against DA Test Scan."""

import uuid

import pytest

from tests.api.support.contract import assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


def _catalog_license(workbench_client, name: str, version: str) -> str:
    info = workbench_client.component_catalog.find(name, version)
    if isinstance(info, dict):
        license_id = info.get("license_identifier") or info.get("license_name")
        if license_id:
            return str(license_id)
    raise AssertionError(
        f"Could not resolve catalog license for {name!r} {version!r}"
    )


@pytest.mark.usefixtures("scan_has_da_results")
class TestDependencyServiceLiveReadOnly:
    def test_list_dependencies(
        self,
        dependency_service,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        deps = dependency_service.list_dependencies(
            dependency_analysis_test_scan_code
        )
        assert deps == scan_has_da_results
        assert len(deps) >= 1

    def test_summarize_existing_dependency(
        self,
        dependency_service,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        target = scan_has_da_results[0]
        summary = dependency_service.summarize_dependency(
            dependency_analysis_test_scan_code,
            target["name"],
            str(target["version"]),
        )
        assert summary["found"] is True
        assert summary["package_id"] == target.get("package_id")


@pytest.mark.usefixtures("allow_mutations", "scan_has_da_results")
class TestDependencyServiceLiveMutations:
    def test_toggle_include_in_report(
        self,
        dependency_service,
        workbench_version,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        target = scan_has_da_results[0]
        name = target["name"]
        version = str(target["version"])
        package_id = target.get("package_id")
        original_included = dependency_service.summarize_dependency(
            dependency_analysis_test_scan_code, name, version
        )["include_in_report"]

        try:
            new_included = not original_included
            result = dependency_service.set_include_in_report(
                dependency_analysis_test_scan_code,
                name,
                version,
                new_included,
                package_id=package_id,
            )
            assert_data_contract(
                "scans.update_dependency_analysis_results",
                result,
                workbench_version=workbench_version,
            )
            assert result["include_in_report"] is new_included

            summary = dependency_service.summarize_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert summary["include_in_report"] is new_included
        finally:
            dependency_service.set_include_in_report(
                dependency_analysis_test_scan_code,
                name,
                version,
                original_included,
                package_id=package_id,
            )
            restored = dependency_service.summarize_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert restored["include_in_report"] == original_included

    def test_remove_and_restore_dependency(
        self,
        dependency_service,
        workbench_client,
        workbench_version,
        dependency_analysis_test_scan_code,
        scan_has_da_results,
    ):
        """Remove a real DA row, then add it back to avoid leaving the scan changed."""
        target = scan_has_da_results[-1]
        name = target["name"]
        version = str(target["version"])
        package_id = target.get("package_id")
        license_identifier = _catalog_license(workbench_client, name, version)
        include_in_report = dependency_service.summarize_dependency(
            dependency_analysis_test_scan_code, name, version
        )["include_in_report"]
        assert package_id

        try:
            assert dependency_service.remove_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert (
                dependency_service.get_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
                is None
            )

            restored = dependency_service.add_dependency(
                dependency_analysis_test_scan_code,
                name,
                version,
                package_id,
                license_identifier,
                include_in_report=include_in_report,
            )
            assert_data_contract(
                "scans.add_dependency_analysis_results",
                restored,
                workbench_version=workbench_version,
            )

            row = dependency_service.get_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert row is not None
            assert row.get("package_id") == package_id
        finally:
            if (
                dependency_service.get_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
                is None
            ):
                dependency_service.add_dependency(
                    dependency_analysis_test_scan_code,
                    name,
                    version,
                    package_id,
                    license_identifier,
                    include_in_report=include_in_report,
                )

    def test_add_and_remove_new_dependency(
        self,
        dependency_service,
        workbench_version,
        dependency_analysis_test_scan_code,
    ):
        tag = uuid.uuid4().hex[:8]
        name = f"api-test-dep-{tag}"
        version = "0.0.1"
        package_id = f"pkg:generic/{name}@{version}"
        license_identifier = "MIT"

        try:
            assert (
                dependency_service.get_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
                is None
            )

            added = dependency_service.add_dependency(
                dependency_analysis_test_scan_code,
                name,
                version,
                package_id,
                license_identifier,
                include_in_report=True,
            )
            assert_data_contract(
                "scans.add_dependency_analysis_results",
                added,
                workbench_version=workbench_version,
            )

            row = dependency_service.get_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert row is not None
            assert row.get("package_id") == package_id

            assert dependency_service.remove_dependency(
                dependency_analysis_test_scan_code, name, version
            )
            assert (
                dependency_service.get_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
                is None
            )
        finally:
            if (
                dependency_service.get_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
                is not None
            ):
                dependency_service.remove_dependency(
                    dependency_analysis_test_scan_code, name, version
                )
