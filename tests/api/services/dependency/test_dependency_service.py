"""Tests for DependencyService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.dependency_service import DependencyService


@pytest.fixture
def dependency_service():
    scans = MagicMock()
    catalog = MagicMock()
    return DependencyService(scans, catalog)


def test_list_dependencies_delegates(dependency_service):
    dependency_service._scans.get_dependency_analysis_results.return_value = [
        {"name": "abbrev", "version": "1.1.1"}
    ]
    result = dependency_service.list_dependencies("S1")
    assert len(result) == 1
    dependency_service._scans.get_dependency_analysis_results.assert_called_once_with("S1")


def test_add_dependency_resolves_catalog_then_adds(dependency_service):
    dependency_service._catalog.resolve.return_value = {"created": True}
    dependency_service._scans.add_dependency_analysis_results.return_value = {"component_id": 1}
    result = dependency_service.add_dependency(
        "S1",
        "abbrev",
        "1.1.1",
        "pkg:npm/abbrev@1.1.1",
        "ISC",
        include_in_report=True,
    )
    assert result["component_id"] == 1
    dependency_service._catalog.resolve.assert_called_once_with(
        "abbrev",
        "1.1.1",
        "ISC",
        supplier_name=None,
        purl="pkg:npm/abbrev@1.1.1",
    )
    dependency_service._scans.add_dependency_analysis_results.assert_called_once()


def test_add_dependency_requires_license(dependency_service):
    with pytest.raises(ValueError, match="license_identifier is required to add"):
        dependency_service.add_dependency("S1", "abbrev", "1.1.1", "pkg:npm/abbrev@1.1.1", "")


def test_set_include_in_report_delegates(dependency_service):
    dependency_service._scans.update_dependency_analysis_results.return_value = {
        "include_in_report": False
    }
    result = dependency_service.set_include_in_report(
        "S1", "abbrev", "1.1.1", False, package_id="pkg:npm/abbrev@1.1.1"
    )
    assert result["include_in_report"] is False
    dependency_service._scans.update_dependency_analysis_results.assert_called_once_with(
        "S1",
        "abbrev",
        "1.1.1",
        package_id="pkg:npm/abbrev@1.1.1",
        projects_and_scopes=None,
        detailed_dependency_info=None,
        include_in_report=False,
    )


def test_remove_dependency_delegates(dependency_service):
    dependency_service._scans.remove_dependency_analysis_results.return_value = True
    assert dependency_service.remove_dependency("S1", "abbrev", "1.1.1")
    dependency_service._scans.remove_dependency_analysis_results.assert_called_once_with(
        "S1", "abbrev", "1.1.1"
    )
