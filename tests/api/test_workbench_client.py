# tests/api/test_workbench_client.py

from unittest.mock import patch

import pytest

from workbench_agent.api import WorkbenchClient
from workbench_agent.api.services.report_service import ReportService


def test_api_report_type_constants():
    """Test that report type sets match ``REPORT_DEFS``."""
    assert isinstance(ReportService.ASYNC_REPORT_TYPES, set)
    scan_types = ReportService.report_types_for_scope("scan")
    project_types = ReportService.report_types_for_scope("project")
    assert isinstance(scan_types, set)
    assert isinstance(project_types, set)

    assert "xlsx" in ReportService.ASYNC_REPORT_TYPES
    assert "spdx" in project_types
    assert "html" in scan_types


@patch.object(WorkbenchClient, "_check_version_compatibility")
def test_workbench_client_exposes_new_api_clients(mock_version_check):
    """WorkbenchClient wires components and files_and_folders clients."""
    client = WorkbenchClient(
        api_url="http://dummy.com/api.php",
        api_user="user",
        api_token="token",
    )
    assert hasattr(client, "components")
    assert hasattr(client, "files_and_folders")
    from workbench_agent.api.clients.components import ComponentsClient
    from workbench_agent.api.clients.files_and_folders import (
        FilesAndFoldersClient,
    )

    assert isinstance(client.components, ComponentsClient)
    assert isinstance(client.files_and_folders, FilesAndFoldersClient)
    assert hasattr(client, "component_catalog")
    from workbench_agent.api.services.component_service import ComponentService
    from workbench_agent.api.services.dependency_service import DependencyService

    assert isinstance(client.component_catalog, ComponentService)
    assert isinstance(client.dependencies, DependencyService)
    assert hasattr(client, "identification")
    from workbench_agent.api.services.identification_service import (
        IdentificationService,
    )

    assert isinstance(client.identification, IdentificationService)
    assert hasattr(client, "vulnerability")
    from workbench_agent.api.services.vulnerability_service import (
        VulnerabilityService,
    )

    assert isinstance(client.vulnerability, VulnerabilityService)
    assert hasattr(client, "policy")
    assert hasattr(client, "links")
    from workbench_agent.api.services.links_service import LinksService
    from workbench_agent.api.services.policy_service import PolicyService

    assert isinstance(client.policy, PolicyService)
    assert isinstance(client.links, LinksService)
    assert not hasattr(client, "results")