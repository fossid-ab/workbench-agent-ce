"""Tests for delete_scan handler."""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.handlers.delete_scan import (
    DELETE_SCAN_POLL_INTERVAL_SEC,
    handle_delete_scan,
)
from workbench_agent.services.types import ResolvedTargets


@pytest.fixture
def params():
    ns = argparse.Namespace()
    ns.command = "delete-scan"
    ns.project_name = "Proj"
    ns.project_code = None
    ns.scan_name = "Scan1"
    ns.scan_code = None
    ns.delete_identifications = False
    ns.scan_number_of_tries = 10
    ns.scan_wait_time = 999
    return ns


@patch("workbench_agent.handlers.delete_scan.resolve_project_and_scan")
def test_handle_delete_scan_success(mock_resolve, params):
    mock_resolve.return_value = ResolvedTargets(
        project_code="proj_code",
        scan_code="sc_code",
        project_created=False,
        scan_is_new=False,
        scan_info={"id": 1},
    )
    client = MagicMock()
    client.user_permissions.can_delete_scan.return_value = True
    client.scan_deletion.delete_scan.return_value = StatusResult(
        status="FINISHED",
        raw_data={"status": "FINISHED"},
        success=True,
        duration=1.5,
    )

    assert handle_delete_scan(client, params) is True
    mock_resolve.assert_called_once_with(client, params, allow_create=False)
    client.user_permissions.can_delete_scan.assert_called_once_with("sc_code")
    client.scan_deletion.delete_scan.assert_called_once_with(
        "sc_code",
        delete_identifications=False,
        wait_retry_count=10,
        wait_retry_interval=DELETE_SCAN_POLL_INTERVAL_SEC,
    )


@patch("workbench_agent.handlers.delete_scan.resolve_project_and_scan")
def test_handle_delete_scan_permission_denied(mock_resolve, params):
    mock_resolve.return_value = ResolvedTargets(
        project_code="proj_code",
        scan_code="sc_code",
        project_created=False,
        scan_is_new=False,
    )
    client = MagicMock()
    client.user_permissions.can_delete_scan.return_value = False

    with pytest.raises(
        WorkbenchAgentError,
        match="does not have permission to delete this scan",
    ):
        handle_delete_scan(client, params)

    client.scan_deletion.delete_scan.assert_not_called()
