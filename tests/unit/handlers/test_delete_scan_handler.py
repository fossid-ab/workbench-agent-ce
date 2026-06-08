"""Tests for delete_scan handler."""

import argparse
from unittest.mock import MagicMock

from workbench_agent.api.services.resolver_service import ResolvedScan

import pytest

from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.handlers.delete_scan import (
    DELETE_SCAN_POLL_INTERVAL_SEC,
    handle_delete_scan,
)


@pytest.fixture
def params():
    ns = argparse.Namespace()
    ns.command = "delete-scan"
    ns.project_name = "Proj"
    ns.scan_name = "Scan1"
    ns.delete_identifications = False
    ns.scan_number_of_tries = 10
    ns.scan_wait_time = 999  # ignored for delete polling (fixed interval)
    return ns


def test_handle_delete_scan_success(params):
    client = MagicMock()
    client.resolver.find_project_and_scan.return_value = (
        "proj_code",
        ResolvedScan(code="sc_code", id=1, info={}),
    )
    client.user_permissions.can_delete_scan.return_value = True
    client.scan_deletion.delete_scan.return_value = StatusResult(
        status="FINISHED",
        raw_data={"status": "FINISHED"},
        success=True,
        duration=1.5,
    )

    assert handle_delete_scan(client, params) is True
    client.resolver.find_project_and_scan.assert_called_once_with(
        "Proj", "Scan1"
    )
    client.user_permissions.can_delete_scan.assert_called_once_with("sc_code")
    client.scan_deletion.delete_scan.assert_called_once_with(
        "sc_code",
        delete_identifications=False,
        wait_retry_count=10,
        wait_retry_interval=DELETE_SCAN_POLL_INTERVAL_SEC,
    )


def test_handle_delete_scan_permission_denied(params):
    client = MagicMock()
    client.resolver.find_project_and_scan.return_value = (
        "proj_code",
        ResolvedScan(code="sc_code", id=1, info={}),
    )
    client.user_permissions.can_delete_scan.return_value = False

    with pytest.raises(
        WorkbenchAgentError,
        match="does not have permission to delete this scan",
    ):
        handle_delete_scan(client, params)

    client.scan_deletion.delete_scan.assert_not_called()
